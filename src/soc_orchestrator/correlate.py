"""IOC extraction and correlation of events into incidents.

Events are linked when they share a host, a user, or an external IOC and fall inside the
correlation window. Linking is transitive (union-find), so a brute-force from one IP, a
logon by the hit account, and a C2 beacon from the same host become one incident.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict
from datetime import timedelta

from .models import IOC, Event

HASH_RE = {64: "sha256", 40: "sha1", 32: "md5"}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
# File names that look like domains; never report these as network IOCs.
NOT_DOMAINS = re.compile(r"\.(exe|dll|ps1|bat|cmd|vbs|js|sys|log|txt|zip|msi)$", re.IGNORECASE)
INTERNAL_SUFFIXES = (".local", ".internal", ".corp.example", ".lan")
# Only treat a dotted token as a domain if it ends in a real-world TLD. Without this,
# PowerShell class names like System.Net.WebClient would be "extracted" as domains.
TLDS = {"com", "net", "org", "io", "co", "info", "biz", "ru", "cn", "xyz", "top", "site", "online", "club",
        "in", "uk", "de", "fr", "nl", "br", "app", "dev", "me", "tk", "cc", "su", "pw", "live", "shop", "example"}


def refang(text: str) -> str:
    return text.replace("[.]", ".").replace("hxxp", "http").replace("[:]", ":")


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


def iocs_for(event: Event) -> list[IOC]:
    found: dict[tuple[str, str], IOC] = {}

    def add(t: str, v: str) -> None:
        found[(t, v)] = IOC(type=t, value=v)

    for ip in (event.src_ip, event.dst_ip):
        if ip and _public_ip(ip):
            add("ip", ip)
    if event.file_hash and len(event.file_hash) in HASH_RE and re.fullmatch(r"[0-9a-fA-F]+", event.file_hash):
        add(HASH_RE[len(event.file_hash)], event.file_hash.lower())
    text = refang(" ".join(filter(None, [event.domain, event.url, event.cmdline])))
    for url in URL_RE.findall(text):
        add("url", url.rstrip(".,;)"))
    for dom in DOMAIN_RE.findall(text):
        dom = dom.lower()
        if (dom.rsplit(".", 1)[-1] in TLDS and not NOT_DOMAINS.search(dom)
                and not dom.endswith(INTERNAL_SUFFIXES) and not IP_RE.fullmatch(dom)):
            add("domain", dom)
    for ip in IP_RE.findall(text):
        if _public_ip(ip):
            add("ip", ip)
    return list(found.values())


class _DSU:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        self.p[self.find(a)] = self.find(b)


def correlate(events: list[Event], window: timedelta = timedelta(hours=2)) -> list[list[Event]]:
    """Group events into clusters. Returns clusters ordered by first timestamp."""
    events = sorted(events, key=lambda e: e.ts)
    dsu = _DSU(len(events))
    last_seen: dict[str, int] = {}
    for i, ev in enumerate(events):
        keys = [f"host:{ev.host}" if ev.host else None, f"user:{ev.user}" if ev.user else None]
        keys += [f"ioc:{i_.type}:{i_.value}" for i_ in iocs_for(ev)]
        for key in filter(None, keys):
            j = last_seen.get(key)
            if j is not None and ev.ts - events[j].ts <= window:
                dsu.union(i, j)
            last_seen[key] = i
    groups: dict[int, list[Event]] = defaultdict(list)
    for i, ev in enumerate(events):
        groups[dsu.find(i)].append(ev)
    return sorted(groups.values(), key=lambda g: g[0].ts)


def correlation_key(cluster: list[Event]) -> str:
    """Stable key for idempotent ticketing: same entities + same first-seen hour => same incident."""
    hosts = sorted({e.host for e in cluster if e.host})
    users = sorted({e.user for e in cluster if e.user})
    anchor = min(e.ts for e in cluster).strftime("%Y-%m-%dT%H")
    raw = "|".join(["h:" + ",".join(hosts), "u:" + ",".join(users), anchor])
    return hashlib.sha256(raw.encode()).hexdigest()[:20]
