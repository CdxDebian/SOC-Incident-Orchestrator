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
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
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
    text = refang(" ".join(filter(None, [event.domain, event.url, event.cmdline, event.message])))
    for email in EMAIL_RE.findall(text):
        add("email", email.lower())
    text = EMAIL_RE.sub(" ", text)  # don't re-extract the email's domain as a separate domain IOC
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


# Correlation weights: how strongly a shared signal suggests two events are the same incident.
# A shared external IOC is the strongest evidence; a shared host alone is enough only when the
# events are close in time; a shared user alone is never enough (users log on everywhere).
WEIGHTS = {"host": 0.5, "user": 0.3, "ioc": 0.6}
LINK_THRESHOLD = 0.5
LATE_FACTOR = 0.75  # applied when events are more than half a window apart


def link_score(a: Event, b: Event, window: timedelta = timedelta(hours=2)) -> tuple[float, list[str]]:
    """Weighted evidence that two events belong to the same incident, with the signals that contributed."""
    dt = abs(b.ts - a.ts)
    if dt > window:
        return 0.0, []
    reasons, score = [], 0.0
    if a.host and a.host == b.host:
        score += WEIGHTS["host"]
        reasons.append(f"host {a.host}")
    if a.user and a.user == b.user:
        score += WEIGHTS["user"]
        reasons.append(f"user {a.user}")
    shared = {(i.type, i.value) for i in iocs_for(a)} & {(i.type, i.value) for i in iocs_for(b)}
    if shared:
        score += WEIGHTS["ioc"]
        reasons.append("ioc " + ", ".join(sorted(v for _, v in shared)))
    if dt > window / 2:
        score *= LATE_FACTOR
        reasons.append(f"time gap {dt}")
    return round(score, 3), reasons


def correlate(events: list[Event], window: timedelta = timedelta(hours=2),
              threshold: float = LINK_THRESHOLD) -> list[list[Event]]:
    """Group events into incidents by weighted scoring of shared host, user, IOC and time proximity.

    Two events are linked when their link score reaches the threshold; linking is transitive, so
    a brute force, the logon it enabled and the C2 beacon that followed end up in one incident.
    """
    events = sorted(events, key=lambda e: e.ts)
    dsu = _DSU(len(events))
    start = 0
    for i, ev in enumerate(events):
        while ev.ts - events[start].ts > window:
            start += 1
        for j in range(start, i):
            if dsu.find(i) != dsu.find(j) and link_score(events[j], ev, window)[0] >= threshold:
                dsu.union(i, j)
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
