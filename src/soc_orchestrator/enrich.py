"""Threat-intel enrichment with hard timeouts and graceful fallback.

A slow or dead TI provider must never stall the pipeline or crash an incident: each lookup
runs with a deadline, failures degrade to verdict="unknown" with a note, and results are
cached so a burst of alerts doesn't hammer the provider.
"""
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Protocol

import httpx

from .models import IOC, TIVerdict


class TIProvider(Protocol):
    name: str

    def lookup(self, ioc: IOC) -> TIVerdict: ...


class LocalFeedProvider:
    """Offline feed (JSON: {"<value>": {"verdict": ..., "score": ..., "note": ...}}). Used in tests and demos."""

    name = "local-feed"

    def __init__(self, path: str | Path) -> None:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self.feed = {k.lower(): v for k, v in raw.items()}

    def lookup(self, ioc: IOC) -> TIVerdict:
        hit = self.feed.get(ioc.value.lower())
        if not hit:
            return TIVerdict(ioc=ioc, source=self.name)
        return TIVerdict(ioc=ioc, verdict=hit.get("verdict", "unknown"), score=int(hit.get("score", 0)),
                         source=self.name, note=hit.get("note", ""))


class VirusTotalProvider:
    """VirusTotal v3. Needs VT_API_KEY. Only hashes, domains and IPs are looked up."""

    name = "virustotal"
    _paths = {"sha256": "files", "sha1": "files", "md5": "files", "domain": "domains", "ip": "ip_addresses"}

    def __init__(self, api_key: str | None = None, timeout: float = 4.0) -> None:
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self.timeout = timeout

    def lookup(self, ioc: IOC) -> TIVerdict:
        path = self._paths.get(ioc.type)
        if not path or not self.api_key:
            return TIVerdict(ioc=ioc, source=self.name, note="not looked up")
        r = httpx.get(f"https://www.virustotal.com/api/v3/{path}/{ioc.value}",
                      headers={"x-apikey": self.api_key}, timeout=self.timeout)
        if r.status_code == 404:
            return TIVerdict(ioc=ioc, source=self.name, note="not found")
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = max(sum(stats.values()), 1)
        score = round(100 * (mal + 0.5 * sus) / total)
        verdict = "malicious" if mal >= 5 else "suspicious" if mal or sus else "benign"
        return TIVerdict(ioc=ioc, verdict=verdict, score=score, source=self.name, note=f"{mal}/{total} engines")


class Enricher:
    def __init__(self, provider: TIProvider, timeout: float = 3.0, max_workers: int = 8) -> None:
        self.provider, self.timeout = provider, timeout
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ti")
        self.cache: dict[tuple[str, str], TIVerdict] = {}

    def enrich(self, iocs: list[IOC]) -> list[TIVerdict]:
        pending = {}
        results: list[TIVerdict] = []
        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key in self.cache:
                results.append(self.cache[key])
            else:
                pending[key] = (ioc, self.pool.submit(self.provider.lookup, ioc))
        for key, (ioc, fut) in pending.items():
            try:
                verdict = fut.result(timeout=self.timeout)
                self.cache[key] = verdict
            except FutureTimeout:
                verdict = TIVerdict(ioc=ioc, source=self.provider.name, note=f"timeout after {self.timeout}s — fallback")
            except Exception as exc:  # provider down, bad JSON, HTTP error: degrade, never crash
                verdict = TIVerdict(ioc=ioc, source=self.provider.name, note=f"lookup failed ({type(exc).__name__}) — fallback")
            results.append(verdict)
        return results
