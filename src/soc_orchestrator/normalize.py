"""Ingest: turn heterogeneous raw telemetry into validated Events, rejecting garbage loudly.

Supported shapes (see samples/events.jsonl):
  * Windows Security log   {"source": "windows_security", "EventID": 4625, ...}
  * EDR                    {"source": "edr", "event_type": "process" | "process_access" | "file", ...}
  * Proxy / DNS / firewall {"source": "proxy" | "dns" | "firewall", ...}
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from .models import MAX_FIELD, Event, Severity

WIN_EVENTS = {
    4624: ("auth_success", Severity.low),
    4625: ("auth_fail", Severity.low),
    4688: ("process", Severity.low),
    4697: ("service_install", Severity.medium),
    4720: ("account_created", Severity.medium),
    1102: ("log_cleared", Severity.high),
}


@dataclass
class IngestResult:
    events: list[Event] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    duplicates: int = 0


def _ts(value: Any) -> datetime:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError) as exc:
            raise ValueError(f"timestamp out of range: {value!r}") from exc
    if not isinstance(value, str) or not value:
        raise ValueError("missing or non-string timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _s(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:MAX_FIELD] or None


def _fingerprint(fields: dict[str, Any]) -> str:
    canon = json.dumps({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in sorted(fields.items())},
                       sort_keys=True, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()[:24]


def _map(raw: dict[str, Any]) -> dict[str, Any]:
    source = _s(raw.get("source"))
    if not source:
        raise ValueError("missing 'source'")
    base: dict[str, Any] = {"ts": _ts(raw.get("timestamp") or raw.get("ts")), "source": source,
                            "host": raw.get("host") or raw.get("Computer"), "message": _s(raw.get("message")) or ""}

    if source == "windows_security":
        try:
            eid = int(raw.get("EventID"))
        except (TypeError, ValueError) as exc:
            raise ValueError("windows_security event without a numeric EventID") from exc
        if eid not in WIN_EVENTS:
            raise ValueError(f"unsupported EventID {eid}")
        kind, sev = WIN_EVENTS[eid]
        base.update(kind=kind, severity=sev, user=raw.get("TargetUserName"), src_ip=_s(raw.get("IpAddress")),
                    process=raw.get("NewProcessName"), cmdline=_s(raw.get("CommandLine")),
                    parent=raw.get("ParentProcessName"), target=raw.get("ServiceName"))
    elif source == "edr":
        kind = _s(raw.get("event_type"))
        if kind not in {"process", "process_access", "file"}:
            raise ValueError(f"unsupported edr event_type {kind!r}")
        base.update(kind=kind, severity=Severity(raw.get("severity", "low")), user=raw.get("user"),
                    process=raw.get("process"), cmdline=_s(raw.get("cmdline")), parent=raw.get("parent"),
                    file_hash=_s(raw.get("sha256")), target=raw.get("target"))
    elif source in {"proxy", "dns", "firewall"}:
        base.update(kind="dns" if source == "dns" else "network", severity=Severity(raw.get("severity", "low")),
                    user=raw.get("user"), src_ip=_s(raw.get("src_ip")), dst_ip=_s(raw.get("dst_ip")),
                    domain=_s(raw.get("domain") or raw.get("query")), url=_s(raw.get("url")),
                    process=raw.get("process"))
    else:
        raise ValueError(f"unknown source {source!r}")
    return base


def normalize(raws: Iterable[dict[str, Any] | str]) -> IngestResult:
    """Accepts dicts or raw JSON lines. Never raises on bad input: bad records are rejected with a reason."""
    out, seen = IngestResult(), set()
    for n, raw in enumerate(raws, start=1):
        try:
            if isinstance(raw, str):
                if not raw.strip():
                    continue
                raw = json.loads(raw)
            if not isinstance(raw, dict):
                raise ValueError("record is not a JSON object")
            fields = _map(raw)
            fields["fingerprint"] = _fingerprint(fields)
            event = Event(**fields)
        except (ValueError, TypeError, OverflowError, ValidationError, json.JSONDecodeError) as exc:
            out.rejected.append({"record": n, "reason": str(exc).splitlines()[0][:200]})
            continue
        if event.fingerprint in seen:
            out.duplicates += 1
            continue
        seen.add(event.fingerprint)
        out.events.append(event)
    out.events.sort(key=lambda e: e.ts)
    return out
