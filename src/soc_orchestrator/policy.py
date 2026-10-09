"""Policy-as-code response engine.

Actions are *proposed* from rule-based facts (risk score, TI verdicts, techniques), never
from LLM output, and each proposal gets a decision with its reasons:

  ALLOW             executed automatically (ticket, paging, blocking a strongly-bad IOC)
  REQUIRE_APPROVAL  waits for a named analyst (containment of hosts/accounts)
  BLOCK             refused outright (protected assets/accounts, blast radius, never-block list)
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import ActionDecision, Incident

KNOWN_ACTIONS = ("create_ticket", "notify_oncall", "block_ioc", "isolate_host", "disable_account")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ResponsePolicy:
    ticket: int = 15
    notify_oncall: int = 60
    isolate_host: int = 80
    disable_account: int = 70
    critical_assets: frozenset[str] = frozenset()
    never_isolate: frozenset[str] = frozenset()
    protected_accounts: frozenset[str] = frozenset()
    never_block: tuple[str, ...] = ()
    max_isolations: int = 3
    block_ioc_min_ti_score: int = 70
    allowed_actions: frozenset[str] = frozenset(KNOWN_ACTIONS)
    extra: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> ResponsePolicy:
        d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        t = d.get("thresholds", {})
        low = lambda xs: frozenset(str(x).lower() for x in (xs or []))
        return cls(
            ticket=int(t.get("ticket", 15)), notify_oncall=int(t.get("notify_oncall", 60)),
            isolate_host=int(t.get("isolate_host", 80)), disable_account=int(t.get("disable_account", 70)),
            critical_assets=low(d.get("critical_assets")), never_isolate=low(d.get("never_isolate")),
            protected_accounts=low(d.get("protected_accounts")),
            never_block=tuple(str(x).lower() for x in d.get("never_block", [])),
            max_isolations=int(d.get("max_isolations_per_incident", 3)),
            block_ioc_min_ti_score=int((d.get("auto_execute") or {}).get("block_ioc_min_ti_score", 70)),
            allowed_actions=_allowlist(d.get("allowed_actions", KNOWN_ACTIONS)),
        )


def _allowlist(actions) -> frozenset[str]:
    allowed = frozenset(str(a) for a in actions or [])
    unknown = allowed - set(KNOWN_ACTIONS)
    if unknown:
        raise PolicyError(f"allowed_actions contains unknown actions: {sorted(unknown)}")
    return allowed


def default_policy_path() -> Path:
    return Path(__file__).resolve().parents[2] / "policy" / "policy.yaml"


def _never_block(value: str, never: tuple[str, ...]) -> bool:
    v = value.lower()
    return any(v == n or v.endswith("." + n) for n in never)


def compromised_accounts(incident: Incident, min_failures: int = 5) -> set[str]:
    """Accounts with a burst of failed logons followed by a successful one."""
    fails = Counter(e.user for e in incident.events if e.kind == "auth_fail" and e.user)
    return {u for u, n in fails.items() if n >= min_failures
            and any(e.kind == "auth_success" and e.user == u for e in incident.events)}


def decide(incident: Incident, policy: ResponsePolicy) -> list[ActionDecision]:
    out: list[ActionDecision] = []
    s = incident.risk_score
    tainted = bool(incident.injection_flags)
    taint_note = ["telemetry contains instruction-like text; decision made from rule-based facts only"] if tainted else []

    if s >= policy.ticket:
        out.append(ActionDecision(action="create_ticket", decision="ALLOW", reasons=[f"risk {s} >= {policy.ticket}"]))
    if s >= policy.notify_oncall:
        out.append(ActionDecision(action="notify_oncall", decision="ALLOW", reasons=[f"risk {s} >= {policy.notify_oncall}"]))

    for v in incident.ti:
        if v.verdict != "malicious" or v.ioc.type not in {"ip", "domain", "sha256", "sha1", "md5"}:
            continue
        if _never_block(v.ioc.value, policy.never_block):
            out.append(ActionDecision(action="block_ioc", target=v.ioc.value, decision="BLOCK",
                                      reasons=["indicator is on the never-block list (shared or own infrastructure)"]))
        elif v.score >= policy.block_ioc_min_ti_score:
            out.append(ActionDecision(action="block_ioc", target=v.ioc.value, decision="ALLOW",
                                      reasons=[f"TI {v.source} score {v.score} >= {policy.block_ioc_min_ti_score}"]))
        else:
            out.append(ActionDecision(action="block_ioc", target=v.ioc.value, decision="REQUIRE_APPROVAL",
                                      reasons=[f"TI score {v.score} below auto-block bar {policy.block_ioc_min_ti_score}"]))

    if s >= policy.isolate_host:
        too_many = len(incident.hosts) > policy.max_isolations
        for host in incident.hosts:
            if host in policy.never_isolate:
                out.append(ActionDecision(action="isolate_host", target=host, decision="BLOCK",
                                          reasons=["host is on the never-isolate list — use the major-incident process"]))
            elif too_many:
                out.append(ActionDecision(action="isolate_host", target=host, decision="BLOCK",
                                          reasons=[f"{len(incident.hosts)} hosts exceeds blast-radius cap {policy.max_isolations}"]))
            else:
                out.append(ActionDecision(action="isolate_host", target=host, decision="REQUIRE_APPROVAL",
                                          reasons=[f"risk {s} >= {policy.isolate_host}", "containment always needs a human", *taint_note]))

    compromised = compromised_accounts(incident)
    if s >= policy.disable_account:
        for user in sorted(compromised):
            if user in policy.protected_accounts:
                out.append(ActionDecision(action="disable_account", target=user, decision="BLOCK",
                                          reasons=["protected account (break-glass/service) — never disabled automatically"]))
            else:
                out.append(ActionDecision(action="disable_account", target=user, decision="REQUIRE_APPROVAL",
                                          reasons=[f"risk {s} >= {policy.disable_account}", "logon after brute force (T1078)", *taint_note]))

    # Allowlist last, so it overrides everything: an action this deployment hasn't enabled never runs.
    for a in out:
        if a.action not in policy.allowed_actions:
            a.decision = "BLOCK"
            a.reasons = [f"'{a.action}' is not on this deployment's action allowlist", *a.reasons]
    for a in out:
        a.status = {"ALLOW": "pending", "REQUIRE_APPROVAL": "pending", "BLOCK": "blocked"}[a.decision]
    return out
