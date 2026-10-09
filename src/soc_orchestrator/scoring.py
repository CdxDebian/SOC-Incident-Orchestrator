"""Deterministic detection mapping (MITRE ATT&CK) and explainable risk scoring.

The score is a sum of named factors, each carrying the evidence that triggered it. It is
computed by rules, never by the LLM, so an analyst (or auditor) can always answer
"why is this a 92?" by reading the factors.
"""
from __future__ import annotations

import re
from collections import Counter

from .models import Event, RiskFactor, Severity, Technique, TIVerdict

ENCODED_PS = re.compile(r"(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|frombase64string)", re.IGNORECASE)
DOWNLOAD_CRADLE = re.compile(r"(downloadstring|downloadfile|invoke-webrequest|iwr |iex\s*\(|invoke-expression)", re.IGNORECASE)
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
SEV_POINTS = {Severity.info: 0, Severity.low: 5, Severity.medium: 10, Severity.high: 20, Severity.critical: 30}


def _base(path: str | None) -> str:
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _ev(e: Event) -> str:
    who = e.user or e.src_ip or "?"
    return f"{e.ts:%H:%M:%S} {e.host or '-'} {e.kind} ({who})"


def detect_techniques(events: list[Event], ti: list[TIVerdict]) -> list[Technique]:
    found: dict[str, Technique] = {}

    def add(tid: str, name: str, tactic: str, evidence: str) -> None:
        t = found.setdefault(tid, Technique(id=tid, name=name, tactic=tactic))
        if evidence not in t.evidence and len(t.evidence) < 5:
            t.evidence.append(evidence)

    fails = Counter((e.user, e.src_ip) for e in events if e.kind == "auth_fail")
    for (user, ip), n in fails.items():
        if n >= 5:
            add("T1110", "Brute Force", "Credential Access", f"{n} failed logons for {user} from {ip}")
            later = [e for e in events if e.kind == "auth_success" and e.user == user]
            if later:
                add("T1078", "Valid Accounts", "Initial Access", f"successful logon as {user} after brute force: {_ev(later[0])}")

    malicious = {v.ioc.value for v in ti if v.verdict == "malicious"}
    for e in events:
        proc, parent, cmd = _base(e.process), _base(e.parent), e.cmdline or ""
        if proc in {"powershell.exe", "pwsh.exe"}:
            add("T1059.001", "PowerShell", "Execution", _ev(e))
            if ENCODED_PS.search(cmd):
                add("T1027", "Obfuscated Files or Information", "Defense Evasion", f"encoded command on {e.host}")
            if DOWNLOAD_CRADLE.search(cmd):
                add("T1105", "Ingress Tool Transfer", "Command and Control", f"download cradle on {e.host}")
        if parent in OFFICE and proc in SHELLS:
            add("T1204.002", "User Execution: Malicious File", "Execution", f"{parent} spawned {proc} on {e.host}")
        if e.kind == "process_access" and _base(e.target) == "lsass.exe":
            add("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access", f"{proc} accessed lsass on {e.host}")
        if e.kind == "service_install":
            add("T1543.003", "Create or Modify System Process: Windows Service", "Persistence", f"service {e.target} on {e.host}")
        if e.kind == "account_created":
            add("T1136.001", "Create Account: Local Account", "Persistence", f"account {e.user} on {e.host}")
        if e.kind == "log_cleared":
            add("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion", f"security log cleared on {e.host}")
        if e.kind in {"network", "dns"} and ({e.domain, e.dst_ip} & malicious):
            add("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
                f"{e.host} -> {e.domain or e.dst_ip} (TI: malicious)")
    return list(found.values())


def score(events: list[Event], ti: list[TIVerdict], techniques: list[Technique],
          critical_assets: set[str], injection_flags: list[str]) -> tuple[int, Severity, list[RiskFactor]]:
    factors: list[RiskFactor] = []
    top = max((e.severity for e in events), key=lambda s: SEV_POINTS[s])
    factors.append(RiskFactor(name=f"highest event severity: {top.value}", points=SEV_POINTS[top]))

    mal = [v for v in ti if v.verdict == "malicious"]
    sus = [v for v in ti if v.verdict == "suspicious"]
    if mal:
        factors.append(RiskFactor(name="known-malicious IOCs", points=min(30, 15 * len(mal)),
                                  evidence=[f"{v.ioc.type} {v.ioc.value} ({v.source}: {v.note or v.score})" for v in mal]))
    if sus:
        factors.append(RiskFactor(name="suspicious IOCs", points=min(10, 5 * len(sus)),
                                  evidence=[f"{v.ioc.type} {v.ioc.value}" for v in sus]))
    if techniques:
        factors.append(RiskFactor(name="ATT&CK techniques observed", points=min(30, 6 * len(techniques)),
                                  evidence=[f"{t.id} {t.name}" for t in techniques]))
    tactics = sorted({t.tactic for t in techniques})
    if len(tactics) >= 3:
        factors.append(RiskFactor(name="multi-stage activity (kill-chain progression)", points=15, evidence=tactics))
    hit_assets = sorted({e.host for e in events if e.host} & critical_assets)
    if hit_assets:
        factors.append(RiskFactor(name="critical asset involved", points=15, evidence=hit_assets))
    if injection_flags:
        factors.append(RiskFactor(name="instruction-like text in telemetry (possible LLM manipulation)", points=5,
                                  evidence=injection_flags[:3]))

    total = min(100, sum(f.points for f in factors))
    level = (Severity.critical if total >= 80 else Severity.high if total >= 60 else
             Severity.medium if total >= 35 else Severity.low if total >= 15 else Severity.info)
    return total, level, factors
