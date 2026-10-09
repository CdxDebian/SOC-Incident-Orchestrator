# Sample run

Output of `soc-orchestrator run samples/events.jsonl` (no LLM configured, so summaries use the deterministic fallback).

```text
Ingest: 25 events in 2 incident(s) · 1 low-risk cluster(s) suppressed · 4 rejected · 1 duplicates · tickets 2 new / 0 updated
  ✗ record 29: Expecting value: line 1 column 57 (char 56)
  ✗ record 30: missing or non-string timestamp
  ✗ record 31: unknown source 'syslog'
  ✗ record 32: record is not a JSON object

──────────────────────────────────────────────────────────────────────────────
inc_34ff77968083  INC-34FF7796  [CRITICAL 100/100]
OS Credential Dumping: LSASS Memory on ws-114
hosts: ws-114   users: priya.k

Why this score:
  +20  highest event severity: high
  +30  known-malicious IOCs  ← ip 185.220.101.47 (local-feed: Tor exit node; brute-force source); url http://update-cdn.xyz/a.ps1 (local-feed: stager URL); domain update-cdn.xyz (local-feed: PowerShell stager distribution)
  + 5  suspicious IOCs  ← sha256 9f2b4c1e7a3d5b8c0e6f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
  +30  ATT&CK techniques observed  ← T1110 Brute Force; T1078 Valid Accounts; T1059.001 PowerShell
  +15  multi-stage activity (kill-chain progression)  ← Command and Control; Credential Access; Defense Evasion
  + 5  instruction-like text in telemetry (possible LLM manipulation)  ← role-override in edr.message on ws-114; verdict-tampering in edr.message on ws-114; suppression-request in edr.message on ws-114

ATT&CK:
  T1110      Brute Force  [Credential Access]
  T1078      Valid Accounts  [Initial Access]
  T1059.001  PowerShell  [Execution]
  T1027      Obfuscated Files or Information  [Defense Evasion]
  T1105      Ingress Tool Transfer  [Command and Control]
  T1204.002  User Execution: Malicious File  [Execution]
  T1071.001  Application Layer Protocol: Web Protocols  [Command and Control]
  T1003.001  OS Credential Dumping: LSASS Memory  [Credential Access]
  T1543.003  Create or Modify System Process: Windows Service  [Persistence]

⚠ Telemetry tried to talk to the AI:
  role-override in edr.message on ws-114
  verdict-tampering in edr.message on ws-114
  suppression-request in edr.message on ws-114

Summary (rules-fallback):
  15 events across ws-114 involving priya.k. Observed: T1110 (Brute Force), T1078 (Valid Accounts), T1059.001 (PowerShell), T1027 (Obfuscated Files or Information), T1105 (Ingress Tool Transfer). Known-malicious indicators: 185.220.101.47, http://update-cdn.xyz/a.ps1, update-cdn.xyz, 91.92.109.14, 8.8.8.8. Telemetry contains instruction-like text aimed at automated tooling; treat as hostile.

Response:
  [0] ✅ ALLOW            create_ticket   → executed  (risk 100 >= 15)
  [1] ✅ ALLOW            notify_oncall   → executed  (risk 100 >= 60)
  [2] ✅ ALLOW            block_ioc 185.220.101.47  → executed  (TI local-feed score 95 >= 70)
  [3] ✅ ALLOW            block_ioc update-cdn.xyz  → executed  (TI local-feed score 92 >= 70)
  [4] ✅ ALLOW            block_ioc 91.92.109.14  → executed  (TI local-feed score 88 >= 70)
  [5] ⛔ BLOCK            block_ioc 8.8.8.8  → blocked  (indicator is on the never-block list (shared or own infrastructure))
  [6] ✋ REQUIRE_APPROVAL isolate_host ws-114  → pending  (risk 100 >= 80; containment always needs a human; telemetry contains instruction-like text; decision made from rule-based facts only)
  [7] ✋ REQUIRE_APPROVAL disable_account priya.k  → pending  (risk 100 >= 70; logon after brute force (T1078); telemetry contains instruction-like text; decision made from rule-based facts only)

──────────────────────────────────────────────────────────────────────────────
inc_b31700ccebc4  INC-B31700CC  [CRITICAL 90/100]
OS Credential Dumping: LSASS Memory on dc01
hosts: dc01   users: administrator, svc_tmp

Why this score:
  +30  highest event severity: critical
  +30  ATT&CK techniques observed  ← T1110 Brute Force; T1078 Valid Accounts; T1059.001 PowerShell
  +15  multi-stage activity (kill-chain progression)  ← Credential Access; Defense Evasion; Execution
  +15  critical asset involved  ← dc01

ATT&CK:
  T1110      Brute Force  [Credential Access]
  T1078      Valid Accounts  [Initial Access]
  T1059.001  PowerShell  [Execution]
  T1027      Obfuscated Files or Information  [Defense Evasion]
  T1003.001  OS Credential Dumping: LSASS Memory  [Credential Access]
  T1136.001  Create Account: Local Account  [Persistence]
  T1070.001  Indicator Removal: Clear Windows Event Logs  [Defense Evasion]

Summary (rules-fallback):
  10 events across dc01 involving administrator, svc_tmp. Observed: T1110 (Brute Force), T1078 (Valid Accounts), T1059.001 (PowerShell), T1027 (Obfuscated Files or Information), T1003.001 (OS Credential Dumping: LSASS Memory).

Response:
  [0] ✅ ALLOW            create_ticket   → executed  (risk 90 >= 15)
  [1] ✅ ALLOW            notify_oncall   → executed  (risk 90 >= 60)
  [2] ⛔ BLOCK            isolate_host dc01  → blocked  (host is on the never-isolate list — use the major-incident process)
  [3] ⛔ BLOCK            disable_account administrator  → blocked  (protected account (break-glass/service) — never disabled automatically)

Audit trail: 26 records · chain intact
```
