"""Command line: run the pipeline over a JSONL file and print an analyst-friendly report.

    soc-orchestrator run samples/events.jsonl
    soc-orchestrator run samples/events.jsonl --ollama http://localhost:11434
    soc-orchestrator verify --db data/orchestrator.db
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .enrich import Enricher, LocalFeedProvider
from .llm import OllamaSummarizer
from .paths import sample_events_path, sample_feed_path
from .pipeline import Orchestrator, RunResult
from .policy import ResponsePolicy, default_policy_path
from .store import Store

ICON = {"ALLOW": "✅", "REQUIRE_APPROVAL": "✋", "BLOCK": "⛔"}


def report(r: RunResult) -> str:
    out = [f"Ingest: {sum(len(i.events) for i in r.incidents)} events in {len(r.incidents)} incident(s) · "
           f"{r.suppressed} low-risk cluster(s) suppressed · {len(r.rejected)} rejected · {r.duplicates} duplicates · "
           f"tickets {r.tickets_created} new / {r.tickets_updated} updated"]
    for rej in r.rejected:
        out.append(f"  ✗ record {rej['record']}: {rej['reason']}")
    for inc in r.incidents:
        out += ["", "─" * 78, f"{inc.id}  {inc.ticket_id or ''}  [{inc.risk_level.value.upper()} {inc.risk_score}/100]",
                f"{inc.title}", f"hosts: {', '.join(inc.hosts)}   users: {', '.join(inc.users) or '—'}", "",
                "Why this score:"]
        out += [f"  +{f.points:>2}  {f.name}" + (f"  ← {'; '.join(f.evidence[:3])}" if f.evidence else "") for f in inc.risk_factors]
        if inc.techniques:
            out += ["", "ATT&CK:"] + [f"  {t.id:<10} {t.name}  [{t.tactic}]" for t in inc.techniques]
        if inc.injection_flags:
            out += ["", "⚠ Telemetry tried to talk to the AI:"] + [f"  {f}" for f in inc.injection_flags]
        if inc.summary:
            out += ["", f"Summary ({inc.summary.produced_by}):", f"  {inc.summary.narrative}"]
        out += ["", "Response:"]
        for n, a in enumerate(inc.actions):
            out.append(f"  [{n}] {ICON[a.decision]} {a.decision:<16} {a.action} {a.target or ''}  → {a.status}  ({'; '.join(a.reasons)})")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soc-orchestrator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="process a JSONL file of telemetry")
    run.add_argument("file", nargs="?", default=str(sample_events_path()))
    run.add_argument("--db", default=":memory:")
    run.add_argument("--policy", default=str(default_policy_path()))
    run.add_argument("--ti-feed", default=str(sample_feed_path()))
    run.add_argument("--ollama", metavar="URL", help="use a local Ollama for summaries")
    run.add_argument("--model", default="llama3.2:3b")
    ver = sub.add_parser("verify", help="verify the audit hash chain")
    ver.add_argument("--db", default="data/orchestrator.db")
    a = ap.parse_args(argv)

    if a.cmd == "verify":
        ok, bad = Store(a.db).verify_audit()
        print("audit chain intact" if ok else f"audit chain BROKEN at record {bad}")
        return 0 if ok else 1

    store = Store(a.db)
    orch = Orchestrator(ResponsePolicy.load(a.policy), store, Enricher(LocalFeedProvider(a.ti_feed)),
                        OllamaSummarizer(a.model, a.ollama) if a.ollama else None)
    result = orch.run(Path(a.file).read_text(encoding="utf-8").splitlines())
    print(report(result))
    ok, _ = store.verify_audit()
    print(f"\nAudit trail: {len(store.audit_records())} records · chain {'intact' if ok else 'BROKEN'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
