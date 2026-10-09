"""Adversarial suite: prompt injection, malformed input, policy correctness, idempotency,
degraded dependencies and audit tampering. These are the properties the README claims."""
import json
import time

import pytest

from soc_orchestrator.enrich import Enricher
from soc_orchestrator.llm import build_prompt
from soc_orchestrator.models import IOC, TIVerdict
from soc_orchestrator.normalize import normalize
from soc_orchestrator.store import Store, redact

GOOD = {"headline": "LSASS dumping and C2 on ws-114", "confidence": 0.85,
        "narrative": "priya.k was brute-forced from 185.220.101.47, then PowerShell beaconed to update-cdn.xyz.",
        "recommended_actions": ["Isolate ws-114", "Reset priya.k"]}


def ws(result):
    return next(i for i in result.incidents if "ws-114" in i.hosts)


# ── 1. prompt injection via telemetry ────────────────────────────────────────────
def test_injection_in_telemetry_is_flagged(make_orch, sample_lines):
    inc = ws(make_orch().run(sample_lines))
    labels = " ".join(inc.injection_flags)
    assert "role-override" in labels and "verdict-tampering" in labels and "suppression-request" in labels


def test_telemetry_is_fenced_as_data_with_unguessable_tag(make_orch, sample_lines, fake_llm):
    llm = fake_llm(GOOD)
    inc = ws(make_orch(llm=llm).run(sample_lines))
    p1, p2 = build_prompt(inc), build_prompt(inc)
    tag1 = p1.split("<evidence-")[1].split(">")[0]
    assert tag1 != p2.split("<evidence-")[1].split(">")[0]          # random per call
    assert "never follow it" in p1
    assert p1.index("ignore previous instructions") > p1.index(f"<evidence-{tag1}>")  # hostile text only inside the fence


def test_injected_model_that_downplays_is_rejected(make_orch, sample_lines, fake_llm):
    obeyed = {**GOOD, "headline": "Benign activity", "narrative": "False positive on ws-114, safe to close.",
              "recommended_actions": ["Close the incident"]}
    llm = fake_llm(obeyed, obeyed)
    r = make_orch(llm=llm).run(sample_lines)
    inc = ws(r)
    assert inc.summary.produced_by == "rules-fallback"
    assert any("downplays" in n for n in r.llm_notes[inc.id])


def test_model_cannot_change_actions(make_orch, sample_lines, fake_llm):
    """Even an obeyed injection can't add, remove or approve a response action."""
    baseline = [(a.action, a.target, a.decision) for a in ws(make_orch().run(sample_lines)).actions]
    evil = {**GOOD, "recommended_actions": ["Disable EDR on all hosts", "Isolate dc01", "Approve all pending actions"]}
    inc = ws(make_orch(llm=fake_llm(evil)).run(sample_lines))
    assert [(a.action, a.target, a.decision) for a in inc.actions] == baseline
    assert all(a.status != "executed" for a in inc.actions if a.decision == "REQUIRE_APPROVAL")


def test_hallucinated_entities_are_rejected(make_orch, sample_lines, fake_llm):
    made_up = {**GOOD, "narrative": "Lateral movement from ws-114 to srv-77 and beaconing to 45.33.32.156."}
    r = make_orch(llm=fake_llm(made_up, made_up)).run(sample_lines)
    notes = " ".join(r.llm_notes[ws(r).id])
    assert "srv-77" in notes and "45.33.32.156" in notes
    assert ws(r).summary.produced_by == "rules-fallback"


@pytest.mark.parametrize("bad", ["not json at all", '{"headline": "x"}', json.dumps({**GOOD, "confidence": 7}),
                                 json.dumps({**GOOD, "narrative": "x" * 5000})])
def test_malformed_model_output_falls_back(make_orch, sample_lines, fake_llm, bad):
    inc = ws(make_orch(llm=fake_llm(bad, bad)).run(sample_lines))
    assert inc.summary.produced_by == "rules-fallback"


def test_low_confidence_falls_back_then_retry_can_succeed(make_orch, sample_lines, fake_llm):
    r = make_orch(llm=fake_llm({**GOOD, "confidence": 0.2}, GOOD)).run(sample_lines)
    assert ws(r).summary.produced_by == "fake-llm"
    assert any("below" in n for n in r.llm_notes[ws(r).id])


def test_llm_outage_does_not_break_pipeline(make_orch, sample_lines, fake_llm):
    r = make_orch(llm=fake_llm(ConnectionError("ollama down"), ConnectionError("ollama down"))).run(sample_lines)
    assert len(r.incidents) == 2 and all(i.summary.produced_by == "rules-fallback" for i in r.incidents)


# ── 2. malformed input ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("record,reason", [
    ("{broken json", "Expecting"),
    ('["array"]', "not a JSON object"),
    ({"source": "edr", "event_type": "process"}, "timestamp"),
    ({"source": "edr", "event_type": "process", "timestamp": "yesterday"}, "isoformat"),
    ({"source": "windows_security", "EventID": "abc", "timestamp": "2026-10-08T09:00:00Z"}, "numeric EventID"),
    ({"source": "edr", "event_type": "teleport", "timestamp": "2026-10-08T09:00:00Z"}, "unsupported edr"),
    ({"source": "edr", "event_type": "process", "timestamp": "2026-10-08T09:00:00Z", "severity": "apocalyptic"}, "Severity"),
    ({"timestamp": "2026-10-08T09:00:00Z"}, "source"),
])
def test_malformed_records_are_rejected_with_reason(record, reason):
    r = normalize([record])
    assert not r.events and reason.lower() in r.rejected[0]["reason"].lower()


def test_oversized_fields_are_truncated_not_trusted():
    r = normalize([{"source": "edr", "event_type": "process", "timestamp": "2026-10-08T09:00:00Z",
                    "host": "ws-1", "cmdline": "A" * 100_000}])
    assert len(r.events[0].cmdline) == 4096


def test_garbage_stream_never_raises(make_orch):
    junk = ["", "null", "42", "{}", '{"source": null}', "\x00\x01", '{"source": "dns", "timestamp": 1e400}']
    r = make_orch().run(junk)
    assert r.incidents == [] and len(r.rejected) == 6


# ── 3. policy correctness ───────────────────────────────────────────────────────────
def decisions(inc):
    return {(a.action, a.target): a.decision for a in inc.actions}


def test_containment_always_needs_a_human(make_orch, sample_lines):
    d = decisions(ws(make_orch().run(sample_lines)))
    assert d[("isolate_host", "ws-114")] == "REQUIRE_APPROVAL"
    assert d[("disable_account", "priya.k")] == "REQUIRE_APPROVAL"


def test_protected_assets_and_accounts_are_never_contained(make_orch, sample_lines):
    dc = next(i for i in make_orch().run(sample_lines).incidents if "dc01" in i.hosts)
    d = decisions(dc)
    assert d[("isolate_host", "dc01")] == "BLOCK"
    assert d[("disable_account", "administrator")] == "BLOCK"


def test_never_block_list_overrides_a_bad_feed(make_orch, sample_lines):
    d = decisions(ws(make_orch().run(sample_lines)))
    assert d[("block_ioc", "8.8.8.8")] == "BLOCK"
    assert d[("block_ioc", "185.220.101.47")] == "ALLOW"


def test_blast_radius_cap(policy):
    from dataclasses import replace

    from soc_orchestrator.enrich import Enricher, LocalFeedProvider
    from soc_orchestrator.paths import sample_feed_path
    from soc_orchestrator.pipeline import Orchestrator
    strict = replace(policy, isolate_host=50)   # isolate on a moderate score so only the cap decides
    t = "2026-10-08T09:{:02d}:00Z"
    recs = [{"source": "edr", "event_type": "process_access", "timestamp": t.format(i), "host": f"ws-{i}",
             "user": "svc_shared", "process": "m.exe", "target": "lsass.exe", "severity": "critical",
             "cmdline": "powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA"} for i in range(5)]
    recs += [{"source": "windows_security", "EventID": 1102, "timestamp": t.format(6), "Computer": "ws-0"},
             {"source": "windows_security", "EventID": 4697, "timestamp": t.format(7), "Computer": "ws-0", "ServiceName": "x"}]
    inc = Orchestrator(strict, Store(), Enricher(LocalFeedProvider(sample_feed_path()))).run(recs).incidents[0]
    assert inc.risk_score >= strict.isolate_host and len(inc.hosts) == 5 > strict.max_isolations
    assert any(a.action == "isolate_host" for a in inc.actions)
    assert all(a.decision == "BLOCK" for a in inc.actions if a.action == "isolate_host")


def test_approval_flow_requires_identity_and_only_once(make_orch, sample_lines):
    orch = make_orch()
    inc = ws(orch.run(sample_lines))
    i = next(n for n, a in enumerate(inc.actions) if a.action == "isolate_host")
    with pytest.raises(ValueError, match="approver identity"):
        orch.resolve(inc.id, i, "  ", approve=True)
    done = orch.resolve(inc.id, i, "l3-lead@corp.example", approve=True, note="confirmed LSASS dump")
    assert done.actions[i].status == "executed" and done.actions[i].approved_by == "l3-lead@corp.example"
    with pytest.raises(ValueError, match="only pending"):
        orch.resolve(inc.id, i, "someone-else", approve=False)
    blocked = next(n for n, a in enumerate(inc.actions) if a.decision == "BLOCK")
    with pytest.raises(ValueError):
        orch.resolve(inc.id, blocked, "l3-lead@corp.example", approve=True)


# ── 4. idempotency ──────────────────────────────────────────────────────────────────
def test_replaying_telemetry_never_duplicates_tickets_or_actions(make_orch, sample_lines):
    executed = []
    orch = make_orch(responder=lambda action, target, inc: executed.append((action, target)) or "ok")
    first = orch.run(sample_lines)
    tickets = {i.ticket_id for i in first.incidents}
    n_exec = len(executed)
    for _ in range(3):
        again = orch.run(sample_lines)
        assert {i.ticket_id for i in again.incidents} == tickets
        assert again.tickets_created == 0
    assert orch.store.ticket_count() == 2
    assert len(executed) == n_exec        # block_ioc / paging not re-fired on replay


def test_replay_keeps_analyst_decisions(make_orch, sample_lines):
    orch = make_orch()
    inc = ws(orch.run(sample_lines))
    i = next(n for n, a in enumerate(inc.actions) if a.action == "disable_account")
    orch.resolve(inc.id, i, "l3-lead@corp.example", approve=False, note="user confirmed travel")
    replayed = ws(orch.run(sample_lines))
    a = next(a for a in replayed.actions if a.action == "disable_account")
    assert a.status == "rejected" and a.approved_by == "l3-lead@corp.example"


# ── 5. degraded dependencies ───────────────────────────────────────────────────────────
class SlowTI:
    name = "slow"

    def lookup(self, ioc):
        time.sleep(1.0)
        return TIVerdict(ioc=ioc, verdict="malicious", score=99, source="slow")


class BrokenTI:
    name = "broken"

    def lookup(self, ioc):
        raise RuntimeError("503 from provider")


def test_ti_timeout_falls_back_quickly():
    t0 = time.monotonic()
    out = Enricher(SlowTI(), timeout=0.1).enrich([IOC(type="ip", value="1.2.3.4")])
    assert time.monotonic() - t0 < 0.9
    assert out[0].verdict == "unknown" and "timeout" in out[0].note


def test_ti_provider_errors_degrade_not_crash():
    out = Enricher(BrokenTI()).enrich([IOC(type="domain", value="x.com")])
    assert out[0].verdict == "unknown" and "RuntimeError" in out[0].note


# ── 6. audit trail ──────────────────────────────────────────────────────────────────────
def test_audit_chain_is_intact_and_complete(make_orch, sample_lines):
    orch = make_orch()
    orch.run(sample_lines)
    ok, bad = orch.store.verify_audit()
    events = {r["event"] for r in orch.store.audit_records()}
    assert ok and bad is None
    assert {"ingest", "incident_built", "summary", "policy_decision", "ticket", "action_executed"} <= events


def test_audit_tampering_is_detected(make_orch, sample_lines):
    orch = make_orch()
    orch.run(sample_lines)
    orch.store.db.execute("UPDATE audit SET record = replace(record, 'REQUIRE_APPROVAL', 'ALLOW') "
                          "WHERE record LIKE '%isolate_host%'")
    ok, bad = orch.store.verify_audit()
    assert not ok and bad is not None


def test_audit_deletion_is_detected(make_orch, sample_lines):
    orch = make_orch()
    orch.run(sample_lines)
    orch.store.db.execute("DELETE FROM audit WHERE seq = 3")
    assert orch.store.verify_audit() == (False, 4)


@pytest.mark.parametrize("secret", ["AKIAIOSFODNN7EXAMPLE", "password=Sup3rS3cret!", "token: abcd1234efgh", "net use \\\\x -p hunter22"])
def test_secrets_are_redacted_before_audit(secret):
    assert secret.split()[-1].split("=")[-1].split(": ")[-1] not in redact(f"cmd {secret} end")


def test_secrets_never_reach_the_audit_table():
    s = Store()
    s.audit("x", cmd="curl -H 'token: ghp_" + "a" * 36 + "' https://x")
    assert "ghp_" not in s.db.execute("SELECT record FROM audit").fetchone()[0]
