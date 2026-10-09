"""The orchestration pipeline.

    raw telemetry -> normalise & dedupe -> correlate -> TI enrichment -> ATT&CK mapping
    -> explainable risk score -> LLM summary (evidence boundary) -> policy decision
    -> execute ALLOW / queue REQUIRE_APPROVAL / refuse BLOCK -> idempotent ticket
    -> compliance evidence -> hash-chained audit at every step
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .compliance import evidence_for
from .correlate import correlate, correlation_key, iocs_for
from .enrich import Enricher
from .llm import Summarizer, scan_injection, summarize
from .models import Incident
from .normalize import normalize
from .policy import ResponsePolicy, decide
from .scoring import detect_techniques, score
from .store import Store
from .tickets import LocalTickets, TicketBackend

# A responder executes an approved/allowed action against a real system (EDR, firewall, IdP).
Responder = Callable[[str, str | None, Incident], str]


# Which technique names the incident: most damaging first.
TITLE_PRIORITY = ["T1003.001", "T1070.001", "T1071.001", "T1543.003", "T1136.001", "T1105", "T1204.002",
                  "T1059.001", "T1078", "T1110", "T1027"]


def simulated_responder(action: str, target: str | None, incident: Incident) -> str:
    return f"[simulated] {action} {target or ''}".strip()


@dataclass
class RunResult:
    incidents: list[Incident] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    duplicates: int = 0
    suppressed: int = 0
    tickets_created: int = 0
    tickets_updated: int = 0
    llm_notes: dict[str, list[str]] = field(default_factory=dict)


class Orchestrator:
    def __init__(self, policy: ResponsePolicy, store: Store, enricher: Enricher,
                 llm: Summarizer | None = None, responder: Responder = simulated_responder,
                 tickets: TicketBackend | None = None) -> None:
        self.policy, self.store, self.enricher, self.llm, self.responder = policy, store, enricher, llm, responder
        self.tickets = tickets or LocalTickets(store)

    def run(self, records: Iterable[dict[str, Any] | str]) -> RunResult:
        res = RunResult()
        ingest = normalize(records)
        res.rejected, res.duplicates = ingest.rejected, ingest.duplicates
        self.store.audit("ingest", accepted=len(ingest.events), rejected=len(ingest.rejected), duplicates=ingest.duplicates)

        for cluster in correlate(ingest.events):
            inc = self._build(cluster)
            if inc.risk_score < self.policy.ticket and not inc.techniques:
                res.suppressed += 1
                self.store.audit("suppressed_low_risk", key=inc.key, risk=inc.risk_score, events=len(cluster))
                continue
            summary, notes = summarize(inc, self.llm)
            inc.summary = summary
            res.llm_notes[inc.id] = notes
            self.store.audit("summary", incident=inc.id, produced_by=summary.produced_by, notes=notes)

            inc.actions = decide(inc, self.policy)
            previous = self.store.get_incident(inc.id)
            done = {(p.action, p.target): p for p in (previous.actions if previous else []) if p.status != "pending"}
            for a in inc.actions:
                prior = done.get((a.action, a.target))
                if prior and prior.decision == a.decision:  # replay: keep the analyst's decision, don't re-execute
                    a.status, a.approved_by = prior.status, prior.approved_by
                    if a.action == "create_ticket":
                        inc.ticket_id, created = self.tickets.upsert(inc)
                        res.tickets_updated += not created
                    continue
                self.store.audit("policy_decision", incident=inc.id, action=a.action, target=a.target,
                                 decision=a.decision, reasons=a.reasons)
                if a.decision == "ALLOW":
                    if a.action == "create_ticket":
                        inc.ticket_id, created = self.tickets.upsert(inc)
                        res.tickets_created += created
                        res.tickets_updated += not created
                        a.status = "executed"
                        self.store.audit("ticket", incident=inc.id, ticket=inc.ticket_id, created=created, backend=self.tickets.name)
                    else:
                        result = self.responder(a.action, a.target, inc)
                        a.status = "executed"
                        self.store.audit("action_executed", incident=inc.id, action=a.action, target=a.target, result=result)
            inc.compliance = evidence_for(inc)
            self.store.save_incident(inc)
            res.incidents.append(inc)
        return res

    def _build(self, cluster) -> Incident:
        key = correlation_key(cluster)
        iocs = list({(i.type, i.value): i for e in cluster for i in iocs_for(e)}.values())
        ti = self.enricher.enrich(iocs)
        techniques = detect_techniques(cluster, ti)
        inc = Incident(
            id="inc_" + key[:12], key=key, title="", first_seen=cluster[0].ts, last_seen=cluster[-1].ts,
            hosts=sorted({e.host for e in cluster if e.host}), users=sorted({e.user for e in cluster if e.user}),
            events=cluster, iocs=iocs, ti=ti, techniques=techniques)
        inc.injection_flags = scan_injection(inc)
        inc.risk_score, inc.risk_level, inc.risk_factors = score(
            cluster, ti, techniques, set(self.policy.critical_assets), inc.injection_flags)
        ranked = sorted(techniques, key=lambda t: TITLE_PRIORITY.index(t.id) if t.id in TITLE_PRIORITY else 99)
        lead = ranked[0].name if ranked else cluster[0].kind.replace("_", " ")
        inc.title = f"{lead} on {', '.join(inc.hosts[:2]) or 'unknown host'}" + (" (+more)" if len(inc.hosts) > 2 else "")
        self.store.audit("incident_built", incident=inc.id, key=key, events=len(cluster), risk=inc.risk_score,
                         factors=[f"{f.name} (+{f.points})" for f in inc.risk_factors],
                         injection_flags=inc.injection_flags)
        return inc

    # --- human in the loop -------------------------------------------------------------------
    def resolve(self, incident_id: str, index: int, analyst: str, approve: bool, note: str = "") -> Incident:
        inc = self.store.get_incident(incident_id)
        if inc is None:
            raise KeyError(incident_id)
        if not 0 <= index < len(inc.actions):
            raise IndexError(index)
        a = inc.actions[index]
        if a.decision != "REQUIRE_APPROVAL" or a.status != "pending":
            raise ValueError(f"action {index} is {a.decision}/{a.status}; only pending approvals can be resolved")
        if not analyst or not analyst.strip():
            raise ValueError("an approver identity is required")
        a.approved_by = analyst.strip()
        if approve:
            result = self.responder(a.action, a.target, inc)
            a.status = "executed"
            self.store.audit("action_approved", incident=inc.id, action=a.action, target=a.target,
                             analyst=a.approved_by, note=note, result=result)
        else:
            a.status = "rejected"
            self.store.audit("action_rejected", incident=inc.id, action=a.action, target=a.target,
                             analyst=a.approved_by, note=note)
        self.store.save_incident(inc)
        return inc
