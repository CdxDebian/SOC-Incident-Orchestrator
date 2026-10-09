"""Idempotent ticketing backends.

Both backends key tickets on the incident's stable correlation key, so a retried webhook,
a replayed batch or a restarted worker updates the existing ticket instead of opening a
duplicate.

  LocalTickets         SQLite only (default; no external dependency)
  GitHubIssuesTickets  GitHub Issues, de-duplicated by an `orch:<key>` label, with the
                       mapping cached locally so replays make no API calls at all
"""
from __future__ import annotations

from typing import Protocol

import httpx

from .models import Incident
from .store import Store, redact


class TicketBackend(Protocol):
    name: str

    def upsert(self, incident: Incident) -> tuple[str, bool]:
        """Return (ticket_id, created)."""
        ...


class LocalTickets:
    name = "sqlite"

    def __init__(self, store: Store) -> None:
        self.store = store

    def upsert(self, incident: Incident) -> tuple[str, bool]:
        return self.store.upsert_ticket(incident.key, incident.title, incident.risk_score)


def issue_body(incident: Incident) -> str:
    lines = [
        f"**Risk:** {incident.risk_level.value.upper()} {incident.risk_score}/100  ",
        f"**Hosts:** {', '.join(incident.hosts) or '—'}  ",
        f"**Users:** {', '.join(incident.users) or '—'}  ",
        f"**Window:** {incident.first_seen:%Y-%m-%d %H:%M} → {incident.last_seen:%H:%M} UTC · {len(incident.events)} events",
        "", "### Why this score",
        *[f"- +{f.points} {f.name}" for f in incident.risk_factors],
        "", "### ATT&CK",
        *[f"- `{t.id}` {t.name} ({t.tactic})" for t in incident.techniques],
    ]
    if incident.injection_flags:
        lines += ["", "> [!WARNING]", "> Telemetry in this incident contains text aimed at automated tooling. Treat it as hostile."]
    lines += ["", f"<!-- orchestrator-key: {incident.key} -->"]
    # Telemetry is attacker-controlled: redact secrets and neutralise @-mentions before it leaves the system.
    return redact("\n".join(lines)).replace("@", "@\u200b")


class GitHubIssuesTickets:
    name = "github-issues"

    def __init__(self, repo: str, token: str, store: Store, client: httpx.Client | None = None,
                 labels: tuple[str, ...] = ("soc-incident",)) -> None:
        if "/" not in repo:
            raise ValueError("repo must be 'owner/name'")
        self.repo, self.store, self.labels = repo, store, labels
        self.http = client or httpx.Client(base_url="https://api.github.com", timeout=10.0)
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def _key_label(self, incident: Incident) -> str:
        return f"orch:{incident.key[:16]}"

    def upsert(self, incident: Incident) -> tuple[str, bool]:
        cached = self.store.get_ticket(incident.key)
        if cached:  # replay: no API call, no duplicate
            self.store.upsert_ticket(incident.key, incident.title, incident.risk_score, ticket_id=cached)
            return cached, False

        label = self._key_label(incident)
        r = self.http.get(f"/repos/{self.repo}/issues", headers=self.headers,
                          params={"labels": label, "state": "all", "per_page": 1})
        r.raise_for_status()
        if r.json():  # local DB was lost, but the issue exists: relink, don't recreate
            ticket_id = f"GH-{r.json()[0]['number']}"
            self.store.upsert_ticket(incident.key, incident.title, incident.risk_score, ticket_id=ticket_id)
            return ticket_id, False

        r = self.http.post(f"/repos/{self.repo}/issues", headers=self.headers, json={
            "title": f"[{incident.risk_level.value.upper()} {incident.risk_score}] {incident.title}"[:250],
            "body": issue_body(incident),
            "labels": [*self.labels, label, f"severity:{incident.risk_level.value}"],
        })
        r.raise_for_status()
        ticket_id = f"GH-{r.json()['number']}"
        self.store.upsert_ticket(incident.key, incident.title, incident.risk_score, ticket_id=ticket_id)
        return ticket_id, True
