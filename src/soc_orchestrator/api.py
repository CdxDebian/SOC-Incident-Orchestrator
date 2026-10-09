"""FastAPI service.

    uvicorn soc_orchestrator.api:create_app --factory --reload

Set ORCH_API_KEY to require an `X-API-Key` header. Set GITHUB_REPO (owner/name) and GITHUB_TOKEN
to open tickets as GitHub Issues instead of local SQLite tickets. Set OLLAMA_URL / OLLAMA_MODEL to use a
local LLM (falls back to deterministic summaries when it's unavailable), TI_FEED to point at
an offline feed, or VT_API_KEY to use VirusTotal instead.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .enrich import Enricher, LocalFeedProvider, VirusTotalProvider
from .llm import OllamaSummarizer
from .models import Incident
from .paths import sample_feed_path
from .pipeline import Orchestrator
from .policy import ResponsePolicy, default_policy_path
from .store import Store
from .tickets import GitHubIssuesTickets


class IngestRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class Resolution(BaseModel):
    analyst: str = Field(min_length=3, max_length=120)
    note: str = Field(default="", max_length=1000)


def build_orchestrator() -> Orchestrator:
    provider = (VirusTotalProvider() if os.environ.get("VT_API_KEY")
                else LocalFeedProvider(os.environ.get("TI_FEED", str(sample_feed_path()))))
    llm = (OllamaSummarizer(model=os.environ.get("OLLAMA_MODEL", "llama3.2:3b"), url=os.environ["OLLAMA_URL"])
           if os.environ.get("OLLAMA_URL") else None)
    store = Store(os.environ.get("DB_PATH", "data/orchestrator.db"))
    tickets = (GitHubIssuesTickets(os.environ["GITHUB_REPO"], os.environ["GITHUB_TOKEN"], store)
               if os.environ.get("GITHUB_REPO") and os.environ.get("GITHUB_TOKEN") else None)
    return Orchestrator(ResponsePolicy.load(os.environ.get("POLICY", str(default_policy_path()))),
                        store, Enricher(provider), llm, tickets=tickets)


def create_app(orchestrator: Orchestrator | None = None) -> FastAPI:
    app = FastAPI(title="SOC Incident Orchestrator", version=__version__)
    orch = orchestrator or build_orchestrator()
    api_key = os.environ.get("ORCH_API_KEY")

    def auth(x_api_key: str | None = Header(default=None)) -> None:
        if api_key and not (x_api_key and hmac.compare_digest(x_api_key, api_key)):
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "llm": orch.llm.name if orch.llm else "rules-fallback",
                "tickets": orch.tickets.name}

    @app.post("/ingest", dependencies=[Depends(auth)])
    def ingest(req: IngestRequest) -> dict:
        r = orch.run(req.records)
        return {
            "incidents": [{"id": i.id, "title": i.title, "risk_score": i.risk_score, "risk_level": i.risk_level,
                           "ticket": i.ticket_id, "pending_approvals": sum(a.status == "pending" and a.decision == "REQUIRE_APPROVAL" for a in i.actions)}
                          for i in r.incidents],
            "rejected": r.rejected, "duplicates": r.duplicates,
            "tickets_created": r.tickets_created, "tickets_updated": r.tickets_updated,
        }

    @app.get("/incidents", dependencies=[Depends(auth)])
    def incidents() -> list[dict]:
        return [{"id": i.id, "title": i.title, "risk_score": i.risk_score, "risk_level": i.risk_level,
                 "ticket": i.ticket_id, "last_seen": i.last_seen} for i in orch.store.list_incidents()]

    @app.get("/incidents/{incident_id}", dependencies=[Depends(auth)])
    def incident(incident_id: str) -> Incident:
        inc = orch.store.get_incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        return inc

    def _resolve(incident_id: str, index: int, body: Resolution, approve: bool) -> Incident:
        try:
            return orch.resolve(incident_id, index, body.analyst, approve, body.note)
        except KeyError:
            raise HTTPException(404, "incident not found") from None
        except IndexError:
            raise HTTPException(404, "action not found") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/incidents/{incident_id}/actions/{index}/approve", dependencies=[Depends(auth)])
    def approve(incident_id: str, index: int, body: Resolution) -> Incident:
        return _resolve(incident_id, index, body, True)

    @app.post("/incidents/{incident_id}/actions/{index}/reject", dependencies=[Depends(auth)])
    def reject(incident_id: str, index: int, body: Resolution) -> Incident:
        return _resolve(incident_id, index, body, False)

    @app.get("/audit/verify", dependencies=[Depends(auth)])
    def verify() -> dict:
        ok, bad = orch.store.verify_audit()
        return {"intact": ok, "first_bad_record": bad, "records": len(orch.store.audit_records())}

    return app

