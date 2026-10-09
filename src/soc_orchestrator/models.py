"""Data contracts. Everything crossing a trust boundary is validated with Pydantic."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_FIELD = 4096  # telemetry fields are truncated, never trusted to be small


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Event(BaseModel):
    """One normalised telemetry event. Every string here is attacker-influenced data."""

    model_config = ConfigDict(frozen=True)

    fingerprint: str
    ts: datetime
    source: str
    kind: str                       # auth_fail, auth_success, process, network, dns, file, ...
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    domain: str | None = None
    url: str | None = None
    process: str | None = None
    cmdline: str | None = None
    parent: str | None = None
    file_hash: str | None = None
    target: str | None = None       # e.g. lsass.exe for process-access events
    severity: Severity = Severity.low
    message: str = ""

    @field_validator("host", "user", "process", "parent", "target", mode="before")
    @classmethod
    def _lower(cls, v: Any) -> Any:
        return v.strip().lower()[:MAX_FIELD] if isinstance(v, str) and v.strip() else None


class IOC(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: str     # ip | domain | url | sha256 | sha1 | md5
    value: str


class TIVerdict(BaseModel):
    ioc: IOC
    verdict: str = "unknown"        # malicious | suspicious | benign | unknown
    score: int = 0                   # 0-100
    source: str = "none"
    note: str = ""


class RiskFactor(BaseModel):
    name: str
    points: int
    evidence: list[str] = Field(default_factory=list)


class Technique(BaseModel):
    id: str
    name: str
    tactic: str
    evidence: list[str] = Field(default_factory=list)


class Summary(BaseModel):
    """What the LLM is allowed to return. Anything else is rejected."""

    headline: str = Field(max_length=200)
    narrative: str = Field(max_length=2000)
    recommended_actions: list[str] = Field(default_factory=list, max_length=6)
    confidence: float = Field(ge=0.0, le=1.0)
    produced_by: str = "llm"


class ActionDecision(BaseModel):
    action: str
    target: str | None = None
    decision: str                    # ALLOW | REQUIRE_APPROVAL | BLOCK
    reasons: list[str]
    status: str = "pending"          # pending | executed | approved | rejected | blocked
    approved_by: str | None = None


class Incident(BaseModel):
    id: str
    key: str                         # stable correlation key -> idempotent ticketing
    title: str
    first_seen: datetime
    last_seen: datetime
    hosts: list[str]
    users: list[str]
    events: list[Event]
    iocs: list[IOC] = Field(default_factory=list)
    ti: list[TIVerdict] = Field(default_factory=list)
    techniques: list[Technique] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: Severity = Severity.low
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    injection_flags: list[str] = Field(default_factory=list)
    summary: Summary | None = None
    actions: list[ActionDecision] = Field(default_factory=list)
    ticket_id: str | None = None
    compliance: dict[str, list[str]] = Field(default_factory=dict)
