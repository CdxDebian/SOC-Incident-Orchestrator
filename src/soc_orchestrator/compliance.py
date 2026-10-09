"""Compliance-evidence mapping.

Each pipeline stage produces evidence for specific controls. Attaching the mapping to every
incident means an auditor's question ("show me how you detect, analyse, contain and log
incidents") is answered by the incident record itself, not a slide.
"""
from __future__ import annotations

from .models import Incident

STAGE_CONTROLS: dict[str, dict[str, list[str]]] = {
    "detection_correlation": {
        "SOC 2": ["CC7.2 Monitors system components for anomalies"],
        "ISO 27001:2022": ["A.8.16 Monitoring activities"],
        "NIST CSF 2.0": ["DE.CM-01 Networks monitored", "DE.AE-02 Adverse events analysed"],
    },
    "triage_scoring": {
        "SOC 2": ["CC7.3 Evaluates security events to determine incidents"],
        "ISO 27001:2022": ["A.5.25 Assessment and decision on information security events"],
        "NIST CSF 2.0": ["DE.AE-04 Impact and scope estimated", "RS.AN-03 Analysis performed"],
    },
    "response_policy": {
        "SOC 2": ["CC7.4 Responds to identified incidents"],
        "ISO 27001:2022": ["A.5.26 Response to information security incidents"],
        "NIST CSF 2.0": ["RS.MA-01 Incident response plan executed", "RS.MI-01 Incidents contained"],
    },
    "ticketing": {
        "SOC 2": ["CC7.4 Responds to identified incidents"],
        "ISO 27001:2022": ["A.5.24 Incident management planning and preparation"],
        "NIST CSF 2.0": ["RS.MA-02 Incident reports triaged and validated"],
    },
    "audit_trail": {
        "SOC 2": ["CC7.5 Recovers and documents incidents", "CC4.1 Monitoring of controls"],
        "ISO 27001:2022": ["A.5.28 Collection of evidence", "A.8.15 Logging"],
        "NIST CSF 2.0": ["RS.AN-06 Actions recorded with integrity preserved"],
    },
}


def evidence_for(incident: Incident) -> dict[str, list[str]]:
    stages = ["detection_correlation", "triage_scoring", "audit_trail"]
    if incident.actions:
        stages.append("response_policy")
    if incident.ticket_id:
        stages.append("ticketing")
    merged: dict[str, list[str]] = {}
    for stage in stages:
        for framework, controls in STAGE_CONTROLS[stage].items():
            bucket = merged.setdefault(framework, [])
            bucket.extend(c for c in controls if c not in bucket)
    return merged
