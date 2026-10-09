import json

import pytest
from fastapi.testclient import TestClient

from soc_orchestrator.api import create_app


@pytest.fixture
def client(make_orch, monkeypatch):
    monkeypatch.delenv("ORCH_API_KEY", raising=False)
    return TestClient(create_app(make_orch()))


@pytest.fixture
def records(sample_lines):
    out = []
    for line in sample_lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_ingest_list_get_approve_verify(client, records):
    r = client.post("/ingest", json={"records": records})
    assert r.status_code == 200
    body = r.json()
    assert len(body["incidents"]) == 2 and body["tickets_created"] == 2
    ws = next(i for i in body["incidents"] if "ws-114" in i["title"])
    assert ws["pending_approvals"] == 2

    assert len(client.get("/incidents").json()) == 2
    inc = client.get(f"/incidents/{ws['id']}").json()
    idx = next(n for n, a in enumerate(inc["actions"]) if a["action"] == "isolate_host")

    bad = client.post(f"/incidents/{ws['id']}/actions/{idx}/approve", json={"analyst": ""})
    assert bad.status_code == 422
    ok = client.post(f"/incidents/{ws['id']}/actions/{idx}/approve", json={"analyst": "l3-lead@corp.example"})
    assert ok.status_code == 200 and ok.json()["actions"][idx]["status"] == "executed"
    again = client.post(f"/incidents/{ws['id']}/actions/{idx}/approve", json={"analyst": "l3-lead@corp.example"})
    assert again.status_code == 409

    assert client.get("/audit/verify").json()["intact"] is True


def test_not_found_and_validation(client):
    assert client.get("/incidents/nope").status_code == 404
    assert client.post("/ingest", json={"records": []}).status_code == 422
    assert client.post("/incidents/nope/actions/0/approve", json={"analyst": "abc"}).status_code == 404


def test_api_key_enforced(make_orch, monkeypatch, records):
    monkeypatch.setenv("ORCH_API_KEY", "s3cret-key")
    c = TestClient(create_app(make_orch()))
    assert c.post("/ingest", json={"records": records}).status_code == 401
    assert c.post("/ingest", json={"records": records}, headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.post("/ingest", json={"records": records}, headers={"X-API-Key": "s3cret-key"}).status_code == 200
    assert c.get("/health").status_code == 200
