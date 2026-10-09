"""GitHub Issues ticketing (mocked GitHub API) and the action allowlist."""
import json
from dataclasses import replace

import httpx
import pytest

from soc_orchestrator.policy import PolicyError, ResponsePolicy, _allowlist
from soc_orchestrator.store import Store
from soc_orchestrator.tickets import GitHubIssuesTickets, issue_body


class FakeGitHub:
    """Minimal in-memory GitHub Issues API."""

    def __init__(self):
        self.issues, self.calls = [], []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        assert request.headers["authorization"] == "Bearer t0ken"
        if request.method == "GET":
            label = request.url.params["labels"]
            return httpx.Response(200, json=[i for i in self.issues if label in i["labels"]][:1])
        body = json.loads(request.content)
        issue = {"number": len(self.issues) + 1, **body}
        self.issues.append(issue)
        return httpx.Response(201, json=issue)

    def client(self):
        return httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(self.handler))


def ws(result):
    return next(i for i in result.incidents if "ws-114" in i.hosts)


def test_github_issues_created_once_and_replays_make_no_api_calls(make_orch, sample_lines):
    gh, store = FakeGitHub(), Store()
    orch = make_orch(store=store)
    orch.tickets = GitHubIssuesTickets("CdxDebian/soc-demo", "t0ken", store, client=gh.client())
    first = orch.run(sample_lines)
    assert first.tickets_created == 2 and len(gh.issues) == 2
    assert {i.ticket_id for i in first.incidents} == {"GH-1", "GH-2"}
    calls = len(gh.calls)
    again = orch.run(sample_lines)
    assert again.tickets_created == 0 and len(gh.issues) == 2 and len(gh.calls) == calls


def test_github_relinks_existing_issue_when_local_state_is_lost(make_orch, sample_lines):
    gh = FakeGitHub()
    for _ in range(2):  # second pass simulates a fresh container with an empty database
        store = Store()
        orch = make_orch(store=store)
        orch.tickets = GitHubIssuesTickets("CdxDebian/soc-demo", "t0ken", store, client=gh.client())
        orch.run(sample_lines)
    assert len(gh.issues) == 2


def test_issue_body_is_explained_redacted_and_cannot_ping_people(make_orch, sample_lines):
    inc = ws(make_orch().run(sample_lines))
    inc.risk_factors[0].name = "token: ghp_" + "a" * 36 + " cc @security-team"
    body = issue_body(inc)
    assert "Why this score" in body and "T1003.001" in body
    assert "ghp_" not in body
    assert "@security-team" not in body  # zero-width joiner after @ neutralises the mention
    assert f"orchestrator-key: {inc.key}" in body


def test_github_backend_rejects_bad_repo():
    with pytest.raises(ValueError):
        GitHubIssuesTickets("not-a-repo", "t", Store())


def test_action_not_on_allowlist_is_blocked(policy, sample_lines):
    from soc_orchestrator.enrich import Enricher, LocalFeedProvider
    from soc_orchestrator.paths import sample_feed_path
    from soc_orchestrator.pipeline import Orchestrator

    narrow = replace(policy, allowed_actions=frozenset({"create_ticket", "notify_oncall"}))
    inc = ws(Orchestrator(narrow, Store(), Enricher(LocalFeedProvider(sample_feed_path()))).run(sample_lines))
    for a in inc.actions:
        if a.action in {"block_ioc", "isolate_host", "disable_account"}:
            assert a.decision == "BLOCK" and "allowlist" in a.reasons[0]
            assert a.status == "blocked"
    assert inc.ticket_id  # allowed actions still run


def test_unknown_action_in_policy_is_refused():
    with pytest.raises(PolicyError):
        _allowlist(["create_ticket", "wipe_disk"])


def test_shipped_policy_declares_its_allowlist(policy):
    assert isinstance(policy, ResponsePolicy)
    assert policy.allowed_actions == {"create_ticket", "notify_oncall", "block_ioc", "isolate_host", "disable_account"}
