import json

import pytest

from soc_orchestrator.enrich import Enricher, LocalFeedProvider
from soc_orchestrator.paths import sample_events_path, sample_feed_path
from soc_orchestrator.pipeline import Orchestrator
from soc_orchestrator.policy import ResponsePolicy, default_policy_path
from soc_orchestrator.store import Store


@pytest.fixture
def policy():
    return ResponsePolicy.load(default_policy_path())


@pytest.fixture
def sample_lines():
    return sample_events_path().read_text(encoding="utf-8").splitlines()


@pytest.fixture
def make_orch(policy):
    def _make(llm=None, store=None, responder=None):
        kw = {"responder": responder} if responder else {}
        return Orchestrator(policy, store or Store(), Enricher(LocalFeedProvider(sample_feed_path())), llm, **kw)
    return _make


class FakeLLM:
    """Scripted model: returns whatever we tell it to, so we can test the evidence boundary."""

    name = "fake-llm"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.prompts = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        r = self.responses.pop(0) if self.responses else self.responses_last
        self.responses_last = r
        if isinstance(r, Exception):
            raise r
        return r if isinstance(r, str) else json.dumps(r)


@pytest.fixture
def fake_llm():
    return FakeLLM
