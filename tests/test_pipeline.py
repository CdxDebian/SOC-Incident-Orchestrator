"""End-to-end behaviour on the bundled sample telemetry."""
from soc_orchestrator.normalize import normalize


def by_title(result, host):
    return next(i for i in result.incidents if host in i.hosts)


def test_sample_produces_two_incidents_and_suppresses_noise(make_orch, sample_lines):
    r = make_orch().run(sample_lines)
    assert len(r.incidents) == 2
    assert r.suppressed == 1          # LAPTOP-07 typo + logon
    assert r.duplicates == 1
    assert len(r.rejected) == 4


def test_workstation_intrusion_is_scored_and_explained(make_orch, sample_lines):
    inc = by_title(make_orch().run(sample_lines), "ws-114")
    assert inc.risk_level.value == "critical"
    ids = {t.id for t in inc.techniques}
    assert {"T1110", "T1078", "T1059.001", "T1027", "T1003.001", "T1071.001", "T1543.003", "T1204.002"} <= ids
    # every point in the score is accounted for by a named factor
    assert min(100, sum(f.points for f in inc.risk_factors)) == inc.risk_score
    assert all(f.name for f in inc.risk_factors)


def test_correlation_links_brute_force_logon_and_c2(make_orch, sample_lines):
    inc = by_title(make_orch().run(sample_lines), "ws-114")
    kinds = {e.kind for e in inc.events}
    assert {"auth_fail", "auth_success", "process", "dns", "network", "process_access", "service_install"} <= kinds


def test_iocs_exclude_private_ips_and_powershell_class_names(make_orch, sample_lines):
    inc = by_title(make_orch().run(sample_lines), "ws-114")
    values = {i.value for i in inc.iocs}
    assert "10.20.4.114" not in values
    assert not any("webclient" in v for v in values)
    assert {"185.220.101.47", "update-cdn.xyz", "91.92.109.14"} <= values


def test_events_are_sorted_and_normalised():
    r = normalize([
        {"source": "dns", "timestamp": "2026-10-08T10:00:00Z", "host": "WS-1", "query": "b.com"},
        {"source": "dns", "timestamp": "2026-10-08T09:00:00Z", "host": "  WS-1 ", "query": "a.com"},
    ])
    assert [e.domain for e in r.events] == ["a.com", "b.com"]
    assert {e.host for e in r.events} == {"ws-1"}
