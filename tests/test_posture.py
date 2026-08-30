"""
Historical posture (§16): new / resolved / persistent / regressed across scans.

The rule this module lives or dies by: nothing is called "resolved" unless the comparison
actually supports it. A narrower re-scan, or a rule that did not run, must never look like
a fix.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability,
                                         Finding, MitreTag, ResourceRef, ScanMode,
                                         ScanRequest, Scope, ScopeLevel, Selector,
                                         Severity, Tactic)
from k8smatrixwarden.core.posture import compare, finding_key, latest_change
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.results import ScanResult
from k8smatrixwarden.core.scoring import RiskScoringEngine


def _f(rule_id, name, severity=Severity.HIGH, ns="default"):
    return Finding(rule_id=rule_id, title=rule_id, severity=severity,
                   resource=ResourceRef("Pod", name, ns), message="m",
                   owning_shard="workload_pod_security",
                   mitre=[MitreTag(Tactic.PERSISTENCE, "T1525", "Implant")],
                   detection_method=DetectionMethod.STATIC_CONFIG,
                   exploitability=Exploitability.LOCAL,
                   blast_radius=BlastRadius.POD)


def _result(findings, rules=None, scan_id="s", generated_at="2026-01-01T00:00:00+05:30"):
    risk = RiskScoringEngine().score(findings)
    return ScanResult(request=ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                                          selector=Selector(), mode=ScanMode.SYNC),
                      findings=findings, risk=risk,
                      resolved_rule_ids=rules if rules is not None
                      else sorted({f.rule_id for f in findings}),
                      counts={s.label: sum(1 for f in findings if f.severity == s)
                              for s in Severity},
                      scan_id=scan_id, generated_at=generated_at,
                      cluster_name="c1")


def test_finding_identity_is_rule_plus_resource():
    assert finding_key(_f("r1", "pod-a")) == "r1|Pod|pod-a|default"
    assert finding_key(_f("r1", "pod-a")) != finding_key(_f("r1", "pod-b"))
    assert finding_key(_f("r1", "pod-a")) != finding_key(_f("r2", "pod-a"))


def test_first_scan_is_a_baseline_not_a_pile_of_regressions():
    out = compare(None, _result([_f("r1", "pod-a")]))
    assert out["previous_scan_id"] is None
    assert len(out["new"]) == 1 and out["resolved"] == []
    assert out["risk"]["direction"] == "baseline"
    assert "baseline" in out["summary"]


def test_new_resolved_and_persistent_are_separated():
    prev = _result([_f("r1", "pod-a"), _f("r2", "pod-b")], rules=["r1", "r2", "r3"])
    cur = _result([_f("r1", "pod-a"), _f("r3", "pod-c")], rules=["r1", "r2", "r3"])
    out = compare(prev, cur)
    assert [f["rule_id"] for f in out["new"]] == ["r3"]
    assert [f["rule_id"] for f in out["resolved"]] == ["r2"]
    assert [f["rule_id"] for f in out["persistent"]] == ["r1"]


def test_a_rule_that_was_not_rerun_is_not_reported_as_resolved():
    """The false-green this guard exists for: a narrower scan 'fixing' everything."""
    prev = _result([_f("r1", "pod-a"), _f("r2", "pod-b")], rules=["r1", "r2"])
    cur = _result([_f("r1", "pod-a")], rules=["r1"])       # r2 never ran this time
    out = compare(prev, cur)
    assert out["resolved"] == []
    assert [f["rule_id"] for f in out["not_rescanned"]] == ["r2"]


def test_severity_movement_on_a_persistent_finding_is_reported():
    prev = _result([_f("r1", "pod-a", Severity.MEDIUM)])
    cur = _result([_f("r1", "pod-a", Severity.CRITICAL)])
    out = compare(prev, cur)
    assert out["counts"]["CRITICAL"]["delta"] == 1
    assert out["counts"]["MEDIUM"]["delta"] == -1


def test_regression_needs_history_not_just_two_scans():
    prev = _result([])
    cur = _result([_f("r1", "pod-a")])
    without_history = compare(prev, cur)
    assert without_history["regressed"] == []

    timeline = {"r1|Pod|pod-a|default": {"first_seen": "2025-12-01",
                                         "resolved_at": "2025-12-20"}}
    with_history = compare(prev, cur, timeline=timeline)
    assert [f["rule_id"] for f in with_history["regressed"]] == ["r1"]
    # A regression is reported once, in `regressed`, not also as `new`.
    assert with_history["new"] == []


def test_risk_direction_reflects_the_score_move():
    low = _result([_f("r1", "pod-a", Severity.LOW)])
    high = _result([_f("r1", "pod-a", Severity.CRITICAL)])
    assert compare(low, high)["risk"]["direction"] == "worse"
    assert compare(high, low)["risk"]["direction"] == "better"
    assert compare(low, low)["risk"]["direction"] == "unchanged"


def test_info_findings_do_not_appear_in_posture():
    prev = _result([])
    cur = _result([_f("r1", "pod-a", Severity.INFO)])
    assert compare(prev, cur)["new"] == []


# --------------------------------------------------------------------------- #
# Through the store, ordering and cluster scoping.
# --------------------------------------------------------------------------- #
def test_latest_change_compares_against_the_previous_scan_of_the_same_cluster():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_result([_f("r1", "pod-a")], scan_id="older",
                       generated_at="2026-01-01T00:00:00+05:30"))
    other = _result([_f("r9", "pod-z")], scan_id="other-cluster",
                    generated_at="2026-01-02T00:00:00+05:30")
    other.cluster_name = "c2"
    store.save(other)
    store.save(_result([_f("r1", "pod-a"), _f("r2", "pod-b")], scan_id="newer",
                       generated_at="2026-01-03T00:00:00+05:30"))

    out = latest_change(store)
    assert out["current_scan_id"] == "newer"
    assert out["previous_scan_id"] == "older"          # c2's scan is not comparable
    assert [f["rule_id"] for f in out["new"]] == ["r2"]


def test_latest_change_on_an_empty_store_is_empty_not_an_error():
    assert latest_change(ReportStore(tempfile.mkdtemp())) == {}


def test_report_ordering_is_stable_for_same_second_scans():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    stamp = "2026-01-01T00:00:00+05:30"
    for sid in ("bbb", "aaa", "ccc"):
        store.save(_result([_f("r1", "pod-a")], scan_id=sid, generated_at=stamp))
    order = [r.scan_id for r in store.list()]
    assert order == sorted(order, reverse=True)
    assert order == [r.scan_id for r in ReportStore(d).list()]


def test_timeline_tracks_open_and_resolved_findings():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_result([_f("r1", "pod-a"), _f("r2", "pod-b")], scan_id="s1",
                       generated_at="2026-01-01T00:00:00+05:30"))
    store.save(_result([_f("r1", "pod-a")], scan_id="s2",
                       generated_at="2026-01-05T00:00:00+05:30"))
    tl = store.timeline()
    assert tl["open"] == 1 and tl["resolved"] == 1
    assert tl["oldest_open_days"] == 4.0
    raw = store.raw_timeline()
    assert raw["r2|Pod|pod-b|default"]["resolved_at"]


def test_posture_history_tool_matches_the_module():
    from k8smatrixwarden.mcp.server import build_tools
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_result([_f("r1", "pod-a")], scan_id="s1",
                       generated_at="2026-01-01T00:00:00+05:30"))
    store.save(_result([_f("r1", "pod-a"), _f("r2", "pod-b")], scan_id="s2",
                       generated_at="2026-01-02T00:00:00+05:30"))
    out = build_tools()["posture_history"](reports_dir=d)
    assert out["current_scan_id"] == "s2"
    assert [f["rule_id"] for f in out["new"]] == ["r2"]
    assert "timeline" in out
