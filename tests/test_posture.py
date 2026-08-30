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
    # Timeline entries are keyed by scope identity as well as finding identity, so one
    # store can hold several clusters/scopes without them resolving each other. Reading a
    # scope back gives the bare finding keys.
    scope = store.scope_key_of("c1", "cluster-wide")
    raw = store.raw_timeline(scope=scope)
    assert raw["r2|Pod|pod-b|default"]["resolved_at"]
    assert raw["r2|Pod|pod-b|default"]["scope"] == scope


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


# --------------------------------------------------------------------------- #
# Timeline scope identity: one store, several security contexts.
#
# The index accumulates across scans and resolves whatever a scan did not re-observe.
# That is only sound within ONE context, so entries are keyed by cluster + scope and the
# resolve sweep never crosses that boundary.
# --------------------------------------------------------------------------- #
def _scoped(findings, cluster, scope, scan_id, when="2026-01-01T00:00:00+05:30",
            rules=None):
    risk = RiskScoringEngine().score(findings)
    level = ScopeLevel.NAMESPACE if scope != "cluster-wide" else ScopeLevel.CLUSTER
    ns = scope.split("/", 1)[1] if scope.startswith("namespace/") else None
    return ScanResult(
        request=ScanRequest(scope=Scope(level, namespace=ns), selector=Selector(),
                            mode=ScanMode.SYNC),
        findings=findings, risk=risk,
        resolved_rule_ids=rules if rules is not None
        else sorted({f.rule_id for f in findings}),
        counts={s.label: sum(1 for f in findings if f.severity is s) for s in Severity},
        scan_id=scan_id, cluster_name=cluster, generated_at=when)


def test_two_clusters_do_not_resolve_each_others_findings():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scoped([_f("r1", "pod-a")], "cluster-a", "cluster-wide", "a1"))
    # Cluster B has none of cluster A's findings. That is not evidence they were fixed.
    store.save(_scoped([_f("r9", "pod-z")], "cluster-b", "cluster-wide", "b1",
                       when="2026-01-02T00:00:00+05:30"))
    a = store.raw_timeline(scope=store.scope_key_of("cluster-a", "cluster-wide"))
    assert a["r1|Pod|pod-a|default"]["resolved_at"] is None


def test_two_namespaces_in_one_cluster_do_not_collide():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scoped([_f("r1", "pod-a", ns="prod")], "c1", "namespace/prod", "p1"))
    store.save(_scoped([_f("r1", "pod-a", ns="staging")], "c1", "namespace/staging", "s1",
                       when="2026-01-02T00:00:00+05:30"))
    prod = store.raw_timeline(scope=store.scope_key_of("c1", "namespace/prod"))
    staging = store.raw_timeline(scope=store.scope_key_of("c1", "namespace/staging"))
    assert prod["r1|Pod|pod-a|prod"]["resolved_at"] is None
    assert staging["r1|Pod|pod-a|staging"]["resolved_at"] is None
    assert len(store.raw_timeline()) == 2       # both live in one store, separately keyed


def test_a_finding_resolves_within_its_own_scope():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scoped([_f("r1", "pod-a"), _f("r2", "pod-b")], "c1", "cluster-wide", "s1"))
    store.save(_scoped([_f("r1", "pod-a")], "c1", "cluster-wide", "s2",
                       when="2026-01-05T00:00:00+05:30", rules=["r1", "r2"]))
    tl = store.raw_timeline(scope=store.scope_key_of("c1", "cluster-wide"))
    assert tl["r2|Pod|pod-b|default"]["resolved_at"]
    assert tl["r1|Pod|pod-a|default"]["resolved_at"] is None


def test_previous_scan_resolution_matches_scope_not_just_cluster():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scoped([_f("r1", "pod-a")], "c1", "cluster-wide", "wide1"))
    store.save(_scoped([_f("r1", "pod-a", ns="prod")], "c1", "namespace/prod", "ns1",
                       when="2026-01-02T00:00:00+05:30"))
    # The newest scan is the namespace one; its predecessor must be a namespace scan of the
    # same namespace, not the cluster-wide scan (which looked at different objects).
    out = latest_change(store)
    assert out["current_scan_id"] == "ns1"
    assert out["previous_scan_id"] is None, "no earlier scan of this scope exists"
    assert out["resolved"] == []


def test_timeline_can_be_narrowed_to_one_scope():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scoped([_f("r1", "pod-a")], "c1", "cluster-wide", "a1"))
    store.save(_scoped([_f("r2", "pod-b")], "c2", "cluster-wide", "b1",
                       when="2026-01-02T00:00:00+05:30"))
    assert store.timeline()["open"] == 2
    assert store.timeline(scope=store.scope_key_of("c1", "cluster-wide"))["open"] == 1


def test_legacy_unscoped_timeline_entries_survive_and_are_never_swept():
    """A store written before scoping existed has 4-field keys. They must stay readable,
    stay visible to a scoped read, and must NOT be marked resolved by a scoped scan."""
    import json
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    legacy = {"r-old|Pod|legacy|default": {
        "rule_id": "r-old", "title": "old", "severity": "HIGH",
        "resource": "Pod/legacy (default)", "first_seen": "2025-12-01T00:00:00+05:30",
        "last_seen": "2025-12-01T00:00:00+05:30", "resolved_at": None}}
    with open(os.path.join(d, "_timeline.json"), "w", encoding="utf-8") as fh:
        json.dump(legacy, fh)
    store.save(_scoped([_f("r1", "pod-a")], "c1", "cluster-wide", "s1"))
    raw = store.raw_timeline()
    assert raw["r-old|Pod|legacy|default"]["resolved_at"] is None
    scoped = store.raw_timeline(scope=store.scope_key_of("c1", "cluster-wide"))
    assert "r-old|Pod|legacy|default" in scoped, "legacy history stays usable after upgrade"


def test_regression_detection_uses_the_scoped_timeline():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scoped([_f("r1", "pod-a")], "c1", "cluster-wide", "s1"))
    store.save(_scoped([], "c1", "cluster-wide", "s2", when="2026-01-02T00:00:00+05:30",
                       rules=["r1"]))                        # r1 fixed
    store.save(_scoped([_f("r1", "pod-a")], "c1", "cluster-wide", "s3",
                       when="2026-01-03T00:00:00+05:30"))    # and back again
    out = latest_change(store)
    assert [r["rule_id"] for r in out["regressed"]] == ["r1"]
    assert out["new"] == [], "a regression is not reported as a first-time finding"
