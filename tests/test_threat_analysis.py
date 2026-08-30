"""
Correlation (§8), reachability (§9), attack paths (§10) and matrix integration (§11).

These are the differentiating claims, so the tests here mostly assert what the tool must
REFUSE to say: no confirmation without a resource-level match, no severity change from
reachability, no attack step without a finding behind it, no runtime observation collapsed
into ordinary static coverage.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent
from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.correlation import correlate, detect_drift
from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability,
                                         Finding, MitreTag, ResourceRef, ScanMode,
                                         ScanRequest, Scope, ScopeLevel, Selector,
                                         Severity, Tactic)
from k8smatrixwarden.core.threat_matrix import attack_paths, build_threat_matrix


def _finding(name="web-server", ns="production", tactic=Tactic.EXECUTION):
    return Finding(rule_id="workload-privileged-container", title="Privileged container",
                   severity=Severity.CRITICAL,
                   resource=ResourceRef("Pod", name, ns), message="privileged",
                   owning_shard="workload_pod_security",
                   mitre=[MitreTag(tactic, "T1059", "Command and Scripting Interpreter")],
                   detection_method=DetectionMethod.STATIC_CONFIG,
                   exploitability=Exploitability.LOCAL,
                   blast_radius=BlastRadius.CLUSTER)


def _alerts(event):
    return RuntimeAgent().evaluate_stream([event])


def _shell(pod="web-server-abc123", ns="production", when="2026-08-30T10:00:00Z"):
    return {"source": "falco", "proc": "bash", "pod": pod, "namespace": ns, "time": when}


# --------------------------------------------------------------------------- #
# Correlation confidence tiers.
# --------------------------------------------------------------------------- #
def test_resource_level_match_confirms():
    out = correlate([_finding()], _alerts(_shell()))
    c = out["correlations"][0]
    assert c["confidence"] == "confirmed" == c["correlation_level"]
    assert out["confirmed_exploitation"] == 1
    assert "belongs to" in c["reason"]


def test_same_namespace_alone_only_corroborates():
    """A namespace collision is not proof; this is the claim the tool must not overstate."""
    out = correlate([_finding(name="payments")], _alerts(_shell(pod="unrelated-xyz")))
    c = out["correlations"][0]
    assert c["confidence"] == "corroborated"
    assert out["confirmed_exploitation"] == 0
    assert "does not match" in c["reason"]


def test_resource_match_in_a_different_namespace_does_not_confirm():
    out = correlate([_finding(ns="production")],
                    _alerts(_shell(pod="web-server-abc123", ns="staging")))
    assert out["correlations"][0]["confidence"] != "confirmed"


def test_no_static_finding_yields_runtime_only():
    out = correlate([], _alerts(_shell()))
    c = out["correlations"][0]
    assert c["confidence"] == "runtime-only" and c["static_findings"] == []
    assert out["runtime_only"] == 1


def test_tactic_mismatch_is_runtime_only_not_a_correlation():
    out = correlate([_finding(tactic=Tactic.IMPACT)], _alerts(_shell()))
    assert out["correlations"][0]["confidence"] == "runtime-only"


def test_correlation_carries_structured_context():
    c = correlate([_finding()], _alerts(_shell()))["correlations"][0]
    for key in ("timestamp", "source", "resource", "namespace", "tactic", "reason",
                "correlation_level", "related_finding"):
        assert key in c, key
    assert c["timestamp"] == "2026-08-30T10:00:00Z"
    assert c["resource"] == "web-server-abc123"
    assert c["related_finding"]["rule_id"] == "workload-privileged-container"


def test_multiple_events_are_ordered_by_time():
    events = [_shell(when="2026-08-30T10:09:00Z"),
              _shell(when="2026-08-30T10:02:00Z"),
              _shell(when="2026-08-30T10:07:00Z")]
    out = correlate([_finding()], RuntimeAgent().evaluate_stream(events))
    stamps = [c["timestamp"] for c in out["timeline"]]
    assert stamps == sorted(stamps)
    assert len(out["correlations"]) == 3


def test_events_without_a_timestamp_sort_last_and_are_not_dropped():
    out = correlate([_finding()], RuntimeAgent().evaluate_stream(
        [_shell(when=""), _shell(when="2026-08-30T10:00:00Z")]))
    assert len(out["timeline"]) == 2
    assert out["timeline"][-1]["timestamp"] == ""


def test_runtime_evidence_stays_distinguishable_from_static():
    c = correlate([_finding()], _alerts(_shell()))["correlations"][0]
    assert c["runtime"]["surface"] == "runtime"
    assert c["static_findings"][0]["rule_id"] == "workload-privileged-container"


# --------------------------------------------------------------------------- #
# Drift: runtime contradicting a declared posture.
# --------------------------------------------------------------------------- #
def _pod(name="api", ns="production", **sc):
    return {"kind": "Pod", "metadata": {"name": name, "namespace": ns},
            "spec": {"securityContext": sc,
                     "containers": [{"name": "c", "securityContext": sc}]}}


def test_drift_flags_root_despite_run_as_non_root():
    out = detect_drift([_pod(runAsNonRoot=True)],
                       [{"source": "falco", "pod": "api", "namespace": "production",
                         "uid": "0", "time": "2026-08-30T10:00:00Z"}])
    assert out["drift_count"] == 1
    d = out["drift"][0]
    assert d["policy"] == "runAsNonRoot" and d["severity"] == "CRITICAL"
    assert d["timestamp"] == "2026-08-30T10:00:00Z"


def test_drift_ignores_writes_to_allowed_paths():
    out = detect_drift([_pod(readOnlyRootFilesystem=True)],
                       [{"source": "falco", "pod": "api", "namespace": "production",
                         "op": "write", "file": "/tmp/scratch"}])
    assert out["drift_count"] == 0


def test_drift_skips_events_it_cannot_attribute_to_a_scanned_pod():
    out = detect_drift([_pod(runAsNonRoot=True)],
                       [{"source": "falco", "pod": "somewhere-else", "uid": "0"}])
    assert out["drift_count"] == 0 and out["events_seen"] == 1


# --------------------------------------------------------------------------- #
# Reachability: context, never severity.
# --------------------------------------------------------------------------- #
def _mock_scan():
    platform = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                          mode=ScanMode.SYNC)
    return platform, ScannerAgent(platform).scan(request,
                                                 platform.make_collector(mock=True))


def test_reachability_never_changes_severity():
    from k8smatrixwarden.core.reachability import annotate_reachability
    platform, result = _mock_scan()
    before = {(f.rule_id, str(f.resource)): (f.severity, f.exploitability, f.blast_radius)
              for f in result.findings}
    evidence = platform.make_collector(mock=True).collect(
        {"Pod", "Service", "Ingress", "NetworkPolicy", "ClusterRole", "Role",
         "ClusterRoleBinding", "RoleBinding"}, Scope(ScopeLevel.CLUSTER))
    annotate_reachability(result.findings, evidence)
    after = {(f.rule_id, str(f.resource)): (f.severity, f.exploitability, f.blast_radius)
             for f in result.findings}
    assert before == after


def test_workload_findings_get_a_structural_path():
    _, result = _mock_scan()
    workload = [f for f in result.findings if f.exploit_path]
    assert workload, "expected at least one workload finding with a path"
    for f in workload:
        kinds = [n["kind"] for n in f.exploit_path]
        assert kinds[0] in ("Internet", "Foothold")     # every chain has an entry point
        assert all({"kind", "name", "detail"} <= set(n) for n in f.exploit_path)
        assert f.path_reason


def test_non_workload_findings_have_no_reachability_path():
    _, result = _mock_scan()
    for f in result.findings:
        if f.resource.kind in ("ClusterRole", "ClusterRoleBinding", "ComponentConfig"):
            assert f.exploit_path == []


# --------------------------------------------------------------------------- #
# Attack path + matrix integration.
# --------------------------------------------------------------------------- #
def test_attack_path_steps_are_backed_by_findings():
    platform, result = _mock_scan()
    path = attack_paths(build_threat_matrix(result, platform.registry.rules))
    assert path["steps"], "the insecure mock cluster must produce a chain"
    for step in path["steps"]:
        assert step["supporting_findings"], f"{step['tactic']} has no finding behind it"
        for f in step["supporting_findings"]:
            assert f["rule_id"] and f["resource"]


def test_attack_path_without_runtime_is_configuration_only():
    platform, result = _mock_scan()
    path = attack_paths(build_threat_matrix(result, platform.registry.rules))
    assert path["confidence"] == "configuration-only"
    assert all(s["confidence"] == "configuration-only" for s in path["steps"])
    assert all(s["runtime_evidence"] == [] for s in path["steps"])


def test_runtime_evidence_lifts_a_step_to_observed():
    platform, result = _mock_scan()
    tactic = next(s["tactic"] for s in
                  attack_paths(build_threat_matrix(result,
                                                   platform.registry.rules))["steps"])
    runtime = {"correlation": {"correlations": [
        {"tactic": tactic, "confidence": "confirmed", "timestamp": "2026-08-30T10:00:00Z",
         "resource": "web-server-abc", "namespace": "production",
         "runtime": {"rule_id": "rt-shell-in-container", "title": "Shell"}}]},
        "drift": {"drift": []}}
    path = attack_paths(build_threat_matrix(result, platform.registry.rules), runtime)
    step = next(s for s in path["steps"] if s["tactic"] == tactic)
    assert step["confidence"] == "observed" and step["runtime_evidence"]
    assert path["confidence"] == "observed"


def test_runtime_only_alerts_do_not_evidence_a_step():
    """A runtime-only alert has no static finding, so it cannot support a chain step."""
    platform, result = _mock_scan()
    runtime = {"correlation": {"correlations": [
        {"tactic": "Execution", "confidence": "runtime-only", "timestamp": "",
         "resource": "x", "namespace": "y", "runtime": {"rule_id": "rt", "title": "t"}}]},
        "drift": {"drift": []}}
    path = attack_paths(build_threat_matrix(result, platform.registry.rules), runtime)
    assert all(s["runtime_evidence"] == [] for s in path["steps"])


def test_empty_scan_produces_no_speculative_path():
    from k8smatrixwarden.core.results import ScanResult
    from k8smatrixwarden.core.scoring import RiskScoringEngine
    platform = build_platform()
    empty = ScanResult(request=ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                                           selector=Selector()),
                       findings=[], risk=RiskScoringEngine().score([]),
                       resolved_rule_ids=[])
    path = attack_paths(build_threat_matrix(empty, platform.registry.rules))
    assert path["steps"] == [] and path["chain"] == ""
    assert path["entry_points"] == [] and path["confidence"] == "none"
    assert path["reaches_impact"] is False


def test_matrix_cells_trace_back_to_rules_findings_and_runtime():
    platform, result = _mock_scan()
    matrix = build_threat_matrix(result, platform.registry.rules)
    hit = next(c for col in matrix.columns for c in col.cells if c.hit)
    d = hit.as_dict()
    assert d["state"] == "hit" and d["finding_rule_ids"] and d["resources"]
    covered = next(c for col in matrix.columns for c in col.cells
                   if c.covered and not c.hit)
    assert covered.as_dict()["state"] == "covered" and covered.as_dict()["rule_ids"]


def test_runtime_coverage_is_not_collapsed_into_static_coverage():
    platform, result = _mock_scan()
    matrix = build_threat_matrix(result, platform.registry.rules)
    runtime_cells = [c for col in matrix.columns for c in col.cells
                     if c.covered_runtime and not c.covered]
    assert runtime_cells, "expected techniques only a runtime detection can see"
    for cell in runtime_cells:
        assert cell.state == "runtime"
        assert cell.as_dict()["runtime_rule_ids"]
    summary = matrix.summary()
    assert summary["coverage_pct_with_runtime"] > summary["coverage_pct"]


def test_matrix_summary_is_stable_across_identical_scans():
    platform, a = _mock_scan()
    _, b = _mock_scan()
    sa = build_threat_matrix(a, platform.registry.rules).summary()
    sb = build_threat_matrix(b, platform.registry.rules).summary()
    for key in ("techniques_total", "techniques_covered", "techniques_hit",
                "tactics_hit", "coverage_pct", "finding_count"):
        assert sa[key] == sb[key], key
