"""
Attack-path layers (core/attack_path.py): tactic adjacency vs evidence-backed causality.

The distinction under test: two findings sharing a tactic are NOT connected, while two
findings on the same reachability chain are. Runtime evidence may strengthen a path that
already exists; it may never invent one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.attack_path import (CONFIG_ONLY, CORROBORATED, OBSERVED,
                                              path_confidence, resource_paths)
from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability,
                                         Finding, MitreTag, ResourceRef, Severity, Tactic)


def _f(rule_id="r", name="api", ns="prod", severity=Severity.HIGH, path=None):
    f = Finding(rule_id=rule_id, title=rule_id, severity=severity,
                resource=ResourceRef("Pod", name, ns), message="m",
                owning_shard="workload_pod_security",
                mitre=[MitreTag(Tactic.PERSISTENCE, "T1525", "Implant")],
                detection_method=DetectionMethod.STATIC_CONFIG,
                exploitability=Exploitability.LOCAL, blast_radius=BlastRadius.POD)
    f.exploit_path = path if path is not None else _chain(name, ns)
    return f


def _chain(name="api", ns="prod", internet=True):
    head = ({"kind": "Internet", "name": "external", "detail": "reachable from outside"}
            if internet else
            {"kind": "Foothold", "name": "compromised pod", "detail": "no external route"})
    return [head,
            {"kind": "Service", "name": "NodePort Service 'api-svc'", "detail": "route"},
            {"kind": "Pod", "name": name, "detail": ns}]


def _runtime(correlations=(), drift=()):
    return {"correlation": {"correlations": list(correlations)},
            "drift": {"drift": list(drift)}}


# --------------------------------------------------------------------------- #
# Grouping and structure
# --------------------------------------------------------------------------- #
def test_findings_on_the_same_chain_collapse_into_one_path():
    paths = resource_paths([_f("r1"), _f("r2"), _f("r3")])
    assert len(paths) == 1
    assert [s["rule_id"] for s in paths[0]["supporting_findings"]] == ["r1", "r2", "r3"]


def test_different_workloads_are_different_paths():
    paths = resource_paths([_f("r1", name="api"), _f("r2", name="worker")])
    assert len(paths) == 2


def test_steps_carry_node_type_relationship_and_reason():
    step = resource_paths([_f()])[0]["steps"]
    assert [s["node_type"] for s in step] == ["Internet", "Service", "Pod"]
    assert step[0]["relationship"] == "entry"
    assert step[1]["relationship"] == "reaches"
    assert all("reason" in s and "confidence" in s for s in step)


def test_findings_without_a_chain_produce_no_path():
    assert resource_paths([_f(path=[])]) == []
    assert resource_paths([_f(path=[{"kind": "Pod", "name": "x", "detail": ""}])]) == []


def test_internet_entry_is_distinguished_from_a_foothold():
    external = resource_paths([_f(path=_chain(internet=True))])[0]
    internal = resource_paths([_f(name="w", path=_chain("w", internet=False))])[0]
    assert external["internet_reachable"] is True
    assert internal["internet_reachable"] is False
    assert "Post-breach" in internal["summary"]


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #
def test_no_runtime_evidence_is_configuration_only():
    paths = resource_paths([_f()])
    assert paths[0]["confidence"] == CONFIG_ONLY
    assert paths[0]["runtime_evidence"] == []
    assert path_confidence(paths) == CONFIG_ONLY


def test_confirmed_event_naming_the_pod_makes_the_path_observed():
    runtime = _runtime([{"confidence": "confirmed", "tactic": "Persistence",
                         "resource": "api", "namespace": "prod",
                         "timestamp": "2026-01-01T00:00:00Z",
                         "runtime": {"rule_id": "rt-shell", "title": "shell"}}])
    paths = resource_paths([_f()], runtime)
    assert paths[0]["confidence"] == OBSERVED
    assert paths[0]["runtime_evidence"][0]["rule_id"] == "rt-shell"


def test_activity_elsewhere_in_the_namespace_only_corroborates():
    runtime = _runtime([{"confidence": "corroborated", "tactic": "Persistence",
                         "resource": "some-other-pod", "namespace": "prod",
                         "timestamp": "2026-01-01T00:00:00Z",
                         "runtime": {"rule_id": "rt-x", "title": "x"}}])
    paths = resource_paths([_f()], runtime)
    assert paths[0]["confidence"] == CORROBORATED


def test_runtime_only_alert_never_evidences_a_path():
    runtime = _runtime([{"confidence": "runtime-only", "tactic": "Persistence",
                         "resource": "api", "namespace": "prod",
                         "runtime": {"rule_id": "rt-y", "title": "y"}}])
    paths = resource_paths([_f()], runtime)
    assert paths[0]["confidence"] == CONFIG_ONLY and paths[0]["runtime_evidence"] == []


def test_unrelated_namespace_activity_does_not_touch_the_path():
    runtime = _runtime([{"confidence": "confirmed", "tactic": "Persistence",
                         "resource": "other", "namespace": "staging",
                         "runtime": {"rule_id": "rt-z", "title": "z"}}])
    paths = resource_paths([_f()], runtime)
    assert paths[0]["confidence"] == CONFIG_ONLY


def test_drift_on_the_pod_counts_as_observed():
    runtime = _runtime(drift=[{"pod": "api", "namespace": "prod", "tactic": "Persistence",
                               "verdict": "policy bypass",
                               "timestamp": "2026-01-02T00:00:00Z"}])
    assert resource_paths([_f()], runtime)[0]["confidence"] == OBSERVED


def test_conflicting_evidence_resolves_to_the_stronger_resource_level_match():
    """One event names the pod (confirmed), another only shares the namespace. The
    resource-level match wins, and the weaker one is not mixed in as if equal."""
    runtime = _runtime([
        {"confidence": "confirmed", "tactic": "Persistence", "resource": "api",
         "namespace": "prod", "timestamp": "2026-01-02T00:00:00Z",
         "runtime": {"rule_id": "rt-hit", "title": "hit"}},
        {"confidence": "corroborated", "tactic": "Persistence", "resource": "other",
         "namespace": "prod", "timestamp": "2026-01-01T00:00:00Z",
         "runtime": {"rule_id": "rt-near", "title": "near"}}])
    path = resource_paths([_f()], runtime)[0]
    assert path["confidence"] == OBSERVED
    assert [e["rule_id"] for e in path["runtime_evidence"]] == ["rt-hit"]


def test_runtime_evidence_is_ordered_by_time():
    runtime = _runtime([
        {"confidence": "confirmed", "tactic": "Persistence", "resource": "api",
         "namespace": "prod", "timestamp": "2026-01-03T00:00:00Z",
         "runtime": {"rule_id": "late", "title": "late"}},
        {"confidence": "confirmed", "tactic": "Persistence", "resource": "api",
         "namespace": "prod", "timestamp": "2026-01-01T00:00:00Z",
         "runtime": {"rule_id": "early", "title": "early"}}])
    stamps = [e["rule_id"] for e in resource_paths([_f()], runtime)[0]["runtime_evidence"]]
    assert stamps == ["early", "late"]


def test_observed_paths_sort_ahead_of_configuration_only():
    runtime = _runtime([{"confidence": "confirmed", "tactic": "Persistence",
                         "resource": "worker", "namespace": "prod",
                         "runtime": {"rule_id": "rt", "title": "t"}}])
    paths = resource_paths([_f("r1", name="api"), _f("r2", name="worker")], runtime)
    assert paths[0]["target"]["name"] == "worker"
    assert paths[0]["confidence"] == OBSERVED


# --------------------------------------------------------------------------- #
# Both layers are returned together, and neither is the other
# --------------------------------------------------------------------------- #
def test_attack_paths_returns_tactic_and_resource_layers_side_by_side():
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    from k8smatrixwarden.core.threat_matrix import attack_paths, build_threat_matrix

    platform = build_platform()
    result = ScannerAgent(platform).scan(ScanRequest(),
                                         platform.make_collector(mock=True))
    out = attack_paths(build_threat_matrix(result, platform.registry.rules))
    assert out["steps"], "tactic layer must still be produced"
    assert out["resource_paths"], "resource layer must be produced"
    assert set(out["layers"]) == {"tactic", "resource", "runtime"}
    # A resource path is a chain of real objects, not a list of tactics.
    kinds = {s["node_type"] for p in out["resource_paths"] for s in p["steps"]}
    assert kinds & {"Pod", "Service", "ServiceAccount", "Foothold", "Internet"}
    assert out["resource_confidence"] in (CONFIG_ONLY, CORROBORATED, OBSERVED)


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
