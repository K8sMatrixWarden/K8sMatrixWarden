"""
Structured finding explanation (§6) and its confidence model.

The point of `explain_finding()` is that every surface gets the SAME answer, in fields
rather than prose. These tests pin the shape, and pin the two honesty rules: runtime
evidence must belong to this finding's resource, and an attack path is only reported when
one actually exists.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.explain import explain_finding, finding_confidence
from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability,
                                         Finding, MitreTag, ResourceRef, Severity, Tactic)
from k8smatrixwarden.core.scoring import RiskScoringEngine

_REQUIRED_KEYS = {"rule", "severity", "what", "why_it_matters", "resource", "evidence",
                  "reachability", "runtime_evidence", "attack_path", "standards",
                  "mitre", "scoring", "validation_steps", "confidence"}


def _finding(name="payment-api", ns="production", rule_id="workload-privileged-container"):
    f = Finding(rule_id=rule_id, title="Privileged container", severity=Severity.CRITICAL,
                resource=ResourceRef("Pod", name, ns), message="privileged: true",
                owning_shard="workload_pod_security",
                mitre=[MitreTag(Tactic.PRIVILEGE_ESCALATION, "T1610", "Escape to Host")],
                detection_method=DetectionMethod.STATIC_CONFIG,
                exploitability=Exploitability.LOCAL, blast_radius=BlastRadius.CLUSTER,
                evidence={"privileged": True})
    f.exploitable_by = ["ingress", "rbac-escalation"]
    f.path_reason = "INTERNET-REACHABLE now via NodePort Service 'api'"
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": "Pod", "name": name, "detail": ns}]
    RiskScoringEngine().score([f])
    return f


def _runtime(pod="payment-api-7c9", ns="production", level="confirmed"):
    return {"correlation": {"correlations": [
        {"tactic": "Privilege Escalation", "confidence": level,
         "correlation_level": level, "timestamp": "2026-08-30T10:00:00Z",
         "resource": pod, "namespace": ns, "reason": "resource-level match",
         "runtime": {"rule_id": "rt-container-escape", "title": "Container escape"}}]},
            "drift": {"drift": []}}


def test_explanation_has_every_section():
    out = explain_finding(_finding())
    assert _REQUIRED_KEYS <= set(out)
    assert out["severity"] == "CRITICAL"
    assert out["what"] and out["why_it_matters"]
    assert out["validation_steps"], "an analyst must be able to reproduce the finding"


def test_explanation_carries_evidence_and_resource():
    out = explain_finding(_finding())
    assert out["evidence"] == {"privileged": True}
    assert out["resource"]["kind"] == "Pod"
    assert out["resource"]["namespace"] == "production"


def test_explanation_reports_reachability_structurally():
    out = explain_finding(_finding())["reachability"]
    assert out["internet_reachable"] is True
    assert out["rbac_escalation"] is True
    assert "internet-reachable" in out["vectors"]
    assert [n["kind"] for n in out["path"]] == ["Internet", "Pod"]


def test_scoring_section_is_reproducible():
    out = explain_finding(_finding())["scoring"]
    product = (out["severity"]["weight"] * out["exploitability"]["weight"]
               * out["blast_radius"]["weight"] * out["path_multiplier"]["weight"])
    assert round(product, 3) == out["score"]


def test_runtime_evidence_matching_the_resource_is_attached():
    out = explain_finding(_finding(), runtime=_runtime())
    assert out["runtime_evidence"]["observed"] is True
    assert out["runtime_evidence"]["correlations"][0]["level"] == "confirmed"


def test_runtime_evidence_for_a_different_resource_is_not_attached():
    """The exact false-confidence trap: same namespace, different pod."""
    out = explain_finding(_finding(), runtime=_runtime(pod="unrelated-worker"))
    assert out["runtime_evidence"]["correlations"] == []
    assert out["runtime_evidence"]["observed"] is False


def test_runtime_evidence_from_another_namespace_is_not_attached():
    out = explain_finding(_finding(), runtime=_runtime(ns="staging"))
    assert out["runtime_evidence"]["correlations"] == []


def test_confirmed_runtime_evidence_raises_confidence_to_certain():
    plain = explain_finding(_finding())["confidence"]
    observed = explain_finding(_finding(), runtime=_runtime())["confidence"]
    assert observed["score"] == 1.0 and observed["label"] == "High"
    assert observed["score"] > plain["score"]
    assert any("runtime evidence" in r for r in observed["reasons"])


def test_corroborated_runtime_evidence_raises_confidence_less_than_confirmed():
    mid = explain_finding(_finding(), runtime=_runtime(level="corroborated"))["confidence"]
    high = explain_finding(_finding(), runtime=_runtime())["confidence"]
    assert mid["score"] < high["score"]


def test_node_access_requirement_lowers_confidence_and_says_why():
    class _Rule:
        confidence = "high"
        requires_node_access = True
        requires_runtime = False
        false_positive_notes = ""
        version = 2
        references = []

    out = finding_confidence(_finding(), _Rule(), None)
    assert out["score"] < 0.9
    assert any("on-node" in r for r in out["reasons"])


def test_confidence_is_bounded():
    class _Rule:
        confidence = "low"
        requires_node_access = True
        requires_runtime = False
        false_positive_notes = ""
        version = 1
        references = []

    f = Finding(rule_id="r", title="t", severity=Severity.LOW,
                resource=ResourceRef("Pod", "p"), message="m")
    assert 0.0 <= finding_confidence(f, _Rule(), None)["score"] <= 1.0


def test_attack_path_is_absent_when_the_finding_is_on_no_path():
    out = explain_finding(_finding(), attack_path={"steps": [{"tactic": "Impact"}],
                                                   "chain": "Impact"})
    assert out["attack_path"] == {}          # the finding is Privilege Escalation only


def test_attack_path_names_the_steps_the_finding_feeds():
    out = explain_finding(_finding(), attack_path={
        "steps": [{"tactic": "Privilege Escalation"}, {"tactic": "Impact"}],
        "chain": "Privilege Escalation -> Impact", "reaches_impact": True})
    assert out["attack_path"]["contributes_to"] == ["Privilege Escalation"]
    assert out["attack_path"]["reaches_impact"] is True


def test_rule_metadata_reaches_the_explanation():
    platform = build_platform()
    rule = platform.registry.rules.get("workload-privileged-container")
    out = explain_finding(_finding(), rule=rule)
    assert out["rule"]["version"] == rule.version
    assert out["rule"]["shard"] == "workload_pod_security"


def test_explanation_works_on_a_real_scan_through_mcp():
    import tempfile
    from k8smatrixwarden.mcp.server import build_tools
    d = tempfile.mkdtemp()
    tools = build_tools()
    tools["run_scan"](mock=True, reports_dir=d, save=True)
    out = tools["explain_finding"](reports_dir=d, limit=2)
    assert out["matched"] > 0
    assert _REQUIRED_KEYS <= set(out["explanations"][0])
    missing = tools["explain_finding"](reports_dir=d, rule_id="nope")
    assert "error" in missing
