"""
Risk scoring: bounds, saturation, determinism, and the published breakdown (§7).

The scoring MODEL is deliberately unchanged, these tests pin the existing arithmetic as a
regression guard first, then check that the explanation published alongside it reproduces
that same arithmetic rather than describing a second, parallel model.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability,
                                         Finding, MitreTag, ResourceRef, Severity, Tactic)
from k8smatrixwarden.core.scoring import SATURATION_K, RiskScoringEngine


def _finding(severity=Severity.CRITICAL, exploitability=Exploitability.REMOTE,
             blast=BlastRadius.CLUSTER, tactics=(Tactic.PRIVILEGE_ESCALATION,),
             rule_id="r1", name="pod-a"):
    return Finding(
        rule_id=rule_id, title="t", severity=severity,
        resource=ResourceRef("Pod", name, "default"), message="m",
        owning_shard="workload_pod_security",
        mitre=[MitreTag(t, "T1610", "Escape") for t in tactics],
        detection_method=DetectionMethod.STATIC_CONFIG,
        exploitability=exploitability, blast_radius=blast)


# --------------------------------------------------------------------------- #
# The model itself, unchanged.
# --------------------------------------------------------------------------- #
def test_no_findings_scores_zero_and_rates_excellent():
    r = RiskScoringEngine().score([])
    assert (r.cluster_risk, r.security_score, r.rating) == (0.0, 100, "Excellent")
    assert r.explanation == {}          # nothing to explain, not a fabricated breakdown


def test_single_worst_case_finding_matches_the_documented_formula():
    f = _finding()
    r = RiskScoringEngine().score([f])
    # severity 10 × exploitability 3 × blast 3 × path 1.0 = 90
    assert f.score == 90.0
    assert r.raw == 90.0
    assert r.cluster_risk == round(10 * 90 / (90 + SATURATION_K), 1) == 6.0


def test_path_multiplier_adds_25_percent_per_extra_tactic():
    one = _finding(tactics=(Tactic.PRIVILEGE_ESCALATION,))
    three = _finding(tactics=(Tactic.PRIVILEGE_ESCALATION, Tactic.PERSISTENCE,
                              Tactic.LATERAL_MOVEMENT))
    RiskScoringEngine().score([one, three])
    assert three.score == one.score * 1.5          # 1 + 0.25 × 2


def test_info_findings_do_not_move_the_score():
    r = RiskScoringEngine().score([_finding(severity=Severity.INFO)])
    assert r.raw == 0.0 and r.cluster_risk == 0.0


def test_score_is_bounded_and_saturates():
    """Ten thousand criticals cannot exceed 10/10, and the score never goes negative."""
    many = [_finding(name=f"pod-{i}", rule_id=f"r{i}") for i in range(10000)]
    r = RiskScoringEngine().score(many)
    assert 0.0 <= r.cluster_risk <= 10.0
    assert r.cluster_risk > 9.9
    assert 0 <= r.security_score <= 100


def test_rating_bands_are_stable():
    engine = RiskScoringEngine()
    assert engine._rating(0.0)[0] == "Excellent"
    assert engine._rating(2.0)[0] == "Excellent"
    assert engine._rating(4.0)[0] == "Good"
    assert engine._rating(6.0)[0] == "Fair"
    assert engine._rating(8.0)[0] == "Poor"
    assert engine._rating(8.1)[0] == "Critical"


def test_scoring_is_deterministic():
    findings = [_finding(name=f"p{i}", rule_id=f"r{i}") for i in range(50)]
    a = RiskScoringEngine().score(findings)
    b = RiskScoringEngine().score(findings)
    assert (a.raw, a.cluster_risk, a.security_score) == (b.raw, b.cluster_risk,
                                                         b.security_score)


def test_missing_factors_fall_back_to_the_lowest_weights():
    """A finding built without exploitability/blast still scores, at the floor."""
    f = Finding(rule_id="r", title="t", severity=Severity.LOW,
                resource=ResourceRef("Pod", "p"), message="m")
    RiskScoringEngine().score([f])
    assert f.score == 1 * 1 * 1 * 1.0


# --------------------------------------------------------------------------- #
# The explanation, derived from the same numbers.
# --------------------------------------------------------------------------- #
def test_per_finding_breakdown_multiplies_back_to_the_score():
    f = _finding(tactics=(Tactic.PRIVILEGE_ESCALATION, Tactic.PERSISTENCE))
    RiskScoringEngine().score([f])
    b = f.score_breakdown
    product = (b["severity"]["weight"] * b["exploitability"]["weight"]
               * b["blast_radius"]["weight"] * b["path_multiplier"]["weight"])
    assert round(product, 3) == round(f.score, 3) == b["score"]


def test_explanation_shares_sum_to_one_hundred_percent():
    findings = [_finding(name=f"p{i}", rule_id=f"r{i}",
                         severity=s, blast=BlastRadius.POD)
                for i, s in enumerate([Severity.CRITICAL, Severity.HIGH,
                                       Severity.MEDIUM, Severity.LOW])]
    r = RiskScoringEngine().score(findings)
    total = sum(v["share_pct"] for v in r.explanation["by_severity"].values())
    assert abs(total - 100.0) < 0.5
    assert r.explanation["raw_total"] == r.raw
    assert r.explanation["scored_findings"] == 4


def test_top_contributors_are_ordered_and_carry_their_breakdown():
    findings = [_finding(severity=Severity.LOW, exploitability=Exploitability.LOCAL,
                         blast=BlastRadius.POD, name="small", rule_id="r-small"),
                _finding(name="big", rule_id="r-big")]
    r = RiskScoringEngine().score(findings)
    top = r.explanation["top_contributors"]
    assert top[0]["rule_id"] == "r-big"
    assert top[0]["score"] > top[1]["score"]
    assert top[0]["breakdown"]["severity"]["label"] == "CRITICAL"


def test_info_findings_get_no_breakdown():
    f = _finding(severity=Severity.INFO)
    RiskScoringEngine().score([f])
    assert f.score_breakdown == {}


def test_risk_explanation_round_trips_through_a_stored_report():
    from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector
    from k8smatrixwarden.core.results import ScanResult

    findings = [_finding()]
    risk = RiskScoringEngine().score(findings)
    result = ScanResult(request=ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                                            selector=Selector()),
                        findings=findings, risk=risk, resolved_rule_ids=["r1"])
    restored = ScanResult.from_dict(result.as_dict())
    assert restored.risk.explanation["raw_total"] == risk.explanation["raw_total"]
    assert restored.findings[0].score_breakdown == findings[0].score_breakdown
