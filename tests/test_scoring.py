"""Risk scoring & attack-path bonus (§18.1)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.models import (BlastRadius, Exploitability, Finding, MitreTag,
                                ResourceRef, Severity, Tactic)
from k8smatrixwarden.core.scoring import RiskScoringEngine


def _finding(sev, tactics, expl=Exploitability.REMOTE, blast=BlastRadius.CLUSTER,
             name="x"):
    return Finding(
        rule_id="r", title="t", severity=sev,
        resource=ResourceRef("Pod", name, "ns"), message="m",
        mitre=[MitreTag(t, "T1610", "Deploy Container") for t in tactics],
        exploitability=expl, blast_radius=blast)


def test_attack_path_bonus_increases_score():
    eng = RiskScoringEngine()
    single = _finding(Severity.HIGH, [Tactic.PERSISTENCE])
    multi = _finding(Severity.HIGH, [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION,
                                     Tactic.LATERAL_MOVEMENT])
    eng.score([single])
    s1 = single.score
    eng.score([multi])
    s3 = multi.score
    # 3 tactics => path_multiplier 1.5 => 50% higher than single-tactic.
    assert abs(s3 - s1 * 1.5) < 1e-6


def test_cluster_risk_bounded_and_monotonic():
    eng = RiskScoringEngine()
    low = eng.score([_finding(Severity.LOW, [Tactic.DISCOVERY],
                              Exploitability.LOCAL, BlastRadius.POD)])
    # Twenty DISTINCT criticals. The fixture used to build twenty copies of one finding on
    # one Pod, which the aggregator would have merged before scoring ever saw them; scoring
    # now counts one contributor per (rule x owning workload), so twenty identical copies
    # correctly score as the one problem they are. Twenty real problems is what this test
    # means, so it now says so.
    high = eng.score([_finding(Severity.CRITICAL, [Tactic.PRIVILEGE_ESCALATION],
                               name=f"pod-{i}")
                      for i in range(20)])
    assert 0 <= low.cluster_risk <= 10
    assert 0 <= high.cluster_risk <= 10
    assert high.cluster_risk > low.cluster_risk
    assert high.rating == "Critical"


def test_info_findings_do_not_move_score():
    eng = RiskScoringEngine()
    res = eng.score([_finding(Severity.INFO, [Tactic.DISCOVERY])])
    assert res.cluster_risk == 0.0
    assert res.security_score == 100


def test_ranking_orders_by_severity():
    eng = RiskScoringEngine()
    fs = [_finding(Severity.MEDIUM, [Tactic.DISCOVERY]),
          _finding(Severity.CRITICAL, [Tactic.PRIVILEGE_ESCALATION]),
          _finding(Severity.LOW, [Tactic.DISCOVERY])]
    eng.score(fs)
    ranked = RiskScoringEngine.rank(fs)
    assert ranked[0].severity == Severity.CRITICAL
