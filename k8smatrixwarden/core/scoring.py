"""
Risk Scoring Engine (§18.1), attack-path aware.

    finding_score = severity_weight × exploitability × blast_radius × path_multiplier
    path_multiplier = 1 + 0.25 × (distinct_tactics_on_finding − 1)     # attack-path bonus
    cluster_risk (0–10) = 10 × raw / (raw + K), raw = Σ finding_score
    security_score (0–100) = round((1 − cluster_risk/10) × 100)

The saturating normalization `raw/(raw+K)` replaces the spec's literal `/max_possible`
(undefined for an arbitrary cluster). It is monotonic, bounded, deterministic, and lets a
handful of criticals dominate, matching the rating bands below. See the "Risk Scoring Math"
section of K8sMatrixWarden-doc.html.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding

SATURATION_K = 60.0


@dataclass
class RiskResult:
    cluster_risk: float           # 0–10
    security_score: int           # 0–100
    rating: str
    rating_emoji: str
    raw: float
    #: Why the number is what it is (§7). Purely derived from the same arithmetic, no
    #: second model: which factors contributed how much raw score, and which findings
    #: dominate. Empty when nothing scored.
    explanation: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"cluster_risk": self.cluster_risk, "security_score": self.security_score,
                "rating": self.rating, "raw": self.raw,
                "explanation": self.explanation}


class RiskScoringEngine:
    def score(self, findings: list[Finding], cluster: str = "") -> RiskResult:
        """Score a scan.

        Every finding is scored, because `score` is what ranks findings in reports and
        drives the top-contributor list. But `raw` -- the number the cluster risk is
        computed from -- sums ONE finding per (rule x owning workload), not every object
        that carries the evidence.

        The reason is Kubernetes' ownership chain. A Deployment whose pod template runs as
        root produces that finding on the Deployment, on its ReplicaSets and on every Pod.
        Summing all of them made one misconfiguration contribute three times, so a cluster
        running ten replicas of a flawed workload scored as though it had ten separate
        problems. On the live scan that built the number this fix responds to, 353 of 517
        findings sat on derived objects.

        This is not a discount. Nothing is divided, no kind is hard-coded as a duplicate,
        and no finding is dropped: the representative keeps its full severity,
        exploitability, blast-radius and attack-path factors, and two genuinely separate
        workloads with the same flaw still contribute twice. What is removed is only the
        repetition of one workload's configuration across the objects Kubernetes generated
        from it.
        """
        from .workload import annotate, workload_issues
        annotate(findings, cluster)
        raw = 0.0
        for f in findings:
            if f.severity.weight == 0:      # INFO / engine errors don't move the score
                f.score = 0.0
                f.score_breakdown = {}
                continue
            path_mult = 1.0 + 0.25 * max(0, len(f.tactics) - 1)
            fscore = (f.severity.weight
                      * f.exploitability.weight
                      * f.blast_radius.weight
                      * path_mult)
            f.score = fscore
            # Same multiplication, spelled out. An analyst can reproduce `score` from these
            # four numbers by hand, which is the whole point of publishing them.
            f.score_breakdown = {
                "severity": {"label": f.severity.label, "weight": f.severity.weight},
                "exploitability": {"label": f.exploitability.label,
                                   "weight": f.exploitability.weight},
                "blast_radius": {"label": f.blast_radius.label,
                                 "weight": f.blast_radius.weight},
                "path_multiplier": {"tactics": [t.value for t in f.tactics],
                                    "weight": round(path_mult, 2)},
                "score": round(fscore, 3),
                "formula": "severity × exploitability × blast_radius × path_multiplier",
            }

        # One contributor per remediation unit. `workload_issues` picks the representative
        # (the object an operator actually edits, worst severity, highest score) and carries
        # that finding's score; it never sums the group, which would put the multiplication
        # straight back.
        issues = workload_issues(findings, cluster)
        raw = sum(i.score for i in issues)

        risk = 10.0 * raw / (raw + SATURATION_K) if raw > 0 else 0.0
        security = round((1.0 - risk / 10.0) * 100)
        rating, emoji = self._rating(risk)
        return RiskResult(round(risk, 1), security, rating, emoji, round(raw, 2),
                          explanation=self._explain(findings, issues, raw, risk))

    @staticmethod
    def _explain(findings: list[Finding], issues: list, raw: float,
                 cluster: float) -> dict:
        """Break the aggregate score down by contributor.

        The shares are computed over WORKLOAD ISSUES, because that is what `raw` sums. If
        they were computed over every resource finding they would not add up to the score
        they claim to explain, which is exactly the kind of quiet inconsistency this
        explanation exists to rule out. The resource-level totals are reported alongside so
        a reader can see how much of the raw evidence count was the ownership chain
        repeating itself.
        """
        scored = [i for i in issues if i.score > 0]
        if not scored:
            return {}

        def _share(bucket: dict) -> dict:
            return {k: {"issues": v["n"], "raw": round(v["raw"], 2),
                        "share_pct": round(100 * v["raw"] / raw, 1) if raw else 0.0}
                    for k, v in sorted(bucket.items(), key=lambda kv: -kv[1]["raw"])}

        by_sev: dict = {}
        by_tactic: dict = {}
        by_shard: dict = {}
        for issue in scored:
            for bucket, key in ((by_sev, issue.severity.label),
                                (by_shard, issue.owning_shard or "unknown")):
                entry = bucket.setdefault(key, {"n": 0, "raw": 0.0})
                entry["n"] += 1
                entry["raw"] += issue.score
            for tactic in issue.tactics:
                entry = by_tactic.setdefault(tactic, {"n": 0, "raw": 0.0})
                entry["n"] += 1
                entry["raw"] += issue.score
        top = sorted(scored, key=lambda i: i.score, reverse=True)[:10]
        derived = sum(1 for f in findings if getattr(f, "is_derived_resource", False))
        return {
            "formula": ("issue_score = severity × exploitability × blast_radius × "
                        "path_multiplier, scored once per (rule × owning workload); "
                        "cluster_risk = 10 × raw / (raw + K)"),
            "scoring_basis": "workload_issues",
            "saturation_k": SATURATION_K,
            "raw_total": round(raw, 2),
            "cluster_risk": round(cluster, 1),
            "scored_issues": len(scored),
            "resource_findings": len(findings),
            "workload_issues": len(issues),
            # How much of the resource count is one workload's configuration reported again
            # on the objects Kubernetes generated from it. Descriptive: nothing divides by it.
            "derived_resource_findings": derived,
            "by_severity": _share(by_sev),
            "by_tactic": _share(by_tactic),
            "by_shard": _share(by_shard),
            "top_contributors": [
                {"rule_id": i.rule_id, "workload": f"{i.workload_kind}/{i.workload_name}",
                 "namespace": i.namespace, "severity": i.severity.label,
                 "score": round(i.score, 2),
                 "share_pct": round(100 * i.score / raw, 1) if raw else 0.0,
                 "resource_findings": len(i.resources),
                 "resources": list(i.resources)[:5],
                 "scored_resource": i.representative,
                 "breakdown": i.score_breakdown}
                for i in top],
        }

    @staticmethod
    def _rating(cluster: float) -> tuple[str, str]:
        if cluster <= 2.0:
            return "Excellent", "🟢"
        if cluster <= 4.0:
            return "Good", "🟢"
        if cluster <= 6.0:
            return "Fair", "🟡"
        if cluster <= 8.0:
            return "Poor", "🟠"
        return "Critical", "🔴"

    @staticmethod
    def rank(findings: list[Finding]) -> list[Finding]:
        """Most-severe / highest-scoring first (for report ordering)."""
        return sorted(findings, key=lambda f: (f.severity.order, f.score), reverse=True)
