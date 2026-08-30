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
    def score(self, findings: list[Finding]) -> RiskResult:
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
            raw += fscore

        cluster = 10.0 * raw / (raw + SATURATION_K) if raw > 0 else 0.0
        security = round((1.0 - cluster / 10.0) * 100)
        rating, emoji = self._rating(cluster)
        return RiskResult(round(cluster, 1), security, rating, emoji, round(raw, 2),
                          explanation=self._explain(findings, raw, cluster))

    @staticmethod
    def _explain(findings: list[Finding], raw: float, cluster: float) -> dict:
        """Break the aggregate score down by contributor. Deterministic and bounded:
        every number here is a share of the same `raw` sum the score itself came from."""
        scored = [f for f in findings if f.score > 0]
        if not scored:
            return {}

        def _share(bucket: dict) -> dict:
            return {k: {"findings": v["n"], "raw": round(v["raw"], 2),
                        "share_pct": round(100 * v["raw"] / raw, 1) if raw else 0.0}
                    for k, v in sorted(bucket.items(),
                                       key=lambda kv: -kv[1]["raw"])}

        by_sev: dict = {}
        by_tactic: dict = {}
        by_shard: dict = {}
        for f in scored:
            for bucket, key in ((by_sev, f.severity.label),
                                (by_shard, f.owning_shard or "unknown")):
                entry = bucket.setdefault(key, {"n": 0, "raw": 0.0})
                entry["n"] += 1
                entry["raw"] += f.score
            for tactic in f.tactics:
                entry = by_tactic.setdefault(tactic.value, {"n": 0, "raw": 0.0})
                entry["n"] += 1
                entry["raw"] += f.score
        top = sorted(scored, key=lambda f: f.score, reverse=True)[:10]
        return {
            "formula": ("finding_score = severity × exploitability × blast_radius × "
                        "path_multiplier; cluster_risk = 10 × raw / (raw + K)"),
            "saturation_k": SATURATION_K,
            "raw_total": round(raw, 2),
            "cluster_risk": round(cluster, 1),
            "scored_findings": len(scored),
            "by_severity": _share(by_sev),
            "by_tactic": _share(by_tactic),
            "by_shard": _share(by_shard),
            "top_contributors": [
                {"rule_id": f.rule_id, "resource": str(f.resource),
                 "severity": f.severity.label, "score": round(f.score, 2),
                 "share_pct": round(100 * f.score / raw, 1) if raw else 0.0,
                 "breakdown": f.score_breakdown}
                for f in top],
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
