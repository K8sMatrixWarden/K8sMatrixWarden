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

from dataclasses import dataclass

from .models import Finding

SATURATION_K = 60.0


@dataclass
class RiskResult:
    cluster_risk: float           # 0–10
    security_score: int           # 0–100
    rating: str
    rating_emoji: str
    raw: float


class RiskScoringEngine:
    def score(self, findings: list[Finding]) -> RiskResult:
        raw = 0.0
        for f in findings:
            if f.severity.weight == 0:      # INFO / engine errors don't move the score
                f.score = 0.0
                continue
            path_mult = 1.0 + 0.25 * max(0, len(f.tactics) - 1)
            fscore = (f.severity.weight
                      * f.exploitability.weight
                      * f.blast_radius.weight
                      * path_mult)
            f.score = fscore
            raw += fscore

        cluster = 10.0 * raw / (raw + SATURATION_K) if raw > 0 else 0.0
        security = round((1.0 - cluster / 10.0) * 100)
        rating, emoji = self._rating(cluster)
        return RiskResult(round(cluster, 1), security, rating, emoji, round(raw, 2))

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
