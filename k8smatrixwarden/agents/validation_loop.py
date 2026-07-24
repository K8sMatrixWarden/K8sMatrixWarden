"""
Critic-triggered re-run decision (Upgrade 1). Pure function, no I/O, trivially testable.

The per-round question ("is this verdict good enough to stop?") lives here. The max-round cap is
the caller's for-loop (investigate). Together: keep going while the critic is unsatisfied and
rounds remain; stop on approval or exhaustion.
"""
from __future__ import annotations


def should_continue(review: dict, minimum_confidence: float = 0.75) -> bool:
    """True if the critic's verdict warrants another evidence-gathering round."""
    if review.get("approved"):
        return False
    if review.get("missing_evidence") or review.get("recommended_tools"):
        return True
    return float(review.get("confidence", 1.0)) < minimum_confidence
