"""
Tool-result quality heuristic (Phase 5). No LLM, cheap structural checks.

Scores 0..1 and names missing information, so the orchestrator (and future tool selection) can
tell a rich result from a thin one. Persist via Memory.save_tool_quality.

ponytail: keyword-presence heuristic, not semantic. Upgrade to an LLM grader only if it
measurably mis-scores.
"""
from __future__ import annotations

import json

# tool -> signals a *good* result should mention.
_EXPECTED = {
    "run_scan": ["severity", "rule_id", "resource"],
    "intelligent_scan": ["attack_path", "threat_matrix", "findings"],
    "correlate_runtime": ["confidence", "confirmed"],
    "build_attack_path": ["steps", "reaches_impact"],
    "run_cis_benchmark": ["pass", "fail"],
}


def evaluate(tool: str, result) -> dict:
    blob = result if isinstance(result, str) else json.dumps(result, default=str)
    low = blob.lower()
    if not blob or '"error"' in low or low.startswith("error"):
        return {"tool": tool, "quality_score": 0.0,
                "missing_information": "tool returned an error or nothing",
                "recommended_followup": "re-run with corrected arguments"}
    expected = _EXPECTED.get(tool)
    if not expected:
        return {"tool": tool, "quality_score": 1.0,
                "missing_information": "", "recommended_followup": ""}
    missing = [k for k in expected if k.lower() not in low]
    score = round(1.0 - len(missing) / len(expected), 2)
    return {"tool": tool, "quality_score": score,
            "missing_information": ", ".join(missing),
            "recommended_followup": (f"gather: {', '.join(missing)}" if missing else "")}


# tool -> deeper tools to reach for when its result comes back thin (Upgrade 2).
_FOLLOWUP = {
    "run_scan": ["correlate_runtime", "build_attack_path"],
    "intelligent_scan": ["correlate_runtime"],
    "correlate_runtime": ["detect_drift"],
    "build_attack_path": ["correlate_runtime"],
    "run_cis_benchmark": ["run_scan"],
}


def evaluate_tool_result(tool_name: str, result) -> dict:
    """Richer, list-shaped view of `evaluate()` for in-loop use (Upgrade 2):
    {score, missing_information: [...], recommended_followups: [...]}. When a result is thin,
    recommend deeper tools so the agent enumerates further instead of concluding early."""
    base = evaluate(tool_name, result)
    missing = [m for m in base["missing_information"].split(", ") if m]
    followups = _FOLLOWUP.get(tool_name, []) if base["quality_score"] < 1.0 else []
    return {"score": base["quality_score"], "missing_information": missing,
            "recommended_followups": followups}
