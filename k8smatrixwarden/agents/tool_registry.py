"""
Richer tool descriptions (Phase 7). WRAPS build_tools(), never replaces it.

The LLM picks tools better with when-to-use guidance than with the bare docstring. Only a few
high-traffic tools are overridden; everything else keeps its own docstring unchanged.
"""
from __future__ import annotations

TOOL_METADATA = {
    "run_scan":
        "Primary reconnaissance + detection scan. Returns findings (rule_id, severity, "
        "resource) mapped to MITRE/OWASP/CIS. Use FIRST, before correlation or attack-path.",
    "intelligent_scan":
        "One-shot: parse a plain-English request, scan, and return findings + threat matrix + "
        "kill-chain attack path. Use for a broad opening question.",
    "correlate_runtime":
        "Join static findings to live Falco/audit events. Use AFTER a scan to VALIDATE whether "
        "a weakness is being exploited now (confirmed / corroborated / runtime-only).",
    "build_attack_path":
        "Chain a scan's hit cells into an Initial-Access -> Impact kill-chain. Use to prioritise "
        "exploitable paths and check reaches_impact.",
    "detect_drift":
        "Flag runtime behaviour that contradicts a Pod's declared posture, the strongest "
        "exploitation signal. Use to validate high-severity workload findings.",
}


def enrich_schemas(schemas: list[dict]) -> list[dict]:
    """Prepend when-to-use guidance to known tools' descriptions. Mutates and returns `schemas`."""
    for s in schemas:
        extra = TOOL_METADATA.get(s.get("name"))
        if extra:
            base = s.get("description", "")
            s["description"] = f"{extra}\n\n{base}".strip()
    return schemas
