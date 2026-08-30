"""
Evidence critic (Phase 4 + Upgrade 1/3). One LLM call reviewing the draft assessment.

Returns a richer verdict, approved, confidence, missing_evidence, recommended_tools, reason, 
plus the original Phase-4 aliases (issues, recommended_actions) so older callers keep working.

Two hard rules baked in here:
  * Fail-open: any parse/format/API problem returns approved=True, a flaky critic can only ADD
    scrutiny, never block the REPL or drop an answer.
  * Low confidence never approves: confidence < 0.5 forces approved=False (Upgrade 3), so a
    self-assured-but-shaky verdict still triggers another evidence round.
"""
from __future__ import annotations

import json
import re

CRITIC_PROMPT = """Review this security assessment. Check:
1. Are findings supported by evidence from the tool results?
2. Were important validation steps skipped (runtime correlation, attack-path, drift)?
3. Is the severity justified, and is confidence in the finding warranted?
4. Are the recommendations accurate?
If evidence is insufficient, do NOT approve: list the gaps in "missing_evidence" and name the
tools that would close them in "recommended_tools". Respond with ONLY JSON:
{"approved": true|false, "confidence": 0.0-1.0, "missing_evidence": [..],
 "recommended_tools": [..], "reason": ".."}"""

_DEFAULT = {"approved": True, "confidence": 1.0, "missing_evidence": [],
            "recommended_tools": [], "reason": "", "issues": [], "recommended_actions": []}


def review(query: str, draft: str, *, client, model: str = "",
           evidence: str = "") -> dict:
    """Critique a draft assessment with whatever provider/model the operator configured.

    `client` is an `llm_provider.LLMProvider` (or a raw SDK client, which is wrapped), so
    the critic is as provider-agnostic as the loop it reviews."""
    from .llm_provider import as_provider
    content = (f"{CRITIC_PROMPT}\n\nTask: {query}\n\nEvidence / tool trace:\n{evidence}\n\n"
               f"Draft assessment:\n{draft}")
    try:
        resp = as_provider(client, model=model).chat(
            system="", messages=[{"role": "user", "content": content}],
            tools=[], max_tokens=1024)
    except Exception:
        return dict(_DEFAULT)  # fail-open, never let the critic break the run
    return _parse(resp.text)


def _parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return dict(_DEFAULT)
    try:
        d = json.loads(m.group(0))
    except (ValueError, TypeError):
        return dict(_DEFAULT)
    approved = bool(d.get("approved", True))
    # new keys, falling back to the Phase-4 names when an older critic reply is parsed.
    missing = list(d.get("missing_evidence", d.get("issues", [])))
    tools = list(d.get("recommended_tools", d.get("recommended_actions", [])))
    confidence = float(d.get("confidence", 1.0 if approved else 0.0))
    if confidence < 0.5:                     # Upgrade 3, low confidence never approves
        approved = False
    return {"approved": approved, "confidence": confidence,
            "missing_evidence": missing, "recommended_tools": tools,
            "reason": str(d.get("reason", "")),
            "issues": missing, "recommended_actions": tools}  # back-compat aliases
