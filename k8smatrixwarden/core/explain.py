"""
Structured finding explanation (§6), one shape, every surface.

Reports, the dashboard, MCP and the agent layer all need the same answer to the same ten
questions about a finding. Before this, each surface assembled its own subset out of
`finding_context` + the Finding's own fields, which is how two surfaces end up disagreeing
about what a finding means.

`explain_finding()` is the single assembler. It invents nothing: every value already
exists on the Finding, its Rule, or the shared content KB. It returns nested data, not a
pre-formatted paragraph, so a caller can render it however it likes:

    what        , rule identity, title, severity, the one-line summary
    why         , impact, standards and MITRE mappings
    evidence    , the raw fields the rule keyed on
    resource    , kind/name/namespace and the owning controller
    reachability, tags + structural hop chain + prose reason
    runtime     , correlations and drift that name THIS finding's resource
    scoring     , the four factors whose product is the finding's score
    confidence  , how much to trust the conclusion, and why
"""
from __future__ import annotations

from typing import Optional

from .finding_context import build_finding_context
from .models import Finding
from .reachability import (EXPLOIT_INGRESS, EXPLOIT_POD_PRIVILEGE,
                           EXPLOIT_RBAC_ESCALATION)

#: Human labels for the reachability vocabulary, so no surface reinvents them.
VECTOR_LABELS = {
    EXPLOIT_INGRESS: "internet-reachable",
    EXPLOIT_POD_PRIVILEGE: "post-breach only",
    EXPLOIT_RBAC_ESCALATION: "ServiceAccount can escalate to cluster-admin",
}

#: Rule-declared confidence -> its numeric floor. A rule that reads a declarative fact off
#: a spec ("privileged: true") starts high; a heuristic starts low. Runtime evidence raises
#: it, never lowers it, because observing the behaviour can only add certainty.
_RULE_CONFIDENCE = {"high": 0.8, "medium": 0.6, "low": 0.4}


def _runtime_for(finding: Finding, runtime: Optional[dict]) -> dict:
    """Runtime evidence that names THIS finding's resource.

    Deliberately strict: the same resource-level test correlation itself uses. A runtime
    event elsewhere in the namespace is not evidence about this finding, and presenting it
    as such is exactly the false confidence §8 forbids."""
    name = finding.resource.name or ""
    ns = finding.resource.namespace
    correlations, drift = [], []
    if not name:
        return {"correlations": [], "drift": [], "observed": False}
    for c in ((runtime or {}).get("correlation") or {}).get("correlations", []):
        pod = str(c.get("resource") or "")
        if not pod or (ns and c.get("namespace") and c["namespace"] != ns):
            continue
        if pod == name or pod.startswith(name + "-"):
            correlations.append({"level": c.get("confidence"),
                                 "timestamp": c.get("timestamp", ""),
                                 "tactic": c.get("tactic"),
                                 "title": (c.get("runtime") or {}).get("title"),
                                 "reason": c.get("reason", "")})
    for d in ((runtime or {}).get("drift") or {}).get("drift", []):
        pod = str(d.get("pod") or "")
        if ns and d.get("namespace") and d["namespace"] != ns:
            continue
        if pod == name or pod.startswith(name + "-"):
            drift.append({"policy": d.get("policy"), "declared": d.get("declared"),
                          "observed": d.get("observed"),
                          "timestamp": d.get("timestamp", ""),
                          "verdict": d.get("verdict", "")})
    observed = any(c["level"] == "confirmed" for c in correlations) or bool(drift)
    return {"correlations": correlations, "drift": drift, "observed": observed}


def finding_confidence(finding: Finding, rule=None,
                       runtime_block: Optional[dict] = None) -> dict:
    """How much to trust this finding, with the reasons that produced the number.

    Deterministic and bounded to [0, 1]. Confidence is about the CONCLUSION, not the
    severity: a low-confidence CRITICAL is still a CRITICAL to triage, it just needs
    verifying first."""
    declared = getattr(rule, "confidence", "high") if rule else "high"
    score = _RULE_CONFIDENCE.get(str(declared).lower(), 0.8)
    reasons = [f"rule declares {declared} detection confidence"]
    if finding.evidence:
        score += 0.1
        reasons.append("the rule captured the offending configuration as evidence")
    if runtime_block and runtime_block.get("observed"):
        score = 1.0
        reasons.append("runtime evidence names this resource (observed, not inferred)")
    elif runtime_block and runtime_block.get("correlations"):
        # Aligned behaviour is corroboration, not proof, so it lifts confidence but is
        # capped below the certainty that only a resource-level confirmation earns.
        score = min(score + 0.1, 0.9)
        reasons.append("runtime behaviour on this resource aligns with the finding "
                       "(corroborating, not confirming)")
    if rule is not None and getattr(rule, "requires_node_access", False):
        score -= 0.2
        reasons.append("a complete answer needs on-node inspection the API cannot provide")
    if rule is not None and getattr(rule, "false_positive_notes", ""):
        reasons.append(f"known false-positive pattern: {rule.false_positive_notes}")
    score = round(max(0.0, min(1.0, score)), 2)
    return {"score": score, "label": _label(score), "reasons": reasons}


def _label(score: float) -> str:
    if score >= 0.85:
        return "High"
    if score >= 0.6:
        return "Moderate"
    return "Low"


def explain_finding(finding: Finding, *, rule=None, runtime: Optional[dict] = None,
                    attack_path: Optional[dict] = None) -> dict:
    """Assemble the full structured explanation for one finding."""
    ctx = build_finding_context(finding)
    runtime_block = _runtime_for(finding, runtime)
    tactics = [t.value for t in finding.tactics]
    return {
        "rule": {
            "id": finding.rule_id,
            "version": getattr(rule, "version", None),
            "title": finding.title,
            "shard": finding.owning_shard,
            "detection_method": (finding.detection_method.value
                                 if finding.detection_method else None),
            "surface": finding.surface,
            "references": list(getattr(rule, "references", []) or []),
            "false_positive_notes": getattr(rule, "false_positive_notes", ""),
            "requires_node_access": getattr(rule, "requires_node_access", False),
            "requires_runtime": getattr(rule, "requires_runtime", False),
        },
        "severity": finding.severity.label,
        "what": ctx.summary,
        "why_it_matters": ctx.impact,
        "message": finding.message,
        "resource": {
            "kind": finding.resource.kind, "name": finding.resource.name,
            "namespace": finding.resource.namespace,
            "owner": (f"{finding.resource.owner_kind}/{finding.resource.owner_name}"
                      if finding.resource.owner_kind else None),
            "labels": dict(finding.resource.labels),
        },
        "evidence": dict(finding.evidence),
        "reachability": {
            "vectors": [VECTOR_LABELS.get(v, v) for v in finding.exploitable_by],
            "tags": list(finding.exploitable_by),
            "internet_reachable": EXPLOIT_INGRESS in finding.exploitable_by,
            "rbac_escalation": EXPLOIT_RBAC_ESCALATION in finding.exploitable_by,
            "path": list(finding.exploit_path),
            "reason": finding.path_reason,
        },
        "runtime_evidence": runtime_block,
        "attack_path": _path_for(finding, tactics, attack_path),
        "standards": [{"framework": s.framework, "control": s.control,
                       "title": s.title, "url": s.url} for s in ctx.standards],
        "mitre": [{"tactic": m.tactic, "technique_id": m.technique_id,
                   "technique_name": m.technique_name, "url": m.url}
                  for m in ctx.mitre],
        "tactics": tactics,
        "scoring": {"score": round(finding.score, 3), **finding.score_breakdown},
        "validation_steps": list(ctx.validation_steps),
        "confidence": finding_confidence(finding, rule, runtime_block),
    }


def _path_for(finding: Finding, tactics: list, attack_path: Optional[dict]) -> dict:
    """Which kill-chain steps this finding contributes to, by tactic. Empty when no path
    was derived, this never fabricates a chain for a finding that is on none."""
    if not attack_path:
        return {}
    steps = [s["tactic"] for s in attack_path.get("steps", [])
             if s["tactic"] in tactics]
    if not steps:
        return {}
    return {"chain": attack_path.get("chain", ""), "contributes_to": steps,
            "reaches_impact": attack_path.get("reaches_impact", False)}
