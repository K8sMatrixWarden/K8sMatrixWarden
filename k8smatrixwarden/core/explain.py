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
    resource    , cluster/namespace/kind/name and the owning controller
    reachability, tags + structural hop chain + prose reason
    network     , the evaluated NetworkPolicy posture, both directions
    rbac        , the multi-hop escalation paths the RBAC graph proved
    runtime     , correlations and drift that name THIS finding's resource
    scoring     , the four factors whose product is the finding's score
    confidence  , how much to trust the conclusion, and why

The `network` and `rbac` blocks matter for a specific reason: reachability.py computes
both onto every workload finding, and before this they were serialised and then read by
nobody. A subsystem producing richer structure that a later subsystem discards is a broken
integration, not a harmless one, it means the report cannot answer "which binding grants
this?" even though the scanner worked it out.
"""
from __future__ import annotations

from typing import Optional

from .correlation import belongs_to
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

#: The project's confidence propagation policy, in one place, because five different
#: "confidence" values now exist and they answer five different questions. Collapsing them
#: into one number is how a tool ends up reporting a certain conclusion drawn from evidence
#: it never read. Enforced by tests/test_integration_pipeline.py.
CONFIDENCE_POLICY = """
Five confidences, deliberately separate:

  evidence     , per resource type: was it read, and how do we know the fraction?
                 (measured | estimated | heuristic | unknown, core/coverage.py)
  assessment   , how much of the cluster the scan saw. A function of coverage ONLY,
                 never of severity, so a bad cluster and a clean one that were both fully
                 read report the same assessment confidence.
  finding      , how much to trust THIS conclusion (core/explain.py). Starts at the rule's
                 declared detection confidence, rises with captured evidence and with
                 runtime observation, falls when the answer needs node access we lack.
  correlation  , how tightly a runtime event ties to a static finding
                 (confirmed | corroborated | runtime-only, core/correlation.py).
  path         , how strongly an attack route is evidenced
                 (configuration-only | corroborated | observed, core/attack_path.py).

The rules that keep them coherent:

  1. Nothing is more confident than the evidence under it. If a resource type could not
     be read, no claim is made about it and no confidence is assigned to the claim that
     was not made, the absence is reported instead.
  2. Only a RESOURCE-level runtime match raises a finding to certainty. Activity elsewhere
     in the namespace corroborates and is capped below certainty.
  3. A runtime event observed at one hop does NOT make a whole multi-hop path observed.
     The path records which hops were witnessed (`observed_nodes`) and states plainly that
     the remainder is configuration-derived (`fully_observed`).
  4. Confidence never changes severity, and never hides a finding. A low-confidence
     CRITICAL is still a CRITICAL to triage; it just needs verifying first.
  5. unknown and partial are values, not synonyms for false or safe. They propagate as
     themselves through coverage, NetworkPolicy, RBAC and the reports.
"""

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
        if belongs_to(pod, name):
            correlations.append({"level": c.get("confidence"),
                                 "timestamp": c.get("timestamp", ""),
                                 "tactic": c.get("tactic"),
                                 "title": (c.get("runtime") or {}).get("title"),
                                 "reason": c.get("reason", "")})
    for d in ((runtime or {}).get("drift") or {}).get("drift", []):
        pod = str(d.get("pod") or "")
        if ns and d.get("namespace") and d["namespace"] != ns:
            continue
        if belongs_to(pod, name):
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


def _rbac_block(finding: Finding) -> dict:
    """The RBAC escalation the graph proved for this finding's pod, or an explicit
    "none found". Never fabricated: these paths come straight off the graph, each edge
    naming the object it was read from."""
    paths = list(finding.rbac_paths or [])
    if not paths:
        return {"escalates": False, "paths": [], "shortest": None,
                "capabilities": [],
                "note": ("no RBAC escalation path was found for this workload's "
                         "ServiceAccount in the evidence collected")}
    shortest = min(paths, key=lambda p: p.get("hops", 99))
    return {
        "escalates": True,
        "capabilities": sorted({p.get("capability", "") for p in paths if p.get("capability")}),
        "shortest": {"capability": shortest.get("capability"),
                     "hops": shortest.get("hops"),
                     "summary": shortest.get("summary"),
                     "chain": " -> ".join(
                         f"{n.get('kind')}/{n.get('name')}"
                         for n in shortest.get("nodes", []))},
        "paths": paths,
    }


def _network_block(finding: Finding) -> dict:
    """The evaluated NetworkPolicy posture for this finding's pod.

    `status` is carried through verbatim so `partial` and `unknown` stay distinguishable
    from `restricted`: an unconfirmed restriction must never read as containment."""
    net = dict(finding.network_context or {})
    if not net:
        return {"evaluated": False,
                "note": "NetworkPolicy was not evaluated for this finding "
                        "(not a workload, or reachability did not run)"}
    ingress, egress = net.get("ingress", {}), net.get("egress", {})
    return {
        "evaluated": True,
        "ingress": ingress,
        "egress": egress,
        "ingress_status": ingress.get("status"),
        "egress_status": egress.get("status"),
        "confirmed_isolation": ingress.get("status") in ("restricted", "deny-all"),
        "policies": sorted(set(ingress.get("policies", []))
                           | set(egress.get("policies", []))),
    }


def explain_finding(finding: Finding, *, rule=None, runtime: Optional[dict] = None,
                    attack_path: Optional[dict] = None,
                    cluster: Optional[str] = None) -> dict:
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
            # Cluster is part of resource identity the moment a store holds more than one
            # cluster's scans, so it travels with the resource rather than being inferred
            # by whichever surface happens to render it.
            "cluster": cluster,
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
        "network": _network_block(finding),
        "rbac": _rbac_block(finding),
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
