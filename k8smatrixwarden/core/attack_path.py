"""
Resource-level attack paths, the causal layer under the tactic chain.

The threat matrix answers "which tactics can an attacker string together in this cluster?"
That is the ATT&CK-navigator view and it stays exactly as it was. It is deliberately NOT a
claim of causality: two findings sharing a tactic are not connected by anything except the
label, and pretending otherwise is how a scanner starts inventing attack chains.

This module adds the layer that IS causal, and only where the cluster's own objects
establish the link:

    tactic-level    , tactics with hit cells, in kill-chain order   (core/threat_matrix.py)
    resource-level  , Internet -> Service -> Pod -> ServiceAccount -> RoleBinding -> Role
                       -> privilege, every hop read off a real object   (this module)
    runtime-observed, a resource-level path whose own resource was named by a runtime event

Every edge already exists before this module runs: reachability computed the network hops
from Services/Ingresses/NetworkPolicies, and the RBAC graph computed the identity hops from
bindings and roles. Nothing new is inferred here, paths are grouped, deduplicated, joined
to the findings that put them there, and graded by how strongly they are evidenced.

Grading is the same three-state vocabulary the tactic layer uses, so the two can be read
together:

    configuration-only , the configuration makes this path possible; nothing was observed
    corroborated       , runtime activity matches the path's namespace and tactic, but no
                          event named this path's own resource
    observed           , a runtime event named THIS path's resource

A runtime event with no static path stays out entirely: it is reported as runtime-only
correlation, and it never manufactures a path of its own.
"""
from __future__ import annotations

from typing import Optional

CONFIG_ONLY, CORROBORATED, OBSERVED = ("configuration-only", "corroborated", "observed")
_RANK = {CONFIG_ONLY: 0, CORROBORATED: 1, OBSERVED: 2}

#: Node kinds that mean the chain starts outside the cluster. Anything else is an
#: assume-breach entry (the attacker already has a foothold), which is a materially weaker
#: claim and is labelled as such rather than being dropped.
_EXTERNAL_ENTRY = {"Internet"}


def _signature(path: list) -> tuple:
    return tuple((n.get("kind", ""), n.get("name", "")) for n in path)


def _runtime_index(runtime: Optional[dict]) -> tuple:
    """(resource-level hits, namespace/tactic-level hits) drawn from a scan's runtime block.

    Resource hits are keyed by the pod/workload name a `confirmed` correlation or a drift
    finding named. Namespace hits are the weaker signal: something happened in that
    namespace, which corroborates but does not confirm.
    """
    by_resource: dict[str, list] = {}
    by_namespace: dict[str, list] = {}
    for c in ((runtime or {}).get("correlation") or {}).get("correlations", []):
        level = c.get("confidence")
        if level == "runtime-only":
            continue                     # no static finding behind it: never evidences a path
        entry = {"level": level, "timestamp": c.get("timestamp", ""),
                 "source": (c.get("runtime") or {}).get("source", ""),
                 "rule_id": (c.get("runtime") or {}).get("rule_id"),
                 "title": (c.get("runtime") or {}).get("title"),
                 "tactic": c.get("tactic", ""), "resource": c.get("resource", ""),
                 "namespace": c.get("namespace", "")}
        if level == "confirmed" and c.get("resource"):
            by_resource.setdefault(c["resource"], []).append(entry)
        if c.get("namespace"):
            by_namespace.setdefault(c["namespace"], []).append(entry)
    for d in ((runtime or {}).get("drift") or {}).get("drift", []):
        entry = {"level": "drift", "timestamp": d.get("timestamp", ""), "source": "drift",
                 "rule_id": "drift", "title": d.get("verdict", ""),
                 "tactic": d.get("tactic", ""), "resource": d.get("pod", ""),
                 "namespace": d.get("namespace", "")}
        if d.get("pod"):
            by_resource.setdefault(d["pod"], []).append(entry)
        if d.get("namespace"):
            by_namespace.setdefault(d["namespace"], []).append(entry)
    return by_resource, by_namespace


def _pod_name(nodes: list) -> str:
    """The workload node in a reachability chain, which is the resource a runtime event
    would name. Reachability always places it directly after the entry hop."""
    for node in nodes:
        if node.get("kind") not in ("Internet", "Service", "Foothold"):
            return node.get("name", "")
    return ""


def resource_paths(findings: list, runtime: Optional[dict] = None,
                   limit: int = 25) -> list[dict]:
    """Group findings into deduplicated, evidence-backed resource-level paths.

    Findings that share the same hop chain describe the same route into the same workload,
    so they collapse into one path carrying all of them. Paths are ordered worst-first: the
    strongest evidence, then internet-reachable, then the severity behind them.
    """
    by_resource, by_namespace = _runtime_index(runtime)
    groups: dict[tuple, dict] = {}

    for f in findings:
        path = list(getattr(f, "exploit_path", []) or [])
        if len(path) < 2:
            continue                    # not a chain: nothing causal to report
        sig = _signature(path)
        group = groups.setdefault(sig, {
            "nodes": [dict(n) for n in path],
            "namespace": f.resource.namespace,
            "findings": [],
        })
        group["findings"].append(f)

    out = []
    for group in groups.values():
        nodes = group["nodes"]
        pod = _pod_name(nodes)
        observed = by_resource.get(pod, [])
        corroborating = [] if observed else by_namespace.get(group["namespace"] or "", [])
        confidence = (OBSERVED if observed
                      else CORROBORATED if corroborating else CONFIG_ONLY)
        supporting = sorted(group["findings"],
                            key=lambda f: (f.severity.order, f.score), reverse=True)
        worst = supporting[0]
        internet = nodes[0].get("kind") in _EXTERNAL_ENTRY
        out.append({
            "layer": "resource",
            "entry_point": dict(nodes[0]),
            "target": dict(nodes[-1]),
            "namespace": group["namespace"],
            "internet_reachable": internet,
            "steps": [_step(nodes, i, supporting, observed or corroborating, confidence)
                      for i in range(len(nodes))],
            "supporting_findings": [{
                "rule_id": f.rule_id, "title": f.title, "severity": f.severity.label,
                "resource": str(f.resource)} for f in supporting[:20]],
            "runtime_evidence": sorted(observed or corroborating,
                                       key=lambda e: e.get("timestamp", "")),
            "worst_severity": worst.severity.label,
            "confidence": confidence,
            "summary": _summary(nodes, confidence, internet),
        })

    out.sort(key=lambda p: (_RANK[p["confidence"]], p["internet_reachable"],
                            _sev_rank(p["worst_severity"])), reverse=True)
    return out[:limit]


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _sev_rank(label: str) -> int:
    return _SEV_RANK.get(label, 0)


def _step(nodes: list, index: int, findings: list, evidence: list,
          confidence: str) -> dict:
    """One hop, with the reason the previous hop reaches it.

    Findings and runtime evidence attach to the hop they are ABOUT: the workload hop, since
    that is the object a finding names and an event reports on. Network and RBAC hops carry
    their own reason string, which reachability and the RBAC graph already wrote.
    """
    node = nodes[index]
    is_workload_hop = node.get("kind") not in (
        "Internet", "Service", "Foothold", "Capability", "RBAC")
    return {
        "node": node.get("name", ""),
        "node_type": node.get("kind", ""),
        "relationship": "entry" if index == 0 else "reaches",
        "reason": node.get("detail", ""),
        "supporting_findings": [f.rule_id for f in findings] if is_workload_hop else [],
        "runtime_evidence": evidence if (is_workload_hop and evidence) else [],
        "confidence": confidence if is_workload_hop else CONFIG_ONLY,
    }


def _summary(nodes: list, confidence: str, internet: bool) -> str:
    chain = " -> ".join(f"{n.get('kind')}/{n.get('name')}" for n in nodes)
    lead = ("Internet-reachable path" if internet
            else "Post-breach path (attacker already has a pod foothold)")
    tail = {CONFIG_ONLY: "configuration makes this possible; nothing observed at runtime",
            CORROBORATED: "runtime activity in this namespace aligns with this path",
            OBSERVED: "a runtime event named this path's own resource"}[confidence]
    return f"{lead}: {chain}. Evidence: {tail}."


def path_confidence(paths: list) -> str:
    """The strongest evidence any resource path carries, for the headline."""
    if not paths:
        return "none"
    return max(paths, key=lambda p: _RANK[p["confidence"]])["confidence"]
