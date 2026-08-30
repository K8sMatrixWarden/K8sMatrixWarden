"""
Reachability tagging (attack-vector context, NOT severity gating).

A real misconfiguration is a real thing to fix regardless of how reachable it is -- for K8s
posture you still remediate a privileged pod even if a NetworkPolicy fronts it. So this pass
NEVER lowers severity, exploitability, or blast_radius. It answers the analyst's triage
question -- "can an outside attacker hit this today, or only after they're already in a
pod?" -- and tags every finding on a workload accordingly:

  * "ingress"       -- the pod is reachable from OUTSIDE the cluster right now (an external
                       Service/Ingress routes to it and no NetworkPolicy isolates it), so
                       this finding is exploitable from the internet today.
                       Fix lever: remediate the finding AND cut the exposure (NetworkPolicy
                       / drop the NodePort-LoadBalancer / restrict the Ingress).
  * "pod-privilege" -- NOT reachable from outside (no external route, or a NetworkPolicy
                       blocks it), so it is exploitable only by an attacker who already has
                       code execution in a pod (assume-breach / lateral movement).
                       Fix lever: still remediate (defense-in-depth) -- it's lower urgency
                       than an internet-reachable one, not lower importance.

Keying off the pod's EXPOSURE (fronting Service/Ingress + NetworkPolicy) rather than the
rule's static REMOTE flag is what makes this fire on real app vulns: an RCE-class or
secret-in-env finding is tagged LOCAL by the rule, but if its pod sits behind a NodePort it
is very much internet-reachable. Reads the shared Evidence snapshot -- no new fetches.

Two engines do the actual reasoning, and both are used here rather than reimplemented:

  core/netpol.py     , full LabelSelector semantics (matchLabels AND matchExpressions,
                        In/NotIn/Exists/DoesNotExist, namespaceSelector) evaluated in BOTH
                        directions. A policy this build cannot evaluate yields `partial`,
                        which is NOT treated as isolation -- an unconfirmed restriction
                        must never downgrade an exposure.
  core/rbac_graph.py , RBAC as a graph, so "this SA can reach cluster-admin" comes with the
                        binding, the role and the hop sequence that prove it, including
                        multi-hop routes (read a token -> become that SA -> its permissions).

Exposure is computed once per workload and cached across its findings.
"""
from __future__ import annotations

from typing import Optional

from . import netpol
from .evidence import Evidence
from .models import Finding, ResourceRef
from .rbac_graph import RbacGraph, principal_for_workload

# Attack-vector tags for Finding.exploitable_by (shared vocabulary).
EXPLOIT_INGRESS = "ingress"              # reachable from outside the cluster now
EXPLOIT_POD_PRIVILEGE = "pod-privilege"  # only reachable post-breach (assume-breach)
EXPLOIT_RBAC_ESCALATION = "rbac-escalation"  # pod's SA holds a cluster-admin escalation lever

# Service types that expose pods OUTSIDE the cluster (ClusterIP is internal-only).
_EXTERNAL_SVC_TYPES = {"NodePort", "LoadBalancer"}

# Only pod-bearing kinds get ingress gating. A NodePort/LoadBalancer Service finding is
# REMOTE at the node level and a pod-selecting NetworkPolicy does NOT neutralise it, so
# those resource kinds are deliberately excluded.
_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                   "Job", "CronJob", "ReplicationController"}

_ALLOW_ALL_CIDRS = {"0.0.0.0/0", "::/0"}


def _pod_labels(workload: dict) -> dict:
    """Labels a NetworkPolicy podSelector matches on -- the *pod* labels, which for a
    controller are the template labels, not the controller's own metadata labels."""
    spec = workload.get("spec", {}) or {}
    if "template" in spec:
        return ((spec.get("template") or {}).get("metadata", {}) or {}).get("labels", {}) or {}
    return (workload.get("metadata", {}) or {}).get("labels", {}) or {}


def _resolve_workload(rref: ResourceRef, evidence: Evidence) -> Optional[dict]:
    if not rref.name or rref.kind not in _WORKLOAD_KINDS:
        return None
    for r in evidence.get(rref.kind, all_scopes=True):
        md = r.get("metadata", {}) or {}
        if md.get("name") == rref.name and md.get("namespace") == rref.namespace:
            return r
    return None


def _network_context(workload: dict, namespace: Optional[str], policies: list[dict],
                     namespaces: Optional[list[dict]]) -> dict:
    """Both directions of this pod's NetworkPolicy posture, as structured data."""
    labels = _pod_labels(workload)
    return {
        "ingress": netpol.evaluate(policies, namespace, labels, "Ingress", namespaces),
        "egress": netpol.evaluate(policies, namespace, labels, "Egress", namespaces),
    }


def _ingress_isolated(network: dict) -> Optional[str]:
    """Reason string if ingress is CONFIRMED isolated, else None.

    Only `restricted` and `deny-all` count. A `partial` evaluation (a policy using a
    construct this build cannot evaluate) is deliberately not isolation: claiming a pod is
    protected on the strength of a policy we could not read is exactly the false negative
    this module exists to avoid.
    """
    ing = network.get("ingress", {})
    if not netpol.isolates(ing):
        return None
    return (f"ingress isolated by NetworkPolicy {', '.join(ing['policies'])}"
            if ing.get("policies") else ing.get("reason", "ingress isolated"))


def _service_selects(service: dict, pod_labels: dict) -> bool:
    """True if a Service's selector routes to a pod with these labels. A selector-less
    Service targets manual Endpoints, not label-matched pods, so it never matches here."""
    sel = Evidence.dig(service, "spec.selector", {}) or {}
    return bool(sel) and all(pod_labels.get(k) == v for k, v in sel.items())


def _ingress_backend_services(namespace: Optional[str], evidence: Evidence) -> set[str]:
    """Service names referenced as backends by any Ingress in the namespace (v1 shapes:
    spec.defaultBackend and spec.rules[].http.paths[].backend)."""
    names: set[str] = set()
    for ing in evidence.get("Ingress", all_scopes=True):
        if Evidence.dig(ing, "metadata.namespace") != namespace:
            continue
        db = Evidence.dig(ing, "spec.defaultBackend.service.name")
        if db:
            names.add(db)
        for rule in Evidence.dig(ing, "spec.rules", []) or []:
            for path in Evidence.dig(rule, "http.paths", []) or []:
                n = Evidence.dig(path, "backend.service.name")
                if n:
                    names.add(n)
    return names


def _external_exposure(workload: dict, namespace: Optional[str],
                       evidence: Evidence) -> Optional[str]:
    """Return a short descriptor of how the pod is exposed OUTSIDE the cluster, else None.
    Two ways in: a NodePort/LoadBalancer Service selecting it, or an Ingress routing to a
    Service that selects it."""
    labels = _pod_labels(workload)
    if not labels:
        return None
    services = [s for s in evidence.get("Service", all_scopes=True)
                if Evidence.dig(s, "metadata.namespace") == namespace]
    for svc in services:
        stype = Evidence.dig(svc, "spec.type", "ClusterIP")
        if stype in _EXTERNAL_SVC_TYPES and _service_selects(svc, labels):
            return f"{stype} Service '{Evidence.dig(svc, 'metadata.name', '?')}'"
    ingress_backends = _ingress_backend_services(namespace, evidence)
    for svc in services:
        if Evidence.dig(svc, "metadata.name") in ingress_backends and _service_selects(svc, labels):
            return f"Ingress → Service '{Evidence.dig(svc, 'metadata.name', '?')}'"
    return None


def _node(kind: str, name: str, detail: str = "") -> dict:
    return {"kind": kind, "name": name, "detail": detail}


def _build_path(workload: dict, namespace: Optional[str], exposure: Optional[str],
                isolated: Optional[str], chain: Optional[str],
                rbac_path=None) -> list[dict]:
    """The structural hop chain behind the prose reason (§9).

    Internet -> Service/Ingress -> Pod -> ServiceAccount -> RoleBinding -> Role -> the
    privilege it grants, with the hops that do not apply simply absent. Same inputs as the
    reason string, so the two can never disagree; this one is machine-readable, for the
    dashboard, MCP, reports and the agent.

    The RBAC tail is no longer a single synthetic "escalation" node: when the graph found a
    concrete shortest path, its real hops (the binding, the role, the capability) are spliced
    in, so a reader sees WHICH binding grants it rather than only that something does.
    """
    meta = workload.get("metadata", {}) or {}
    sa = Evidence.pod_spec(workload).get("serviceAccountName", "default")
    path: list[dict] = []
    if exposure and not isolated:
        path.append(_node("Internet", "external", "reachable from outside the cluster"))
        path.append(_node("Service", exposure, "external route to this pod"))
    elif exposure and isolated:
        path.append(_node("Foothold", "compromised pod",
                          f"external route exists ({exposure}) but {isolated}"))
    else:
        path.append(_node("Foothold", "compromised pod",
                          isolated or "no external Service or Ingress routes to this pod"))
    path.append(_node(workload.get("kind") or "Pod", meta.get("name", ""), namespace or ""))
    if chain:
        path.append(_node("ServiceAccount", sa, f"{namespace or ''}/{sa}".strip("/")))
        if rbac_path is not None:
            # Skip the principal node the graph starts from, it is the ServiceAccount hop
            # just appended; every following hop carries the edge's own reason.
            for edge in rbac_path.edges:
                path.append(_node(edge.target.kind, edge.target.name, edge.reason))
        else:
            path.append(_node("RBAC", "cluster-admin escalation", chain))
    return path


def _classify(workload: dict, namespace: Optional[str], policies: list[dict],
              evidence: Evidence, graph: Optional[RbacGraph] = None,
              namespaces: Optional[list[dict]] = None) -> tuple:
    """(tags, analyst-facing reason, structural path, network context, rbac paths) for a
    workload: external exposure, NetworkPolicy posture in both directions, and multi-hop
    RBAC escalation."""
    exposure = _external_exposure(workload, namespace, evidence)
    network = _network_context(workload, namespace, policies, namespaces)
    isolated = _ingress_isolated(network)                         # reason str or None

    if exposure and not isolated:
        tags, reason = [EXPLOIT_INGRESS], (
            f"INTERNET-REACHABLE now via {exposure} with no NetworkPolicy isolating the pod "
            f"— an external attacker can reach this finding today. Fix: remediate the issue "
            f"and cut the exposure (add a NetworkPolicy, or drop the external Service / "
            f"restrict the Ingress).")
    elif exposure and isolated:
        tags, reason = [EXPLOIT_POD_PRIVILEGE], (
            f"Exposed via {exposure} but {isolated}, so the network path is blocked — "
            f"reachable only after an attacker already has a foothold in a pod. Still "
            f"remediate (defense-in-depth); lower urgency than an internet-reachable one.")
    else:
        why = isolated or "no external Service or Ingress routes to this pod"
        tags, reason = [EXPLOIT_POD_PRIVILEGE], (
            f"NOT internet-reachable ({why}) — exploitable only by an attacker already "
            f"executing in a pod (assume-breach / lateral movement). Still remediate for "
            f"defense-in-depth; treat as lower urgency than internet-reachable findings.")

    graph = graph or RbacGraph.from_evidence(evidence)
    principal = principal_for_workload(workload, namespace)
    chain, rbac_paths = graph.escalation_summary(principal)
    if chain:
        tags.append(EXPLOIT_RBAC_ESCALATION)
        reason += (f" ⚠ RBAC escalation: this pod's ServiceAccount "
                   f"'{principal.name}' can reach cluster-admin — {chain}. A breach here "
                   f"isn't contained to the pod.")

    # Egress is context, never a tag: a pod with unrestricted egress is not "more exposed"
    # to an inbound attacker, it is more useful to one who is already inside. Say so where
    # it changes the analyst's next move, and stay quiet where it does not.
    egress = network.get("egress", {})
    if egress.get("status") == netpol.UNRESTRICTED:
        reason += (" Egress is unrestricted, so a compromised process here can reach any "
                   "in-cluster service and the internet (exfiltration / C2 path).")
    elif netpol.isolates(egress):
        reason += f" Egress is constrained: {egress.get('reason', '')}"
    elif egress.get("status") == netpol.PARTIAL:
        reason += (" Egress restriction could not be fully evaluated, treat it as "
                   "unconfirmed rather than as containment.")

    shortest = rbac_paths[0] if rbac_paths else None
    return (tags, reason,
            _build_path(workload, namespace, exposure, isolated, chain, shortest),
            network, [p.as_dict() for p in rbac_paths[:10]])


def inventory(evidence: Evidence) -> dict:
    """Cluster inventory + per-pod exposure buckets for the dashboard's scope bar.

    Classifies EVERY pod in scope (not just ones with findings) so the bar has an honest
    denominator -- "380 pods, 4 internet-reachable" reads very differently from "4 of 4".
    Each pod lands in exactly one worst-wins bucket so the segments sum to the pod total:
    internet+admin > internet > admin > internal. Reuses _classify -- same tags, no new logic.
    """
    policies = evidence.get("NetworkPolicy", all_scopes=True)
    namespaces = evidence.get("Namespace", all_scopes=True)
    pods = evidence.get("Pod")                       # scope-filtered, same as the rules saw
    graph = RbacGraph.from_evidence(evidence)        # built once for the whole inventory
    buckets = {"internet_admin": 0, "internet": 0, "admin": 0, "internal": 0}
    for pod in pods:
        try:
            tags = _classify(pod, Evidence.dig(pod, "metadata.namespace"),
                             policies, evidence, graph, namespaces)[0]
        except Exception:                    # pragma: no cover - defensive
            # One unclassifiable pod must not cost the whole inventory bar. It lands in
            # the least-alarming bucket rather than being dropped, so the segments still
            # sum to the honest pod total.
            tags = []
        ingress, admin = EXPLOIT_INGRESS in tags, EXPLOIT_RBAC_ESCALATION in tags
        key = ("internet_admin" if ingress and admin else "internet" if ingress
               else "admin" if admin else "internal")
        buckets[key] += 1
    return {"nodes": len(evidence.get("Node", all_scopes=True)),
            "namespaces": len(evidence.get("Namespace", all_scopes=True)),
            "pods": len(pods), "exposure": buckets}


def annotate_reachability(findings: list[Finding], evidence: Evidence) -> list[Finding]:
    """In-place: tag every workload finding with how an attacker reaches it and whether its
    ServiceAccount can escalate to cluster-admin.

    Never changes severity/exploitability/blast_radius -- only sets `exploitable_by` and a
    human-readable `path_reason`. Classification is computed once per workload and reused
    across all its findings.
    """
    policies = evidence.get("NetworkPolicy", all_scopes=True)
    namespaces = evidence.get("Namespace", all_scopes=True)
    graph = RbacGraph.from_evidence(evidence)   # one index, reused for every workload
    cache: dict[tuple, tuple] = {}
    for f in findings:
        workload = _resolve_workload(f.resource, evidence)
        if workload is None:
            continue                          # non-pod finding -> different fix lever, skip
        key = (f.resource.kind, f.resource.name, f.resource.namespace)
        if key not in cache:
            # Per-workload isolation, the same philosophy the Detection Engine applies per
            # rule. A single malformed object (a selector that is a string, a spec that is
            # null) must cost that ONE workload its reachability context, not blank the
            # analysis for every finding in the scan. The failure is recorded on the
            # finding rather than swallowed, so it reads as "not analysed", never as
            # "analysed and found safe".
            try:
                cache[key] = _classify(workload, f.resource.namespace, policies, evidence,
                                       graph, namespaces)
            except Exception as exc:            # pragma: no cover - defensive
                cache[key] = ([], f"reachability could not be analysed for this "
                                  f"resource: {type(exc).__name__}: {exc}",
                              [], {}, [])
        tags, reason, path, network, rbac_paths = cache[key]
        f.exploitable_by = list(tags)
        f.path_reason = reason
        f.exploit_path = [dict(node) for node in path]
        f.network_context = network
        f.rbac_paths = rbac_paths
    return findings
