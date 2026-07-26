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

ponytail: matchLabels/flat-selector match, ingress direction only; egress and RBAC-chain
tagging are a later pass. Exposure is computed once per workload and cached across its
findings.
"""
from __future__ import annotations

from typing import Optional

from .evidence import Evidence
from .models import Finding, ResourceRef

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


def _selects(policy: dict, pod_labels: dict) -> bool:
    """True if `policy`'s podSelector selects a pod with these labels. Empty selector
    ({}) selects every pod in the namespace (k8s semantics)."""
    match = Evidence.dig(policy, "spec.podSelector.matchLabels", {}) or {}
    return all(pod_labels.get(k) == v for k, v in match.items())


def _ingress_governs(policy: dict) -> bool:
    """Does this policy put ingress under a default-deny? k8s: if policyTypes is omitted,
    Ingress always applies; otherwise it applies only when listed."""
    types = Evidence.dig(policy, "spec.policyTypes", None)
    return types is None or "Ingress" in types


def _allows_all_ingress(policy: dict) -> bool:
    """True if any ingress rule admits traffic from anywhere (empty `from`, or an
    0.0.0.0/0 ipBlock) -- which means the pod is NOT isolated from remote sources."""
    for rule in Evidence.dig(policy, "spec.ingress", []) or []:
        froms = rule.get("from")
        if not froms:                       # empty/absent `from` == allow all sources
            return True
        for peer in froms:
            cidr = (peer.get("ipBlock") or {}).get("cidr", "")
            if cidr in _ALLOW_ALL_CIDRS:
                return True
    return False


def _resolve_workload(rref: ResourceRef, evidence: Evidence) -> Optional[dict]:
    if not rref.name or rref.kind not in _WORKLOAD_KINDS:
        return None
    for r in evidence.get(rref.kind, all_scopes=True):
        md = r.get("metadata", {}) or {}
        if md.get("name") == rref.name and md.get("namespace") == rref.namespace:
            return r
    return None


def _ingress_isolated(workload: dict, namespace: Optional[str],
                      policies: list[dict]) -> Optional[str]:
    """Return a reason string if the workload is isolated from remote ingress, else None.

    Isolated == selected by >=1 ingress-governing policy AND no selecting policy opens it
    to all sources. Policies are additive (union of allows), so a single allow-all defeats
    isolation.
    """
    labels = _pod_labels(workload)
    selecting = [p for p in policies
                 if Evidence.dig(p, "metadata.namespace") == namespace and _selects(p, labels)]
    governing = [p for p in selecting if _ingress_governs(p)]
    if not governing:
        return None
    if any(_allows_all_ingress(p) for p in governing):
        return None
    names = ", ".join(sorted(Evidence.dig(p, "metadata.name", "?") for p in governing))
    return f"ingress isolated by NetworkPolicy {names}"


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


def _binds_sa(binding: dict, sa: str, ns: Optional[str]) -> bool:
    # exact (name, namespace) match -- a ServiceAccount subject always carries a namespace,
    # so no is-None fallback: a "reaches cluster-admin" claim must not match loosely.
    for s in binding.get("subjects", []) or []:
        if (s.get("kind") == "ServiceAccount"
                and s.get("name") == sa and s.get("namespace") == ns):
            return True
    return False


def _sa_rules(workload: dict, ns: Optional[str], evidence: Evidence) -> list[dict]:
    """All RBAC policy rules granted to the workload's ServiceAccount, via its Cluster/Role
    bindings. Reused-per-pod; the caller caches."""
    sa = Evidence.pod_spec(workload).get("serviceAccountName", "default")
    croles = {Evidence.dig(r, "metadata.name"): r
              for r in evidence.get("ClusterRole", all_scopes=True)}
    roles = {(Evidence.dig(r, "metadata.name"), Evidence.dig(r, "metadata.namespace")): r
             for r in evidence.get("Role", all_scopes=True)}
    rules: list[dict] = []

    def add(roleref: dict, binding_ns: Optional[str]):
        name = roleref.get("name")
        role = croles.get(name) if roleref.get("kind") == "ClusterRole" \
            else roles.get((name, binding_ns))
        if role:
            rules.extend(role.get("rules", []) or [])

    for crb in evidence.get("ClusterRoleBinding", all_scopes=True):
        if _binds_sa(crb, sa, ns):
            add(crb.get("roleRef", {}) or {}, None)
    for rb in evidence.get("RoleBinding", all_scopes=True):
        if _binds_sa(rb, sa, ns):
            add(rb.get("roleRef", {}) or {}, Evidence.dig(rb, "metadata.namespace"))
    return rules


def _escalation_chain(rules: list[dict]) -> Optional[str]:
    """Name the cluster-admin escalation levers this SA's rules grant, or None.

    ponytail: single-level primitive detection, not a real shortest-path graph. It flags the
    known escalation verbs an SA holds -- enough to say "this SA can reach cluster-admin".
    Upgrade to true multi-hop chaining (KubeHound/IceKube style) only if customers need the
    exact hop sequence rather than "an escalation lever exists here".
    """
    def grants(verbs: set, resources: set) -> bool:
        for r in rules:
            rv, rr = set(r.get("verbs", []) or []), set(r.get("resources", []) or [])
            if (verbs & rv or "*" in rv) and (resources & rr or "*" in rr):
                return True
        return False

    if grants({"*"}, {"*"}):
        return "SA already holds cluster-admin-equivalent (verbs=* on resources=*)"
    steps = []
    if grants({"bind", "escalate"}, {"clusterroles", "roles"}):
        steps.append("bind/escalate roles → grant itself cluster-admin")
    if grants({"impersonate"}, {"users", "groups", "serviceaccounts"}):
        steps.append("impersonate a higher-privileged identity")
    if grants({"create"}, {"pods", "deployments", "daemonsets"}):
        steps.append("create a workload with any SA / privileged → node → cluster")
    if grants({"get", "list"}, {"secrets"}):
        steps.append("read secrets → steal another identity's token")
    return "; ".join(steps) or None


def _classify(workload: dict, namespace: Optional[str], policies: list[dict],
              evidence: Evidence) -> tuple[list[str], str]:
    """(tags, analyst-facing reason) for a workload: external exposure + RBAC escalation."""
    exposure = _external_exposure(workload, namespace, evidence)
    isolated = _ingress_isolated(workload, namespace, policies)   # reason str or None

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

    chain = _escalation_chain(_sa_rules(workload, namespace, evidence))
    if chain:
        sa = Evidence.pod_spec(workload).get("serviceAccountName", "default")
        tags.append(EXPLOIT_RBAC_ESCALATION)
        reason += (f" ⚠ RBAC escalation: this pod's ServiceAccount '{sa}' can reach "
                   f"cluster-admin — {chain}. A breach here isn't contained to the pod.")
    return tags, reason


def annotate_reachability(findings: list[Finding], evidence: Evidence) -> list[Finding]:
    """In-place: tag every workload finding with how an attacker reaches it and whether its
    ServiceAccount can escalate to cluster-admin.

    Never changes severity/exploitability/blast_radius -- only sets `exploitable_by` and a
    human-readable `path_reason`. Classification is computed once per workload and reused
    across all its findings.
    """
    policies = evidence.get("NetworkPolicy", all_scopes=True)
    cache: dict[tuple, tuple[list[str], str]] = {}
    for f in findings:
        workload = _resolve_workload(f.resource, evidence)
        if workload is None:
            continue                          # non-pod finding -> different fix lever, skip
        key = (f.resource.kind, f.resource.name, f.resource.namespace)
        if key not in cache:
            cache[key] = _classify(workload, f.resource.namespace, policies, evidence)
        tags, reason = cache[key]
        f.exploitable_by = list(tags)
        f.path_reason = reason
    return findings
