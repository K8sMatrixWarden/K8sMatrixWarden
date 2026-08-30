"""
RBAC as a graph, with real multi-hop escalation paths.

The earlier pass answered one question: "does this ServiceAccount hold a verb that is
known to be dangerous?" That is a flat permission test. It cannot say WHICH binding
granted the permission, cannot follow a permission that yields a *second* identity, and
cannot show its work. This module models RBAC the way Kubernetes actually shapes it:

    Principal (ServiceAccount / User / Group)
        --bound-by-->      RoleBinding | ClusterRoleBinding
        --grants-->        Role | ClusterRole
        --permits-->       verb on resource
        --enables-->       escalation capability
        --reaches-->       another Principal / Role  (the second hop)

and walks it.

Two hard rules, because an attack path that is not true is worse than no path at all:

  * EVERY edge is evidence-backed. An edge exists only because a specific object in the
    collected evidence says so, and it carries that object's identity and a reason. There
    is no inference from "this looks like the kind of cluster where...".
  * A second hop is only emitted when its TARGET exists in the evidence. "Can bind any
    ClusterRole" becomes an escalation path only if a ClusterRole worth binding was
    actually collected; otherwise the capability is reported with no onward hop.

Traversal is breadth-first with a visited set and a hop cap, so a cyclic RBAC graph (A
can impersonate B, B can impersonate A, which is legal and does happen) terminates and
yields the shortest path rather than spinning.

Read-only: this module only reads the evidence snapshot. It never contacts the cluster.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

#: Escalation capabilities, in the order a report should present them: the most direct
#: route to cluster-admin first. Each maps to (verbs, resources) that grant it, matched
#: against a principal's effective policy rules.
#: Sub-resource forms are included where Kubernetes uses them (`pods/exec` is a distinct
#: resource string from `pods`, and only the former grants execution).
#: (capability, verbs, resources, apiGroups, why). `apiGroups` matters: a CustomResource
#: called "secrets" in someone's own API group is not a core Kubernetes Secret, and
#: treating it as one manufactures an escalation that does not exist. "" is the core group,
#: and a rule's apiGroups must intersect (or be "*") for the grant to be the one we mean.
ESCALATION_PRIMITIVES = [
    ("cluster-admin", {"*"}, {"*"}, {"*"},
     "holds verbs=* on resources=*, this principal already IS cluster-admin"),
    ("bind-roles", {"bind", "escalate"}, {"clusterroles", "roles"},
     {"rbac.authorization.k8s.io"},
     "can bind/escalate roles, so it can grant itself any role in the cluster"),
    ("impersonate", {"impersonate"}, {"users", "groups", "serviceaccounts"}, {""},
     "can impersonate another identity and inherit its permissions"),
    ("create-workload", {"create"}, {"pods", "deployments", "daemonsets", "statefulsets",
                                     "jobs", "cronjobs", "replicasets"},
     {"", "apps", "batch"},
     "can create a workload, and a workload can run as any ServiceAccount in its namespace"),
    ("exec-pods", {"create", "get"}, {"pods/exec", "pods/attach"}, {""},
     "can exec into running pods and use their mounted ServiceAccount tokens"),
    ("read-secrets", {"get", "list"}, {"secrets"}, {""},
     "can read Secrets, which include other identities' ServiceAccount tokens"),
    ("modify-bindings", {"create", "update", "patch"},
     {"rolebindings", "clusterrolebindings"}, {"rbac.authorization.k8s.io"},
     "can write (Cluster)RoleBindings, so it can bind any role to itself"),
]

#: Capabilities whose onward hop lands on ANOTHER PRINCIPAL rather than on a role.
_PRINCIPAL_HOPS = {"impersonate", "create-workload", "exec-pods", "read-secrets"}

#: Default ClusterRoles Kubernetes ships. They are not evidence of a misconfiguration by
#: themselves, but they ARE legitimate escalation targets: "can bind any ClusterRole" is
#: only dangerous because `cluster-admin` is sitting there to be bound.
_ADMIN_ROLE_NAMES = ("cluster-admin", "admin")

#: Edge budget for a traversal. Reaching one privilege from one principal costs three edges
#: (bound-by, grants, enables); taking over a second identity costs a fourth (reaches) plus
#: another three. 8 therefore admits a two-identity chain and stops there: a three-identity
#: chain is not more true, only longer, and every extra level multiplies the path count.
MAX_HOPS = 8

#: Cap on how many onward principals one capability expands to. A "can create workloads"
#: capability technically reaches every ServiceAccount in the namespace, and enumerating
#: all of them on a large cluster produces thousands of near-identical paths that say the
#: same thing. The cap keeps traversal bounded; the capability itself is always reported in
#: full, only the per-target expansion is truncated.
MAX_ONWARD_TARGETS = 25

#: Order capabilities are presented in, most direct route to cluster-admin first.
_CAP_ORDER = {cap: i for i, (cap, *_rest) in enumerate(ESCALATION_PRIMITIVES)}

#: Whether a traversal was exhaustive or stopped at a bound. Shared vocabulary with
#: core/attack_path.py, so every bounded analysis in the project says so the same way.
COMPLETE, TRUNCATED = "complete", "truncated"


@dataclass(frozen=True)
class Node:
    """One vertex. `kind` is the Kubernetes kind (or a synthetic kind for permissions and
    capabilities), so a renderer can style a path without parsing strings."""
    kind: str
    name: str
    namespace: Optional[str] = None

    @property
    def id(self) -> str:
        return f"{self.kind}/{self.namespace or ''}/{self.name}"

    def as_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "namespace": self.namespace}

    def __str__(self) -> str:
        return f"{self.kind}/{self.name}" if not self.namespace \
            else f"{self.kind}/{self.namespace}/{self.name}"


@dataclass(frozen=True)
class Edge:
    source: Node
    target: Node
    relationship: str
    reason: str
    #: The evidence object this edge was read off, so a reader can go straight to it.
    evidence: str = ""

    def as_dict(self) -> dict:
        return {"from": self.source.as_dict(), "to": self.target.as_dict(),
                "relationship": self.relationship, "reason": self.reason,
                "evidence": self.evidence}


@dataclass
class Path:
    edges: list = field(default_factory=list)          # list[Edge]
    capability: str = ""
    summary: str = ""

    @property
    def hops(self) -> int:
        return len(self.edges)

    @property
    def nodes(self) -> list:
        if not self.edges:
            return []
        return [self.edges[0].source] + [e.target for e in self.edges]

    def as_dict(self) -> dict:
        return {"capability": self.capability, "hops": self.hops,
                "summary": self.summary or self.render(),
                "nodes": [n.as_dict() for n in self.nodes],
                "edges": [e.as_dict() for e in self.edges]}

    def render(self) -> str:
        return " -> ".join(str(n) for n in self.nodes)


def _norm(values: Iterable) -> set:
    return {str(v) for v in (values or [])}


def _rule_grants(rule: dict, verbs: set, resources: set,
                 api_groups: Optional[set] = None) -> bool:
    """Does this PolicyRule grant `verbs` on `resources` in `api_groups`, unrestricted?

    Three Kubernetes details that a naive verb/resource intersection gets wrong, each of
    which manufactures an escalation that does not exist:

      apiGroups     , a rule is scoped to an API group. `resources: ["secrets"]` under
                      `apiGroups: ["vendor.example.com"]` is somebody's CustomResource,
                      NOT a core Secret. Ignoring the group let any CRD borrow the name of
                      a sensitive built-in and inherit its escalation meaning.
      resourceNames , a rule carrying `resourceNames` grants access to THOSE OBJECTS ONLY.
                      "can get secrets" restricted to one named secret is not "can read
                      every ServiceAccount token in the namespace", which is the claim the
                      read-secrets capability makes. A named-resource grant therefore never
                      establishes a blanket capability here; `restricted_grant` reports it
                      separately so it is visible rather than silently dropped.
      nonResourceURLs, a rule with only nonResourceURLs (/healthz, /metrics) grants no
                      resource access at all. It has no `resources`, so it cannot match,
                      which is already correct and is asserted by test.
    """
    rv, rr = _norm(rule.get("verbs")), _norm(rule.get("resources"))
    if rule.get("resourceNames"):
        return False                      # object-scoped: never a blanket capability
    if not (verbs & rv or "*" in rv):
        return False
    if not (resources & rr or "*" in rr):
        return False
    if api_groups is None or "*" in api_groups:
        return True
    rg = _norm(rule.get("apiGroups"))
    if not rg:
        # A resource rule without apiGroups is malformed (the API server rejects it on
        # create), so this only happens with hand-written or synthetic evidence. Absence is
        # not evidence AGAINST the grant, and silently dropping the rule would be a false
        # negative on a real escalation. A claim is only downgraded when the evidence
        # positively contradicts it, which an absent field does not.
        return True
    return bool("*" in rg or api_groups & rg)


def restricted_grant(rule: dict, verbs: set, resources: set,
                     api_groups: Optional[set] = None) -> bool:
    """True when the rule WOULD grant the capability but is limited to named objects.

    Reported as a restricted grant, not as an escalation: it may well be dangerous (if the
    named object is the sensitive one) but the evidence does not establish the blanket
    capability, and claiming it would be an over-claim."""
    if not rule.get("resourceNames"):
        return False
    probe = {k: v for k, v in rule.items() if k != "resourceNames"}
    return _rule_grants(probe, verbs, resources, api_groups)


class RbacGraph:
    """An index over the RBAC objects in one evidence snapshot, plus traversal over it."""

    def __init__(self, cluster_roles: list[dict], roles: list[dict],
                 cluster_role_bindings: list[dict], role_bindings: list[dict],
                 service_accounts: Optional[list[dict]] = None):
        self.cluster_roles = {self._name(r): r for r in cluster_roles or []}
        self.roles = {(self._name(r), self._ns(r)): r for r in roles or []}
        self.cluster_role_bindings = list(cluster_role_bindings or [])
        self.role_bindings = list(role_bindings or [])
        self.service_accounts = list(service_accounts or [])
        #: Set by a traversal when it stops at a bound; read by escalation_analysis.
        self._truncated_reason: Optional[str] = None
        #: Grants limited by `resourceNames`, collected by _capabilities.
        self._restricted: list = []

    # -- construction ---------------------------------------------------- #
    @classmethod
    def from_evidence(cls, evidence) -> "RbacGraph":
        """Build from the shared Evidence snapshot. Cluster-scoped RBAC is read with
        `all_scopes=True` so a namespace-scoped scan still sees the ClusterRoles that a
        binding in its namespace points at, without which every path would dead-end."""
        return cls(
            cluster_roles=evidence.get("ClusterRole", all_scopes=True),
            roles=evidence.get("Role", all_scopes=True),
            cluster_role_bindings=evidence.get("ClusterRoleBinding", all_scopes=True),
            role_bindings=evidence.get("RoleBinding", all_scopes=True),
            service_accounts=evidence.get("ServiceAccount", all_scopes=True))

    @staticmethod
    def _name(obj: dict) -> str:
        return (obj.get("metadata", {}) or {}).get("name", "")

    @staticmethod
    def _ns(obj: dict) -> Optional[str]:
        return (obj.get("metadata", {}) or {}).get("namespace")

    # -- principal -> bindings -> roles ----------------------------------- #
    def _subject_matches(self, subject: dict, principal: Node) -> bool:
        """Does an RBAC subject refer to this principal?

        A ServiceAccount subject always carries a namespace, so the namespace is compared
        exactly: matching loosely is how a tool ends up claiming that some other
        namespace's `default` SA is cluster-admin. User and Group subjects are
        cluster-scoped and carry no namespace.
        """
        if subject.get("kind") != principal.kind or subject.get("name") != principal.name:
            return False
        if principal.kind == "ServiceAccount":
            return subject.get("namespace") == principal.namespace
        return True

    def bindings_for(self, principal: Node) -> list[tuple]:
        """[(binding_object, is_cluster_binding)] naming this principal as a subject."""
        out = []
        for crb in self.cluster_role_bindings:
            if any(self._subject_matches(s, principal)
                   for s in crb.get("subjects", []) or []):
                out.append((crb, True))
        for rb in self.role_bindings:
            if any(self._subject_matches(s, principal)
                   for s in rb.get("subjects", []) or []):
                out.append((rb, False))
        return out

    def role_for(self, role_ref: dict, binding_namespace: Optional[str]):
        """Resolve a roleRef to its object, honouring the namespace rules: a RoleBinding
        may point at a ClusterRole (granting it only within the binding's namespace) or at
        a Role in its OWN namespace. Returns (object, node) or (None, None)."""
        name = (role_ref or {}).get("name", "")
        if (role_ref or {}).get("kind") == "ClusterRole":
            obj = self.cluster_roles.get(name)
            return (obj, Node("ClusterRole", name)) if obj else (None, None)
        obj = self.roles.get((name, binding_namespace))
        return (obj, Node("Role", name, binding_namespace)) if obj else (None, None)

    def grant_edges(self, principal: Node) -> list[tuple]:
        """[(binding_edge, role_edge, role_object, role_node, grant_namespace)] for every
        role this principal holds. Two edges per grant, so the binding that made it is
        never lost, plus the namespace the grant is confined to (None = cluster-wide)."""
        out = []
        for binding, is_cluster in self.bindings_for(principal):
            bkind = "ClusterRoleBinding" if is_cluster else "RoleBinding"
            bns = None if is_cluster else self._ns(binding)
            bnode = Node(bkind, self._name(binding), bns)
            role_obj, rnode = self.role_for(binding.get("roleRef", {}) or {}, bns)
            if role_obj is None:
                continue          # dangling roleRef: no evidence for what it grants, skip
            # EFFECTIVE SCOPE, not the role's own kind. Kubernetes: a RoleBinding grants
            # its roleRef's rules ONLY inside the binding's namespace, even when that
            # roleRef is a ClusterRole. Reading the ClusterRole and reporting cluster-wide
            # power is the single most dangerous over-claim this module can make: binding
            # `cluster-admin` into one team namespace is a normal delegation pattern, and
            # calling it "this principal IS cluster-admin" is simply false.
            grant_ns = None if is_cluster else bns
            scope = "cluster-wide" if is_cluster else f"in namespace {bns} only"
            out.append((
                Edge(principal, bnode, "bound-by",
                     f"{bkind} {self._name(binding)} names {principal} as a subject",
                     evidence=f"{bkind}/{self._name(binding)}"),
                Edge(bnode, rnode, "grants",
                     f"roleRef points at {rnode}, granting its rules {scope}",
                     evidence=f"{bkind}/{self._name(binding)}"),
                role_obj, rnode, grant_ns))
        return out

    def effective_rules(self, principal: Node) -> list[dict]:
        """Every policy rule this principal holds, from every binding. Kubernetes RBAC is
        purely additive and has no inheritance between roles, so this is the union, and
        aggregationRule-built ClusterRoles are read from their materialised `rules` (which
        is what the controller writes back and what the API returns)."""
        rules: list[dict] = []
        for _b, _r, role_obj, _n, _ns in self.grant_edges(principal):
            rules.extend(role_obj.get("rules", []) or [])
        return rules

    # -- permissions ------------------------------------------------------ #
    def permission_paths(self, principal: Node, verb: str, resource: str) -> list[Path]:
        """Concrete paths proving this principal can perform `verb` on `resource`.

        This is the plain, non-escalation question, "how exactly does payment-api get
        secrets/get?", and the answer names the binding and the role, not just "yes".
        """
        out = []
        for bind_edge, role_edge, role_obj, rnode, _ns in self.grant_edges(principal):
            for rule in role_obj.get("rules", []) or []:
                if not _rule_grants(rule, {verb}, {resource}, api_groups={"*"}):
                    continue
                pnode = Node("Permission", f"{resource}/{verb}")
                out.append(Path(
                    edges=[bind_edge, role_edge,
                           Edge(rnode, pnode, "permits",
                                f"rule grants verbs={sorted(_norm(rule.get('verbs')))} on "
                                f"resources={sorted(_norm(rule.get('resources')))}",
                                evidence=str(rnode))],
                    capability=f"{resource}/{verb}",
                    summary=""))
                break                      # one proof per role is enough
        return sorted(out, key=lambda p: p.hops)

    # -- escalation ------------------------------------------------------- #
    def _capabilities(self, principal: Node) -> list[tuple]:
        """[(capability, prefix_edges, rule, grant_namespace)] the principal holds, each
        with the concrete binding -> role -> permission edges that prove it.

        `grant_namespace` is None for a cluster-wide grant and a namespace name when the
        grant came through a RoleBinding, which confines it. Onward traversal uses it, so a
        namespace-confined admin cannot reach identities outside that namespace.

        Grants limited by `resourceNames` are recorded in `restricted` rather than treated
        as capabilities: they are real permissions but not the blanket access the
        capability asserts.
        """
        found, self._restricted = [], []
        for bind_edge, role_edge, role_obj, rnode, grant_ns in self.grant_edges(principal):
            for cap, verbs, resources, groups, why in ESCALATION_PRIMITIVES:
                matched = False
                for rule in role_obj.get("rules", []) or []:
                    if _rule_grants(rule, verbs, resources, groups):
                        where = ("" if grant_ns is None
                                 else f" (within namespace {grant_ns} only)")
                        cnode = Node("Capability", cap, grant_ns)
                        edges = [bind_edge, role_edge,
                                 Edge(rnode, cnode, "enables", why + where,
                                      evidence=str(rnode))]
                        found.append((cap, edges, rule, grant_ns))
                        matched = True
                        break
                if matched:
                    continue
                for rule in role_obj.get("rules", []) or []:
                    if restricted_grant(rule, verbs, resources, groups):
                        self._restricted.append({
                            "capability": cap, "role": str(rnode),
                            "namespace": grant_ns,
                            "resource_names": sorted(_norm(rule.get("resourceNames"))),
                            "note": (f"grants {cap} but only on named object(s); this is a "
                                     f"real permission, not the blanket capability, so no "
                                     f"escalation path is claimed from it")})
                        break
        return found

    def _admin_roles(self) -> list[Node]:
        """Cluster-admin-equivalent ClusterRoles present in THIS cluster's evidence.

        A "can bind any role" capability is only an escalation if such a role exists to be
        bound, so this is what turns a capability into an onward hop, and its absence is
        what stops us inventing one.
        """
        out = []
        for name, obj in sorted(self.cluster_roles.items()):
            if name in _ADMIN_ROLE_NAMES or any(
                    _rule_grants(r, {"*"}, {"*"}) for r in obj.get("rules", []) or []):
                out.append(Node("ClusterRole", name))
        return out

    def _other_principals(self, namespace: Optional[str]) -> list[Node]:
        """ServiceAccounts a principal could take over via a workload/exec/secret-read
        capability. Restricted to the namespace the capability applies in, because a
        namespaced permission cannot reach another namespace's tokens."""
        out = []
        for sa in self.service_accounts:
            ns = self._ns(sa)
            if namespace is not None and ns != namespace:
                continue
            out.append(Node("ServiceAccount", self._name(sa), ns))
        return out

    def unevaluable_grants(self, principal: Node) -> list[dict]:
        """Roles held by this principal whose effective permissions cannot be read.

        The case that matters is an **aggregated ClusterRole**: its `rules` are filled in
        by the controller from every ClusterRole matching its `aggregationRule` selectors.
        If a snapshot catches it before that happens, or the selectors match roles outside
        what was collected, the role looks empty. Reporting "no escalation" there is a
        false negative dressed as a clean result, so it is reported as UNKNOWN instead.

        Aggregation is not resolved by this build: the honest answer is that the effective
        permission set is unknown, not that it is empty.
        """
        out = []
        for _b, _r, role_obj, rnode, grant_ns in self.grant_edges(principal):
            agg = role_obj.get("aggregationRule")
            if agg and not (role_obj.get("rules") or []):
                out.append({
                    "role": str(rnode), "namespace": grant_ns, "reason": "aggregated",
                    "selectors": (agg or {}).get("clusterRoleSelectors", []),
                    "note": ("aggregated ClusterRole whose rules were not populated in "
                             "this snapshot; its effective permissions are UNKNOWN, not "
                             "empty, and no escalation conclusion is drawn either way")})
        return out

    def escalation_analysis(self, principal: Node,
                            *, max_hops: int = MAX_HOPS) -> dict:
        """`escalation_paths` plus an honest statement of what the walk could and could
        not establish.

        Three separate honesty signals, none of which may be collapsed into "no path":
          analysis_status  , did a bound stop the walk (truncated) or not (complete)?
          restricted_grants, permissions limited by `resourceNames`, real but not blanket
          unevaluable_roles, roles whose effective rules are unknown (aggregation)
        """
        self._truncated_reason = None
        self._restricted = []
        paths = self.escalation_paths(principal, max_hops=max_hops)
        reason = self._truncated_reason
        unevaluable = self.unevaluable_grants(principal)
        restricted = list(self._restricted)
        return {
            "principal": str(principal),
            "paths": paths,
            "analysis_status": TRUNCATED if reason else COMPLETE,
            "truncation_reason": reason,
            "restricted_grants": restricted,
            "unevaluable_roles": unevaluable,
            # "No path found" only means something when everything was readable. When a
            # role's rules are unknown, the correct answer is `unknown`, not `none`.
            "escalation_verdict": ("unknown" if (unevaluable and not paths)
                                   else ("escalates" if paths else "none")),
            "limits": {"max_hops": max_hops,
                       "max_onward_targets": MAX_ONWARD_TARGETS},
        }

    def escalation_paths(self, principal: Node, *, max_hops: int = MAX_HOPS) -> list[Path]:
        """Multi-hop escalation paths from `principal`, shortest first.

        Breadth-first over principals: each level expands the capabilities a principal
        holds, and where a capability yields ANOTHER principal (impersonate, run a
        workload as a different SA, read its token, exec into its pod) that principal is
        queued for the next level. `seen` guards against RBAC cycles, and `max_hops`
        bounds the walk regardless.
        """
        paths: list[Path] = []
        seen = {principal.id}
        frontier = [(principal, [])]
        while frontier:
            nxt = []
            for current, prefix in frontier:
                if len(prefix) >= max_hops:
                    self._note_truncation("edge_limit")
                    continue
                for cap, edges, _rule, grant_ns in self._capabilities(current):
                    full = prefix + edges
                    if len(full) > max_hops:
                        self._note_truncation("edge_limit")
                        continue
                    paths.append(Path(edges=full, capability=cap,
                                      summary=_capability_summary(cap, current, grant_ns)))
                    for target_edge, target_node in self._onward(cap, current, grant_ns):
                        if len(full) + 1 > max_hops:
                            self._note_truncation("edge_limit")
                            continue
                        if target_node.kind != "ServiceAccount":
                            # A privilege target (an admin ClusterRole). Reaching it IS the
                            # escalation, so the path ends here rather than being expanded:
                            # a role is not a principal and holds no bindings of its own.
                            paths.append(Path(
                                edges=full + [target_edge], capability=cap,
                                summary=f"{_capability_summary(cap, current, grant_ns)} "
                                        f"(reaches {target_node})"))
                            continue
                        if target_node.id in seen:
                            continue
                        seen.add(target_node.id)
                        nxt.append((target_node, full + [target_edge]))
            frontier = nxt
        # Shortest, then most-direct capability first, then stable by rendering, so the
        # same evidence always yields the same ordered paths (determinism matters: these
        # end up in reports and SARIF).
        return sorted(paths, key=lambda p: (p.hops, _CAP_ORDER.get(p.capability, 99),
                                            p.render()))

    def _onward(self, capability: str, current: Node,
                grant_ns: Optional[str] = None) -> list[tuple]:
        """[(edge, next_node)] a capability actually reaches, given THIS cluster's objects.

        Empty when nothing in the evidence can be reached, which is the difference between
        "holds a dangerous verb" and "has a path to a specific privilege here".

        `grant_ns` confines the walk. A capability granted through a RoleBinding exists
        only inside that namespace, so it can neither bind a role cluster-wide nor take
        over an identity living somewhere else.
        """
        cnode = Node("Capability", capability, grant_ns)
        out = []
        if capability in ("bind-roles", "modify-bindings"):
            if grant_ns is not None:
                # Namespace-confined: the principal can create RoleBindings in its own
                # namespace, which grants the role's rules THERE. That is real, but it is
                # not "becomes cluster-admin", so no cluster-wide privilege hop is emitted.
                return out
            for role in self._admin_roles():
                out.append((Edge(cnode, role, "reaches",
                                 f"{role} exists in this cluster and can be bound to this "
                                 f"principal using that capability",
                                 evidence=str(role)), role))
        elif capability in _PRINCIPAL_HOPS:
            how = {"impersonate": "can impersonate this identity",
                   "create-workload": "can run a workload as this ServiceAccount",
                   "exec-pods": "can exec into a pod running as this ServiceAccount",
                   "read-secrets": "can read this ServiceAccount's token Secret"}[capability]
            # A namespaced grant reaches only its own namespace's identities; a
            # cluster-wide one reaches the principal's namespace (where its workloads and
            # tokens live). Neither ever crosses into an unrelated namespace.
            scope_ns = grant_ns if grant_ns is not None else current.namespace
            for other in self._other_principals(scope_ns):
                if other.id == current.id:
                    continue
                out.append((Edge(cnode, other, "reaches", how, evidence=str(other)), other))
                if len(out) >= MAX_ONWARD_TARGETS:
                    self._note_truncation("onward_target_limit")
                    break
        return out

    def _note_truncation(self, reason: str) -> None:
        """Record that a bound was hit. First reason wins, so the message names the bound
        that actually stopped the walk rather than the last one encountered."""
        if getattr(self, "_truncated_reason", None) is None:
            self._truncated_reason = reason

    # -- summary ---------------------------------------------------------- #
    def escalation_summary(self, principal: Node,
                           *, max_hops: int = MAX_HOPS) -> tuple[Optional[str], list]:
        """(one-line summary, paths) for a principal. `None` when nothing escalates, which
        is what callers use to decide whether to tag a finding at all."""
        paths = self.escalation_paths(principal, max_hops=max_hops)
        if not paths:
            return None, []
        best: dict = {}
        for p in paths:
            best.setdefault(p.capability, p)      # shortest path per capability wins
        parts = [best[cap].summary
                 for cap in sorted(best, key=lambda c: _CAP_ORDER.get(c, 99))]
        return "; ".join(parts), paths


def _capability_summary(capability: str, principal: Node,
                        grant_ns: Optional[str] = None) -> str:
    text = {
        "cluster-admin": "already holds cluster-admin-equivalent (verbs=* on resources=*)",
        "bind-roles": "bind/escalate roles, grant itself cluster-admin",
        "modify-bindings": "write (Cluster)RoleBindings, bind any role to itself",
        "impersonate": "impersonate a higher-privileged identity",
        "create-workload": "create a workload with any ServiceAccount / privileged, node, "
                           "cluster",
        "exec-pods": "exec into another pod and use its ServiceAccount token",
        "read-secrets": "read secrets, steal another identity's token",
    }.get(capability, capability)
    if grant_ns is not None:
        # The scope belongs in the sentence, not in a footnote: "IS cluster-admin" and
        # "is admin inside team-a" are different security statements.
        text += f" (within namespace {grant_ns} only)"
    return text


def principal_for_workload(workload: dict, namespace: Optional[str]) -> Node:
    """The ServiceAccount principal a workload runs as. Kubernetes defaults an unset
    `serviceAccountName` to `default`, and that default SA is a real, bindable identity, so
    it is modelled rather than skipped."""
    from .evidence import Evidence
    sa = Evidence.pod_spec(workload).get("serviceAccountName") or "default"
    return Node("ServiceAccount", sa, namespace)
