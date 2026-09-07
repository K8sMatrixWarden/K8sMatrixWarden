"""
Federation blast-radius, "if this cluster is compromised, what does the attacker reach in
the others?"

The hard part of multi-cluster is knowing the clusters are actually ONE blast radius rather
than assuming it. This engine never assumes: it only surfaces a cross-cluster edge where the
SAME non-default identity, a custom ClusterRole, ServiceAccount, cloud IAM role, Secret or
ConfigMap of the same kind+name, appears in two or more clusters. That collision is a
CANDIDATE shared trust principal (shared IaC, a federated SA, a reused cloud role) worth
verifying, not proof on its own, since two clusters could coincidentally name a role the
same. Built-in/default identities (cluster-admin, system:*, default SA, kube-root-ca.crt)
are excluded because they exist in every cluster by design. No candidate ⇒ the clusters are
reported as independent, not silently linked.

Pure and offline: it takes the ScanResults the caller already has (one per cluster, newest
each) and correlates. It reruns nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .correlation import belongs_to
from .results import ScanResult

# Kinds whose (kind, name) is a durable identity worth correlating across clusters. A Pod or
# Deployment name recurring across clusters is noise; a ClusterRole or cloud IAM role
# recurring is a shared trust relationship.
_IDENTITY_KINDS = {
    "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding",
    "ServiceAccount", "CloudIAM", "ManagedIdentity", "Secret", "ConfigMap",
}
# Built-in / default identities exist independently in EVERY cluster, a kind+name collision
# on these is not a shared trust principal, it is Kubernetes shipping the same defaults
# everywhere. Counting them would manufacture false cross-cluster paths (the #1 federation
# false-positive), so they are excluded from the shared-identity join.
_BUILTIN_NAMES = {
    "cluster-admin", "admin", "edit", "view",             # default user-facing ClusterRoles
    "default",                                             # default ServiceAccount per ns
    "kube-root-ca.crt", "kube-dns", "coredns", "extension-apiserver-authentication",
    # Objects the control plane, kubeadm, or a managed provider ships in every cluster.
    # A live audit found `ConfigMap/kube-proxy` drawn as a cross-cluster path between an
    # operator's laptop cluster and an unrelated EKS cluster. Nothing was wrong with the
    # join; kube-proxy simply exists in both, as it does in every cluster on earth. The
    # exclusion list is what was wrong, so it now covers the rest of that family.
    "kube-proxy", "kubelet-config", "kube-apiserver", "kube-controller-manager",
    "kube-scheduler", "cluster-info", "kubeadm-config", "kubelet-serving-ca",
    "aws-auth", "amazon-vpc-cni", "gke-common-webhook-config", "azure-ip-masq-agent",
    "cilium-config", "calico-config", "kube-flannel-cfg", "weave-net",
    "coredns-autoscaler", "metrics-server", "local-path-config", "ingress-nginx",
    "istio", "linkerd-config", "cert-manager", "tigera-operator",
}

#: Namespaces whose contents are shipped by Kubernetes or a provider, never by the
#: operator. A kind+name collision inside one of these says both clusters run Kubernetes.
_BUILTIN_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}

#: Names a rule emits when it could NOT determine what it was looking at. Joining two of
#: these together says "both clusters contain something we could not identify, therefore
#: it is the same thing", which is an UNKNOWN promoted to a claim -- the one conversion
#: this project refuses everywhere else. A live audit found `CloudIAM/?` linking two
#: clusters on exactly that basis; `?` is cloud_iam.py's fallback for a missing
#: serviceAccount field.
_UNKNOWN_NAMES = {"?", "-", "unknown", "unnamed", "n/a", "none", "null", "<unknown>"}


def _is_builtin_identity(kind: str, name: str, namespace: str = "") -> bool:
    """Would this kind+name collide in two clusters that share nothing at all?"""
    if (namespace or "") in _BUILTIN_NAMESPACES:
        return True
    return (name in _BUILTIN_NAMES
            or name.startswith("system:")
            or name.startswith("kubeadm:")
            or name.startswith("kube-")            # kube-* is control-plane convention
            or name.startswith("eks-")             # provider-managed
            or name.startswith("gke-")
            or name.startswith("aks-"))


def _is_unidentified(name: str) -> bool:
    """True when the name carries no identity, so two of them are not one principal."""
    return not (name or "").strip() or (name or "").strip().lower() in _UNKNOWN_NAMES


#: Kinds that live inside a namespace. Their identity is namespace-scoped: a Role called
#: `secret-reader` in `team-a` and one in `team-b` are different grants that happen to
#: share a word, and joining them across clusters on the bare name would be a guess
#: dressed as evidence. Cluster-scoped kinds have no namespace and join on name alone.
_NAMESPACED_KINDS = {"Role", "RoleBinding", "ServiceAccount", "Secret", "ConfigMap"}


#: Cluster labels that are placeholders rather than identities. A scan carrying one of
#: these was read from somewhere that could not name its cluster, so two such scans may be
#: one cluster or two unrelated ones. An edge resting on one is reported, because
#: suppressing a cluster would hide real findings, but it is reported as unverified so it
#: is never mistaken for a cross-cluster path between two known clusters.
_UNVERIFIED_CLUSTERS = {"", "target-cluster", "live-cluster", "unidentified-cluster",
                        "unknown", "unknown-cluster"}


#: Scan modes that did not observe a cluster. A fixture run is sample data with a label on
#: it, not a place an attacker could be, so it cannot be one END of a cross-cluster path.
_NON_CLUSTER_MODES = {"mock", "fixture"}


def cluster_identity_verified(name: str, mode: str = "") -> bool:
    """Did this scan actually establish which cluster it was reading?

    Two ways to fail. The label may be a placeholder rather than a name -- see
    _UNVERIFIED_CLUSTERS. Or the scan may never have touched a cluster at all: the bundled
    fixture is saved under `mock-cluster`, which looks like a perfectly good identity and
    is not one. That matters because the fixture deliberately contains names like
    `super-role` and `default-admin`, so any real cluster that happens to use one would be
    handed a cross-cluster blast-radius edge to a sample data file.
    """
    if (mode or "").strip().lower() in _NON_CLUSTER_MODES:
        return False
    return (name or "").strip().lower() not in _UNVERIFIED_CLUSTERS


def identity_key(kind: str, name: str, namespace: str = "") -> str:
    """The join key. Namespaced kinds carry their namespace; cluster-scoped ones do not."""
    if kind in _NAMESPACED_KINDS and (namespace or ""):
        return f"{kind}/{namespace}/{name}"
    return f"{kind}/{name}"

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

#: What KIND of thing is shared, so a consumer can tell "the same ClusterRole grants this
#: in both clusters" from "the same Secret name exists in both". Workload kinds are
#: deliberately absent from `_IDENTITY_KINDS` above and therefore from this map: a
#: Deployment called `api` in two clusters is a naming convention, not a trust link, and
#: correlating it would manufacture exactly the speculative path this module refuses to
#: draw. The category exists in the vocabulary for a future evidence source (a shared
#: image digest, a federated workload identity) that could justify it.
RELATIONSHIPS = ("shared-identity", "shared-resource", "shared-workload")
_KIND_RELATIONSHIP = {
    "ClusterRole": "shared-identity", "Role": "shared-identity",
    "ClusterRoleBinding": "shared-identity", "RoleBinding": "shared-identity",
    "ServiceAccount": "shared-identity", "CloudIAM": "shared-identity",
    "ManagedIdentity": "shared-identity",
    "Secret": "shared-resource", "ConfigMap": "shared-resource",
}


@dataclass
class SharedIdentity:
    key: str                       # "ClusterRole/super-role"
    kind: str
    name: str
    clusters: list                 # cluster names it appears in (>=2)
    tactics: list                  # union of MITRE tactics it is implicated in
    worst_severity: str
    findings: list                 # [{cluster, rule_id, title, severity, tactic}]
    #: For namespaced kinds, part of the identity rather than decoration: a Role named
    #: `secret-reader` in two different namespaces is two different grants.
    namespace: str = ""
    #: True only when EVERY cluster on this edge was actually identified. False means at
    #: least one side carries a placeholder label, so "two clusters" is itself unproven.
    cluster_identity_verified: bool = True
    #: What sort of link this is: shared-identity (a trust principal) or shared-resource
    #: (a named object). See RELATIONSHIPS.
    relationship: str = "shared-identity"
    #: `candidate` , the same kind+name exists in both clusters. That is a lead to verify,
    #: NOT proof the two are the same principal (two clusters can coincidentally name a
    #: role the same). `confirmed` , runtime evidence in more than one cluster names this
    #: resource as being acted on, which is observation, not inference.
    status: str = "candidate"
    #: Why it is not confirmed / what would confirm it.
    verification: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "kind": self.kind, "name": self.name,
                "clusters": self.clusters, "namespace": self.namespace,
                "cluster_identity_verified": self.cluster_identity_verified,
                "tactics": self.tactics,
                "worst_severity": self.worst_severity, "findings": self.findings,
                "relationship": self.relationship, "status": self.status,
                "verification": self.verification}


@dataclass
class FederationReport:
    clusters: list = field(default_factory=list)          # [{name, rating, risk, findings}]
    shared_identities: list = field(default_factory=list)  # list[SharedIdentity]
    federated_tactics: dict = field(default_factory=dict)  # tactic -> finding count (all clusters)
    top_tactic: str = ""
    summary: str = ""

    def as_dict(self) -> dict:
        return {"clusters": self.clusters,
                "shared_identities": [s.as_dict() for s in self.shared_identities],
                "federated_tactics": self.federated_tactics,
                "top_tactic": self.top_tactic,
                "cross_cluster_paths": len(self.shared_identities),
                "summary": self.summary}


def _observed_in(by_cluster: dict, name: str) -> set:
    """Clusters whose saved runtime block CONFIRMS activity on a resource of this name.

    This is the only thing that upgrades a shared identity from `candidate` to
    `confirmed`, because it is observation rather than a name collision. Requires a scan
    that actually carried a runtime feed; mock and runtime-less scans contribute nothing,
    which is why the default stays `candidate`."""
    hits = set()
    if not name:
        return hits
    for cname, result in by_cluster.items():
        for c in ((result.runtime or {}).get("correlation") or {}).get(
                "correlations", []):
            if c.get("confidence") != "confirmed":
                continue
            resource = str(c.get("resource") or "")
            # Same ownership test the correlator uses. A loose prefix match here would
            # promote a shared identity to `confirmed` on the strength of an event about a
            # differently-named workload that merely shares a prefix.
            if belongs_to(resource, name):
                hits.add(cname)
    return hits


def _worst(sevs: list) -> str:
    return max(sevs, key=lambda s: _SEV_RANK.get(s, 0)) if sevs else "INFO"


def latest_per_cluster(store) -> list:
    """Newest saved ScanResult for each distinct cluster in a ReportStore, the offline
    input for build_federation. A cluster that was scanned many times contributes once."""
    seen: dict = {}
    for meta in store.list():                       # already sorted newest-first
        if meta.cluster not in seen:
            seen[meta.cluster] = meta.scan_id
    return [store.load(sid) for sid in seen.values()]


def build_federation(results: list) -> FederationReport:
    """Correlate one ScanResult per cluster into a blast-radius view."""
    # De-dup to newest scan per cluster, preserving input order for stability.
    by_cluster: dict = {}
    for r in results:
        by_cluster.setdefault(r.cluster_name, r)  # caller passes newest-first; keep first

    clusters = [{"name": c, "rating": r.risk.rating, "risk": r.risk.cluster_risk,
                 "findings": sum(v for k, v in r.counts.items() if k != "INFO")}
                for c, r in by_cluster.items()]

    # identity key -> {cluster -> [finding dicts]}
    idx: dict = {}
    fed_tactics: dict = {}
    for cname, r in by_cluster.items():
        for f in r.findings:
            if f.severity.weight <= 0:
                continue
            for m in f.mitre:
                fed_tactics[m.tactic.value] = fed_tactics.get(m.tactic.value, 0) + 1
            if f.resource.kind not in _IDENTITY_KINDS:
                continue
            if _is_builtin_identity(f.resource.kind, f.resource.name or "",
                                    f.resource.namespace or ""):
                continue        # default identity present in every cluster, not a shared path
            if _is_unidentified(f.resource.name or ""):
                continue        # an unnamed thing is not evidence of a shared principal
            key = identity_key(f.resource.kind, f.resource.name or "",
                               f.resource.namespace or "")
            tactic = f.mitre[0].tactic.value if f.mitre else ""
            idx.setdefault(key, {}).setdefault(cname, []).append(
                {"cluster": cname, "rule_id": f.rule_id, "title": f.title,
                 "severity": f.severity.label, "tactic": tactic})

    shared = []
    for key, per_cluster in idx.items():
        if len(per_cluster) < 2:
            continue                # present in only one cluster, not a cross-cluster path
        kind, _, rest = key.partition("/")
        # A namespaced key is kind/namespace/name; a cluster-scoped one is kind/name.
        namespace, _, tail = rest.partition("/")
        name, namespace = (tail, namespace) if tail else (rest, "")
        flat = [fd for fds in per_cluster.values() for fd in fds]
        tactics = sorted({fd["tactic"] for fd in flat if fd["tactic"]})
        observed = _observed_in(by_cluster, name)
        verified_sides = all(
            cluster_identity_verified(c, getattr(by_cluster.get(c), "mode", ""))
            for c in per_cluster)
        # An edge whose endpoints are not both identified cannot be confirmed either: the
        # runtime evidence would be proving activity in a cluster we cannot name.
        confirmed = len(observed) >= 2 and verified_sides
        shared.append(SharedIdentity(
            key=key, kind=kind, name=name, namespace=namespace,
            clusters=sorted(per_cluster.keys()),
            tactics=tactics,
            worst_severity=_worst([fd["severity"] for fd in flat]),
            findings=flat,
            relationship=_KIND_RELATIONSHIP.get(kind, "shared-resource"),
            cluster_identity_verified=verified_sides,
            status="confirmed" if confirmed else "candidate",
            verification=(
                "at least one side of this edge is not an observed cluster -- a "
                "placeholder label, or a fixture/mock scan -- so it is not evidence of a "
                "path BETWEEN two clusters; scan each cluster live through its own "
                "kubeconfig context to give it a real identity"
                if not verified_sides else
                f"runtime evidence names this resource in {', '.join(sorted(observed))}"
                if confirmed else
                "same kind+name in both clusters; confirm they are the same trust "
                "principal (shared IaC, federated identity, or a reused cloud role) "
                "before treating this as one blast radius")))
    shared.sort(key=lambda s: (-_SEV_RANK.get(s.worst_severity, 0), -len(s.clusters)))

    top_tactic = max(fed_tactics, key=fed_tactics.get) if fed_tactics else ""
    summary = _summary(clusters, shared, top_tactic)
    return FederationReport(clusters=clusters, shared_identities=shared,
                            federated_tactics=fed_tactics, top_tactic=top_tactic,
                            summary=summary)


def _summary(clusters, shared, top_tactic) -> str:
    n = len(clusters)
    if n < 2:
        return (f"Only {n} cluster in scope, add more clusters (scan each context) to see "
                f"cross-cluster blast radius.")
    if not shared:
        return (f"{n} clusters scanned; no shared identity links them, on this evidence they "
                f"are independent blast radii, not one federation.")
    crit = [s for s in shared if s.worst_severity == "CRITICAL"]
    lead = shared[0]
    return (f"{n} clusters share {len(shared)} non-default identity(ies), each a CANDIDATE "
            f"cross-cluster lateral-movement path to verify (same name ≠ guaranteed same "
            f"principal). {len(crit)} critical. Worst: {lead.key} spans "
            f"{', '.join(lead.clusters)}. Most-exposed tactic federation-wide: {top_tactic}.")
