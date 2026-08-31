"""
DomainShard base class (§5.1).

A shard is a plugin that owns a set of Rules sharing an evidence-fetch pattern. It declares
three things (§21): the rules it owns, the K8s resources it needs, and the RBAC verbs it
requires (from which the Plugin Loader mints a scoped RoleBinding).
"""
from __future__ import annotations

from typing import Iterable

from ..core.models import Rule
from ..core.plugin import PluginManifest


class DomainShard:
    #: unique shard/module name (used as the `module` selector value)
    name: str = "base"
    #: human title
    title: str = "Base Shard"
    #: circled index from the spec, for display
    index: str = ""
    version: str = "1.0.0"
    isolation: str = "in_process"
    #: external evidence sources (e.g. "cloud_iam_api"), if any
    external_evidence: list[str] = []

    def rules(self) -> list[Rule]:
        raise NotImplementedError

    # -- derived declarations --------------------------------------------- #
    def resource_types(self) -> set[str]:
        out: set[str] = set()
        for r in self.rules():
            out.update(r.evidence_needs or r.resource_scope)
        return out

    def rbac_verbs(self) -> list[dict]:
        """
        Default: read-only get/list/watch on every K8s resource type this shard needs.
        Shards may override for tighter or different scopes.
        """
        from ..core.evidence import KIND_ALIASES
        api_groups = _API_GROUPS
        by_group: dict[str, set[str]] = {}
        for kind in self.resource_types():
            if kind in ("ComponentConfig", "CloudIAM"):
                continue  # synthetic, not real API resources
            group = api_groups.get(kind, "")
            plural = KIND_ALIASES.get(kind, kind.lower())
            by_group.setdefault(group, set()).add(plural)
        rules = []
        for group, resources in sorted(by_group.items()):
            rules.append({
                "apiGroups": [group],
                "resources": sorted(resources),
                "verbs": ["get", "list", "watch"],
            })
        return rules

    def manifest(self) -> PluginManifest:
        return PluginManifest(
            name=self.name,
            version=self.version,
            isolation=self.isolation,
            evidence_k8s=sorted(self.resource_types()),
            evidence_external=list(self.external_evidence),
            rbac_verbs=self.rbac_verbs(),
        )


# Kind -> apiGroup, for scoped-role generation.
_API_GROUPS = {
    "Deployment": "apps", "DaemonSet": "apps", "StatefulSet": "apps", "ReplicaSet": "apps",
    "Job": "batch", "CronJob": "batch",
    "NetworkPolicy": "networking.k8s.io", "Ingress": "networking.k8s.io",
    "Role": "rbac.authorization.k8s.io", "RoleBinding": "rbac.authorization.k8s.io",
    "ClusterRole": "rbac.authorization.k8s.io",
    "ClusterRoleBinding": "rbac.authorization.k8s.io",
    "MutatingWebhookConfiguration": "admissionregistration.k8s.io",
    "ValidatingWebhookConfiguration": "admissionregistration.k8s.io",
}


# ----------------------------------------------------------------------- #
# Small helpers shared by rule check functions.
# ----------------------------------------------------------------------- #
#: One hop past these intermediates is the controller a report should name. A Pod's direct
#: owner is a ReplicaSet or a Job, which is an implementation detail of the Deployment or
#: CronJob the operator actually manages.
_INTERMEDIATE_OWNERS = {"ReplicaSet": "Deployment", "Job": "CronJob"}


def resolve_owner(rref, evidence):
    """Resolve a ResourceRef's owner past the intermediate controller, where evidence allows.

    The single implementation of owner attribution. It used to live only in
    workload_pod_security, so a Pod's findings from that shard named `Deployment/api` while
    the same Pod's findings from another shard named `ReplicaSet/api-5f8b`: one object with
    two owners inside a single scan, which splits a workload in two anywhere a report groups
    by owner. Applied centrally after rules run, every finding on a resource agrees.

    An ownerReference never leaves its object's namespace, so every lookup is namespaced.
    An unconfirmable hop keeps the direct owner rather than guessing."""
    import dataclasses
    if rref is None or not rref.owner_kind:
        return rref
    target = _INTERMEDIATE_OWNERS.get(rref.owner_kind)
    if not target:
        return rref
    mid = _lookup(evidence, rref.owner_kind, rref.owner_name, rref.namespace)
    if not mid:
        return rref
    mid_kind, mid_name = _direct_owner(mid.get("metadata", {}) or {})
    if mid_kind != target:
        return rref
    labels, annotations = rref.labels, rref.annotations
    top = _lookup(evidence, mid_kind, mid_name, rref.namespace)
    if top:
        meta = top.get("metadata", {}) or {}
        # Helm/ArgoCD/Flux stamp their markers on the controller, not the Pod.
        labels = meta.get("labels", {}) or {}
        annotations = meta.get("annotations", {}) or {}
    return dataclasses.replace(rref, owner_kind=mid_kind, owner_name=mid_name,
                               labels=labels, annotations=annotations)


def _lookup(evidence, kind: str, name: str, namespace):
    """(kind, name, namespace) -> object, from an index memoised on the shared snapshot.
    Scanning the full object list per finding made every workload rule quadratic."""
    if not kind or not name or evidence is None:
        return None
    cache = getattr(evidence, "_owner_index", None)
    if cache is None:
        cache = {}
        try:
            evidence._owner_index = cache
        except Exception:          # an exotic Evidence: correctness over speed
            pass
    by_key = cache.get(kind)
    if by_key is None:
        by_key = {}
        for o in evidence.get(kind, all_scopes=True):
            md = o.get("metadata") or {}
            by_key.setdefault((md.get("name"), md.get("namespace")), o)
        cache[kind] = by_key
    return by_key.get((name, namespace))


def ref(resource: dict, kind: str = None):
    """Build a ResourceRef, generically capturing labels/annotations and the resource's
    *direct* owner (one ownerReferences hop, e.g. a DaemonSet/StatefulSet-owned Pod).
    The further hop (ReplicaSet->Deployment, Job->CronJob) needs Evidence, and is applied
    to every finding centrally once rules have run, see `resolve_owner`."""
    from ..core.models import ResourceRef
    meta = resource.get("metadata", {}) or {}
    owner_kind, owner_name = _direct_owner(meta)
    return ResourceRef(kind=kind or resource.get("kind", ""),
                       name=meta.get("name", ""),
                       namespace=meta.get("namespace"),
                       owner_kind=owner_kind, owner_name=owner_name,
                       labels=meta.get("labels", {}) or {},
                       annotations=meta.get("annotations", {}) or {})


def _direct_owner(meta: dict):
    """The controller-flagged ownerReferences entry (or the first one), if any."""
    owners = meta.get("ownerReferences", []) or []
    if not owners:
        return None, None
    primary = next((o for o in owners if o.get("controller")), owners[0])
    return primary.get("kind"), primary.get("name")
