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
def ref(resource: dict, kind: str = None):
    """Build a ResourceRef, generically capturing labels/annotations and the resource's
    *direct* owner (one ownerReferences hop, e.g. a DaemonSet/StatefulSet-owned Pod).
    Resolving a further hop (ReplicaSet->Deployment, Job->CronJob) needs Evidence to look
    up the intermediate object, which this shared, evidence-free helper doesn't have, 
    see workload_pod_security.py's own `ref(ev, res)` wrapper for that."""
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
