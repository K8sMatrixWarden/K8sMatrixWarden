"""
Plugin model & loader (§21).

Every scanner is a plugin that self-declares (rules it owns · evidence it needs · RBAC
verbs it requires). The loader mints a scoped RoleBinding per plugin from those verbs
(least-privilege *below* the agent level, §20). Built-in shards register in-process;
third-party plugins would be sandboxed (WASM/gRPC), represented here by the manifest's
`isolation` field.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PluginManifest:
    name: str
    version: str = "1.0.0"
    kind: str = "domain_shard"
    isolation: str = "in_process"          # in_process | wasm | grpc
    evidence_k8s: list[str] = field(default_factory=list)
    evidence_external: list[str] = field(default_factory=list)
    rbac_verbs: list[dict] = field(default_factory=list)

    def role_name(self) -> str:
        """DNS-1123-safe ClusterRole name for this plugin.

        Shard names use underscores (e.g. `admission_control`), which are NOT valid in
        DNS-1123 object names. RBAC's own validator tolerates them, but hardened clusters
        commonly enforce DNS-1123 on all resources via admission policies (Gatekeeper/
        Kyverno) and would reject an underscore name on apply, so hyphenate.
        """
        return f"k8smatrixwarden-plugin-{self.name.replace('_', '-')}"

    def scoped_role(self) -> dict:
        """Generate the least-privilege ClusterRole this plugin actually needs (§20)."""
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": self.role_name()},
            "rules": self.rbac_verbs or [],
        }


class PluginLoader:
    """
    Discovers and loads domain shards. Built-in shards live under `k8smatrixwarden.shards`;
    custom shards can be dropped into any importable package passed via `extra_packages`.
    """

    def __init__(self, registry, extra_packages: Optional[list[str]] = None):
        self.registry = registry
        self.extra_packages = extra_packages or []
        self.manifests: dict[str, PluginManifest] = {}

    def load_builtin(self) -> None:
        from .. import shards as shards_pkg
        self._load_from_package(shards_pkg)

    def load_extras(self) -> None:
        for pkg_name in self.extra_packages:
            try:
                pkg = importlib.import_module(pkg_name)
                self._load_from_package(pkg)
            except Exception as exc:  # pragma: no cover
                print(f"[plugin-loader] could not load {pkg_name}: {exc}")

    def _load_from_package(self, pkg) -> None:
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name in ("base", "__init__"):
                continue
            module = importlib.import_module(f"{pkg.__name__}.{mod.name}")
            factory = getattr(module, "SHARD", None) or getattr(module, "get_shard", None)
            if factory is None:
                continue
            shard = factory() if callable(factory) else factory
            self.registry.register_shard(shard)
            self.manifests[shard.name] = shard.manifest()

    def scoped_roles(self) -> list[dict]:
        return [m.scoped_role() for m in self.manifests.values()]

    def deployment_manifest(self, *, service_account: str = "k8smatrixwarden-scanner",
                            namespace: str = "k8smatrixwarden-system",
                            create_namespace: bool = True) -> dict:
        """
        A single, ready-to-`kubectl apply -f` manifest that actually grants the tool the
        least-privilege access it declared (§20/§21): one ServiceAccount + one scoped
        ClusterRole/ClusterRoleBinding pair *per shard*. Nothing here grants write access, 
        every generated rule is get/list/watch only, matching what each shard's rules
        declared they need (no more).

        Returned as a Kubernetes `List` object, which `kubectl apply -f` accepts natively
        as a single JSON/YAML file (no external yaml dependency required).
        """
        items: list[dict] = []
        if create_namespace:
            items.append({"apiVersion": "v1", "kind": "Namespace",
                          "metadata": {"name": namespace}})
        items.append({
            "apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": service_account, "namespace": namespace},
        })
        for manifest in self.manifests.values():
            role = manifest.scoped_role()
            if not role["rules"]:
                continue     # nothing to bind for a shard with no K8s API needs
            items.append(role)
            items.append({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": f"{role['metadata']['name']}-binding"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                           "kind": "ClusterRole", "name": role["metadata"]["name"]},
                "subjects": [{"kind": "ServiceAccount", "name": service_account,
                             "namespace": namespace}],
            })
        return {"apiVersion": "v1", "kind": "List", "items": items}
