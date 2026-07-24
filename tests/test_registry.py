"""Registry, mapping-engine build & validation (§6)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform


def test_all_shards_and_rules_load():
    p = build_platform()
    # A floor, not an equality: adding a shard is expected, silently losing one is not.
    assert len(p.registry.shard_names()) >= 11
    assert p.rule_count() >= 40


def test_no_validation_problems():
    p = build_platform()
    # Every rule's technique id must exist in the vendored taxonomy; aliases must resolve.
    assert p.validation_problems == [], p.validation_problems


def test_no_duplicate_rule_ids():
    p = build_platform()
    ids = p.registry.rules.ids()
    assert len(ids) == len(set(ids))



def test_every_tactic_has_coverage():
    p = build_platform()
    cov = p.coverage()
    assert len(cov) == 9
    # At least the high-value tactics must have rules.
    for tactic in ("Privilege Escalation", "Persistence", "Credential Access",
                   "Lateral Movement", "Initial Access"):
        assert cov[tactic] > 0


def test_scoped_roles_generated_per_plugin():
    p = build_platform()
    roles = p.loader.scoped_roles()
    # the invariant is one scoped role per shard, derived, so a new shard can't drift
    assert len(roles) == len(p.registry.shard_names())
    assert all(r["kind"] == "ClusterRole" for r in roles)


def test_every_shard_has_nonempty_rbac_needs():
    # A shard with an empty role can never actually run live, every shard must declare
    # at least one real K8s permission (incl. synthetic-evidence shards like
    # cluster_control_plane, which needs `pods` to recover control-plane flags live).
    p = build_platform()
    for name, verbs in p.registry.rbac_verbs().items():
        assert verbs, f"shard {name!r} has no RBAC verbs, it cannot function live"


def test_deployment_manifest_binds_every_shard():
    p = build_platform()
    manifest = p.loader.deployment_manifest(service_account="k8smatrixwarden-scanner",
                                            namespace="k8smatrixwarden-system")
    assert manifest["kind"] == "List"
    kinds = [item["kind"] for item in manifest["items"]]
    shard_count = len(p.registry.shard_names())
    assert kinds.count("ClusterRole") == shard_count
    assert kinds.count("ClusterRoleBinding") == shard_count
    assert kinds.count("ServiceAccount") == 1
    assert kinds.count("Namespace") == 1
    # every binding must reference a role that was actually emitted, and the SA we asked for
    role_names = {i["metadata"]["name"] for i in manifest["items"] if i["kind"] == "ClusterRole"}
    for item in manifest["items"]:
        if item["kind"] != "ClusterRoleBinding":
            continue
        assert item["roleRef"]["name"] in role_names
        assert item["subjects"][0] == {"kind": "ServiceAccount", "name": "k8smatrixwarden-scanner",
                                       "namespace": "k8smatrixwarden-system"}
    # every rule verb across every emitted role must be read-only (get/list/watch)
    write_verbs = {"create", "update", "patch", "delete", "deletecollection"}
    for item in manifest["items"]:
        if item["kind"] != "ClusterRole":
            continue
        for rule in item["rules"]:
            assert not (write_verbs & set(rule["verbs"])), \
                f"{item['metadata']['name']} grants a write verb: {rule}"


def test_deployment_manifest_no_create_namespace():
    p = build_platform()
    manifest = p.loader.deployment_manifest(create_namespace=False)
    kinds = [item["kind"] for item in manifest["items"]]
    assert "Namespace" not in kinds


def test_generated_object_names_are_dns_1123_safe():
    # Shard names use underscores; generated K8s object names must NOT, a hardened
    # cluster (Gatekeeper/Kyverno enforcing DNS-1123) would reject them on apply.
    import re
    dns1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    p = build_platform()
    manifest = p.loader.deployment_manifest()
    for item in manifest["items"]:
        name = item["metadata"]["name"]
        assert "_" not in name, f"{item['kind']} name {name!r} contains an underscore"
        assert dns1123.match(name), f"{item['kind']} name {name!r} is not DNS-1123"


# --------------------------------------------------------------------------- #
# Control-plane flag rules must not invent findings from unreadable evidence
#
# On EKS/GKE/AKS the control plane is provider-owned and its kube-system static Pods are
# invisible, so ComponentConfig arrives with no apiServer/etcd/kubelet section. A predicate
# like `lambda v: not v` reads that as "the flag is off" and reports a Critical finding for
# a setting that was never readable.
# --------------------------------------------------------------------------- #
def _control_plane_rule_ids(component_config):
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.core.evidence import EvidenceCollector
    from k8smatrixwarden.core.models import (ScanMode, ScanRequest, Scope, ScopeLevel,
                                              Selector)

    class _Fixture(EvidenceCollector):
        def __init__(self):
            super().__init__()
            self.fetched_ok = True

        def _fetch(self, kind, bucket):
            return list(component_config) if bucket == "componentconfig" else []

    p = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                          selector=Selector(modules=["cluster_control_plane"]),
                          mode=ScanMode.SYNC)
    return sorted(f.rule_id for f in ScannerAgent(p).scan(request, _Fixture()).findings)


def test_managed_control_plane_produces_no_flag_findings():
    # ComponentConfig exists but carries no component sections, the managed-cluster shape
    assert _control_plane_rule_ids(
        [{"kind": "ComponentConfig", "spec": {"version": None}}]) == []


def test_absent_component_config_produces_no_flag_findings():
    assert _control_plane_rule_ids([]) == []


def test_readable_insecure_control_plane_still_fires_every_rule():
    # the guard must not silence real findings on a self-managed cluster
    ids = _control_plane_rule_ids([{"kind": "ComponentConfig", "spec": {
        "apiServer": {"anonymousAuth": True, "insecurePort": 6443,
                      "auditLogPath": "", "encryptionProvider": ""},
        "etcd": {"clientCertAuth": False},
        "kubelet": {"anonymousAuth": True, "readOnlyPort": 10255,
                    "authorizationMode": "AlwaysAllow"},
        "version": "v1.24.0"}}])
    assert ids == ["apiserver-anonymous-auth", "apiserver-audit-logging",
                   "apiserver-insecure-port", "deprecated-k8s-version",
                   "etcd-client-cert-auth", "etcd-encryption-missing",
                   "kubelet-anonymous-auth", "kubelet-authz-always-allow",
                   "kubelet-read-only-port"]


def test_one_readable_component_does_not_unlock_the_others():
    """A cluster exposing only the kubelet config must be graded on the kubelet alone."""
    ids = _control_plane_rule_ids([{"kind": "ComponentConfig", "spec": {
        "kubelet": {"anonymousAuth": True, "readOnlyPort": 0,
                    "authorizationMode": "Webhook"}}}])
    assert ids == ["kubelet-anonymous-auth"]
