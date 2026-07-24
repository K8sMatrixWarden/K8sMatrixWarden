"""RBAC shard, built-in default roles are not flagged, blast radius follows role kind."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import Scope, ScopeLevel
from k8smatrixwarden.shards.rbac_identity import RbacIdentityShard


def _run(rule_id, objs):
    shard = RbacIdentityShard()
    rule = next(r for r in shard.rules() if r.id == rule_id)
    buckets = {"clusterroles": [o for o in objs if o.get("kind") == "ClusterRole"],
               "roles": [o for o in objs if o.get("kind") == "Role"],
               "clusterrolebindings": [], "rolebindings": []}
    ev = Evidence(buckets, Scope(ScopeLevel.CLUSTER))
    return list(rule.check(rule, ev, Scope(ScopeLevel.CLUSTER)))


def _cr(name, verbs=("*",), resources=("*",), labels=None, kind="ClusterRole", ns=None):
    meta = {"name": name}
    if labels:
        meta["labels"] = labels
    if ns:
        meta["namespace"] = ns
    return {"kind": kind, "metadata": meta,
            "rules": [{"verbs": list(verbs), "resources": list(resources)}]}


def test_builtin_cluster_admin_is_not_flagged():
    assert _run("rbac-wildcard-verbs", [_cr("cluster-admin")]) == []


def test_bootstrapping_labelled_role_is_not_flagged():
    obj = _cr("something", labels={"kubernetes.io/bootstrapping": "rbac-defaults"})
    assert _run("rbac-wildcard-verbs", [obj]) == []


def test_system_prefixed_role_is_not_flagged():
    assert _run("rbac-wildcard-verbs", [_cr("system:controller:x")]) == []


def test_custom_wildcard_role_is_still_flagged():
    out = _run("rbac-wildcard-verbs", [_cr("super-role")])
    assert len(out) == 1 and out[0].resource.name == "super-role"


def test_namespaced_role_gets_namespace_blast_radius():
    out = _run("rbac-wildcard-verbs", [_cr("app-role", kind="Role", ns="prod")])
    assert len(out) == 1
    assert out[0].blast_radius.label == "Namespace"


def test_clusterrole_keeps_cluster_blast_radius():
    out = _run("rbac-wildcard-verbs", [_cr("super-role")])
    assert out[0].blast_radius.label == "Cluster-wide"
