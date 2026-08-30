"""
RBAC graph (core/rbac_graph.py): multi-hop escalation paths that are evidence-backed.

The point of this module is that it can be WRONG in a way the old flat check could not, it
claims a route exists. So most of these tests are about refusing to claim one: no target in
the evidence, no path; wrong namespace, no path; a cycle, no hang.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import Scope, ScopeLevel
from k8smatrixwarden.core.rbac_graph import (MAX_HOPS, Node, RbacGraph,
                                             principal_for_workload)


def _crole(name, rules):
    return {"kind": "ClusterRole", "metadata": {"name": name}, "rules": rules}


def _role(name, ns, rules):
    return {"kind": "Role", "metadata": {"name": name, "namespace": ns}, "rules": rules}


def _binding(name, role_kind, role_name, sa, sa_ns, ns=None):
    meta = {"name": name}
    if ns:
        meta["namespace"] = ns
    return {"kind": "RoleBinding" if ns else "ClusterRoleBinding", "metadata": meta,
            "roleRef": {"kind": role_kind, "name": role_name},
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": sa_ns}]}


def _sa(name, ns):
    return {"kind": "ServiceAccount", "metadata": {"name": name, "namespace": ns}}


def _graph(croles=(), roles=(), crbs=(), rbs=(), sas=()):
    return RbacGraph(list(croles), list(roles), list(crbs), list(rbs), list(sas))


SA = Node("ServiceAccount", "app", "prod")


# --------------------------------------------------------------------------- #
# Direct permission, one hop chain: SA -> binding -> role -> permission
# --------------------------------------------------------------------------- #
def test_direct_permission_path_names_the_binding_and_the_role():
    g = _graph(croles=[_crole("reader", [{"verbs": ["get"], "resources": ["secrets"]}])],
               crbs=[_binding("b", "ClusterRole", "reader", "app", "prod")])
    paths = g.permission_paths(SA, "get", "secrets")
    assert len(paths) == 1
    kinds = [n.kind for n in paths[0].nodes]
    assert kinds == ["ServiceAccount", "ClusterRoleBinding", "ClusterRole", "Permission"]
    assert paths[0].edges[0].relationship == "bound-by"
    assert paths[0].edges[1].relationship == "grants"
    assert "ClusterRoleBinding/b" == paths[0].edges[0].evidence


def test_permission_absent_yields_no_path():
    g = _graph(croles=[_crole("reader", [{"verbs": ["get"], "resources": ["configmaps"]}])],
               crbs=[_binding("b", "ClusterRole", "reader", "app", "prod")])
    assert g.permission_paths(SA, "get", "secrets") == []


def test_wildcard_verb_and_resource_satisfy_a_specific_permission():
    g = _graph(croles=[_crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
               crbs=[_binding("b", "ClusterRole", "god", "app", "prod")])
    assert g.permission_paths(SA, "delete", "pods")


# --------------------------------------------------------------------------- #
# Role vs ClusterRole, RoleBinding vs ClusterRoleBinding, namespace boundaries
# --------------------------------------------------------------------------- #
def test_rolebinding_to_namespaced_role_resolves_in_its_own_namespace():
    g = _graph(roles=[_role("r", "prod", [{"verbs": ["get"], "resources": ["secrets"]}])],
               rbs=[_binding("rb", "Role", "r", "app", "prod", ns="prod")])
    paths = g.permission_paths(SA, "get", "secrets")
    assert [n.kind for n in paths[0].nodes][1:3] == ["RoleBinding", "Role"]


def test_rolebinding_does_not_resolve_a_role_from_another_namespace():
    # The Role exists, but in `staging`; a `prod` RoleBinding cannot grant it.
    g = _graph(roles=[_role("r", "staging", [{"verbs": ["get"], "resources": ["secrets"]}])],
               rbs=[_binding("rb", "Role", "r", "app", "prod", ns="prod")])
    assert g.permission_paths(SA, "get", "secrets") == []


def test_rolebinding_may_point_at_a_clusterrole():
    g = _graph(croles=[_crole("reader", [{"verbs": ["list"], "resources": ["secrets"]}])],
               rbs=[_binding("rb", "ClusterRole", "reader", "app", "prod", ns="prod")])
    paths = g.permission_paths(SA, "list", "secrets")
    assert [n.kind for n in paths[0].nodes][1:3] == ["RoleBinding", "ClusterRole"]


def test_subject_in_a_different_namespace_is_not_this_principal():
    g = _graph(croles=[_crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
               crbs=[_binding("b", "ClusterRole", "god", "app", "staging")])
    assert g.escalation_paths(SA) == []


def test_dangling_role_reference_yields_nothing():
    # roleRef names a ClusterRole that was never collected: we cannot know what it grants.
    g = _graph(crbs=[_binding("b", "ClusterRole", "not-collected", "app", "prod")])
    assert g.effective_rules(SA) == []
    assert g.escalation_paths(SA) == []


# --------------------------------------------------------------------------- #
# Escalation, one hop and multi-hop
# --------------------------------------------------------------------------- #
def test_cluster_admin_equivalent_is_a_single_capability():
    g = _graph(croles=[_crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
               crbs=[_binding("b", "ClusterRole", "god", "app", "prod")])
    summary, paths = g.escalation_summary(SA)
    assert "cluster-admin" in summary
    assert paths[0].capability == "cluster-admin"


def test_bind_capability_reaches_an_admin_role_that_actually_exists():
    g = _graph(croles=[_crole("binder", [{"verbs": ["bind"], "resources": ["clusterroles"]}]),
                       _crole("cluster-admin", [{"verbs": ["*"], "resources": ["*"]}])],
               crbs=[_binding("b", "ClusterRole", "binder", "app", "prod")])
    paths = g.escalation_paths(SA)
    reached = [p for p in paths if any(n.name == "cluster-admin" for n in p.nodes)]
    assert reached, "bind capability should reach the admin ClusterRole present in evidence"
    assert reached[0].edges[-1].relationship == "reaches"


def test_bind_capability_with_no_admin_role_present_claims_no_onward_hop():
    # Same permission, but this cluster has no admin-equivalent ClusterRole collected.
    # The capability is still reported; the ESCALATION TARGET is not invented.
    g = _graph(croles=[_crole("binder", [{"verbs": ["bind"], "resources": ["clusterroles"]}])],
               crbs=[_binding("b", "ClusterRole", "binder", "app", "prod")])
    paths = g.escalation_paths(SA)
    assert paths and all(n.kind != "ClusterRole" or n.name != "cluster-admin"
                         for p in paths for n in p.nodes)


def test_multi_hop_secret_read_reaches_another_service_account():
    """SA app can read Secrets in prod -> it can steal ops's token -> ops is cluster-admin.
    Two identities, one real chain."""
    g = _graph(
        croles=[_crole("reader", [{"verbs": ["get"], "resources": ["secrets"]}]),
                _crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
        crbs=[_binding("b1", "ClusterRole", "reader", "app", "prod"),
              _binding("b2", "ClusterRole", "god", "ops", "prod")],
        sas=[_sa("app", "prod"), _sa("ops", "prod")])
    paths = g.escalation_paths(SA)
    multi = [p for p in paths if p.hops > 3 and p.capability == "cluster-admin"]
    assert multi, "expected a chain through the other ServiceAccount"
    names = [n.name for n in multi[0].nodes]
    assert "ops" in names and names[0] == "app"


def test_multi_hop_does_not_cross_a_namespace_boundary():
    # ops lives in another namespace: reading prod Secrets cannot yield its token.
    g = _graph(
        croles=[_crole("reader", [{"verbs": ["get"], "resources": ["secrets"]}]),
                _crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
        crbs=[_binding("b1", "ClusterRole", "reader", "app", "prod"),
              _binding("b2", "ClusterRole", "god", "ops", "other")],
        sas=[_sa("app", "prod"), _sa("ops", "other")])
    paths = g.escalation_paths(SA)
    assert all("ops" not in [n.name for n in p.nodes] for p in paths)


def test_shortest_path_comes_first():
    g = _graph(
        croles=[_crole("god", [{"verbs": ["*"], "resources": ["*"]}]),
                _crole("reader", [{"verbs": ["get"], "resources": ["secrets"]}])],
        crbs=[_binding("b1", "ClusterRole", "god", "app", "prod"),
              _binding("b2", "ClusterRole", "reader", "app", "prod")],
        sas=[_sa("app", "prod"), _sa("ops", "prod")])
    paths = g.escalation_paths(SA)
    assert paths[0].hops == min(p.hops for p in paths)


def test_traversal_terminates_on_a_cycle():
    """A and B can each impersonate the other. Legal RBAC, and an infinite loop for a naive
    walker. Must return, and must not revisit a principal."""
    g = _graph(
        croles=[_crole("imp", [{"verbs": ["impersonate"],
                                "resources": ["serviceaccounts"]}])],
        crbs=[_binding("b1", "ClusterRole", "imp", "app", "prod"),
              _binding("b2", "ClusterRole", "imp", "peer", "prod")],
        sas=[_sa("app", "prod"), _sa("peer", "prod")])
    paths = g.escalation_paths(SA)          # must not hang
    assert paths
    for p in paths:
        principals = [n.id for n in p.nodes if n.kind == "ServiceAccount"]
        assert len(principals) == len(set(principals)), "a principal was revisited"


def test_hop_cap_is_respected():
    g = _graph(
        croles=[_crole("imp", [{"verbs": ["impersonate"],
                                "resources": ["serviceaccounts"]}])],
        crbs=[_binding("b", "ClusterRole", "imp", "app", "prod")],
        sas=[_sa("app", "prod")] + [_sa(f"sa{i}", "prod") for i in range(5)])
    for p in g.escalation_paths(SA, max_hops=3):
        assert p.hops <= 3
    assert all(p.hops <= MAX_HOPS for p in g.escalation_paths(SA))


def test_no_bindings_means_no_escalation_and_no_summary():
    g = _graph(croles=[_crole("god", [{"verbs": ["*"], "resources": ["*"]}])])
    summary, paths = g.escalation_summary(SA)
    assert summary is None and paths == []


def test_paths_are_deterministic_across_runs():
    g = _graph(
        croles=[_crole("reader", [{"verbs": ["get"], "resources": ["secrets"]}]),
                _crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
        crbs=[_binding("b1", "ClusterRole", "reader", "app", "prod"),
              _binding("b2", "ClusterRole", "god", "ops", "prod")],
        sas=[_sa("app", "prod"), _sa("ops", "prod"), _sa("zzz", "prod")])
    first = [p.render() for p in g.escalation_paths(SA)]
    second = [p.render() for p in g.escalation_paths(SA)]
    assert first == second and first == sorted(set(first), key=first.index)


# --------------------------------------------------------------------------- #
# Construction from evidence + the workload principal
# --------------------------------------------------------------------------- #
def test_from_evidence_and_workload_principal_default_service_account():
    ev = Evidence({"clusterroles": [_crole("god", [{"verbs": ["*"], "resources": ["*"]}])],
                   "roles": [], "rolebindings": [],
                   "clusterrolebindings": [_binding("b", "ClusterRole", "god",
                                                    "default", "kube-system")],
                   "serviceaccounts": [_sa("default", "kube-system")]},
                  Scope(ScopeLevel.CLUSTER))
    g = RbacGraph.from_evidence(ev)
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "kube-system"},
           "spec": {"containers": []}}
    principal = principal_for_workload(pod, "kube-system")
    assert principal == Node("ServiceAccount", "default", "kube-system")
    summary, paths = g.escalation_summary(principal)
    assert paths and "cluster-admin" in summary


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
