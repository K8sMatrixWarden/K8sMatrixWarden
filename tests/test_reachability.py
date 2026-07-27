"""Reachability tagging (core/reachability.py): tag the attack vector by pod exposure,
never lower severity. v2 keys off fronting Service/Ingress + NetworkPolicy, not the rule's
REMOTE flag, so it fires on ordinary LOCAL app findings whose pod is internet-exposed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import (BlastRadius, Exploitability, Finding,
                                          ResourceRef, Scope, ScopeLevel, Severity)
from k8smatrixwarden.core.reachability import (EXPLOIT_INGRESS, EXPLOIT_POD_PRIVILEGE,
                                               EXPLOIT_RBAC_ESCALATION,
                                               annotate_reachability, inventory)


def _pod(name="web", ns="prod", labels=None):
    return {"metadata": {"name": name, "namespace": ns, "labels": labels or {"app": "web"}},
            "spec": {"containers": [{"name": "c"}]}}


def _finding(ns="prod", name="web", kind="Pod", expl=Exploitability.LOCAL,
             blast=BlastRadius.POD):
    return Finding(rule_id="r", title="t", severity=Severity.HIGH,
                   resource=ResourceRef(kind, name, ns), message="m",
                   exploitability=expl, blast_radius=blast)


def _ev(pods=None, policies=None, services=None):
    return Evidence({"pods": pods or [], "networkpolicies": policies or [],
                     "services": services or [], "ingresses": []},
                    Scope(ScopeLevel.CLUSTER))


_NODEPORT_SVC = {"metadata": {"name": "web-svc", "namespace": "prod"},
                 "spec": {"type": "NodePort", "selector": {"app": "web"}}}
_CLUSTERIP_SVC = {"metadata": {"name": "web-svc", "namespace": "prod"},
                  "spec": {"type": "ClusterIP", "selector": {"app": "web"}}}
_DEFAULT_DENY = {"metadata": {"name": "deny-ingress", "namespace": "prod"},
                 "spec": {"podSelector": {"matchLabels": {"app": "web"}},
                          "policyTypes": ["Ingress"]}}


def test_exposed_nodeport_no_policy_is_ingress():
    f = _finding()
    annotate_reachability([f], _ev([_pod()], [], [_NODEPORT_SVC]))
    assert f.exploitable_by == [EXPLOIT_INGRESS]
    assert "INTERNET-REACHABLE" in f.path_reason and "NodePort" in f.path_reason


def test_exposed_but_isolated_is_pod_privilege():
    f = _finding()
    annotate_reachability([f], _ev([_pod()], [_DEFAULT_DENY], [_NODEPORT_SVC]))
    assert f.exploitable_by == [EXPLOIT_POD_PRIVILEGE]
    assert "network path is blocked" in f.path_reason


def test_clusterip_only_is_pod_privilege():
    # internal Service is not an external exposure -> post-breach only
    f = _finding()
    annotate_reachability([f], _ev([_pod()], [], [_CLUSTERIP_SVC]))
    assert f.exploitable_by == [EXPLOIT_POD_PRIVILEGE]
    assert "NOT internet-reachable" in f.path_reason


def test_no_service_is_pod_privilege():
    f = _finding()
    annotate_reachability([f], _ev([_pod()], [], []))
    assert f.exploitable_by == [EXPLOIT_POD_PRIVILEGE]


def test_local_app_finding_on_exposed_pod_gets_tagged():
    # the v2 point: a LOCAL finding (rule's static label) still gets tagged ingress
    # because its pod is internet-exposed. v1 would have skipped it.
    f = _finding(expl=Exploitability.LOCAL)
    annotate_reachability([f], _ev([_pod()], [], [_NODEPORT_SVC]))
    assert f.exploitable_by == [EXPLOIT_INGRESS]


def test_severity_and_blast_never_lowered():
    f = _finding(expl=Exploitability.REMOTE, blast=BlastRadius.CLUSTER)
    annotate_reachability([f], _ev([_pod()], [_DEFAULT_DENY], [_NODEPORT_SVC]))
    assert f.severity == Severity.HIGH
    assert f.exploitability == Exploitability.REMOTE   # unchanged
    assert f.blast_radius == BlastRadius.CLUSTER       # unchanged


def test_non_workload_finding_untouched():
    f = _finding(kind="ControlPlane", name="apiServer", ns=None)
    annotate_reachability([f], _ev([_pod()], [], [_NODEPORT_SVC]))
    assert f.exploitable_by == []


def test_exposure_cached_across_findings_on_same_pod():
    a = _finding(name="web")
    b = _finding(name="web")
    annotate_reachability([a, b], _ev([_pod()], [], [_NODEPORT_SVC]))
    assert a.exploitable_by == b.exploitable_by == [EXPLOIT_INGRESS]


def _pod_with_sa(sa="pwn-sa", ns="prod"):
    p = _pod(ns=ns)
    p["spec"]["serviceAccountName"] = sa
    return p


def _ev_rbac(pods, crb=None, croles=None):
    return Evidence({"pods": pods, "networkpolicies": [], "services": [], "ingresses": [],
                     "clusterrolebindings": crb or [], "clusterroles": croles or [],
                     "rolebindings": [], "roles": []}, Scope(ScopeLevel.CLUSTER))


def test_sa_bound_to_cluster_admin_gets_escalation_tag():
    crb = [{"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "admin-cr"},
            "subjects": [{"kind": "ServiceAccount", "name": "pwn-sa", "namespace": "prod"}]}]
    croles = [{"metadata": {"name": "admin-cr"},
               "rules": [{"verbs": ["*"], "resources": ["*"]}]}]
    f = _finding()
    annotate_reachability([f], _ev_rbac([_pod_with_sa()], crb, croles))
    assert EXPLOIT_RBAC_ESCALATION in f.exploitable_by
    assert "cluster-admin" in f.path_reason


def test_create_pods_lever_detected():
    crb = [{"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "cr"},
            "subjects": [{"kind": "ServiceAccount", "name": "pwn-sa", "namespace": "prod"}]}]
    croles = [{"metadata": {"name": "cr"},
               "rules": [{"verbs": ["create"], "resources": ["pods"]}]}]
    f = _finding()
    annotate_reachability([f], _ev_rbac([_pod_with_sa()], crb, croles))
    assert EXPLOIT_RBAC_ESCALATION in f.exploitable_by


def test_harmless_sa_gets_no_escalation_tag():
    crb = [{"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "cr"},
            "subjects": [{"kind": "ServiceAccount", "name": "pwn-sa", "namespace": "prod"}]}]
    croles = [{"metadata": {"name": "cr"},
               "rules": [{"verbs": ["get"], "resources": ["configmaps"]}]}]
    f = _finding()
    annotate_reachability([f], _ev_rbac([_pod_with_sa()], crb, croles))
    assert EXPLOIT_RBAC_ESCALATION not in f.exploitable_by


def test_inventory_buckets_worst_wins_and_sums_to_pods():
    # 3 pods: one internet-exposed, one clean-internal, one with a cluster-admin SA.
    exposed = _pod(name="edge", labels={"app": "edge"})
    internal = _pod(name="worker", labels={"app": "worker"})
    admin = _pod_with_sa(sa="pwn-sa")
    admin["metadata"]["name"] = "ops"
    svc = {"metadata": {"name": "edge-svc", "namespace": "prod"},
           "spec": {"type": "LoadBalancer", "selector": {"app": "edge"}}}
    crb = [{"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "cr"},
            "subjects": [{"kind": "ServiceAccount", "name": "pwn-sa", "namespace": "prod"}]}]
    croles = [{"metadata": {"name": "cr"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}]
    ev = Evidence({"pods": [exposed, internal, admin], "services": [svc], "networkpolicies": [],
                   "ingresses": [], "nodes": [{"metadata": {"name": "n1"}}],
                   "namespaces": [{"metadata": {"name": "prod"}}],
                   "clusterrolebindings": crb, "clusterroles": croles,
                   "rolebindings": [], "roles": []}, Scope(ScopeLevel.CLUSTER))
    inv = inventory(ev)
    assert inv["pods"] == 3 and inv["nodes"] == 1 and inv["namespaces"] == 1
    x = inv["exposure"]
    assert x["internet"] == 1 and x["admin"] == 1 and x["internal"] == 1
    assert sum(x.values()) == inv["pods"]   # every pod in exactly one bucket


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("all passed")
