"""
Deep Kubernetes-semantics regressions: the false negatives ordinary tests miss.

The previous adversarial pass asked "can the tool be made to over-claim?". This one asks
the harder question: **where does it say nothing when Kubernetes says something?** A false
negative is silent by construction, so each test here encodes a specific Kubernetes rule
and asserts the scanner honours it, rather than asserting a feature exists.

Tests marked REGRESSION reproduce a defect this pass found and fixed.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core import netpol as N
from k8smatrixwarden.core.attack_path import CORROBORATED, OBSERVED, resource_paths
from k8smatrixwarden.core.correlation import RUNTIME_FRESHNESS_DAYS, correlate
from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag, ResourceRef,
                                         ScanRequest, Severity, Tactic)
from k8smatrixwarden.core.rbac_graph import (CLUSTER_SCOPED_RESOURCES, Node, RbacGraph,
                                             grant_is_effective)

_PLATFORM = None
_BUCKETS = ("namespaces", "pods", "deployments", "daemonsets", "statefulsets",
            "replicasets", "jobs", "cronjobs", "services", "ingresses", "networkpolicies",
            "serviceaccounts", "secrets", "configmaps", "roles", "rolebindings",
            "clusterroles", "clusterrolebindings", "mutatingwebhookconfigurations",
            "validatingwebhookconfigurations", "componentconfig", "cloudiam")


def _platform():
    global _PLATFORM
    if _PLATFORM is None:
        _PLATFORM = build_platform()
    return _PLATFORM


def _cluster(**buckets):
    base = {k: [] for k in _BUCKETS}
    base["namespaces"] = [{"kind": "Namespace", "metadata": {"name": "default"}}]
    base.update(buckets)
    return base


def _scan(cluster):
    platform = _platform()
    path = os.path.join(tempfile.mkdtemp(), "c.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cluster, fh)
    return ScannerAgent(platform).scan(
        ScanRequest(), platform.make_collector(mock=True, fixture=path))


def _crole(name, rules, **extra):
    return {"kind": "ClusterRole", "metadata": {"name": name}, "rules": rules, **extra}


def _role(name, ns, rules):
    return {"kind": "Role", "metadata": {"name": name, "namespace": ns}, "rules": rules}


def _crb(name, role, subject, **meta):
    return {"kind": "ClusterRoleBinding", "metadata": {"name": name, **meta},
            "roleRef": {"kind": "ClusterRole", "name": role}, "subjects": [subject]}


def _rb(name, ns, role, subject, kind="Role"):
    return {"kind": "RoleBinding", "metadata": {"name": name, "namespace": ns},
            "roleRef": {"kind": kind, "name": role}, "subjects": [subject]}


def _sa_subject(name, ns):
    return {"kind": "ServiceAccount", "name": name, "namespace": ns}


APP = Node("ServiceAccount", "app", "prod")


def _graph(croles=(), roles=(), crbs=(), rbs=(), sas=()):
    return RbacGraph(list(croles), list(roles), list(crbs), list(rbs), list(sas))


def _caps(graph, principal=APP):
    return sorted({c for c, *_ in graph._capabilities(principal)})


# =========================================================================== #
# RBAC: non-ServiceAccount subjects
# =========================================================================== #
def test_cluster_admin_bound_to_anonymous_or_all_users_is_detected():
    """REGRESSION, the most serious false negative found in this project.

    A cluster where `system:anonymous`, `system:authenticated` and
    `system:unauthenticated` are each bound to `cluster-admin` produced ZERO RBAC
    findings. Every RBAC rule inspected only ServiceAccount subjects, and the
    role-definition scanners skip Kubernetes' built-in roles, so nothing ever looked at
    WHO `cluster-admin` was granted to unless it was a ServiceAccount named `default`.
    Unauthenticated cluster-admin is about as bad as a Kubernetes finding gets.
    """
    cluster = _cluster(
        clusterroles=[_crole("cluster-admin",
                             [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                             metadata={"name": "cluster-admin"})],
        clusterrolebindings=[
            _crb("anon", "cluster-admin", {"kind": "User", "name": "system:anonymous"}),
            _crb("all-users", "cluster-admin",
                 {"kind": "Group", "name": "system:authenticated"}),
            _crb("unauth", "cluster-admin",
                 {"kind": "Group", "name": "system:unauthenticated"})])
    findings = [f for f in _scan(cluster).findings
                if f.rule_id == "rbac-broad-subject-admin"]
    assert len(findings) == 3, "each broad binding is its own finding"
    assert all(f.severity is Severity.CRITICAL for f in findings)
    subjects = " ".join(f.message for f in findings)
    for who in ("system:anonymous", "system:authenticated", "system:unauthenticated"):
        assert who in subjects
    # An unauthenticated grant is remotely exploitable; an authenticated one needs a
    # credential first.
    anon = next(f for f in findings if "system:anonymous" in f.message)
    assert anon.exploitability.label == "Remote"


def test_a_namespaced_broad_binding_is_reported_with_the_smaller_blast_radius():
    """A RoleBinding confines the grant to one namespace. Still every authenticated
    principal holding admin there, but not cluster compromise, and the severity says so."""
    cluster = _cluster(
        clusterroles=[_crole("admin", [{"apiGroups": ["*"], "resources": ["*"],
                                        "verbs": ["*"]}])],
        rolebindings=[_rb("ns-admin", "default", "admin",
                          {"kind": "Group", "name": "system:authenticated"},
                          kind="ClusterRole")])
    findings = [f for f in _scan(cluster).findings
                if f.rule_id == "rbac-broad-subject-admin"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].blast_radius.label == "Namespace"
    assert "in namespace default" in findings[0].message


def test_kubernetes_own_bootstrap_bindings_are_not_flagged():
    """The false-positive control. Kubernetes binds `system:authenticated` to
    `system:discovery` and `system:basic-user` on every cluster; flagging those would make
    the new rule useless noise."""
    cluster = _cluster(
        clusterroles=[
            _crole("system:discovery",
                   [{"nonResourceURLs": ["/api", "/healthz"], "verbs": ["get"]}]),
            _crole("system:basic-user",
                   [{"apiGroups": ["authorization.k8s.io"],
                     "resources": ["selfsubjectaccessreviews"], "verbs": ["create"]}]),
            # broad within ONE api group, which is not cluster-admin
            _crole("apps-owner", [{"apiGroups": ["apps"], "resources": ["*"],
                                   "verbs": ["*"]}])],
        clusterrolebindings=[
            _crb("d", "system:discovery",
                 {"kind": "Group", "name": "system:authenticated"}),
            _crb("b", "system:basic-user",
                 {"kind": "Group", "name": "system:authenticated"}),
            _crb("a", "apps-owner",
                 {"kind": "Group", "name": "system:authenticated"})])
    flagged = [f for f in _scan(cluster).findings
               if f.rule_id in ("rbac-broad-subject-admin",
                                "rbac-cluster-admin-user-binding")]
    assert flagged == [], f"legitimate bootstrap bindings flagged: {flagged}"


def test_the_default_system_masters_binding_is_deliberately_not_reported():
    """Kubernetes ships `cluster-admin` bound to `system:masters` on every cluster, and the
    API server hard-codes that group to full access anyway, so the binding is not what
    grants it. Membership comes from the client certificate, not RBAC, so there is no
    remediation to offer. Reporting it would put an unactionable CRITICAL on every single
    scan. Asserted so a later pass does not "fix" this back into noise."""
    cluster = _cluster(
        clusterroles=[_crole("cluster-admin", [{"apiGroups": ["*"], "resources": ["*"],
                                                "verbs": ["*"]}])],
        clusterrolebindings=[_crb("cluster-admin", "cluster-admin",
                                  {"kind": "Group", "name": "system:masters"},
                                  labels={"kubernetes.io/bootstrapping": "rbac-defaults"})])
    flagged = [f for f in _scan(cluster).findings
               if f.rule_id in ("rbac-broad-subject-admin",
                                "rbac-cluster-admin-user-binding")]
    assert flagged == [], f"the universal default binding was reported: {flagged}"


def test_a_named_administrator_is_an_inventory_item_not_a_misconfiguration():
    cluster = _cluster(
        clusterroles=[_crole("cluster-admin", [{"apiGroups": ["*"], "resources": ["*"],
                                                "verbs": ["*"]}])],
        clusterrolebindings=[_crb("alice", "cluster-admin",
                                  {"kind": "User", "name": "alice@corp.example"})])
    findings = [f for f in _scan(cluster).findings
                if f.rule_id == "rbac-cluster-admin-user-binding"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "confirm" in findings[0].message


# =========================================================================== #
# RBAC: wildcards expand along their own axis only
# =========================================================================== #
def test_a_wildcard_inside_one_api_group_is_not_cluster_admin():
    """REGRESSION. `apiGroups: ["apps"], resources: ["*"], verbs: ["*"]` is total control
    of Deployments and nothing else. It was reported as cluster-admin because the
    capability's own `{"*"}` group short-circuited the check before the rule's groups were
    read."""
    g = _graph(croles=[_crole("r", [{"apiGroups": ["apps"], "resources": ["*"],
                                     "verbs": ["*"]}])],
               crbs=[_crb("b", "r", _sa_subject("app", "prod"))])
    caps = _caps(g)
    assert "cluster-admin" not in caps
    assert "create-workload" in caps, "it IS full control of workloads"


def test_a_wildcard_verb_on_one_resource_is_not_cluster_admin():
    g = _graph(croles=[_crole("r", [{"apiGroups": ["*"], "resources": ["pods"],
                                     "verbs": ["*"]}])],
               crbs=[_crb("b", "r", _sa_subject("app", "prod"))])
    assert "cluster-admin" not in _caps(g)


def test_all_three_wildcards_together_are_cluster_admin():
    """The control: narrowing the wildcard rule must not lose the genuine case."""
    g = _graph(croles=[_crole("r", [{"apiGroups": ["*"], "resources": ["*"],
                                     "verbs": ["*"]}])],
               crbs=[_crb("b", "r", _sa_subject("app", "prod"))])
    assert "cluster-admin" in _caps(g)


def test_a_wildcard_resource_covers_subresources():
    """Kubernetes: `resources: ["*"]` matches subresources too, so it does grant
    pods/exec. Missing this would be a false negative on a genuine exec capability."""
    g = _graph(croles=[_crole("r", [{"apiGroups": ["*"], "resources": ["*"],
                                     "verbs": ["create"]}])],
               crbs=[_crb("b", "r", _sa_subject("app", "prod"))])
    assert "exec-pods" in _caps(g)


# =========================================================================== #
# RBAC: namespaced vs cluster-scoped resources
# =========================================================================== #
def test_a_rolebinding_cannot_grant_a_cluster_scoped_resource():
    """REGRESSION. A Role may LIST `nodes` in its rules; the API server simply never
    honours it, because a RoleBinding grants namespaced access only. Reporting node access
    from a Role is a permission the principal does not have."""
    g = _graph(roles=[_role("r", "prod", [{"apiGroups": [""], "resources": ["nodes"],
                                           "verbs": ["*"]}])],
               rbs=[_rb("b", "prod", "r", _sa_subject("app", "prod"))])
    assert g.permission_paths(APP, "get", "nodes") == []


def test_a_clusterrolebinding_does_grant_cluster_scoped_resources():
    """The control for the rule above."""
    g = _graph(croles=[_crole("cr", [{"apiGroups": [""], "resources": ["nodes"],
                                      "verbs": ["*"]}])],
               crbs=[_crb("b", "cr", _sa_subject("app", "prod"))])
    assert g.permission_paths(APP, "get", "nodes")


def test_a_rolebinding_still_grants_namespaced_resources():
    g = _graph(roles=[_role("r", "prod", [{"apiGroups": [""], "resources": ["secrets"],
                                           "verbs": ["get"]}])],
               rbs=[_rb("b", "prod", "r", _sa_subject("app", "prod"))])
    assert g.permission_paths(APP, "get", "secrets")


def test_grant_effectiveness_covers_the_cluster_scoped_resource_set():
    assert "nodes" in CLUSTER_SCOPED_RESOURCES
    assert "persistentvolumes" in CLUSTER_SCOPED_RESOURCES
    assert "clusterroles" in CLUSTER_SCOPED_RESOURCES
    assert grant_is_effective({"nodes"}, None) is True          # cluster-wide grant
    assert grant_is_effective({"nodes"}, "prod") is False       # namespaced grant
    assert grant_is_effective({"secrets"}, "prod") is True
    assert grant_is_effective({"*"}, "prod") is True            # wildcard reaches pods


# =========================================================================== #
# Runtime: freshness, cluster identity, and path observation
# =========================================================================== #
def _finding(name="api", ns="prod", kind="Deployment"):
    f = Finding(rule_id="r1", title="r1", severity=Severity.HIGH,
                resource=ResourceRef(kind, name, ns), message="m",
                mitre=[MitreTag(Tactic.EXECUTION, "T1059", "Cmd")],
                detection_method=DetectionMethod.STATIC_CONFIG)
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": kind, "name": name, "detail": ns}]
    return f


def _alerts(events):
    return RuntimeAgent().evaluate_stream(normalize_events(events))


_NOW = "2026-08-31T00:00:00Z"


def test_a_stale_runtime_event_is_labelled_historical_not_current():
    """REGRESSION. A 2019 Falco alert still read as a current observation. The event is
    never discarded, it happened, but "observed" implies now, so age is reported."""
    old = correlate([_finding()], _alerts(
        [{"source": "falco", "proc": "bash", "pod": "api-9zskz", "namespace": "prod",
          "time": "2019-01-01T00:00:00Z"}]), cluster="c1", now=_NOW)["correlations"][0]
    assert old["freshness"] == "historical"
    assert old["age_days"] > RUNTIME_FRESHNESS_DAYS
    assert old["timestamp"] == "2019-01-01T00:00:00Z", "the real time is preserved"

    fresh = correlate([_finding()], _alerts(
        [{"source": "falco", "proc": "bash", "pod": "api-9zskz", "namespace": "prod",
          "time": "2026-08-30T23:00:00Z"}]), cluster="c1", now=_NOW)["correlations"][0]
    assert fresh["freshness"] == "recent"


def test_an_event_with_no_timestamp_has_unknown_freshness_not_assumed_fresh():
    out = correlate([_finding()], _alerts(
        [{"source": "falco", "proc": "bash", "pod": "api-9zskz", "namespace": "prod"}]),
        cluster="c1", now=_NOW)["correlations"][0]
    assert out["freshness"] == "unknown"
    assert out["age_days"] is None


def test_an_event_labelled_with_another_cluster_cannot_confirm():
    """REGRESSION. Runtime events carry no cluster identity natively, but a multi-cluster
    falcosidekick adds one, and one endpoint receiving several clusters' alerts is a normal
    topology. A same-named pod elsewhere is a different pod."""
    out = correlate([_finding()], _alerts(
        [{"source": "falco", "proc": "bash", "pod": "api-9zskz", "namespace": "prod",
          "cluster": "some-other-cluster"}]), cluster="c1", now=_NOW)
    assert out["confirmed_exploitation"] == 0
    assert out["correlations"][0]["confidence"] == "corroborated"
    assert "some-other-cluster" in out["correlations"][0]["verdict"]


def test_an_event_from_this_cluster_or_with_no_label_still_confirms():
    """The control. An unlabelled event is not evidence of a mismatch, so it is not
    treated as one, that would trade a false positive for a false negative."""
    for event in ({"source": "falco", "proc": "bash", "pod": "api-9zskz",
                   "namespace": "prod", "cluster": "c1"},
                  {"source": "falco", "proc": "bash", "pod": "api-9zskz",
                   "namespace": "prod"}):
        out = correlate([_finding()], _alerts([event]), cluster="c1", now=_NOW)
        assert out["confirmed_exploitation"] == 1


def test_a_confirmed_correlation_marks_its_own_path_observed():
    """REGRESSION, a false negative in the path layer. A Falco event names a running pod
    (`api-9zskz`) while the finding, and so the path node, names the workload (`api`).
    Matching on string equality left a path the correlator had already CONFIRMED reported
    as merely corroborated, understating evidence the scan actually held."""
    corr = correlate([_finding()], _alerts(
        [{"source": "falco", "proc": "bash", "pod": "api-9zskz", "namespace": "prod"}]),
        cluster="c1", now=_NOW)
    assert corr["confirmed_exploitation"] == 1
    path = resource_paths([_finding()],
                          {"correlation": corr, "drift": {"drift": []}})[0]
    assert path["confidence"] == OBSERVED
    assert path["observed_nodes"] == ["api"]


def test_repeating_one_event_does_not_strengthen_the_conclusion():
    """Alert counting and evidence strength are deliberately separate: 20 copies of one
    alert are 20 alerts, and exactly as much evidence as one."""
    def path_for(n):
        corr = correlate([_finding()], _alerts(
            [{"source": "falco", "proc": "bash", "pod": "api-9zskz",
              "namespace": "prod"}] * n), cluster="c1", now=_NOW)
        return corr, resource_paths([_finding()],
                                    {"correlation": corr, "drift": {"drift": []}})[0]

    one_corr, one = path_for(1)
    many_corr, many = path_for(20)
    assert one["confidence"] == many["confidence"] == OBSERVED
    assert one_corr["total_alerts"] == 1 and many_corr["total_alerts"] == 20


def test_a_pod_from_an_unrecognisable_suffix_only_corroborates():
    """A pod whose suffix is not a Kubernetes-generated one cannot be proven to belong to
    the workload, so it corroborates rather than confirms."""
    out = correlate([_finding()], _alerts(
        [{"source": "falco", "proc": "bash", "pod": "api-oldrs-9zskz",
          "namespace": "prod"}]), cluster="c1", now=_NOW)
    assert out["correlations"][0]["confidence"] == CORROBORATED


# =========================================================================== #
# NetworkPolicy: directionality is never claimed from one side
# =========================================================================== #
def test_one_sided_egress_never_becomes_a_pod_to_pod_reachability_claim():
    """Kubernetes requires BOTH sides to permit traffic: A's egress to B is irrelevant if
    B denies ingress. The tool models egress as context on the pod's own finding and never
    joins two pods' policies into an edge, so it cannot make the one-sided claim. This test
    exists so that property is not quietly lost later."""
    a_labels, b_labels = {"app": "a"}, {"app": "b"}
    a_egress = {"kind": "NetworkPolicy",
                "metadata": {"name": "a-egress", "namespace": "prod"},
                "spec": {"podSelector": {"matchLabels": a_labels},
                         "policyTypes": ["Egress"],
                         "egress": [{"to": [{"podSelector":
                                             {"matchLabels": b_labels}}]}]}}
    b_deny = {"kind": "NetworkPolicy",
              "metadata": {"name": "b-deny", "namespace": "prod"},
              "spec": {"podSelector": {"matchLabels": b_labels},
                       "policyTypes": ["Ingress"]}}
    policies = [a_egress, b_deny]
    assert N.evaluate(policies, "prod", a_labels, "Egress")["status"] == N.RESTRICTED
    assert N.evaluate(policies, "prod", b_labels, "Ingress")["status"] == N.DENY_ALL

    # The reachability layer must not report B as reachable from A on the strength of A's
    # egress rule: no pod-to-pod edge exists in the model at all.
    import inspect
    from k8smatrixwarden.core import reachability
    source = inspect.getsource(reachability)
    assert "pod_to_pod" not in source and "peer_reachable" not in source


def test_ip_block_except_ranges_are_preserved_for_the_analyst():
    policy = {"kind": "NetworkPolicy",
              "metadata": {"name": "p", "namespace": "prod"},
              "spec": {"podSelector": {},
                       "egress": [{"to": [{"ipBlock": {
                           "cidr": "10.0.0.0/8",
                           "except": ["10.1.0.0/16", "10.2.0.0/16"]}}]}],
                       "policyTypes": ["Egress"]}}
    out = N.evaluate([policy], "prod", {"app": "x"}, "Egress")
    peer = out["peers"][0]
    assert peer["cidr"] == "10.0.0.0/8"
    assert peer["except"] == ["10.1.0.0/16", "10.2.0.0/16"]
    assert out["status"] == N.RESTRICTED


def test_an_ipv6_world_cidr_is_allow_all_too():
    policy = {"kind": "NetworkPolicy",
              "metadata": {"name": "p", "namespace": "prod"},
              "spec": {"podSelector": {},
                       "ingress": [{"from": [{"ipBlock": {"cidr": "::/0"}}]}]}}
    assert N.evaluate([policy], "prod", {"app": "x"}, "Ingress")["status"] == N.ALLOW_ALL


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
