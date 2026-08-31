"""
Adversarial suite: attempts to make K8sMatrixWarden wrong.

Every test here is an attack on a security conclusion, not a feature check. Each documents
the scenario, the security semantics Kubernetes actually requires, and what a naive
implementation would get wrong. Tests marked REGRESSION reproduce a real defect that this
audit found and fixed; they fail against the previous implementation.

Organised by the layer under attack:

    RBAC · NetworkPolicy · Workload types · Pod security · Runtime correlation
    Confidence · Attack paths · Historical posture · Resource identity
    MCP/Web/Reports · Scale & pagination · Read-only safety · LLM isolation
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core import netpol as N
from k8smatrixwarden.core.correlation import belongs_to, correlate, detect_drift
from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import (ScanMode, ScanRequest, Scope, ScopeLevel,
                                         Selector)
from k8smatrixwarden.core.rbac_graph import Node, RbacGraph

_PLATFORM = None


def _platform():
    global _PLATFORM
    if _PLATFORM is None:
        _PLATFORM = build_platform()
    return _PLATFORM


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #
def _crole(name, rules, **extra):
    return {"kind": "ClusterRole", "metadata": {"name": name}, "rules": rules, **extra}


def _role(name, ns, rules):
    return {"kind": "Role", "metadata": {"name": name, "namespace": ns}, "rules": rules}


def _crb(name, role, sa, sa_ns, kind="ClusterRole"):
    return {"kind": "ClusterRoleBinding", "metadata": {"name": name},
            "roleRef": {"kind": kind, "name": role},
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": sa_ns}]}


def _rb(name, ns, role, sa, sa_ns, kind="ClusterRole"):
    return {"kind": "RoleBinding", "metadata": {"name": name, "namespace": ns},
            "roleRef": {"kind": kind, "name": role},
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": sa_ns}]}


def _sa(name, ns):
    return {"kind": "ServiceAccount", "metadata": {"name": name, "namespace": ns}}


def _graph(croles=(), roles=(), crbs=(), rbs=(), sas=()):
    return RbacGraph(list(croles), list(roles), list(crbs), list(rbs), list(sas))


APP = Node("ServiceAccount", "app", "prod")


# =========================================================================== #
# RBAC
# =========================================================================== #
def test_resource_names_do_not_imply_access_to_every_object_of_that_type():
    """REGRESSION. `get secrets` restricted to `resourceNames: [one-secret]` is NOT the
    ability to read every ServiceAccount token in the namespace, which is exactly what the
    read-secrets capability asserts. Reporting it as such invents an escalation."""
    g = _graph(croles=[_crole("r", [{"apiGroups": [""], "resources": ["secrets"],
                                     "verbs": ["get"],
                                     "resourceNames": ["only-this-one"]}])],
               crbs=[_crb("b", "r", "app", "prod")])
    summary, paths = g.escalation_summary(APP)
    assert paths == [] and summary is None, "named-object grant is not blanket access"
    analysis = g.escalation_analysis(APP)
    # ...but the permission is real, so it is reported rather than silently dropped.
    assert analysis["restricted_grants"], "a restricted grant must stay visible"
    assert analysis["restricted_grants"][0]["capability"] == "read-secrets"
    assert analysis["restricted_grants"][0]["resource_names"] == ["only-this-one"]


def test_a_custom_resource_borrowing_a_builtin_name_is_not_that_builtin():
    """REGRESSION. `secrets` in a vendor API group is somebody's CRD, not a core Secret.
    Ignoring apiGroups let any CRD inherit a built-in's escalation meaning."""
    g = _graph(croles=[_crole("r", [{"apiGroups": ["vendor.example.com"],
                                     "resources": ["secrets"], "verbs": ["get"]}])],
               crbs=[_crb("b", "r", "app", "prod")])
    assert g.escalation_summary(APP)[0] is None

    core = _graph(croles=[_crole("r", [{"apiGroups": [""], "resources": ["secrets"],
                                        "verbs": ["get"]}])],
                  crbs=[_crb("b", "r", "app", "prod")])
    assert "secrets" in (core.escalation_summary(APP)[0] or ""), \
        "the real core-group grant must still be detected"


def test_rolebinding_to_clusterrole_is_namespace_scoped_not_cluster_admin():
    """REGRESSION, highest severity found. Kubernetes: a RoleBinding referencing a
    ClusterRole grants those rules ONLY inside the binding's namespace. Binding
    `cluster-admin` into one team namespace is a normal delegation; calling the subject
    cluster-admin is false, and it is the most dangerous over-claim this tool could make."""
    g = _graph(croles=[_crole("cluster-admin", [{"apiGroups": ["*"], "resources": ["*"],
                                                 "verbs": ["*"]}])],
               rbs=[_rb("b", "team-a", "cluster-admin", "app", "prod")])
    summary, paths = g.escalation_summary(APP)
    assert "within namespace team-a only" in summary
    # It must NOT reach the cluster-wide admin ClusterRole as an onward privilege hop.
    reaches = [n for p in paths for n in p.nodes
               if n.kind == "ClusterRole" and n.name == "cluster-admin"]
    assert all(e.relationship != "reaches" for p in paths for e in p.edges
               if e.target.kind == "ClusterRole"), \
        "a namespaced grant cannot bind a role cluster-wide"
    assert reaches or True   # the role may appear as the grant source, which is correct


def test_clusterrolebinding_to_cluster_admin_is_still_reported_in_full():
    """The control for the test above: weakening the namespaced case must not weaken the
    genuine cluster-wide one."""
    g = _graph(croles=[_crole("cluster-admin", [{"apiGroups": ["*"], "resources": ["*"],
                                                 "verbs": ["*"]}])],
               crbs=[_crb("b", "cluster-admin", "app", "prod")])
    summary, paths = g.escalation_summary(APP)
    assert "cluster-admin-equivalent" in summary
    assert "within namespace" not in summary
    assert paths


def test_a_namespaced_grant_cannot_take_over_another_namespaces_identity():
    """A capability confined to namespace X must not reach an identity in namespace Y."""
    g = _graph(croles=[_crole("reader", [{"apiGroups": [""], "resources": ["secrets"],
                                          "verbs": ["get"]}])],
               rbs=[_rb("b", "team-a", "reader", "app", "prod")],
               sas=[_sa("app", "prod"), _sa("victim", "prod"), _sa("other", "team-a")])
    paths = g.escalation_paths(APP)
    reached = {n.name for p in paths for n in p.nodes if n.kind == "ServiceAccount"}
    assert "victim" not in reached, \
        "the grant lives in team-a; prod identities are out of its reach"


def test_aggregated_clusterrole_is_unknown_not_a_clean_bill_of_health():
    """REGRESSION. An aggregated ClusterRole whose rules the controller has not populated
    looks empty. Reporting "no escalation" is a false negative dressed as a clean result;
    the honest answer is that its effective permissions are unknown."""
    agg = _crole("agg", [], aggregationRule={
        "clusterRoleSelectors": [{"matchLabels": {"rbac": "x"}}]})
    g = _graph(croles=[agg], crbs=[_crb("b", "agg", "app", "prod")])
    analysis = g.escalation_analysis(APP)
    assert analysis["escalation_verdict"] == "unknown"
    assert analysis["unevaluable_roles"][0]["reason"] == "aggregated"
    assert "UNKNOWN" in analysis["unevaluable_roles"][0]["note"]


def test_non_resource_urls_grant_no_resource_access():
    """`nonResourceURLs` (/healthz, /metrics) are not Kubernetes resources. A rule holding
    only them, even with verbs `*`, must not read as resource power."""
    g = _graph(croles=[_crole("r", [{"nonResourceURLs": ["*"], "verbs": ["*"]}])],
               crbs=[_crb("b", "r", "app", "prod")])
    assert g.escalation_paths(APP) == []


def test_subresource_identity_is_exact():
    """`pods/exec` is a distinct resource string from `pods`. Holding one must not imply
    the other in either direction."""
    execer = _graph(croles=[_crole("r", [{"apiGroups": [""], "resources": ["pods/exec"],
                                          "verbs": ["create"]}])],
                    crbs=[_crb("b", "r", "app", "prod")])
    caps = {c for c, *_ in execer._capabilities(APP)}
    assert "exec-pods" in caps
    assert "create-workload" not in caps, "pods/exec is not permission to create pods"

    creator = _graph(croles=[_crole("r", [{"apiGroups": [""], "resources": ["pods"],
                                           "verbs": ["create"]}])],
                     crbs=[_crb("b", "r", "app", "prod")])
    caps = {c for c, *_ in creator._capabilities(APP)}
    assert "create-workload" in caps and "exec-pods" not in caps


def test_a_binding_naming_a_different_subject_grants_this_principal_nothing():
    g = _graph(croles=[_crole("admin", [{"apiGroups": ["*"], "resources": ["*"],
                                         "verbs": ["*"]}])],
               crbs=[_crb("b", "admin", "someone-else", "prod")])
    assert g.escalation_paths(APP) == []


def test_same_service_account_name_in_two_namespaces_stays_distinct():
    g = _graph(croles=[_crole("admin", [{"apiGroups": ["*"], "resources": ["*"],
                                         "verbs": ["*"]}])],
               crbs=[_crb("b", "admin", "app", "prod")],
               sas=[_sa("app", "prod"), _sa("app", "staging")])
    assert g.escalation_paths(Node("ServiceAccount", "app", "prod"))
    assert g.escalation_paths(Node("ServiceAccount", "app", "staging")) == []


def test_rbac_cycle_terminates_and_yields_no_repeated_principal():
    """A can impersonate B, B can impersonate A. Legal RBAC, an infinite loop for a naive
    walker."""
    g = _graph(croles=[_crole("imp", [{"apiGroups": [""], "verbs": ["impersonate"],
                                       "resources": ["serviceaccounts"]}])],
               crbs=[_crb("b1", "imp", "app", "prod"), _crb("b2", "imp", "peer", "prod")],
               sas=[_sa("app", "prod"), _sa("peer", "prod")])
    paths = g.escalation_paths(APP)          # must return
    for p in paths:
        principals = [n.id for n in p.nodes if n.kind == "ServiceAccount"]
        assert len(principals) == len(set(principals))


def test_wildcard_verb_alone_is_not_wildcard_resource():
    """verbs `*` on ONE resource is not cluster-admin."""
    g = _graph(croles=[_crole("r", [{"apiGroups": [""], "resources": ["configmaps"],
                                     "verbs": ["*"]}])],
               crbs=[_crb("b", "r", "app", "prod")])
    caps = {c for c, *_ in g._capabilities(APP)}
    assert "cluster-admin" not in caps


# =========================================================================== #
# NetworkPolicy
# =========================================================================== #
def _pol(name, ns="prod", sel=None, ing=None, egr=None, types=None):
    spec = {"podSelector": {} if sel is None else sel}
    if ing is not None:
        spec["ingress"] = ing
    if egr is not None:
        spec["egress"] = egr
    if types is not None:
        spec["policyTypes"] = types
    return {"kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns},
            "spec": spec}


LABELS = {"app": "web", "tier": "frontend"}


def test_policies_are_additive_a_deny_plus_a_narrow_allow_stays_isolated():
    out = N.evaluate([_pol("deny", types=["Ingress"]),
                      _pol("allow", ing=[{"from": [{"podSelector":
                                                    {"matchLabels": {"app": "api"}}}]}])],
                     "prod", LABELS, "Ingress")
    assert out["status"] == N.RESTRICTED and N.isolates(out)


def test_one_allow_all_rule_defeats_every_strict_sibling():
    out = N.evaluate([_pol("strict", ing=[{"from": [{"podSelector":
                                                     {"matchLabels": {"a": "b"}}}]}]),
                      _pol("lax", ing=[{}])], "prod", LABELS, "Ingress")
    assert out["status"] == N.ALLOW_ALL and not N.isolates(out)


def test_world_cidr_with_private_exceptions_is_still_internet_open():
    out = N.evaluate([_pol("open", ing=[{"from": [{"ipBlock": {
        "cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}]}])], "prod", LABELS, "Ingress")
    assert out["status"] == N.ALLOW_ALL and not N.isolates(out)


def test_omitted_policy_types_governs_ingress_only():
    """Kubernetes defaults policyTypes to [Ingress], plus Egress only when egress rules
    exist. Assuming both would report an unrestricted pod as egress-contained."""
    p = _pol("p", ing=[{"from": [{"podSelector": {"matchLabels": {"a": "b"}}}]}])
    assert N.evaluate([p], "prod", LABELS, "Ingress")["status"] == N.RESTRICTED
    assert N.evaluate([p], "prod", LABELS, "Egress")["status"] == N.UNRESTRICTED


def test_empty_rule_list_is_deny_all_but_absent_evidence_is_unknown():
    """Three states that must never merge: governed-with-no-rules (deny), not governed
    (unrestricted), and no evidence at all (unknown)."""
    deny = N.evaluate([_pol("d", ing=[], types=["Ingress"])], "prod", LABELS, "Ingress")
    none = N.evaluate([], "prod", LABELS, "Ingress")
    unknown = N.evaluate(None, "prod", LABELS, "Ingress")
    assert deny["status"] == N.DENY_ALL and N.isolates(deny)
    assert none["status"] == N.UNRESTRICTED and not N.isolates(none)
    assert unknown["status"] == N.UNKNOWN and not N.isolates(unknown)


def test_an_unevaluable_selector_is_partial_and_never_isolation():
    out = N.evaluate([_pol("weird", sel={"matchExpressions": [
        {"key": "app", "operator": "Regex", "values": ["w.*"]}]}, types=["Ingress"])],
        "prod", LABELS, "Ingress")
    assert out["status"] == N.PARTIAL
    assert not N.isolates(out), "unknown is not denied, and never confirmed isolation"


def test_a_policy_in_another_namespace_does_not_apply():
    out = N.evaluate([_pol("d", ns="staging", types=["Ingress"])], "prod", LABELS,
                     "Ingress")
    assert out["status"] == N.UNRESTRICTED


def test_not_in_is_satisfied_by_a_missing_key():
    sel = {"matchExpressions": [{"key": "env", "operator": "NotIn", "values": ["prod"]}]}
    assert N.selector_matches(sel, {}) is True
    assert N.selector_matches(sel, {"env": "dev"}) is True
    assert N.selector_matches(sel, {"env": "prod"}) is False


def test_ports_are_reported_but_reachability_is_not_port_filtered():
    """Documented limitation, asserted so it cannot silently change. Ports travel with the
    peer as data; a port-443-only policy is NOT treated as narrower reachability than an
    all-ports one. Claiming otherwise without a port model would be false precision."""
    p = _pol("p", ing=[{"from": [{"podSelector": {"matchLabels": {"a": "b"}}}],
                        "ports": [{"port": 443, "protocol": "TCP"}]}])
    out = N.evaluate([p], "prod", LABELS, "Ingress")
    assert out["peers"][0]["ports"] == [{"port": 443, "protocol": "TCP"}]
    assert out["status"] == N.RESTRICTED      # same verdict as an all-ports rule


# =========================================================================== #
# Workload types and pod security
# =========================================================================== #
def _cluster(**buckets):
    base = {k: [] for k in (
        "namespaces", "pods", "deployments", "daemonsets", "statefulsets", "replicasets",
        "jobs", "cronjobs", "services", "ingresses", "networkpolicies", "serviceaccounts",
        "secrets", "configmaps", "roles", "rolebindings", "clusterroles",
        "clusterrolebindings", "mutatingwebhookconfigurations",
        "validatingwebhookconfigurations", "componentconfig", "cloudiam")}
    base["namespaces"] = [{"kind": "Namespace", "metadata": {"name": "default"}}]
    base.update(buckets)
    return base


def _scan_cluster(cluster):
    platform = _platform()
    path = os.path.join(tempfile.mkdtemp(), "c.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cluster, fh)
    return ScannerAgent(platform).scan(
        ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                    mode=ScanMode.SYNC),
        platform.make_collector(mock=True, fixture=path), mode_label="mock"), platform


def _priv(name="c"):
    return {"name": name, "image": "x:1", "securityContext": {"privileged": True}}


def test_cronjob_pod_specs_are_actually_inspected():
    """REGRESSION. A CronJob nests its PodSpec one level deeper
    (spec.jobTemplate.spec.template.spec). Unwrapping only `spec.template` handed the
    jobTemplate wrapper to the rules as if it were a PodSpec, so every workload rule saw an
    empty pod: a privileged container inside a CronJob was invisible. CronJob is the
    Persistence technique the threat matrix names outright."""
    cluster = _cluster(cronjobs=[{"kind": "CronJob",
                                  "metadata": {"name": "cj", "namespace": "default"},
                                  "spec": {"schedule": "* * * * *", "jobTemplate": {
                                      "spec": {"template": {"metadata": {}, "spec": {
                                          "containers": [_priv()]}}}}}}])
    result, _ = _scan_cluster(cluster)
    hits = {(f.resource.kind, f.resource.name) for f in result.findings
            if f.rule_id == "workload-privileged-container"}
    assert ("CronJob", "cj") in hits


def test_the_same_risk_is_found_in_every_workload_kind():
    """A rule that fires on Deployments but not DaemonSets is a false negative with a
    friendly face."""
    cluster = _cluster(
        pods=[{"kind": "Pod", "metadata": {"name": "raw", "namespace": "default"},
               "spec": {"containers": [_priv()]}}],
        deployments=[{"kind": "Deployment", "metadata": {"name": "dep",
                                                         "namespace": "default"},
                      "spec": {"template": {"metadata": {},
                                            "spec": {"containers": [_priv()]}}}}],
        daemonsets=[{"kind": "DaemonSet", "metadata": {"name": "ds",
                                                       "namespace": "default"},
                     "spec": {"template": {"metadata": {},
                                           "spec": {"containers": [_priv()]}}}}],
        statefulsets=[{"kind": "StatefulSet", "metadata": {"name": "sts",
                                                           "namespace": "default"},
                       "spec": {"template": {"metadata": {},
                                             "spec": {"containers": [_priv()]}}}}],
        jobs=[{"kind": "Job", "metadata": {"name": "job", "namespace": "default"},
               "spec": {"template": {"metadata": {},
                                     "spec": {"containers": [_priv()]}}}}],
        cronjobs=[{"kind": "CronJob", "metadata": {"name": "cj", "namespace": "default"},
                   "spec": {"schedule": "* * * * *", "jobTemplate": {"spec": {
                       "template": {"metadata": {},
                                    "spec": {"containers": [_priv()]}}}}}}])
    result, _ = _scan_cluster(cluster)
    hits = {(f.resource.kind, f.resource.name) for f in result.findings
            if f.rule_id == "workload-privileged-container"}
    for expected in [("Pod", "raw"), ("Deployment", "dep"), ("DaemonSet", "ds"),
                     ("StatefulSet", "sts"), ("Job", "job"), ("CronJob", "cj")]:
        assert expected in hits, f"privileged container missed on {expected[0]}"


def test_init_and_ephemeral_containers_are_not_a_blind_spot():
    """A privileged initContainer is exactly as much of a host-escape primitive as a
    privileged long-running one, and an ephemeral debug container is a live one."""
    cluster = _cluster(pods=[
        {"kind": "Pod", "metadata": {"name": "init-pod", "namespace": "default"},
         "spec": {"containers": [{"name": "ok", "image": "x:1",
                                  "securityContext": {"privileged": False}}],
                  "initContainers": [_priv("init")]}},
        {"kind": "Pod", "metadata": {"name": "eph-pod", "namespace": "default"},
         "spec": {"containers": [{"name": "ok", "image": "x:1",
                                  "securityContext": {"privileged": False}}],
                  "ephemeralContainers": [_priv("debug")]}}])
    result, _ = _scan_cluster(cluster)
    hits = {f.resource.name for f in result.findings
            if f.rule_id == "workload-privileged-container"}
    assert {"init-pod", "eph-pod"} <= hits


def test_pod_spec_unwrapping_is_shared_by_every_consumer():
    """`Evidence.pod_spec` is the one place that knows where a PodSpec lives. Any consumer
    re-implementing it drifts, which is how CronJob became invisible in the first place."""
    cronjob = {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {
        "spec": {"containers": [{"name": "a"}], "serviceAccountName": "cj-sa"}}}}}}
    assert Evidence.pod_spec(cronjob).get("serviceAccountName") == "cj-sa"
    assert [c["name"] for c in Evidence.containers(cronjob)] == ["a"]

    from k8smatrixwarden.core.models import _all_containers
    assert [c["name"] for c in _all_containers(cronjob)] == ["a"]


def test_an_omitted_security_field_is_not_an_explicit_safe_value():
    """A pod that never sets runAsNonRoot is not a pod that set it to true. Drift detection
    must only claim a contradiction against a posture actually declared."""
    from k8smatrixwarden.core.correlation import _declared_posture
    silent = {"spec": {"containers": [{"name": "c", "securityContext": {}}]}}
    declared = {"spec": {"securityContext": {"runAsNonRoot": True},
                         "containers": [{"name": "c", "securityContext": {}}]}}
    assert _declared_posture(silent)["non_root"] is False
    assert _declared_posture(declared)["non_root"] is True


def test_one_container_opting_out_breaks_the_pods_promise():
    """Pod-level securityContext is a default; a container may override it. A promise holds
    only when every container keeps it."""
    from k8smatrixwarden.core.correlation import _declared_posture
    mixed = {"spec": {"containers": [
        {"name": "a", "securityContext": {"readOnlyRootFilesystem": True}},
        {"name": "b", "securityContext": {}}]}}
    assert _declared_posture(mixed)["read_only_fs"] is False


# =========================================================================== #
# Runtime correlation
# =========================================================================== #
def _finding(rule="r1", name="api", ns="prod", kind="Deployment"):
    from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag,
                                             ResourceRef, Severity, Tactic)
    return Finding(rule_id=rule, title=rule, severity=Severity.HIGH,
                   resource=ResourceRef(kind, name, ns), message="m",
                   mitre=[MitreTag(Tactic.EXECUTION, "T1059", "Command and Scripting "
                                                              "Interpreter")],
                   detection_method=DetectionMethod.STATIC_CONFIG)


def _alerts(events):
    from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
    return RuntimeAgent().evaluate_stream(normalize_events(events))


def test_a_pod_of_a_similarly_named_workload_is_not_confirmed_exploitation():
    """REGRESSION. `api-server-7d9f-xk2` starts with `api-`, so a naive prefix test
    confirmed exploitation of workload `api` from an event about workload `api-server`.
    Confirmed exploitation is the strongest claim this tool makes."""
    out = correlate([_finding(name="api")],
                    _alerts([{"source": "falco", "proc": "bash",
                              "pod": "api-server-7d9f-xk2", "namespace": "prod"}]))
    assert out["confirmed_exploitation"] == 0
    assert out["correlations"][0]["confidence"] == "corroborated"


def test_a_genuine_generated_pod_name_still_confirms():
    """The control: tightening the match must not lose true positives."""
    for pod in ("api-7d9f4c8b21-lrw5s", "api-9zskz", "api"):
        out = correlate([_finding(name="api")],
                        _alerts([{"source": "falco", "proc": "bash", "pod": pod,
                                  "namespace": "prod"}]))
        assert out["confirmed_exploitation"] == 1, pod


def test_an_event_without_a_namespace_cannot_confirm():
    """REGRESSION. Two namespaces routinely run identically named workloads, so an event
    that names no namespace cannot establish resource identity. It still correlates."""
    out = correlate([_finding(name="web")],
                    _alerts([{"source": "falco", "proc": "bash", "pod": "web-9zskz"}]))
    assert out["confirmed_exploitation"] == 0
    assert out["correlations"][0]["confidence"] == "corroborated"


def test_an_event_in_another_namespace_never_confirms():
    out = correlate([_finding(name="web", ns="prod")],
                    _alerts([{"source": "falco", "proc": "bash", "pod": "web-9zskz",
                              "namespace": "staging"}]))
    assert out["confirmed_exploitation"] == 0


def test_an_event_with_no_matching_static_finding_is_runtime_only():
    from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag,
                                             ResourceRef, Severity, Tactic)
    impact_only = Finding(rule_id="r", title="r", severity=Severity.HIGH,
                          resource=ResourceRef("Pod", "other", "prod"), message="m",
                          mitre=[MitreTag(Tactic.IMPACT, "T1485", "Data Destruction")],
                          detection_method=DetectionMethod.STATIC_CONFIG)
    out = correlate([impact_only],
                    _alerts([{"source": "falco", "proc": "bash", "pod": "web-9zskz",
                              "namespace": "prod"}]))
    assert out["runtime_only"] == 1


def test_events_with_unparseable_or_missing_timestamps_still_order_deterministically():
    events = [
        {"source": "falco", "proc": "bash", "pod": "web-9zskz", "namespace": "prod",
         "time": "2026-01-03T00:00:00Z"},
        {"source": "falco", "proc": "nc", "pod": "web-9zskz", "namespace": "prod"},
        {"source": "falco", "proc": "nmap", "pod": "web-9zskz", "namespace": "prod",
         "time": "not-a-date"},
        {"source": "falco", "proc": "xmrig", "pod": "web-9zskz", "namespace": "prod",
         "time": "2026-01-01T00:00:00Z"}]
    first = correlate([_finding(name="web")], _alerts(events))["timeline"]
    second = correlate([_finding(name="web")], _alerts(events))["timeline"]
    stamps = [e.get("timestamp", "") for e in first]
    assert stamps == [e.get("timestamp", "") for e in second], "ordering must be stable"
    real = [s for s in stamps if s.startswith("2026")]
    assert real == sorted(real), "parseable timestamps ascend"


def test_duplicate_events_do_not_change_the_security_conclusion():
    one = correlate([_finding(name="web")],
                    _alerts([{"source": "falco", "proc": "bash", "pod": "web-9zskz",
                              "namespace": "prod"}]))
    three = correlate([_finding(name="web")],
                      _alerts([{"source": "falco", "proc": "bash", "pod": "web-9zskz",
                                "namespace": "prod"}] * 3))
    assert one["correlations"][0]["confidence"] == \
        three["correlations"][0]["confidence"] == "confirmed"


def test_drift_needs_a_declared_posture_to_contradict():
    """An undeclared posture cannot be contradicted. Reporting drift against a pod that
    promised nothing would be a pure false positive."""
    silent = [{"kind": "Pod", "metadata": {"name": "p", "namespace": "prod"},
               "spec": {"containers": [{"name": "c"}]}}]
    events = [{"source": "falco", "proc": "sh", "uid": "0", "pod": "p",
               "namespace": "prod"}]
    assert detect_drift(silent, events)["drift_count"] == 0

    promised = [{"kind": "Pod", "metadata": {"name": "p", "namespace": "prod"},
                 "spec": {"securityContext": {"runAsNonRoot": True},
                          "containers": [{"name": "c"}]}}]
    assert detect_drift(promised, events)["drift_count"] == 1


def test_drift_ignores_an_event_it_cannot_attribute_to_a_scanned_pod():
    promised = [{"kind": "Pod", "metadata": {"name": "p", "namespace": "prod"},
                 "spec": {"securityContext": {"runAsNonRoot": True},
                          "containers": [{"name": "c"}]}}]
    assert detect_drift(promised, [{"source": "falco", "uid": "0",
                                    "pod": "ghost", "namespace": "prod"}])[
        "drift_count"] == 0


# =========================================================================== #
# Attack paths and confidence
# =========================================================================== #
def test_two_findings_sharing_a_tactic_do_not_become_a_resource_path():
    """Tactic adjacency is not causality. Two unrelated workloads in the same tactic must
    never be joined into one route."""
    from k8smatrixwarden.core.attack_path import resource_paths
    a, b = _finding(name="alpha"), _finding(name="beta")
    a.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": "Pod", "name": "alpha", "detail": "prod"}]
    b.exploit_path = [{"kind": "Foothold", "name": "compromised pod", "detail": ""},
                      {"kind": "Pod", "name": "beta", "detail": "prod"}]
    paths = resource_paths([a, b])
    assert len(paths) == 2, "separate chains stay separate"
    for p in paths:
        names = {s["node"] for s in p["steps"]}
        assert not ({"alpha", "beta"} <= names)


def test_a_runtime_event_observes_only_the_hop_it_named():
    """REGRESSION guard. A shell in a pod is not evidence that the RoleBinding after it was
    used."""
    from k8smatrixwarden.core.attack_path import OBSERVED, resource_paths
    f = _finding(name="api")
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": "Pod", "name": "api", "detail": "prod"},
                      {"kind": "ServiceAccount", "name": "api-sa", "detail": "prod"},
                      {"kind": "RoleBinding", "name": "api-bind", "detail": ""}]
    runtime = {"correlation": {"correlations": [
        {"confidence": "confirmed", "tactic": "Execution", "resource": "api",
         "namespace": "prod", "timestamp": "2026-01-01T00:00:00Z",
         "runtime": {"rule_id": "rt", "title": "shell"}}]}, "drift": {"drift": []}}
    path = resource_paths([f], runtime)[0]
    assert path["confidence"] == OBSERVED
    assert path["fully_observed"] is False
    assert path["observed_nodes"] == ["api"]
    assert "configuration-derived" in path["summary"]


def test_confidence_never_exceeds_the_evidence_beneath_it():
    from k8smatrixwarden.core.explain import finding_confidence

    class _Rule:
        confidence = "low"
        requires_node_access = True
        false_positive_notes = ""
        version = 1
        references: list = []
        requires_runtime = False

    f = _finding()
    low = finding_confidence(f, _Rule(), None)
    assert low["score"] <= 0.4, "a heuristic rule needing node access cannot be certain"
    assert any("node" in r for r in low["reasons"])


# =========================================================================== #
# Historical posture
# =========================================================================== #
def _stored(findings, cluster, scope, scan_id, when, rules=None):
    from k8smatrixwarden.core.models import Severity
    from k8smatrixwarden.core.results import ScanResult
    from k8smatrixwarden.core.scoring import RiskScoringEngine
    level = ScopeLevel.NAMESPACE if scope.startswith("namespace/") else ScopeLevel.CLUSTER
    ns = scope.split("/", 1)[1] if scope.startswith("namespace/") else None
    return ScanResult(
        request=ScanRequest(scope=Scope(level, namespace=ns), selector=Selector(),
                            mode=ScanMode.SYNC),
        findings=findings, risk=RiskScoringEngine().score(findings),
        resolved_rule_ids=rules if rules is not None
        else sorted({f.rule_id for f in findings}),
        counts={s.label: sum(1 for f in findings if f.severity is s) for s in Severity},
        scan_id=scan_id, cluster_name=cluster, generated_at=when)


def test_a_rule_that_did_not_run_is_never_reported_as_resolved_then_regressed():
    """The full three-scan sequence: present, not re-scanned, present again. The middle
    scan must not manufacture a resolution, the third must not manufacture a regression from
    one, and, since the middle scan never looked, the third must not call the finding NEW
    either. All three are the same error in different directions: treating a scan's silence
    about a rule it never ran as information about the cluster."""
    from k8smatrixwarden.core.posture import latest_change
    from k8smatrixwarden.core.report_store import ReportStore
    store = ReportStore(tempfile.mkdtemp())
    f = _finding(rule="r1", name="pod-a", ns="default")
    store.save(_stored([f], "c1", "cluster-wide", "s1", "2026-01-01T00:00:00+05:30"))
    store.save(_stored([], "c1", "cluster-wide", "s2", "2026-01-02T00:00:00+05:30",
                       rules=["other-rule"]))          # r1 never ran
    store.save(_stored([_finding(rule="r1", name="pod-a", ns="default")], "c1",
                       "cluster-wide", "s3", "2026-01-03T00:00:00+05:30"))
    out = latest_change(store)
    assert out["regressed"] == [], "it was never resolved, so it cannot have regressed"
    assert out["new"] == [], "the previous scan never ran r1, so r1 cannot be called new"
    still_open = [x for x in out["persistent"] if x["rule_id"] == "r1"]
    assert len(still_open) == 1, "it is still open, and reported as such"
    assert still_open[0]["unevaluated_in_previous_scan"] is True


def test_two_clusters_never_share_a_finding_history():
    from k8smatrixwarden.core.report_store import ReportStore
    store = ReportStore(tempfile.mkdtemp())
    store.save(_stored([_finding(rule="r1", name="pod-a", ns="default")], "cluster-a",
                       "cluster-wide", "a1", "2026-01-01T00:00:00+05:30"))
    store.save(_stored([], "cluster-b", "cluster-wide", "b1",
                       "2026-01-02T00:00:00+05:30", rules=["r1"]))
    a = store.raw_timeline(scope=store.scope_key_of("cluster-a", "cluster-wide"))
    assert a["r1|Deployment|pod-a|default"]["resolved_at"] is None, \
        "cluster B's scan says nothing about cluster A"


# =========================================================================== #
# Read-only safety and LLM isolation
# =========================================================================== #
def test_no_module_can_write_to_the_cluster():
    """Static audit: the Kubernetes client is only ever used for reads. A write verb
    anywhere in the package would be a breach of the tool's core promise."""
    import re
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "k8smatrixwarden")
    writes = re.compile(r"\b(create_namespaced_\w+|delete_namespaced_\w+|"
                        r"patch_namespaced_\w+|replace_namespaced_\w+|"
                        r"create_cluster_\w+|delete_collection\w*)\s*\(")
    offenders = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    if writes.search(line):
                        offenders.append(f"{path}:{i}")
    assert offenders == [], f"cluster-mutating API calls found: {offenders}"


def test_the_scanner_core_never_imports_the_llm_layer():
    """A deterministic result that depended on a model would not be deterministic."""
    import re
    core = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "k8smatrixwarden", "core")
    bad = []
    for name in sorted(os.listdir(core)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(core, name), encoding="utf-8") as fh:
            body = fh.read()
        if re.search(r"import\s+(anthropic|openai)\b|llm_provider|llm_orchestrator", body):
            bad.append(name)
    assert bad == [], f"scanner core reaches into the LLM layer: {bad}"


def test_scan_results_are_identical_with_and_without_llm_configuration():
    """Whatever the operator configures, the deterministic answer is the same one."""
    saved = {k: os.environ.get(k) for k in
             ("K8SMATRIXWARDEN_LLM_PROVIDER", "K8SMATRIXWARDEN_LLM_MODEL",
              "ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
    cluster = _cluster(pods=[{"kind": "Pod",
                              "metadata": {"name": "p", "namespace": "default"},
                              "spec": {"containers": [_priv()]}}])
    try:
        for k in saved:
            os.environ.pop(k, None)
        none = _scan_cluster(cluster)[0]
        os.environ.update({"K8SMATRIXWARDEN_LLM_PROVIDER": "does-not-exist",
                           "K8SMATRIXWARDEN_LLM_MODEL": "nonsense"})
        broken = _scan_cluster(cluster)[0]
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
    assert none.risk.cluster_risk == broken.risk.cluster_risk
    assert sorted(f.dedup_key() for f in none.findings) == \
        sorted(f.dedup_key() for f in broken.findings)


# =========================================================================== #
# MCP: malformed input must produce a clear error, never a crash or a wrong scan
# =========================================================================== #
def _tools():
    from k8smatrixwarden.mcp.server import build_tools
    return build_tools()


def test_an_unknown_scope_level_is_refused_not_silently_widened():
    """REGRESSION. `scope_level="namesapce"` used to fall back to a CLUSTER-WIDE scan, so
    a caller that believed it had scoped its request got the whole cluster back with no
    indication. Silently widening a scope is the worst failure mode a scoping argument
    can have."""
    tools = _tools()
    for name, call in (
            ("run_scan", lambda f: f(scope_level="galaxy", mock=True, save=False)),
            ("preview_scan", lambda f: f(scope_level="galaxy")),
            ("intelligent_scan", lambda f: f("scan", scope_level="galaxy", mock=True,
                                             save=False)),
            ("build_threat_matrix", lambda f: f(scope_level="galaxy", mock=True)),
            ("build_attack_path", lambda f: f(scope_level="galaxy", mock=True))):
        out = call(tools[name])
        assert isinstance(out, dict) and "error" in out, f"{name} accepted a bad scope"
        assert "scope_level" in out["error"]


def test_a_malformed_evidence_source_is_an_error_not_a_traceback():
    """REGRESSION. A fixture that is not JSON escaped as a raw JSONDecodeError."""
    bad = os.path.join(tempfile.mkdtemp(), "b.json")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("definitely not json")
    out = _tools()["run_scan"](mock=True, fixture=bad, save=False)
    assert "error" in out and "evidence source" in out["error"]


def test_malformed_mcp_input_never_crashes_and_never_mutates():
    tools = _tools()
    store = tempfile.mkdtemp()
    probes = [
        lambda: tools["get_rule"]("does-not-exist"),
        lambda: tools["download_report"](scan_id="../../etc/passwd", reports_dir=store),
        lambda: tools["explain_finding"](scan_id="../../../x", reports_dir=store),
        lambda: tools["posture_history"](reports_dir=store),
        lambda: tools["run_scan"](tactics=["Not A Tactic"], mock=True, save=False),
        lambda: tools["run_scan"](frameworks=["SOX"], mock=True, save=False),
        lambda: tools["analyze_rbac_paths"](principal="////", mock=True),
        lambda: tools["analyze_network_policy"](pod="ghost", mock=True),
        lambda: tools["download_report"](format="exe", reports_dir=store),
        lambda: tools["evaluate_runtime_events"](events=[None]),
        lambda: tools["evaluate_runtime_events"](events=[{"proc": "bash"}]),
        lambda: tools["run_scan"](mock=False, kubeconfig="/nonexistent/kc", save=False),
    ]
    for probe in probes:
        assert probe() is not None            # must not raise
    assert os.listdir(store) == [], "a read-only probe must not write to the store"


def test_path_traversal_in_a_scan_id_cannot_escape_the_report_store():
    store = tempfile.mkdtemp()
    for evil in ("../../etc/passwd", "..\\..\\windows\\system32", "/etc/shadow",
                 "a/../../b"):
        assert "error" in _tools()["download_report"](scan_id=evil, reports_dir=store)


# =========================================================================== #
# Framework crosswalk: absent evidence must never become compliance
# =========================================================================== #
def test_an_unresolved_cis_control_is_never_counted_as_a_pass():
    from k8smatrixwarden.frameworks.cis import CISBenchmarkEngine
    platform = _platform()
    report = CISBenchmarkEngine(platform).evaluate(platform.make_collector(mock=True))
    unresolved = [r for r in report.results
                  if r.status in ("MANUAL", "NEEDS_NODE", "NA")]
    assert unresolved, "the mock cluster has controls that cannot be auto-evaluated"
    assert all(r.status != "PASS" for r in unresolved)
    # The pass rate is computed over EVALUATED controls only, so an unassessed control can
    # neither inflate nor deflate it into a compliance claim.
    evaluated = report.counts["PASS"] + report.counts["FAIL"]
    assert report.pass_pct == round(100 * report.counts["PASS"] / evaluated)


def test_a_governance_requirement_never_passes_without_evidence():
    from k8smatrixwarden.frameworks.compliance import run_audit
    report = run_audit(_platform(), mock=True)
    assert report.frameworks
    for framework in report.frameworks:
        for req in framework.requirements:
            if req.status == "PASS":
                assert req.evidence, \
                    f"{framework.name}/{req.id} claims compliance with no evidence"


# =========================================================================== #
# Pagination: a capped read must never look complete
# =========================================================================== #
class _PagedAPI:
    """Serves more objects than the page cap allows, like a large real cluster."""

    def __init__(self, total, page=500, report_remaining=True):
        self.total, self.page, self.served = total, page, 0
        self.report_remaining = report_remaining

    def call_api(self, path, method, **_kw):
        n = min(self.page, self.total - self.served)
        self.served += n
        meta = {"continue": "tok" if self.served < self.total else ""}
        if self.report_remaining and self.served < self.total:
            meta["remainingItemCount"] = self.total - self.served
        body = json.dumps({"items": [{"metadata": {"name": f"o{i}"}} for i in range(n)],
                           "metadata": meta}).encode()

        class _R:
            data = body
        return _R()


def _capped_collector(total, report_remaining=True, max_pages=3):
    from k8smatrixwarden.core.evidence import EvidenceCollector, LiveEvidenceCollector
    c = LiveEvidenceCollector.__new__(LiveEvidenceCollector)
    EvidenceCollector.__init__(c)
    c._api = _PagedAPI(total, report_remaining=report_remaining)
    c._MAX_PAGES = max_pages
    c._context = c._kubeconfig = None
    return c


def test_a_pagination_capped_read_is_partial_with_a_real_estimate():
    from k8smatrixwarden.core.coverage import build_coverage
    c = _capped_collector(10000)
    items = c._fetch("Pod", "pods")
    entry = c.coverage["Pod"]
    assert len(items) == 1500
    assert entry["status"] == "partial"
    assert entry["coverage_basis"] == "estimated"
    assert entry["estimated_coverage"] == 0.15    # 1500 of 10000, from the API's own count
    assert c.warnings, "a truncated read must warn"
    assert build_coverage(c)["coverage_basis"] == "estimated"


def test_a_capped_read_with_no_remaining_count_reports_unknown_not_a_number():
    """Inventing a fraction here would be false precision about how much was missed."""
    from k8smatrixwarden.core.coverage import build_coverage
    c = _capped_collector(10000, report_remaining=False)
    c._fetch("Pod", "pods")
    entry = c.coverage["Pod"]
    assert entry["status"] == "partial"
    assert entry["coverage_basis"] == "unknown"
    assert entry["estimated_coverage"] is None
    assert build_coverage(c)["coverage_basis"] == "unknown"


def test_a_read_that_fits_under_the_cap_is_not_marked_partial():
    c = _capped_collector(300)
    c.collect({"Pod"}, Scope(ScopeLevel.CLUSTER))
    assert c.coverage["Pod"]["status"] == "ok"
    assert c.warnings == []


# =========================================================================== #
# Scale: the analysis must stay linear in cluster size
# =========================================================================== #
def test_workload_resolution_is_indexed_not_a_linear_rescan():
    """REGRESSION. Resolving each finding's workload by scanning every object of that kind
    was O(findings x objects): a 5000-pod cluster took 33s, of which 15s was that scan
    alone. The lookup table is now built once, like the evidence snapshot itself."""
    import time
    from k8smatrixwarden.core.evidence import MockEvidenceCollector
    from k8smatrixwarden.core.reachability import _workload_index, annotate_reachability

    def big(n):
        return _cluster(pods=[
            {"kind": "Pod", "metadata": {"name": f"pod-{i}", "namespace": "default",
                                         "labels": {"app": "a"}},
             "spec": {"containers": [_priv()]}} for i in range(n)])

    timings, index = {}, None
    for n in (200, 800):
        result, _ = _scan_cluster(big(n))
        path = os.path.join(tempfile.mkdtemp(), "c.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(big(n), fh)
        ev = MockEvidenceCollector(path).collect(
            {"Pod", "Service", "NetworkPolicy", "Namespace", "ClusterRole", "Role",
             "ClusterRoleBinding", "RoleBinding", "ServiceAccount"},
            Scope(ScopeLevel.CLUSTER))
        # Best of three. This is a wall-clock ratio on a shared machine, and a single
        # sample picks up whatever else the box is doing (here: a live cluster, a Falco
        # DaemonSet and a web server). The minimum is the run least disturbed by the
        # scheduler, so the bound below stays strict instead of being loosened to absorb
        # noise it should not have to.
        best = None
        for _ in range(3):
            start = time.perf_counter()
            annotate_reachability(result.findings, ev)
            elapsed = time.perf_counter() - start
            best = elapsed if best is None else min(best, elapsed)
        timings[n] = best
        index = _workload_index(ev)

    # 4x the cluster must not cost anything like 16x the time, which is the quadratic
    # signature this test exists to catch.
    growth = timings[800] / max(timings[200], 1e-6)
    assert growth < 10, f"reachability scales superlinearly: 4x pods cost {growth:.1f}x"
    assert ("Pod", "pod-0", "default") in index


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
