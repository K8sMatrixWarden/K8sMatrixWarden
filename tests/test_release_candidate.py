"""
Release-candidate trust regressions.

Where the deep-semantics pass asked "does the scanner miss a real weakness?", this one asks
"can the scanner state something it has not established?". The defects below are all of that
shape: a verdict produced by an absence — a rule that never ran, a scan that never looked, a
cluster that could not be read, an event that is years old — being reported as though it
were a measurement.

Each test names the claim that must not be made.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.attack_path import resource_paths
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag, ResourceRef,
                                         ScanRequest, Selector, Severity, Tactic)
from k8smatrixwarden.core.posture import latest_change
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.frameworks.cis import (CISBenchmarkEngine, NOT_ASSESSED, PASS,
                                            _unreadable_kinds)
from k8smatrixwarden.frameworks.compliance import ComplianceEngine

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
    cl = {k: [] for k in _BUCKETS}
    cl["namespaces"] = [{"kind": "Namespace", "metadata": {"name": "prod"}}]
    cl.update(buckets)
    return cl


def _fixture(cluster):
    path = os.path.join(tempfile.mkdtemp(), "c.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cluster, fh)
    return path


def _scan(cluster, modules=None, break_rule=None):
    p = _platform()
    original = None
    if break_rule:
        rule = p.registry.rules.get(break_rule)
        original = rule.check

        def boom(*a, **k):
            raise RuntimeError("simulated rule crash")
        rule.check = boom
    try:
        return ScannerAgent(p).scan(
            ScanRequest(selector=Selector(modules=list(modules or []))),
            p.make_collector(mock=True, fixture=_fixture(cluster)))
    finally:
        if original is not None:
            p.registry.rules.get(break_rule).check = original


WILDCARD = _cluster(
    clusterroles=[{"kind": "ClusterRole", "metadata": {"name": "cr"},
                   "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}])


# =========================================================================== #
# Historical posture: a scan may only report what it actually evaluated
# =========================================================================== #
def test_a_rule_that_crashed_is_never_reported_as_fixed():
    """REGRESSION, the worst defect of this pass. `resolved_rule_ids` carried the rules a
    scan SELECTED, not the ones that ran, so a rule that raised still counted as evidence
    that its findings were gone. The finding was reported `resolved` and the risk score
    improved to match: a broken rule made the cluster look like it had been repaired."""
    store = ReportStore(tempfile.mkdtemp())
    healthy = _scan(WILDCARD, modules=["rbac_identity"])
    store.save(healthy)
    assert any(f.rule_id == "rbac-wildcard-verbs" for f in healthy.findings)

    crashed = _scan(WILDCARD, modules=["rbac_identity"],
                    break_rule="rbac-wildcard-verbs")
    store.save(crashed)
    assert "rbac-wildcard-verbs" not in crashed.resolved_rule_ids
    assert "rbac-wildcard-verbs" in crashed.failed_rule_ids
    assert not any(f.rule_id == "rbac-wildcard-verbs" and f.severity.weight
                   for f in crashed.findings), "the crashed rule produced no finding"

    change = latest_change(store, crashed.scan_id)
    assert [v["rule_id"] for v in change["resolved"]] == []
    assert "rbac-wildcard-verbs" in [v["rule_id"] for v in change["not_rescanned"]]


def test_a_finding_the_previous_scan_never_evaluated_is_not_reported_as_new():
    """REGRESSION, the mirror image. Scan 2 used a different selector, so it never looked
    for scan 1's findings. When scan 3 looked again they were reported as NEW, telling an
    analyst five fresh critical RBAC problems had appeared when nothing had changed."""
    store = ReportStore(tempfile.mkdtemp())
    store.save(_scan(WILDCARD, modules=["rbac_identity"]))
    store.save(_scan(WILDCARD, modules=["network_security"]))
    third = _scan(WILDCARD, modules=["rbac_identity"])
    store.save(third)

    change = latest_change(store, third.scan_id)
    assert change["new"] == [], "the previous scan never ran these rules"
    assert change["regressed"] == [], "they were never resolved, so never regressed"
    carried = [v for v in change["persistent"] if v["unevaluated_in_previous_scan"]]
    assert len(carried) == 5, "still open, and flagged as unevaluated last time"
    assert "not evaluated by the previous scan" in change["summary"]


def test_a_genuinely_new_finding_is_still_reported_as_new():
    """The control. The carried-over rule must only apply when the previous scan was blind
    to the rule; two consecutive full scans still report real change."""
    store = ReportStore(tempfile.mkdtemp())
    store.save(_scan(_cluster(), modules=["rbac_identity"]))
    second = _scan(WILDCARD, modules=["rbac_identity"])
    store.save(second)
    change = latest_change(store, second.scan_id)
    assert "rbac-wildcard-verbs" in [v["rule_id"] for v in change["new"]]


def test_two_scans_in_the_same_second_compare_in_the_right_direction():
    """REGRESSION. `generated_at` has second resolution, so the store breaks ties on the
    scan id, whose trailing field was a hash of the timestamp. Deterministic, but ordered
    at random: the LATER of two same-second scans could sort first, and posture then
    compared backwards, swapping `new` and `resolved`."""
    from k8smatrixwarden.core.results import _scan_id
    ids = [_scan_id("x") for _ in range(60)]
    assert ids == sorted(ids), "ids minted in order must sort in order"

    store = ReportStore(tempfile.mkdtemp())
    first = _scan(_cluster(), modules=["rbac_identity"])
    store.save(first)
    second = _scan(WILDCARD, modules=["rbac_identity"])
    store.save(second)
    if first.generated_at == second.generated_at:      # the case under test
        change = latest_change(store, second.scan_id)
        assert change["previous_scan_id"] == first.scan_id
        assert "rbac-wildcard-verbs" in [v["rule_id"] for v in change["new"]]


# =========================================================================== #
# Compliance: absence of evidence is not compliance
# =========================================================================== #
class _UnreadableCollector:
    """Every read fails, as when RBAC forbids it or the API server is unreachable."""

    KINDS = ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "Service",
             "Ingress", "NetworkPolicy", "ServiceAccount", "Secret", "ConfigMap", "Role",
             "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Namespace", "Node",
             "ReplicaSet", "ComponentConfig")

    def __init__(self):
        self.warnings = [f"{k}: skipped (forbidden)" for k in self.KINDS]
        self.degraded = True
        self.fetched_ok = False
        self.coverage = {k: {"status": "skipped", "count": 0, "reason": "forbidden",
                             "estimated_coverage": 0.0, "coverage_basis": "measured"}
                         for k in self.KINDS}

    def collect(self, needs, scope):
        from k8smatrixwarden.core.evidence import Evidence
        return Evidence({}, scope)

    def cluster_label(self):
        return "unreachable"


def test_an_unreadable_cluster_never_produces_a_compliance_pass():
    """REGRESSION, the defect an auditor would have acted on. A cluster nothing could be
    read from produced the same empty finding set as a clean one, so every rule-backed CIS
    control returned "no violations detected" and the frameworks built on them reported
    SOC 2 at a 100% pass rate, including CC6.3 (least privilege) and NIST AC-6."""
    coll = _UnreadableCollector()
    assert _unreadable_kinds(coll), "the collector reports what it could not read"

    report = CISBenchmarkEngine(_platform()).evaluate(coll)
    passed = [r for r in report.results if r.status == PASS]
    assert passed == [], f"controls passed without evidence: {[r.control.id for r in passed]}"
    assert any(r.status == NOT_ASSESSED for r in report.results)

    audit = ComplianceEngine().evaluate(cis_results=report.results, findings=[],
                                        cluster="unreachable")
    for framework in audit.frameworks:
        assert framework.counts[PASS] == 0, f"{framework.short} passed on no evidence"
        assert "not a passing result" in framework.attestation


def test_a_readable_but_empty_cluster_still_reports_real_passes():
    """The control, and the distinction the fix turns on: a cluster that was READ and holds
    no workloads genuinely satisfies "no privileged containers". Only an unreadable one is
    unassessable. Confusing the two in either direction is a wrong answer."""
    p = _platform()
    coll = p.make_collector(mock=True, fixture=_fixture(_cluster()))
    report = CISBenchmarkEngine(p).evaluate(coll)
    assert any(r.status == PASS for r in report.results)
    assert all(r.status != NOT_ASSESSED for r in report.results)


def test_cis_statuses_keep_distinct_meanings():
    """NOT_ASSESSED must not be quietly folded into an existing status; each answers a
    different question and an auditor reads them differently."""
    from k8smatrixwarden.frameworks import cis
    assert len(set(cis._ALL_STATUSES)) == 6
    for status in (cis.PASS, cis.FAIL, cis.MANUAL, cis.NA, cis.NEEDS_NODE,
                   cis.NOT_ASSESSED):
        assert status in cis._ALL_STATUSES and status in cis._EMOJI


# =========================================================================== #
# Runtime evidence: age and volume
# =========================================================================== #
_NOW = "2026-08-31T00:00:00Z"


def _finding(name="api", ns="prod", kind="Deployment"):
    f = Finding(rule_id="r1", title="r1", severity=Severity.HIGH,
                resource=ResourceRef(kind, name, ns), message="m",
                mitre=[MitreTag(Tactic.EXECUTION, "T1059", "Cmd")],
                detection_method=DetectionMethod.STATIC_CONFIG)
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": kind, "name": name, "detail": ns}]
    return f


def _event(time=None, **kw):
    e = {"source": "falco", "proc": "bash", "pod": "api-9zskz", "namespace": "prod"}
    if time:
        e["time"] = time
    e.update(kw)
    return e


def _alerts(events):
    return RuntimeAgent().evaluate_stream(normalize_events(events))


def _path(events):
    corr = correlate([_finding()], _alerts(events), cluster="c1", now=_NOW)
    return corr, resource_paths([_finding()],
                                {"correlation": corr, "drift": {"drift": []}})[0]


def test_an_attack_path_carries_the_age_of_the_evidence_it_rests_on():
    """REGRESSION. The correlator labelled a 2019 alert `historical`, but the attack path
    dropped that and reported `observed` with no age, so every surface reading the path
    presented seven-year-old evidence as a live intrusion."""
    _, path = _path([_event(time="2019-01-01T00:00:00Z")])
    assert path["evidence_freshness"] == "historical"
    entry = path["runtime_evidence"][0]
    assert entry["freshness"] == "historical"
    assert entry["age_days"] > 2000

    _, fresh = _path([_event(time="2026-08-30T23:00:00Z")])
    assert fresh["evidence_freshness"] == "recent"


def test_a_path_with_no_runtime_evidence_says_none_not_unknown():
    """`none` (nothing was observed) and `unknown` (something was observed, of unknown age)
    are different states and a reader acts on them differently."""
    paths = resource_paths([_finding()], {"correlation": {"correlations": []},
                                          "drift": {"drift": []}})
    assert paths[0]["evidence_freshness"] == "none"


def test_repeated_alerts_raise_the_volume_not_the_evidence():
    """REGRESSION. A shell held open emits the same Falco alert repeatedly. Counting each
    copy turned one observation into "50 confirmed exploitations", overstating an incident
    to the audience least able to check it. Volume and strength are now separate."""
    for n in (1, 5, 50):
        corr, path = _path([_event(time="2026-08-30T23:00:00Z")] * n)
        assert corr["total_alerts"] == n, "volume is reported honestly"
        assert corr["confirmed_exploitation"] == 1, "one weakness, one resource, one fact"
        assert path["confidence"] == "observed"


def test_distinct_resources_still_count_separately():
    """The control: deduplication must key on the resource, not collapse everything."""
    corr = correlate(
        [_finding(name="api"), _finding(name="worker")],
        _alerts([_event(time=_NOW, pod="api-9zskz"),
                 _event(time=_NOW, pod="worker-4dfxq")]), cluster="c1", now=_NOW)
    assert corr["confirmed_exploitation"] == 2


def test_runtime_correlation_is_deterministic_regardless_of_event_order():
    batch = [_event(time="2026-08-30T10:00:00Z", proc="nc"),
             _event(time="2026-08-30T09:00:00Z", proc="bash"),
             _event(time="2026-08-30T09:00:00Z", proc="curl"),
             _event(proc="sh"),
             _event(time="garbage", proc="python")]
    runs = [[(c["timestamp"], c["resource"], c["confidence"])
             for c in correlate([_finding()], _alerts(batch), cluster="c1",
                                now=_NOW)["correlations"]] for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]
    reverse = correlate([_finding()], _alerts(list(reversed(batch))), cluster="c1",
                        now=_NOW)["correlations"]
    assert sorted(str(c["timestamp"]) for c in reverse) == sorted(str(t)
                                                                  for t, _, _ in runs[0])


# =========================================================================== #
# Resource identity and owner attribution
# =========================================================================== #
_TPL = {"metadata": {"labels": {"app": "api"}},
        "spec": {"containers": [{"name": "c", "image": "x:1",
                                 "securityContext": {"privileged": True}}]}}


def _owners(result, kind="Pod"):
    return {(f.resource.owner_kind, f.resource.owner_name)
            for f in result.findings if f.resource.kind == kind}


def test_one_pod_has_one_owner_across_every_shard():
    """REGRESSION. Owner resolution lived in workload_pod_security only, so that shard's
    findings named `Deployment/api` while another shard's findings on the SAME Pod named
    `ReplicaSet/api-5f8b`. One object with two owners splits a workload in two wherever a
    report groups by owner."""
    result = _scan(_cluster(
        deployments=[{"kind": "Deployment", "metadata": {"name": "api",
                                                         "namespace": "prod"},
                      "spec": {"template": _TPL}}],
        replicasets=[{"kind": "ReplicaSet",
                      "metadata": {"name": "api-5f8b", "namespace": "prod",
                                   "ownerReferences": [{"kind": "Deployment",
                                                        "name": "api"}]},
                      "spec": {"template": _TPL}}],
        pods=[{"kind": "Pod",
               "metadata": {"name": "api-5f8b-aaaaa", "namespace": "prod",
                            "labels": {"app": "api"},
                            "ownerReferences": [{"kind": "ReplicaSet",
                                                 "name": "api-5f8b"}]},
               "spec": _TPL["spec"]}]))
    shards = {f.owning_shard for f in result.findings if f.resource.kind == "Pod"}
    assert len(shards) > 1, "the test needs findings from more than one shard to be useful"
    assert _owners(result) == {("Deployment", "api")}


def test_owner_resolution_never_crosses_a_namespace():
    """REGRESSION. The intermediate lookup matched on name alone, so a Pod in `staging`
    owned by a ReplicaSet called `shared` could resolve through the `prod` ReplicaSet of the
    same name and be attributed to the wrong Deployment. Names repeat across namespaces
    constantly, e.g. the same Helm chart installed twice."""
    cl = _cluster()
    cl["namespaces"] = [{"kind": "Namespace", "metadata": {"name": "prod"}},
                        {"kind": "Namespace", "metadata": {"name": "staging"}}]
    cl["deployments"] = [
        {"kind": "Deployment", "metadata": {"name": "prod-api", "namespace": "prod"},
         "spec": {"template": _TPL}},
        {"kind": "Deployment", "metadata": {"name": "staging-api",
                                            "namespace": "staging"},
         "spec": {"template": _TPL}}]
    cl["replicasets"] = [
        {"kind": "ReplicaSet",
         "metadata": {"name": "shared", "namespace": ns,
                      "ownerReferences": [{"kind": "Deployment", "name": owner}]},
         "spec": {"template": _TPL}}
        for ns, owner in (("prod", "prod-api"), ("staging", "staging-api"))]
    cl["pods"] = [{"kind": "Pod",
                   "metadata": {"name": "p", "namespace": "staging",
                                "labels": {"app": "api"},
                                "ownerReferences": [{"kind": "ReplicaSet",
                                                     "name": "shared"}]},
                   "spec": _TPL["spec"]}]
    assert _owners(_scan(cl)) == {("Deployment", "staging-api")}


def test_a_cronjob_pod_is_attributed_to_the_cronjob_not_the_job():
    result = _scan(_cluster(
        cronjobs=[{"kind": "CronJob", "metadata": {"name": "backup",
                                                   "namespace": "prod"},
                   "spec": {"jobTemplate": {"spec": {"template": _TPL}}}}],
        jobs=[{"kind": "Job",
               "metadata": {"name": "backup-28900", "namespace": "prod",
                            "ownerReferences": [{"kind": "CronJob", "name": "backup"}]},
               "spec": {"template": _TPL}}],
        pods=[{"kind": "Pod",
               "metadata": {"name": "backup-28900-x1", "namespace": "prod",
                            "labels": {"app": "api"},
                            "ownerReferences": [{"kind": "Job",
                                                 "name": "backup-28900"}]},
               "spec": _TPL["spec"]}]))
    assert _owners(result) == {("CronJob", "backup")}


def test_controller_posture_survives_pod_churn():
    """A recreated Pod has a new name and a new UID, but the Deployment's security posture
    is the same fact about the same object. Controller-level findings must not churn."""
    def scan_with(pod_name):
        return _scan(_cluster(
            deployments=[{"kind": "Deployment",
                          "metadata": {"name": "api", "namespace": "prod"},
                          "spec": {"template": _TPL}}],
            pods=[{"kind": "Pod",
                   "metadata": {"name": pod_name, "namespace": "prod",
                                "uid": pod_name, "labels": {"app": "api"}},
                   "spec": _TPL["spec"]}]))

    from k8smatrixwarden.core.posture import finding_key
    keys = [{finding_key(f) for f in scan_with(n).findings
             if f.resource.kind == "Deployment" and f.severity.weight}
            for n in ("api-aaaaa", "api-zzzzz")]
    assert keys[0] == keys[1] and keys[0]


# =========================================================================== #
# Bounds, and the LLM
# =========================================================================== #
def test_a_truncated_rbac_search_never_reports_no_escalation():
    """A bound that stops the search must never read as a finished search that found
    nothing. `truncated` plus `none` would be the graph layer's version of a false green."""
    from k8smatrixwarden.core.rbac_graph import Node, RbacGraph
    croles = [{"kind": "ClusterRole", "metadata": {"name": f"r{i}"},
               "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
                         {"apiGroups": ["rbac.authorization.k8s.io"],
                          "resources": ["clusterroles"],
                          "verbs": ["bind", "escalate"]}]} for i in range(60)]
    crbs, sas = [], []
    for i in range(60):
        sas.append({"kind": "ServiceAccount",
                    "metadata": {"name": f"sa{i}", "namespace": "prod"}})
        for j in range(3):
            crbs.append({"kind": "ClusterRoleBinding",
                         "metadata": {"name": f"b{i}-{j}"},
                         "roleRef": {"kind": "ClusterRole", "name": f"r{(i + j) % 60}"},
                         "subjects": [{"kind": "ServiceAccount", "name": f"sa{i}",
                                       "namespace": "prod"}]})
    analysis = RbacGraph(croles, [], crbs, [], sas).escalation_analysis(
        Node("ServiceAccount", "sa0", "prod"))
    if analysis["analysis_status"] == "truncated":
        assert analysis["escalation_verdict"] != "none"
        assert analysis["truncation_reason"]
    assert analysis["limits"]["max_hops"] and analysis["limits"]["max_onward_targets"]


def test_binding_lookup_is_indexed_but_still_namespace_exact():
    """The binding index must not have traded correctness for speed: a ServiceAccount
    subject is namespaced, and matching loosely is how a tool claims some other namespace's
    `default` account is cluster-admin."""
    from k8smatrixwarden.core.rbac_graph import Node, RbacGraph
    crb = {"kind": "ClusterRoleBinding", "metadata": {"name": "b"},
           "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
           "subjects": [{"kind": "ServiceAccount", "name": "default",
                         "namespace": "prod"}]}
    graph = RbacGraph([], [], [crb], [], [])
    assert graph.bindings_for(Node("ServiceAccount", "default", "prod"))
    assert graph.bindings_for(Node("ServiceAccount", "default", "staging")) == []
    # A Group is cluster-scoped, so its namespace is not part of its identity.
    gcrb = {"kind": "ClusterRoleBinding", "metadata": {"name": "g"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "Group", "name": "devs"}]}
    assert RbacGraph([], [], [gcrb], [], []).bindings_for(Node("Group", "devs", ""))


def test_the_scanner_is_identical_with_and_without_an_llm():
    """The LLM may explain findings; it may never be load-bearing for them."""
    p = _platform()
    saved = {k: v for k, v in os.environ.items() if k.startswith("K8SMATRIXWARDEN_LLM")}
    try:
        digests = []
        for env in ({}, {"K8SMATRIXWARDEN_LLM_PROVIDER": "not-a-provider"},
                    {"K8SMATRIXWARDEN_LLM_PROVIDER": "openai",
                     "K8SMATRIXWARDEN_LLM_BASE_URL": "http://127.0.0.1:9/v1",
                     "K8SMATRIXWARDEN_LLM_API_KEY": "x"}):
            for k in list(os.environ):
                if k.startswith("K8SMATRIXWARDEN_LLM"):
                    del os.environ[k]
            os.environ.update(env)
            result = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
            digests.append(sorted((f.rule_id, str(f.resource), f.severity.label)
                                  for f in result.findings))
        assert digests[0] == digests[1] == digests[2]
    finally:
        for k in list(os.environ):
            if k.startswith("K8SMATRIXWARDEN_LLM"):
                del os.environ[k]
        os.environ.update(saved)


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
