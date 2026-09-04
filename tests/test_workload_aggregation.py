"""
Workload-level aggregation: the ways it could group two things that are not the same, or
fail to group two things that are.

Aggregation exists because Kubernetes represents one workload as a chain of objects, so one
misconfiguration is reported on the Deployment, its ReplicaSets and every Pod. Collapsing
that chain makes the headline count mean "how many separate fixes", which is what a count is
read as meaning. Collapsing anything else would be a lie in the other direction: two real
problems reported as one, which is how a scanner hides a finding.

So these tests are mostly about refusal. Aggregation follows Kubernetes' ownership metadata
and nothing else -- never a name prefix, never a similarity, never a pod-naming convention.
Namespace and cluster are part of workload identity. The group key is (rule, workload), so
two flaws on one workload stay two issues and one flaw on two workloads stays two issues.

The resource-level findings are never touched. Every test that checks a collapse also checks
that the evidence underneath it is still all there.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, ScanRequest,
                                         Severity, Tactic)
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.results import ScanResult
from k8smatrixwarden.core.scoring import RiskResult, RiskScoringEngine
from k8smatrixwarden.core.workload import (is_derived_resource, summarize, workload_id,
                                           workload_issues)

CLUSTER = "cluster-a"


def F(rule, kind, name, namespace="prod", owner_kind=None, owner_name=None,
      severity=Severity.HIGH, tactics=(Tactic.EXECUTION,)):
    return Finding(
        rule_id=rule, title=rule, severity=severity,
        resource=ResourceRef(kind=kind, name=name, namespace=namespace,
                             owner_kind=owner_kind, owner_name=owner_name),
        message="m", owning_shard="workload_pod_security",
        mitre=[MitreTag(t, "T1610", "Deploy Container") for t in tactics])


def groups(findings, cluster=CLUSTER):
    return workload_issues(list(findings), cluster)


# =========================================================================== #
# The collapse that is the point
# =========================================================================== #

def test_deployment_replicaset_pod_is_one_issue():
    findings = [F("run-as-root", "Deployment", "foo"),
                F("run-as-root", "ReplicaSet", "foo-abc123", owner_kind="Deployment",
                  owner_name="foo"),
                F("run-as-root", "Pod", "foo-abc123-xyz", owner_kind="Deployment",
                  owner_name="foo")]
    issues = groups(findings)
    assert len(issues) == 1
    assert issues[0].workload_id == f"Deployment/foo|prod|{CLUSTER}"


def test_the_resource_evidence_survives_the_collapse():
    """Aggregation adds a count. It must never be a way of losing a finding."""
    findings = [F("run-as-root", "Deployment", "foo"),
                F("run-as-root", "Pod", "foo-abc-xyz", owner_kind="Deployment",
                  owner_name="foo")]
    issue = groups(findings)[0]
    assert issue.as_dict()["resource_count"] == 2
    assert len(findings) == 2, "the findings list is not consumed or filtered"
    assert set(issue.resources) == {"Deployment/foo (prod)", "Pod/foo-abc-xyz (prod)"}


def test_statefulset_daemonset_and_job_chains_collapse():
    for kind, pod in (("StatefulSet", "db-0"), ("DaemonSet", "node-exp-x9k2z"),
                      ("Job", "one-shot-4bq7w")):
        findings = [F("run-as-root", kind, "w"),
                    F("run-as-root", "Pod", pod, owner_kind=kind, owner_name="w")]
        assert len(groups(findings)) == 1, kind


def test_cronjob_job_pod_collapses_to_the_cronjob():
    """resolve_owner walks Job -> CronJob, so both the Job and its Pod name the CronJob."""
    findings = [F("run-as-root", "CronJob", "nightly"),
                F("run-as-root", "Job", "nightly-28", owner_kind="CronJob",
                  owner_name="nightly"),
                F("run-as-root", "Pod", "nightly-28-w4t2p", owner_kind="CronJob",
                  owner_name="nightly")]
    issues = groups(findings)
    assert len(issues) == 1
    assert issues[0].workload_id.startswith("CronJob/nightly|")


def test_many_pods_of_one_deployment_are_one_issue():
    findings = [F("run-as-root", "Deployment", "foo")] + [
        F("run-as-root", "Pod", f"foo-abc-{i}", owner_kind="Deployment", owner_name="foo")
        for i in range(20)]
    issues = groups(findings)
    assert len(issues) == 1
    assert issues[0].as_dict()["resource_count"] == 21


def test_two_replicasets_during_a_rollout_are_one_issue():
    """Both the outgoing and incoming ReplicaSet belong to the same Deployment."""
    findings = [F("run-as-root", "ReplicaSet", "foo-old", owner_kind="Deployment",
                  owner_name="foo"),
                F("run-as-root", "ReplicaSet", "foo-new", owner_kind="Deployment",
                  owner_name="foo")]
    assert len(groups(findings)) == 1


# =========================================================================== #
# Collapses that must NOT happen
# =========================================================================== #

def test_two_rules_on_one_workload_stay_two_issues():
    findings = [F("run-as-root", "Deployment", "foo"),
                F("privileged", "Deployment", "foo"),
                F("hostpath", "Deployment", "foo")]
    assert len(groups(findings)) == 3


def test_one_rule_on_two_workloads_stays_two_issues():
    findings = [F("run-as-root", "Deployment", "foo"),
                F("run-as-root", "Deployment", "bar")]
    assert len(groups(findings)) == 2


def test_the_same_workload_name_in_two_namespaces_does_not_collapse():
    findings = [F("run-as-root", "Deployment", "api", namespace="staging"),
                F("run-as-root", "Deployment", "api", namespace="production")]
    assert len({i.workload_id for i in groups(findings)}) == 2


def test_the_same_workload_name_in_two_clusters_does_not_collapse():
    resource = ResourceRef(kind="Deployment", name="api", namespace="prod")
    assert workload_id(resource, "cluster-a") != workload_id(resource, "cluster-b")


def test_a_similar_name_is_not_the_same_workload():
    """`api-server` starts with `api-`. Nothing here matches on prefixes."""
    findings = [F("run-as-root", "Deployment", "api"),
                F("run-as-root", "Deployment", "api-server")]
    assert len(groups(findings)) == 2


def test_a_pod_is_never_attached_to_a_workload_by_its_name():
    """A Pod named like a Deployment's children, but owned by nothing, stands alone."""
    findings = [F("run-as-root", "Deployment", "foo"),
                F("run-as-root", "Pod", "foo-abc123-xyz")]     # no ownerReference
    issues = groups(findings)
    assert len(issues) == 2, "the name resemblance must not create an ownership claim"


def test_two_workload_kinds_sharing_a_name_do_not_collapse():
    findings = [F("run-as-root", "Deployment", "api"),
                F("run-as-root", "StatefulSet", "api")]
    assert len(groups(findings)) == 2


def test_cluster_scoped_and_namespaced_resources_do_not_collapse():
    findings = [F("wildcard", "ClusterRole", "admin", namespace=None),
                F("wildcard", "Role", "admin", namespace="prod")]
    assert len(groups(findings)) == 2


# =========================================================================== #
# Standalone and unresolvable objects keep their own identity
# =========================================================================== #

def test_a_standalone_pod_is_its_own_workload():
    findings = [F("run-as-root", "Pod", "debug-shell")]
    issue = groups(findings)[0]
    assert issue.workload_id == f"Pod/debug-shell|prod|{CLUSTER}"
    assert not findings[0].is_derived_resource


def test_two_standalone_pods_are_two_workloads():
    findings = [F("run-as-root", "Pod", "debug-a"), F("run-as-root", "Pod", "debug-b")]
    assert len(groups(findings)) == 2


def test_a_pod_whose_controller_is_missing_keeps_the_owner_it_has():
    """The controller was deleted, or the scan could not read it. The Pod is attributed to
    the ReplicaSet Kubernetes actually named, not to a Deployment nobody confirmed."""
    findings = [F("run-as-root", "Pod", "foo-abc-xyz", owner_kind="ReplicaSet",
                  owner_name="foo-abc")]
    assert groups(findings)[0].workload_id == f"ReplicaSet/foo-abc|prod|{CLUSTER}"


def test_a_pod_with_a_flaw_its_controller_does_not_have_is_still_one_issue():
    """Only the Pod fires. It is still that workload's issue, and the evidence says which
    object carries it, so nobody is sent to edit the wrong thing blind."""
    findings = [F("run-as-root", "Pod", "foo-abc-xyz", owner_kind="Deployment",
                  owner_name="foo")]
    issue = groups(findings)[0]
    assert issue.workload_id == f"Deployment/foo|prod|{CLUSTER}"
    assert issue.resources == ["Pod/foo-abc-xyz (prod)"]


def test_derived_is_about_ownership_not_about_the_kind():
    owned = ResourceRef(kind="Pod", name="p", namespace="n",
                        owner_kind="Deployment", owner_name="d")
    alone = ResourceRef(kind="Pod", name="p", namespace="n")
    controller = ResourceRef(kind="Deployment", name="d", namespace="n")
    assert is_derived_resource(owned)
    assert not is_derived_resource(alone)
    assert not is_derived_resource(controller)


# =========================================================================== #
# The representative and the severity of a group
# =========================================================================== #

def test_the_group_is_represented_by_the_object_an_operator_edits():
    findings = [F("run-as-root", "Pod", "foo-abc-xyz", owner_kind="Deployment",
                  owner_name="foo"),
                F("run-as-root", "Deployment", "foo")]
    assert groups(findings)[0].representative == "Deployment/foo (prod)"


def test_a_group_takes_the_worst_severity_in_its_evidence():
    """Aggregating must never quietly downgrade a finding."""
    findings = [F("r", "Deployment", "foo", severity=Severity.MEDIUM),
                F("r", "Pod", "foo-a-b", owner_kind="Deployment", owner_name="foo",
                  severity=Severity.CRITICAL)]
    assert groups(findings)[0].severity == Severity.CRITICAL


def test_grouping_is_deterministic():
    findings = [F("b-rule", "Deployment", "z"), F("a-rule", "Deployment", "a"),
                F("a-rule", "Deployment", "b", severity=Severity.CRITICAL)]
    first = [i.group for i in groups(list(findings))]
    second = [i.group for i in groups(list(reversed(findings)))]
    assert first == second


# =========================================================================== #
# Risk scoring
# =========================================================================== #

def test_controller_layers_do_not_multiply_the_score():
    """The defect this whole change answers: a Deployment scored three times because
    Kubernetes had generated a ReplicaSet and a Pod from it."""
    engine = RiskScoringEngine()
    one = engine.score([F("r", "Deployment", "foo")], CLUSTER)
    three = engine.score([F("r", "Deployment", "foo"),
                          F("r", "ReplicaSet", "foo-abc", owner_kind="Deployment",
                            owner_name="foo"),
                          F("r", "Pod", "foo-abc-xyz", owner_kind="Deployment",
                            owner_name="foo")], CLUSTER)
    assert three.raw == one.raw
    assert three.cluster_risk == one.cluster_risk


def test_two_real_workloads_still_score_twice():
    """Not a discount. Two separate places to fix are twice the risk of one."""
    engine = RiskScoringEngine()
    one = engine.score([F("r", "Deployment", "foo")], CLUSTER)
    two = engine.score([F("r", "Deployment", "foo"), F("r", "Deployment", "bar")],
                       CLUSTER)
    assert two.raw == 2 * one.raw


def test_two_rules_on_one_workload_still_score_twice():
    engine = RiskScoringEngine()
    one = engine.score([F("r1", "Deployment", "foo")], CLUSTER)
    two = engine.score([F("r1", "Deployment", "foo"), F("r2", "Deployment", "foo")],
                       CLUSTER)
    assert two.raw == 2 * one.raw


def test_standalone_pods_each_carry_their_own_risk():
    engine = RiskScoringEngine()
    pods = [F("r", "Pod", f"debug-{i}") for i in range(5)]
    one = engine.score([F("r", "Pod", "debug-0")], CLUSTER)
    assert engine.score(pods, CLUSTER).raw == 5 * one.raw


def test_the_explanation_names_the_basis_it_scored_on():
    result = RiskScoringEngine().score(
        [F("r", "Deployment", "foo"),
         F("r", "Pod", "foo-a-b", owner_kind="Deployment", owner_name="foo")], CLUSTER)
    assert result.explanation["scoring_basis"] == "workload_issues"
    assert result.explanation["resource_findings"] == 2
    assert result.explanation["workload_issues"] == 1
    assert result.explanation["derived_resource_findings"] == 1


def test_the_explanation_shares_still_sum_to_the_score():
    findings = [F("r1", "Deployment", "a", severity=Severity.CRITICAL),
                F("r2", "Deployment", "b", severity=Severity.HIGH),
                F("r3", "Pod", "a-x-y", owner_kind="Deployment", owner_name="a")]
    result = RiskScoringEngine().score(findings, CLUSTER)
    total = sum(v["share_pct"] for v in result.explanation["by_severity"].values())
    assert abs(total - 100.0) < 0.5


def test_a_contributor_is_still_reproducible_by_hand():
    result = RiskScoringEngine().score([F("r", "Deployment", "foo")], CLUSTER)
    top = result.explanation["top_contributors"][0]
    b = top["breakdown"]
    product = (b["severity"]["weight"] * b["exploitability"]["weight"]
               * b["blast_radius"]["weight"] * b["path_multiplier"]["weight"])
    assert round(product, 3) == round(top["score"], 3)


# =========================================================================== #
# Runtime semantics are a different concept and stay untouched
# =========================================================================== #

def test_runtime_events_are_not_deduplicated_by_workload():
    """Five shell executions in one workload are five events. Static workload identity has
    no business collapsing them: the runtime pipeline's identity is the event, not the
    object it happened in."""
    from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
    events = [{"source": "falco", "proc": "bash", "namespace": "prod",
               "pod": "foo-abc123-xyz", "time": f"2026-09-02T10:0{i}:00Z"}
              for i in range(5)]
    alerts = RuntimeAgent().evaluate_stream(normalize_events(events))
    assert len([a for a in alerts if a.rule_id == "rt-shell-in-container"]) == 5


def test_runtime_alerts_carry_no_workload_aggregation_fields():
    """The aggregation vocabulary belongs to static findings. Leaking it onto a runtime
    alert would invite a surface to group events by workload and call it deduplication."""
    from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
    alert = RuntimeAgent().evaluate_stream(normalize_events(
        [{"source": "falco", "proc": "bash", "namespace": "prod", "pod": "p"}]))[0]
    assert not hasattr(alert, "owning_workload_id")
    assert not hasattr(alert, "aggregation_group")


def test_correlation_still_confirms_on_resource_identity():
    """Aggregation must not widen what a runtime event can confirm."""
    from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
    from k8smatrixwarden.core.correlation import correlate
    finding = F("workload-privileged", "Pod", "payment-api", namespace="production")
    alerts = RuntimeAgent().evaluate_stream(normalize_events(
        [{"source": "falco", "proc": "bash", "namespace": "production",
          "pod": "other-workload-5f8b94447d-blxwg"}]))
    assert correlate([finding], alerts)["confirmed_exploitation"] == 0


# =========================================================================== #
# Historical posture at both levels
# =========================================================================== #

def _result(findings, rules, cluster=CLUSTER):
    result = ScanResult(
        request=ScanRequest(), findings=list(findings),
        risk=RiskResult(cluster_risk=1.0, security_score=90, rating="Low",
                        rating_emoji="", raw=1.0),
        resolved_rule_ids=list(rules))
    result.cluster_name = cluster
    return result


def _chain(deployment, replicaset, pod, rule="run-as-root"):
    return [F(rule, "Deployment", deployment),
            F(rule, "ReplicaSet", replicaset, owner_kind="Deployment",
              owner_name=deployment),
            F(rule, "Pod", pod, owner_kind="Deployment", owner_name=deployment)]


def test_identical_scans_show_no_change_at_either_level():
    from k8smatrixwarden.core.posture import compare
    a = _result(_chain("foo", "foo-abc", "foo-abc-xyz"), ["run-as-root"])
    b = _result(_chain("foo", "foo-abc", "foo-abc-xyz"), ["run-as-root"])
    change = compare(a, b)
    assert change["new"] == [] and change["resolved"] == []
    assert change["workload"]["new"] == [] and change["workload"]["resolved"] == []
    assert len(change["workload"]["persistent"]) == 1


def test_a_rollout_is_resource_churn_but_not_a_workload_change():
    """REGRESSION for the reporting failure this level exists to fix. Deleting a Pod,
    creating a ReplicaSet and creating a Pod changes every resource key while the workload
    configuration is identical."""
    from k8smatrixwarden.core.posture import compare
    before = _result(_chain("foo", "foo-abc", "foo-abc-xyz"), ["run-as-root"])
    after = _result(_chain("foo", "foo-def", "foo-def-uvw"), ["run-as-root"])
    change = compare(before, after)
    # Honest at the resource level: those objects really did come and go.
    assert len(change["new"]) == 2 and len(change["resolved"]) == 2
    # Nothing changed about the thing an operator would fix.
    assert change["workload"]["new"] == []
    assert change["workload"]["resolved"] == []
    assert len(change["workload"]["persistent"]) == 1


def test_a_genuinely_new_problem_is_new_at_the_workload_level():
    from k8smatrixwarden.core.posture import compare
    before = _result(_chain("foo", "foo-abc", "foo-abc-xyz"), ["run-as-root"])
    after = _result(_chain("foo", "foo-abc", "foo-abc-xyz")
                    + [F("privileged", "Deployment", "foo")],
                    ["run-as-root", "privileged"])
    change = compare(before, after)
    assert [i["rule_id"] for i in change["workload"]["new"]] == ["privileged"]


def test_a_fixed_workload_is_resolved_at_the_workload_level():
    from k8smatrixwarden.core.posture import compare
    before = _result(_chain("foo", "foo-abc", "foo-abc-xyz"), ["run-as-root"])
    after = _result([], ["run-as-root"])
    change = compare(before, after)
    assert len(change["workload"]["resolved"]) == 1


def test_a_rule_that_did_not_run_is_never_resolved_at_the_workload_level():
    from k8smatrixwarden.core.posture import compare
    before = _result(_chain("foo", "foo-abc", "foo-abc-xyz"), ["run-as-root"])
    after = _result([], [])                       # the rule was not evaluated at all
    change = compare(before, after)
    assert change["workload"]["resolved"] == []
    assert len(change["workload"]["not_rescanned"]) == 1


# =========================================================================== #
# Surfaces publish both counts, consistently
# =========================================================================== #

def _scan():
    platform = build_platform()
    return ScannerAgent(platform).scan(ScanRequest(),
                                       platform.make_collector(mock=True))


def test_a_scan_carries_both_counts():
    result = _scan()
    agg = result.aggregation
    assert agg["resource_findings"] == len(result.findings)
    assert agg["workload_issues"] == len(result.workload_issues)
    assert agg["workload_issues"] <= agg["resource_findings"]


def test_both_counts_survive_a_store_round_trip():
    result = _scan()
    store = ReportStore(tempfile.mkdtemp())
    store.save(result)
    loaded = store.load(result.scan_id)
    assert loaded.aggregation == result.aggregation
    assert len(loaded.workload_issues) == len(result.workload_issues)
    assert len(loaded.findings) == len(result.findings), "no evidence lost in storage"


def test_every_rendered_format_reports_both_counts():
    from k8smatrixwarden.core.reporting import ReportingEngine
    result = _scan()
    engine = ReportingEngine()
    for fmt in ("markdown", "html", "terminal", "text"):
        rendered = engine.render(result, fmt)
        assert "resource" in rendered.lower(), fmt
        assert "workload issue" in rendered.lower(), fmt


def test_the_json_report_names_both_counts_distinctly():
    from k8smatrixwarden.core.reporting import ReportingEngine
    result = _scan()
    summary = json.loads(ReportingEngine().render(result, "json"))["summary"]
    assert summary["resource_findings"] == len(result.findings)
    assert summary["workload_issues"] == len(result.workload_issues)


def test_the_dashboard_api_publishes_both_and_keeps_every_finding():
    from k8smatrixwarden.web.app import WebApp
    platform = build_platform()
    directory = tempfile.mkdtemp()
    store = ReportStore(directory)
    result = ScannerAgent(platform).scan(ScanRequest(),
                                         platform.make_collector(mock=True))
    store.save(result)
    body = json.loads(WebApp(platform, reports_dir=directory)
                      .route("GET", "/api/dashboard").text)
    assert body["aggregation"]["workload_issues"] == len(result.workload_issues)
    assert len(body["findings"]) == len(result.findings), "resource view is untouched"


def test_the_mcp_scan_tool_publishes_both():
    from k8smatrixwarden.mcp.server import build_tools
    out = build_tools()["run_scan"](mock=True, save=False, max_findings=5)
    assert out["summary"]["resource_findings"] >= out["summary"]["workload_issues"]
    assert out["summary"]["workload_issues"] > 0


def test_a_report_saved_before_aggregation_still_reports_both():
    """An old report has no stored aggregation. It must show both counts rather than a
    blank, and it must not claim an identity it never had."""
    from k8smatrixwarden.core.reporting import workload_summary
    result = _scan()
    result.aggregation = {}
    result.workload_issues = []
    agg = workload_summary(result)
    assert agg["resource_findings"] == len(result.findings)
    assert agg["workload_issues"] > 0


# =========================================================================== #
# Findings themselves are unchanged
# =========================================================================== #

def test_aggregation_annotates_findings_without_removing_any():
    findings = _chain("foo", "foo-abc", "foo-abc-xyz")
    before = len(findings)
    workload_issues(findings, CLUSTER)
    assert len(findings) == before
    for finding in findings:
        assert finding.resource_finding_id
        assert finding.owning_workload_id
        assert finding.aggregation_group


def test_resource_finding_ids_are_unique_and_stable():
    findings = _chain("foo", "foo-abc", "foo-abc-xyz")
    workload_issues(findings, CLUSTER)
    ids = [f.resource_finding_id for f in findings]
    assert len(set(ids)) == 3
    again = _chain("foo", "foo-abc", "foo-abc-xyz")
    workload_issues(again, CLUSTER)
    assert [f.resource_finding_id for f in again] == ids


def test_the_summary_arithmetic_is_self_consistent():
    findings = _chain("foo", "foo-abc", "foo-abc-xyz") + [F("r2", "Deployment", "bar")]
    issues = workload_issues(findings, CLUSTER)
    agg = summarize(findings, issues)
    assert agg["resource_findings"] == 4
    assert agg["workload_issues"] == 2
    assert agg["derived_resource_findings"] == 2
    assert agg["distinct_workloads"] == 2
    assert sum(agg["resource_counts"].values()) == 4
    assert sum(agg["workload_counts"].values()) == 2


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
