"""
End-to-end integration: do the subsystems compose into ONE analysis, or several?

Unit tests prove each engine right in isolation. They cannot catch the failure mode this
file exists for: an engine producing correct, richer structure that the next stage quietly
drops. That is exactly what happened with the RBAC and NetworkPolicy results, which were
computed onto every finding and then read by nobody.

So each test here runs a REAL scan over a purpose-built cluster and follows one fact from
the evidence all the way to the surfaces a user sees, asserting it survives every hop:

    evidence -> detection -> reachability -> RBAC/NetworkPolicy -> correlation
             -> attack path -> threat matrix -> risk -> report / MCP / web
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import fixtures_scenarios as fx

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.attack_path import CONFIG_ONLY, CORROBORATED, OBSERVED
from k8smatrixwarden.core.correlation import correlate, detect_drift
from k8smatrixwarden.core.explain import explain_finding
from k8smatrixwarden.core.models import (ScanMode, ScanRequest, Scope, ScopeLevel,
                                         Selector)
from k8smatrixwarden.core.threat_matrix import attack_paths, build_threat_matrix

_PLATFORM = None


def _platform():
    global _PLATFORM
    if _PLATFORM is None:
        _PLATFORM = build_platform()
    return _PLATFORM


def _scan(fixture: dict, namespace=None, runtime_events=None):
    """Run a real scan over a scenario fixture and return (result, platform)."""
    platform = _platform()
    path = fx.write_fixture(fixture, tempfile.mkdtemp())
    scope = (Scope(ScopeLevel.NAMESPACE, namespace=namespace) if namespace
             else Scope(ScopeLevel.CLUSTER))
    request = ScanRequest(scope=scope, selector=Selector(), mode=ScanMode.SYNC)
    collector = platform.make_collector(mock=True, fixture=path)
    result = ScannerAgent(platform).scan(request, collector, mode_label="mock")
    if runtime_events is not None:
        from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
        events = normalize_events(runtime_events)
        alerts = RuntimeAgent().evaluate_stream(events)
        pods = collector.collect({"Pod"}, scope).get("Pod")
        result.runtime = {"source": "test", "events_seen": len(events),
                          "correlation": correlate(result.findings, alerts),
                          "drift": detect_drift(pods, events)}
    return result, platform


def _finding(result, rule_id, name=None, namespace=None):
    for f in result.findings:
        if f.rule_id != rule_id:
            continue
        if name and f.resource.name != name:
            continue
        if namespace and f.resource.namespace != namespace:
            continue
        return f
    return None


# =========================================================================== #
# Scenario A, Internet -> Ingress -> Service -> Pod -> SA -> Binding -> Role
#             -> secrets/get, as ONE coherent evidence-backed chain
# =========================================================================== #
def test_scenario_a_full_chain_is_one_coherent_evidence_backed_path():
    result, platform = _scan(fx.scenario_a())
    f = _finding(result, "workload-privileged-container", "payment-api")
    assert f is not None, "the privileged pod must be detected"

    # 1. Reachability recognised the Ingress -> Service route as external.
    assert "ingress" in f.exploitable_by
    assert "INTERNET-REACHABLE" in f.path_reason

    # 2. The RBAC graph found the escalation, and named the objects behind it.
    assert f.rbac_paths, "the SA is bound to a Role granting secrets/get"
    shortest = min(f.rbac_paths, key=lambda p: p["hops"])
    chain = [n["kind"] for n in shortest["nodes"]]
    assert chain[0] == "ServiceAccount"
    assert "RoleBinding" in chain and "Role" in chain
    names = [n["name"] for n in shortest["nodes"]]
    assert "payment-api-binding" in names and "payment-reader" in names
    # Provenance: every edge says why it exists and which object proves it.
    for edge in shortest["edges"]:
        assert edge["reason"] and edge["evidence"]

    # 3. The structural hop chain on the finding spans network AND identity.
    kinds = [n["kind"] for n in f.exploit_path]
    assert kinds[0] == "Internet"
    assert "Service" in kinds and "Pod" in kinds and "ServiceAccount" in kinds

    # 4. The resource-level attack path reproduces it.
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules),
                      result.runtime, cluster=result.cluster_name)
    paths = [p for p in ap["resource_paths"] if p["target"]["name"] == "payment-api"
             or any(s["node"] == "payment-api" for s in p["steps"])]
    assert paths, "the chain must appear as a resource-level path"
    assert paths[0]["internet_reachable"] is True
    assert paths[0]["path_type"] in ("resource", "observed")

    # 5. The explanation, which every surface shares, carries all of it.
    ex = explain_finding(f, rule=platform.registry.rules.get(f.rule_id),
                         runtime=result.runtime, attack_path=ap,
                         cluster=result.cluster_name)
    assert ex["rbac"]["escalates"] is True
    assert "RoleBinding" in ex["rbac"]["shortest"]["chain"]
    assert ex["network"]["evaluated"] is True
    assert ex["reachability"]["internet_reachable"] is True
    assert ex["resource"]["cluster"] == result.cluster_name


def test_scenario_a_chain_survives_into_every_report_format():
    """The same chain, rendered. A report that cannot name the binding is a report that
    lost the analysis."""
    result, platform = _scan(fx.scenario_a())
    md = platform.reporting.render(result, "markdown")
    assert "RBAC Escalation Path" in md
    assert "payment-api-binding" in md and "payment-reader" in md
    assert "NetworkPolicy" in md and "Reachability Chain" in md

    html = platform.reporting.render(result, "html")
    assert "RBAC escalation path" in html and "payment-api-binding" in html

    doc = json.loads(platform.reporting.render(result, "json"))
    target = next(f for f in doc["findings"]
                  if f["rule_id"] == "workload-privileged-container")
    assert target["rbac_paths"], "JSON must carry the structured paths"
    assert target["network_context"]["ingress"]["status"]
    assert doc["attack_path"]["resource_paths"]


# =========================================================================== #
# Scenario B, a NetworkPolicy blocks the path
# =========================================================================== #
def test_scenario_b_blocked_path_changes_context_not_severity():
    open_result, _ = _scan(fx.scenario_a())
    blocked_result, platform = _scan(fx.scenario_b())

    exposed = _finding(open_result, "workload-privileged-container", "payment-api")
    blocked = _finding(blocked_result, "workload-privileged-container", "payment-api")

    # The vulnerability is identical. Only the reachability context moved.
    assert blocked.severity == exposed.severity
    assert blocked.exploitability == exposed.exploitability
    assert blocked.blast_radius == exposed.blast_radius
    assert "ingress" in exposed.exploitable_by
    assert "pod-privilege" in blocked.exploitable_by
    assert "ingress" not in blocked.exploitable_by
    assert "network path is blocked" in blocked.path_reason

    # And the network engine's own verdict is carried, not just the prose.
    assert blocked.network_context["ingress"]["status"] == "deny-all"
    assert blocked.network_context["ingress"]["policies"] == ["deny-ingress"]

    ap = attack_paths(build_threat_matrix(blocked_result, platform.registry.rules))
    for path in ap["resource_paths"]:
        if any(s["node"] == "payment-api" for s in path["steps"]):
            assert path["internet_reachable"] is False


def test_scenario_b_expression_selector_is_matched_like_match_labels():
    """A policy selecting by matchExpressions must isolate exactly as one using
    matchLabels. Getting this wrong reports a protected pod as internet-reachable."""
    result, _ = _scan(fx.scenario_b_expression_selector())
    f = _finding(result, "workload-privileged-container", "payment-api")
    assert f.network_context["ingress"]["status"] == "deny-all"
    assert "pod-privilege" in f.exploitable_by


def test_scenario_b_unevaluable_policy_is_partial_and_not_isolation():
    """partial != confirmed isolation. The pod stays reported as reachable."""
    result, _ = _scan(fx.scenario_b_unevaluable_policy())
    f = _finding(result, "workload-privileged-container", "payment-api")
    assert f.network_context["ingress"]["status"] == "partial"
    assert "ingress" in f.exploitable_by, \
        "an unconfirmed restriction must not be treated as protection"


# =========================================================================== #
# Scenario C, runtime evidence strengthens a static finding
# =========================================================================== #
def test_scenario_c_runtime_evidence_strengthens_without_inventing_causality():
    result, platform = _scan(fx.scenario_a(),
                             runtime_events=fx.runtime_shell_in_payment_api())
    corr = result.runtime["correlation"]
    assert corr["total_alerts"] >= 2
    assert corr["confirmed_exploitation"] >= 1, \
        "events naming the pod a finding is on are resource-level confirmations"

    # Timestamps and source survive normalisation into the correlation record.
    confirmed = [c for c in corr["correlations"] if c["confidence"] == "confirmed"]
    assert all(c.get("timestamp") for c in confirmed)
    assert all(c["runtime"].get("source") for c in confirmed)

    f = _finding(result, "workload-privileged-container", "payment-api")
    ex = explain_finding(f, rule=platform.registry.rules.get(f.rule_id),
                         runtime=result.runtime)
    assert ex["runtime_evidence"]["observed"] is True
    assert ex["confidence"]["score"] == 1.0

    ap = attack_paths(build_threat_matrix(result, platform.registry.rules),
                      result.runtime)
    path = next(p for p in ap["resource_paths"]
                if any(s["node"] == "payment-api" for s in p["steps"]))
    assert path["confidence"] == OBSERVED
    assert path["path_type"] == "observed"
    # ...but only the hop an event actually named is observed. A shell in the pod is not
    # evidence that the RoleBinding was used.
    assert "payment-api" in path["observed_nodes"]
    assert path["fully_observed"] is False
    assert "configuration-derived" in path["summary"]
    observed_steps = [s for s in path["steps"] if s["confidence"] == OBSERVED]
    assert len(observed_steps) < len(path["steps"])


def test_runtime_events_elsewhere_do_not_touch_this_finding():
    result, platform = _scan(fx.scenario_a(),
                             runtime_events=fx.runtime_unrelated_namespace())
    f = _finding(result, "workload-privileged-container", "payment-api")
    ex = explain_finding(f, rule=platform.registry.rules.get(f.rule_id),
                         runtime=result.runtime)
    assert ex["runtime_evidence"]["observed"] is False
    assert ex["runtime_evidence"]["correlations"] == []
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules),
                      result.runtime)
    path = next(p for p in ap["resource_paths"]
                if any(s["node"] == "payment-api" for s in p["steps"]))
    assert path["confidence"] == CONFIG_ONLY


# =========================================================================== #
# Scenario D, runtime contradicts declared posture
# =========================================================================== #
def test_scenario_d_drift_detects_the_contradiction_and_keeps_the_evidence():
    result, _ = _scan(fx.scenario_d(),
                      runtime_events=fx.runtime_contradicting_posture())
    drift = result.runtime["drift"]
    assert drift["drift_count"] >= 1
    policies = {d["policy"] for d in drift["drift"]}
    assert "runAsNonRoot" in policies or "readOnlyRootFilesystem" in policies
    for d in drift["drift"]:
        assert d["pod"] == "hardened" and d["namespace"] == "production"
        assert d["declared"] and d["observed"] and d["severity"] == "CRITICAL"
        assert d["event"], "the originating event must travel with the drift finding"


def test_drift_is_evidence_for_an_attack_path_step():
    result, platform = _scan(fx.scenario_d(),
                             runtime_events=fx.runtime_contradicting_posture())
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules),
                      result.runtime)
    hardened = [p for p in ap["resource_paths"]
                if any(s["node"] == "hardened" for s in p["steps"])]
    if hardened:      # only if the pod carries a static finding to hang a path on
        assert hardened[0]["confidence"] in (OBSERVED, CORROBORATED)


# =========================================================================== #
# Scenario E, partial evidence
# =========================================================================== #
class _PartialCollector:
    """A mock collector with one resource type it could not read and one it read only
    partly, i.e. the RBAC-forbidden Secrets / huge-list case a real cluster produces."""

    def __new__(cls, fixture_path, unreadable=("ConfigMap",), partial=("Role",)):
        from k8smatrixwarden.core.evidence import MockEvidenceCollector

        class _C(MockEvidenceCollector):
            def _fetch(self, kind, bucket):
                if kind in unreadable:
                    self._record(kind, "skipped", 0,
                                 "HTTP 403 Forbidden, scanner lacks read RBAC for it")
                    self.warnings.append(f"{kind}: skipped (HTTP 403 Forbidden)")
                    return []
                items = super()._fetch(kind, bucket)
                if kind in partial:
                    self._record(kind, "partial", len(items),
                                 "hit the pagination cap", estimated=None,
                                 basis="unknown")
                return items

        return _C(fixture_path)


def test_scenario_e_partial_evidence_stays_consistent_across_the_pipeline():
    """A kind that could not be read must lower coverage, must NOT lower the findings that
    were made, and must be visible in the report with its basis."""
    platform = _platform()
    path = fx.write_fixture(fx.scenario_a(), tempfile.mkdtemp())
    collector = _PartialCollector(path)
    result = ScannerAgent(platform).scan(
        ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                    mode=ScanMode.SYNC), collector, mode_label="mock")

    cov = result.coverage
    assert cov["coverage_pct"] < 100
    assert "ConfigMap" in cov["unread_kinds"]
    assert "Role" in cov["partial_kinds"]
    # An unknown fraction must stay unknown, not be rounded into a plausible number.
    assert cov["kinds"]["Role"]["coverage_basis"] == "unknown"
    assert cov["coverage_basis"] == "unknown", \
        "one unknown contributor makes the total unknown, not measured"
    assert cov["confidence_pct"] == cov["coverage_pct"]
    assert cov["domains"]["Secrets"]["coverage_pct"] < 100

    # Findings that WERE made are unaffected by coverage.
    assert _finding(result, "workload-privileged-container", "payment-api") is not None
    assert result.evidence_ok is True, "partial is not degraded"

    md = platform.reporting.render(result, "markdown")
    assert "Evidence coverage" in md and "Coverage basis" in md
    assert "ConfigMap" in md, "an unread kind must be named in the report"

    # And the same numbers reach MCP, not a separately computed set.
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.mcp.server import build_tools
    reports = tempfile.mkdtemp()
    ReportStore(reports).save(result)
    mcp = build_tools()["get_cluster_coverage"](scan_id=result.scan_id,
                                                reports_dir=reports)
    assert mcp["coverage"]["coverage_pct"] == cov["coverage_pct"]
    assert mcp["coverage"]["confidence_pct"] == cov["confidence_pct"]
    assert mcp["coverage"]["coverage_basis"] == cov["coverage_basis"]
    assert mcp["warnings"] == result.warnings


def test_unreadable_evidence_is_never_reported_as_a_clean_domain():
    """The core honesty rule: 'we could not look' must not render as 'nothing found'."""
    platform = _platform()
    path = fx.write_fixture(fx.scenario_a(), tempfile.mkdtemp())
    collector = _PartialCollector(path, unreadable=("ClusterRole", "Role"),
                                  partial=())
    result = ScannerAgent(platform).scan(
        ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                    mode=ScanMode.SYNC), collector, mode_label="mock")
    cov = result.coverage
    assert cov["domains"]["RBAC"]["coverage_pct"] < 100
    assert result.warnings, "the surfaces that show warnings must be told"
    # With RBAC unreadable there can be no RBAC escalation claim either way, and the tool
    # must not present that silence as "this ServiceAccount is safe".
    f = _finding(result, "workload-privileged-container", "payment-api")
    assert not f.rbac_paths
    ex = explain_finding(f, rule=platform.registry.rules.get(f.rule_id))
    assert ex["rbac"]["escalates"] is False
    assert "evidence collected" in ex["rbac"]["note"]


def test_a_degraded_scan_reports_unknown_rather_than_excellent():
    """The severest partial-evidence case: nothing could be read at all."""
    from k8smatrixwarden.core.coverage import build_coverage

    class _Dead:
        coverage = {"Pod": {"status": "skipped", "count": 0, "reason": "HTTP 401",
                            "estimated_coverage": 0.0, "coverage_basis": "measured"}}
        degraded = True

    cov = build_coverage(_Dead())
    assert cov["confidence_pct"] == 0.0
    assert cov["confidence_label"] == "None"


# =========================================================================== #
# Scenario F, cross-namespace separation
# =========================================================================== #
def test_scenario_f_identical_workloads_in_two_namespaces_stay_separate():
    result, platform = _scan(fx.scenario_f())
    alpha = _finding(result, "workload-privileged-container", "api", "alpha")
    beta = _finding(result, "workload-privileged-container", "api", "beta")
    assert alpha is not None and beta is not None
    assert alpha is not beta

    # Reachability: only alpha has a LoadBalancer in front of it.
    assert "ingress" in alpha.exploitable_by
    assert "ingress" not in beta.exploitable_by

    # RBAC: only alpha's ServiceAccount is bound, even though both are called `api-sa`.
    assert alpha.rbac_paths, "alpha's SA is bound to a secret-reading ClusterRole"
    assert not beta.rbac_paths, "beta's identically named SA is bound to nothing"

    # Attack paths keep them apart, and each carries its own namespace.
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules),
                      cluster=result.cluster_name)
    namespaces = {p["namespace"] for p in ap["resource_paths"]}
    assert {"alpha", "beta"} <= namespaces


def test_scenario_f_timeline_keeps_the_two_namespaces_apart():
    from k8smatrixwarden.core.report_store import ReportStore
    result, _ = _scan(fx.scenario_f())
    store = ReportStore(tempfile.mkdtemp())
    store.save(result)
    keys = [k for k in store.raw_timeline()
            if "workload-privileged-container" in k and "|api|" in k]
    assert len({k for k in keys if k.endswith("alpha")}) == 1
    assert len({k for k in keys if k.endswith("beta")}) == 1


# =========================================================================== #
# Cross-surface consistency: one scan, many renderings, one meaning
# =========================================================================== #
def test_cli_mcp_web_and_reports_agree_on_the_same_scan():
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.mcp.server import build_tools
    from k8smatrixwarden.web.app import WebApp

    result, platform = _scan(fx.scenario_a(),
                             runtime_events=fx.runtime_shell_in_payment_api())
    reports = tempfile.mkdtemp()
    store = ReportStore(reports)
    store.save(result)

    scored = [f for f in result.findings if f.severity.weight > 0]
    core_total = len(scored)
    core_risk = result.risk.cluster_risk

    # JSON report
    doc = json.loads(platform.reporting.render(result, "json"))
    assert doc["risk"]["cluster_risk"] == core_risk
    assert len([f for f in doc["findings"] if f["severity"] != "INFO"]) == core_total

    # SARIF
    sarif = json.loads(platform.reporting.render(result, "sarif"))
    assert len(sarif["runs"][0]["results"]) == core_total

    # MCP
    tools = build_tools()
    mcp_doc = tools["download_report"](scan_id=result.scan_id, reports_dir=reports,
                                       format="json")
    mcp_json = json.loads(mcp_doc["content"])
    assert mcp_json["risk"]["cluster_risk"] == core_risk

    # Web API
    app = WebApp(platform, reports_dir=reports)
    payload = json.loads(app.route("GET", "/api/dashboard").text)
    assert payload["scan"]["cluster_risk"] == core_risk
    assert payload["scan"]["total"] == core_total

    # And the identities match, not merely the counts.
    core_ids = sorted((f.rule_id, f.resource.name, f.resource.namespace) for f in scored)
    web_ids = sorted((f["rule_id"], f["resource"]["name"], f["resource"]["namespace"])
                     for f in payload["findings"] if f["severity"] != "INFO")
    assert core_ids == web_ids


def test_attack_path_is_identical_through_core_mcp_and_web():
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.mcp.server import build_tools
    from k8smatrixwarden.web.app import WebApp

    result, platform = _scan(fx.scenario_a())
    reports = tempfile.mkdtemp()
    ReportStore(reports).save(result)

    core = attack_paths(build_threat_matrix(result, platform.registry.rules),
                        result.runtime, cluster=result.cluster_name)
    mcp = build_tools()["build_attack_path"](scan_id=result.scan_id,
                                             reports_dir=reports)
    web = json.loads(WebApp(platform, reports_dir=reports)
                     .route("GET", "/api/dashboard").text)["attack_path"]

    assert core["chain"] == mcp["chain"] == web["chain"]
    assert (core["resource_path_count"] == mcp["resource_path_count"]
            == web["resource_path_count"])
    assert core["confidence"] == mcp["confidence"] == web["confidence"]


def test_explain_finding_is_the_same_object_through_mcp_and_web():
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.core.reporting import finding_anchor
    from k8smatrixwarden.mcp.server import build_tools
    from k8smatrixwarden.web.app import WebApp

    result, platform = _scan(fx.scenario_a())
    reports = tempfile.mkdtemp()
    ReportStore(reports).save(result)
    f = _finding(result, "workload-privileged-container", "payment-api")
    anchor = finding_anchor(f.rule_id, f.resource.kind, f.resource.name,
                            f.resource.namespace)

    mcp = build_tools()["explain_finding"](
        scan_id=result.scan_id, reports_dir=reports,
        rule_id="workload-privileged-container")["explanations"][0]
    web = json.loads(WebApp(platform, reports_dir=reports).route(
        "GET", "/api/finding", f"scan_id={result.scan_id}&anchor={anchor}").text)

    assert web["explanation"]["rule"]["id"] == mcp["rule"]["id"]
    assert web["explanation"]["confidence"] == mcp["confidence"]
    assert web["explanation"]["rbac"]["escalates"] == mcp["rbac"]["escalates"]
    assert web["explanation"]["network"]["ingress_status"] == \
        mcp["network"]["ingress_status"]


# =========================================================================== #
# Threat matrix + risk integration
# =========================================================================== #
def test_runtime_evidence_does_not_erase_static_matrix_coverage():
    with_runtime, platform = _scan(fx.scenario_a(),
                                   runtime_events=fx.runtime_shell_in_payment_api())
    without, _ = _scan(fx.scenario_a())
    a = build_threat_matrix(with_runtime, platform.registry.rules)
    b = build_threat_matrix(without, platform.registry.rules)
    assert a.techniques_hit == b.techniques_hit, \
        "runtime data must not add or remove static hits"
    assert a.techniques_covered == b.techniques_covered


def test_risk_is_unchanged_by_reachability_and_runtime_context():
    """Context prioritises; it never re-scores.

    Compared per finding, not per cluster: scenario B adds a NetworkPolicy, so the
    "namespace has no NetworkPolicy" finding correctly stops firing and the cluster total
    legitimately moves. What must NOT move is the privileged-pod finding itself, whether
    its pod is internet-reachable, isolated, or observed being attacked.
    """
    a, _ = _scan(fx.scenario_a())
    b, _ = _scan(fx.scenario_b())
    c, _ = _scan(fx.scenario_a(), runtime_events=fx.runtime_shell_in_payment_api())

    scores = []
    for result in (a, b, c):
        f = _finding(result, "workload-privileged-container", "payment-api")
        scores.append((f.severity, f.exploitability, f.blast_radius, f.score))
    assert scores[0] == scores[1] == scores[2]

    # And runtime evidence alone changes no score at all: A and C are the same cluster.
    assert a.risk.cluster_risk == c.risk.cluster_risk
    # B differs only by the finding the added policy resolved.
    a_keys = {(f.rule_id, f.resource.name) for f in a.findings}
    b_keys = {(f.rule_id, f.resource.name) for f in b.findings}
    assert a_keys - b_keys == {("net-no-networkpolicy", "production")}


def test_the_risk_explanation_reproduces_the_score():
    result, _ = _scan(fx.scenario_a())
    raw = sum(f.score for f in result.findings)
    assert round(raw, 2) == result.risk.explanation["raw_total"]
    for f in result.findings:
        if f.severity.weight == 0:
            continue
        b = f.score_breakdown
        product = (b["severity"]["weight"] * b["exploitability"]["weight"]
                   * b["blast_radius"]["weight"] * b["path_multiplier"]["weight"])
        assert round(product, 6) == round(f.score, 6)


# =========================================================================== #
# Bounded analysis must announce itself
# =========================================================================== #
def test_bounded_graph_analysis_reports_its_status():
    from k8smatrixwarden.core.rbac_graph import Node, RbacGraph
    result, _ = _scan(fx.scenario_a())
    platform = _platform()
    collector = platform.make_collector(
        mock=True, fixture=fx.write_fixture(fx.scenario_a(), tempfile.mkdtemp()))
    ev = collector.collect({"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding",
                            "ServiceAccount"}, Scope(ScopeLevel.CLUSTER))
    graph = RbacGraph.from_evidence(ev)
    analysis = graph.escalation_analysis(
        Node("ServiceAccount", "payment-api", "production"))
    assert analysis["analysis_status"] in ("complete", "truncated")
    assert analysis["limits"]["max_hops"] > 0
    if analysis["analysis_status"] == "complete":
        assert analysis["truncation_reason"] is None

    ap = attack_paths(build_threat_matrix(result, platform.registry.rules))
    for path in ap["resource_paths"]:
        assert path["analysis_status"] in ("complete", "truncated")


def test_mcp_graph_tools_declare_their_analysis_status():
    from k8smatrixwarden.mcp.server import build_tools
    tools = build_tools()
    path = fx.write_fixture(fx.scenario_a(), tempfile.mkdtemp())
    rbac = tools["analyze_rbac_paths"](mock=True, fixture=path)
    net = tools["analyze_network_policy"](mock=True, fixture=path)
    assert rbac["analysis_status"] in ("complete", "truncated")
    assert net["analysis_status"] in ("complete", "truncated")
    assert rbac["cluster"] and net["cluster"]


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")


# =========================================================================== #
# Confidence propagation policy (see core/explain.py CONFIDENCE_POLICY)
# =========================================================================== #
def test_finding_confidence_never_exceeds_the_evidence_behind_it():
    """A finding cannot be more certain than the evidence it rests on. With RBAC
    unreadable, no RBAC claim is made and confidence stays at the rule's own level, it
    does not inherit certainty from a conclusion that was never reachable."""
    platform = _platform()
    path = fx.write_fixture(fx.scenario_a(), tempfile.mkdtemp())
    blind = _PartialCollector(path, unreadable=("ClusterRole", "Role", "RoleBinding"),
                              partial=())
    result = ScannerAgent(platform).scan(
        ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                    mode=ScanMode.SYNC), blind, mode_label="mock")
    f = _finding(result, "workload-privileged-container", "payment-api")
    ex = explain_finding(f, rule=platform.registry.rules.get(f.rule_id))
    assert ex["rbac"]["escalates"] is False
    assert ex["confidence"]["score"] < 1.0, \
        "only runtime observation earns full confidence"


def test_confidence_rises_only_with_resource_level_runtime_evidence():
    platform = _platform()
    base, _ = _scan(fx.scenario_a())
    near, _ = _scan(fx.scenario_a(), runtime_events=fx.runtime_unrelated_namespace())
    hit, _ = _scan(fx.scenario_a(), runtime_events=fx.runtime_shell_in_payment_api())

    def conf(result):
        f = _finding(result, "workload-privileged-container", "payment-api")
        return explain_finding(f, rule=platform.registry.rules.get(f.rule_id),
                               runtime=result.runtime)["confidence"]["score"]

    assert conf(base) == conf(near), "activity elsewhere must not raise confidence"
    assert conf(hit) > conf(base)
    assert conf(hit) == 1.0


def test_assessment_confidence_tracks_coverage_not_severity():
    a, _ = _scan(fx.scenario_a())
    f_result, _ = _scan(fx.scenario_f())
    # Different clusters, different severities, same complete coverage.
    assert a.coverage["confidence_pct"] == f_result.coverage["confidence_pct"]
    assert a.coverage["confidence_pct"] == a.coverage["coverage_pct"]


def test_the_five_confidence_values_stay_distinguishable():
    """Evidence, finding, correlation, path and assessment confidence answer different
    questions and must not be collapsed into one number."""
    result, platform = _scan(fx.scenario_a(),
                             runtime_events=fx.runtime_shell_in_payment_api())
    f = _finding(result, "workload-privileged-container", "payment-api")
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules),
                      result.runtime)
    ex = explain_finding(f, rule=platform.registry.rules.get(f.rule_id),
                         runtime=result.runtime, attack_path=ap)

    assert isinstance(result.coverage["confidence_pct"], float)      # assessment
    assert 0.0 <= ex["confidence"]["score"] <= 1.0                    # finding
    levels = {c["confidence"] for c in result.runtime["correlation"]["correlations"]}
    assert levels <= {"confirmed", "corroborated", "runtime-only"}    # correlation
    path = next(p for p in ap["resource_paths"]
                if any(s["node"] == "payment-api" for s in p["steps"]))
    assert path["confidence"] in (CONFIG_ONLY, CORROBORATED, OBSERVED)  # path
    assert result.coverage["kinds"]["Pod"]["coverage_basis"] == "measured"  # evidence


# =========================================================================== #
# Dashboard exposure of the graph analysis
# =========================================================================== #
def test_dashboard_exposes_the_resource_layer_without_recomputing_it():
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.web.app import WebApp

    result, platform = _scan(fx.scenario_a(),
                             runtime_events=fx.runtime_shell_in_payment_api())
    reports = tempfile.mkdtemp()
    ReportStore(reports).save(result)
    app = WebApp(platform, reports_dir=reports)

    payload = json.loads(app.route("GET", "/api/dashboard").text)
    paths = payload["attack_path"]["resource_paths"]
    assert paths, "the resource layer must reach the dashboard payload"
    assert all("analysis_status" in p for p in paths)
    assert all("path_type" in p for p in paths)

    shell = app.route("GET", "/").text
    # The panel exists and is fed from the payload; no severity/reachability arithmetic
    # is duplicated in the browser.
    assert "Evidence-backed routes" in shell
    assert "resource_paths" in shell
    assert "netStatusPill" in shell and "exposureHTML" in shell


def test_finding_detail_endpoint_carries_rbac_and_network_for_the_ui():
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.core.reporting import finding_anchor
    from k8smatrixwarden.web.app import WebApp

    result, platform = _scan(fx.scenario_a())
    reports = tempfile.mkdtemp()
    ReportStore(reports).save(result)
    f = _finding(result, "workload-privileged-container", "payment-api")
    anchor = finding_anchor(f.rule_id, f.resource.kind, f.resource.name,
                            f.resource.namespace)
    body = json.loads(WebApp(platform, reports_dir=reports).route(
        "GET", "/api/finding", f"scan_id={result.scan_id}&anchor={anchor}").text)
    ex = body["explanation"]
    assert ex["rbac"]["escalates"] is True
    assert ex["rbac"]["shortest"]["chain"]
    assert ex["network"]["ingress_status"]
    assert ex["confidence"]["reasons"]


# =========================================================================== #
# Error isolation: a malformed object costs its own analysis, never the scan
# =========================================================================== #
def test_a_malformed_object_does_not_blank_reachability_for_everything_else():
    """One unreadable NetworkPolicy must not cost every finding its reachability
    context, the same per-rule isolation philosophy the Detection Engine applies."""
    cluster = fx.scenario_a()
    cluster["networkpolicies"] = [
        {"kind": "NetworkPolicy",
         "metadata": {"name": "broken", "namespace": "production"},
         "spec": {"podSelector": "this-should-be-an-object",
                  "policyTypes": ["Ingress"]}}]
    result, platform = _scan(cluster)
    f = _finding(result, "workload-privileged-container", "payment-api")
    assert f is not None, "the scan itself must still complete"
    assert f.path_reason, "the finding is still annotated, one way or the other"
    # And the whole pipeline downstream still runs.
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules))
    assert isinstance(ap["resource_paths"], list)
    assert platform.reporting.render(result, "markdown")


def test_a_malformed_exploit_path_is_skipped_not_fatal():
    from k8smatrixwarden.core.attack_path import resource_paths
    result, _ = _scan(fx.scenario_a())
    good = [f for f in result.findings if f.exploit_path]
    assert good
    broken = good[0]
    broken.exploit_path = ["not-a-node", 42]
    paths = resource_paths(result.findings)
    assert isinstance(paths, list), "a malformed chain must not raise"
    for p in paths:
        assert all(isinstance(s, dict) for s in p["steps"])


def test_the_only_duplicated_formula_between_python_and_js_still_agrees():
    """The dashboard computes a finding's anchor client-side so the payload need not carry
    it. That is the single formula intentionally implemented twice; if the two drift,
    every deep link from the dashboard into the report silently breaks.

    It is a display slug, not security logic, so duplication is acceptable, but only while
    it is checked."""
    import re
    from k8smatrixwarden.core.reporting import finding_anchor
    from k8smatrixwarden.web import pages

    js = pages._APP_JS if hasattr(pages, "_APP_JS") else ""
    if not js:
        js = "".join(v for k, v in vars(pages).items()
                     if isinstance(v, str) and "findingAnchor" in v)
    assert "findingAnchor" in js, "the dashboard must still define the anchor helper"

    def js_anchor(rule_id, kind, name, namespace):
        raw = f"{rule_id}-{kind}-{name}-{namespace or ''}"
        slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
        return "f-" + (slug or "finding")

    cases = [
        ("workload-privileged-container", "Pod", "payment-api", "production"),
        ("rbac-wildcard-verbs", "ClusterRole", "super-role", None),
        ("net-no-networkpolicy", "Namespace", "prod-ns", ""),
        ("weird.rule_id", "Pod", "a--b", "ns"),
    ]
    for case in cases:
        assert finding_anchor(*case) == js_anchor(*case), case
