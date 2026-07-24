"""Multi-cluster federation blast radius, cluster_name plumbing + shared-identity join."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Severity, Tactic,
                                         Scope, ScopeLevel, ScanRequest, Selector, ScanMode)
from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.federation import build_federation, latest_per_cluster
from k8smatrixwarden.core import federation_report as fr


def _scan(label):
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                             mode=ScanMode.SYNC), p.make_collector(mock=True), mode_label="mock")
    r.cluster_name = label
    return r


def _f(kind, name, sev=Severity.HIGH, tactic=Tactic.PRIVILEGE_ESCALATION, ns=""):
    return Finding(rule_id="r", title=f"{kind}/{name}", severity=sev,
                   resource=ResourceRef(kind, name, ns), message="",
                   mitre=[MitreTag(tactic, "T1", "t")])


# ---- cluster_name plumbing ---------------------------------------------- #
def test_mock_scan_records_mock_cluster():
    assert _scan("x").cluster_name == "x"


def test_scanner_defaults_cluster_from_collector_label():
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                             mode=ScanMode.SYNC), p.make_collector(mock=True), mode_label="mock")
    assert r.cluster_name == "mock-cluster"


def test_store_list_surfaces_cluster():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scan("prod-eks"))
    assert store.list()[0].cluster == "prod-eks"


# ---- shared-identity detection ------------------------------------------ #
def _cluster_result(label, findings):
    r = _scan(label)
    r.findings = findings
    return r


def test_shared_identity_links_two_clusters():
    a = _cluster_result("a", [_f("ClusterRole", "super-role", Severity.CRITICAL)])
    b = _cluster_result("b", [_f("ClusterRole", "super-role", Severity.CRITICAL)])
    rep = build_federation([a, b])
    assert len(rep.shared_identities) == 1
    s = rep.shared_identities[0]
    assert s.key == "ClusterRole/super-role"
    assert sorted(s.clusters) == ["a", "b"]
    assert s.worst_severity == "CRITICAL"


def test_identity_in_only_one_cluster_is_not_a_path():
    a = _cluster_result("a", [_f("ClusterRole", "only-here")])
    b = _cluster_result("b", [_f("ClusterRole", "different")])
    assert build_federation([a, b]).shared_identities == []


def test_non_identity_kinds_are_ignored():
    # a Pod of the same name in two clusters is noise, not a shared trust relationship.
    a = _cluster_result("a", [_f("Pod", "nginx")])
    b = _cluster_result("b", [_f("Pod", "nginx")])
    assert build_federation([a, b]).shared_identities == []


def test_builtin_default_identities_are_not_shared_paths():
    # cluster-admin / system:* / default SA exist in every cluster by design, excluding them
    # is what stops the federation view manufacturing false cross-cluster edges.
    for kind, name in [("ClusterRole", "cluster-admin"), ("ClusterRole", "system:node"),
                       ("ServiceAccount", "default"), ("ConfigMap", "kube-root-ca.crt")]:
        a = _cluster_result("a", [_f(kind, name, Severity.CRITICAL)])
        b = _cluster_result("b", [_f(kind, name, Severity.CRITICAL)])
        assert build_federation([a, b]).shared_identities == [], f"{kind}/{name} leaked"


def test_custom_role_of_same_name_is_still_a_candidate():
    a = _cluster_result("a", [_f("ClusterRole", "super-role", Severity.CRITICAL)])
    b = _cluster_result("b", [_f("ClusterRole", "super-role", Severity.CRITICAL)])
    assert len(build_federation([a, b]).shared_identities) == 1


def test_cloud_iam_role_is_a_cross_cluster_path():
    a = _cluster_result("a", [_f("CloudIAM", "shared-sa")])
    b = _cluster_result("b", [_f("CloudIAM", "shared-sa")])
    assert build_federation([a, b]).shared_identities[0].kind == "CloudIAM"


def test_info_findings_do_not_create_paths():
    a = _cluster_result("a", [_f("ClusterRole", "x", Severity.INFO)])
    b = _cluster_result("b", [_f("ClusterRole", "x", Severity.INFO)])
    assert build_federation([a, b]).shared_identities == []


# ---- honesty about connection ------------------------------------------- #
def test_single_cluster_is_not_a_federation():
    rep = build_federation([_cluster_result("solo", [_f("ClusterRole", "x")])])
    assert rep.shared_identities == []
    assert "add more clusters" in rep.summary.lower()


def test_unlinked_clusters_reported_independent_not_assumed():
    a = _cluster_result("a", [_f("ClusterRole", "a-role")])
    b = _cluster_result("b", [_f("ClusterRole", "b-role")])
    rep = build_federation([a, b])
    assert not rep.shared_identities
    assert "independent" in rep.summary.lower()


def test_federated_tactics_aggregate_across_clusters():
    a = _cluster_result("a", [_f("ClusterRole", "x", tactic=Tactic.PRIVILEGE_ESCALATION)])
    b = _cluster_result("b", [_f("ClusterRole", "x", tactic=Tactic.PRIVILEGE_ESCALATION)])
    rep = build_federation([a, b])
    assert rep.top_tactic == "Privilege Escalation"
    assert rep.federated_tactics["Privilege Escalation"] == 2


# ---- store facade + renderers ------------------------------------------- #
def test_latest_per_cluster_dedups_repeat_scans():
    d = tempfile.mkdtemp()
    store = ReportStore(d)
    store.save(_scan("prod"))
    store.save(_scan("prod"))       # rescan same cluster
    store.save(_scan("staging"))
    results = latest_per_cluster(store)
    assert sorted(r.cluster_name for r in results) == ["prod", "staging"]


def test_renderers_round_trip():
    a = _cluster_result("a", [_f("ClusterRole", "super-role", Severity.CRITICAL)])
    b = _cluster_result("b", [_f("ClusterRole", "super-role", Severity.CRITICAL)])
    rep = build_federation([a, b])
    md = fr.to_markdown(rep)
    assert "Federation Blast Radius" in md and "super-role" in md
    html = fr.to_html(rep)
    assert "<!doctype html>" in html.lower()
    assert "<!doctype" not in fr.to_html(rep, standalone=False).lower()
