"""
Cluster identity: when are two scans the same cluster, and when is an edge between them
evidence of anything?

Written from a live audit of an operator's real report store, which held a laptop cluster
(`docker-desktop`), an EKS cluster, and the bundled fixture. The federation view drew seven
cross-cluster blast-radius edges. Four of them were between the SAME fixture recorded under
two labels, one joined two clusters on `ConfigMap/kube-proxy` (which Kubernetes ships in
every cluster), and one joined them on `CloudIAM/?` -- where `?` is the placeholder a rule
emits when it cannot name the principal at all.

None of those were joins on evidence. They were joins on coincidence, on a Kubernetes
default, and on a shared inability to identify something. The distinctions this file pins
down are:

    administrative visibility   both clusters happen to be reachable from this machine
    name collision              both clusters contain a thing with the same name
    shared principal            the same identity really does govern both  <- the claim
    proven lateral movement     runtime evidence of it being used          <- `confirmed`

Only the third and fourth justify calling two clusters one blast radius.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.evidence import EvidenceCollector
from k8smatrixwarden.core.federation import (build_federation, cluster_identity_verified,
                                             identity_key, _is_builtin_identity,
                                             _is_unidentified)
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, ScanRequest,
                                         Scope, ScopeLevel, Selector, Severity, Tactic)
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.results import ScanResult
from k8smatrixwarden.core.scoring import RiskResult


def _finding(kind, name, namespace=None, rule="rbac-wildcard-verbs",
             severity=Severity.CRITICAL, tactic=Tactic.PRIVILEGE_ESCALATION):
    return Finding(rule_id=rule, title=f"{kind} {name}", severity=severity,
                   resource=ResourceRef(kind=kind, name=name, namespace=namespace),
                   message="m", owning_shard="rbac_identity",
                   mitre=[MitreTag(tactic, "T1078", "Valid Accounts")])


def _result(cluster, findings, scope=None):
    request = ScanRequest(scope=scope or Scope(level=ScopeLevel.CLUSTER),
                          selector=Selector())
    return ScanResult(
        request=request, findings=findings,
        risk=RiskResult(cluster_risk=9.0, security_score=10, rating="Critical",
                        rating_emoji="!", raw=9.0),
        warnings=[], evidence_ok=True,
        resolved_rule_ids=sorted({f.rule_id for f in findings}), failed_rule_ids=[],
        counts={f.severity.label: 1 for f in findings},
        workload_issues=[], aggregation={}, by_tactic={}, by_shard={},
        name="", cluster_name=cluster, mode="live", inventory={}, coverage={})


def _edges(*results):
    return build_federation(list(results)).shared_identities


def _keys(*results):
    return {s.key for s in _edges(*results)}


# --------------------------------------------------------------------------- #
# Phase 5.7 Case 1 + 4 -- independent clusters, colliding names
# --------------------------------------------------------------------------- #

def test_two_independent_clusters_share_no_edge():
    """Case 1. Nothing in common means nothing to draw."""
    a = _result("cluster-a", [_finding("ClusterRole", "team-a-deployer")])
    b = _result("cluster-b", [_finding("ClusterRole", "team-b-deployer")])
    assert _edges(a, b) == []


def test_a_kubernetes_shipped_object_is_never_a_cross_cluster_path():
    """Case 4, and the LIVE false positive. `ConfigMap/kube-proxy` linked an operator's
    laptop cluster to an unrelated EKS cluster. Every cluster has it."""
    for kind, name, namespace in (("ConfigMap", "kube-proxy", "kube-system"),
                                  ("ConfigMap", "kubelet-config", "kube-system"),
                                  ("ConfigMap", "cluster-info", "kube-public"),
                                  ("ConfigMap", "aws-auth", "kube-system"),
                                  ("ClusterRole", "system:node", None),
                                  ("ClusterRole", "kubeadm:get-nodes", None),
                                  ("ServiceAccount", "default", "default"),
                                  ("ClusterRole", "cluster-admin", None)):
        a = _result("cluster-a", [_finding(kind, name, namespace)])
        b = _result("cluster-b", [_finding(kind, name, namespace)])
        assert _edges(a, b) == [], (
            f"{kind}/{name} drew a cross-cluster edge; it exists in every cluster by "
            f"design, so the collision proves only that both run Kubernetes")


def test_anything_in_a_control_plane_namespace_is_excluded():
    """A name we have never heard of is still not operator-authored if it lives there."""
    for namespace in ("kube-system", "kube-public", "kube-node-lease"):
        a = _result("cluster-a", [_finding("Secret", "some-provider-token", namespace)])
        b = _result("cluster-b", [_finding("Secret", "some-provider-token", namespace)])
        assert _edges(a, b) == [], f"{namespace} contents joined two clusters"


# --------------------------------------------------------------------------- #
# An unidentified thing is not a shared identity
# --------------------------------------------------------------------------- #

def test_two_unidentified_principals_are_not_one_principal():
    """The LIVE false positive `CloudIAM/?`. `?` is cloud_iam.py's fallback for a missing
    serviceAccount field, so this edge said: both clusters contain something we could not
    identify, therefore it is the same thing."""
    for placeholder in ("?", "", "  ", "unknown", "n/a", "none", "<unknown>"):
        a = _result("cluster-a", [_finding("CloudIAM", placeholder)])
        b = _result("cluster-b", [_finding("CloudIAM", placeholder)])
        assert _edges(a, b) == [], (
            f"an identity named {placeholder!r} linked two clusters; UNKNOWN must not be "
            f"promoted to a claim")


def test_the_unidentified_predicate_is_not_over_broad():
    """It must not eat real names that merely contain a question mark or the word none."""
    assert not _is_unidentified("nonexistent-role")
    assert not _is_unidentified("unknown-team-sa")
    assert _is_unidentified("?")
    assert _is_unidentified("UNKNOWN")


# --------------------------------------------------------------------------- #
# Namespaced identity
# --------------------------------------------------------------------------- #

def test_the_same_role_name_in_different_namespaces_is_two_grants():
    """`secret-reader` in team-a and in team-b share a word, not a principal."""
    a = _result("cluster-a", [_finding("Role", "secret-reader", "team-a")])
    b = _result("cluster-b", [_finding("Role", "secret-reader", "team-b")])
    assert _edges(a, b) == [], "a Role name was joined across different namespaces"


def test_the_same_role_in_the_same_namespace_is_a_candidate():
    """The surviving live edge: both clusters run the same chart, so the Role really is
    identically named and placed. A lead to verify -- and only a lead."""
    a = _result("cluster-a", [_finding("Role", "secret-reader", "big-monolith")])
    b = _result("cluster-b", [_finding("Role", "secret-reader", "big-monolith")])
    found = _edges(a, b)
    assert len(found) == 1, found
    assert found[0].status == "candidate", "a name collision is not proof of a shared trust"
    assert found[0].namespace == "big-monolith", "the namespace is part of the identity"


def test_cluster_scoped_kinds_join_on_name_alone():
    """A ClusterRole has no namespace; requiring one would drop every real edge."""
    assert identity_key("ClusterRole", "binder") == "ClusterRole/binder"
    assert identity_key("Role", "r", "ns") == "Role/ns/r"
    # A namespaced kind with no namespace recorded still joins, rather than vanishing.
    assert identity_key("Role", "r") == "Role/r"


# --------------------------------------------------------------------------- #
# Phase 5.7 Case 2 + 3 -- shared kubeconfig, shared workstation
# --------------------------------------------------------------------------- #

def test_reachability_from_one_machine_is_not_a_trust_relationship():
    """Cases 2 and 3. Both clusters are in one kubeconfig and scanned from one laptop.
    Federation input is saved ScanResults, so it cannot even see the kubeconfig -- this
    asserts that the absence stays an absence and nothing infers a link from co-location."""
    a = _result("docker-desktop", [_finding("ClusterRole", "laptop-only-role")])
    b = _result("arn:aws:eks:us-east-1:1234:cluster/prod",
                [_finding("ClusterRole", "eks-only-role")])
    report = build_federation([a, b])
    assert report.shared_identities == []
    assert "independent blast radi" in report.summary, report.summary


# --------------------------------------------------------------------------- #
# Phase 5.7 Case 5 + 6 -- a real shared principal
# --------------------------------------------------------------------------- #

def test_a_genuinely_shared_identity_is_reported_as_a_candidate_with_a_reason():
    """Case 5/6. The fix must not have deleted the capability it exists for."""
    shared = _finding("CloudIAM", "arn:aws:iam::1234:role/shared-ci-deployer")
    a = _result("cluster-a", [shared])
    b = _result("cluster-b", [shared])
    found = _edges(a, b)
    assert len(found) == 1, "a genuine cross-cluster identity was dropped"
    assert found[0].status == "candidate"
    assert found[0].cluster_identity_verified is True
    assert "same kind+name" in found[0].verification


def test_a_shared_identity_across_three_clusters_still_reports_every_cluster():
    shared = _finding("ClusterRole", "org-wide-deployer")
    found = _edges(_result("a", [shared]), _result("b", [shared]), _result("c", [shared]))
    assert len(found) == 1
    assert found[0].clusters == ["a", "b", "c"]


# --------------------------------------------------------------------------- #
# Unverified cluster identity
# --------------------------------------------------------------------------- #

def test_the_base_collector_label_is_not_a_cluster_identity():
    """It is the absence of one. The live store had four edges between the same fixture
    under two labels, because this string was doing duty as a name."""
    assert EvidenceCollector().cluster_label() == EvidenceCollector.UNVERIFIED_LABEL
    assert not cluster_identity_verified(EvidenceCollector.UNVERIFIED_LABEL)
    for placeholder in ("", "target-cluster", "live-cluster", "unknown",
                        "unidentified-cluster"):
        assert not cluster_identity_verified(placeholder), placeholder
    for real in ("docker-desktop", "arn:aws:eks:us-east-1:1234:cluster/prod", "minikube"):
        assert cluster_identity_verified(real), real


def test_a_fixture_scan_is_not_a_cross_cluster_peer():
    """REGRESSION. The bundled fixture saves under `mock-cluster`, which looks like a
    perfectly good cluster name and is not one -- it is sample data. It deliberately
    contains `super-role`, `default-admin` and friends, so a real cluster using any of
    those names was handed a cross-cluster blast-radius edge to a file on disk."""
    shared = _finding("ClusterRole", "shared-deployer")
    fixture = _result("mock-cluster", [shared])
    fixture.mode = "mock"
    live = _result("docker-desktop", [shared])
    live.mode = "live"
    found = build_federation([fixture, live]).shared_identities
    assert len(found) == 1, "the edge was suppressed rather than qualified"
    assert found[0].cluster_identity_verified is False, (
        "a fixture scan was treated as an observed cluster")
    assert "fixture/mock scan" in found[0].verification


def test_two_live_clusters_sharing_an_identity_stay_verified():
    """The fix must not disqualify the case federation exists for."""
    shared = _finding("ClusterRole", "shared-deployer")
    a, b = _result("cluster-a", [shared]), _result("cluster-b", [shared])
    a.mode = b.mode = "live"
    found = build_federation([a, b]).shared_identities
    assert found and found[0].cluster_identity_verified is True


def test_the_verification_predicate_reads_both_the_label_and_the_mode():
    assert cluster_identity_verified("docker-desktop", "live") is True
    assert cluster_identity_verified("docker-desktop", "mock") is False
    assert cluster_identity_verified("mock-cluster", "mock") is False
    assert cluster_identity_verified("target-cluster", "live") is False


def test_an_edge_resting_on_a_placeholder_is_marked_unverified():
    """Not suppressed -- suppressing a cluster would hide real findings -- but never
    presentable as a path between two known clusters."""
    shared = _finding("ClusterRole", "super-role")
    found = _edges(_result("mock-cluster", [shared]), _result("target-cluster", [shared]))
    assert len(found) == 1, "the edge was suppressed rather than qualified"
    assert found[0].cluster_identity_verified is False
    assert "not an observed cluster" in found[0].verification
    assert found[0].status == "candidate"


def test_an_unverified_edge_can_never_be_confirmed():
    """Runtime evidence cannot prove activity in a cluster that was never identified."""
    shared = _finding("ClusterRole", "super-role")
    a, b = _result("target-cluster", [shared]), _result("live-cluster", [shared])
    for result in (a, b):
        result.runtime = {"correlation": {"correlations": [
            {"confidence": "confirmed", "resource": "super-role"}]}}
    found = _edges(a, b)
    assert found and found[0].status == "candidate", \
        "an unidentified cluster was upgraded to confirmed on runtime evidence"


# --------------------------------------------------------------------------- #
# Phase 4 -- posture history isolation
# --------------------------------------------------------------------------- #

def _store(tmp):
    return ReportStore(tmp)


def test_posture_scope_keys_separate_clusters():
    """Two clusters never share a history bucket, whatever they name their resources."""
    assert (ReportStore.scope_key_of("cluster-a", "cluster-wide")
            != ReportStore.scope_key_of("cluster-b", "cluster-wide"))


def test_posture_scope_keys_separate_scopes_within_one_cluster():
    """A namespace scan must not 'resolve' everything a cluster scan found."""
    assert (ReportStore.scope_key_of("a", "cluster-wide")
            != ReportStore.scope_key_of("a", "namespace/production"))


def test_an_unknown_cluster_does_not_inherit_the_base_bucket():
    """REGRESSION. An empty cluster was coerced to `target-cluster`, so a scan whose
    identity was never established silently inherited that bucket's history and could
    report its findings resolved -- a false green produced by a default value."""
    unknown = ReportStore.scope_key_of("", "cluster-wide")
    assert unknown != ReportStore.scope_key_of("target-cluster", "cluster-wide")
    assert "unidentified" in unknown, unknown


def test_same_cluster_same_finding_is_persistent_and_cross_cluster_is_independent():
    """Phase 4.4 cases 1 and 5/6, on the real comparison function."""
    import tempfile

    from k8smatrixwarden.core.posture import compare
    finding = _finding("ClusterRole", "super-role")
    a1, a2 = _result("cluster-a", [finding]), _result("cluster-a", [finding])
    same = compare(a1, a2)
    assert len(same["persistent"]) == 1, same["persistent"]
    assert same["new"] == [] and same["resolved"] == []

    # Different cluster, byte-identical finding: nothing may be called resolved or new by
    # comparing them, which is why latest_change never selects across clusters.
    b1 = _result("cluster-b", [finding])
    assert (ReportStore.scope_key(a1) != ReportStore.scope_key(b1)), \
        "two clusters resolved to one history scope"
    del tempfile


def test_a_finding_whose_rule_did_not_rerun_is_never_resolved():
    """Phase 4.4: the false-green guard, asserted on the real diff."""
    from k8smatrixwarden.core.posture import compare
    previous = _result("cluster-a", [_finding("ClusterRole", "super-role",
                                              rule="rbac-wildcard-verbs")])
    # A narrower scan that never ran that rule.
    current = _result("cluster-a", [])
    current.resolved_rule_ids = ["some-other-rule"]
    found = compare(previous, current)
    assert found["resolved"] == [], "a rule that never ran resolved a finding"
    assert len(found["not_rescanned"]) == 1, found["not_rescanned"]


if __name__ == "__main__":
    import traceback
    failed = 0
    for key, fn in sorted(globals().items()):
        if key.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {key}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
