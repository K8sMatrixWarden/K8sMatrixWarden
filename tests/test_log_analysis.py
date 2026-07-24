"""Log Analysis shard (shards/log_analysis.py), audit-trail posture.

Answers "if an attacker got in, could you tell?" at scan time. The rules pair with the
Runtime Agent's T1070 detections: it catches log tampering as it happens, this catches the
posture that makes tampering unrecoverable.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.evidence import EvidenceCollector
from k8smatrixwarden.core.models import (ScanMode, ScanRequest, Scope, ScopeLevel,
                                          Selector, Tactic)

MODULE = "log_analysis"


class _Fixture(EvidenceCollector):
    """Serves a hand-built cluster snapshot, so each posture can be tested exactly."""

    def __init__(self, buckets):
        super().__init__()
        self._b = buckets
        self.fetched_ok = True

    def _fetch(self, kind, bucket):
        items = self._b.get(bucket, [])
        for it in items:
            it.setdefault("kind", kind)
        return list(items)


def _component_config(**flags):
    return {"kind": "ComponentConfig", "metadata": {"name": "control-plane"},
            "spec": {"apiServer": {"flags": {k.replace("_", "-"): v
                                             for k, v in flags.items()}}}}


def _healthy_audit_flags():
    return dict(audit_policy_file="/etc/kubernetes/audit-policy.yaml",
                audit_log_path="/var/log/k8s-audit.log",
                audit_log_maxage="30", audit_log_maxbackup="10", audit_log_maxsize="100")


def _workload(name, image):
    return {"metadata": {"name": name},
            "spec": {"template": {"spec": {"containers": [{"image": image}]}}}}


def _rule_ids(buckets):
    platform = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                          selector=Selector(modules=[MODULE]), mode=ScanMode.SYNC)
    result = ScannerAgent(platform).scan(request, _Fixture(buckets))
    return sorted(f.rule_id for f in result.findings)


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #
def test_shard_is_registered_and_selectable_by_module():
    platform = build_platform()
    assert MODULE in platform.registry.shard_names()
    ids = platform.mapping.resolve(Selector(modules=[MODULE]))
    assert ids, "the module selector must resolve to this shard's rules"
    owned = {r.id for r in platform.registry.rules.all() if r.owning_shard == MODULE}
    assert set(ids) == owned


def test_rules_are_tagged_for_the_defense_evasion_coverage_gap():
    """The point of the shard: put detection coverage on the tactic an attacker uses to
    erase their tracks."""
    platform = build_platform()
    rules = [r for r in platform.registry.rules.all() if r.owning_shard == MODULE]
    assert rules
    assert all(r.owasp == "K10" for r in rules), "all map to OWASP K10 (logging/monitoring)"
    assert all(Tactic.DEFENSE_EVASION in r.tactics for r in rules)


# --------------------------------------------------------------------------- #
# audit-flag posture
# --------------------------------------------------------------------------- #
def test_fully_configured_audit_trail_is_clean():
    assert _rule_ids({"componentconfig": [_component_config(**_healthy_audit_flags())],
                      "daemonsets": [_workload("fluent-bit", "fluent/fluent-bit:2.1")]}) == []


def test_missing_audit_policy_is_reported():
    flags = _healthy_audit_flags()
    flags.pop("audit_policy_file")
    ids = _rule_ids({"componentconfig": [_component_config(**flags)],
                     "daemonsets": [_workload("fluent-bit", "fluent/fluent-bit:2.1")]})
    assert ids == ["log-audit-policy-missing"]


def test_retention_below_the_cis_floor_is_reported():
    flags = dict(_healthy_audit_flags(), audit_log_maxage="7")
    ids = _rule_ids({"componentconfig": [_component_config(**flags)],
                     "daemonsets": [_workload("vector", "timberio/vector:0.34")]})
    assert ids == ["log-audit-retention-short"]


def test_retention_exactly_at_the_floor_is_accepted():
    flags = dict(_healthy_audit_flags(), audit_log_maxage="30")
    assert _rule_ids({"componentconfig": [_component_config(**flags)],
                      "daemonsets": [_workload("vector", "timberio/vector:0.34")]}) == []


def test_weak_rotation_is_reported_even_when_retention_days_are_fine():
    """30-day retention means nothing if a burst rotates the interesting entries away."""
    flags = dict(_healthy_audit_flags(), audit_log_maxbackup="1", audit_log_maxsize="5")
    ids = _rule_ids({"componentconfig": [_component_config(**flags)],
                     "daemonsets": [_workload("vector", "timberio/vector:0.34")]})
    assert ids == ["log-audit-rotation-weak"]


# --------------------------------------------------------------------------- #
# absence of evidence is not evidence of absence
# --------------------------------------------------------------------------- #
def test_managed_control_plane_does_not_produce_invented_audit_findings():
    """On EKS/GKE/AKS the control plane is provider-owned and its static Pods are
    invisible, so ComponentConfig arrives with no apiServer section. Reading that as
    "audit logging is off" would manufacture three findings out of missing evidence."""
    ids = _rule_ids({
        "componentconfig": [{"kind": "ComponentConfig", "spec": {"version": None}}],
        "daemonsets": [_workload("aws-for-fluent-bit", "amazon/aws-for-fluent-bit:2.31")]})
    assert ids == []


def test_no_component_config_at_all_produces_no_audit_findings():
    ids = _rule_ids({"daemonsets": [_workload("fluent-bit", "fluent/fluent-bit:2.1")]})
    assert ids == []


# --------------------------------------------------------------------------- #
# log collector detection
# --------------------------------------------------------------------------- #
def test_missing_log_collector_is_reported():
    ids = _rule_ids({"componentconfig": [_component_config(**_healthy_audit_flags())]})
    assert ids == ["log-no-collector"]


def test_collector_is_recognised_by_daemonset_or_deployment():
    healthy = {"componentconfig": [_component_config(**_healthy_audit_flags())]}
    for bucket, name, image in (
            ("daemonsets", "fluent-bit", "fluent/fluent-bit:2.1"),
            ("daemonsets", "logging", "grafana/promtail:2.9"),
            ("deployments", "otel-collector", "otel/opentelemetry-collector:0.91"),
            ("deployments", "shipper", "timberio/vector:0.34"),
            ("daemonsets", "ama-logs", "mcr.microsoft.com/azuremonitor/ama-logs:3.1")):
        assert _rule_ids(dict(healthy, **{bucket: [_workload(name, image)]})) == [], image


def test_unrelated_workloads_do_not_count_as_a_collector():
    ids = _rule_ids({"componentconfig": [_component_config(**_healthy_audit_flags())],
                     "daemonsets": [_workload("node-exporter", "prom/node-exporter:1.7")],
                     "deployments": [_workload("web", "nginx:1.25")]})
    assert ids == ["log-no-collector"]


def test_collector_finding_says_it_can_miss_an_external_agent():
    """The check cannot see a node agent running outside the cluster, so the message must
    not assert that logs are lost, only that no in-cluster collector was found."""
    platform = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                          selector=Selector(rule_ids=["log-no-collector"]),
                          mode=ScanMode.SYNC)
    result = ScannerAgent(platform).scan(request, _Fixture({}))
    message = result.findings[0].message
    assert "outside the cluster" in message and "expected" in message
