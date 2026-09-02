"""correlate(): scan findings × runtime alerts → confirmed / corroborated / runtime-only."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.correlation import correlate, detect_drift
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Severity,
                                         Tactic)
from k8smatrixwarden.agents.runtime import (RuntimeAgent, normalize_events,
                                            normalize_falco_event)


def test_normalize_falco_syscall_event():
    raw = {"source": "syscall", "rule": "Terminal shell in container",
           "output_fields": {"proc.name": "bash", "k8s.ns.name": "default",
                             "k8s.pod.name": "web-abc", "user.uid": 0,
                             "fd.name": "/etc/passwd", "evt.type": "open"}}
    ev = normalize_falco_event(raw)
    # `rule` and `time` are carried through so a correlation can name the Falco rule that
    # fired and be placed in an incident timeline; this event has no timestamp, so `time`
    # is dropped rather than invented.
    assert ev == {"source": "falco", "proc": "bash", "op": "open",
                  "namespace": "default", "pod": "web-abc", "uid": 0,
                  "file": "/etc/passwd", "rule": "Terminal shell in container"}


def test_normalize_falco_event_keeps_the_timestamp():
    raw = {"source": "syscall", "time": "2026-08-30T10:15:00Z", "rule": "Shell",
           "output_fields": {"proc.name": "bash", "k8s.pod.name": "web-abc"}}
    assert normalize_falco_event(raw)["time"] == "2026-08-30T10:15:00Z"


def test_normalize_falco_network_event():
    raw = {"source": "syscall",
           "output_fields": {"proc.name": "curl", "fd.name": "169.254.169.254:80",
                             "fd.sip": "169.254.169.254"}}
    ev = normalize_falco_event(raw)
    assert ev["connect"] == "169.254.169.254:80" and "file" not in ev


def test_normalize_falco_audit_event():
    raw = {"source": "k8s_audit",
           "output_fields": {"ka.verb": "create",
                             "ka.target.resource": "clusterrolebindings",
                             "ka.target.namespace": "production"}}
    ev = normalize_falco_event(raw)
    # Falco's k8saudit plugin renders the same API-server record the audit log carries, so
    # it flattens to the same shape, including the provider that produced the evidence.
    assert ev == {"source": "audit", "verb": "create",
                  "resource": "clusterrolebindings", "namespace": "production",
                  "provider": "kubernetes-audit"}


def test_normalize_events_single_and_flat_passthrough():
    # single Falco event → list of one; already-flat event passes through untouched
    out = normalize_events({"source": "syscall", "output_fields": {"proc.name": "sh"}})
    assert out == [{"source": "falco", "proc": "sh"}]
    flat = {"source": "falco", "proc": "nmap"}
    assert normalize_events([flat]) == [flat]


def test_normalized_falco_events_fire_the_same_alerts():
    # a raw Falco shell event, once normalized, fires the shell-in-container rule
    raw = [{"source": "syscall", "output_fields": {"proc.name": "bash"}}]
    alerts = RuntimeAgent().evaluate_stream(normalize_events(raw))
    assert any(a.rule_id == "rt-shell-in-container" for a in alerts)


def _pod(name, ns, sc=None, container_sc=None):
    return {"kind": "Pod", "metadata": {"name": name, "namespace": ns},
            "spec": {"securityContext": sc or {},
                     "containers": [{"name": "app",
                                     "securityContext": container_sc or {}}]}}


def _finding(tactic, ns="production", name="payment-api"):
    return Finding(
        rule_id="workload-privileged", title="Privileged container",
        severity=Severity.HIGH,
        resource=ResourceRef(kind="Pod", name=name, namespace=ns),
        message="privileged", owning_shard="workload_pod_security",
        mitre=[MitreTag(tactic, "T1610", "Deploy Container")])


def test_confirmed_only_when_event_pod_matches_the_finding_resource():
    # the runtime event NAMES the pod the finding is on (payment-api), resource-level link.
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION, ns="production", name="payment-api")]
    alerts = RuntimeAgent().evaluate_stream([
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings",
         "namespace": "production", "pod": "payment-api"}])
    out = correlate(findings, alerts)
    assert out["confirmed_exploitation"] == 1
    assert out["correlations"][0]["confidence"] == "confirmed"


def test_confirmed_matches_workload_owned_pod_name():
    # pods are <workload>-<rs>-<hash>; a finding on the workload still counts as the resource.
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION, ns="production", name="payment-api")]
    alerts = RuntimeAgent().evaluate_stream([
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings",
         "namespace": "production", "pod": "payment-api-5f8b94447d-blxwg"}])
    assert correlate(findings, alerts)["confirmed_exploitation"] == 1


def test_namespace_match_without_pod_is_corroborated_not_confirmed():
    # same tactic + namespace but the event names no matching pod, NOT proof of exploitation.
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION, ns="production", name="payment-api")]
    alerts = RuntimeAgent().evaluate_stream([
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings",
         "namespace": "production"}])
    out = correlate(findings, alerts)
    assert out["confirmed_exploitation"] == 0
    assert out["correlated"] == 1
    assert out["correlations"][0]["confidence"] == "corroborated"


def test_corroborated_when_tactic_matches_but_namespace_differs():
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION, ns="production")]
    alerts = RuntimeAgent().evaluate_stream([
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings",
         "namespace": "staging"}])
    out = correlate(findings, alerts)
    assert out["confirmed_exploitation"] == 0
    assert out["correlated"] == 1
    assert out["correlations"][0]["confidence"] == "corroborated"


def test_runtime_only_when_no_static_finding_shares_the_tactic():
    findings = [_finding(Tactic.PRIVILEGE_ESCALATION)]
    # crypto-miner = Impact tactic, no Impact finding in scan
    alerts = RuntimeAgent().evaluate_stream([{"source": "falco", "proc": "xmrig"}])
    out = correlate(findings, alerts)
    assert out["runtime_only"] == 1
    assert out["correlations"][0]["static_findings"] == []


def test_drift_root_despite_runasnonroot():
    pods = [_pod("api", "prod", sc={"runAsNonRoot": True})]
    out = detect_drift(pods, [{"source": "falco", "pod": "api", "namespace": "prod",
                               "uid": 0, "proc": "bash"}])
    assert out["drift_count"] == 1
    assert out["drift"][0]["policy"] == "runAsNonRoot"


def test_drift_write_despite_readonly_rootfs():
    pods = [_pod("api", "prod", container_sc={"readOnlyRootFilesystem": True})]
    out = detect_drift(pods, [{"source": "falco", "pod": "api", "namespace": "prod",
                               "op": "write", "file": "/etc/passwd"}])
    assert out["drift_count"] == 1
    assert out["drift"][0]["policy"] == "readOnlyRootFilesystem"


def test_write_to_tmp_is_allowed_not_drift():
    pods = [_pod("api", "prod", container_sc={"readOnlyRootFilesystem": True})]
    out = detect_drift(pods, [{"source": "falco", "pod": "api", "namespace": "prod",
                               "op": "write", "file": "/tmp/scratch"}])
    assert out["drift_count"] == 0


def test_unattributable_event_skipped():
    pods = [_pod("api", "prod", sc={"runAsNonRoot": True})]
    # event names no pod -> can't attribute -> skipped, no false positive
    out = detect_drift(pods, [{"source": "falco", "uid": 0}])
    assert out["drift_count"] == 0


if __name__ == "__main__":
    for fn in (test_confirmed_only_when_event_pod_matches_the_finding_resource,
               test_confirmed_matches_workload_owned_pod_name,
               test_namespace_match_without_pod_is_corroborated_not_confirmed,
               test_corroborated_when_tactic_matches_but_namespace_differs,
               test_runtime_only_when_no_static_finding_shares_the_tactic,
               test_drift_root_despite_runasnonroot,
               test_drift_write_despite_readonly_rootfs,
               test_write_to_tmp_is_allowed_not_drift,
               test_unattributable_event_skipped):
        fn()
    print("ok")
