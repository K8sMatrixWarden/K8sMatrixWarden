"""
A managed control plane is unreadable, and unreadable is not the same as insecure.

Found on a live EKS scan. The collector correctly reported:

    ComponentConfig: no control-plane static Pods visible in kube-system, the control
    plane is provider-managed (EKS/GKE/AKS) or runs outside the cluster, so API server /
    etcd / kubelet flag checks were not applicable

and the same report carried a CRITICAL finding saying "etcd encryption at rest is not
enabled, Secrets stored in plaintext". Nothing had been read; the claim was manufactured
out of the absence.

The shape that does this is an ABSENCE check -- `if not dig(cfg, flag)` -- because a
missing section and a disabled flag both dig to None. `cluster_control_plane._flag_check`
and `log_analysis._apiserver_flags` both guard against it and both say so in their
docstrings, and on that EKS scan every rule built on them stayed silent. `_etcd_encryption`
was hand-written and skipped the guard, so it was the single control-plane finding on a
cluster whose control plane KMW cannot see.

These tests hold the whole family to the rule, not just the one that broke.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import Scope, ScopeLevel

#: What ComponentConfig looks like on EKS/GKE/AKS: the bucket exists, the section does not.
MANAGED = [{"kind": "ComponentConfig", "spec": {}}]
#: And on a self-managed cluster whose API server genuinely has no encryption flag.
SELF_MANAGED_UNENCRYPTED = [{"kind": "ComponentConfig", "spec": {"apiServer": {
    "anonymousAuth": False, "encryptionProvider": "", "flags": ["--secure-port=6443"]}}}]
SELF_MANAGED_ENCRYPTED = [{"kind": "ComponentConfig", "spec": {"apiServer": {
    "anonymousAuth": False, "encryptionProvider": "/etc/kubernetes/enc.yaml"}}}]


def _fire(rule_id, componentconfig):
    """Run one rule against a hand-built ComponentConfig bucket."""
    platform = build_platform()
    rule = platform.registry.rules.get(rule_id)
    assert rule is not None, f"no such rule: {rule_id}"
    evidence = Evidence({"componentconfig": list(componentconfig)},
                        Scope(level=ScopeLevel.CLUSTER))
    return list(rule.check(rule, evidence, Scope(level=ScopeLevel.CLUSTER)))


def test_etcd_encryption_is_silent_when_the_control_plane_was_never_read():
    """REGRESSION. The live EKS false positive."""
    assert _fire("sec-etcd-not-encrypted", MANAGED) == [], (
        "a CRITICAL 'Secrets stored in plaintext' was asserted about a control plane "
        "KMW cannot see")


def test_etcd_encryption_is_silent_when_there_is_no_componentconfig_at_all():
    assert _fire("sec-etcd-not-encrypted", []) == []


def test_etcd_encryption_still_fires_when_the_flag_is_genuinely_absent():
    """The fix must not have disarmed the rule. Docker Desktop was verified by hand:
    the API server there carries no --encryption-provider-config, and the section IS
    readable, so this is a true positive that has to survive."""
    found = _fire("sec-etcd-not-encrypted", SELF_MANAGED_UNENCRYPTED)
    assert len(found) == 1, found
    assert "plaintext" in found[0].message


def test_etcd_encryption_is_silent_when_encryption_is_configured():
    assert _fire("sec-etcd-not-encrypted", SELF_MANAGED_ENCRYPTED) == []


# --------------------------------------------------------------------------- #
# The whole family, not just the rule that broke
# --------------------------------------------------------------------------- #

def _componentconfig_rules():
    platform = build_platform()
    return [r for r in platform.registry.rules.all()
            if "ComponentConfig" in (r.evidence_needs or [])]


def test_the_family_is_not_empty():
    """If this ever hits zero the sweep below is passing vacuously."""
    rules = _componentconfig_rules()
    assert len(rules) >= 5, [r.id for r in rules]


def test_no_control_plane_rule_fires_on_a_managed_cluster():
    """The sweep. Every rule that reads control-plane config must treat an unreadable
    control plane as unreadable -- a finding here is a claim about evidence nobody has."""
    noisy = []
    for rule in _componentconfig_rules():
        for componentconfig in (MANAGED, []):
            try:
                if list(rule.check(rule, Evidence({"componentconfig": list(componentconfig)},
                                                  Scope(level=ScopeLevel.CLUSTER)),
                                   Scope(level=ScopeLevel.CLUSTER))):
                    noisy.append(rule.id)
                    break
            except Exception as exc:                    # a crash is its own failure
                noisy.append(f"{rule.id} raised {type(exc).__name__}")
                break
    assert not noisy, (
        f"these rules invent a finding from an unread control plane: {sorted(set(noisy))}")


# --------------------------------------------------------------------------- #
# Managed-cloud infrastructure must not be reported as somebody else's endpoint
# --------------------------------------------------------------------------- #

def _webhook(url, name="w.example.com", config="pod-identity-webhook"):
    return [{"kind": "MutatingWebhookConfiguration", "metadata": {"name": config},
             "webhooks": [{"name": name, "clientConfig": {"url": url}}]}]


def _webhook_findings(webhooks):
    platform = build_platform()
    rule = platform.registry.rules.get("admission-malicious-webhook")
    evidence = Evidence({"mutatingwebhookconfigurations": webhooks},
                        Scope(level=ScopeLevel.CLUSTER))
    return list(rule.check(rule, evidence, Scope(level=ScopeLevel.CLUSTER)))


def test_a_loopback_webhook_is_not_an_external_endpoint():
    """REGRESSION. EKS ships pod-identity-webhook and the VPC resource controller on
    https://127.0.0.1, and both were reported CRITICAL as "targets an external URL" --
    untrue, and true of every EKS cluster there is."""
    for url in ("https://127.0.0.1:23443/mutate",
                "https://127.0.0.1:9443/mutate-v1-pod",
                "https://localhost:8443/mutate",
                "https://127.10.20.30:443/mutate"):
        assert _webhook_findings(_webhook(url)) == [], url


def test_a_genuinely_external_webhook_is_still_critical():
    """The fix must not have disarmed the rule it exists for: a third party in the
    admission path can rewrite every pod in the cluster."""
    found = _webhook_findings(_webhook("https://attacker.example.com/mutate",
                                       name="inject.evil.io"))
    assert len(found) == 1, found
    assert found[0].severity.label == "CRITICAL"
    assert "external URL" in found[0].message


def test_the_in_cluster_service_form_is_not_flagged():
    """`clientConfig.service` is the normal, reviewable case and was never the target."""
    webhook = [{"kind": "MutatingWebhookConfiguration", "metadata": {"name": "ok"},
                "webhooks": [{"name": "w", "clientConfig": {
                    "service": {"name": "svc", "namespace": "default"}}}]}]
    assert _webhook_findings(webhook) == []


def test_the_collector_explains_why_the_checks_were_skipped():
    """Silence has to be accounted for, or it reads as a pass."""
    import inspect

    from k8smatrixwarden.core import evidence
    source = inspect.getsource(evidence.LiveEvidenceCollector._build_component_config)
    assert "provider-managed" in source, (
        "the collector no longer explains an unreadable managed control plane")


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
