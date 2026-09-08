"""Shard ⑥, Secrets (§5.8)."""
from __future__ import annotations

import re

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard, ref
from .workload_pod_security import WORKLOAD_KINDS

NAME = "secrets"
_CRED_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
                      r"private[_-]?key|credential)", re.I)
_CLOUD_CRED_FILES = (".aws/credentials", "azure.json", "gcp", "service_account.json",
                     ".kube/config")


def _env_var_secrets(rule, ev, scope):
    for kind in WORKLOAD_KINDS:
        for res in ev.get(kind):
            for c in ev.containers(res):
                for e in c.get("env", []) or []:
                    if Evidence.dig(e, "valueFrom.secretKeyRef"):
                        yield rule.finding(
                            ref(res), f"container '{c.get('name')}' injects a Secret via "
                            f"env var '{e.get('name')}' (exposed in logs/crash dumps)",
                            evidence={"env": e.get("name")})


def _configmap_credentials(rule, ev, scope):
    for cm in ev.get("ConfigMap"):
        for k, v in (cm.get("data", {}) or {}).items():
            if _CRED_RE.search(k) or _CRED_RE.search(str(v)):
                yield rule.finding(ref(cm), f"ConfigMap key '{k}' looks like a hardcoded "
                                   f"credential", evidence={"key": k})
                break


def _mounted_cloud_creds(rule, ev, scope):
    for kind in WORKLOAD_KINDS:
        for res in ev.get(kind):
            for vm in _all_volume_mounts(ev, res):
                mp = vm.get("mountPath", "")
                if any(f in mp for f in _CLOUD_CRED_FILES):
                    yield rule.finding(
                        ref(res), f"mounts a cloud credential path ({mp}), service "
                        f"principal / managed identity exposure",
                        evidence={"mountPath": mp})


def _all_volume_mounts(ev, res):
    out = []
    for c in ev.containers(res):
        out.extend(c.get("volumeMounts", []) or [])
    return out


def _etcd_encryption(rule, ev, scope):
    """Fires only when the API server's config was actually read and the flag is absent.

    This is an ABSENCE check, which makes it the one shape that turns unread evidence into
    a Critical finding if it is not guarded. On a managed cluster the control plane is
    provider-owned and its static Pods are invisible, so ComponentConfig arrives with no
    `apiServer` section at all and `dig` returns None for every flag -- indistinguishable,
    to a bare `if not ...`, from a cluster that really has encryption switched off.

    A live EKS scan caught exactly that: the collector warned "the control plane is
    provider-managed ... so API server / etcd / kubelet flag checks were not applicable"
    and this rule asserted CRITICAL "Secrets stored in plaintext" in the same report.
    Every other ComponentConfig rule already no-ops here -- see
    cluster_control_plane._flag_check and log_analysis._apiserver_flags, which both
    document this and were silent on that scan. This one was hand-written and skipped the
    guard.
    """
    items = ev.get("ComponentConfig", all_scopes=True)
    if not items:
        return                      # control plane not readable at all
    cfg = items[0]
    if not Evidence.dig(cfg, "spec.apiServer"):
        return                      # the API server's config was never read
    if not Evidence.dig(cfg, "spec.apiServer.encryptionProvider"):
        yield rule.finding(ResourceRef("ControlPlane", "etcd"),
                           "etcd encryption at rest is not enabled, Secrets stored in "
                           "plaintext", severity=S.CRITICAL, blast_radius=BR.CLUSTER)


class SecretsShard(DomainShard):
    name = NAME
    title = "Secrets"
    index = "⑥"

    def rules(self):
        return [
            Rule("sec-env-var-secrets", "Secret exposed as env var", self.name,
                 ["Pod"], S.HIGH, DM.STATIC_CONFIG, _env_var_secrets,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552.007",
                          "Container API Credentials")],
                 owasp="K03", cis=["5.4.1"], evidence_needs=WORKLOAD_KINDS),
            Rule("sec-configmap-credentials", "Credentials in ConfigMap", self.name,
                 ["ConfigMap"], S.HIGH, DM.STATIC_CONFIG, _configmap_credentials,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552", "Unsecured Credentials")],
                 owasp="K03", evidence_needs=["ConfigMap"]),
            Rule("sec-mounted-cloud-creds", "Mounted cloud credentials", self.name,
                 ["Pod"], S.HIGH, DM.STATIC_CONFIG, _mounted_cloud_creds,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552", "Unsecured Credentials")],
                 owasp="K03", evidence_needs=WORKLOAD_KINDS),
            Rule("sec-etcd-not-encrypted", "etcd not encrypted", self.name,
                 ["ComponentConfig"], S.CRITICAL, DM.STATIC_CONFIG, _etcd_encryption,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552", "Unsecured Credentials")],
                 owasp="K03", cis=["1.2.28"], evidence_needs=["ComponentConfig"]),
        ]


SHARD = SecretsShard
