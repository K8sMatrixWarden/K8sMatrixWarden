"""Shard ①, Cluster & Control Plane (§5.3).

Control-plane flags are modeled as a synthetic 'ComponentConfig' resource so the same
rule code works in mock mode and (where exposed) live mode.
"""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, Exploitability as EX,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard

NAME = "cluster_control_plane"


def _cfg(ev):
    items = ev.get("ComponentConfig", all_scopes=True)
    return items[0] if items else {}


def _flag_rule(path, bad_predicate, message):
    """A check over one control-plane flag at `path` (``spec.<component>.<field>``).

    Fires only when that component's config was actually READ. On a managed cluster
    (EKS/GKE/AKS) the control plane is provider-owned and its kube-system static Pods are
    invisible, so ComponentConfig arrives with no `apiServer`/`etcd`/`kubelet` section at
    all. `Evidence.dig` then returns None for every flag, and a predicate like
    ``lambda v: not v`` reads that as "the flag is off", inventing a Critical finding out
    of evidence that was never available. Absence of evidence is not evidence of absence:
    when the section is missing the rule stays silent, and the collector records one
    warning explaining that these checks were not applicable (see
    core/evidence.py::_build_component_config).
    """
    parts = path.split(".")
    # spec.<component>.<field> -> the section that must be present; spec.<field> -> none.
    section = parts[1] if len(parts) >= 3 else None
    component = parts[1] if len(parts) > 1 else "control-plane"   # apiServer/etcd/kubelet

    def _check(rule, ev, scope):
        cfg = _cfg(ev)
        if not cfg:
            return                       # control plane not readable at all
        if section is not None and not Evidence.dig(cfg, f"spec.{section}"):
            return                       # this component's config was never read
        val = Evidence.dig(cfg, path)
        if bad_predicate(val):
            yield rule.finding(ResourceRef("ControlPlane", component),
                               message.format(val=val),
                               blast_radius=BR.CLUSTER, exploitability=EX.REMOTE,
                               evidence={path: val})
    return _check


class ClusterControlPlaneShard(DomainShard):
    name = NAME
    title = "Cluster & Control Plane"
    index = "①"

    def rbac_verbs(self) -> list[dict]:
        """
        Rules declare 'ComponentConfig' as their evidence need, a synthetic kind with no
        real API resource, so the base implementation grants nothing for it. But in LIVE
        mode, ComponentConfig is actually built by reading kube-system static Pods
        (core/evidence.py::build_component_config, the control-plane flag mitigation), so
        this shard genuinely needs get/list/watch on pods to function live. Declare that
        explicitly rather than relying on another shard happening to grant it too.
        """
        return super().rbac_verbs() + [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]},
        ]

    def rules(self):
        need = ["ComponentConfig"]
        return [
            Rule("apiserver-anonymous-auth", "API server anonymous auth enabled", self.name,
                 need, S.CRITICAL, DM.STATIC_CONFIG,
                 _flag_rule("spec.apiServer.anonymousAuth", lambda v: v is True,
                            "API server has --anonymous-auth=true"),
                 mitre=[M(T.INITIAL_ACCESS, "T1078", "Valid Accounts")],
                 owasp="K09", cis=["1.2.1"], nsa_cisa=["Authentication"], evidence_needs=need),
            Rule("apiserver-insecure-port", "API server insecure port open", self.name,
                 need, S.CRITICAL, DM.STATIC_CONFIG,
                 _flag_rule("spec.apiServer.insecurePort", lambda v: v not in (0, None),
                            "API server --insecure-port is not 0 (={val})"),
                 mitre=[M(T.INITIAL_ACCESS, "T1133", "External Remote Services")],
                 owasp="K06", evidence_needs=need),
            Rule("apiserver-audit-logging", "API audit logging disabled", self.name,
                 need, S.HIGH, DM.STATIC_CONFIG,
                 _flag_rule("spec.apiServer.auditLogPath", lambda v: not v,
                            "API server has no --audit-log-path (audit logging off)"),
                 mitre=[M(T.DEFENSE_EVASION, "T1562", "Impair Defenses")],
                 owasp="K10", cis=["1.2.17"], nsa_cisa=["Audit Logging"], evidence_needs=need),
            Rule("etcd-encryption-missing", "etcd encryption not configured", self.name,
                 need, S.HIGH, DM.STATIC_CONFIG,
                 _flag_rule("spec.apiServer.encryptionProvider", lambda v: not v,
                            "no --encryption-provider-config (secrets stored plaintext)"),
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552", "Unsecured Credentials")],
                 owasp="K03", cis=["1.2.28"], evidence_needs=need),
            Rule("etcd-client-cert-auth", "etcd client cert auth disabled", self.name,
                 need, S.CRITICAL, DM.STATIC_CONFIG,
                 _flag_rule("spec.etcd.clientCertAuth", lambda v: v is not True,
                            "etcd --client-cert-auth is not true"),
                 mitre=[M(T.DISCOVERY, "T1613", "Container and Resource Discovery")],
                 owasp="K06", cis=["2.2"], evidence_needs=need),
            Rule("kubelet-anonymous-auth", "Kubelet anonymous auth enabled", self.name,
                 need, S.CRITICAL, DM.STATIC_CONFIG,
                 _flag_rule("spec.kubelet.anonymousAuth", lambda v: v is True,
                            "kubelet --anonymous-auth=true"),
                 mitre=[M(T.DISCOVERY, "T1613", "Access Kubelet API")],
                 owasp="K06", cis=["4.2.1"], evidence_needs=need),
            Rule("kubelet-read-only-port", "Kubelet read-only port open", self.name,
                 need, S.HIGH, DM.STATIC_CONFIG,
                 _flag_rule("spec.kubelet.readOnlyPort", lambda v: v not in (0, None),
                            "kubelet read-only port {val} is open"),
                 mitre=[M(T.DISCOVERY, "T1613", "Access Kubelet API")],
                 owasp="K06", cis=["4.2.4"], evidence_needs=need),
            Rule("kubelet-authz-always-allow", "Kubelet AlwaysAllow authz", self.name,
                 need, S.CRITICAL, DM.STATIC_CONFIG,
                 _flag_rule("spec.kubelet.authorizationMode",
                            lambda v: v == "AlwaysAllow",
                            "kubelet --authorization-mode=AlwaysAllow"),
                 mitre=[M(T.DISCOVERY, "T1613", "Access Kubelet API")],
                 owasp="K06", cis=["4.2.2"], evidence_needs=need),
            Rule("deprecated-k8s-version", "Deprecated/EOL Kubernetes version", self.name,
                 need, S.HIGH, DM.STATIC_CONFIG,
                 _flag_rule("spec.version", lambda v: bool(v) and _eol(v),
                            "cluster runs an EOL/CVE-affected version ({val})"),
                 mitre=[M(T.DISCOVERY, "T1613", "Container and Resource Discovery")],
                 owasp="K07", evidence_needs=need),
        ]


def _eol(version: str) -> bool:
    try:
        major_minor = version.lstrip("v").split(".")
        return (int(major_minor[0]), int(major_minor[1])) < (1, 26)
    except Exception:
        return False


SHARD = ClusterControlPlaneShard
