"""Shard ⑪, Log Analysis & Audit Trail.

Answers one question the other ten shards do not: **if an attacker got in, could you
tell?** Every other shard asks whether a door is open; this one asks whether anyone is
writing down who walked through it.

That makes it the scan-surface counterpart to the Runtime Agent. The Runtime Agent
detects log tampering *as it happens* (`Container log cleared/truncated`, `K8s events
deleted`, MITRE T1070). This shard detects, at scan time, the posture that makes such
tampering unrecoverable in the first place: no audit policy, retention too short to cover
a dwell time, or no log collector shipping anything off the node. A cleared log only
matters if it was the only copy.

Scope note, the API server's `--audit-log-path` check already lives in
`cluster_control_plane` as `apiserver-audit-logging` (CIS 1.2.17). It is intentionally
left there rather than moved: rule ids are the identity used by saved reports and the
finding timeline, so renaming one would orphan history. This shard covers what that check
does *not*, the policy, the retention window, and whether logs leave the node at all.

Every rule here is scoped to the `log_analysis` module, so `--module log_analysis` (CLI),
`module:log_analysis` (dashboard selector) and the `log_analysis` MCP selector all
resolve to exactly this set.
"""
from __future__ import annotations

from typing import Optional

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, Exploitability as EX,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard

NAME = "log_analysis"

#: CIS 1.2.18 to 30 days is the benchmark's floor, and it is also roughly the industry
#: median attacker dwell time, so a shorter window can expire before an intrusion is even
#: noticed.
_MIN_AUDIT_MAXAGE_DAYS = 30
#: CIS 1.2.19 / 1.2.20, enough rotated files, and large enough files, that a burst of
#: activity cannot silently roll the interesting entries out of retention.
_MIN_AUDIT_MAXBACKUP = 10
_MIN_AUDIT_MAXSIZE_MB = 100

#: Substrings identifying a log-shipping agent by workload name or container image.
#: Deliberately broad, a false *negative* here (we recognise your collector and stay
#: quiet) is much cheaper than telling an operator their logging is missing when it isn't.
_LOG_COLLECTORS = (
    "fluentd", "fluent-bit", "fluentbit", "filebeat", "logstash", "vector",
    "promtail", "loki", "otel-collector", "opentelemetry-collector", "otelcol",
    "datadog-agent", "splunk", "newrelic", "cloudwatch-agent", "aws-for-fluent-bit",
    "ama-logs", "omsagent", "stackdriver", "logging-agent", "sumologic", "elastic-agent",
)


def _apiserver_flags(ev) -> Optional[dict]:
    """The API server's parsed command-line flags, or None when the control plane could
    not be read at all.

    None is NOT the same as "the flag is missing". On a managed cluster (EKS/GKE/AKS) the
    control plane is provider-owned and its static Pods are invisible, so ComponentConfig
    comes back with no `apiServer` section. Treating that as "audit logging is off" would
    invent a finding out of absent evidence, the same mistake as scoring an unread
    cluster as clean. Every audit-flag rule below therefore no-ops when this returns None.
    """
    items = ev.get("ComponentConfig", all_scopes=True)
    if not items:
        return None
    api = (Evidence.dig(items[0], "spec.apiServer") or {})
    if not api:
        return None
    flags = api.get("flags")
    return flags if isinstance(flags, dict) else {}


def _int_flag(flags: dict, name: str) -> Optional[int]:
    try:
        return int(str(flags.get(name)).strip())
    except (TypeError, ValueError):
        return None


def _control_plane_ref() -> ResourceRef:
    return ResourceRef("ControlPlane", "apiServer")


# ----------------------------------------------------------------------- #
# Rule checks
# ----------------------------------------------------------------------- #
def _audit_policy_missing(rule, ev, scope):
    """Audit logging with no policy file records nothing useful: without a policy the API
    server defaults to logging no events, so `--audit-log-path` alone is a file that stays
    empty."""
    flags = _apiserver_flags(ev)
    if flags is None:
        return
    if not (flags.get("audit-policy-file") or "").strip():
        yield rule.finding(
            _control_plane_ref(),
            "API server has no --audit-policy-file, so no audit events are recorded "
            "even if --audit-log-path is set",
            blast_radius=BR.CLUSTER, exploitability=EX.REMOTE,
            evidence={"audit-policy-file": flags.get("audit-policy-file") or None,
                      "audit-log-path": flags.get("audit-log-path") or None})


def _audit_retention_short(rule, ev, scope):
    flags = _apiserver_flags(ev)
    if flags is None:
        return
    maxage = _int_flag(flags, "audit-log-maxage")
    if maxage is None:
        yield rule.finding(
            _control_plane_ref(),
            "API server has no --audit-log-maxage, so audit-log retention is undefined",
            blast_radius=BR.CLUSTER, exploitability=EX.REMOTE,
            evidence={"audit-log-maxage": None,
                      "recommended_days": _MIN_AUDIT_MAXAGE_DAYS})
    elif maxage < _MIN_AUDIT_MAXAGE_DAYS:
        yield rule.finding(
            _control_plane_ref(),
            f"audit logs are kept for only {maxage} day(s), shorter than the "
            f"{_MIN_AUDIT_MAXAGE_DAYS}-day floor, so an intrusion can age out before "
            f"it is investigated",
            blast_radius=BR.CLUSTER, exploitability=EX.REMOTE,
            evidence={"audit-log-maxage": maxage,
                      "recommended_days": _MIN_AUDIT_MAXAGE_DAYS})


def _audit_rotation_weak(rule, ev, scope):
    """Retention in days is only half the story: too few rotated files, or files too
    small, and a noisy hour silently discards the entries that matter."""
    flags = _apiserver_flags(ev)
    if flags is None:
        return
    backup = _int_flag(flags, "audit-log-maxbackup")
    size = _int_flag(flags, "audit-log-maxsize")
    problems = []
    if backup is None or backup < _MIN_AUDIT_MAXBACKUP:
        problems.append(f"--audit-log-maxbackup={backup if backup is not None else 'unset'} "
                        f"(recommended >= {_MIN_AUDIT_MAXBACKUP})")
    if size is None or size < _MIN_AUDIT_MAXSIZE_MB:
        problems.append(f"--audit-log-maxsize={size if size is not None else 'unset'} "
                        f"(recommended >= {_MIN_AUDIT_MAXSIZE_MB} MB)")
    if problems:
        yield rule.finding(
            _control_plane_ref(),
            "audit-log rotation discards history too aggressively: " + "; ".join(problems),
            blast_radius=BR.CLUSTER, exploitability=EX.REMOTE,
            evidence={"audit-log-maxbackup": backup, "audit-log-maxsize": size})


def _no_log_collector(rule, ev, scope):
    """No workload in the cluster looks like a log shipper, so container and audit logs
    only ever exist on the node that produced them.

    ponytail: name/image substring match over DaemonSets and Deployments. It cannot see a
    collector running outside the cluster (a managed logging agent on the node, or a
    provider-side pipeline like CloudWatch/Cloud Logging), which is why this is MEDIUM and
    the message says so rather than asserting logs are lost. Upgrade to reading the node's
    own systemd units, or a provider logging API, if a definitive answer matters.
    """
    for kind in ("DaemonSet", "Deployment"):
        for workload in ev.get(kind, all_scopes=True):
            name = (Evidence.dig(workload, "metadata.name") or "").lower()
            images = " ".join(
                str(c.get("image", "")).lower() for c in Evidence.containers(workload))
            haystack = f"{name} {images}"
            if any(c in haystack for c in _LOG_COLLECTORS):
                return                        # something ships logs, nothing to report
    yield rule.finding(
        ResourceRef("Cluster", "log-pipeline"),
        "no in-cluster log collector (fluent-bit/fluentd/vector/otel-collector/…) was "
        "found, so container and audit logs stay on the node that produced them, an "
        "attacker who clears them leaves no second copy. If logs are shipped by a node "
        "agent outside the cluster, this is expected and can be suppressed.",
        blast_radius=BR.CLUSTER, exploitability=EX.LOCAL,
        evidence={"searched_kinds": ["DaemonSet", "Deployment"],
                  "known_collectors": list(_LOG_COLLECTORS)})


# ----------------------------------------------------------------------- #
class LogAnalysisShard(DomainShard):
    name = NAME
    title = "Log Analysis & Audit Trail"
    index = "⑪"

    def rbac_verbs(self) -> list[dict]:
        """ComponentConfig is synthetic, so the base class grants nothing for it, but in
        live mode it is built by reading kube-system static Pods, which needs pods read.
        Same reasoning as cluster_control_plane."""
        return super().rbac_verbs() + [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]},
        ]

    def rules(self):
        cfg = ["ComponentConfig"]
        return [
            Rule("log-audit-policy-missing", "Audit policy file not configured", self.name,
                 cfg, S.HIGH, DM.STATIC_CONFIG, _audit_policy_missing,
                 mitre=[M(T.DEFENSE_EVASION, "T1562", "Impair Defenses")],
                 owasp="K10", cis=["3.2.1"], nsa_cisa=["Audit Logging"],
                 evidence_needs=cfg,
                 default_blast_radius=BR.CLUSTER,
                 default_exploitability=EX.REMOTE),
            Rule("log-audit-retention-short", "Audit log retention below 30 days", self.name,
                 cfg, S.MEDIUM, DM.STATIC_CONFIG, _audit_retention_short,
                 mitre=[M(T.DEFENSE_EVASION, "T1070", "Indicator Removal")],
                 owasp="K10", cis=["1.2.18"], nsa_cisa=["Audit Logging"],
                 evidence_needs=cfg,
                 default_blast_radius=BR.CLUSTER,
                 default_exploitability=EX.REMOTE),
            Rule("log-audit-rotation-weak", "Audit log rotation discards history", self.name,
                 cfg, S.MEDIUM, DM.STATIC_CONFIG, _audit_rotation_weak,
                 mitre=[M(T.DEFENSE_EVASION, "T1070", "Indicator Removal")],
                 owasp="K10", cis=["1.2.19", "1.2.20"], nsa_cisa=["Audit Logging"],
                 evidence_needs=cfg,
                 default_blast_radius=BR.CLUSTER,
                 default_exploitability=EX.REMOTE),
            Rule("log-no-collector", "No log collector shipping logs off-node", self.name,
                 ["DaemonSet", "Deployment"], S.MEDIUM, DM.STATIC_CONFIG, _no_log_collector,
                 mitre=[M(T.DEFENSE_EVASION, "T1070", "Indicator Removal"),
                        M(T.IMPACT, "T1485", "Data Destruction")],
                 owasp="K10", nsa_cisa=["Audit Logging", "Log Aggregation"],
                 evidence_needs=["DaemonSet", "Deployment"],
                 default_blast_radius=BR.CLUSTER),
        ]


SHARD = LogAnalysisShard
