"""
Evidence coverage and assessment confidence (§5).

A scan's risk score answers "how bad is what we saw". It says nothing about how much we
managed to see. Those are different questions, and conflating them is how a scan of a
cluster whose Secrets and Nodes were unreadable gets read as a clean bill of health.

So a result now carries three numbers, not one:

    Risk Score            , how bad the findings are          (core/scoring.py)
    Evidence Coverage     , what fraction of the evidence the scan actually read
    Assessment Confidence , how much weight to put on the risk score given that coverage

Coverage is structural, not a guess: the Evidence Collector records the read outcome of
every resource type it was asked for (`ok` / `partial` / `skipped`), and this module
aggregates that. Confidence is a deterministic function of coverage, never of severity, a
low-coverage scan reports LOW CONFIDENCE and its findings in full. Coverage never
suppresses, downgrades or hides a finding: what was seen was seen.
"""
from __future__ import annotations

#: Resource types grouped into the domains an analyst thinks in, so the report can say
#: "RBAC 93%" instead of listing eight kinds. A kind not listed here is its own domain.
_DOMAINS = {
    "Pod": "Workloads", "Deployment": "Workloads", "DaemonSet": "Workloads",
    "StatefulSet": "Workloads", "ReplicaSet": "Workloads", "Job": "Workloads",
    "CronJob": "Workloads",
    "Role": "RBAC", "RoleBinding": "RBAC", "ClusterRole": "RBAC",
    "ClusterRoleBinding": "RBAC", "ServiceAccount": "RBAC",
    "Service": "Network", "Ingress": "Network", "NetworkPolicy": "Network",
    "Secret": "Secrets", "ConfigMap": "Secrets",
    "Node": "Node configuration", "ComponentConfig": "Control plane",
    "MutatingWebhookConfiguration": "Admission control",
    "ValidatingWebhookConfiguration": "Admission control",
    "CloudIAM": "Cloud IAM", "Namespace": "Cluster inventory",
}

#: How much a read outcome counts toward coverage. `partial` is a real read that returned
#: an incomplete list, so it counts for half rather than being rounded to a clean pass.
_WEIGHT = {"ok": 1.0, "partial": 0.5, "skipped": 0.0}


def _pct(n: float, total: float) -> float:
    return round(100.0 * n / total, 1) if total else 0.0


def build_coverage(collector) -> dict:
    """Aggregate a collector's per-kind read outcomes into the coverage block carried on
    every ScanResult. Returns {} for a collector that recorded nothing (nothing was ever
    requested), so old stored reports and pseudo-scans stay unaffected."""
    raw = dict(getattr(collector, "coverage", {}) or {})
    if not raw:
        return {}

    kinds = {kind: dict(info) for kind, info in sorted(raw.items())}
    earned = sum(_WEIGHT.get(i["status"], 0.0) for i in kinds.values())
    coverage_pct = _pct(earned, len(kinds))

    domains: dict[str, dict] = {}
    for kind, info in kinds.items():
        d = domains.setdefault(_DOMAINS.get(kind, kind),
                               {"kinds": [], "earned": 0.0, "total": 0})
        d["kinds"].append(kind)
        d["earned"] += _WEIGHT.get(info["status"], 0.0)
        d["total"] += 1
    for d in domains.values():
        d["coverage_pct"] = _pct(d.pop("earned"), d.pop("total"))

    unread = sorted(k for k, i in kinds.items() if i["status"] == "skipped")
    partial = sorted(k for k, i in kinds.items() if i["status"] == "partial")
    degraded = bool(getattr(collector, "degraded", False))
    confidence_pct = 0.0 if degraded else coverage_pct
    return {
        "coverage_pct": coverage_pct,
        "confidence_pct": confidence_pct,
        "confidence_label": confidence_label(confidence_pct, evidence_ok=not degraded),
        "kinds": kinds,
        "domains": dict(sorted(domains.items())),
        "unread_kinds": unread,
        "partial_kinds": partial,
    }


def confidence_label(confidence_pct: float, *, evidence_ok: bool = True) -> str:
    """Words for the number, so no surface has to invent its own thresholds.

    `None` is deliberately not a value here: a scan that read nothing is `None`, which is
    not the bottom of a scale, it is the absence of one."""
    if not evidence_ok:
        return "None"
    if confidence_pct >= 90:
        return "High"
    if confidence_pct >= 70:
        return "Moderate"
    if confidence_pct >= 40:
        return "Low"
    return "Very Low"


def summary_line(coverage: dict) -> str:
    """One-line rendering shared by the terminal, text and markdown reports."""
    if not coverage:
        return ""
    return (f"Evidence coverage {coverage['coverage_pct']}%  ·  assessment confidence "
            f"{coverage['confidence_pct']}% ({coverage['confidence_label']})")
