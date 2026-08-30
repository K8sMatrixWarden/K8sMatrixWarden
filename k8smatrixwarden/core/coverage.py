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

#: Fallback weight per status, used only when the collector recorded no estimate of its
#: own. `ok` and `skipped` are exact. `partial` without an estimate is the one genuinely
#: unknown case, and the 0.5 it gets is labelled `heuristic` everywhere it surfaces, so a
#: reader is never shown a guess formatted like a measurement.
_WEIGHT = {"ok": 1.0, "partial": 0.5, "skipped": 0.0}

#: Ranked worst-first: the aggregate basis is the weakest basis any kind contributed,
#: because a total containing one guess is not a measurement.
_BASIS_RANK = ["unknown", "heuristic", "estimated", "measured"]


def _weight(info: dict) -> float:
    """How much this kind contributes to coverage, preferring the collector's own estimate
    over the status fallback."""
    est = info.get("estimated_coverage")
    if isinstance(est, (int, float)):
        return float(est)
    return _WEIGHT.get(info.get("status"), 0.0)


def _basis(info: dict) -> str:
    """How this kind's number was arrived at. A `partial` with no estimate is heuristic,
    which is exactly the case that used to be indistinguishable from a real measurement."""
    recorded = info.get("coverage_basis")
    if recorded:
        return recorded
    if info.get("status") == "partial":
        return "heuristic"
    return "measured"


def _aggregate_basis(bases) -> str:
    ranks = [(_BASIS_RANK.index(b) if b in _BASIS_RANK else 0) for b in bases]
    return _BASIS_RANK[min(ranks)] if ranks else "unknown"


def _pct(n: float, total: float) -> float:
    return round(100.0 * n / total, 1) if total else 0.0


def build_coverage(collector) -> dict:
    """Aggregate a collector's per-kind read outcomes into the coverage block carried on
    every ScanResult. Returns {} for a collector that recorded nothing (nothing was ever
    requested), so old stored reports and pseudo-scans stay unaffected."""
    raw = dict(getattr(collector, "coverage", {}) or {})
    if not raw:
        return {}

    kinds = {}
    for kind, info in sorted(raw.items()):
        entry = dict(info)
        # Normalise: every kind carries both numbers explicitly, so no consumer has to
        # re-derive them (and none can re-derive them differently).
        entry["estimated_coverage"] = _weight(info)
        entry["coverage_basis"] = _basis(info)
        kinds[kind] = entry

    earned = sum(i["estimated_coverage"] for i in kinds.values())
    coverage_pct = _pct(earned, len(kinds))
    basis = _aggregate_basis(i["coverage_basis"] for i in kinds.values())

    domains: dict[str, dict] = {}
    for kind, info in kinds.items():
        d = domains.setdefault(_DOMAINS.get(kind, kind),
                               {"kinds": [], "earned": 0.0, "total": 0, "bases": []})
        d["kinds"].append(kind)
        d["earned"] += info["estimated_coverage"]
        d["total"] += 1
        d["bases"].append(info["coverage_basis"])
    for d in domains.values():
        d["coverage_pct"] = _pct(d.pop("earned"), d.pop("total"))
        d["coverage_basis"] = _aggregate_basis(d.pop("bases"))

    unread = sorted(k for k, i in kinds.items() if i["status"] == "skipped")
    partial = sorted(k for k, i in kinds.items() if i["status"] == "partial")
    degraded = bool(getattr(collector, "degraded", False))
    confidence_pct = 0.0 if degraded else coverage_pct
    return {
        "coverage_pct": coverage_pct,
        # How the percentage above was arrived at: `measured` when every kind was counted
        # exactly, degrading to `estimated`/`heuristic`/`unknown` if any kind was not.
        "coverage_basis": basis,
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
    basis = coverage.get("coverage_basis", "measured")
    qualifier = "" if basis == "measured" else f" [{basis}]"
    return (f"Evidence coverage {coverage['coverage_pct']}%{qualifier}  ·  assessment "
            f"confidence {coverage['confidence_pct']}% "
            f"({coverage['confidence_label']})")
