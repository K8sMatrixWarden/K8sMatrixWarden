"""
Scanner Agent (§5), wires registry + evidence + detection + aggregate + score.

The scan path is identical for every request shape (§7.2):
    resolve(selector) → fetch-once evidence → execute rules → aggregate → score → result
"""
from __future__ import annotations

from typing import Optional

from ..bootstrap import Platform
from ..core.evidence import EvidenceCollector
from ..core.models import ScanRequest
from ..core.results import ScanResult
from ..core.scoring import RiskResult


class ScannerAgent:
    def __init__(self, platform: Platform):
        self.p = platform

    def resolve(self, request: ScanRequest) -> list[str]:
        """Selector → concrete rule id set (the single choke point)."""
        return self.p.mapping.resolve(request.selector)

    def scan(self, request: ScanRequest, collector: EvidenceCollector,
             mode_label: str = "mock", name: str = "",
             suppressions: Optional[list] = None) -> ScanResult:
        rule_ids = self.resolve(request)

        # Evidence is already scope-constrained by the collector, so findings are in scope.
        # Cluster-scoped objects (RBAC, webhooks) intentionally remain visible.
        findings = self.p.detection.run(rule_ids, collector, request.scope)

        # A rule that raised was isolated into an `_engine` row and produced no findings.
        # That is NOT the same as a rule that ran and found nothing, and the difference is
        # load-bearing: historical posture treats every evaluated rule as entitled to mark
        # its previous findings `resolved`. Leaving a crashed rule in that set let a broken
        # rule report its own findings as FIXED, with the risk score improving to match.
        # Computed before aggregation, which may merge or drop the error rows.
        failed = sorted({f.rule_id for f in findings
                         if f.resource.kind == "_engine" and f.rule_id in set(rule_ids)})
        evaluated = [r for r in rule_ids if r not in set(failed)]

        suppressed, supp_notes = [], []
        if suppressions:
            from ..core.suppressions import apply as _suppress
            findings, suppressed, supp_notes = _suppress(findings, suppressions)

        findings = self.p.aggregator.aggregate(findings)

        # Resolved BEFORE scoring: the cluster name is part of workload identity, so two
        # clusters' reports in one store can never merge a workload by name alone.
        cluster = "target-cluster"
        try:
            cluster = collector.cluster_label() or cluster
        except Exception:
            pass

        risk = self.p.scoring.score(findings, cluster)
        # Findings are already stamped with their aggregation identity by scoring; this
        # groups them into the remediation units the headline count reports, without
        # removing, merging or hiding any of the evidence underneath.
        from ..core.workload import summarize, workload_issues
        issues = workload_issues(findings, cluster)
        aggregation = summarize(findings, issues)

        issue_dicts = [i.as_dict() for i in issues]
        try:
            from ..core.ownership import annotate as _owners
            _owners(issue_dicts, findings, collector.collect({"Namespace"}, request.scope).get("Namespace", all_scopes=True))
        except Exception:                     # ownership is a convenience, never a reason to fail
            pass

        # A collector that could read nothing produces zero findings, which scores as
        # "Excellent". That is a lie about a cluster we never inspected, so the rating is
        # replaced with an explicit Unknown and the reason travels on the result to every
        # surface (report, dashboard, JSON, PDF). See EvidenceCollector.degraded.
        warnings = list(getattr(collector, "warnings", []))
        evidence_ok = not getattr(collector, "degraded", False)
        if not evidence_ok:
            risk = RiskResult(cluster_risk=0.0, security_score=0, rating="Unknown",
                              rating_emoji="⚠️", raw=0.0)

        # Cluster inventory + pod exposure buckets for the dashboard scope bar. The collector
        # caches buckets, so kinds the rules already fetched cost nothing here; only Node /
        # Namespace (if unused by rules) trigger a one-off fetch. Isolated: a probe failure
        # must never fail the scan, the bar just won't render.
        inv: dict = {}
        try:
            from ..core.reachability import inventory as _inventory, INVENTORY_KINDS
            ev = collector.collect(set(INVENTORY_KINDS), request.scope)
            inv = _inventory(ev)
        except Exception:
            pass

        topology: dict = {}
        try:
            from ..core.topology import build_topology
            topology = build_topology(collector.collect(
                {"Pod", "ReplicaSet", "Job", "Service", "Ingress", "NetworkPolicy",
                 "Namespace", "EndpointSlice"}, request.scope))
        except Exception:                     # the graph must never fail a scan
            pass

        # Best-effort wider discovery; kinds the scanner cannot read are recorded as
        # skipped and never fail the scan or lower confidence.
        try:
            from ..core.evidence import EXTENDED_KINDS
            collector.collect(set(EXTENDED_KINDS), request.scope)
        except Exception:
            pass

        cluster_detail: dict = {}
        try:
            from ..core.cluster_inventory import build_cluster_inventory
            from ..core.evidence import EXTENDED_KINDS
            need = {"Pod", "ReplicaSet", "Job", "Deployment", "StatefulSet", "DaemonSet", "CronJob", "Node",
                    "Namespace", "NetworkPolicy", "Service", "Ingress", "ClusterRole", "Role",
                    "ClusterRoleBinding", "RoleBinding", "ServiceAccount", "ConfigMap",
                    "ImageVulnerability"} | set(EXTENDED_KINDS)
            cluster_detail = build_cluster_inventory(collector.collect(need, request.scope), findings, topology)
        except Exception:                     # the inventory must never fail a scan
            pass

        # Evidence coverage / assessment confidence, computed AFTER every collect() above
        # so the inventory probe's kinds are counted too. Structural, derived from what the
        # collector actually managed to read (§5); it never changes a finding.
        from ..core.coverage import build_coverage
        try:
            coverage = build_coverage(collector)
        except Exception:                     # never let bookkeeping fail a scan
            coverage = {}

        return ScanResult(
            request=request,
            findings=findings,
            risk=risk,
            warnings=warnings,
            evidence_ok=evidence_ok,
            resolved_rule_ids=evaluated,
            failed_rule_ids=failed,
            counts=self.p.aggregator.counts(findings),
            workload_issues=issue_dicts,
            aggregation=aggregation,
            by_tactic=self.p.aggregator.by_tactic(findings),
            by_shard=self.p.aggregator.by_shard(findings),
            name=name,
            cluster_name=cluster,
            mode=mode_label,
            inventory=inv,
            topology=topology,
            cluster_inventory=cluster_detail,
            coverage=coverage,
            suppressed=suppressed,
            suppression_notes=supp_notes,
        )
