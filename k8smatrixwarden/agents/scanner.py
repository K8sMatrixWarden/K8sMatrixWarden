"""
Scanner Agent (§5), wires registry + evidence + detection + aggregate + score.

The scan path is identical for every request shape (§7.2):
    resolve(selector) → fetch-once evidence → execute rules → aggregate → score → result
"""
from __future__ import annotations

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
             mode_label: str = "mock", name: str = "") -> ScanResult:
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

        findings = self.p.aggregator.aggregate(findings)
        risk = self.p.scoring.score(findings)

        # A collector that could read nothing produces zero findings, which scores as
        # "Excellent". That is a lie about a cluster we never inspected, so the rating is
        # replaced with an explicit Unknown and the reason travels on the result to every
        # surface (report, dashboard, JSON, PDF). See EvidenceCollector.degraded.
        warnings = list(getattr(collector, "warnings", []))
        evidence_ok = not getattr(collector, "degraded", False)
        if not evidence_ok:
            risk = RiskResult(cluster_risk=0.0, security_score=0, rating="Unknown",
                              rating_emoji="⚠️", raw=0.0)

        # Record WHICH cluster this scan hit, so a saved report can be grouped by cluster
        # in the federation/blast-radius view. Falls back to the model default.
        cluster = "target-cluster"
        try:
            cluster = collector.cluster_label() or cluster
        except Exception:
            pass

        # Cluster inventory + pod exposure buckets for the dashboard scope bar. The collector
        # caches buckets, so kinds the rules already fetched cost nothing here; only Node /
        # Namespace (if unused by rules) trigger a one-off fetch. Isolated: a probe failure
        # must never fail the scan, the bar just won't render.
        inv: dict = {}
        try:
            from ..core.reachability import inventory as _inventory
            ev = collector.collect(
                {"Pod", "Node", "Namespace", "Service", "NetworkPolicy",
                 "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"}, request.scope)
            inv = _inventory(ev)
        except Exception:
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
            by_tactic=self.p.aggregator.by_tactic(findings),
            by_shard=self.p.aggregator.by_shard(findings),
            name=name,
            cluster_name=cluster,
            mode=mode_label,
            inventory=inv,
            coverage=coverage,
        )
