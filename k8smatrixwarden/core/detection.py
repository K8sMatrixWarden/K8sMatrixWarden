"""
Detection Engine / Rule Executor (§6.1).

Executes the resolved rule set against the shared evidence snapshot, in parallel, with
per-rule isolation: a bug or exception in one rule becomes an INFO finding rather than
crashing the whole scan (this is the concrete answer to the Option-B "God module" critique
in the redesign doc, one bad check must not take the scan down).

External tool output (Trivy, kube-bench, kubescape, Falco) is folded in through the
`ExternalToolAdapter` interface, normalized to the same `Finding` schema (§22).
"""
from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from .evidence import Evidence, EvidenceCollector
from .models import (BlastRadius, DetectionMethod, Exploitability, Finding,
                     ResourceRef, Rule, Scope, Severity)
from .reachability import annotate_reachability
from .registry import RuleRegistry


class ExternalToolAdapter:
    """Normalize a third-party tool's output into internal Findings (§22)."""

    name = "external"

    def available(self) -> bool:
        return False

    def findings(self, scope: Scope) -> list[Finding]:  # pragma: no cover - interface
        return []


class DetectionEngine:
    def __init__(self, registry: RuleRegistry, max_workers: int = 16):
        self.registry = registry
        self.max_workers = max_workers
        self._adapters: list[ExternalToolAdapter] = []

    def register_adapter(self, adapter: ExternalToolAdapter) -> None:
        self._adapters.append(adapter)

    def evidence_needs(self, rule_ids: list[str]) -> set[str]:
        """Union of evidence needs across the resolved rules (for one shared fetch)."""
        needs: set[str] = set()
        for rid in rule_ids:
            rule = self.registry.get(rid)
            if rule:
                needs.update(rule.evidence_needs or rule.resource_scope)
        return needs

    def run(self, rule_ids: list[str], collector: EvidenceCollector,
            scope: Scope) -> list[Finding]:
        needs = self.evidence_needs(rule_ids)
        evidence = collector.collect(needs, scope)   # <-- fetch ONCE, shared snapshot

        rules = [self.registry.get(rid) for rid in rule_ids]
        rules = [r for r in rules if r is not None and r.enabled]

        findings: list[Finding] = []
        if not rules:
            return findings

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(rules))) as pool:
            futs = {pool.submit(self._run_rule, r, evidence, scope): r for r in rules}
            for fut in as_completed(futs):
                findings.extend(fut.result())

        # Fold in external adapters that are actually available.
        for adapter in self._adapters:
            try:
                if adapter.available():
                    findings.extend(adapter.findings(scope))
            except Exception as exc:  # pragma: no cover
                findings.append(_error_finding(f"adapter:{adapter.name}", str(exc)))

        # Owner attribution, applied once for every shard's findings. Doing it here rather
        # than per-shard is what stops one Pod being reported under two different owners
        # depending on which rule fired. Isolated: attribution is context, never a verdict.
        try:
            from ..shards.base import resolve_owner
            for f in findings:
                if f.resource is not None and f.resource.kind != "_engine":
                    f.resource = resolve_owner(f.resource, evidence)
        except Exception as exc:  # pragma: no cover - never let attribution fail a scan
            findings.append(_error_finding("owner-resolution", str(exc)))

        # Reachability tagging: tag each finding with its attack vector (internet-reachable /
        # post-breach / rbac-escalation) from the cluster's own exposure + RBAC, on the same
        # shared snapshot. NEVER lowers severity. Isolated so a bug here can't fail the scan.
        try:
            findings = annotate_reachability(findings, evidence)
        except Exception as exc:  # pragma: no cover - never let gating crash a scan
            findings.append(_error_finding("reachability", str(exc)))

        return findings

    @staticmethod
    def _run_rule(rule: Rule, evidence: Evidence, scope: Scope) -> list[Finding]:
        try:
            out = list(rule.check(rule, evidence, scope) or [])
            return out
        except Exception as exc:  # isolation: never let one rule crash the scan
            detail = f"{exc}\n{traceback.format_exc(limit=3)}"
            return [_error_finding(rule.id, detail)]


def _error_finding(rule_id: str, detail: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Rule execution error: {rule_id}",
        severity=Severity.INFO,
        resource=ResourceRef(kind="_engine", name=rule_id),
        message=f"Rule failed to execute and was skipped: {detail.splitlines()[0]}",
        detection_method=DetectionMethod.STATIC_CONFIG,
        exploitability=Exploitability.LOCAL,
        blast_radius=BlastRadius.POD,
        evidence={"error": detail},
    )
