"""
Result Aggregator (§6.1).

Dedupes findings that reference the same underlying object and merges their taxonomy tags
into one finding, so a pod flagged by two related rules surfaces once with the union of its
MITRE/OWASP/CIS tags. Also computes summary counts used by scoring and reporting.
"""
from __future__ import annotations

from collections import defaultdict

from .models import Finding, MitreTag, Severity


class ResultAggregator:
    def aggregate(self, findings: list[Finding]) -> list[Finding]:
        merged: dict[tuple, Finding] = {}
        for f in findings:
            key = f.dedup_key()
            if key not in merged:
                merged[key] = f
                continue
            # Same rule + same object reported twice: merge tags, keep worst severity.
            existing = merged[key]
            existing.mitre = _merge_mitre(existing.mitre, f.mitre)
            existing.cis = sorted(set(existing.cis) | set(f.cis))
            existing.nsa_cisa = sorted(set(existing.nsa_cisa) | set(f.nsa_cisa))
            if f.severity.order > existing.severity.order:
                existing.severity = f.severity
        # Deterministic order, worst first then by identity. Rules execute in parallel and
        # complete in whatever order the pool finishes them, so without this the SAME scan
        # emits findings in a different sequence each run, which shows up as spurious diffs
        # in SARIF/JSON output and makes two reports awkward to compare.
        return sorted(merged.values(),
                      key=lambda f: (-f.severity.order, f.rule_id, f.resource.kind,
                                     f.resource.name, f.resource.namespace or ""))

    @staticmethod
    def counts(findings: list[Finding]) -> dict[str, int]:
        c = defaultdict(int)
        for f in findings:
            c[f.severity.label] += 1
        return {s.label: c.get(s.label, 0) for s in Severity}

    @staticmethod
    def by_tactic(findings: list[Finding]) -> dict[str, int]:
        c = defaultdict(int)
        for f in findings:
            for t in f.tactics:
                c[t.value] += 1
        return dict(c)

    @staticmethod
    def by_shard(findings: list[Finding]) -> dict[str, int]:
        c = defaultdict(int)
        for f in findings:
            c[f.owning_shard or "unknown"] += 1
        return dict(c)


def _merge_mitre(a: list[MitreTag], b: list[MitreTag]) -> list[MitreTag]:
    seen, out = set(), []
    for tag in list(a) + list(b):
        k = (tag.tactic, tag.technique_id)
        if k not in seen:
            seen.add(k)
            out.append(tag)
    return out
