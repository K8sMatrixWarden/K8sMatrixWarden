"""Shard ⑦, CIS Benchmark & Compliance (§5.9).

Mostly owns framework tags. Native rules cover Pod Security Admission posture; deeper CIS
coverage is folded in via the kube-bench external adapter when available.
"""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, MitreTag as M,
                           ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard

NAME = "compliance"
_PSA_ENFORCE = "pod-security.kubernetes.io/enforce"


def _psa_not_enforced(rule, ev, scope):
    for ns in ev.get("Namespace", all_scopes=True):
        name = Evidence.dig(ns, "metadata.name")
        if name in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        if scope.namespace and name != scope.namespace:
            continue
        labels = Evidence.dig(ns, "metadata.labels", {}) or {}
        level = labels.get(_PSA_ENFORCE)
        if level != "restricted":
            yield rule.finding(
                ResourceRef("Namespace", name),
                f"namespace '{name}' does not enforce Pod Security Standard 'restricted' "
                f"(current: {level or 'none'})",
                blast_radius=BR.NAMESPACE,
                evidence={"namespace": name, "enforce": level})


class ComplianceShard(DomainShard):
    name = NAME
    title = "CIS Benchmark & Compliance"
    index = "⑦"

    def rules(self):
        return [
            Rule("compliance-psa-not-restricted", "PSA not enforcing 'restricted'",
                 self.name, ["Namespace"], S.HIGH, DM.STATIC_CONFIG, _psa_not_enforced,
                 mitre=[M(T.PERSISTENCE, "T1610", "Deploy Container")],
                 owasp="K04", cis=["5.2.1"],
                 nsa_cisa=["Pod Security", "Policy Enforcement"],
                 evidence_needs=["Namespace"]),
        ]


SHARD = ComplianceShard
