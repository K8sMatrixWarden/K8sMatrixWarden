"""Shard ⑧, Attack Surface Mapper (§5.10).

Cross-cutting analyses that don't belong to a single other shard: ServiceAccount fan-out
(same SA reused across many pods/namespaces → lateral-movement blast radius) and an
external-entry-point summary.
"""
from __future__ import annotations

from collections import defaultdict

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, Exploitability as EX,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard
from .workload_pod_security import WORKLOAD_KINDS

NAME = "attack_surface"
FANOUT_THRESHOLD = 3


def _sa_fanout(rule, ev, scope):
    usage: dict[str, set] = defaultdict(set)
    pods_per_sa: dict[str, int] = defaultdict(int)
    for kind in WORKLOAD_KINDS:
        for res in ev.get(kind):
            spec = ev.pod_spec(res)
            sa = spec.get("serviceAccountName") or spec.get("serviceAccount")
            if not sa or sa == "default":
                continue
            ns = Evidence.dig(res, "metadata.namespace")
            usage[sa].add(ns)
            pods_per_sa[sa] += 1
    for sa, namespaces in usage.items():
        if pods_per_sa[sa] >= FANOUT_THRESHOLD and len(namespaces) > 1:
            yield rule.finding(
                ResourceRef("ServiceAccount", sa),
                f"ServiceAccount '{sa}' is reused by {pods_per_sa[sa]} workloads across "
                f"{len(namespaces)} namespaces ({', '.join(sorted(namespaces))}), wide "
                f"lateral-movement blast radius",
                blast_radius=BR.CLUSTER, exploitability=EX.ADJACENT,
                evidence={"pods": pods_per_sa[sa], "namespaces": sorted(namespaces)})


class AttackSurfaceShard(DomainShard):
    name = NAME
    title = "Attack Surface Mapper"
    index = "⑧"

    def rules(self):
        return [
            Rule("as-sa-fanout", "ServiceAccount fan-out", self.name,
                 WORKLOAD_KINDS, S.MEDIUM, DM.RBAC, _sa_fanout,
                 mitre=[M(T.LATERAL_MOVEMENT, "T1078", "Valid Accounts")],
                 owasp="K02", evidence_needs=WORKLOAD_KINDS),
        ]


SHARD = AttackSurfaceShard
