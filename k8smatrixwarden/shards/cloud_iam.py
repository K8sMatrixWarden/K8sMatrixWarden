"""Shard ⑩, Cloud IAM & Workload Identity (NEW, §5.12).

Reads a synthetic 'CloudIAM' evidence bucket (IRSA / Workload Identity / AAD Pod Identity
bindings). Live mode would populate this from the cloud provider IAM API via a scoped,
read-only credential declared in the plugin manifest. Without cloud access it degrades to
advisory findings from ServiceAccount annotations.
"""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, Exploitability as EX,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard

NAME = "cloud_iam"
_BROAD_ACTIONS = ("*", "iam:*", "s3:*", "ec2:*", "AdministratorAccess", "roles/owner",
                  "roles/editor", "Contributor", "Owner")


def _iter_bindings(ev):
    return ev.get("CloudIAM", all_scopes=True)


def _overpermissive(rule, ev, scope):
    for b in _iter_bindings(ev):
        actions = b.get("actions", []) or []
        policy = b.get("policy", "")
        broad = [a for a in actions if a in _BROAD_ACTIONS] or \
                any(p in policy for p in _BROAD_ACTIONS)
        if broad:
            yield rule.finding(
                ResourceRef("CloudIAM", b.get("serviceAccount", "?"),
                            b.get("namespace")),
                f"workload identity for SA '{b.get('serviceAccount')}' is over-permissive "
                f"(binding: {b.get('role') or policy})",
                blast_radius=BR.CLUSTER, exploitability=EX.ADJACENT,
                evidence={"binding": b})


def _node_role_broad(rule, ev, scope):
    for b in _iter_bindings(ev):
        if b.get("kind") == "NodeInstanceRole":
            actions = b.get("actions", []) or []
            if any(a in _BROAD_ACTIONS for a in actions):
                yield rule.finding(
                    ResourceRef("CloudIAM", b.get("role", "node-role")),
                    "node instance role is broader than the pods running on it require",
                    blast_radius=BR.CLUSTER, evidence={"binding": b})


def _managed_identity_reachable(rule, ev, scope):
    """Advisory: SA annotated for cloud identity + no metadata egress block (best-effort)."""
    annotated = []
    for sa in ev.get("ServiceAccount"):
        annos = Evidence.dig(sa, "metadata.annotations", {}) or {}
        if any(k for k in annos if "iam" in k.lower() or "iam.gke" in k.lower()
               or "azure" in k.lower() or "eks.amazonaws" in k.lower()):
            annotated.append(sa)
    for sa in annotated:
        yield rule.finding(
            ResourceRef("ServiceAccount", Evidence.dig(sa, "metadata.name"),
                        Evidence.dig(sa, "metadata.namespace")),
            "ServiceAccount is bound to a cloud managed identity; ensure metadata API "
            "egress is restricted and the identity is least-privilege",
            severity=S.MEDIUM, evidence={"annotations": Evidence.dig(
                sa, "metadata.annotations", {})})


class CloudIamShard(DomainShard):
    name = NAME
    title = "Cloud IAM & Workload Identity"
    index = "⑩"
    external_evidence = ["cloud_iam_api"]

    def rules(self):
        return [
            Rule("iam-overpermissive", "Over-permissive workload identity", self.name,
                 ["CloudIAM"], S.HIGH, DM.CLOUD_IAM, _overpermissive,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078.004", "Cloud Accounts"),
                        M(T.LATERAL_MOVEMENT, "T1078.004", "Cloud Accounts")],
                 owasp="K08", evidence_needs=["CloudIAM"]),
            Rule("iam-node-role-broad", "Broad node instance role", self.name,
                 ["CloudIAM"], S.HIGH, DM.CLOUD_IAM, _node_role_broad,
                 mitre=[M(T.INITIAL_ACCESS, "T1078.004", "Cloud Accounts"),
                        M(T.LATERAL_MOVEMENT, "T1078.004", "Cloud Accounts")],
                 owasp="K08", evidence_needs=["CloudIAM"]),
            Rule("iam-managed-identity-reachable", "Managed identity reachable", self.name,
                 ["ServiceAccount"], S.MEDIUM, DM.CLOUD_IAM, _managed_identity_reachable,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552.005",
                          "Cloud Instance Metadata API")],
                 owasp="K08", evidence_needs=["ServiceAccount"]),
        ]


SHARD = CloudIamShard
