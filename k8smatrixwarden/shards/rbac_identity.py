"""Shard ③, RBAC & Identity (§5.5)."""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, Exploitability as EX,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard, ref

NAME = "rbac_identity"


# Default RBAC that Kubernetes ships on every cluster (cluster-admin, admin, edit, view,
# and the whole system:* set) is wildcard/broad BY DESIGN. Flagging it fires CRITICALs on
# every cluster's first run and, because the same kind+name recurs everywhere, manufactures
# false cross-cluster "shared identity" edges in the federation view. Skip these built-ins
# in the role-DEFINITION scanners; a suspicious BINDING of them is still caught separately.
_DEFAULT_CLUSTERROLES = {"cluster-admin", "admin", "edit", "view"}


def _is_builtin_role(obj) -> bool:
    meta = obj.get("metadata", {}) or {}
    if (meta.get("labels", {}) or {}).get("kubernetes.io/bootstrapping") == "rbac-defaults":
        return True
    name = meta.get("name", "") or ""
    return name.startswith("system:") or name in _DEFAULT_CLUSTERROLES


def _blast(obj):
    # A namespaced Role is a namespace blast radius; only a ClusterRole is cluster-wide.
    return BR.CLUSTER if (obj.get("kind") == "ClusterRole") else BR.NAMESPACE


def _roles(ev):
    """ClusterRoles + namespaced Roles, minus the built-in defaults."""
    return [o for o in ev.get("ClusterRole", all_scopes=True) + ev.get("Role")
            if not _is_builtin_role(o)]


def _rule_grants(rules_list, verbs=None, resources=None):
    for r in rules_list or []:
        rv = set(r.get("verbs", []) or [])
        rr = set(r.get("resources", []) or [])
        if verbs and not (rv & set(verbs) or "*" in rv):
            continue
        if resources and not (rr & set(resources) or "*" in rr):
            continue
        yield r


def _wildcard_verbs(rule, ev, scope):
    for cr in _roles(ev):
        for r in cr.get("rules", []) or []:
            if "*" in (r.get("verbs", []) or []):
                yield rule.finding(ref(cr), f"role grants wildcard verbs (verbs: ['*'])",
                                   blast_radius=_blast(cr), evidence={"rule": r})
                break


def _wildcard_resources(rule, ev, scope):
    for cr in _roles(ev):
        for r in cr.get("rules", []) or []:
            if "*" in (r.get("resources", []) or []):
                yield rule.finding(ref(cr), "role grants wildcard resources "
                                   "(resources: ['*'])",
                                   blast_radius=_blast(cr), evidence={"rule": r})
                break


def _cluster_admin_default_sa(rule, ev, scope):
    for crb in ev.get("ClusterRoleBinding", all_scopes=True):
        role = Evidence.dig(crb, "roleRef.name")
        if role != "cluster-admin":
            continue
        for subj in crb.get("subjects", []) or []:
            if subj.get("kind") == "ServiceAccount" and subj.get("name") == "default":
                yield rule.finding(
                    ref(crb), f"cluster-admin bound to default ServiceAccount "
                    f"({subj.get('namespace')}/default)",
                    blast_radius=BR.CLUSTER, exploitability=EX.ADJACENT,
                    evidence={"subject": subj})


def _bind_escalate(rule, ev, scope):
    for cr in _roles(ev):
        for r in cr.get("rules", []) or []:
            verbs = set(r.get("verbs", []) or [])
            if verbs & {"bind", "escalate", "impersonate"}:
                yield rule.finding(
                    ref(cr), f"role can {', '.join(sorted(verbs & {'bind','escalate','impersonate'}))} "
                    f", privilege-escalation primitive",
                    blast_radius=_blast(cr), evidence={"verbs": sorted(verbs)})
                break


def _secret_read_broad(rule, ev, scope):
    for cr in _roles(ev):
        if cr.get("kind") != "ClusterRole":
            continue                       # cluster-wide secret read is the ClusterRole case
        for r in _rule_grants(cr.get("rules", []), verbs=["get", "list"],
                               resources=["secrets"]):
            yield rule.finding(ref(cr), "ClusterRole can read secrets cluster-wide "
                               "(get/list on secrets)",
                               blast_radius=BR.CLUSTER, evidence={"rule": r})
            break


def _can_delete_events(rule, ev, scope):
    for cr in _roles(ev):
        for r in _rule_grants(cr.get("rules", []), verbs=["delete"], resources=["events"]):
            yield rule.finding(ref(cr), "role can delete events (defense evasion / "
                               "covering tracks)", blast_radius=_blast(cr),
                               evidence={"rule": r})
            break


def _coredns_write(rule, ev, scope):
    for cr in _roles(ev):
        for r in _rule_grants(cr.get("rules", []), verbs=["update", "patch"],
                              resources=["configmaps"]):
            yield rule.finding(ref(cr), "role can modify ConfigMaps (potential CoreDNS "
                               "poisoning if kube-system CoreDNS CM is writable)",
                               blast_radius=_blast(cr), evidence={"rule": r})
            break


class RbacIdentityShard(DomainShard):
    name = NAME
    title = "RBAC & Identity"
    index = "③"

    def rules(self):
        need = ["ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"]
        return [
            Rule("rbac-wildcard-verbs", "Wildcard verbs in role", self.name,
                 ["ClusterRole", "Role"], S.CRITICAL, DM.RBAC, _wildcard_verbs,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                 owasp="K02", cis=["5.1.3"], evidence_needs=need),
            Rule("rbac-wildcard-resources", "Wildcard resources in role", self.name,
                 ["ClusterRole", "Role"], S.CRITICAL, DM.RBAC, _wildcard_resources,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                 owasp="K02", cis=["5.1.3"], evidence_needs=need),
            Rule("rbac-cluster-admin-default-sa", "cluster-admin on default SA", self.name,
                 ["ClusterRoleBinding"], S.CRITICAL, DM.RBAC, _cluster_admin_default_sa,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                 owasp="K02", cis=["5.1.1"], evidence_needs=need),
            Rule("rbac-bind-escalate-verbs", "bind/escalate/impersonate verbs", self.name,
                 ["ClusterRole", "Role"], S.CRITICAL, DM.RBAC, _bind_escalate,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                 owasp="K02", cis=["5.1.8"], evidence_needs=need),
            Rule("rbac-secret-read-broad", "Broad secret read access", self.name,
                 ["ClusterRole"], S.HIGH, DM.RBAC, _secret_read_broad,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552.007",
                          "Container API Credentials")],
                 owasp="K03", cis=["5.1.2"], evidence_needs=need),
            Rule("rbac-can-delete-events", "Can delete Kubernetes events", self.name,
                 ["ClusterRole", "Role"], S.HIGH, DM.RBAC, _can_delete_events,
                 mitre=[M(T.DEFENSE_EVASION, "T1070", "Indicator Removal")],
                 owasp="K10", evidence_needs=need),
            Rule("rbac-coredns-configmap-write", "Can write ConfigMaps (CoreDNS risk)",
                 self.name, ["ClusterRole", "Role"], S.HIGH, DM.RBAC, _coredns_write,
                 mitre=[M(T.LATERAL_MOVEMENT, "T1557", "Adversary-in-the-Middle")],
                 owasp="K05", evidence_needs=need),
        ]


SHARD = RbacIdentityShard
