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


#: Subjects that are not one identity but a whole population. Binding a privileged role to
#: any of these grants it to every request that reaches the API server in that class, which
#: is why they are called out separately from a named user or ServiceAccount.
#:
#:   system:anonymous / system:unauthenticated , every request with NO credentials at all
#:   system:authenticated                       , every request with ANY valid credential,
#:                                                which on most clusters includes every
#:                                                ServiceAccount in every namespace
#:   system:serviceaccounts                     , every ServiceAccount cluster-wide
#:
#: `system:masters` is deliberately NOT here. Kubernetes ships a `cluster-admin`
#: ClusterRoleBinding to that group on every cluster ever built, and the API server
#: hard-codes the group to full access regardless, so the binding is not what grants it and
#: deleting the binding would change nothing. Membership comes from the client certificate's
#: O field, not from RBAC, so there is no RBAC remediation to point at. Reporting it would
#: put an unactionable CRITICAL on 100% of scans, which is how a real anonymous-admin
#: finding gets scrolled past. Who holds a `system:masters` certificate is a PKI question,
#: outside what the API server can show a read-only scanner.
_BROAD_SUBJECTS = {
    "system:anonymous": "every unauthenticated request",
    "system:unauthenticated": "every unauthenticated request",
    "system:authenticated": "every authenticated principal, including every ServiceAccount",
    "system:serviceaccounts": "every ServiceAccount in the cluster",
}

#: Roles whose grant is (near) total. `cluster-admin` is unrestricted by definition; `admin`
#: and `edit` are namespace-scoped but still allow creating workloads and reading secrets.
_HIGH_PRIVILEGE_ROLES = {"cluster-admin", "admin", "edit"}


def _grants_everything(obj) -> bool:
    """Does this role grant unrestricted access on EVERY axis (verbs, resources, groups)?

    All three must be `*`. A rule that is `*` on only one axis, `apiGroups: ["apps"]` with
    `resources: ["*"]` for instance, is broad within that group but is not cluster-admin,
    and calling it so would be a false positive.
    """
    for r in obj.get("rules", []) or []:
        if ("*" in set(r.get("verbs", []) or [])
                and "*" in set(r.get("resources", []) or [])
                and "*" in set(r.get("apiGroups", []) or [])):
            return True
    return False


def _role_is_high_privilege(ev, role_ref) -> bool:
    name = (role_ref or {}).get("name", "")
    if name in _HIGH_PRIVILEGE_ROLES:
        return True
    for cr in ev.get("ClusterRole", all_scopes=True):
        if Evidence.dig(cr, "metadata.name") == name:
            return _grants_everything(cr)
    return False


def _broad_subject_binding(rule, ev, scope):
    """A privileged role bound to a whole population rather than to an identity.

    The case this exists for: a ClusterRoleBinding granting `cluster-admin` to
    `system:authenticated`, or worse to `system:anonymous`. Nothing in the rule set looked
    at User or Group subjects at all, so a cluster in which every unauthenticated request
    is cluster-admin produced zero RBAC findings.

    Both binding kinds are checked. A RoleBinding confines the grant to its own namespace,
    which is materially less severe than a cluster-wide one but is still a whole population
    holding admin over that namespace, so it is reported with the smaller blast radius
    rather than skipped.
    """
    for kind in ("ClusterRoleBinding", "RoleBinding"):
        for binding in ev.get(kind, all_scopes=True):
            role_ref = binding.get("roleRef", {}) or {}
            if not _role_is_high_privilege(ev, role_ref):
                continue
            cluster_wide = kind == "ClusterRoleBinding"
            ns = Evidence.dig(binding, "metadata.namespace")
            for subj in binding.get("subjects", []) or []:
                name = subj.get("name", "")
                if subj.get("kind") not in ("User", "Group"):
                    continue
                who = _BROAD_SUBJECTS.get(name)
                if who is None and not name.startswith("system:serviceaccounts"):
                    continue
                who = who or "every ServiceAccount in that namespace"
                where = "cluster-wide" if cluster_wide else "in namespace " + str(ns)
                anonymous = name in ("system:anonymous", "system:unauthenticated")
                yield rule.finding(
                    ref(binding),
                    f"{kind} grants {role_ref.get('name')!r} {where} to "
                    f"{subj.get('kind')} {name!r}, which is {who}",
                    severity=S.CRITICAL if cluster_wide else S.HIGH,
                    blast_radius=BR.CLUSTER if cluster_wide else BR.NAMESPACE,
                    exploitability=EX.REMOTE if anonymous else EX.ADJACENT,
                    evidence={"subject": subj, "roleRef": role_ref,
                              "binding_namespace": ns})


def _cluster_admin_user_binding(rule, ev, scope):
    """cluster-admin bound cluster-wide to a NAMED User or Group.

    Distinct from the broad-subject rule: this is a specific human or team, which is often
    legitimate, so it is reported as something to confirm rather than as a
    misconfiguration. It is reported at all because a cluster's admin bindings are exactly
    what an auditor needs enumerated, and nothing else in the rule set surfaces a
    non-ServiceAccount subject.
    """
    for binding in ev.get("ClusterRoleBinding", all_scopes=True):
        role_ref = binding.get("roleRef", {}) or {}
        if (role_ref.get("name") or "") != "cluster-admin":
            continue
        if _is_builtin_role(binding):
            continue                     # Kubernetes' own bootstrap binding
        for subj in binding.get("subjects", []) or []:
            name = subj.get("name", "")
            if subj.get("kind") not in ("User", "Group"):
                continue
            if name in _BROAD_SUBJECTS or name.startswith("system:"):
                continue                 # broad subjects belong to the rule above
            yield rule.finding(
                ref(binding),
                f"cluster-admin is bound cluster-wide to {subj.get('kind')} {name!r}; "
                f"confirm this identity still requires unrestricted access",
                blast_radius=BR.CLUSTER, exploitability=EX.ADJACENT,
                evidence={"subject": subj, "roleRef": role_ref})


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
            Rule("rbac-broad-subject-admin", "Privileged role bound to a whole population",
                 self.name, ["ClusterRoleBinding", "RoleBinding"], S.CRITICAL, DM.RBAC,
                 _broad_subject_binding,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                 owasp="K02", cis=["5.1.1"], evidence_needs=need,
                 references=["https://kubernetes.io/docs/reference/access-authn-authz/"
                             "rbac/#default-roles-and-role-bindings"],
                 false_positive_notes=(
                     "Kubernetes' own bootstrap bindings grant system:authenticated a few "
                     "harmless discovery roles; only high-privilege roles match here.")),
            Rule("rbac-cluster-admin-user-binding", "cluster-admin bound to a User/Group",
                 self.name, ["ClusterRoleBinding"], S.HIGH, DM.RBAC,
                 _cluster_admin_user_binding,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                 owasp="K02", cis=["5.1.1"], evidence_needs=need, confidence="medium",
                 false_positive_notes=(
                     "A named administrator legitimately holding cluster-admin is normal; "
                     "this is an inventory item to confirm, not a misconfiguration.")),
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
