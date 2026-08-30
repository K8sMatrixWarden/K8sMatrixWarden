"""
NetworkPolicy evaluation, complete label-selector semantics, both directions.

The earlier pass matched `spec.podSelector.matchLabels` only, ignored `matchExpressions`,
ignored `namespaceSelector`, and looked at ingress alone. That under-matched real policies
two ways: a policy selecting pods by expression looked like it selected nothing (so an
isolated pod read as exposed), and egress restrictions were invisible to reachability and
to attack paths.

This module implements the Kubernetes semantics properly and, just as importantly, admits
when it cannot. Every answer carries a `status`, and "we could not evaluate this policy" is
one of the values, never silently folded into "unrestricted":

    unrestricted , no policy governs this direction for this pod (the Kubernetes default)
    allow-all    , a governing policy admits every peer (empty `from`/`to`, or 0.0.0.0/0)
    restricted   , governed, and every rule names specific peers, which are returned
    deny-all     , governed with no rules at all, nothing may enter/leave
    partial      , some governing policies were evaluated, at least one could not be
    unknown      , nothing could be evaluated (unsupported constructs only)

A selector match is tri-state for the same reason: `True`, `False`, or `None` meaning "this
selector uses something we do not implement, do not guess". Callers treat `None` as
"unknown", never as a match or a non-match.

Reference: https://kubernetes.io/docs/concepts/services-networking/network-policies/
"""
from __future__ import annotations

from typing import Optional

#: The four set-based operators Kubernetes defines for matchExpressions. Anything else is
#: not a Kubernetes operator, and a selector carrying one is reported as unevaluable rather
#: than being quietly treated as a non-match.
SUPPORTED_OPERATORS = ("In", "NotIn", "Exists", "DoesNotExist")

#: CIDRs that cover the whole address space, an ipBlock naming one is an allow-all peer.
ALLOW_ALL_CIDRS = {"0.0.0.0/0", "::/0"}

UNRESTRICTED, ALLOW_ALL, RESTRICTED, DENY_ALL, PARTIAL, UNKNOWN = (
    "unrestricted", "allow-all", "restricted", "deny-all", "partial", "unknown")


def selector_matches(selector: Optional[dict], labels: dict) -> Optional[bool]:
    """Does a Kubernetes LabelSelector match this label set?

    Returns True/False, or None when the selector uses a construct this implementation
    does not support (an unknown operator, or a malformed expression). An EMPTY selector
    (`{}`) matches everything, which is the Kubernetes rule and the difference between
    "selects no pods" and "selects every pod in the namespace".

    `None` as the selector is NOT the same as `{}` and is the caller's decision to
    interpret: inside a NetworkPolicySpec an absent podSelector is invalid, while inside a
    peer an absent podSelector means "do not constrain pods". Callers pass what they mean.
    """
    if selector is None:
        return None
    if not isinstance(selector, dict):
        return None
    for key, want in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != want:
            return False
    for expr in selector.get("matchExpressions") or []:
        if not isinstance(expr, dict):
            return None
        op = expr.get("operator")
        key = expr.get("key")
        values = expr.get("values") or []
        if op not in SUPPORTED_OPERATORS or not key:
            return None                       # unknown operator: refuse to guess
        present = key in labels
        value = labels.get(key)
        if op == "In":
            if not present or value not in values:
                return False
        elif op == "NotIn":
            # Kubernetes: a pod without the key satisfies NotIn.
            if present and value in values:
                return False
        elif op == "Exists":
            if not present:
                return False
        elif op == "DoesNotExist":
            if present:
                return False
    return True


def _ns_labels(namespace: str, namespaces: list[dict]) -> Optional[dict]:
    """Labels of a Namespace object, or None when that Namespace was not collected.

    Kubernetes auto-labels every namespace with `kubernetes.io/metadata.name`, so that key
    is synthesised when the object is present but the label is not (older clusters), which
    is what makes the common `namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: x}}`
    evaluable. Without the object at all we return None, and the caller reports `partial`
    rather than inventing an answer.
    """
    for ns in namespaces or []:
        meta = ns.get("metadata", {}) or {}
        if meta.get("name") == namespace:
            labels = dict(meta.get("labels", {}) or {})
            labels.setdefault("kubernetes.io/metadata.name", namespace)
            return labels
    return None


def peer_description(peer: dict, policy_ns: str,
                     namespaces: Optional[list[dict]] = None) -> dict:
    """Turn one ingress `from` / egress `to` entry into structured, readable peer data.

    `evaluable` is False when the peer uses a selector this module cannot evaluate, which
    is what turns a whole direction's status into `partial`.
    """
    ip_block = peer.get("ipBlock") or {}
    if ip_block:
        cidr = ip_block.get("cidr", "")
        return {"type": "ipBlock", "cidr": cidr,
                "except": list(ip_block.get("except") or []),
                "allow_all": cidr in ALLOW_ALL_CIDRS, "evaluable": True,
                "description": f"ipBlock {cidr}" + (
                    f" except {', '.join(ip_block['except'])}"
                    if ip_block.get("except") else "")}

    pod_sel = peer.get("podSelector")
    ns_sel = peer.get("namespaceSelector")
    evaluable = True
    for sel in (pod_sel, ns_sel):
        if sel is not None and selector_matches(sel, {}) is None and sel != {}:
            # A selector we cannot evaluate against ANY labels is unsupported, not merely
            # non-matching (selector_matches returns None only for unsupported constructs).
            evaluable = False

    if ns_sel is None:
        scope = f"namespace {policy_ns}"      # peers default to the policy's own namespace
        ns_names = [policy_ns]
    elif ns_sel == {}:
        scope = "all namespaces"
        ns_names = _all_namespace_names(namespaces)
    else:
        ns_names = _selected_namespaces(ns_sel, namespaces)
        if ns_names is None:
            # Either the Namespace objects were not collected or the selector is
            # unsupported. Either way the peer set is not known, say so.
            evaluable = False
            scope = "namespaces matching a selector (not resolved)"
        else:
            scope = ("namespaces " + ", ".join(ns_names)) if ns_names \
                else "no namespace currently matches this selector"
    pods = "all pods" if pod_sel in (None, {}) else "pods matching a selector"
    return {"type": "selector", "pod_selector": pod_sel, "namespace_selector": ns_sel,
            "namespaces": ns_names, "allow_all": False, "evaluable": evaluable,
            "description": f"{pods} in {scope}"}


def _all_namespace_names(namespaces: Optional[list[dict]]) -> Optional[list[str]]:
    if not namespaces:
        return None
    return sorted((ns.get("metadata", {}) or {}).get("name", "") for ns in namespaces)


def _selected_namespaces(ns_sel: dict,
                         namespaces: Optional[list[dict]]) -> Optional[list[str]]:
    """Namespaces a namespaceSelector picks out, or None when we cannot tell (the Namespace
    objects were not collected, or the selector is unsupported)."""
    if not namespaces:
        return None
    out = []
    for ns in namespaces:
        name = (ns.get("metadata", {}) or {}).get("name", "")
        labels = _ns_labels(name, namespaces) or {}
        hit = selector_matches(ns_sel, labels)
        if hit is None:
            return None
        if hit:
            out.append(name)
    return sorted(out)


def _governs(policy: dict, direction: str) -> bool:
    """Does this policy put `direction` under its control?

    Kubernetes: when `policyTypes` is omitted it defaults to ["Ingress"], plus ["Egress"]
    if the policy has an egress section. Omitting it therefore never implies egress control
    on its own, which is exactly the mistake that would make an unrestricted pod look
    locked down.
    """
    types = (policy.get("spec", {}) or {}).get("policyTypes")
    if types is None:
        if direction == "Ingress":
            return True
        return bool((policy.get("spec", {}) or {}).get("egress"))
    return direction in types


def policies_selecting(policies: list[dict], namespace: Optional[str],
                       pod_labels: dict) -> tuple[list[dict], list[dict]]:
    """(policies that select this pod, policies whose podSelector we could not evaluate).

    A NetworkPolicy only applies inside its own namespace, so the namespace match is exact
    and is not a heuristic.
    """
    selected, unevaluable = [], []
    for policy in policies or []:
        if (policy.get("metadata", {}) or {}).get("namespace") != namespace:
            continue
        sel = (policy.get("spec", {}) or {}).get("podSelector")
        # An absent podSelector in a NetworkPolicySpec is invalid Kubernetes; treat it the
        # way the API server's defaulting does, as {} (select every pod in the namespace).
        hit = selector_matches({} if sel is None else sel, pod_labels)
        if hit is None:
            unevaluable.append(policy)
        elif hit:
            selected.append(policy)
    return selected, unevaluable


def evaluate(policies: list[dict], namespace: Optional[str], pod_labels: dict,
             direction: str = "Ingress",
             namespaces: Optional[list[dict]] = None) -> dict:
    """Evaluate one direction of a pod's network policy, as structured data.

    Kubernetes policies are ADDITIVE: a pod is isolated for a direction once any policy
    governs it, and the allowed peers are the union across every governing policy. One
    allow-all rule therefore defeats isolation no matter how strict its siblings are.
    """
    if policies is None:
        return {"direction": direction, "status": UNKNOWN, "policies": [], "peers": [],
                "reason": "NetworkPolicy evidence was not collected, exposure unknown"}

    selected, unevaluable = policies_selecting(policies, namespace, pod_labels)
    governing = [p for p in selected if _governs(policy=p, direction=direction)]
    names = sorted((p.get("metadata", {}) or {}).get("name", "?") for p in governing)

    if not governing:
        status = PARTIAL if unevaluable else UNRESTRICTED
        reason = (f"no NetworkPolicy governs {direction.lower()} for this pod"
                  if status == UNRESTRICTED else
                  f"{len(unevaluable)} NetworkPolicy(ies) use selector constructs this "
                  f"build cannot evaluate, {direction.lower()} exposure is not confirmed")
        return {"direction": direction, "status": status, "policies": names,
                "peers": [], "reason": reason,
                "unevaluable_policies": _names(unevaluable)}

    key = "ingress" if direction == "Ingress" else "egress"
    peers, allow_all, rule_count, unevaluable_peer = [], False, 0, False
    for policy in governing:
        pol_ns = (policy.get("metadata", {}) or {}).get("namespace", "")
        for rule in (policy.get("spec", {}) or {}).get(key) or []:
            rule_count += 1
            entries = rule.get("from" if direction == "Ingress" else "to")
            if not entries:
                allow_all = True              # empty/absent peer list == every source
                peers.append({"type": "any", "allow_all": True, "evaluable": True,
                              "description": "any peer (rule names no restriction)",
                              "policy": (policy.get("metadata", {}) or {}).get("name", "?")})
                continue
            for entry in entries:
                described = peer_description(entry, pol_ns, namespaces)
                described["policy"] = (policy.get("metadata", {}) or {}).get("name", "?")
                described["ports"] = list(rule.get("ports") or [])
                if described.get("allow_all"):
                    allow_all = True
                if not described.get("evaluable", True):
                    unevaluable_peer = True
                peers.append(described)

    if rule_count == 0:
        status, reason = DENY_ALL, (
            f"NetworkPolicy {', '.join(names)} governs {direction.lower()} with no rules, "
            f"nothing may {'reach' if direction == 'Ingress' else 'leave'} this pod")
    elif allow_all:
        status, reason = ALLOW_ALL, (
            f"NetworkPolicy {', '.join(names)} governs {direction.lower()} but a rule "
            f"admits every peer, this is not isolation")
    elif unevaluable_peer or unevaluable:
        status, reason = PARTIAL, (
            f"NetworkPolicy {', '.join(names)} restricts {direction.lower()}, but at least "
            f"one peer selector could not be evaluated, treat the restriction as unconfirmed")
    else:
        status, reason = RESTRICTED, (
            f"{direction.lower()} restricted by NetworkPolicy {', '.join(names)} to "
            f"{len(peers)} named peer(s)")
    return {"direction": direction, "status": status, "policies": names, "peers": peers,
            "reason": reason, "unevaluable_policies": _names(unevaluable)}


def _names(policies: list[dict]) -> list[str]:
    return sorted((p.get("metadata", {}) or {}).get("name", "?") for p in policies)


#: Statuses that mean "an outside source cannot simply reach this pod". `partial` is
#: deliberately absent: an unconfirmed restriction must not be reported as isolation.
ISOLATING = {RESTRICTED, DENY_ALL}


def isolates(evaluation: dict) -> bool:
    """True when this direction's evaluation shows real, confirmed isolation."""
    return evaluation.get("status") in ISOLATING
