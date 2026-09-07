"""
NetworkPolicy tri-state, from policy objects a real API server accepted and stored.

Every spec below was applied to a live Docker Desktop cluster and read back with
`kubectl get netpol -o jsonpath={.spec}`, so these are the exact shapes Kubernetes
normalises to -- not hand-written approximations of them. KMW's verdict matched the
policy semantics in all four evaluable states on that cluster.

TWO THINGS THIS FILE DOES NOT CLAIM, because the live run established that it cannot:

`partial` is not reachable through a conformant API server. A selector operator outside
In/NotIn/Exists/DoesNotExist is rejected at admission -- the cluster answered
`Invalid value: "SortOfMaybeIn": not a valid selector operator`. So `partial` is a
defensive state for objects that never came from a healthy API server (a fixture, a
mangled export, an operator a future Kubernetes adds), and it can only be tested here.

Enforcement is not tested at all. KMW reports what the DECLARED policy permits, which is a
different question from what the network actually does, and the two must not be conflated.
On the audit cluster kindnet is the CNI and does not implement NetworkPolicy; cross-namespace
pod traffic was blocked there even in a namespace with no policy whatsoever, so observed
traffic could not have validated anything.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core import netpol
from k8smatrixwarden.core.netpol import selector_matches

TARGET = {"app": "target"}
PROBER = {"app": "client", "role": "prober"}

#: `kubectl get netpol -o jsonpath={.spec}`, verbatim, from the live cluster.
DENY_ALL = {"podSelector": {}, "policyTypes": ["Ingress"]}
ALLOW_ALL = {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]}
RESTRICTED = {
    "podSelector": {"matchLabels": {"app": "target"}},
    "policyTypes": ["Ingress"],
    "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"tier": "open"}},
                           "podSelector": {"matchLabels": {"role": "prober"}}}]}]}


def test_the_six_states_are_the_documented_set():
    """Six, not three. A restriction that could not be confirmed has its own answer."""
    assert {netpol.UNRESTRICTED, netpol.ALLOW_ALL, netpol.RESTRICTED, netpol.DENY_ALL,
            netpol.PARTIAL, netpol.UNKNOWN} == {
        "unrestricted", "allow-all", "restricted", "deny-all", "partial", "unknown"}
    assert netpol.SUPPORTED_OPERATORS == ("In", "NotIn", "Exists", "DoesNotExist"), (
        "these are exactly the operators a conformant API server will accept")


# --------------------------------------------------------------------------- #
# Selector semantics, against the labels the live pods actually carried
# --------------------------------------------------------------------------- #

def test_an_empty_selector_matches_everything():
    """Kubernetes semantics, and the reason ALLOW_ALL's podSelector governs every pod."""
    assert selector_matches({}, TARGET) is True
    assert selector_matches({}, {}) is True


def test_matchlabels_is_an_and_not_an_or():
    assert selector_matches({"matchLabels": {"app": "client", "role": "prober"}},
                            PROBER) is True
    assert selector_matches({"matchLabels": {"app": "client", "role": "admin"}},
                            PROBER) is False


def test_every_kubernetes_set_operator_is_supported():
    """These four are the only operators the API server accepts, so these four are the
    only ones that can ever arrive from a real cluster."""
    assert selector_matches(
        {"matchExpressions": [{"key": "role", "operator": "In",
                               "values": ["prober", "admin"]}]}, PROBER) is True
    assert selector_matches(
        {"matchExpressions": [{"key": "role", "operator": "NotIn",
                               "values": ["prober"]}]}, PROBER) is False
    assert selector_matches(
        {"matchExpressions": [{"key": "role", "operator": "Exists"}]}, PROBER) is True
    assert selector_matches(
        {"matchExpressions": [{"key": "missing", "operator": "DoesNotExist"}]},
        PROBER) is True


def test_an_unknown_operator_is_unevaluable_rather_than_false():
    """None, not False. `False` would read as 'this peer does not match', which is a
    claim; the truth is that this build cannot say -- and that is what turns a direction
    into `partial` instead of quietly narrowing it."""
    found = selector_matches(
        {"matchExpressions": [{"key": "role", "operator": "SortOfMaybeIn",
                               "values": ["prober"]}]}, PROBER)
    assert found is None, found


def test_an_expression_with_no_key_is_unevaluable():
    """No key means there is nothing to compare, so the answer is 'cannot say'."""
    assert selector_matches(
        {"matchExpressions": [{"operator": "In", "values": ["x"]}]}, PROBER) is None


def test_in_with_no_values_matches_nothing_rather_than_being_unevaluable():
    """`In []` is answerable: nothing is a member of the empty set. That is False, a real
    verdict, and must not be softened into `partial`."""
    assert selector_matches(
        {"matchExpressions": [{"key": "role", "operator": "In"}]}, PROBER) is False


# --------------------------------------------------------------------------- #
# The states, end to end through the analyzer
# --------------------------------------------------------------------------- #

def _verdict(policies, pod_labels=TARGET, namespace="np-test", namespaces=None):
    """One direction, the way the analyzer is actually called."""
    from k8smatrixwarden.core.netpol import evaluate
    return evaluate(policies, namespace, dict(pod_labels), "Ingress", namespaces or [
        {"metadata": {"name": "np-test", "labels": {"tier": "closed"}}},
        {"metadata": {"name": "np-unrestricted", "labels": {"tier": "open"}}}])


def test_no_policy_is_unrestricted_not_secure():
    """The Kubernetes default is wide open, and saying so is the point of this state."""
    assert _verdict([])["status"] == "unrestricted"


def test_a_governing_policy_with_no_rules_is_deny_all():
    assert _verdict([_ns(DENY_ALL)])["status"] == "deny-all"


def test_an_empty_ingress_rule_is_allow_all():
    """`ingress: [{}]` -- a rule with no `from` -- admits every peer. Read as `restricted`
    it would report isolation that does not exist."""
    assert _verdict([_ns(ALLOW_ALL)])["status"] == "allow-all"


def test_named_peers_are_restricted_and_returned():
    found = _verdict([_ns(RESTRICTED)])
    assert found["status"] == "restricted"
    assert found["peers"], "a restricted direction must say which peers it admits"


def test_an_unevaluable_peer_makes_the_direction_partial_not_restricted():
    """The state a conformant API server cannot produce, and the reason it exists: an
    unconfirmed restriction must never be presented as isolation."""
    unevaluable = {"podSelector": {"matchLabels": {"app": "target"}},
                   "policyTypes": ["Ingress"],
                   "ingress": [{"from": [{"podSelector": {"matchExpressions": [
                       {"key": "role", "operator": "SortOfMaybeIn",
                        "values": ["prober"]}]}}]}]}
    found = _verdict([_ns(unevaluable)])
    assert found["status"] == "partial", found
    # The peer that could not be read is flagged, and the reason says so in words, so a
    # reader is never left to infer that an unconfirmed restriction was isolation.
    assert any(p.get("evaluable") is False for p in found["peers"]), found["peers"]
    assert "unconfirmed" in found["reason"], found["reason"]
    assert not netpol.isolates(found), (
        "a partial direction must not count as isolation; that is the whole point of the "
        "state")


def _ns(spec, namespace="np-test", name="p"):
    return {"metadata": {"name": name, "namespace": namespace}, "spec": spec}


def test_a_policy_in_another_namespace_does_not_govern_this_pod():
    """NetworkPolicy is namespaced. A deny-all next door isolates nothing here."""
    elsewhere = _ns(DENY_ALL, namespace="somewhere-else")
    assert _verdict([elsewhere])["status"] == "unrestricted"


if __name__ == "__main__":
    import traceback
    failed = 0
    for key, fn in sorted(globals().items()):
        if key.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {key}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
