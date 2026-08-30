"""
NetworkPolicy evaluation (core/netpol.py): Kubernetes selector semantics, both directions.

Two things are being defended here. First, correctness against the real Kubernetes rules
(an empty selector selects everything; NotIn is satisfied by an absent key; policyTypes
defaults to Ingress only). Second, and more important for a security tool: the refusal to
report a restriction it could not actually evaluate as if it were isolation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core import netpol


def _policy(name, ns="prod", pod_selector=None, ingress=None, egress=None,
            policy_types=None):
    spec = {"podSelector": {} if pod_selector is None else pod_selector}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    if policy_types is not None:
        spec["policyTypes"] = policy_types
    return {"kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns},
            "spec": spec}


def _ns(name, labels=None):
    return {"kind": "Namespace", "metadata": {"name": name, "labels": labels or {}}}


LABELS = {"app": "web", "tier": "frontend"}


# --------------------------------------------------------------------------- #
# Selector semantics
# --------------------------------------------------------------------------- #
def test_empty_selector_matches_everything():
    assert netpol.selector_matches({}, {}) is True
    assert netpol.selector_matches({}, LABELS) is True


def test_none_selector_is_not_evaluable():
    assert netpol.selector_matches(None, LABELS) is None


def test_match_labels_all_must_match():
    assert netpol.selector_matches({"matchLabels": {"app": "web"}}, LABELS) is True
    assert netpol.selector_matches(
        {"matchLabels": {"app": "web", "tier": "backend"}}, LABELS) is False


def test_match_expressions_in():
    sel = {"matchExpressions": [{"key": "app", "operator": "In",
                                 "values": ["web", "api"]}]}
    assert netpol.selector_matches(sel, LABELS) is True
    assert netpol.selector_matches(sel, {"app": "db"}) is False


def test_match_expressions_not_in_is_satisfied_by_a_missing_key():
    # Kubernetes: a pod that does not carry the key satisfies NotIn.
    sel = {"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["db"]}]}
    assert netpol.selector_matches(sel, LABELS) is True
    assert netpol.selector_matches(sel, {}) is True
    assert netpol.selector_matches(sel, {"app": "db"}) is False


def test_match_expressions_exists_and_does_not_exist():
    exists = {"matchExpressions": [{"key": "tier", "operator": "Exists"}]}
    missing = {"matchExpressions": [{"key": "tier", "operator": "DoesNotExist"}]}
    assert netpol.selector_matches(exists, LABELS) is True
    assert netpol.selector_matches(exists, {"app": "web"}) is False
    assert netpol.selector_matches(missing, {"app": "web"}) is True
    assert netpol.selector_matches(missing, LABELS) is False


def test_match_labels_and_expressions_combine_with_and():
    sel = {"matchLabels": {"app": "web"},
           "matchExpressions": [{"key": "tier", "operator": "In", "values": ["backend"]}]}
    assert netpol.selector_matches(sel, LABELS) is False


def test_unknown_operator_is_unevaluable_not_a_non_match():
    sel = {"matchExpressions": [{"key": "app", "operator": "Matches", "values": ["w.*"]}]}
    assert netpol.selector_matches(sel, LABELS) is None


# --------------------------------------------------------------------------- #
# Direction: governance, defaults, and the additive union
# --------------------------------------------------------------------------- #
def test_no_policy_means_unrestricted_in_both_directions():
    for direction in ("Ingress", "Egress"):
        out = netpol.evaluate([], "prod", LABELS, direction)
        assert out["status"] == netpol.UNRESTRICTED
        assert not netpol.isolates(out)


def test_missing_evidence_is_unknown_not_unrestricted():
    out = netpol.evaluate(None, "prod", LABELS, "Ingress")
    assert out["status"] == netpol.UNKNOWN and not netpol.isolates(out)


def test_default_deny_ingress_is_deny_all():
    out = netpol.evaluate([_policy("deny", policy_types=["Ingress"])],
                          "prod", LABELS, "Ingress")
    assert out["status"] == netpol.DENY_ALL and netpol.isolates(out)


def test_omitted_policy_types_governs_ingress_but_not_egress():
    # Kubernetes defaults policyTypes to ["Ingress"] (+ Egress only if egress rules exist).
    policy = _policy("p", ingress=[{"from": [{"podSelector": {"matchLabels": {"a": "b"}}}]}])
    assert netpol.evaluate([policy], "prod", LABELS, "Ingress")["status"] == \
        netpol.RESTRICTED
    assert netpol.evaluate([policy], "prod", LABELS, "Egress")["status"] == \
        netpol.UNRESTRICTED


def test_egress_rules_alone_govern_egress():
    policy = _policy("p", egress=[{"to": [{"podSelector": {"matchLabels": {"a": "b"}}}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Egress")
    assert out["status"] == netpol.RESTRICTED and netpol.isolates(out)


def test_empty_from_is_allow_all_and_defeats_isolation():
    out = netpol.evaluate([_policy("open", ingress=[{}])], "prod", LABELS, "Ingress")
    assert out["status"] == netpol.ALLOW_ALL and not netpol.isolates(out)


def test_world_cidr_is_allow_all():
    policy = _policy("open", ingress=[{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}])
    assert netpol.evaluate([policy], "prod", LABELS, "Ingress")["status"] == \
        netpol.ALLOW_ALL


def test_policies_are_additive_one_allow_all_defeats_a_strict_sibling():
    strict = _policy("strict", ingress=[{"from": [{"podSelector":
                                                   {"matchLabels": {"a": "b"}}}]}])
    lax = _policy("lax", ingress=[{}])
    out = netpol.evaluate([strict, lax], "prod", LABELS, "Ingress")
    assert out["status"] == netpol.ALLOW_ALL
    assert out["policies"] == ["lax", "strict"]


def test_policy_in_another_namespace_does_not_apply():
    out = netpol.evaluate([_policy("deny", ns="staging", policy_types=["Ingress"])],
                          "prod", LABELS, "Ingress")
    assert out["status"] == netpol.UNRESTRICTED


def test_policy_selecting_by_expression_is_matched():
    policy = _policy("deny", pod_selector={
        "matchExpressions": [{"key": "tier", "operator": "In", "values": ["frontend"]}]},
        policy_types=["Ingress"])
    assert netpol.evaluate([policy], "prod", LABELS, "Ingress")["status"] == \
        netpol.DENY_ALL


def test_unevaluable_pod_selector_yields_partial_not_isolation():
    policy = _policy("weird", pod_selector={
        "matchExpressions": [{"key": "app", "operator": "Regex", "values": ["w.*"]}]},
        policy_types=["Ingress"])
    out = netpol.evaluate([policy], "prod", LABELS, "Ingress")
    assert out["status"] == netpol.PARTIAL
    assert not netpol.isolates(out), "an unconfirmed restriction must not read as isolation"
    assert out["unevaluable_policies"] == ["weird"]


def test_unevaluable_peer_selector_yields_partial():
    policy = _policy("p", ingress=[{"from": [{"podSelector": {
        "matchExpressions": [{"key": "x", "operator": "Regex", "values": ["y"]}]}}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Ingress")
    assert out["status"] == netpol.PARTIAL and not netpol.isolates(out)


# --------------------------------------------------------------------------- #
# Peers: podSelector / namespaceSelector / ipBlock
# --------------------------------------------------------------------------- #
def test_namespace_selector_resolves_to_named_namespaces():
    policy = _policy("p", ingress=[{"from": [{"namespaceSelector": {
        "matchLabels": {"env": "prod"}}}]}])
    namespaces = [_ns("prod", {"env": "prod"}), _ns("staging", {"env": "staging"})]
    out = netpol.evaluate([policy], "prod", LABELS, "Ingress", namespaces)
    peer = out["peers"][0]
    assert peer["namespaces"] == ["prod"] and peer["evaluable"] is True


def test_namespace_selector_matches_the_builtin_metadata_name_label():
    policy = _policy("p", egress=[{"to": [{"namespaceSelector": {
        "matchLabels": {"kubernetes.io/metadata.name": "db"}}}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Egress", [_ns("db"), _ns("prod")])
    assert out["peers"][0]["namespaces"] == ["db"]


def test_peer_without_namespace_selector_stays_in_the_policy_namespace():
    policy = _policy("p", ingress=[{"from": [{"podSelector":
                                              {"matchLabels": {"app": "api"}}}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Ingress")
    assert out["peers"][0]["namespaces"] == ["prod"]


def test_ip_block_peer_is_described_with_its_exceptions():
    policy = _policy("p", egress=[{"to": [{"ipBlock": {"cidr": "10.0.0.0/8",
                                                       "except": ["10.1.0.0/16"]}}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Egress")
    peer = out["peers"][0]
    assert peer["type"] == "ipBlock" and peer["except"] == ["10.1.0.0/16"]
    assert out["status"] == netpol.RESTRICTED


def test_combined_selectors_on_one_peer_are_both_reported():
    policy = _policy("p", egress=[{"to": [{"namespaceSelector": {},
                                           "podSelector": {"matchLabels": {"a": "b"}}}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Egress", [_ns("prod")])
    peer = out["peers"][0]
    assert peer["pod_selector"] == {"matchLabels": {"a": "b"}}
    assert peer["namespace_selector"] == {}


def test_ports_travel_with_the_peer():
    policy = _policy("p", ingress=[{"from": [{"podSelector": {"matchLabels": {"a": "b"}}}],
                                    "ports": [{"port": 8080, "protocol": "TCP"}]}])
    out = netpol.evaluate([policy], "prod", LABELS, "Ingress")
    assert out["peers"][0]["ports"] == [{"port": 8080, "protocol": "TCP"}]


def test_policies_selecting_reports_unevaluable_separately():
    good = _policy("good", pod_selector={"matchLabels": {"app": "web"}})
    bad = _policy("bad", pod_selector={
        "matchExpressions": [{"key": "app", "operator": "Nope", "values": []}]})
    selected, unevaluable = netpol.policies_selecting([good, bad], "prod", LABELS)
    assert [p["metadata"]["name"] for p in selected] == ["good"]
    assert [p["metadata"]["name"] for p in unevaluable] == ["bad"]


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
