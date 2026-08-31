"""
Unified runtime detection: curated rules stay authoritative, Falco fills the gaps, and
nothing disappears in between.

Two detection engines now feed one evidence model, which creates three ways to be wrong:
claim a provider's verdict as your own, report one event twice because two detectors saw
it, or drop an event neither engine claims. Each test below pins one of those shut.

The governing invariant, asserted directly in
`test_every_event_lands_in_exactly_one_accounted_bucket`:

    every event is matched by a curated rule, relayed under Falco's name, or reported
    unusable WITH a reason. There is no fourth, silent bucket.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import (DETECTION_FALCO, DETECTION_KMW, PROVIDER_FALCO,
                                            PROVIDER_KMW, RuntimeAgent, normalize_events)
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag, ResourceRef,
                                         Severity, Tactic)

AGENT = RuntimeAgent()
_NOW = "2026-09-01T02:00:00+05:30"


def _falco(rule="", priority="Warning", tags=None, **fields):
    """A Falco-native event, in the shape Falco 0.44.1 actually emits."""
    of = {"proc.name": "cat", "evt.type": "open", "k8s.ns.name": "default",
          "k8s.pod.name": "api-9zskz", "container.name": "api", "user.uid": 0}
    of.update({k.replace("__", "."): v for k, v in fields.items()})
    ev = {"source": "syscall", "time": "2026-09-01T01:00:00Z", "output_fields": of,
          "priority": priority}
    if rule:
        ev["rule"] = rule
    if tags is not None:
        ev["tags"] = tags
    return ev


def _one(event):
    alerts = AGENT.evaluate_stream(normalize_events([event]))
    assert len(alerts) == 1, f"expected exactly one finding, got {len(alerts)}"
    return alerts[0]


# =========================================================================== #
# Precedence: curated rules own the verdict
# =========================================================================== #
def test_a_curated_rule_owns_the_verdict_and_keeps_falco_as_supporting_evidence():
    """The overlap case, validated live against a real Falco rule written to collide with
    rt-shell-in-container. Both engines saw the same shell spawn. The curated rule owns the
    finding — its id, its severity, its tactic — and Falco's rule name is retained as
    supporting provider evidence, not raised as a second detection."""
    alert = _one(_falco("Terminal shell in container", priority="Notice",
                        tags=["mitre_execution"], proc__name="bash",
                        evt__type="execve"))
    assert alert.rule_id == "rt-shell-in-container"
    assert alert.detection_source == DETECTION_KMW
    assert alert.provider == PROVIDER_KMW
    assert alert.severity is Severity.HIGH, "our severity, not Falco's Notice"
    assert alert.tactic == Tactic.EXECUTION.value

    p = alert.provenance()
    assert p["provider_rule"] == "Terminal shell in container"
    assert p["supporting_evidence"] == "falco:Terminal shell in container"
    assert p["kmw_equivalent"] is None


def test_one_event_seen_by_both_engines_is_one_finding_not_two():
    """REGRESSION guard for the double-count §9 forbids. Two detectors recognising the same
    syscall is two observations of one fact; counting it twice would inflate the confirmed
    exploitation count, and that number is the strongest claim this tool makes."""
    events = [_falco("Terminal shell in container", tags=["mitre_execution"],
                     proc__name="bash", evt__type="execve")] * 5
    alerts, coverage = AGENT.evaluate_batch(normalize_events(events))
    assert len(alerts) == 5, "five events, five findings"
    assert coverage["kmw_matches"] == 5 and coverage["falco_relays"] == 0
    assert all(a.rule_id == "rt-shell-in-container" for a in alerts)

    finding = _finding()
    out = correlate([finding], alerts, cluster="c1", now=_NOW)
    assert out["total_alerts"] == 5, "volume is reported honestly"
    assert out["confirmed_exploitation"] == 1, "one weakness on one resource is one fact"


def test_a_curated_audit_rule_needs_no_falco_at_all():
    """The 5 audit rules cover the Kubernetes API, which Falco's syscall source cannot see.
    They must keep working with no Falco involvement whatsoever, so a cluster with no
    sensor still detects a RoleBinding being created."""
    alert = _one({"source": "audit", "verb": "create",
                  "resource": "clusterrolebindings", "namespace": "kube-system"})
    assert alert.rule_id == "rt-new-rolebinding"
    assert alert.detection_source == DETECTION_KMW
    assert alert.source == "audit"
    assert alert.provenance()["provider_rule"] is None, "no provider was involved"


# =========================================================================== #
# Fallback: Falco's verdict, relayed under Falco's name
# =========================================================================== #
def test_a_falco_rule_with_no_curated_equivalent_is_relayed_and_attributed():
    alert = _one(_falco("Read sensitive file untrusted",
                        tags=["T1555", "mitre_credential_access"],
                        fd__name="/etc/shadow"))
    assert alert.rule_id == "falco:Read sensitive file untrusted"
    assert alert.detection_source == DETECTION_FALCO
    assert alert.provider == PROVIDER_FALCO
    assert alert.tactic == Tactic.CREDENTIAL_ACCESS.value, "from Falco's own tag"
    p = alert.provenance()
    assert p["provider_rule"] == "Read sensitive file untrusted"
    assert p["kmw_equivalent"] == "none"
    assert p["supporting_evidence"] is None, "the provider IS the detector here"


def test_a_relayed_detection_never_becomes_a_curated_rule():
    """§18 is strict: however many Falco rules an operator enables, none of them may enter
    the curated catalog. The catalog is deliberately small and hand-owned."""
    before = {r.id for r in AGENT.rules}
    for rule in ("Read sensitive file untrusted", "Drop and execute new binary",
                 "Some Brand New Rule An Operator Wrote"):
        _one(_falco(rule, tags=["mitre_execution"]))
    assert {r.id for r in AGENT.rules} == before, "the catalog must not grow by itself"
    assert not any(r.id.startswith("falco:") for r in AGENT.rules)


def test_the_provider_rule_set_is_never_hard_coded():
    """§29: K8sMatrixWarden must reflect whatever Falco currently has enabled, without a
    source change. Validated live by adding two rules to Falco and seeing them handled with
    no code change; asserted here by checking no Falco rule name is baked into the source."""
    import ast
    import inspect

    from k8smatrixwarden.agents import runtime as rt_mod
    # Only executable code counts. Rule names DO appear in docstrings, which explain the
    # defect this design fixed; what must not exist is a rule name the logic branches on.
    tree = ast.parse(inspect.getsource(rt_mod))
    doc_nodes = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr)                 and isinstance(getattr(body[0], "value", None), ast.Constant)                 and isinstance(body[0].value.value, str):
            doc_nodes.add(id(body[0].value))
    literals = [n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in doc_nodes]
    for name in ("Read sensitive file untrusted", "Terminal shell in container",
                 "Drop and execute new binary", "Launch Privileged Container"):
        assert not any(name in lit for lit in literals),             f"Falco rule {name!r} is hard-coded in executable code"


def test_several_distinct_falco_rules_all_relay_independently():
    events = [_falco("Rule A", tags=["mitre_execution"]),
              _falco("Rule B", tags=["mitre_discovery"]),
              _falco("Rule C", tags=["mitre_impact"])]
    alerts, coverage = AGENT.evaluate_batch(normalize_events(events))
    assert coverage["falco_relays"] == 3 and coverage["kmw_matches"] == 0
    assert {a.rule_id for a in alerts} == {"falco:Rule A", "falco:Rule B", "falco:Rule C"}
    assert {a.tactic for a in alerts} == {Tactic.EXECUTION.value, Tactic.DISCOVERY.value,
                                          Tactic.IMPACT.value}


# =========================================================================== #
# Metadata is preserved, never invented
# =========================================================================== #
def test_an_untagged_falco_rule_gets_unknown_not_an_inferred_tactic():
    """Validated live with a purpose-built untagged Falco rule. A tactic is a claim; where
    the provider makes none, neither do we. Inferring one from the rule name would be
    exactly the fabrication §7 forbids."""
    alert = _one(_falco("KMW validation untagged rule", tags=["container"],
                        proc__name="whoami"))
    assert alert.rule_id == "falco:KMW validation untagged rule"
    assert alert.tactic == "Unknown"
    assert alert.tactic not in {t.value for t in Tactic}, "not a real tactic value"


def test_falco_priority_maps_deterministically_and_only_once():
    """§8: one authoritative mapping, and a plain Warning must not silently become
    Critical."""
    from k8smatrixwarden.agents.runtime import _FALCO_PRIORITY
    expected = {"emergency": Severity.CRITICAL, "alert": Severity.CRITICAL,
                "critical": Severity.CRITICAL, "error": Severity.HIGH,
                "warning": Severity.MEDIUM, "notice": Severity.LOW,
                "informational": Severity.INFO, "info": Severity.INFO,
                "debug": Severity.INFO}
    assert _FALCO_PRIORITY == expected
    for priority, severity in expected.items():
        alert = _one(_falco("R", priority=priority, tags=["mitre_execution"]))
        assert alert.severity is severity, priority
    # An unknown priority string falls to MEDIUM rather than to the top of the scale.
    assert _one(_falco("R", priority="wat", tags=["mitre_execution"])).severity \
        is Severity.MEDIUM

    # The mapping lives in exactly one module.
    import inspect
    for mod_name in ("k8smatrixwarden.core.reporting", "k8smatrixwarden.mcp.server",
                     "k8smatrixwarden.core.correlation"):
        mod = __import__(mod_name, fromlist=["x"])
        assert "emergency" not in inspect.getsource(mod).lower(), \
            f"{mod_name} appears to duplicate the priority mapping"


def test_missing_provider_fields_stay_missing():
    """Absent metadata is reported absent, not filled in."""
    bare = {"source": "syscall", "rule": "Sparse Rule", "tags": ["mitre_impact"],
            "output_fields": {}}
    alert = _one(bare)
    assert alert.rule_id == "falco:Sparse Rule"
    assert alert.event.get("namespace") is None and alert.event.get("pod") is None
    assert alert.provenance()["provider_priority"] in (None, "")


# =========================================================================== #
# The invariant: no silent fourth state
# =========================================================================== #
def test_every_event_lands_in_exactly_one_accounted_bucket():
    """The whole point of the accounting. Anything not detected is reported unusable with a
    reason, so a coverage gap can never look like a quiet cluster."""
    events = [
        _falco("Terminal shell in container", tags=["mitre_execution"],
               proc__name="bash", evt__type="execve"),          # curated
        _falco("Read sensitive file untrusted",
               tags=["mitre_credential_access"]),               # relayed
        {"source": "audit", "verb": "create",
         "resource": "clusterrolebindings"},                    # curated (audit)
        {"source": "falco", "proc": "nginx"},                   # nothing claims it
        {"source": "falco"},                                    # no rule, no match
    ]
    alerts, cov = AGENT.evaluate_batch(normalize_events(events))
    assert cov["events_received"] == 5
    assert cov["kmw_matches"] + cov["falco_relays"] + cov["unusable_events"] == 5
    assert cov["discarded"] == 0
    assert cov["kmw_matches"] == 2 and cov["falco_relays"] == 1
    assert cov["unusable_events"] == 2
    for entry in cov["unusable"]:
        assert entry["reason"], "an unusable event must say why"
        assert "discard" not in entry["reason"].lower()
    assert len(alerts) == 3


def test_malformed_events_are_rejected_with_a_reason_not_dropped():
    alerts, cov = AGENT.evaluate_batch([None, "not-an-event", {}, 42])
    assert alerts == []
    assert cov["events_received"] == 4 and cov["unusable_events"] == 4
    assert cov["discarded"] == 0
    assert any("malformed" in e["reason"] for e in cov["unusable"])


def test_an_empty_batch_is_not_mistaken_for_a_clean_cluster():
    alerts, cov = AGENT.evaluate_batch([])
    assert alerts == [] and cov["events_received"] == 0 and cov["discarded"] == 0


# =========================================================================== #
# Relayed detections get the same correlation treatment, and no more
# =========================================================================== #
def _finding(kind="Deployment", name="api", ns="default",
             tactic=Tactic.EXECUTION, rule="workload-sa-token-automount"):
    f = Finding(rule_id=rule, title="t", severity=Severity.HIGH,
                resource=ResourceRef(kind, name, ns), message="m",
                mitre=[MitreTag(tactic, "T1059", "Cmd")],
                detection_method=DetectionMethod.STATIC_CONFIG)
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": kind, "name": name, "detail": ns}]
    return f


def test_a_relayed_detection_correlates_like_any_other_but_gains_no_free_confidence():
    """§13: same pipeline, same rules of evidence. A provider fallback must not be
    privileged, and must not be penalised either."""
    alerts = AGENT.evaluate_stream(normalize_events(
        [_falco("Read sensitive file untrusted",
                tags=["mitre_credential_access"])]))
    out = correlate([_finding(tactic=Tactic.CREDENTIAL_ACCESS)], alerts,
                    cluster="c1", now=_NOW)
    entry = out["correlations"][0]
    assert entry["confidence"] == "confirmed", "same resource, so the same verdict"
    assert entry["runtime"]["detection_source"] == DETECTION_FALCO
    assert entry["freshness"] in ("recent", "historical", "unknown")


def test_a_relayed_detection_cannot_confirm_across_an_identity_boundary():
    """§15, validated live: 22 shell events whose pod/namespace Falco could not resolve
    produced 0 confirmations. Identity is required for a resource-level claim."""
    kmw_finding = _finding(tactic=Tactic.CREDENTIAL_ACCESS)
    cases = {
        "wrong namespace": _falco("Read sensitive file untrusted",
                                  tags=["mitre_credential_access"],
                                  k8s__ns__name="other-ns"),
        "no identity at all": {"source": "syscall", "rule": "Read sensitive file untrusted",
                               "tags": ["mitre_credential_access"], "output_fields": {}},
    }
    for label, event in cases.items():
        alerts = AGENT.evaluate_stream(normalize_events([event]))
        out = correlate([kmw_finding], alerts, cluster="c1", now=_NOW)
        assert out["confirmed_exploitation"] == 0, f"{label} must not confirm"

    # And the control: correct identity still confirms.
    ok = AGENT.evaluate_stream(normalize_events(
        [_falco("Read sensitive file untrusted", tags=["mitre_credential_access"])]))
    assert correlate([kmw_finding], ok, cluster="c1",
                     now=_NOW)["confirmed_exploitation"] == 1


def test_a_stale_relayed_detection_is_not_current_exploitation():
    """§14: the fallback path must not bypass freshness."""
    old = _falco("Read sensitive file untrusted", tags=["mitre_credential_access"])
    old["time"] = "2019-01-01T00:00:00Z"
    out = correlate([_finding(tactic=Tactic.CREDENTIAL_ACCESS)],
                    AGENT.evaluate_stream(normalize_events([old])),
                    cluster="c1", now=_NOW)
    entry = out["correlations"][0]
    assert entry["freshness"] == "historical" and entry["age_days"] > 2000


def test_runtime_findings_are_deterministically_ordered():
    """§30: identical input, identical output, every time."""
    events = [_falco(f"Rule {c}", tags=["mitre_execution"]) for c in "CABED"]
    runs = [[a.rule_id for a in AGENT.evaluate_stream(normalize_events(events))]
            for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]


# =========================================================================== #
# Provenance reaches the surfaces
# =========================================================================== #
def test_provenance_is_exposed_through_correlation_and_mcp():
    alerts = AGENT.evaluate_stream(normalize_events(
        [_falco("Terminal shell in container", tags=["mitre_execution"],
                proc__name="bash", evt__type="execve")]))
    entry = correlate([_finding()], alerts, cluster="c1", now=_NOW)["correlations"][0]
    rt = entry["runtime"]
    assert rt["detection_source"] == DETECTION_KMW
    assert rt["provider"] == PROVIDER_KMW
    assert rt["supporting_evidence"] == "falco:Terminal shell in container"

    from k8smatrixwarden.mcp.server import build_tools
    out = build_tools()["evaluate_runtime_events"](events=[
        _falco("Read sensitive file untrusted", tags=["mitre_credential_access"])])
    assert out["coverage"]["falco_relays"] == 1 and out["coverage"]["discarded"] == 0
    assert out["alerts"][0]["provenance"]["detection_source"] == DETECTION_FALCO


def test_reports_state_who_detected_each_runtime_finding():
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    from k8smatrixwarden.core.reporting import ReportingEngine

    p = build_platform()
    result = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    alerts, coverage = AGENT.evaluate_batch(normalize_events(
        [_falco("Read sensitive file untrusted", tags=["mitre_credential_access"])]))
    result.runtime = {"source": "falco-logs", "collected_at": _NOW, "cluster": "c1",
                      "events_seen": 1, "detection_coverage": coverage,
                      "correlation": correlate([_finding(tactic=Tactic.CREDENTIAL_ACCESS)],
                                               alerts, cluster="c1", now=_NOW),
                      "drift": {"drift": []}}
    engine = ReportingEngine()
    for fmt in ("terminal", "text", "markdown", "html"):
        body = engine.render(result, fmt)
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        assert "Falco" in body, f"{fmt} does not name the detector"
        assert "discarded" in body.lower(), f"{fmt} does not state the discard count"


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
