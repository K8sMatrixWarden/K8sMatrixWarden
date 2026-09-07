"""
Runtime correlation, written from a live Falco event rather than an imagined one.

The seed is a real alert captured from Falco 0.44.1 on a Docker Desktop cluster running
Kubernetes Goat: rule `Read sensitive file untrusted`, priority Warning, tagged T1555 /
mitre_credential_access, naming pod `build-code-deployment-5f9586cd5b-klddd` in `default`
and container `5088f0a14286`. Every field below is copied from that event, so the shapes
these tests assert are shapes Falco actually emits.

What the live run caught: the `confirmed` verdict read "static weakness on this resource is
being actively exploited", and the weakness it named was `workload-sa-token-automount`.
Reading /etc/shadow does not exploit an auto-mounted service-account token. Both are
Credential Access on the same pod, so `confirmed` is the right tier -- but the sentence
asserted a route the evidence never established, and an operator acting on it triages the
wrong weakness. The tier is unchanged here; the claim is not.
"""
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Severity, Tactic)

#: Copied from the captured alert.
LIVE_POD = "build-code-deployment-5f9586cd5b-klddd"
LIVE_NS = "default"
LIVE_CONTAINER = "5088f0a14286"
NOW = dt.datetime(2026, 9, 7, 19, 10, 0, tzinfo=dt.timezone.utc)


def _event(pod=LIVE_POD, namespace=LIVE_NS, minutes_ago=5, **extra):
    """The live Falco event, with one field varied at a time."""
    when = (NOW - dt.timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = {"source": "falco", "rule": "Read sensitive file untrusted",
            "priority": "Warning", "time": when, "file": "/etc/shadow",
            "proc": "head", "namespace": namespace, "pod": pod,
            "container_id": LIVE_CONTAINER,
            "tags": ["T1555", "mitre_credential_access"]}
    base.update(extra)
    return base


def _finding(kind="Pod", name=LIVE_POD, namespace=LIVE_NS,
             rule="workload-sa-token-automount", tactic=Tactic.CREDENTIAL_ACCESS):
    return Finding(rule_id=rule, title="SA token auto-mounted", severity=Severity.MEDIUM,
                   resource=ResourceRef(kind=kind, name=name, namespace=namespace),
                   message="m", owning_shard="workload_pod_security",
                   mitre=[MitreTag(tactic, "T1552", "Unsecured Credentials")])


def _correlate(findings, events, cluster="docker-desktop"):
    alerts = RuntimeAgent().evaluate_stream(normalize_events(events))
    return correlate(findings, alerts, now=NOW, cluster=cluster)


def _one(findings, events, **kw):
    out = _correlate(findings, events, **kw)["correlations"]
    return out[0] if out else None


# --------------------------------------------------------------------------- #
# 2.5 -- the correlation cases, each with its own evidence
# --------------------------------------------------------------------------- #

def test_case_a_same_resource_confirms():
    """A. The event names the very pod the finding is on."""
    entry = _one([_finding()], [_event()])
    assert entry["confidence"] == "confirmed", entry
    assert entry["freshness"] == "recent"


def test_case_b_a_generated_pod_confirms_its_owning_workload():
    """B. Falco names a Pod; the finding is on the Deployment that owns it. The ownership
    test is the generated-name relationship, not a prefix guess."""
    entry = _one([_finding(kind="Deployment", name="build-code-deployment")], [_event()])
    assert entry["confidence"] == "confirmed", entry
    assert "belongs to" in entry["reason"], entry["reason"]


def test_case_b_negative_a_shared_prefix_is_not_ownership():
    """The same test must reject a workload that merely starts with the same letters."""
    entry = _one([_finding(kind="Deployment", name="build")], [_event()])
    assert entry is None or entry["confidence"] != "confirmed", entry


def test_case_c_a_different_workload_is_not_confirmed():
    """C. Same rule, same tactic, different resource: aligns, not proven."""
    entry = _one([_finding(kind="Pod", name="metadata-db-bc696c464-xg55d")], [_event()])
    assert entry["confidence"] == "corroborated", entry
    assert "no resource-level link" in entry["verdict"]


def test_case_d_the_same_pod_name_in_another_namespace_is_not_confirmed():
    """D. Namespace is part of identity. This is the collision an attacker gets for free
    by naming a workload the same thing in a namespace they control."""
    entry = _one([_finding(namespace="staging")], [_event()])
    assert entry["confidence"] != "confirmed", entry


def test_case_e_an_event_from_another_cluster_cannot_confirm():
    """E. A feed aggregating clusters can deliver an event about a same-named pod."""
    entry = _one([_finding()], [_event(cluster="other-cluster")],
                 cluster="docker-desktop")
    assert entry["confidence"] == "corroborated", entry
    assert "another cluster cannot confirm" in entry["verdict"], entry["verdict"]


def test_case_f_incomplete_identity_cannot_confirm():
    """F. No pod name means no resource link, whatever else the event carries."""
    for missing in ({"pod": ""}, {"pod": None}, {"namespace": ""}):
        entry = _one([_finding()], [_event(**missing)])
        assert entry is None or entry["confidence"] != "confirmed", (missing, entry)


def test_a_runtime_event_with_no_static_finding_is_runtime_only():
    entry = _one([], [_event()])
    assert entry is None or entry["confidence"] == "runtime-only"


# --------------------------------------------------------------------------- #
# The verdict may not claim a route it did not establish
# --------------------------------------------------------------------------- #

def test_a_confirmed_verdict_states_the_link_not_the_route():
    """REGRESSION from live validation. `confirmed` means tactic + resource, and the
    sentence must say that and stop there."""
    entry = _one([_finding()], [_event()])
    assert entry["confidence"] == "confirmed"
    verdict = entry["verdict"]
    assert "is being actively exploited" not in verdict, verdict
    assert "does not prove" in verdict, verdict
    assert "Credential Access" in verdict, "the matched tactic should be named"
    # The reader still gets every matched finding and can judge the route themselves.
    assert entry["static_findings"], "matched findings must remain in the output"


def test_a_stale_confirmed_verdict_is_past_tense_and_dated():
    entry = _one([_finding()], [_event(minutes_ago=60 * 24 * 30)])
    assert entry["confidence"] == "confirmed", "the resource link survives age"
    assert entry["freshness"] == "historical"
    assert "occurred" in entry["verdict"]
    assert "history, not a live intrusion" in entry["verdict"]


# --------------------------------------------------------------------------- #
# 2.8 -- provenance: severity and tactic come from the provider, or not at all
# --------------------------------------------------------------------------- #

def test_the_tactic_comes_from_falcos_own_tags():
    """T1555 / mitre_credential_access is on the live event. KMW must read it, not guess."""
    alerts = RuntimeAgent().evaluate_stream(normalize_events([_event()]))
    assert alerts, "the live event shape produced no alert at all"
    assert alerts[0].tactic == Tactic.CREDENTIAL_ACCESS.value, alerts[0].tactic


def test_no_tactic_is_invented_when_falco_supplies_none():
    """An event with no MITRE tag must not acquire one on the way through."""
    alerts = RuntimeAgent().evaluate_stream(normalize_events(
        [_event(rule="Some Unmapped Custom Rule", tags=[])]))
    for a in alerts:
        assert a.tactic in ("", None) or a.provider_rule, (
            f"tactic {a.tactic!r} appeared for an event carrying no MITRE tag")


def test_falco_provenance_is_never_reported_as_a_kmw_detection():
    """A relayed provider verdict must stay labelled as one."""
    alerts = RuntimeAgent().evaluate_stream(normalize_events([_event()]))
    relayed = [a for a in alerts if a.detection_source == "falco"]
    assert relayed, "the live Falco rule was not relayed"
    for a in relayed:
        assert a.provider == "falco"
        assert a.rule_id.startswith("falco:"), a.rule_id


# --------------------------------------------------------------------------- #
# 2.6 -- deduplication
# --------------------------------------------------------------------------- #

def test_one_event_yields_one_alert_not_one_per_detector():
    """When a curated KMW rule and Falco both describe the same event, the result is one
    alert carrying both provenances -- not two findings for one thing that happened."""
    alerts = RuntimeAgent().evaluate_stream(normalize_events([_event()]))
    assert len(alerts) == 1, [a.rule_id for a in alerts]


def test_two_genuinely_different_events_stay_two():
    """Dedup must not swallow distinct activity."""
    alerts = RuntimeAgent().evaluate_stream(normalize_events([
        _event(),
        _event(rule="Terminal shell in container", proc="bash",
               tags=["T1059", "mitre_execution"], minutes_ago=4)]))
    assert len(alerts) == 2, [a.rule_id for a in alerts]


def test_every_event_is_accounted_for():
    """The accounting invariant: nothing is silently discarded."""
    _alerts, coverage = RuntimeAgent().evaluate_batch(
        normalize_events([_event(), {"source": "falco"}]))
    assert coverage["discarded"] == 0, coverage
    seen = (coverage["kmw_matches"] + coverage["falco_relays"]
            + coverage["unusable_events"])
    assert seen == coverage["events_received"] == 2, coverage
    for entry in coverage.get("unusable") or []:
        assert entry.get("reason"), "an unusable event must say why"


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
