"""
Runtime identity: recovering the resource behind an event, without ever guessing it.

Falco usually enriches events with the Pod and namespace. When it cannot — on the
validation cluster it logged `libpman: disabled BPF iterators (not running in the root PID
namespace)` and emitted a run of events carrying only a container id — the event is still a
real observation, and the correlator already refuses to confirm it. That is safe but
uninformative: "we saw something we could not place" looked identical to "we saw nothing".

These tests pin both halves: identity is recovered where the container id makes it certain,
and is reported as partial / ambiguous / unknown everywhere else, with no effect on what may
be confirmed.

The captured payload below is a verbatim POST body from a real falcosidekick 2.x webhook on
that cluster, headers `User-Agent: Falcosidekick`, `Content-Type: application/json`.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import (DETECTION_FALCO, DETECTION_KMW, RuntimeAgent,
                                            normalize_batch, normalize_events)
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.falco_feed import parse_falco_log
from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag, ResourceRef,
                                         Severity, Tactic)
from k8smatrixwarden.core.runtime_identity import (AMBIGUOUS, COMPLETE, PARTIAL, UNKNOWN,
                                                   build_container_index, enrich_events)

AGENT = RuntimeAgent()
_NOW = "2026-09-01T03:00:00+05:30"

#: Verbatim falcosidekick POST body captured from the live cluster.
SIDEKICK_PAYLOAD = {
    "hostname": "desktop-control-plane",
    "output": ("22:24:55.091549322: Notice Shell spawned in container "
               "(user=root proc=sh container=<NA> k8s_ns=<NA> k8s_pod=<NA>)"),
    "output_fields": {"container.id": "35bef3485064", "evt.time": 1788215095091549322,
                      "proc.name": "sh", "user.name": "root"},
    "priority": "Notice",
    "rule": "KMW validation shell in container",
    "source": "syscall",
    "tags": ["", "T1059", "container", "mitre_execution", "shell"],
    "time": "2026-08-31T22:24:55.091549322Z",
    "uuid": "5f1a0f3c-0000-4000-8000-000000000000",
}


def _pod(ns, name, container="app", cid="", key="containerStatuses"):
    return {"kind": "Pod", "metadata": {"namespace": ns, "name": name},
            "status": {key: [{"name": container,
                              "containerID": f"containerd://{cid}"}] if cid else []}}


def _falco(rule="R", tags=("mitre_execution",), **of):
    fields = {"proc.name": "sh", "evt.type": "execve"}
    fields.update({k.replace("__", "."): v for k, v in of.items()})
    return {"source": "syscall", "rule": rule, "priority": "Warning",
            "tags": list(tags), "time": "2026-09-01T02:00:00Z",
            "output_fields": fields}


def _enrich(event, pods):
    events, coverage = enrich_events(normalize_events([event]), pods)
    return events[0], coverage


# =========================================================================== #
# Recovery, only where it is certain
# =========================================================================== #
def test_a_container_id_recovers_the_pod_when_exactly_one_container_matches():
    """The only join used is a container id Kubernetes itself assigned. Falco reports the
    first 12 characters of the same id that appears in the Pod's containerStatuses."""
    full = "a1b2c3d4e5f6" + "0" * 52
    pods = [_pod("prod", "api-9zskz", "api", full)]
    event, coverage = _enrich(_falco(container__id=full[:12]), pods)
    assert event["namespace"] == "prod" and event["pod"] == "api-9zskz"
    assert event["container"] == "api"
    assert event["identity_status"] == COMPLETE
    assert event["identity_resolved_by"] == "container-id"
    assert coverage["recovered_from_container_id"] == 1


def test_recovery_covers_init_and_ephemeral_containers():
    """A shell in a debug container is exactly the event worth placing."""
    for key in ("initContainerStatuses", "ephemeralContainerStatuses"):
        full = "beef" + "0" * 60
        pods = [_pod("prod", "api-1", "debugger", full, key=key)]
        event, _ = _enrich(_falco(container__id=full[:12]), pods)
        assert event["pod"] == "api-1" and event["identity_status"] == COMPLETE


def test_two_containers_sharing_a_prefix_are_ambiguous_never_resolved():
    """REGRESSION guard for the one way this could become a guess. Picking either match
    would attribute an event to a resource it may not have happened in."""
    prefix = "cafebabe1234"
    pods = [_pod("prod", "api-1", "api", prefix + "a" * 52),
            _pod("staging", "api-2", "api", prefix + "b" * 52)]
    event, coverage = _enrich(_falco(container__id=prefix), pods)
    assert event["identity_status"] == AMBIGUOUS
    assert event.get("namespace") is None and event.get("pod") is None
    assert event["identity_candidates"] == 2
    assert coverage["ambiguous"] == 1


def test_an_unknown_container_id_stays_unknown_with_a_reason():
    """The live case: the container id belonged to no Pod the API knew about. Reported as
    unknown WITH the reason, which is the difference between an unplaceable event and no
    event at all."""
    event, coverage = _enrich(_falco(container__id="35bef3485064"),
                              [_pod("prod", "other", "c", "f" * 64)])
    assert event["identity_status"] == UNKNOWN
    assert event["identity_missing"] == ["namespace", "pod"]
    assert "not known to the Kubernetes API" in event["identity_reason"]
    assert coverage["unknown"] == 1 and coverage["recovered_from_container_id"] == 0


def test_an_event_with_no_container_id_says_so():
    event, _ = _enrich(_falco(), [])
    assert event["identity_status"] == UNKNOWN
    assert "no container id" in event["identity_reason"]


def test_a_partly_identified_event_is_partial_not_unknown():
    event, coverage = _enrich(_falco(k8s__ns__name="prod"), [])
    assert event["identity_status"] == PARTIAL
    assert event["identity_missing"] == ["pod"]
    assert coverage["partial"] == 1


def test_identity_from_the_provider_is_left_alone():
    """Recovery only fills gaps; it never overwrites what Falco reported."""
    pods = [_pod("wrong-ns", "wrong-pod", "c", "dd" * 32)]
    event, coverage = _enrich(_falco(k8s__ns__name="prod", k8s__pod__name="api-9zskz",
                                     container__id="dd" * 32), pods)
    assert event["namespace"] == "prod" and event["pod"] == "api-9zskz"
    assert event["identity_status"] == COMPLETE
    assert coverage["recovered_from_container_id"] == 0, "nothing needed recovering"


def test_the_index_never_matches_on_names():
    """No name, prefix or similarity match may exist: the index is keyed by container id."""
    pods = [_pod("prod", "api-9zskz", "api", "aa" * 32)]
    index = build_container_index(pods)
    assert set(index) == {"aa" * 32, ("aa" * 32)[:12]}
    assert not any("api" in key for key in index)


# =========================================================================== #
# Recovery must not widen what may be confirmed
# =========================================================================== #
def _finding(kind="Deployment", name="api", ns="prod", tactic=Tactic.EXECUTION):
    f = Finding(rule_id="workload-sa-token-automount", title="t",
                severity=Severity.HIGH, resource=ResourceRef(kind, name, ns),
                message="m", mitre=[MitreTag(tactic, "T1059", "Cmd")],
                detection_method=DetectionMethod.STATIC_CONFIG)
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": kind, "name": name, "detail": ns}]
    return f


def _correlate(event, pods, findings=None, cluster="c1"):
    events, _ = enrich_events(normalize_events([event]), pods)
    alerts = AGENT.evaluate_stream(events)
    return correlate(findings or [_finding()], alerts, cluster=cluster, now=_NOW)


def test_a_recovered_identity_confirms_only_by_the_ordinary_rules():
    """Enrichment must increase CORRECT confirmations, not confirmations. A recovered pod
    is judged exactly as a provider-reported one would be."""
    full = "1234abcd5678" + "0" * 52
    pods = [_pod("prod", "api-9zskz", "api", full)]
    out = _correlate(_falco("Shell", container__id=full[:12]), pods)
    assert out["confirmed_exploitation"] == 1

    # Same recovery, but the finding lives in another namespace: still no confirmation.
    other = _correlate(_falco("Shell", container__id=full[:12]), pods,
                       findings=[_finding(ns="staging")])
    assert other["confirmed_exploitation"] == 0


def test_ambiguous_and_unknown_identity_can_never_confirm():
    prefix = "abcdef123456"
    ambiguous_pods = [_pod("prod", "api-1", "api", prefix + "a" * 52),
                      _pod("prod", "api-2", "api", prefix + "b" * 52)]
    assert _correlate(_falco("Shell", container__id=prefix),
                      ambiguous_pods)["confirmed_exploitation"] == 0
    assert _correlate(_falco("Shell", container__id="nosuchcontainer"),
                      [])["confirmed_exploitation"] == 0


def test_recovery_does_not_cross_a_cluster_boundary():
    full = "9999abcd0000" + "0" * 52
    pods = [_pod("prod", "api-9zskz", "api", full)]
    event = _falco("Shell", container__id=full[:12])
    events, _ = enrich_events(normalize_events([event]), pods)
    events[0]["cluster"] = "some-other-cluster"
    out = correlate([_finding()], AGENT.evaluate_stream(events),
                    cluster="c1", now=_NOW)
    assert out["confirmed_exploitation"] == 0, "a recovered pod in another cluster"


def test_a_recovered_event_does_not_observe_the_whole_path():
    """Enrichment must not make a Pod-level observation vouch for the RBAC behind it."""
    from k8smatrixwarden.core.attack_path import resource_paths
    full = "5555bbbb0000" + "0" * 52
    pods = [_pod("prod", "api-9zskz", "api", full)]
    corr = _correlate(_falco("Shell", container__id=full[:12]), pods)
    path = resource_paths([_finding()], {"correlation": corr,
                                         "drift": {"drift": []}})[0]
    assert path["confidence"] == "observed"
    assert path["fully_observed"] is False
    assert path["observed_nodes"] == ["api"]


# =========================================================================== #
# The captured falcosidekick payload
# =========================================================================== #
def test_the_real_falcosidekick_payload_normalises_like_the_log_line():
    """§12: push and pull are two transports for one event and must mean the same thing.
    Validated live (falcosidekick POST OK 200 to /api/runtime); this pins the equivalence."""
    pulled = normalize_events(parse_falco_log(json.dumps(SIDEKICK_PAYLOAD)))
    pushed = normalize_events(SIDEKICK_PAYLOAD)
    assert pulled == pushed

    alert = AGENT.evaluate_stream(pushed)[0]
    assert alert.rule_id == "rt-shell-in-container", "curated rule owns it"
    assert alert.detection_source == DETECTION_KMW
    assert alert.provider_rule == "KMW validation shell in container"
    assert pushed[0]["time"] == "2026-08-31T22:24:55.091549322Z"
    assert pushed[0]["container_id"] == "35bef3485064"


def test_the_real_payload_is_reported_unplaceable_rather_than_dropped():
    """The live outcome, pinned: this container is not a Pod container, so identity is
    unknown, the event is still detected, and it correlates without confirming."""
    events, coverage = enrich_events(normalize_events(SIDEKICK_PAYLOAD), [])
    assert events[0]["identity_status"] == UNKNOWN
    assert coverage["unknown"] == 1
    alerts, detection = AGENT.evaluate_batch(events)
    assert detection["kmw_matches"] == 1 and detection["discarded"] == 0
    out = correlate([_finding()], alerts, cluster="c1", now=_NOW)
    assert out["confirmed_exploitation"] == 0
    assert out["total_alerts"] == 1, "detected, just not attributable"


def test_a_batch_entry_that_is_not_an_event_is_counted_not_dropped():
    """REGRESSION. `normalize_events` skipped non-dict entries silently, so a POST of two
    items where one was junk reported ONE event received. The junk never becomes a finding,
    but the arithmetic must show it arrived."""
    events, rejected = normalize_batch([None, SIDEKICK_PAYLOAD, "junk", 42])
    assert len(events) == 1 and len(rejected) == 3
    assert all("malformed" in r["reason"] for r in rejected)


def test_freshness_survives_the_push_path():
    old = dict(SIDEKICK_PAYLOAD, time="2019-01-01T00:00:00Z")
    events, _ = enrich_events(normalize_events(old), [])
    out = correlate([_finding()], AGENT.evaluate_stream(events), cluster="c1", now=_NOW)
    entry = out["correlations"][0]
    assert entry["freshness"] == "historical" and entry["age_days"] > 2000


# =========================================================================== #
# Kubernetes audit stays independent of Falco
# =========================================================================== #
AUDIT_EVENTS = [
    ({"source": "audit", "verb": "create", "resource": "clusterrolebindings"},
     "rt-new-rolebinding"),
    ({"source": "audit", "verb": "create", "resource": "pods/exec",
      "namespace": "kube-system"}, "rt-exec-kube-system"),
    ({"source": "audit", "verb": "list", "resource": "secrets"}, "rt-secret-enum"),
    ({"source": "audit", "verb": "delete", "resource": "events"}, "rt-delete-events"),
    ({"source": "audit", "verb": "delete", "resource": "pods", "count": 25},
     "rt-mass-delete"),
]


def test_all_five_audit_rules_fire_with_no_falco_involvement():
    """§15: the audit half of the catalog must not become dependent on the provider. A
    cluster with no sensor still detects a RoleBinding being created."""
    for event, expected in AUDIT_EVENTS:
        events, _ = enrich_events(normalize_events(event), [])
        alerts, coverage = AGENT.evaluate_batch(events)
        assert [a.rule_id for a in alerts] == [expected]
        assert alerts[0].source == "audit"
        assert alerts[0].detection_source == DETECTION_KMW
        assert alerts[0].provenance()["provider_rule"] is None
        assert coverage["falco_relays"] == 0 and coverage["discarded"] == 0


def test_audit_and_falco_events_keep_separate_provenance():
    """§16: two sources observing related activity stay two observations. They are not
    merged because they share a tactic or a namespace."""
    # `cat` reading a file matches no curated rule, so this one relays under Falco's name
    # and the two detections sit side by side with different provenance.
    batch = [AUDIT_EVENTS[0][0],
             _falco("Read sensitive file untrusted",
                    tags=["mitre_credential_access"], k8s__ns__name="kube-system",
                    proc__name="cat", evt__type="open", fd__name="/etc/shadow")]
    events, _ = enrich_events(normalize_events(batch), [])
    alerts, _ = AGENT.evaluate_batch(events)
    by_source = {a.source: a for a in alerts}
    assert set(by_source) == {"audit", "falco"}
    assert by_source["audit"].detection_source == DETECTION_KMW
    assert by_source["falco"].detection_source == DETECTION_FALCO
    assert len(alerts) == 2, "two sources, two observations"


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
