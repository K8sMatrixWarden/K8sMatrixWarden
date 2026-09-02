"""
Native Kubernetes API-server audit records through the runtime pipeline.

Falco's k8saudit plugin already gave us audit events, but only where Falco is deployed and
only in Falco's flattened `ka.*` rendering. These tests cover the other source: the audit
log the API server writes itself, in the `audit.k8s.io/v1` shape, which is available on any
cluster whose operator can set `--audit-policy-file` and needs no agent at all.

What is being locked down here is not "audit works" but the three ways it could quietly be
wrong: an audit record misread as a syscall event, an audit detection that claims Falco
found it, and a curated rule that cannot fire from real audit data even though it fires from
a hand-built fixture.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures_audit import AUDIT_CASES, audit_event, mass_delete_events

from k8smatrixwarden.agents.runtime import (AUDIT_STAGE_COMPLETE, RuntimeAgent,
                                            is_kubernetes_audit_event,
                                            normalize_audit_event, normalize_batch,
                                            normalize_events)
from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.reporting import ReportingEngine
from k8smatrixwarden.core.runtime_identity import COMPLETE, PARTIAL, UNKNOWN
from k8smatrixwarden.web.app import WebApp


def _alerts(events):
    return RuntimeAgent().evaluate_stream(normalize_events(events))


# --------------------------------------------------------------------------- #
# Recognising a native audit record
# --------------------------------------------------------------------------- #

def test_native_audit_event_is_recognised_by_its_api_version():
    assert is_kubernetes_audit_event(AUDIT_CASES["rt-new-rolebinding"])


def test_a_falco_event_is_not_mistaken_for_a_native_audit_record():
    # Both describe API activity; only one is the API server's own record.
    assert not is_kubernetes_audit_event(
        {"source": "k8s_audit", "output_fields": {"ka.verb": "create"}})
    assert not is_kubernetes_audit_event({"source": "falco", "proc": "bash"})
    assert not is_kubernetes_audit_event("not an event")


def test_a_kubernetes_object_that_is_not_an_audit_event_is_not_claimed():
    # A core/v1 Event is also `kind: Event`; only the audit apiVersion makes it ours.
    assert not is_kubernetes_audit_event({"kind": "Event", "apiVersion": "v1"})


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

def test_audit_record_normalizes_to_the_flat_internal_shape():
    ev = normalize_audit_event(AUDIT_CASES["rt-new-rolebinding"])
    assert ev["source"] == "audit"
    assert ev["verb"] == "create"
    assert ev["resource"] == "clusterrolebindings"
    assert ev["resource_name"] == "attacker-binding"
    assert ev["provider"] == "kubernetes-audit"


def test_the_actor_and_origin_survive_normalization():
    # "Who did this, from where, and did it succeed" is what makes an audit finding
    # actionable; dropping it would leave an alert nobody can chase.
    ev = normalize_audit_event(AUDIT_CASES["rt-new-rolebinding"])
    assert ev["username"] == "kubernetes-admin"
    assert "kubeadm:cluster-admins" in ev["user_groups"]
    assert ev["source_ip"] == "192.168.65.3"
    assert ev["user_agent"].startswith("kubectl/")
    assert ev["response_status"] == 201
    assert ev["audit_id"] == "11111111-1111-4111-8111-111111111111"


def test_subresource_joins_its_parent_the_way_kubernetes_writes_it():
    # `pods/exec` is the form RBAC uses and the form the curated rules match on.
    ev = normalize_audit_event(AUDIT_CASES["rt-exec-kube-system"])
    assert ev["resource"] == "pods/exec"


def test_absent_fields_are_omitted_not_defaulted():
    # A cluster-scoped action has no namespace. Emitting "" would make it an action in a
    # namespace named empty string, which correlation would then reason about.
    ev = normalize_audit_event(AUDIT_CASES["rt-new-rolebinding"])
    assert "namespace" not in ev


def test_the_providers_own_timestamp_is_carried_not_invented():
    ev = normalize_audit_event(AUDIT_CASES["rt-new-rolebinding"])
    assert ev["time"] == "2026-09-02T06:10:00.250000Z"


def test_request_received_stage_is_rejected_with_a_reason_not_dropped():
    # The same request appears twice, once as an attempt and once as an outcome. Counting
    # both reports one action twice; dropping it silently loses the arithmetic.
    received = audit_event(verb="create", resource="clusterrolebindings", name="x",
                           stage="RequestReceived")
    events, rejected = normalize_batch([received])
    assert events == []
    assert len(rejected) == 1
    assert AUDIT_STAGE_COMPLETE in rejected[0]["reason"]


def test_a_batch_can_mix_native_audit_falco_and_flat_events():
    events, rejected = normalize_batch([
        AUDIT_CASES["rt-secret-enum"],
        {"source": "syscall", "output_fields": {"proc.name": "bash"}},
        {"source": "falco", "proc": "nmap"},
    ])
    assert rejected == []
    assert [e["source"] for e in events] == ["audit", "falco", "falco"]


# --------------------------------------------------------------------------- #
# The five curated audit rules, each fired from a native record
# --------------------------------------------------------------------------- #

def test_rt_new_rolebinding_fires_from_a_native_audit_record():
    assert any(a.rule_id == "rt-new-rolebinding"
               for a in _alerts([AUDIT_CASES["rt-new-rolebinding"]]))


def test_rt_exec_kube_system_fires_from_a_native_audit_record():
    assert any(a.rule_id == "rt-exec-kube-system"
               for a in _alerts([AUDIT_CASES["rt-exec-kube-system"]]))


def test_rt_secret_enum_fires_from_a_native_audit_record():
    assert any(a.rule_id == "rt-secret-enum"
               for a in _alerts([AUDIT_CASES["rt-secret-enum"]]))


def test_rt_delete_events_fires_from_a_native_audit_record():
    assert any(a.rule_id == "rt-delete-events"
               for a in _alerts([AUDIT_CASES["rt-delete-events"]]))


def test_rt_mass_delete_fires_from_a_burst_of_native_audit_records():
    # The regression this exists for: a single audit record cannot carry "twenty-five
    # deletions", so before the batch tally this rule was unreachable from real audit data
    # while still passing against a hand-built event with a `count` key.
    assert any(a.rule_id == "rt-mass-delete" for a in _alerts(mass_delete_events(25)))


def test_a_deletion_burst_raises_one_alert_not_one_per_record():
    hits = [a for a in _alerts(mass_delete_events(25)) if a.rule_id == "rt-mass-delete"]
    assert len(hits) == 1


def test_a_burst_below_the_threshold_does_not_fire():
    assert not any(a.rule_id == "rt-mass-delete" for a in _alerts(mass_delete_events(4)))


def test_a_single_deletion_is_never_given_a_rate():
    events, _ = normalize_batch(mass_delete_events(1))
    assert "count" not in events[0]


def test_deletions_by_different_users_are_not_pooled_into_one_spike():
    # Twelve deletions is a spike; six each by two operators is two ordinary cleanups.
    burst = mass_delete_events(12)
    for e in burst[6:]:
        e["user"] = dict(e["user"], username="other-admin")
    assert not any(a.rule_id == "rt-mass-delete" for a in _alerts(burst))


def test_a_caller_supplied_count_is_not_overwritten_by_the_batch_tally():
    # A caller that aggregated over an hour knows more than this batch does.
    pre = dict(normalize_audit_event(mass_delete_events(1)[0]), count=500)
    events, _ = normalize_batch([pre, dict(pre)])
    assert events[0]["count"] == 500


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #

def test_audit_detections_carry_the_audit_stream_and_the_api_server_as_provider():
    for rule_id, raw in AUDIT_CASES.items():
        alert = next(a for a in _alerts([raw]) if a.rule_id == rule_id)
        p = alert.provenance()
        assert p["event_source"] == "audit", rule_id
        assert p["detection_source"] == "kmw", rule_id
        assert p["provider"] == "kubernetes-audit", rule_id


def test_an_audit_detection_never_claims_falco_supporting_evidence():
    # The API server records requests; it does not raise alerts. Attaching a provider rule
    # here would invent corroboration from a product that never saw the event.
    alert = next(a for a in _alerts([AUDIT_CASES["rt-secret-enum"]])
                 if a.rule_id == "rt-secret-enum")
    assert not alert.provenance()["provider_rule"]


def test_falco_rendered_audit_events_report_the_same_provider():
    # Same API-server record, different transport. The provenance must not depend on which
    # path it arrived by, or two reports of one event would disagree.
    ev = normalize_events({"source": "k8s_audit",
                           "output_fields": {"ka.verb": "list",
                                             "ka.target.resource": "secrets",
                                             "ka.target.namespace": "default"}})[0]
    assert ev["provider"] == "kubernetes-audit"


def test_falco_rendered_audit_maps_the_object_name_not_the_pod_field():
    # `ka.target.name` is the object the request named, which is only a pod when the
    # resource is pods. Mapping it to `pod` unconditionally made a ClusterRoleBinding named
    # "attacker-binding" look like a pod, which correlation could then confirm against.
    ev = normalize_events({"source": "k8s_audit",
                           "output_fields": {"ka.verb": "create",
                                             "ka.target.resource": "clusterrolebindings",
                                             "ka.target.name": "attacker-binding"}})[0]
    assert ev["resource_name"] == "attacker-binding"
    assert "pod" not in ev


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

def _enriched(raw):
    """One event through normalization and identity enrichment, as ingestion does it."""
    from k8smatrixwarden.core.runtime_identity import enrich_events
    return enrich_events(normalize_events([raw]), [])[0][0]


def test_a_cluster_scoped_audit_action_is_complete_identity_not_unknown():
    # The pod/namespace test is right for a syscall and wrong for an audit record: creating
    # a ClusterRoleBinding has no pod by design, yet names exactly what was created.
    assert _enriched(AUDIT_CASES["rt-new-rolebinding"])["identity_status"] == COMPLETE


def test_a_collection_request_is_partial_and_says_why():
    event = _enriched(AUDIT_CASES["rt-secret-enum"])
    assert event["identity_status"] == PARTIAL
    assert event["identity_missing"] == ["resource_name"]
    assert event["identity_reason"]


def test_an_audit_record_naming_no_resource_is_unknown():
    from k8smatrixwarden.core.runtime_identity import enrich_event
    out = enrich_event({"source": "audit", "verb": "get"}, {})
    assert out["identity_status"] == UNKNOWN


# --------------------------------------------------------------------------- #
# Accounting
# --------------------------------------------------------------------------- #

def test_nothing_is_discarded_and_folded_deletions_say_so():
    events, rejected = normalize_batch(list(AUDIT_CASES.values()) + mass_delete_events(25))
    _alerts_, coverage = RuntimeAgent().evaluate_batch(events)
    assert rejected == []
    assert coverage["discarded"] == 0
    assert coverage["events_received"] == len(events)
    # The 24 non-representative deletions contributed to an alert. Reporting them as "no
    # rule matched" would present the evidence behind a finding as evidence of nothing.
    folded = [u for u in coverage["unusable"] if "deletion-rate tally" in u["reason"]]
    assert len(folded) == 24


# --------------------------------------------------------------------------- #
# Deduplication across ingestion paths
# --------------------------------------------------------------------------- #

def test_the_same_action_via_both_paths_is_one_event_not_two():
    """Falco's k8saudit rendering and the native record describe the SAME request.

    A cluster running Falco with the k8saudit plugin AND a native audit feed sees each API
    call twice. Two rows for one `kubectl get secrets` would double every audit count an
    operator reads off the page."""
    app, _ = _app_with_audit()
    app.route("POST", "/api/runtime", body=json.dumps({"events": [
        {"source": "k8s_audit",
         "output_fields": {"ka.verb": "list", "ka.target.resource": "secrets",
                           "ka.target.namespace": "default",
                           # The same request the native fixture describes. Falco carries
                           # the API server's auditID, which is what makes them joinable.
                           "ka.auid": AUDIT_CASES["rt-secret-enum"]["auditID"]}}]}).encode())
    body = json.loads(app.route("GET", "/api/runtime", query="limit=100").text)
    enumerations = [e for e in body["events"] if e["rule"] == "rt-secret-enum"]
    assert len(enumerations) == 1


def test_a_redelivered_event_is_not_counted_twice():
    """falcosidekick delivers at least once, so the same event can arrive more than once.

    Absent an auditID to join on, identity falls back to the observable content, so a
    redelivery collapses. The documented cost is that two genuinely separate calls carrying
    no distinguishing field also collapse; the fix for that is an auditID, not a
    similarity heuristic."""
    app, _ = _app_with_audit()
    app.route("POST", "/api/runtime", body=json.dumps({"events": [
        {"source": "k8s_audit",
         "output_fields": {"ka.verb": "list", "ka.target.resource": "secrets",
                           "ka.target.namespace": "kube-node-lease"}}]}).encode())
    app.route("POST", "/api/runtime", body=json.dumps({"events": [
        {"source": "k8s_audit",
         "output_fields": {"ka.verb": "list", "ka.target.resource": "secrets",
                           "ka.target.namespace": "kube-node-lease"}}]}).encode())
    body = json.loads(app.route("GET", "/api/runtime", query="limit=100").text)
    assert len([e for e in body["events"]
                if e["rule"] == "rt-secret-enum"
                and e.get("namespace") == "kube-node-lease"]) == 1


def test_one_request_tripping_two_rules_stays_two_findings():
    """Shared auditID must not collapse distinct detections about the same call."""
    from k8smatrixwarden.core.runtime_events import _event_id
    base = {"kind": "correlation", "audit_id": "abc-123", "namespace": "default"}
    assert (_event_id(dict(base, rule="rt-delete-events"))
            != _event_id(dict(base, rule="rt-mass-delete")))


# --------------------------------------------------------------------------- #
# Surfaces
# --------------------------------------------------------------------------- #

def _app_with_audit():
    platform = build_platform()
    directory = tempfile.mkdtemp()
    store = ReportStore(directory)
    store.save(ScannerAgent(platform).scan(ScanRequest(),
                                           platform.make_collector(mock=True)))
    app = WebApp(platform, reports_dir=directory)
    app.route("POST", "/api/runtime",
              body=json.dumps({"events": list(AUDIT_CASES.values())}).encode())
    return app, store


def test_audit_events_are_readable_through_the_runtime_api():
    app, _ = _app_with_audit()
    body = json.loads(app.route("GET", "/api/runtime", query="source=audit").text)
    assert {e["source"] for e in body["events"]} == {"audit"}
    assert {e["provider"] for e in body["events"]} == {"kubernetes-audit"}


def test_audit_events_coexist_with_syscall_events_under_the_same_filters():
    app, _ = _app_with_audit()
    app.route("POST", "/api/runtime", body=json.dumps({"events": [
        {"source": "syscall", "rule": "Terminal shell in container",
         "output_fields": {"proc.name": "bash", "k8s.ns.name": "production",
                           "k8s.pod.name": "api-1"}}]}).encode())
    every = json.loads(app.route("GET", "/api/runtime", query="limit=100").text)
    assert {"audit", "falco"} <= {e["source"] for e in every["events"]}
    only_audit = json.loads(app.route("GET", "/api/runtime", query="source=audit").text)
    assert all(e["source"] == "audit" for e in only_audit["events"])


def test_the_runtime_page_renders_with_audit_events_present():
    app, _ = _app_with_audit()
    page = app.route("GET", "/runtime")
    assert page.status == 200 and "Runtime" in page.text


def test_an_audit_detection_reads_the_same_in_every_rendered_report():
    """One detection, eight renderers, no surface allowed to describe it differently."""
    app, store = _app_with_audit()
    result = store.resolve(None)
    engine = ReportingEngine()
    for fmt in ("markdown", "html", "terminal", "text"):
        rendered = engine.render(result, fmt)
        assert "rt-new-rolebinding" in rendered, fmt
        # The stream is named, so an audit detection cannot be read as a syscall one.
        assert "(audit)" in rendered, fmt


def test_the_json_report_keeps_the_structured_provenance():
    app, store = _app_with_audit()
    payload = json.loads(ReportingEngine().render(store.resolve(None), "json"))
    runtime = json.dumps(payload.get("runtime", {}))
    assert "kubernetes-audit" in runtime
    assert '"event_source": "audit"' in runtime


def test_the_mcp_tool_reports_the_same_provenance_as_the_api():
    from k8smatrixwarden.mcp.server import build_tools
    out = build_tools()["evaluate_runtime_events"](
        events=[AUDIT_CASES["rt-new-rolebinding"]])
    alert = next(a for a in out["alerts"] if a["rule_id"] == "rt-new-rolebinding")
    assert alert["provenance"]["event_source"] == "audit"
    assert alert["provenance"]["provider"] == "kubernetes-audit"
    assert alert["provenance"]["detection_source"] == "kmw"


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
