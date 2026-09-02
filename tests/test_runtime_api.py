"""
`GET /api/runtime`: a read-only view of runtime evidence already stored on a scan.

Two properties matter more than the feature itself. The read side must not disturb
ingestion — `POST /api/runtime` is what Falco and falcosidekick talk to, and a regression
there loses live evidence. And it must not become a second event store: the records are
reshaped from `ScanResult.runtime`, so this view and the report can never disagree about
what was observed.

A filter that quietly does nothing is the failure mode here. A malformed `limit`, `source`
or `since` is ignored AND named in `warnings`, because an operator who believes a filter
applied will read an empty page as "nothing happened".
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.runtime_events import (apply_filters, flatten, parse_since,
                                                 summarize)
from k8smatrixwarden.web.app import WebApp

_PLATFORM = None


def _platform():
    global _PLATFORM
    if _PLATFORM is None:
        _PLATFORM = build_platform()
    return _PLATFORM


def _correlation(rule="falco:Read sensitive file untrusted", *, detector="falco",
                 severity="MEDIUM", tactic="Credential Access", ns="default",
                 pod="api-9zskz", ts="2026-09-01T10:00:00Z", confidence="confirmed",
                 source="falco", identity="complete", supporting=None):
    return {
        "confidence": confidence, "correlation_level": confidence,
        "verdict": "static weakness on this resource is being actively exploited",
        "severity": severity, "timestamp": ts, "freshness": "recent", "age_days": 0.1,
        "cluster": "c1", "resource": pod, "namespace": ns, "tactic": tactic,
        "static_findings": [{"rule_id": "workload-sa-token-automount",
                             "resource": "Deployment/api (default)"}],
        "runtime": {"rule_id": rule, "title": rule, "severity": severity,
                    "source": source, "surface": "runtime", "timestamp": ts,
                    "detection_source": detector,
                    "provider": ("falco" if detector == "falco"
                                 else "k8smatrixwarden"),
                    "provider_rule": ("Read sensitive file untrusted"
                                      if detector == "falco" else None),
                    "provider_priority": "Warning",
                    "technique_id": "T1555", "technique_name": "Credentials from stores",
                    "supporting_evidence": supporting, "kmw_equivalent": None,
                    "event": {"source": source, "proc": "cat", "namespace": ns,
                              "pod": pod, "container": "api", "time": ts,
                              "identity_status": identity,
                              "identity_missing": [] if identity == "complete"
                              else ["namespace", "pod"]}},
    }


def _runtime_block(correlations, drift=()):
    return {
        "source": "falco-logs", "collected_at": "2026-09-01T10:05:00+05:30",
        "cluster": "c1", "falco_namespace": "falco", "since_seconds": 3600,
        "events_seen": len(correlations),
        "detection_coverage": {"kmw_rules": 11, "events_received": len(correlations),
                               "kmw_matches": 0, "falco_relays": len(correlations),
                               "unusable_events": 0, "unusable": [], "discarded": 0},
        "identity_coverage": {"complete": len(correlations), "partial": 0,
                              "ambiguous": 0, "unknown": 0,
                              "recovered_from_container_id": 0, "containers_indexed": 3},
        "correlation": {"total_alerts": len(correlations),
                        "correlated": len(correlations),
                        "confirmed_exploitation": len(correlations),
                        "runtime_only": 0, "correlations": list(correlations),
                        "timeline": list(correlations)},
        "drift": {"drift": list(drift), "drift_count": len(drift),
                  "pods_checked": 3, "events_seen": len(correlations)},
    }


def _app_with(runtime=None):
    """A web app over a temp store holding exactly one scan, with `runtime` attached."""
    p = _platform()
    store_dir = tempfile.mkdtemp()
    result = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    result.cluster_name = "c1"
    if runtime is not None:
        result.runtime = runtime
    ReportStore(store_dir).save(result)
    return WebApp(p, reports_dir=store_dir), result


def _get(app, query=""):
    r = app.route("GET", "/api/runtime", query=query)
    return r.status, json.loads(r.text)


# =========================================================================== #
# The endpoint
# =========================================================================== #
def test_get_returns_the_events_stored_on_the_scan():
    app, _ = _app_with(_runtime_block([_correlation()]))
    status, body = _get(app)
    assert status == 200
    assert body["total"] == 1 and body["matched"] == 1 and body["returned"] == 1
    event = body["events"][0]
    assert event["rule"] == "falco:Read sensitive file untrusted"
    assert event["detection_source"] == "falco" and event["provider"] == "falco"
    assert event["correlation"] == "confirmed" and event["freshness"] == "recent"


def test_every_field_of_the_provenance_model_is_exposed():
    """The model is the contract. A consumer must be able to answer who detected this,
    under whose name, on what resource, and how sure we are of that resource."""
    app, _ = _app_with(_runtime_block([
        _correlation(detector="kmw", rule="rt-shell-in-container",
                     supporting="falco:Terminal shell in container")]))
    event = _get(app)[1]["events"][0]
    for field in ("event_id", "timestamp", "source", "detection_source", "provider",
                  "provider_rule", "provider_priority", "rule", "severity", "tactic",
                  "technique_id", "technique_name", "cluster", "namespace", "workload",
                  "pod", "container", "process", "freshness", "identity_status",
                  "supporting_evidence", "correlation"):
        assert field in event, f"{field} missing from the API response"
    assert event["detection_source"] == "kmw"
    assert event["supporting_evidence"] == "falco:Terminal shell in container"
    assert event["workload"] == "Deployment/api (default)"


def test_the_default_page_is_the_most_recent_fifty():
    app, _ = _app_with(_runtime_block(
        [_correlation(pod=f"pod-{i}", ts=f"2026-09-01T10:{i:02d}:00Z")
         for i in range(60)]))
    body = _get(app)[1]
    assert body["limit"] == 50 and body["returned"] == 50
    assert body["total"] == 60 and body["matched"] == 60, "totals are before the limit"
    assert body["events"][0]["timestamp"] == "2026-09-01T10:59:00Z", "newest first"


def test_no_stored_runtime_is_an_empty_result_not_an_error():
    """A scan with no runtime feed is a normal state, and must not read as a failure."""
    app, _ = _app_with(None)
    status, body = _get(app)
    assert status == 200
    assert body["events"] == [] and body["total"] == 0 and body["matched"] == 0


def test_no_saved_scan_at_all_is_a_clear_error():
    app = WebApp(_platform(), reports_dir=tempfile.mkdtemp())
    status, body = _get(app)
    assert status == 400 and "scan" in body["error"]


# =========================================================================== #
# Filters
# =========================================================================== #
def test_source_filter_selects_by_detector_and_by_stream():
    """`kmw` and `falco` ask "who decided this?"; `audit` and `drift` ask "which stream?".
    Both are questions operators actually have, and they are not the same question."""
    app, _ = _app_with(_runtime_block(
        [_correlation(detector="falco"),
         _correlation(detector="kmw", rule="rt-shell-in-container"),
         _correlation(detector="kmw", rule="rt-secret-enum", source="audit")],
        drift=[{"pod": "api-1", "namespace": "default", "verdict": "runs as uid 0",
                "declared": "runAsNonRoot: true", "observed": "uid 0",
                "timestamp": "2026-09-01T09:00:00Z", "tactic": "Privilege Escalation"}]))
    assert _get(app, "source=falco")[1]["matched"] == 1
    assert _get(app, "source=kmw")[1]["matched"] == 3, "drift is a kmw detection too"
    assert _get(app, "source=audit")[1]["matched"] == 1
    assert _get(app, "source=drift")[1]["matched"] == 1
    assert _get(app, "source=all")[1]["matched"] == 4


def test_severity_namespace_and_limit_filters():
    app, _ = _app_with(_runtime_block([
        _correlation(severity="CRITICAL", ns="prod", pod="a"),
        _correlation(severity="HIGH", ns="prod", pod="b"),
        _correlation(severity="MEDIUM", ns="default", pod="c")]))
    assert _get(app, "severity=CRITICAL")[1]["matched"] == 1
    assert _get(app, "severity=CRITICAL,HIGH")[1]["matched"] == 2
    assert _get(app, "namespace=prod")[1]["matched"] == 2
    assert _get(app, "namespace=prod&severity=HIGH")[1]["matched"] == 1
    limited = _get(app, "limit=1")[1]
    assert limited["returned"] == 1 and limited["matched"] == 3


def test_a_filter_matching_nothing_returns_empty_without_pretending_otherwise():
    app, _ = _app_with(_runtime_block([_correlation(ns="default")]))
    body = _get(app, "namespace=does-not-exist")[1]
    assert body["events"] == [] and body["matched"] == 0
    assert body["total"] == 1, "the scan still holds an event; the filter excluded it"
    assert body["warnings"] == [], "an empty result is not a warning"


def test_since_accepts_durations_and_seconds():
    assert parse_since("90s") == 90
    assert parse_since("15m") == 900
    assert parse_since("2h") == 7200
    assert parse_since("7d") == 604800
    assert parse_since("1w") == 604800
    assert parse_since("600") == 600
    assert parse_since("") is None and parse_since(None) is None
    assert parse_since("later") is None and parse_since("-5m") is None


def test_since_narrows_by_age_but_keeps_undateable_events():
    """An event with no readable timestamp is kept. Dropping it would let a time filter
    hide evidence, which is the failure this whole layer avoids."""
    records = flatten(_runtime_block([
        _correlation(pod="recent", ts="2026-09-01T10:00:00Z"),
        _correlation(pod="old", ts="2026-08-01T10:00:00Z"),
        _correlation(pod="undated", ts="")]), "c1")
    import datetime
    now = datetime.datetime(2026, 9, 1, 11, 0, tzinfo=datetime.timezone.utc).timestamp()
    kept = {r["pod"] for r in apply_filters(records, since_seconds=7200, now=now)}
    assert kept == {"recent", "undated"}


# =========================================================================== #
# Malformed input
# =========================================================================== #
def test_malformed_query_parameters_are_ignored_and_reported():
    """A filter that silently does nothing is worse than a rejected one: the operator reads
    the unfiltered page as if it were filtered."""
    app, _ = _app_with(_runtime_block([_correlation()]))
    for query, needle in (("limit=abc", "limit"), ("limit=-5", "limit"),
                          ("limit=0", "limit"), ("source=martian", "source"),
                          ("since=100y", "since"), ("since=soon", "since")):
        status, body = _get(app, query)
        assert status == 200, f"{query} must not error"
        assert body["matched"] == 1, f"{query} must not silently filter"
        assert any(needle in w for w in body["warnings"]), f"{query} unreported"


def test_a_huge_limit_is_capped_rather_than_honoured():
    app, _ = _app_with(_runtime_block([_correlation(pod=f"p{i}") for i in range(5)]))
    body = _get(app, "limit=99999")[1]
    assert body["limit"] == 1000 and body["returned"] == 5


# =========================================================================== #
# Ordering
# =========================================================================== #
def test_ordering_is_newest_first_and_stable_for_identical_timestamps():
    """Ties break on the event id, a content hash, so repeated requests never reshuffle."""
    same = "2026-09-01T10:00:00Z"
    app, _ = _app_with(_runtime_block(
        [_correlation(pod=f"pod-{i}", ts=same) for i in range(6)]
        + [_correlation(pod="newest", ts="2026-09-01T11:00:00Z"),
           _correlation(pod="oldest", ts="2026-09-01T08:00:00Z")]))
    first = [e["event_id"] for e in _get(app)[1]["events"]]
    for _ in range(4):
        assert [e["event_id"] for e in _get(app)[1]["events"]] == first
    stamps = [e["timestamp"] for e in _get(app)[1]["events"]]
    assert stamps == sorted(stamps, reverse=True)
    assert _get(app)[1]["events"][0]["pod"] == "newest"
    assert _get(app)[1]["events"][-1]["pod"] == "oldest"


def test_event_ids_are_stable_across_requests_and_unique_per_event():
    app, _ = _app_with(_runtime_block(
        [_correlation(pod=f"pod-{i}") for i in range(5)]))
    a = [e["event_id"] for e in _get(app)[1]["events"]]
    b = [e["event_id"] for e in _get(app)[1]["events"]]
    assert a == b and len(set(a)) == len(a)


# =========================================================================== #
# Coexistence with ingestion, and no second store
# =========================================================================== #
def test_post_still_ingests_after_get_was_added():
    """The read route must not shadow the write route. Falco talks to POST."""
    app, _ = _app_with(_runtime_block([_correlation()]))
    r = app.route("POST", "/api/runtime", body=json.dumps({"events": [
        {"source": "falco", "proc": "bash", "namespace": "default", "pod": "p-1"}]}).encode())
    assert r.status == 200
    posted = json.loads(r.text)
    assert "correlation" in posted and "detection_coverage" in posted
    assert posted["detection_coverage"]["discarded"] == 0
    # And GET still answers on the same path.
    assert _get(app)[0] == 200


def test_get_reads_the_scan_store_rather_than_a_second_event_store():
    """No parallel storage: what GET returns must come from the same block the report
    renders, or the two would drift."""
    runtime = _runtime_block([_correlation(pod="only-here")])
    app, result = _app_with(runtime)
    body = _get(app)[1]
    assert body["scan_id"] == result.scan_id
    assert [e["pod"] for e in body["events"]] == ["only-here"]
    assert body["events"] == flatten(result.runtime, result.cluster_name)


def test_the_response_carries_no_configuration_or_secrets():
    """Read-only means read-only: no kubeconfig, credentials or host paths leak out.

    Checked structurally rather than by substring, because legitimate content mentions
    these words: `workload-sa-token-automount` is a rule id, not a secret."""
    import re
    app, _ = _app_with(_runtime_block([_correlation()]))
    body = _get(app)[1]
    blob = json.dumps(body)

    def keys(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield str(key).lower()
                yield from keys(value)
        elif isinstance(node, list):
            for item in node:
                yield from keys(item)

    banned_keys = {"kubeconfig", "api_key", "apikey", "password", "secret", "token",
                   "authorization", "client-key-data", "client_key", "reports_dir",
                   "certificate-authority-data"}
    assert not (set(keys(body)) & banned_keys), "response carries a credential-shaped key"

    # No credential-shaped VALUE: PEM blocks, bearer headers, long opaque blobs.
    assert "BEGIN " not in blob and "PRIVATE KEY" not in blob
    assert not re.search(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}", blob)
    assert not re.search(r"[A-Za-z0-9+/]{200,}={0,2}", blob), "long opaque blob"
    # No host filesystem paths.
    assert not re.search(r"(?i)[a-z]:\\\\users\\\\|/home/[a-z]+/|/root/", blob)


# =========================================================================== #
# Reports written before the provenance model
# =========================================================================== #
def test_an_old_report_without_provenance_still_renders():
    """Reports saved before provenance existed have no `detection_source`. They must read
    as `unknown` rather than erroring or being assumed to be ours."""
    legacy = {"source": "falco-logs", "collected_at": "2026-01-01T00:00:00+05:30",
              "correlation": {"correlations": [{
                  "confidence": "corroborated", "severity": "HIGH",
                  "timestamp": "2026-01-01T00:00:00Z", "tactic": "Execution",
                  "namespace": "default", "resource": "api-1",
                  "runtime": {"rule_id": "rt-shell-in-container", "title": "shell",
                              "severity": "HIGH", "source": "falco",
                              "event": {"proc": "bash"}}}]},
              "drift": {"drift": []}}
    app, _ = _app_with(legacy)
    status, body = _get(app)
    assert status == 200 and body["matched"] == 1
    event = body["events"][0]
    assert event["detection_source"] == "unknown" and event["provider"] == "unknown"
    assert event["identity_status"] == "unknown"
    assert event["rule"] == "rt-shell-in-container"


# =========================================================================== #
# The page
# =========================================================================== #
def test_the_runtime_page_renders_and_is_linked_from_the_navigation():
    app, _ = _app_with(_runtime_block([_correlation()]))
    page = app.route("GET", "/runtime")
    assert page.status == 200
    body = page.text
    assert "Runtime Events" in body
    assert "/api/runtime" in body, "the page reads the documented endpoint"
    for control in ("f-source", "f-severity", "f-namespace", "f-since", "f-limit"):
        assert control in body, f"missing the {control} filter control"
    # The three detection kinds must be visually distinguishable, not merged.
    for label in ("KMW", "Falco", "DRIFT"):
        assert label in body
    # Reachable from every page's navigation.
    assert 'href="/runtime"' in body or "href='/runtime'" in body


def test_the_dashboard_navigation_offers_the_runtime_page():
    app, _ = _app_with(_runtime_block([_correlation()]))
    assert "/runtime" in app.route("GET", "/").text


def test_summarize_counts_each_axis_separately():
    records = flatten(_runtime_block([
        _correlation(detector="falco"),
        _correlation(detector="kmw", rule="rt-shell-in-container")]), "c1")
    summary = summarize(records)
    assert summary["total"] == 2
    assert summary["by_detector"] == {"falco": 1, "kmw": 1}
    assert set(summary) == {"total", "by_detector", "by_source", "by_correlation",
                            "by_severity", "by_identity"}


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")
