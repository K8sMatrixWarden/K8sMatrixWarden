"""
Regressions from the final adversarial audit.

Each test here corresponds to a defect that was found by trying to make the tool lie, not
by exercising a feature. The grouping is by the kind of lie:

  * a grant whose contents could not be read, reported as "no escalation"
  * evidence from months ago, reported in the present tense
  * a runtime event acknowledged with 200 and then lost
  * a report write defeated by somebody else reading the file

The last two only appear under concurrency, which is the condition the endpoint actually
runs in: falcosidekick pushes while the dashboard polls.
"""
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest
from k8smatrixwarden.core.rbac_graph import Node, RbacGraph
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.threat_matrix import _step_confidence


# =========================================================================== #
# 1. A role we could not read is UNKNOWN, never "no escalation"
# =========================================================================== #

def _binding(name, role_kind, role_name, subject_ns="prod", subject="app"):
    return {"metadata": {"name": name},
            "roleRef": {"kind": role_kind, "name": role_name},
            "subjects": [{"kind": "ServiceAccount", "name": subject,
                          "namespace": subject_ns}]}


def test_a_binding_to_an_uncollected_clusterrole_is_reported_as_unknown():
    """REGRESSION. `grant_edges` skips a roleRef it cannot resolve, having no rules to
    walk. That skip was invisible: the analysis came back `complete` with no paths and
    nothing unevaluable, which reads as "this ServiceAccount is fine".

    The case is not exotic. A scanner refused permission to list ClusterRoles collects
    none of them, so EVERY roleRef dangles at once and every principal in the cluster
    looks clean."""
    graph = RbacGraph([], [], [_binding("b", "ClusterRole", "cluster-admin")], [])
    out = graph.escalation_analysis(Node("ServiceAccount", "app", "prod"))
    assert out["paths"] == [], "there are no rules to walk, so no path can be claimed"
    unknown = out["unevaluable_roles"]
    assert len(unknown) == 1, "the grant itself was read and must be reported"
    assert unknown[0]["reason"] == "not-collected"
    assert "cluster-admin" in unknown[0]["note"]
    assert "UNKNOWN" in unknown[0]["note"]


def test_a_rolebinding_to_an_uncollected_role_is_reported_too():
    graph = RbacGraph([], [], [], [dict(_binding("b", "Role", "secret-reader"),
                                        metadata={"name": "b", "namespace": "prod"})])
    out = graph.escalation_analysis(Node("ServiceAccount", "app", "prod"))
    assert [u["reason"] for u in out["unevaluable_roles"]] == ["not-collected"]


def test_a_resolvable_binding_is_not_reported_as_unknown():
    """The signal has to stay quiet when the evidence is complete, or it is noise."""
    role = {"metadata": {"name": "reader"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]}
    graph = RbacGraph([role], [], [_binding("b", "ClusterRole", "reader")], [])
    out = graph.escalation_analysis(Node("ServiceAccount", "app", "prod"))
    assert out["unevaluable_roles"] == []
    assert out["paths"], "a readable grant must still produce its escalation path"


# =========================================================================== #
# 2. Stale evidence is not present-tense evidence
# =========================================================================== #

def _finding(tactic=None):
    from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Severity,
                                             Tactic)
    return Finding(rule_id="workload-privileged", title="Privileged container",
                   severity=Severity.HIGH,
                   resource=ResourceRef(kind="Pod", name="payment-api",
                                        namespace="production"),
                   message="privileged", owning_shard="workload_pod_security",
                   mitre=[MitreTag(tactic or Tactic.EXECUTION, "T1610",
                                   "Deploy Container")])


def _correlate_at(age_days):
    import datetime as dt

    from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
    from k8smatrixwarden.core.correlation import correlate
    now = dt.datetime(2026, 9, 2, tzinfo=dt.timezone.utc)
    when = (now - dt.timedelta(days=age_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    alerts = RuntimeAgent().evaluate_stream(normalize_events(
        [{"source": "falco", "proc": "bash", "namespace": "production",
          "pod": "payment-api-5f8b94447d-blxwg", "time": when}]))
    return correlate([_finding()], alerts, now=now)["correlations"][0]


def test_a_year_old_event_is_not_described_as_active_exploitation():
    """REGRESSION. Freshness was computed and reported, and then ignored by the verdict:
    a 400-day-old event read "is being actively exploited", which an operator acts on as
    a live intrusion."""
    entry = _correlate_at(400)
    assert entry["freshness"] == "historical"
    assert "actively exploited" not in entry["verdict"]
    assert "WAS exploited" in entry["verdict"]
    assert "400 days old" in entry["verdict"]


def test_a_stale_event_still_confirms_the_resource_link():
    """The fix must not throw the evidence away. The link is real; only its tense was
    wrong."""
    assert _correlate_at(400)["confidence"] == "confirmed"


def test_a_recent_event_keeps_the_present_tense_verdict():
    entry = _correlate_at(1)
    assert entry["freshness"] == "recent"
    assert "actively exploited" in entry["verdict"]


def test_an_attack_path_step_is_not_observed_on_stale_proof():
    """`observed` is the top rank and a present-tense claim about a live path."""
    assert _step_confidence([{"level": "confirmed", "freshness": "historical"}]) \
        == "corroborated"
    assert _step_confidence([{"level": "drift", "freshness": "historical"}]) \
        == "corroborated"


def test_an_attack_path_step_is_observed_on_fresh_proof():
    assert _step_confidence([{"level": "confirmed", "freshness": "recent"}]) == "observed"
    # An event whose age we cannot read is not evidence of staleness either.
    assert _step_confidence([{"level": "confirmed", "freshness": "unknown"}]) == "observed"
    # One fresh proof is enough; stale siblings do not drag it down.
    assert _step_confidence([{"level": "confirmed", "freshness": "historical"},
                             {"level": "confirmed", "freshness": "recent"}]) == "observed"


def test_a_step_with_no_runtime_proof_is_still_configuration_only():
    assert _step_confidence([]) == "configuration-only"
    assert _step_confidence([{"level": "corroborated"}]) == "corroborated"


# =========================================================================== #
# 3. Concurrent ingestion loses nothing
# =========================================================================== #

def _app_with_scan():
    platform = build_platform()
    directory = tempfile.mkdtemp()
    store = ReportStore(directory)
    store.save(ScannerAgent(platform).scan(ScanRequest(),
                                           platform.make_collector(mock=True)))
    from k8smatrixwarden.web.app import WebApp
    return WebApp(platform, reports_dir=directory)


def test_concurrent_ingestion_does_not_lose_events():
    """REGRESSION. Persisting a batch is a read-modify-write of one stored scan, and it
    was unsynchronised. Forty simultaneous POSTs each merged into the copy they had loaded
    before the others saved; thirty-nine events vanished and every request answered 200.

    falcosidekick pushes concurrently, so this is the endpoint's normal condition, not an
    edge case."""
    app = _app_with_scan()
    failures = []

    def post(i):
        try:
            app.route("POST", "/api/runtime", body=json.dumps({"events": [
                {"source": "falco", "proc": "bash", "namespace": "prod",
                 "pod": f"w{i}-blxwg"}]}).encode())
        except Exception as exc:                       # pragma: no cover - diagnostic
            failures.append(repr(exc))

    threads = [threading.Thread(target=post, args=(i,)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert failures == []
    listed = json.loads(app.route("GET", "/api/runtime", query="limit=1000").text)
    pods = {e.get("pod") for e in listed["events"]}
    missing = [i for i in range(40) if f"w{i}-blxwg" not in pods]
    assert missing == [], f"{len(missing)} events acknowledged and then lost"


def test_concurrent_ingestion_alongside_concurrent_reads_loses_nothing():
    """Reading is what made writing fail on Windows; the two must run together."""
    app = _app_with_scan()

    def churn(i):
        app.route("POST", "/api/runtime", body=json.dumps({"events": [
            {"source": "falco", "proc": "bash", "namespace": "prod",
             "pod": f"r{i}-blxwg"}]}).encode())
        app.route("GET", "/api/runtime", query="limit=50")

    threads = [threading.Thread(target=churn, args=(i,)) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    listed = json.loads(app.route("GET", "/api/runtime", query="limit=1000").text)
    pods = {e.get("pod") for e in listed["events"]}
    assert [i for i in range(30) if f"r{i}-blxwg" not in pods] == []


def test_redelivering_the_same_event_does_not_multiply_it():
    app = _app_with_scan()
    event = {"source": "falco", "proc": "bash", "namespace": "prod", "pod": "dup-blxwg"}
    for _ in range(6):
        app.route("POST", "/api/runtime",
                  body=json.dumps({"events": [event]}).encode())
    listed = json.loads(app.route("GET", "/api/runtime", query="limit=1000").text)
    assert len([e for e in listed["events"] if e.get("pod") == "dup-blxwg"]) == 1


# =========================================================================== #
# 4. A concurrent reader cannot defeat a write
# =========================================================================== #

def test_report_writes_survive_concurrent_readers():
    """REGRESSION. Windows refuses to rename over a file any handle has open, and every
    reader of a report holds one while it parses. `os.replace` raised PermissionError, the
    save was reported as failed, and the runtime event it carried was gone, while the API
    had already answered 200.

    Readers here do what real readers do: open, parse, close, then wait before polling
    again. That is the contention the fix addresses, and it is what failed before it,
    on both sides.

    Two limits are deliberately not tested, because no retry can fix either. A reader that
    keeps a handle open indefinitely blocks a write on Windows, and stdlib `open` cannot
    ask for the share-delete mode that would permit it. And a reader that polls with no
    pause at all keeps a handle open essentially always, which starves the writer rather
    than merely delaying it. Both are documented platform limits.
    """
    from k8smatrixwarden.core.report_store import _atomic_write_json, _open_json
    directory = tempfile.mkdtemp()
    path = os.path.join(directory, "report.json")
    _atomic_write_json(path, {"generation": 0})
    errors, stop = [], threading.Event()

    def reader():
        # The reader the store itself uses, not a bare open(): tolerating the replace
        # window is part of the fix, and a test that reads around it would not exercise it.
        while not stop.is_set():
            try:
                with _open_json(path) as fh:
                    json.load(fh)
            except FileNotFoundError:                  # pragma: no cover - timing
                pass
            except Exception as exc:
                errors.append(f"reader: {exc!r}")
            time.sleep(0.002)         # a poll, not a spin

    def writer(i):
        try:
            for generation in range(25):
                _atomic_write_json(path, {"generation": generation, "writer": i})
        except Exception as exc:
            errors.append(f"writer: {exc!r}")

    readers = [threading.Thread(target=reader, daemon=True) for _ in range(4)]
    for t in readers:
        t.start()
    writers = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    for t in readers:
        t.join(timeout=5)
    assert errors == [], errors
    with open(path, encoding="utf-8") as fh:
        assert "generation" in json.load(fh)


def test_two_threads_writing_one_report_do_not_share_a_temp_file():
    """The temp name was keyed on the pid alone, so two threads writing the same report
    serialised into the same file and could interleave each other's bytes."""
    from k8smatrixwarden.core.report_store import _atomic_write_json
    directory = tempfile.mkdtemp()
    path = os.path.join(directory, "report.json")
    errors = []

    def write(i):
        try:
            for _ in range(20):
                _atomic_write_json(path, {"writer": i, "payload": "x" * 5000})
        except Exception as exc:                       # pragma: no cover - diagnostic
            errors.append(repr(exc))

    threads = [threading.Thread(target=write, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)               # must parse: never a half-written file
    assert payload["payload"] == "x" * 5000
    leftovers = [f for f in os.listdir(directory) if f.endswith(".tmp")]
    assert leftovers == [], f"temp files left behind: {leftovers}"


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
