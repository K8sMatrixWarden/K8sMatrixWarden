"""
MCP as a first-class surface: capability parity, routing, errors, observability.

The audit behind these tests asked one question — can an MCP client do the meaningful
security work the CLI and the web can? Three answers were no, and each has a test here:

  * no tool could READ the runtime events stored on a scan, so "show me recent Falco events"
    was impossible over MCP even though the dashboard shows them;
  * no tool could PULL a fresh Falco feed from the cluster, which the dashboard can;
  * `posture_history` answered about a DIFFERENT scan when given an id that does not exist,
    silently, which is worse than an error.

The rest guard the properties that make the surface trustworthy rather than merely present:
tools route into the same core the other surfaces use, hostile arguments are refused, and a
failure is visible in the log.
"""
import io
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.mcp.server import build_tools, observe

TOOLS = build_tools()


def _saved_scan(directory=None):
    directory = directory or tempfile.mkdtemp()
    scan = TOOLS["run_scan"](mock=True, save=True, reports_dir=directory,
                             max_findings=1)
    return directory, scan["scan_id"]


# =========================================================================== #
# The capability gaps the audit found
# =========================================================================== #

def test_runtime_events_can_be_read_through_mcp():
    """The dashboard's GET /api/runtime had no MCP counterpart, so an MCP client could
    ingest and correlate runtime events but never ask what had been observed."""
    directory, scan_id = _saved_scan()
    out = TOOLS["get_runtime_events"](scan_id=scan_id, reports_dir=directory)
    assert "events" in out and "total" in out and "matched" in out
    assert out["scan_id"] == scan_id


def test_reading_runtime_events_uses_the_same_code_as_the_web():
    """Not a second implementation: both surfaces call core.runtime_events.query_runtime,
    so they cannot disagree about what was seen."""
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.web.app import WebApp
    directory, scan_id = _saved_scan()
    TOOLS["evaluate_runtime_events"](events=[
        {"source": "falco", "proc": "bash", "namespace": "production",
         "pod": "payment-api-5f8b94447d-blxwg"}])
    app = WebApp(build_platform(), reports_dir=directory)
    app.route("POST", "/api/runtime", body=json.dumps({"events": [
        {"source": "falco", "proc": "bash", "namespace": "production",
         "pod": "payment-api-5f8b94447d-blxwg"}]}).encode())
    web = json.loads(app.route("GET", "/api/runtime",
                               query=f"scan_id={scan_id}&limit=50").text)
    mcp = TOOLS["get_runtime_events"](scan_id=scan_id, reports_dir=directory, limit=50)
    assert web["total"] == mcp["total"]
    assert web["matched"] == mcp["matched"]
    assert [e["event_id"] for e in web["events"]] == \
        [e["event_id"] for e in mcp["events"]]


def test_runtime_read_validates_filters_instead_of_silently_ignoring_them():
    """A filter that quietly does nothing hides events."""
    directory, scan_id = _saved_scan()
    out = TOOLS["get_runtime_events"](scan_id=scan_id, reports_dir=directory,
                                      source="nonsense", limit=-5, since="blah")
    assert len(out["warnings"]) == 3
    assert out["filters"]["source"] == "all"


def test_a_fresh_falco_feed_can_be_pulled_through_mcp():
    """The pull path exists over MCP; without cluster access it says so rather than
    reporting an empty feed, because "no events" and "could not look" differ."""
    directory, scan_id = _saved_scan()
    out = TOOLS["refresh_runtime_feed"](scan_id=scan_id, reports_dir=directory,
                                        kubeconfig="/nonexistent/kubeconfig")
    assert "error" in out or out.get("runtime") is None
    if "error" in out:
        assert "cluster access" in out["error"] or "kubeconfig" in out["error"].lower()


def test_posture_history_refuses_an_unknown_scan_instead_of_answering_about_another():
    """REGRESSION. `latest_change` fell back to the newest scan when the requested id was
    not in the store, so "what changed in scan X" was answered with scan Y's diff and
    nothing said so."""
    directory, scan_id = _saved_scan()
    out = TOOLS["posture_history"](scan_id="no-such-scan", reports_dir=directory)
    assert "error" in out
    assert out.get("current_scan_id") is None


def test_posture_history_still_defaults_to_the_latest_scan():
    """An OMITTED id is a different request from a wrong one and must keep working."""
    directory, scan_id = _saved_scan()
    out = TOOLS["posture_history"](reports_dir=directory)
    assert out.get("current_scan_id") == scan_id


# =========================================================================== #
# Errors: structured, every time
# =========================================================================== #

_SCAN_READERS = ("get_cluster_coverage", "download_report", "posture_history",
                 "explain_finding", "get_runtime_events", "refresh_runtime_feed",
                 "build_threat_matrix", "build_attack_path")


def test_every_scan_reading_tool_returns_a_structured_error_for_a_missing_scan():
    """An MCP client sees a tool result, not a traceback. A raised exception reaches the
    client as a transport-level failure with a stack trace in it."""
    directory, _ = _saved_scan()
    for name in _SCAN_READERS:
        kwargs = {"scan_id": "does-not-exist", "reports_dir": directory}
        if name == "download_report":
            kwargs["format"] = "markdown"
        out = TOOLS[name](**kwargs)
        assert isinstance(out, dict), name
        assert "error" in out, f"{name} did not report the missing scan"


def test_errors_do_not_leak_filesystem_contents():
    directory, _ = _saved_scan()
    for probe in ("../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                  "C:/Windows/win.ini"):
        out = TOOLS["get_cluster_coverage"](scan_id=probe, reports_dir=directory)
        body = json.dumps(out).lower()
        assert "root:" not in body and "[fonts]" not in body
        assert "traceback" not in body


# =========================================================================== #
# Security boundary
# =========================================================================== #

def test_the_report_store_only_lists_actual_reports():
    """REGRESSION. Any parseable .json in the directory became a row, taking its scan id
    from the FILENAME. Pointed at an unrelated directory the store listed `wrapperMap` and
    friends as scans: a garbage row in the history, and — since `reports_dir` is a
    caller-supplied argument — a way to enumerate .json filenames in any readable
    directory."""
    directory = tempfile.mkdtemp()
    with io.open(os.path.join(directory, "not-a-report.json"), "w",
                 encoding="utf-8") as fh:
        json.dump({"some": "unrelated file"}, fh)
    with io.open(os.path.join(directory, "also-not.json"), "w", encoding="utf-8") as fh:
        json.dump(["a", "list"], fh)
    assert ReportStore(directory).list() == []
    assert TOOLS["list_reports"](reports_dir=directory) == []
    _saved_scan(directory)
    assert len(TOOLS["list_reports"](reports_dir=directory)) == 1


def test_no_mcp_tool_can_write_to_kubernetes():
    """The read-only invariant has to hold on this surface too."""
    import inspect
    writes = ("create_namespaced_", "delete_namespaced_", "patch_namespaced_",
              "replace_namespaced_", "delete_collection_")
    offenders = []
    for name, fn in TOOLS.items():
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):
            continue
        for needle in writes:
            if needle in src:
                offenders.append(f"{name}:{needle}")
    assert offenders == [], offenders


def test_hostile_arguments_are_handled_not_executed():
    for tool, args in (("get_kubectl_command", {"name": "list; rm -rf /"}),
                       ("lookup_cve", {"cve_id": "$(whoami)"}),
                       ("get_rule", {"rule_id": "rbac\x00../../etc"})):
        out = TOOLS[tool](**args)
        body = json.dumps(out) if not isinstance(out, str) else out
        assert "root:" not in body and "uid=" not in body


# =========================================================================== #
# Layering: MCP calls the same core as everything else
# =========================================================================== #

def test_mcp_tools_route_into_core_rather_than_reimplementing_it():
    """A tool that contained its own detection or scoring would drift from the CLI. Each
    of these must mention the core module it delegates to."""
    import inspect
    expected = {
        "run_scan": "ScannerAgent",
        "analyze_rbac_paths": "rbac_graph",
        "analyze_network_policy": "netpol",
        "build_threat_matrix": "threat_matrix",
        "correlate_runtime": "correlation",
        "evaluate_runtime_events": "RuntimeAgent",
        "get_runtime_events": "query_runtime",
        "refresh_runtime_feed": "build_runtime_feed",
        "posture_history": "latest_change",
        "explain_finding": "explain",
        # Reached through the shared platform engine, not a private renderer.
        "download_report": "platform.reporting",
    }
    missing = [name for name, needle in expected.items()
               if needle not in inspect.getsource(TOOLS[name])]
    assert missing == [], f"tools not delegating to core: {missing}"


# =========================================================================== #
# Observability
# =========================================================================== #

def _capture(fn, *args, **kwargs):
    import contextlib
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        result = fn(*args, **kwargs)
    return result, buffer.getvalue()


def test_a_tool_call_is_logged_with_its_name_duration_and_outcome():
    """The SDK logs only "Processing request of type CallToolRequest", which cannot tell
    you which tool ran or whether it worked."""
    wrapped = observe("mitre_coverage", TOOLS["mitre_coverage"])
    result, log = _capture(wrapped)
    assert result
    assert "event=tool.started" in log and "tool=mitre_coverage" in log
    assert "event=tool.completed" in log and "duration_ms=" in log
    assert "request_id=" in log


def test_a_handled_error_is_logged_as_an_error_not_a_success():
    wrapped = observe("get_rule", TOOLS["get_rule"])
    _result, log = _capture(wrapped, rule_id="no-such-rule")
    assert "event=tool.error" in log
    assert "event=tool.completed" not in log


def test_a_raised_exception_is_logged_and_re_raised():
    def boom():
        raise RuntimeError("boom")
    wrapped = observe("boom", boom)
    import contextlib
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        try:
            wrapped()
            raised = False
        except RuntimeError:
            raised = True
    assert raised, "the wrapper must not swallow the exception"
    assert "event=tool.failed" in buffer.getvalue()
    assert "error=RuntimeError" in buffer.getvalue()


def test_logs_carry_argument_names_but_never_argument_values():
    """A value can be a kubeconfig path or a namespace an operator would rather not have
    in a shared log."""
    wrapped = observe("get_rule", TOOLS["get_rule"])
    _result, log = _capture(wrapped, rule_id="rbac-wildcard-verbs")
    assert "args=rule_id" in log
    assert "rbac-wildcard-verbs" not in log


def test_logging_never_writes_to_stdout():
    """stdout is the JSON-RPC channel. One stray line there corrupts the stream and the
    client disconnects."""
    import contextlib
    out, err = io.StringIO(), io.StringIO()
    wrapped = observe("mitre_coverage", TOOLS["mitre_coverage"])
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        wrapped()
    assert out.getvalue() == ""
    assert err.getvalue() != ""


def test_the_wrapper_does_not_change_what_a_tool_returns():
    import contextlib
    plain = TOOLS["mitre_coverage"]()
    with contextlib.redirect_stderr(io.StringIO()):
        wrapped = observe("mitre_coverage", TOOLS["mitre_coverage"])()
    assert wrapped == plain


# =========================================================================== #
# Concurrency
# =========================================================================== #

def test_concurrent_tool_calls_do_not_mix_results():
    directory, _ = _saved_scan()
    answers, lock = [], threading.Lock()

    def work(i):
        if i % 2:
            out = TOOLS["get_rule"](rule_id="rbac-wildcard-verbs")
            key = out.get("id") or out.get("rule_id")
        else:
            out = TOOLS["lookup_cve"](cve_id="CVE-2024-9486")
            key = "cve" if out.get("severity") else None
        with lock:
            answers.append((i, key))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(answers) == 16
    for i, key in answers:
        assert key is not None, f"call {i} got an empty or foreign answer"


def test_concurrent_saving_scans_through_mcp_does_not_lose_reports():
    directory = tempfile.mkdtemp()
    errors, lock = [], threading.Lock()

    def work():
        try:
            TOOLS["run_scan"](mock=True, save=True, reports_dir=directory,
                              max_findings=1)
        except Exception as exc:                       # pragma: no cover - diagnostic
            with lock:
                errors.append(repr(exc))

    threads = [threading.Thread(target=work) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(TOOLS["list_reports"](reports_dir=directory)) == 6


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
