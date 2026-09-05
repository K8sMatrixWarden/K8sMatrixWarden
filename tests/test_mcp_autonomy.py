"""
MCP autonomy: can a client do the job without anyone opening a terminal?

The previous MCP audit asked whether every security capability had a tool. This one asks a
harder question, and it found two places where the honest answer was no:

  * the Security Dashboard could only be started by running `k8smatrixwarden web`, so an
    assistant asked to "open the dashboard" had to hand the user a shell command;
  * the CLI's `doctor` answers "is this installation healthy and is the read-only
    guarantee intact", which is what an operator actually means, and no tool did.

The fix for a missing operation is a narrow purpose-built tool over the existing core, never
a general command-execution escape hatch. These tests hold that line: they check the new
tools work, and they check that no tool anywhere grew a way to run arbitrary code.
"""
import inspect
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.mcp.server import build_tools

TOOLS = build_tools()


def _free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stop():
    try:
        TOOLS["stop_web_server"]()
    except Exception:                                  # pragma: no cover - cleanup
        pass


# --------------------------------------------------------------------------- #
# Platform diagnostics: the whole check, not a corner of it
# --------------------------------------------------------------------------- #

def test_run_doctor_is_registered_and_runs_the_real_check():
    assert "run_doctor" in TOOLS
    out = TOOLS["run_doctor"]()
    assert isinstance(out, dict)
    assert "sections" in out and "counts" in out
    assert out["sections"], "doctor returned no sections"


def test_run_doctor_is_the_single_platform_health_tool():
    """A narrower `validate_platform` used to sit beside this answering only "did the rule
    registry load". It was a strict subset of these sections, and two tools for one
    question just made an assistant guess, so it was removed rather than kept as an alias.
    Everything it reported still has a home here."""
    assert "validate_platform" not in TOOLS, "the duplicate tool is back"
    doctor = TOOLS["run_doctor"]()
    titles = [s.get("title") for s in doctor["sections"]]
    assert "Shard discovery" in titles and "Rules" in titles
    assert any("read-only" in str(t).lower() for t in titles),         "doctor must still assert the read-only invariant"


def test_run_doctor_does_not_touch_the_network_by_default():
    """`probe_llm` is opt-in: the default must not call out anywhere."""
    assert inspect.signature(TOOLS["run_doctor"]).parameters["probe_llm"].default is False


# --------------------------------------------------------------------------- #
# Dashboard lifecycle
# --------------------------------------------------------------------------- #

def test_the_dashboard_can_be_started_and_stopped_entirely_through_mcp():
    """REGRESSION for the gap: starting the dashboard required a shell command."""
    port = _free_port()
    try:
        assert TOOLS["get_web_server_status"]()["running"] is False
        started = TOOLS["start_web_server"](port=port)
        assert started["status"] == "started"
        assert started["port"] == port
        assert started["url"].endswith(f":{port}/")

        status = TOOLS["get_web_server_status"]()
        assert status["running"] is True
        assert status["port"] == port
        assert status["uptime_seconds"] is not None
    finally:
        stopped = TOOLS["stop_web_server"]()
    assert stopped["status"] == "stopped"
    assert TOOLS["get_web_server_status"]()["running"] is False


def test_a_started_dashboard_actually_serves():
    """A tool that reports "started" and serves nothing would be worse than no tool."""
    import urllib.error
    import urllib.request
    port = _free_port()
    try:
        TOOLS["start_web_server"](port=port)
        deadline = time.time() + 10
        body = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/health", timeout=2) as response:
                    body = response.read().decode()
                    break
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.2)
        assert body and '"status"' in body, "dashboard did not answer /health"
    finally:
        _stop()


def test_starting_twice_returns_the_running_server_rather_than_binding_again():
    port = _free_port()
    try:
        first = TOOLS["start_web_server"](port=port)
        second = TOOLS["start_web_server"](port=port)
        assert first["status"] == "started"
        assert second["status"] == "already-running"
        assert second["port"] == port
    finally:
        _stop()


def test_stopping_when_nothing_runs_is_not_an_error():
    assert TOOLS["stop_web_server"]()["status"] == "not-running"


def test_a_port_already_in_use_is_a_structured_error_not_an_exception():
    import socket
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    taken = holder.getsockname()[1]
    try:
        out = TOOLS["start_web_server"](port=taken)
        assert out["status"] == "error"
        assert "could not bind" in out["error"]
    finally:
        holder.close()
        _stop()


def test_a_non_loopback_bind_is_refused_without_an_explicit_opt_in():
    """The dashboard has no authentication of its own. A caller that is a program will not
    read a printed warning, so this is refused rather than warned about."""
    for host in ("0.0.0.0", "::", "192.168.1.10", ""):
        out = TOOLS["start_web_server"](host=host, port=_free_port())
        assert "error" in out, f"{host!r} was allowed to bind"
        assert "no authentication" in out["error"]
    assert TOOLS["get_web_server_status"]()["running"] is False


def test_an_invalid_port_is_refused():
    for bad in (-1, 99999, 65536, "8080", None, 3.5):
        out = TOOLS["start_web_server"](port=bad)
        assert "error" in out, f"port {bad!r} was accepted"
        assert "invalid port" in out["error"]
    assert TOOLS["get_web_server_status"]()["running"] is False


def test_port_zero_means_the_shared_default():
    """0 is the sentinel for "whatever the CLI would use", so one address means one
    dashboard however it was started. It is not a bindable port, so it cannot collide
    with a real request."""
    from k8smatrixwarden.web.server import DEFAULT_PORT
    try:
        out = TOOLS["start_web_server"](port=0)
        assert out["status"] == "started"
        assert out["port"] == DEFAULT_PORT
    finally:
        _stop()
    assert TOOLS["get_web_server_status"]()["running"] is False


def test_a_remote_bind_never_accepts_a_client_supplied_kubeconfig():
    """Loading a kubeconfig runs its credential plugin as this user. Over a network bind
    that is remote code execution, so the two are never combined."""
    source = inspect.getsource(TOOLS["start_web_server"])
    assert "allow_remote_kubeconfig=False" in source


def test_the_dashboard_lifecycle_is_concurrency_safe():
    """Several clients may ask at once; exactly one server must exist afterwards."""
    port = _free_port()
    _stop()                      # no leaked server from an earlier test
    outcomes, lock = [], threading.Lock()

    def racer():
        out = TOOLS["start_web_server"](port=port)
        with lock:
            outcomes.append(out["status"])

    threads = [threading.Thread(target=racer) for _ in range(8)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes.count("started") == 1, f"expected one bind, got {outcomes}"
        assert set(outcomes) <= {"started", "already-running"}
        assert TOOLS["get_web_server_status"]()["running"] is True
    finally:
        _stop()


# --------------------------------------------------------------------------- #
# The line that must not move
# --------------------------------------------------------------------------- #

def test_no_tool_accepts_a_command_to_execute():
    """The whole point of adding narrow tools instead of an escape hatch."""
    offenders = []
    for name, fn in TOOLS.items():
        for param in inspect.signature(fn).parameters:
            if param in ("command", "cmd", "shell", "script", "exec", "eval", "code",
                         "args", "argv"):
                offenders.append(f"{name}.{param}")
    assert offenders == [], f"tools taking executable input: {offenders}"


def test_the_only_process_spawning_tool_is_gated_and_uses_argv():
    """`deploy_falco` runs helm, and is the single deliberate exception. It must stay
    opt-in and must never reach a shell."""
    import json as _json

    from k8smatrixwarden.core import falco_lifecycle
    # The tool delegates; the gate and the argv discipline live in the shared service.
    assert "falco_lifecycle" in inspect.getsource(TOOLS["deploy_falco"])
    service = inspect.getsource(falco_lifecycle)
    assert "shell=True" not in service.split('"""')[-1]
    assert "K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE" in service
    was = os.environ.pop("K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE", None)
    try:
        out = TOOLS["deploy_falco"](webhook_url="http://127.0.0.1:8080/api/runtime")
        assert out["status"] == "dry-run", "helm ran without the opt-in"
        assert "K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE" in _json.dumps(out)
    finally:
        if was is not None:
            os.environ["K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE"] = was


def test_hostile_scan_ids_are_rejected_by_every_report_reading_tool():
    directory = tempfile.mkdtemp()
    TOOLS["run_scan"](mock=True, save=True, reports_dir=directory, max_findings=1)
    hostile = ["../../../../etc/passwd", "..\\..\\Windows\\win.ini", "/etc/shadow",
               "scan\x00.json", "a; rm -rf /", "$(whoami)", "`id`",
               "%2e%2e%2fetc%2fpasswd"]
    for tool, extra in (("download_report", {"format": "markdown"}),
                        ("get_cluster_coverage", {}), ("posture_history", {}),
                        ("get_runtime_events", {}), ("explain_finding", {})):
        for evil in hostile:
            out = TOOLS[tool](scan_id=evil, reports_dir=directory, **extra)
            assert isinstance(out, dict) and "error" in out, \
                f"{tool} accepted {evil!r}"
            assert "root:" not in str(out) and "[fonts]" not in str(out)


def test_generated_rbac_stays_read_only():
    text = str(TOOLS["generate_rbac_manifest"]())
    for verb in ("create", "update", "patch", "delete", "deletecollection"):
        assert f'"{verb}"' not in text and f"'{verb}'" not in text, \
            f"generated RBAC contains the write verb {verb!r}"


# --------------------------------------------------------------------------- #
# Protocol: the tools must be reachable as tools, not just as functions
# --------------------------------------------------------------------------- #

def test_every_new_tool_is_reachable_over_the_wire():
    """A tool that works in-process but not over JSON-RPC is not an MCP capability. This
    speaks the real protocol to a real server subprocess."""
    import json
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen([sys.executable, "-m", "k8smatrixwarden", "mcp"],
                            cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                            bufsize=1)

    def call(idx, method, params):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": idx, "method": method,
                                     "params": params}) + "\n")
        proc.stdin.flush()
        while True:
            line = proc.stdout.readline()
            if not line:
                raise AssertionError("server closed the pipe")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == idx:
                return msg

    try:
        init = call(1, "initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "kmw-tests", "version": "1.0"}})
        assert init["result"]["serverInfo"]["name"] == "k8smatrixwarden-mcp"
        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized",
             "params": {}}) + "\n")
        proc.stdin.flush()

        listed = call(2, "tools/list", {})
        names = {t["name"] for t in listed["result"]["tools"]}
        for expected in ("run_doctor", "start_web_server", "get_web_server_status",
                         "stop_web_server", "get_runtime_events",
                         "refresh_runtime_feed"):
            assert expected in names, f"{expected} not advertised over the protocol"
        assert names == set(TOOLS), "advertised tools differ from the registry"

        status = call(3, "tools/call", {"name": "get_web_server_status",
                                        "arguments": {}})
        assert status["result"].get("isError") is not True

        unknown = call(4, "tools/call", {"name": "no_such_tool", "arguments": {}})
        assert unknown["result"]["isError"] is True
        text = unknown["result"]["content"][0]["text"]
        assert "Traceback" not in text
    finally:
        try:
            proc.stdin.close()
        except Exception:                              # pragma: no cover - cleanup
            pass
        proc.terminate()
        proc.wait(timeout=10)


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
