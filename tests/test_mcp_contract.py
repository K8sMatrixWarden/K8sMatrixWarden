"""
MCP tool return types must match what the tools actually return.

The defect this exists for: `evaluate_runtime_events` was annotated `-> list[dict]` while
returning `{"coverage": ..., "alerts": [...]}`. Every in-process test passed, because calling
a Python function does not check its annotation. Over the wire it failed outright -- the MCP
runtime validates each result against the declared type and refused the response, so the tool
was simply uncallable by any client.

That is the whole point of this module: the existing MCP tests call `build_tools()` and
invoke the functions directly, which cannot see a lying annotation. These tests read the
annotation and compare it against the value, the way the MCP runtime does.
"""
import inspect
import os
import sys
import tempfile
import typing

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.mcp.server import build_tools

TOOLS = build_tools()

#: Tools that need a cluster, a network call, or write somewhere. Their annotations are
#: still checked; only their return VALUE is not exercised here.
_NOT_INVOKED = {
    "run_scan", "intelligent_scan", "build_threat_matrix", "build_attack_path",
    "run_cis_benchmark", "run_compliance_audit", "correlate_runtime", "detect_drift",
    "analyze_network_policy", "analyze_rbac_paths", "detect_cluster_provider",
    "list_namespaces", "deploy_falco", "download_report", "explain_finding",
    "get_cluster_coverage", "posture_history", "federation_blast_radius",
    "list_reports", "generate_rbac_manifest",
}

#: Arguments for the tools that are cheap to actually call.
_ARGS = {
    "get_rule": {"rule_id": "rbac-wildcard-verbs"},
    "lookup_cve": {"cve_id": "CVE-2024-9486"},
    "get_kubectl_command": {"name": "list-privileged-pods"},
    "get_tool_commands": {"tool": "trivy"},
    "get_compliance_ruleset": {},
    "resolve_selector": {"tactics": ["Privilege Escalation"]},
    "preview_scan": {},
    "interpret_query": {"text": "scan the cluster for privilege escalation"},
    "list_rules": {},
    "evaluate_runtime_events": {
        "events": [{"source": "falco", "proc": "bash", "pod": "api-5f8b94447d-blxwg",
                    "namespace": "production"}]},
}


def _declared(fn):
    """The runtime type a tool's return annotation demands.

    Resolved with `eval_str=True` because mcp/server.py uses `from __future__ import
    annotations`, so the raw annotation is the STRING "dict", not the type. That detail is
    part of why the original mismatch survived: a string compares equal to nothing useful,
    and a test that forgets to evaluate it silently checks nothing.
    """
    annotation = inspect.signature(fn, eval_str=True).return_annotation
    if annotation is typing.Any:
        return None                     # deliberately polymorphic (format-dependent)
    return typing.get_origin(annotation) or annotation


def test_every_tool_declares_a_return_type():
    """An undeclared return type is not validated by the MCP runtime at all, which is how a
    mismatch survives to a client."""
    missing = [name for name, fn in TOOLS.items()
               if inspect.signature(fn, eval_str=True).return_annotation
               is inspect.Signature.empty]
    assert missing == [], f"tools with no return annotation: {missing}"


def test_declared_return_types_are_containers_the_runtime_can_validate():
    allowed = {dict, list, str, int, float, bool}
    wrong = {}
    for name, fn in TOOLS.items():
        declared = _declared(fn)
        if declared is None:
            continue                    # typing.Any: the format argument picks the type
        if declared not in allowed:
            wrong[name] = declared
    assert wrong == {}, f"unexpected declared return types: {wrong}"


def test_cheap_tools_return_what_they_declare():
    """REGRESSION. `evaluate_runtime_events` declared list[dict] and returned a dict, so the
    MCP runtime rejected every response and the tool could not be called at all."""
    mismatches = []
    for name, fn in sorted(TOOLS.items()):
        if name in _NOT_INVOKED:
            continue
        declared = _declared(fn)
        if declared is None:
            continue
        try:
            value = fn(**_ARGS.get(name, {}))
        except TypeError:
            continue                    # needs arguments this test does not supply
        if not isinstance(value, declared):
            mismatches.append(f"{name}: declares {declared.__name__}, "
                              f"returns {type(value).__name__}")
    assert mismatches == [], "; ".join(mismatches)


def test_evaluate_runtime_events_returns_the_documented_shape():
    """Its own contract, stated in its docstring: coverage beside the alerts, so a caller
    can tell "nothing matched" from "nothing arrived"."""
    out = TOOLS["evaluate_runtime_events"](**_ARGS["evaluate_runtime_events"])
    assert isinstance(out, dict)
    assert "alerts" in out and "coverage" in out
    assert out["coverage"]["discarded"] == 0
    assert isinstance(out["alerts"], list)


def test_run_scan_publishes_both_finding_counts_over_mcp():
    """The MCP surface must report the same two counts as every other surface."""
    out = TOOLS["run_scan"](mock=True, save=False, max_findings=1)
    summary = out["summary"]
    assert summary["resource_findings"] == out["counts"]["CRITICAL"] \
        + out["counts"]["HIGH"] + out["counts"]["MEDIUM"] + out["counts"]["LOW"]
    assert summary["workload_issues"] == len(out["workload_issues"])
    assert out["aggregation"]["workload_issues"] == summary["workload_issues"]


def test_get_cluster_coverage_carries_the_aggregation():
    from k8smatrixwarden.core.report_store import ReportStore
    directory = tempfile.mkdtemp()
    scan = TOOLS["run_scan"](mock=True, save=True, reports_dir=directory,
                             max_findings=1)
    out = TOOLS["get_cluster_coverage"](scan_id=scan["scan_id"],
                                        reports_dir=directory)
    assert out["aggregation"]["workload_issues"] > 0
    assert out["risk"]["explanation"]["scoring_basis"] == "workload_issues"
    assert ReportStore(directory).load(scan["scan_id"]) is not None


def test_download_report_states_both_counts():
    directory = tempfile.mkdtemp()
    scan = TOOLS["run_scan"](mock=True, save=True, reports_dir=directory,
                             max_findings=1)
    out = TOOLS["download_report"](scan_id=scan["scan_id"], reports_dir=directory,
                                   format="markdown")
    assert out["scan_id"] == scan["scan_id"]
    assert "Resource-level findings" in out["content"]
    assert "Owning-workload issues" in out["content"]


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
