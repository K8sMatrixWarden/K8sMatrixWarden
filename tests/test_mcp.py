"""MCP tool surface (§10), knowledge layer, scan/audit/runtime layer, reports, platform."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.mcp.server import build_tools

ALL_TOOLS = {
    "list_rules", "resolve_selector", "get_kubectl_command", "list_kubectl_commands",
    "get_tool_commands", "list_tool_commands",
    "lookup_cve", "list_cves", "get_compliance_ruleset", "get_taxonomy",
    "mitre_coverage", "list_shards", "list_namespaces", "detect_cluster_provider",
    "validate_platform",
    "preview_scan", "run_scan", "interpret_query", "intelligent_scan",
    "run_cis_benchmark", "run_compliance_audit", "evaluate_runtime_events",
    "correlate_runtime",
    "detect_drift", "deploy_falco", "list_runtime_detections",
    "build_threat_matrix", "build_attack_path",
    "list_reports", "download_report", "federation_blast_radius",
    "generate_rbac_manifest",
}


def test_build_attack_path_chains_hits_in_killchain_order():
    tools = build_tools()
    path = tools["build_attack_path"](mock=True)
    tactics = [s["tactic"] for s in path["steps"]]
    assert tactics, "mock cluster is insecure, expected a non-empty attack path"
    order = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
             "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
             "Impact"]
    assert tactics == sorted(tactics, key=order.index), "steps not in kill-chain order"
    assert path["entry_points"] == path["steps"][0]["techniques"]
    assert path["chain"] == " -> ".join(tactics)


def test_intelligent_scan_returns_matrix_and_path():
    tools = build_tools()
    doc = tools["intelligent_scan"]("scan cluster for privilege escalation", mock=True)
    assert "error" not in doc
    assert doc["rule_count"] > 0
    assert "threat_matrix" in doc and "attack_path" in doc
    assert doc["cluster"]["profile"] == "self-managed"


def test_all_expected_tools_are_registered():
    tools = build_tools()
    assert ALL_TOOLS <= set(tools.keys())
    assert set(tools.keys()) == ALL_TOOLS, \
        f"unexpected extra/missing tools: {set(tools.keys()) ^ ALL_TOOLS}"


def test_every_tool_has_a_nonempty_docstring():
    # every tool's docstring IS its description as surfaced to the calling LLM, 
    # FastMCP reads it directly, so an empty one means a nameless, undocumented tool.
    tools = build_tools()
    for name, fn in tools.items():
        assert fn.__doc__ and len(fn.__doc__.strip()) > 20, \
            f"{name} has no meaningful docstring/description"


def test_no_remediation_or_apply_tool_is_exposed():
    # Safety control: the tool detects and reports only, no write/remediation/apply path
    # is exposed over MCP (or anywhere). This must stay locked out.
    tools = build_tools()
    forbidden_markers = ("apply", "remediate", "remediation", "fix_", "patch", "rollback",
                         "playbook")
    offenders = [name for name in tools
                 if any(m in name.lower() for m in forbidden_markers)]
    assert offenders == [], f"unexpected write-capable MCP tool(s): {offenders}"


def test_deploy_falco_is_read_only_by_default():
    # The one tool that CAN write to a cluster must not do so unless explicitly opted in, 
    # the read-only / offline guarantee holds for every normal invocation.
    tools = build_tools()
    out = tools["deploy_falco"](webhook_url="http://x/api/runtime")
    assert out["status"] == "dry-run"
    assert out["commands"] and "commands were" not in out  # returns commands, does not run
    assert "K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE" in out["note"]


def test_run_scan_mock_full_cluster_returns_findings():
    tools = build_tools()
    doc = tools["run_scan"](mock=True)
    assert "error" not in doc
    assert doc["summary"]["total_findings"] > 0
    assert doc["risk"]["rating"] in ("Excellent", "Good", "Fair", "Poor", "Critical")
    # per-finding report-grade context is embedded, same as `-o json` from the CLI;
    # remediation was removed by design, so it must NOT be present
    assert all(f.get("impact") for f in doc["findings"])
    assert not any("remediation" in f for f in doc["findings"])


def test_run_scan_respects_selector_and_scope():
    tools = build_tools()
    doc = tools["run_scan"](scope_level="namespace", namespace="production",
                            tactics=["Persistence"], mock=True)
    assert "error" not in doc
    for f in doc["findings"]:
        assert f["resource"]["namespace"] in (None, "production")


def test_run_scan_max_findings_truncates():
    tools = build_tools()
    doc = tools["run_scan"](mock=True, max_findings=1)
    assert len(doc["findings"]) <= 1
    if doc["summary"]["total_findings"] > 1:
        assert doc.get("findings_truncated") is True


def test_run_scan_bad_selector_returns_error_not_exception():
    tools = build_tools()
    doc = tools["run_scan"](tactics=["Not A Real Tactic"], mock=True)
    assert "error" in doc


def test_preview_scan_matches_run_scan_rule_count_without_scanning():
    tools = build_tools()
    preview = tools["preview_scan"](tactics=["Persistence"])
    scanned = tools["run_scan"](tactics=["Persistence"], mock=True)
    assert preview["rule_count"] == len(scanned["resolved_rules"])
    assert set(preview["resolved_rule_ids"]) == set(scanned["resolved_rules"])


def test_interpret_query_resolves_natural_language():
    tools = build_tools()
    interp = tools["interpret_query"]("scan production for persistence")
    assert interp["intent"] == "scan"
    assert "production" in interp["scope"]
    assert interp["rule_count"] > 0


def test_intelligent_scan_one_call_end_to_end():
    # One call: parses NL, detects cluster, runs scan, returns findings + risk + cluster info
    tools = build_tools()
    result = tools["intelligent_scan"](
        query="find exposed secrets in production",
        scope_level="cluster",
        mock=True
    )
    assert result["intent"] == "scan"
    assert result["rule_count"] > 0
    assert "findings" in result
    assert "risk" in result
    assert "cluster" in result
    assert result["cluster"]["profile"] == "self-managed"


def test_run_cis_benchmark_mock_covers_all_130_controls():
    tools = build_tools()
    report = tools["run_cis_benchmark"](mock=True)
    assert report["total_controls"] == 130


def test_list_namespaces_mock():
    tools = build_tools()
    out = tools["list_namespaces"](mock=True)
    assert "namespaces" in out
    assert "production" in out["namespaces"]


def test_list_shards_covers_every_registered_shard():
    from k8smatrixwarden.bootstrap import build_platform
    tools = build_tools()
    shards = tools["list_shards"]()
    assert len(shards) == len(build_platform().registry.shard_names())
    assert all(s["rule_count"] > 0 for s in shards)


def test_generate_rbac_manifest_is_read_only():
    tools = build_tools()
    manifest = tools["generate_rbac_manifest"]()
    write_verbs = {"create", "update", "patch", "delete", "deletecollection"}
    for item in manifest["items"]:
        if item["kind"] != "ClusterRole":
            continue
        for rule in item["rules"]:
            assert not (write_verbs & set(rule["verbs"]))


# ======================================================================= #
# Knowledge-layer browsability (list_* complements every get_*/lookup_*)
# ======================================================================= #
def test_list_kubectl_commands_covers_get_kubectl_command():
    tools = build_tools()
    names = tools["list_kubectl_commands"]()
    assert "list-privileged-pods" in names
    assert names["list-privileged-pods"] == tools["get_kubectl_command"](
        "list-privileged-pods")


def test_list_tool_commands_covers_get_tool_commands():
    tools = build_tools()
    all_tools = tools["list_tool_commands"]()
    assert "trivy" in all_tools
    assert all_tools["trivy"] == tools["get_tool_commands"]("trivy")


def test_list_cves_covers_lookup_cve():
    tools = build_tools()
    all_cves = tools["list_cves"]()
    assert "CVE-2024-9486" in all_cves
    assert all_cves["CVE-2024-9486"] == tools["lookup_cve"]("CVE-2024-9486")



def test_get_compliance_ruleset_single_and_all():
    tools = build_tools()
    all_fw = tools["get_compliance_ruleset"]()
    assert set(all_fw) == {"CIS", "PSS", "NSA_CISA"}
    assert tools["get_compliance_ruleset"]("cis") == all_fw["CIS"]  # case-insensitive


# ======================================================================= #
# validate_platform (doctor equivalent)
# ======================================================================= #
def test_validate_platform_clean():
    tools = build_tools()
    out = tools["validate_platform"]()
    assert out["valid"] is True
    assert out["problems"] == []
    assert out["shards_loaded"] >= 11
    assert out["rules_loaded"] >= 50


# ======================================================================= #
# evaluate_runtime_events (Runtime Agent, previously unexposed)
# ======================================================================= #
def test_evaluate_runtime_events_detects_falco_and_audit():
    tools = build_tools()
    alerts = tools["evaluate_runtime_events"]([
        {"source": "falco", "proc": "bash"},
        {"source": "falco", "connect": "169.254.169.254:80"},
        {"source": "audit", "verb": "create", "resource": "clusterrolebindings"},
        {"source": "falco", "proc": "nginx"},  # benign, should not alert
    ])
    ids = {a["rule_id"] for a in alerts}
    assert "rt-shell-in-container" in ids
    assert "rt-metadata-api" in ids
    assert "rt-new-rolebinding" in ids
    assert len(alerts) == 3


def test_evaluate_runtime_events_empty_stream_is_safe():
    tools = build_tools()
    assert tools["evaluate_runtime_events"]([]) == []


def test_evaluate_runtime_events_tags_alerts_as_runtime_surface():
    tools = build_tools()
    alerts = tools["evaluate_runtime_events"]([{"source": "falco", "proc": "bash"}])
    assert alerts and all(a["surface"] == "runtime" for a in alerts)
    assert all("source" in a for a in alerts)


def test_list_runtime_detections_are_all_runtime_surface():
    tools = build_tools()
    cat = tools["list_runtime_detections"]()
    assert len(cat) >= 8
    assert all(d["surface"] == "runtime" for d in cat)
    assert all(d["source"] in ("falco", "audit", "drift") for d in cat)
    # and they carry a MITRE mapping, same taxonomy the scan rules use
    assert all(d["tactic"] and d["technique_id"] for d in cat)


def test_scan_rules_are_all_scan_surface():
    # the counterpart guarantee: every registry (Scanner) rule is point-in-time 'scan'
    tools = build_tools()
    assert all(r["surface"] == "scan" for r in tools["list_rules"]())


# ======================================================================= #
# build_threat_matrix (Kubernetes Threat Matrix projection, §12)
# ======================================================================= #
def test_build_threat_matrix_fresh_scan():
    tools = build_tools()
    m = tools["build_threat_matrix"](scope_level="cluster", mock=True)
    assert "error" not in m
    assert m["summary"]["tactics_total"] == 9
    assert m["summary"]["tactics_hit"] == 9        # insecure mock hits every tactic
    assert len(m["columns"]) == 9


def test_build_threat_matrix_coverage_has_no_hits():
    tools = build_tools()
    m = tools["build_threat_matrix"](coverage=True)
    assert m["summary"]["techniques_hit"] == 0
    assert m["summary"]["techniques_covered"] > 0


def test_build_threat_matrix_from_saved_report():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        doc = tools["run_scan"](mock=True, save=True, reports_dir=d)
        m = tools["build_threat_matrix"](scan_id=doc["scan_id"], reports_dir=d)
        assert "error" not in m and m["summary"]["scan_id"] == doc["scan_id"]


def test_build_threat_matrix_selector_scopes_hits():
    tools = build_tools()
    m = tools["build_threat_matrix"](tactics=["Persistence"], mock=True)
    persistence = next(c for c in m["columns"] if c["tactic"] == "Persistence")
    assert persistence["techniques_hit"] > 0       # the selected tactic is implicated
    # multi-tactic findings may also light up other columns, that's the attack-path map


def test_build_threat_matrix_missing_report_errors():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        assert "error" in tools["build_threat_matrix"](scan_id="nope", reports_dir=d)


# ======================================================================= #
# list_reports / download_report (save -> list -> export in any format)
# ======================================================================= #
def test_report_lifecycle_save_list_download():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        assert tools["list_reports"](reports_dir=d) == []

        doc = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                                save=True, reports_dir=d)
        assert doc["saved"] is True
        scan_id = doc["scan_id"]

        reports = tools["list_reports"](reports_dir=d)
        assert len(reports) == 1
        assert reports[0]["scan_id"] == scan_id

        for fmt in ("markdown", "json", "sarif", "html", "text"):
            dl = tools["download_report"](scan_id=scan_id, format=fmt, reports_dir=d)
            assert "error" not in dl
            assert dl["format"] == fmt
            assert len(dl["content"]) > 100

        # omitting scan_id downloads the latest
        latest = tools["download_report"](reports_dir=d)
        assert latest["scan_id"] == scan_id


def test_download_report_missing_scan_id_returns_error():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        out = tools["download_report"](scan_id="scan-does-not-exist", reports_dir=d)
        assert "error" in out


def test_download_report_empty_store_returns_error():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        out = tools["download_report"](reports_dir=d)
        assert "error" in out


def test_run_scan_without_save_does_not_persist():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                          save=False, reports_dir=d)
        assert tools["list_reports"](reports_dir=d) == []


# ======================================================================= #
# run_scan output_format (fresh scan rendered to any of the 6 report formats)
# ======================================================================= #
def test_run_scan_output_format_markdown_returns_rendered_content():
    tools = build_tools()
    r = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                          output_format="markdown")
    assert "content" in r and "findings" not in r
    assert r["format"] == "markdown"
    assert "# 🛡️ K8s Security Report" in r["content"]
    assert r["total_findings"] > 0


def test_run_scan_output_format_sarif_is_valid_json():
    tools = build_tools()
    r = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                          output_format="sarif")
    doc = json.loads(r["content"])
    assert doc["version"] == "2.1.0"


def test_run_scan_default_output_format_is_unchanged_json_shape():
    # default output_format stays structured JSON (findings, no rendered `content`).
    # Scans now persist by default so they reach the web dashboard, assert that, using an
    # isolated store so the test never writes into the real per-user reports dir.
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        r = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True, reports_dir=d)
        assert "findings" in r and "content" not in r
        assert r["saved"] is True
        assert tools["list_reports"](reports_dir=d), "default scan should be listed"


def test_run_scan_typoed_output_format_returns_error_not_silent_terminal():
    # a typo'd format must never silently render as terminal while claiming success, 
    # that's a real bug this test guards (found during review; format was previously
    # echoed back unvalidated).
    tools = build_tools()
    r = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                          output_format="markdwn")
    assert "error" in r
    assert "content" not in r


def test_download_report_typoed_format_returns_error():
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True, save=True,
                          reports_dir=d)
        r = tools["download_report"](format="sariff", reports_dir=d)
        assert "error" in r
        assert "content" not in r


# ======================================================================= #
# PDF (binary), travels as base64 over MCP's JSON transport, never a bare `content`
# str. Skips gracefully if the optional `pdf` extra (fpdf2) isn't installed.
# ======================================================================= #
try:
    import fpdf  # noqa: F401
    _FPDF = True
except ImportError:
    _FPDF = False


def test_run_scan_output_format_pdf_returns_base64_not_content():
    if not _FPDF:
        return
    import base64
    tools = build_tools()
    r = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                          output_format="pdf")
    assert "error" not in r
    assert "content" not in r
    assert r["encoding"] == "base64"
    data = base64.b64decode(r["content_base64"])
    assert data.startswith(b"%PDF-")


def test_download_report_format_pdf_returns_base64():
    if not _FPDF:
        return
    import base64
    tools = build_tools()
    with tempfile.TemporaryDirectory() as d:
        tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True, save=True,
                          reports_dir=d)
        r = tools["download_report"](format="pdf", reports_dir=d)
        assert "error" not in r
        data = base64.b64decode(r["content_base64"])
        assert data.startswith(b"%PDF-")


def test_pdf_is_a_valid_output_format_choice():
    tools = build_tools()
    # even without fpdf2 installed, "pdf" itself must be accepted as a known format, 
    # only the underlying render should fail, not format validation
    r = tools["run_scan"](rule_ids=["workload-no-seccomp"], mock=True,
                          output_format="pdf")
    assert r.get("error") != ("unknown output_format 'pdf', valid values: html, "
                              "json, markdown, sarif, terminal, text")
