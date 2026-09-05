"""
K8s Security MCP Server (§8/§10).

Exposes the full read-only capability surface of k8smatrixwarden as MCP tools, so any
MCP-compatible AI agent (Claude, Cursor, VS Code, Windsurf, ...) can do everything the
CLI can do: scan, audit, browse the rule/knowledge datasets, evaluate a runtime event
stream, and list/export previously-saved reports in any format, the same engine the CLI
and chat use.

Read-only by design: this tool does not do remediation/apply at all, it detects and
reports, it never mutates the cluster or deletes anything. Scanning (§4.4), the knowledge
datasets, and report rendering/export are all side-effect-free;
`tests/test_mcp.py::test_no_remediation_or_apply_tool_is_exposed` enforces this stays true.

Four layers (the exact tool count is whatever `build_tools()` returns, `doctor` and
`python -m k8smatrixwarden mcp --list-tools` both report it, so no number is hard-coded
here to drift):
  1. Knowledge  , browse/query the rule registry, taxonomy, and the 6 MCP datasets
  2. Scan/audit , scan / CIS benchmark / runtime detections + event eval / threat matrix
  3. Reports    , persist a scan, list/export it in any format, and analyse a stored one
                   (explain a finding, evidence coverage, posture change, federation)
  4. Platform   , validate the install, generate least-privilege RBAC

Uses the official `mcp` Python SDK (FastMCP) when installed. If it is not installed, the
same functions are still callable in-process via `build_tools()`, the server is a thin
protocol wrapper over them, so nothing is lost when running without the SDK. Each tool's
docstring below IS its description as surfaced to the calling LLM (FastMCP reads it
directly), kept accurate and complete for exactly that reason.
"""
from __future__ import annotations

import json
import os
from typing import Annotated, Any, Optional

from ..bootstrap import build_platform
from ..core.evidence import detect_provider
from ..core.report_store import DEFAULT_DIR as _DEFAULT_REPORTS_DIR
from ..core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity
from . import datasets

#: ReportingEngine.render()'s valid `fmt` values, anything else silently falls back to
#: `terminal` there, which would make a typo'd output_format look "successful" while
#: quietly ignoring what was actually asked for. MCP tools validate against this
#: explicitly instead and return a clear error.
_VALID_REPORT_FORMATS = {"terminal", "text", "markdown", "json", "sarif", "html", "pdf"}
#: pdf is the only format that renders to bytes, not str, MCP responses are JSON, which
#: has no binary type, so pdf content travels as base64 instead of a plain `content` string.

# --------------------------------------------------------------------------- #
# Per-parameter descriptions.
#
# FastMCP builds each tool's input JSON-Schema from the function signature; a plain type
# hint yields no `description`, so the calling LLM sees an untyped, undocumented argument.
# Wrapping the hint as `Annotated[T, Field(description=...)]` puts a human description on
# every parameter in the schema WITHOUT changing the runtime default (so in-process
# `build_tools()` callers and the tests keep working unchanged). The aliases below cover
# the parameters shared across many tools so each tool's signature stays readable and the
# wording stays consistent; one-off parameters are annotated inline at the call site.
#
# pydantic ships with the MCP SDK; when neither is installed (the stdlib-only core path),
# `_F` degrades to a no-op so `Annotated[T, None]` stays valid and imports never fail.
# --------------------------------------------------------------------------- #
try:
    from pydantic import Field as _F
except Exception:  # pragma: no cover - only when pydantic/the mcp SDK is absent
    def _F(*_a, **_k):  # type: ignore
        return None

# scope axes -------------------------------------------------------------- #
_ScopeLevel = Annotated[str, _F(description=(
    "Scope granularity: 'cluster' (default), 'namespace', 'workload', 'pod', 'node', "
    "'image', or 'helm_release'. Choose the narrowest scope that answers the question."))]
_Namespace = Annotated[Optional[str], _F(description=(
    "Namespace to scope to (when scope_level='namespace', or to narrow a cluster scan to "
    "one namespace). Use list_namespaces to see valid names."))]
_Name = Annotated[Optional[str], _F(description=(
    "Object name for a workload/pod/node/helm_release scope (e.g. the Deployment or Pod "
    "name). Ignored for a cluster or namespace scope."))]
_Kind = Annotated[Optional[str], _F(description=(
    "Workload kind when scope_level='workload', e.g. 'Deployment', 'DaemonSet', "
    "'StatefulSet'."))]
_Image = Annotated[Optional[str], _F(description=(
    "Container image reference (repo:tag or repo@sha256:…) when scope_level='image'."))]
# selector axes ----------------------------------------------------------- #
_Tactics = Annotated[Optional[list[str]], _F(description=(
    "MITRE ATT&CK tactic names to include, e.g. ['Privilege Escalation','Persistence']. "
    "Combined (union) with every other selector axis."))]
_Techniques = Annotated[Optional[list[str]], _F(description=(
    "MITRE technique ids/names or composite aliases (e.g. 'Container Escape') to include. "
    "Union'd with the other axes."))]
_Modules = Annotated[Optional[list[str]], _F(description=(
    "Domain shard names to include, e.g. ['rbac_identity','secrets']. See list_shards for "
    "valid values."))]
_RuleIds = Annotated[Optional[list[str]], _F(description=(
    "Exact rule ids to include (see list_rules), target specific checks regardless of "
    "tactic or module."))]
_Aliases = Annotated[Optional[list[str]], _F(description=(
    "Composite technique aliases to include, e.g. 'Exposed Secrets', 'Privileged Pods'."))]
_Frameworks = Annotated[Optional[list[str]], _F(description=(
    "Compliance frameworks whose rules to include: any of 'CIS', 'NSA', 'OWASP'."))]
_SeverityMin = Annotated[Optional[str], _F(description=(
    "Lowest severity to keep: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'. Findings below this "
    "are dropped from the selector."))]
# target / collector ------------------------------------------------------ #
_Mock = Annotated[bool, _F(description=(
    "True (default) scans the bundled insecure MOCK cluster. False scans a real cluster "
    "(needs the 'kubernetes' extra plus a reachable kubeconfig/context)."))]
_Fixture = Annotated[Optional[str], _F(description=(
    "Path to a custom mock-cluster JSON fixture to scan instead of the bundled one "
    "(only used when mock=True)."))]
_Kubeconfig = Annotated[Optional[str], _F(description=(
    "Path to a kubeconfig file for a live scan (default: ~/.kube/config). Ignored when "
    "mock=True."))]
_Context = Annotated[Optional[str], _F(description=(
    "kubeconfig context to use for a live scan (default: current-context). Ignored when "
    "mock=True."))]
# reports ----------------------------------------------------------------- #
_ReportsDir = Annotated[str, _F(description=(
    "Report store directory to read/write. Defaults to the shared per-user store so scans "
    "also show up in the web dashboard history; override with $K8SMATRIXWARDEN_REPORTS_DIR."))]
_ScanIdOpt = Annotated[Optional[str], _F(description=(
    "A previously saved scan id to operate on instead of running a fresh scan (see "
    "list_reports). Omit to run a new scan."))]
_OutputFormat = Annotated[str, _F(description=(
    "Report format: 'json' (default, structured findings + context) or one of "
    "'markdown' | 'html' | 'sarif' | 'text' | 'terminal' | 'pdf' (rendered report; pdf "
    "comes back base64-encoded)."))]
_Save = Annotated[bool, _F(description=(
    "Persist this scan to the report store (default True) so it appears in the web "
    "dashboard and can be re-exported later with download_report without rescanning."))]
_ScanName = Annotated[Optional[str], _F(description=(
    "Optional human name for this scan. Seeds the report name and id as "
    "'<name> + date + time', making it easy to find in the dashboard history."))]
_MaxFindings = Annotated[Optional[int], _F(description=(
    "Cap how many findings are returned in JSON mode (all are still counted in the risk "
    "score/summary; only the returned list is truncated). Ignored for non-JSON output."))]
_Events = Annotated[list[dict], _F(description=(
    "Batch of runtime events to evaluate. Each needs a 'source' of 'falco' or 'audit' "
    "plus that source's fields (Falco: proc/connect/file/op; audit: verb/resource/"
    "namespace/count)."))]


def _ist_now() -> str:
    """Now, as the scan clock sees it. Used to age runtime events so a stale alert is
    labelled `historical` rather than presented as a current observation."""
    from ..core.timeutil import ist_timestamp
    return ist_timestamp()


def _encode_report(content) -> dict:
    """content is `str` for every format except pdf, where it's `bytes`. Return the
    right shape for either: {"content": "..."} for text formats, or
    {"content_base64": "...", "encoding": "base64"} for pdf, the caller must
    base64-decode and write the result in binary mode."""
    if isinstance(content, bytes):
        import base64
        return {"content_base64": base64.b64encode(content).decode("ascii"),
                "encoding": "base64"}
    return {"content": content}


def _agg(result) -> dict:
    """Resource-finding and workload-issue counts, recomputed when a stored report predates
    workload aggregation so an old scan still reports both."""
    from ..core.reporting import workload_summary
    return workload_summary(result)


def build_tools(config_path: Optional[str] = None) -> dict[str, Any]:
    """Return the callable tool implementations (usable with or without the MCP SDK)."""
    platform = build_platform(config_path)

    # ================================================================== #
    # LAYER 1, Knowledge: rule registry + the 6 MCP datasets (§10)
    # ================================================================== #
    def list_rules(
        shard: Annotated[Optional[str], _F(description=(
            "Restrict to one domain shard, e.g. 'rbac_identity' (see list_shards for "
            "valid names). Omit for all shards."))] = None,
        tactic: Annotated[Optional[str], _F(description=(
            "Restrict to rules mapped to one MITRE tactic, e.g. 'Privilege Escalation'. "
            "Omit for all tactics."))] = None) -> list[dict]:
        """List rules in the registry, each with its id, title, owning shard, severity,
        and full taxonomy (MITRE tactic+technique, OWASP, CIS, NSA/CISA tags). Optionally
        filter to one domain shard (e.g. 'rbac_identity') and/or one MITRE tactic (e.g.
        'Privilege Escalation'). Use this to discover valid rule_id values for
        preview_scan/run_scan's `rule_ids` selector, or to browse what a shard covers."""
        rules = platform.registry.rules.all()
        if shard:
            rules = [r for r in rules if r.owning_shard == shard]
        if tactic:
            rules = [r for r in rules
                     if any(m.tactic.value.lower() == tactic.lower() for m in r.mitre)]
        return [r.metadata() for r in rules]

    def resolve_selector(tactics: _Tactics = None,
                         techniques: _Techniques = None,
                         modules: _Modules = None,
                         aliases: _Aliases = None,
                         frameworks: _Frameworks = None,
                         rule_ids: _RuleIds = None) -> list[str]:
        """Resolve a selector (any combination of MITRE tactics, techniques/composite
        aliases like 'Container Escape', domain modules, compliance frameworks, or exact
        rule ids) to the concrete list of rule ids it expands to, WITHOUT scanning
        anything. Lower-level than preview_scan (no scope, no shard breakdown); use this
        when you only need the raw rule_id list, e.g. to feed into another tool."""
        sel = Selector(tactics=tactics or [], techniques=techniques or [],
                       modules=modules or [], aliases=aliases or [],
                       frameworks=frameworks or [], rule_ids=rule_ids or [])
        return platform.mapping.resolve(sel)

    def get_kubectl_command(
        name: Annotated[str, _F(description=(
            "The dataset key of the kubectl one-liner to fetch, e.g. "
            "'list-privileged-pods' or 'cluster-admin-bindings'. Call "
            "list_kubectl_commands() first to see every valid name."))]) -> str:
        """Look up ONE named kubectl security-inspection one-liner from the kubectl
        Security Commands dataset (e.g. 'list-privileged-pods', 'cluster-admin-bindings').
        Returns '' if the name isn't found, call list_kubectl_commands() first to see
        every available name and its command."""
        return datasets.KUBECTL_COMMANDS.get(name, "")

    def list_kubectl_commands() -> dict:
        """List every named kubectl security-inspection command in the dataset (name ->
        the full command, e.g. jq-piped one-liners to list privileged pods, cluster-admin
        bindings, wildcard ClusterRoles, NodePort services, mutating webhooks, ...). Use
        this to discover what's available before calling get_kubectl_command(name)."""
        return dict(datasets.KUBECTL_COMMANDS)

    def get_tool_commands(
        tool: Annotated[str, _F(description=(
            "External security tool name to fetch example invocations for, e.g. 'trivy', "
            "'kube-bench', 'kubescape', 'cosign', 'trufflehog'. Call list_tool_commands() "
            "to see every valid name."))]) -> list:
        """Look up the example invocation(s) for ONE named external security tool (e.g.
        'trivy', 'kube-bench', 'kubescape', 'cosign', 'trufflehog'). Returns [] if the
        tool name isn't found, call list_tool_commands() to see every available name."""
        return datasets.TOOL_COMMANDS.get(tool, [])

    def list_tool_commands() -> dict:
        """List every external security tool in the dataset with its example
        invocation(s) (trivy, kube-bench, kubeaudit, kubesec, kubescape, popeye,
        trufflehog, cosign). These are the tools k8smatrixwarden integrates as normalizing
        adapters (§22), this dataset is how to run them directly."""
        return dict(datasets.TOOL_COMMANDS)

    def lookup_cve(
        cve_id: Annotated[str, _F(description=(
            "CVE identifier to look up, e.g. 'CVE-2024-9486' (case-insensitive). Call "
            "list_cves() to see every id in the bundled knowledge base."))]) -> dict:
        """Look up ONE CVE by id (e.g. 'CVE-2024-9486') in the bundled Kubernetes CVE
        knowledge base, returns {severity, affects, desc}, or {} if not found. This is
        a curated subset (§15.1), not a live feed, call list_cves() to see every id
        that's actually in it before assuming a lookup miss means "not vulnerable"."""
        return datasets.CVE_KB.get(cve_id.upper(), {})

    def list_cves() -> dict:
        """List every CVE in the bundled Kubernetes CVE knowledge base, each with its
        severity, affected version range, and a one-line description."""
        return dict(datasets.CVE_KB)

    def get_compliance_ruleset(
        framework: Annotated[Optional[str], _F(description=(
            "Which framework's metadata to return: 'CIS', 'PSS', or 'NSA_CISA' "
            "(case-insensitive). Omit to get all three."))] = None) -> dict:
        """Get metadata about a compliance framework k8smatrixwarden tracks, 'CIS' (version,
        tool, pass threshold), 'PSS' (Pod Security Standard levels), or 'NSA_CISA' (the
        hardening-guide sections covered). Omit `framework` to get all three. This is
        summary metadata, not the controls themselves, for the full, evaluated CIS
        Kubernetes Benchmark (all 130 controls with PASS/FAIL/MANUAL/NA/NEEDS_NODE/NOT_ASSESSED
        status), use run_cis_benchmark instead."""
        if framework:
            return datasets.COMPLIANCE_RULES.get(framework.upper(), {})
        return dict(datasets.COMPLIANCE_RULES)

    def get_taxonomy() -> dict:
        """Get the vendored MITRE ATT&CK for Containers technique catalog (the
        machine-readable technique ids/names every rule's `mitre` tags are validated
        against) plus the current rule-count-per-tactic coverage snapshot."""
        return {"techniques": platform.taxonomy.get("techniques", []),
                "coverage": platform.coverage()}

    def mitre_coverage() -> dict:
        """Get the number of registered rules per MITRE ATT&CK tactic (all 9: Initial
        Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
        Credential Access, Discovery, Lateral Movement, Impact), a quick "how well
        covered is each attacker behavior" snapshot, same data k8smatrixwarden's `coverage`
        CLI command and chat's "coverage" turn show."""
        return platform.coverage()

    def list_shards() -> list[dict]:
        """List the 10 domain shards (the scanner's execution boundary, RBAC, network,
        secrets, images, workload/pod security, control plane, compliance, attack
        surface, admission control, cloud IAM) with each shard's title and rule count.
        Shard names are the valid values for preview_scan/run_scan's `modules` selector
        and this tool's own `shard` filter on list_rules."""
        out = []
        for shard_name in platform.registry.shard_names():
            shard = platform.registry.get_shard(shard_name)
            rules = platform.registry.rules.by_shard(shard_name)
            out.append({"name": shard_name, "title": getattr(shard, "title", shard_name),
                       "index": getattr(shard, "index", ""), "rule_count": len(rules)})
        return out

    def list_namespaces(mock: _Mock = True, fixture: _Fixture = None,
                        kubeconfig: _Kubeconfig = None,
                        context: _Context = None) -> dict:
        """List namespace names visible in the target cluster (mock or live), use this
        before scoping a scan to a namespace, to avoid guessing a name that doesn't
        exist (preview_scan/run_scan won't validate it for you, they'll just find
        nothing)."""
        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            ev = collector.collect({"Namespace"}, Scope(ScopeLevel.CLUSTER))
            return {"namespaces": [n for n in ev.namespaces() if n]}
        except RuntimeError as exc:
            return {"error": str(exc)}

    def detect_cluster_provider(mock: _Mock = True, fixture: _Fixture = None,
                                kubeconfig: _Kubeconfig = None,
                                context: _Context = None) -> dict:
        """Detect which kind of cluster this is from its Node objects, so the right
        provider-specific choices are made without asking the user. Returns:
          cloud  , 'gcp' | 'aws' | 'azure' | 'local'  (which IaaS the nodes run on)
          managed, True if the control plane is a managed offering (GKE/EKS/AKS)
          profile, 'gke' | 'eks' | 'aks' | 'self-managed'  (pass straight to
                    run_cis_benchmark's `profile`, or leave it 'auto' to do this
                    automatically)
        Reads Node providerID + managed-service labels only, no writes, no control
        plane access. On the bundled mock cluster this returns local/self-managed."""
        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            ev = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER))
        except RuntimeError as exc:
            return {"error": str(exc)}
        return detect_provider(ev.get("Node", all_scopes=True))

    # NOTE: `intelligent_scan` is defined once, in Layer 2 below (it composes
    # detect_cluster_provider + interpret_query + run_scan + threat matrix + attack path).

    def validate_platform() -> dict:
        """Validate the k8smatrixwarden install itself, equivalent to the `k8smatrixwarden doctor` CLI
        command. Checks: every shard/rule loaded correctly, every rule's MITRE technique
        id exists in the vendored ATT&CK-for-Containers taxonomy, every composite alias
        (e.g. 'Container Escape') resolves to real rule ids, and there are no duplicate
        rule ids across shards. Call this first if any other tool is behaving
        unexpectedly, or after editing a custom config (`--config`/`config_path`)."""
        return {
            "shards_loaded": len(platform.registry.shard_names()),
            "shard_names": platform.registry.shard_names(),
            "rules_loaded": platform.rule_count(),
            "valid": not platform.validation_problems,
            "problems": list(platform.validation_problems),
        }

    # ================================================================== #
    # LAYER 2, Scan / audit / runtime: read-only, mirrors `scan` / `cis` / Runtime Agent
    # ================================================================== #
    def _make_scope(scope_level: Optional[str], namespace: Optional[str],
                    name: Optional[str], kind: Optional[str],
                    image: Optional[str]) -> Scope:
        key = (scope_level or "cluster").strip().lower().replace("-", "_")
        try:
            level = ScopeLevel(key)
        except ValueError:
            # Silently defaulting to a cluster-wide scan is the wrong failure mode: a
            # caller that asked for `namesapce` (or anything else unrecognised) would get
            # the WHOLE cluster back, believing it had scoped the request. Refuse instead.
            raise ValueError(
                f"unknown scope_level {scope_level!r}; valid values: "
                f"{', '.join(sorted(l.value for l in ScopeLevel))}") from None
        return Scope(level=level, namespace=namespace, name=name, kind=kind, image=image)

    def _make_selector(tactics, techniques, modules, rule_ids, aliases, frameworks,
                       severity_min) -> Selector:
        sev = Severity.parse(severity_min) if severity_min else None
        return Selector(tactics=tactics or [], techniques=techniques or [],
                        modules=modules or [], rule_ids=rule_ids or [],
                        aliases=aliases or [], frameworks=frameworks or [],
                        severity_min=sev)

    def preview_scan(scope_level: _ScopeLevel = "cluster", namespace: _Namespace = None,
                     name: _Name = None, kind: _Kind = None,
                     image: _Image = None, tactics: _Tactics = None,
                     techniques: _Techniques = None,
                     modules: _Modules = None,
                     rule_ids: _RuleIds = None,
                     aliases: _Aliases = None,
                     frameworks: _Frameworks = None,
                     severity_min: _SeverityMin = None) -> dict:
        """Resolve a scan's scope+selector to the exact rule set WITHOUT touching the
        cluster or running anything, the plan-before-you-scan step (mirrors `scan
        --dry-run` / the chat's confirmation prompt). Call this first, show the user
        what would run, then call run_scan with the same arguments to execute it."""
        try:
            scope = _make_scope(scope_level, namespace, name, kind, image)
            selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                      frameworks, severity_min)
            resolved = platform.mapping.resolve(selector)
        except ValueError as exc:
            return {"error": str(exc)}
        shards = sorted({platform.registry.rules.get(r).owning_shard for r in resolved
                         if platform.registry.rules.get(r)})
        return {"scope": scope.describe(), "selector": selector.describe(),
               "rule_count": len(resolved), "resolved_rule_ids": resolved,
               "shards": shards}

    def run_scan(scope_level: _ScopeLevel = "cluster", namespace: _Namespace = None,
                name: _Name = None, kind: _Kind = None,
                image: _Image = None, tactics: _Tactics = None,
                techniques: _Techniques = None,
                modules: _Modules = None,
                rule_ids: _RuleIds = None,
                aliases: _Aliases = None,
                frameworks: _Frameworks = None,
                severity_min: _SeverityMin = None, mock: _Mock = True,
                fixture: _Fixture = None, kubeconfig: _Kubeconfig = None,
                context: _Context = None, output_format: _OutputFormat = "json",
                save: _Save = True, reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR,
                scan_name: _ScanName = None,
                max_findings: _MaxFindings = None) -> dict:
        """Run a k8smatrixwarden security scan (read-only), mirrors `k8smatrixwarden scan`.

        scope_level: cluster | namespace | workload | node | pod | image | helm_release
        tactics/techniques/modules/rule_ids/aliases/frameworks: selector axes, union'd
          together (same semantics as the CLI's repeatable --tactic/--technique/... flags)
        mock: True (default) scans the bundled insecure mock cluster. False scans a real
          cluster and requires the 'kubernetes' extra + a reachable kubeconfig/context.
        output_format: 'json' (default) returns structured findings + risk score +
          per-finding context. Any of 'markdown'|'html'|'sarif'|'text'|'terminal'
          instead returns {scan_id, format, content, risk, total_findings} where
          `content` is the fully rendered report string, e.g. ask for 'markdown' to get
          a shareable report, or 'sarif' for a CI/GitHub-Code-Scanning-ready result.
          'pdf' returns {..., content_base64, encoding: "base64"} instead of `content`
          (PDF is binary; base64-decode it and write the bytes to a .pdf file yourself, 
          requires the optional `pdf` extra installed server-side, `pip install -e
          ".[pdf]"`, or this returns an `error`).
        save: persist this scan to the shared report store (default True) so it shows up in
          the web dashboard history and can be re-exported later with download_report,
          without re-scanning. Set False for a throwaway scan you don't want listed.
        scan_name: optional human name for the scan; the saved report is named/identified
          as '<scan_name> + date + time' so it is easy to find in the dashboard.
        max_findings: optionally cap how many findings are returned in JSON mode (all
          are still counted in the risk score / summary; only the returned list is
          truncated). Ignored for non-JSON output_format.
        """
        from ..agents.scanner import ScannerAgent

        fmt = (output_format or "json").lower()
        if fmt not in _VALID_REPORT_FORMATS:
            return {"error": f"unknown output_format {output_format!r}, valid values: "
                             f"{', '.join(sorted(_VALID_REPORT_FORMATS))}"}

        try:
            scope = _make_scope(scope_level, namespace, name, kind, image)
            selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                      frameworks, severity_min)
        except ValueError as exc:
            return {"error": str(exc)}

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except (RuntimeError, ValueError, OSError) as exc:
            # A malformed or unreadable fixture is bad input, not a crash: an MCP caller
            # gets a structured error the same as for any other bad argument.
            return {"error": f"could not load evidence source: {exc}"}

        request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
        try:
            result = ScannerAgent(platform).scan(
                request, collector, mode_label="mock" if mock else "live",
                name=scan_name or "")
        except Exception as exc:
            return {"error": f"scan failed: {exc}"}

        if save:
            from ..core.report_store import ReportStore
            ReportStore(reports_dir).save(result)

        if fmt != "json":
            try:
                content = platform.reporting.render(result, fmt)
            except RuntimeError as exc:
                return {"error": str(exc)}
            return {"scan_id": result.scan_id, "format": fmt,
                   **_encode_report(content), "saved": save,
                   "risk": {"cluster_risk": result.risk.cluster_risk,
                           "security_score": result.risk.security_score,
                           "rating": result.risk.rating},
                   "total_findings": result.total(),
                   # Both counts under names that cannot be confused: the evidence, and
                   # the number of separate fixes it amounts to.
                   "resource_findings": result.total(),
                   "workload_issues": (result.aggregation or {}).get("workload_issues"),
                   "aggregation": result.aggregation or {}}

        doc = json.loads(platform.reporting.json(result))
        if max_findings is not None and len(doc["findings"]) > max_findings:
            doc["findings"] = doc["findings"][:max_findings]
            doc["findings_truncated"] = True
        doc["saved"] = save
        # Resource types skipped during live collection (RBAC/absent API group), so the
        # caller knows coverage was partial rather than assuming a clean, complete scan.
        if getattr(collector, "warnings", None):
            doc["warnings"] = list(collector.warnings)
        return doc

    def interpret_query(
        text: Annotated[str, _F(description=(
            "The natural-language security request to parse, e.g. 'scan production for "
            "persistence' or 'any exposed secrets?'. Parsed into scope + selector + the "
            "resolved rule plan, without scanning."))]) -> dict:
        """Parse a natural-language security request (e.g. 'scan production for
        persistence', 'any exposed secrets?') into scope/selector and the resolved rule
        plan, WITHOUT executing it, the exact parsing `k8smatrixwarden chat` uses before it asks
        for confirmation. Follow up with run_scan using the returned scope/selector to
        actually execute it."""
        from ..agents.orchestrator import Orchestrator
        orch = Orchestrator(platform)
        interp = orch.interpret(text)
        return {
            "intent": interp.intent,
            "scope": interp.request.scope.describe(),
            "selector": interp.request.selector.describe(),
            "rule_count": len(interp.resolved_rule_ids),
            "resolved_rule_ids": interp.resolved_rule_ids,
            "notes": interp.notes,
            "plan_summary": orch.confirmation_summary(interp),
        }

    def intelligent_scan(
            query: Annotated[str, _F(description=(
                "Plain-English security request that drives scope + selector, e.g. 'scan "
                "the cluster for privilege escalation' or 'find exposed secrets in "
                "production'."))],
            scope_level: Annotated[Optional[str], _F(description=(
                "Override the scope granularity the query inferred: 'cluster', "
                "'namespace', 'workload', 'pod', 'node', 'image', or 'helm_release'."))] = None,
            namespace: _Namespace = None, name: _Name = None,
            kind: _Kind = None, image: _Image = None,
            mock: _Mock = True, fixture: _Fixture = None,
            kubeconfig: _Kubeconfig = None, context: _Context = None,
            max_findings: _MaxFindings = None,
            include_attack_path: Annotated[bool, _F(description=(
                "Include the derived kill-chain attack path in the result (default True); "
                "set False to omit it for a lighter response."))] = True,
            save: _Save = True, reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR,
            scan_name: _ScanName = None) -> dict:
        """One call, everything: parse a plain-English request into scope+selector, detect
        which kind of cluster it is, run the read-only scan, and return the findings, risk,
        threat matrix, and a kill-chain attack path, the composed shortcut for
        detect_cluster_provider + interpret_query + run_scan + build_threat_matrix +
        build_attack_path done by hand. The query drives scope/selector; pass any explicit
        scope arg (namespace/name/kind/image, or a non-cluster scope_level) to override
        what the query inferred. By default the scan is saved to the shared report store
        (save=True) so it appears in the web dashboard history; pass scan_name to label it.
        Returns: intent, scope, selector, rule_count, notes; `cluster` (detected cloud +
        CIS profile); `findings` + `risk` + embedded `threat_matrix`; and `attack_path`
        (the exploit chain; omit with include_attack_path=False). Use this to just ask and
        get the analysis, use preview_scan then run_scan when you need to confirm the plan
        before scanning."""
        from ..agents.orchestrator import Orchestrator
        from ..core.threat_matrix import build_threat_matrix as _build, attack_paths

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except RuntimeError as exc:
            return {"error": str(exc)}
        orch = Orchestrator(platform)
        interp = orch.interpret(query)
        request = interp.request
        # Explicit scope args win over what the query inferred.
        if any((namespace, name, kind, image)) or (scope_level and scope_level != "cluster"):
            try:
                request.scope = _make_scope(scope_level or "cluster", namespace, name,
                                            kind, image)
            except ValueError as exc:
                return {"error": str(exc)}
        try:
            result = orch.run(request, collector,
                              mode_label="mock" if mock else "live",
                              name=scan_name or "")
        except Exception as exc:
            return {"error": f"scan failed: {exc}"}

        if save:
            from ..core.report_store import ReportStore
            ReportStore(reports_dir).save(result)

        doc = json.loads(platform.reporting.json(result))
        if max_findings is not None and len(doc["findings"]) > max_findings:
            doc["findings"] = doc["findings"][:max_findings]
            doc["findings_truncated"] = True
        nodes = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER)).get(
            "Node", all_scopes=True)
        doc.update({
            "intent": interp.intent,
            "scope": request.scope.describe(),
            "selector": request.selector.describe(),
            "rule_count": len(interp.resolved_rule_ids),
            "notes": interp.notes,
            "cluster": detect_provider(nodes),
            "saved": save,
        })
        if getattr(collector, "warnings", None):
            doc["warnings"] = list(collector.warnings)
        if include_attack_path:
            doc["attack_path"] = attack_paths(_build(result, platform.registry.rules),
                                              result.runtime)
        return doc

    def run_cis_benchmark(mock: _Mock = True, fixture: _Fixture = None,
                          kubeconfig: _Kubeconfig = None, context: _Context = None,
                          profile: Annotated[str, _F(description=(
                              "CIS profile: 'auto' (default, detects the provider from Node "
                              "objects), 'self-managed', 'eks', 'gke', or 'aks'. Managed "
                              "profiles mark the provider-owned control plane N/A."))] = "auto",
                          kube_bench_json: Annotated[Optional[str], _F(description=(
                              "Optional path to `kube-bench --json` output, used to resolve "
                              "node file-permission controls the K8s API alone cannot "
                              "see."))] = None) -> dict:
        """Run the full CIS Kubernetes Benchmark v1.8 (130 controls, read-only) and
        return the report (PASS/FAIL/MANUAL/NA/NEEDS_NODE/NOT_ASSESSED per control). Mirrors
        `k8smatrixwarden cis`. profile: auto (default) | self-managed | eks | gke | aks, 
        'auto' detects the provider from Node objects (see detect_cluster_provider);
        managed profiles mark the provider-owned control plane NA instead of ungradeable.
        kube_bench_json: optional path to `kube-bench --json` output to resolve node
        file-permission controls that the K8s API alone cannot see."""
        from ..frameworks.cis import CISBenchmarkEngine
        from ..frameworks.kube_bench_adapter import maybe_load

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except RuntimeError as exc:
            return {"error": str(exc)}
        if profile == "auto":
            ev = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER))
            profile = detect_provider(ev.get("Node", all_scopes=True))["profile"]
        kb = maybe_load(kube_bench_json)
        report = CISBenchmarkEngine(platform).evaluate(collector, kube_bench_results=kb,
                                                        profile=profile)
        return report.as_dict()

    def run_compliance_audit(
            mock: _Mock = True, fixture: _Fixture = None,
            kubeconfig: _Kubeconfig = None, context: _Context = None,
            profile: Annotated[str, _F(description=(
                "CIS profile driving the underlying benchmark: 'auto' (default), "
                "'self-managed', 'eks', 'gke', or 'aks'."))] = "auto",
            frameworks: Annotated[Optional[list[str]], _F(description=(
                "Which governance frameworks to assess. Any of 'PCI-DSS-4.0', 'SOC2', "
                "'ISO-27001-2022', 'NIST-800-53-r5'. Omit for all four."))] = None,
            output_format: Annotated[str, _F(description=(
                "'json' (default, structured), 'markdown', 'html', or 'pdf' "
                "(base64-encoded auditor document)."))] = "json",
            kube_bench_json: Annotated[Optional[str], _F(description=(
                "Optional path to `kube-bench --json` output to resolve node "
                "file-permission CIS controls."))] = None) -> Any:
        """Produce a governance compliance audit, maps this cluster's posture onto PCI DSS
        v4.0, SOC 2, ISO 27001:2022 and NIST 800-53 rev5, with per-requirement
        pass/fail/partial/manual/not-assessed status, the evidence behind each verdict, and
        the exact findings blocking attestation (e.g. 'N findings block PCI DSS
        attestation'). Runs a read-only scan + the CIS benchmark once and crosswalks both;
        it invents no new checks. Assesses the Kubernetes-relevant subset of each framework
        and never marks an unverified requirement as passing. output_format: json (default)
        | markdown | html | pdf."""
        from ..frameworks.compliance import run_audit, framework_keys
        from ..frameworks import compliance_report as cr

        valid = set(framework_keys())
        if frameworks:
            bad = [f for f in frameworks if f not in valid]
            if bad:
                return {"error": f"unknown framework(s): {bad}. Valid: {sorted(valid)}"}
        try:
            report = run_audit(platform, mock=mock, fixture=fixture, kubeconfig=kubeconfig,
                               context=context, profile=profile, frameworks=frameworks,
                               kube_bench_json=kube_bench_json)
        except RuntimeError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            return {"error": f"compliance audit failed: {exc}"}

        fmt = (output_format or "json").lower()
        if fmt == "json":
            return report.as_dict()
        if fmt == "markdown" or fmt == "md":
            return _encode_report(cr.to_markdown(report))
        if fmt == "html":
            return _encode_report(cr.to_html(report))
        if fmt == "pdf":
            try:
                return _encode_report(cr.to_pdf(report))
            except RuntimeError as exc:
                return {"error": str(exc)}
        return {"error": f"unknown output_format: {output_format}"}

    def evaluate_runtime_events(events: _Events) -> dict:
        """Evaluate a batch of runtime events (Falco-style syscall events or Kubernetes
        audit events) against the Runtime Agent's rule catalog (§8) and return any
        alerts that fired. Each event needs a `source` key of 'falco' or 'audit' plus
        the relevant fields for that source, Falco: `proc` (process name), `connect`
        (dest addr:port), `file`, `op`; audit: `verb`, `resource`, `namespace`, `count`.
        Detects: shell-in-container, metadata-API access, network-recon tools,
        crypto-miner signatures, container-escape indicators, log tampering, new
        (Cluster)RoleBindings, exec into kube-system, secret enumeration, event
        deletion, and mass-delete spikes. This evaluates a batch you provide, it does
        NOT tail a live cluster (there is no running Runtime Agent DaemonSet here).

        Returns {"coverage": {...}, "alerts": [...]}. `coverage` accounts for every event
        you sent: `kmw_matches` (a curated rule owned the verdict), `falco_relays` (no
        curated rule matched, so Falco's own verdict is relayed as `falco:<rule>`),
        `unusable_events` (listed in `unusable` with a reason), and `discarded`, which is
        always 0 by construction. Each alert carries `provenance` naming the detector,
        the provider, and any supporting provider evidence, so a Falco verdict is never
        mistaken for a K8sMatrixWarden detection."""
        from ..agents.runtime import RuntimeAgent, normalize_events
        # Normalise first, as every other runtime entry point does. Without this, a raw
        # Falco JSON alert (the shape an operator actually has to hand) matched nothing and
        # returned an empty list: silent loss, in the one tool whose job is to say what was
        # detected. Already-flat events pass through unchanged.
        from ..core.runtime_identity import enrich_events
        # No cluster read here (this tool evaluates a batch you supply), so identity is
        # whatever the events carry; the status still says which of them are placeable.
        enriched, identity_coverage = enrich_events(normalize_events(events or []), [])
        alerts, coverage = RuntimeAgent().evaluate_batch(enriched)
        return {
            # Detection accounting first: an empty alert list means something different
            # when 0 events arrived than when 5 did and none could be used.
            "coverage": coverage,
            "identity_coverage": identity_coverage,
            "alerts": [{"rule_id": a.rule_id, "title": a.title,
                        "severity": a.severity.label, "tactic": a.tactic,
                        "surface": a.surface, "source": a.source,
                        "provenance": a.provenance(),
                        "identity_status": a.event.get("identity_status"),
                        "identity_missing": a.event.get("identity_missing"),
                        "event": a.event}
                       for a in alerts],
        }

    def correlate_runtime(events: _Events, scan_id: _ScanIdOpt = None,
                          scope_level: _ScopeLevel = "cluster", namespace: _Namespace = None,
                          name: _Name = None, kind: _Kind = None,
                          image: _Image = None, tactics: _Tactics = None,
                          techniques: _Techniques = None,
                          modules: _Modules = None,
                          rule_ids: _RuleIds = None,
                          aliases: _Aliases = None,
                          frameworks: _Frameworks = None,
                          severity_min: _SeverityMin = None, mock: _Mock = True,
                          fixture: _Fixture = None, kubeconfig: _Kubeconfig = None,
                          context: _Context = None,
                          reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Correlate a batch of runtime events against a scan's static findings, the
        "which weakness is being exploited RIGHT NOW" view. Evaluates `events` (same
        Falco/audit shape as evaluate_runtime_events) into runtime alerts, then joins them
        to scan findings by MITRE tactic (and namespace, when the event names one).
        Returns per-correlation `confidence`, 'confirmed' (same tactic + same namespace:
        the static weakness is being acted on), 'corroborated' (same tactic: behaviour
        aligns with a known gap), or 'runtime-only' (live behaviour the scan never
        predicted), plus headline counts (confirmed_exploitation, correlated,
        runtime_only). scan_id: correlate against a saved report; otherwise runs a fresh
        read-only scan (same scope/selector args as run_scan)."""
        from ..agents.runtime import RuntimeAgent, normalize_events
        from ..core.correlation import correlate

        if scan_id:
            from ..core.report_store import ReportStore
            try:
                result = ReportStore(reports_dir).resolve(scan_id)
            except FileNotFoundError:
                return {"error": f"no stored report with scan-id {scan_id!r}"}
            if result is None:
                return {"error": f"no stored reports in {reports_dir!r}"}
        else:
            from ..agents.scanner import ScannerAgent
            try:
                scope = _make_scope(scope_level, namespace, name, kind, image)
                selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                          frameworks, severity_min)
                collector = platform.make_collector(mock=mock, fixture=fixture,
                                                    kubeconfig=kubeconfig, context=context)
            except (ValueError, RuntimeError, OSError) as exc:
                return {"error": str(exc)}
            request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
            try:
                result = ScannerAgent(platform).scan(
                    request, collector, mode_label="mock" if mock else "live")
            except Exception as exc:
                return {"error": f"scan failed: {exc}"}
        alerts = RuntimeAgent().evaluate_stream(normalize_events(events or []))
        return correlate(result.findings, alerts,
                         cluster=result.cluster_name,
                         now=_ist_now())

    def detect_drift(events: _Events, namespace: _Namespace = None,
                     mock: _Mock = True, fixture: _Fixture = None,
                     kubeconfig: _Kubeconfig = None,
                     context: _Context = None) -> dict:
        """Detect runtime behaviour that CONTRADICTS a Pod's declared security posture, 
        the strongest exploitation signal, because it means a control the operator thinks
        is enforced is not. Fetches Pod specs (optionally scoped to `namespace`), reads
        each pod's promise (runAsNonRoot / readOnlyRootFilesystem / not-privileged), then
        checks `events` against the pod they name (Falco k8s.pod.name enrichment; events
        that don't name a scanned pod are skipped). Flags: process as uid 0 despite
        runAsNonRoot; write outside tmp despite readOnlyRootFilesystem; a privileged-only
        op (nsenter/mount/release_agent) from a non-privileged pod. Returns drift findings
        (each CRITICAL: declared vs observed vs pod) + counts. Read-only."""
        from ..agents.runtime import normalize_events
        from ..core.correlation import detect_drift as _drift

        level = ScopeLevel.NAMESPACE if namespace else ScopeLevel.CLUSTER
        scope = Scope(level=level, namespace=namespace)
        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            ev = collector.collect({"Pod"}, scope)
        except RuntimeError as exc:
            return {"error": str(exc)}
        return _drift(ev.get("Pod"), normalize_events(events or []))

    def deploy_falco(
            webhook_url: Annotated[str, _F(description=(
                "URL Falco/falcosidekick should POST runtime events to, your "
                "K8sMatrixWarden runtime endpoint, e.g. "
                "'http://host.minikube.internal:8080/api/runtime'."))],
            namespace: Annotated[str, _F(description=(
                "Namespace to install Falco into (created if missing). Default 'falco'."))]
            = "falco") -> dict:
        """Falco + falcosidekick install helper for wiring up the runtime feed. K8sMatrixWarden
        is READ-ONLY by default, so this does NOT touch your cluster unless you opt in: it
        returns the exact `helm` commands (with the webhook pre-filled) for you to run
        yourself. Only when the env var K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1 is set will it
        execute them, that is the single write path in the tool and it is off by default, so
        the read-only / offline guarantee holds for every normal invocation. Requires helm."""
        # json_output=true makes Falco print one JSON alert per line to stdout, required
        # for the pull feed (a `scan --live` reads these pod logs directly); falcosidekick
        # covers the push feed (POST to /api/runtime). Setting both wires up either path.
        vals = (f"falco.json_output=true,"
                f"falcosidekick.enabled=true,"
                f"falcosidekick.config.webhook.address={webhook_url}")
        commands = [
            "helm repo add falcosecurity https://falcosecurity.github.io/charts",
            "helm repo update",
            f"helm install falco falcosecurity/falco -n {namespace} --create-namespace "
            f"--set {vals}",
        ]
        next_steps = [
            f"Check pod status: kubectl get pods -n {namespace}",
            f"Tail logs: kubectl logs -n {namespace} -l app=falco -f",
            "Send runtime events to /api/runtime to see correlations"]

        if os.environ.get("K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE") != "1":
            return {"status": "dry-run", "webhook": webhook_url, "commands": commands,
                    "next_steps": next_steps,
                    "note": ("K8sMatrixWarden is read-only by default, these commands were "
                             "NOT run. Execute them yourself, or set "
                             "K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1 to let this tool run them.")}

        import subprocess
        out = {"status": "ok", "steps": [], "commands": commands}
        try:
            subprocess.run(["helm", "repo", "add", "falcosecurity",
                           "https://falcosecurity.github.io/charts"],
                          check=True, capture_output=True, timeout=30)
            out["steps"].append("✓ Added falcosecurity Helm repo")
            subprocess.run(["helm", "repo", "update"], check=True,
                          capture_output=True, timeout=30)
            out["steps"].append("✓ Updated Helm repos")
            subprocess.run(
                ["helm", "install", "falco", "falcosecurity/falco",
                 "-n", namespace, "--create-namespace", "--set", vals],
                check=True, capture_output=True, timeout=60)
            out["steps"].append(f"✓ Installed Falco in ns/{namespace}")
            out["webhook"] = webhook_url
            out["next_steps"] = next_steps
        except FileNotFoundError:
            return {"error": "helm not found, install helm first (https://helm.sh)"}
        except subprocess.CalledProcessError as e:
            return {"error": f"helm install failed: {e.stderr.decode()[:200] if e.stderr else str(e)}"}
        except Exception as e:
            return {"error": str(e)}
        return out

    def list_runtime_detections() -> list[dict]:
        """List the Runtime Agent's detection catalog (§8), every rule tagged
        surface='runtime', i.e. what is caught by observing a LIVE stream (Falco/Tetragon
        syscalls, K8s audit events, container drift) rather than by a point-in-time scan.
        This is the runtime half of the runtime-vs-scan split: the Scanner's rules
        (list_rules) all carry surface='scan'. Each entry has id, title, severity, source
        (falco | audit | drift), and MITRE tactic/technique. Use evaluate_runtime_events to
        actually match a batch of events against these."""
        from ..agents.runtime import RuntimeAgent
        return RuntimeAgent().catalog()

    def build_threat_matrix(scope_level: _ScopeLevel = "cluster", namespace: _Namespace = None,
                            name: _Name = None, kind: _Kind = None,
                            image: _Image = None,
                            tactics: _Tactics = None,
                            techniques: _Techniques = None,
                            modules: _Modules = None,
                            rule_ids: _RuleIds = None,
                            aliases: _Aliases = None,
                            frameworks: _Frameworks = None,
                            severity_min: _SeverityMin = None,
                            scan_id: _ScanIdOpt = None,
                            coverage: Annotated[bool, _F(description=(
                                "True returns the GLOBAL detection-coverage matrix (which "
                                "techniques any rule can detect at all), with no scan "
                                "overlaid. Ignored when scan_id is set."))] = False,
                            mock: _Mock = True, fixture: _Fixture = None,
                            kubeconfig: _Kubeconfig = None, context: _Context = None,
                            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Project findings onto the Kubernetes Threat Matrix (the 9-tactic
        Microsoft/Redguard matrix, MITRE ATT&CK for Containers, §12) and return the full
        structure: a `summary` (tactics/techniques hit, coverage %) plus `columns`, one
        per tactic, each a list of technique `cells` with state gap|covered|hit, worst
        severity, finding count, mapped resources, and the ATT&CK reference URL. This is
        the same matrix the HTML report/web dashboard heatmap and the JSON report's
        `threat_matrix` block use.

        Three modes:
          • scan_id set        → build the matrix from a previously saved report (no rescan)
          • coverage=True      → the GLOBAL detection-coverage matrix (which techniques any
                                 rule can detect at all), with no scan overlaid
          • otherwise (default)→ run a fresh read-only scan with the given scope/selector
                                 (same args as run_scan) and overlay its findings

        Cells are painted three ways: `hit` (a finding fired, coloured by worst severity),
        `covered` (a rule exists but nothing fired this scan), `gap` (no rule yet, an
        honest, un-hidden coverage hole)."""
        from ..core.threat_matrix import build_threat_matrix as _build

        if coverage:
            from ..web.app import _empty_result
            return _build(_empty_result(platform), platform.registry.rules).as_dict()

        if scan_id:
            from ..core.report_store import ReportStore
            try:
                result = ReportStore(reports_dir).resolve(scan_id)
            except FileNotFoundError:
                return {"error": f"no stored report with scan-id {scan_id!r}"}
            if result is None:
                return {"error": f"no stored reports in {reports_dir!r}"}
            return _build(result, platform.registry.rules).as_dict()

        from ..agents.scanner import ScannerAgent
        try:
            scope = _make_scope(scope_level, namespace, name, kind, image)
            selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                      frameworks, severity_min)
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
        except (ValueError, RuntimeError, OSError) as exc:
            return {"error": str(exc)}
        request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
        try:
            result = ScannerAgent(platform).scan(
                request, collector, mode_label="mock" if mock else "live")
        except Exception as exc:
            return {"error": f"scan failed: {exc}"}
        return _build(result, platform.registry.rules).as_dict()

    def build_attack_path(scope_level: _ScopeLevel = "cluster", namespace: _Namespace = None,
                          name: _Name = None, kind: _Kind = None,
                          image: _Image = None, tactics: _Tactics = None,
                          techniques: _Techniques = None,
                          modules: _Modules = None,
                          rule_ids: _RuleIds = None,
                          aliases: _Aliases = None,
                          frameworks: _Frameworks = None,
                          severity_min: _SeverityMin = None,
                          scan_id: _ScanIdOpt = None, mock: _Mock = True,
                          fixture: _Fixture = None, kubeconfig: _Kubeconfig = None,
                          context: _Context = None,
                          reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Chain a scan's threat-matrix HIT cells into a kill-chain exploit path, the
        tactics an attacker can actually string together in THIS cluster, Initial Access
        -> ... -> Impact. Returns `chain` (the tactic sequence), `steps` (per tactic: the
        available techniques, their worst severity, the exposing resources, and finding
        rule ids), `entry_points` (the first step's techniques, where the chain starts),
        and `reaches_impact` (does the chain terminate in the Impact tactic). scan_id:
        build from a previously saved report; otherwise runs a fresh read-only scan (same
        scope/selector args as run_scan). A coverage-only matrix has no hits, so no path."""
        from ..core.threat_matrix import build_threat_matrix as _build, attack_paths

        if scan_id:
            from ..core.report_store import ReportStore
            try:
                result = ReportStore(reports_dir).resolve(scan_id)
            except FileNotFoundError:
                return {"error": f"no stored report with scan-id {scan_id!r}"}
            if result is None:
                return {"error": f"no stored reports in {reports_dir!r}"}
        else:
            from ..agents.scanner import ScannerAgent
            try:
                scope = _make_scope(scope_level, namespace, name, kind, image)
                selector = _make_selector(tactics, techniques, modules, rule_ids, aliases,
                                          frameworks, severity_min)
                collector = platform.make_collector(mock=mock, fixture=fixture,
                                                    kubeconfig=kubeconfig, context=context)
            except (ValueError, RuntimeError, OSError) as exc:
                return {"error": str(exc)}
            request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
            try:
                result = ScannerAgent(platform).scan(
                    request, collector, mode_label="mock" if mock else "live")
            except Exception as exc:
                return {"error": f"scan failed: {exc}"}
        return attack_paths(_build(result, platform.registry.rules), result.runtime,
                            cluster=result.cluster_name)

    def analyze_rbac_paths(
            principal: Annotated[Optional[str], _F(description=(
                "Principal to analyse, as 'ServiceAccount/namespace/name' (or "
                "'User/name' / 'Group/name', which are cluster-scoped). Omit to analyse "
                "every ServiceAccount that has at least one escalation path."))] = None,
            namespace: _Namespace = None,
            max_hops: Annotated[int, _F(description=(
                "Traversal depth cap (default 6). Each RBAC hop is one edge: principal -> "
                "binding -> role -> capability -> next principal."))] = 6,
            limit: Annotated[int, _F(description=(
                "Maximum principals to report on when no principal is named."))] = 20,
            mock: _Mock = True, fixture: _Fixture = None,
            kubeconfig: _Kubeconfig = None, context: _Context = None) -> dict:
        """Multi-hop RBAC escalation analysis: model the cluster's RBAC as a graph and
        return the concrete, evidence-backed paths from a principal to a privilege.

        Each path is a chain of edges, ServiceAccount -> (Cluster)RoleBinding ->
        (Cluster)Role -> capability -> (optionally) another principal or an admin
        ClusterRole, and every edge names the object it was read from and why it exists.
        Paths are shortest-first; traversal is cycle-safe and depth-capped.

        Only evidence supports a path: a capability whose target does not exist in this
        cluster (e.g. 'can bind any role' with no admin ClusterRole collected) is reported
        as a capability with no onward hop rather than as an escalation. Namespaces are
        respected, a namespaced permission never reaches another namespace's identities.

        Read-only: reads the same cluster snapshot a scan reads, and changes nothing."""
        from ..core.models import Scope as _Scope, ScopeLevel as _SL
        from ..core.rbac_graph import Node, RbacGraph

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            evidence = collector.collect(
                {"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding",
                 "ServiceAccount"},
                _Scope(_SL.NAMESPACE, namespace=namespace) if namespace
                else _Scope(_SL.CLUSTER))
        except (ValueError, RuntimeError) as exc:
            return {"error": str(exc)}
        graph = RbacGraph.from_evidence(evidence)
        # Cluster is part of a principal's identity once results leave this process: two
        # clusters can both have `default` in `kube-system`, and an agent correlating them
        # needs to know which one it is looking at.
        try:
            cluster_label = collector.cluster_label()
        except Exception:
            cluster_label = None

        if principal:
            parts = [p for p in str(principal).split("/") if p]
            if len(parts) == 3:
                node = Node(parts[0], parts[2], parts[1])
            elif len(parts) == 2:
                node = Node(parts[0], parts[1], namespace)
            else:
                return {"error": "principal must be 'Kind/namespace/name' or 'Kind/name'"}
            analysis = graph.escalation_analysis(node, max_hops=max_hops)
            paths = analysis["paths"]
            summary, _ = graph.escalation_summary(node, max_hops=max_hops)
            return {"cluster": cluster_label, "principal": str(node),
                    "escalates": bool(paths),
                    "summary": summary or "no escalation path from this principal",
                    "analysis_status": analysis["analysis_status"],
                    "truncation_reason": analysis["truncation_reason"],
                    "limits": analysis["limits"],
                    "paths": [p.as_dict() for p in paths]}

        out = []
        truncated = False
        for sa in graph.service_accounts:
            meta = sa.get("metadata", {}) or {}
            node = Node("ServiceAccount", meta.get("name", ""), meta.get("namespace"))
            analysis = graph.escalation_analysis(node, max_hops=max_hops)
            paths = analysis["paths"]
            truncated = truncated or analysis["analysis_status"] == "truncated"
            if paths:
                summary, _ = graph.escalation_summary(node, max_hops=max_hops)
                out.append({"principal": str(node), "cluster": cluster_label,
                            "namespace": node.namespace,
                            "summary": summary,
                            "shortest_hops": paths[0].hops,
                            "capabilities": sorted({p.capability for p in paths}),
                            "analysis_status": analysis["analysis_status"],
                            "paths": [p.as_dict() for p in paths[:5]]})
        out.sort(key=lambda e: (e["shortest_hops"], e["principal"]))
        listing_truncated = len(out) > limit
        return {"cluster": cluster_label,
                "principals_with_escalation": len(out),
                "principals": out[:limit],
                # Bounded analysis must announce itself: a caller reading 20 principals
                # must be able to tell that from "these are all of them".
                "analysis_status": ("truncated" if (truncated or listing_truncated)
                                    else "complete"),
                "truncation_reason": ("principal_listing_limit" if listing_truncated
                                      else ("graph_bounds" if truncated else None)),
                "limits": {"max_hops": max_hops, "principal_limit": limit},
                "note": "shortest path first; a principal with no path is omitted"}

    def analyze_network_policy(
            pod: Annotated[Optional[str], _F(description=(
                "Pod name to evaluate. Omit to evaluate every pod in scope."))] = None,
            namespace: _Namespace = None,
            limit: Annotated[int, _F(description=(
                "Maximum pods to report on when no pod is named."))] = 25,
            mock: _Mock = True, fixture: _Fixture = None,
            kubeconfig: _Kubeconfig = None, context: _Context = None) -> dict:
        """Evaluate NetworkPolicy for a pod (or every pod in scope), BOTH directions, with
        full Kubernetes LabelSelector semantics.

        Supports matchLabels and matchExpressions (operators In, NotIn, Exists,
        DoesNotExist), podSelector and namespaceSelector on peers, ipBlock with `except`,
        policyTypes defaulting, and the additive union across several policies.

        Each direction returns a `status`: unrestricted (no policy governs it),
        allow-all (a rule admits every peer), restricted (specific peers, which are
        listed), deny-all (governed with no rules), partial (a selector this build cannot
        evaluate, so the restriction is NOT confirmed), or unknown (no policy evidence).
        `partial` is never reported as isolation, an unconfirmed restriction must not read
        as protection.

        Read-only."""
        from ..core.models import Scope as _Scope, ScopeLevel as _SL
        from ..core import netpol

        try:
            collector = platform.make_collector(mock=mock, fixture=fixture,
                                                kubeconfig=kubeconfig, context=context)
            evidence = collector.collect(
                {"Pod", "NetworkPolicy", "Namespace"},
                _Scope(_SL.NAMESPACE, namespace=namespace) if namespace
                else _Scope(_SL.CLUSTER))
        except (ValueError, RuntimeError) as exc:
            return {"error": str(exc)}

        try:
            cluster_label = collector.cluster_label()
        except Exception:
            cluster_label = None
        policies = evidence.get("NetworkPolicy", all_scopes=True)
        namespaces = evidence.get("Namespace", all_scopes=True)
        out = []
        for p in evidence.get("Pod"):
            meta = p.get("metadata", {}) or {}
            if pod and meta.get("name") != pod:
                continue
            ns = meta.get("namespace")
            labels = meta.get("labels", {}) or {}
            out.append({
                "cluster": cluster_label,
                "pod": meta.get("name"), "namespace": ns, "labels": labels,
                "ingress": netpol.evaluate(policies, ns, labels, "Ingress", namespaces),
                "egress": netpol.evaluate(policies, ns, labels, "Egress", namespaces)})
        if pod and not out:
            return {"error": f"no pod named {pod!r} in scope"}
        truncated = len(out) > limit
        return {"cluster": cluster_label,
                "policies_in_scope": len(policies), "pods_evaluated": len(out),
                "analysis_status": "truncated" if truncated else "complete",
                "truncation_reason": "pod_limit" if truncated else None,
                "pods": out[:limit]}

    # ================================================================== #
    # LAYER 3, Reports: persist + list + export in any format (§16.4)
    # ================================================================== #
    def list_reports(reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR,
                     limit: Annotated[Optional[int], _F(description=(
                         "Maximum number of reports to return, newest first. Omit for "
                         "all."))] = None) -> list[dict]:
        """List previously saved scan reports (from a run_scan call with save=True), 
        mirrors `k8smatrixwarden report list`. Each entry has the scan_id (needed for
        download_report), when it was generated, its rating/risk score, total finding
        count, and scope. Returns [] if nothing has been saved yet in `reports_dir`."""
        from ..core.report_store import ReportStore
        store = ReportStore(reports_dir)
        return [{"scan_id": r.scan_id, "generated_at": r.generated_at,
                "rating": r.rating, "risk_score": r.risk_score,
                "total_findings": r.total, "scope": r.scope}
               for r in store.list(limit=limit)]

    def download_report(
            scan_id: Annotated[Optional[str], _F(description=(
                "The saved scan id to re-render (see list_reports). Omit for the most "
                "recent saved report."))] = None,
            format: Annotated[str, _F(description=(
                "Format to render the stored scan into: 'markdown' (default), 'terminal', "
                "'text', 'json', 'sarif', 'html', or 'pdf' (returned base64-encoded)."))]
            = "markdown",
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Re-render a previously saved scan report in ANY format, without re-scanning, 
        mirrors `k8smatrixwarden report download`. This is how to get the same scan as a
        markdown write-up for a PR, a SARIF file for CI, and an HTML page for a
        stakeholder, all from one run_scan(save=True) call. Omit scan_id for the most
        recent saved report. format: terminal | text | markdown | json | sarif | html |
        pdf. Returns {scan_id, format, content}, `content` is the full rendered report
        string; write it to a file yourself if you need it on disk. For format='pdf',
        the response has `content_base64` (+ `encoding: "base64"`) instead of `content`,
        since PDF is binary, base64-decode it before writing. Returns an `error` key
        instead if nothing has been saved yet, the given scan_id isn't found, or (for
        pdf) the optional `pdf` extra isn't installed server-side."""
        fmt = (format or "markdown").lower()
        if fmt not in _VALID_REPORT_FORMATS:
            return {"error": f"unknown format {format!r}, valid values: "
                             f"{', '.join(sorted(_VALID_REPORT_FORMATS))}"}
        from ..core.report_store import ReportStore
        store = ReportStore(reports_dir)
        try:
            result = store.resolve(scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r} in "
                             f"{reports_dir!r}"}
        if result is None:
            return {"error": f"no stored reports in {reports_dir!r}, call "
                             f"run_scan(save=True) first"}
        try:
            content = platform.reporting.render(result, fmt)
        except RuntimeError as exc:
            return {"error": str(exc)}
        return {"scan_id": result.scan_id, "format": fmt, **_encode_report(content)}

    def federation_blast_radius(
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR,
            output_format: Annotated[str, _F(description=(
                "'json' (default), 'markdown', or 'html'."))] = "json") -> Any:
        """Cross-cluster blast radius: 'if one cluster is compromised, what does the
        attacker reach in the others?' Correlates the newest saved scan of EACH distinct
        cluster in the report store and finds shared identities, the same ClusterRole,
        ServiceAccount, cloud IAM role, Secret or ConfigMap (by kind+name) present in two
        or more clusters (built-in defaults like cluster-admin/system:*/default SA are
        excluded). Each shared identity is a CANDIDATE cross-cluster lateral-movement path to
        verify, a same-name collision to confirm is the same trust principal, not proof on
        its own (no candidate ⇒ reported as independent). Also returns a federated
        tactic-exposure view across all clusters. To populate the store, run_scan(save=True)
        against each cluster with its own context. output_format: json | markdown | html."""
        from ..core.federation import build_federation, latest_per_cluster
        from ..core.federation_report import to_markdown, to_html
        from ..core.report_store import ReportStore

        store = ReportStore(reports_dir)
        try:
            results = latest_per_cluster(store)
        except Exception as exc:
            return {"error": f"could not load saved scans: {exc}"}
        rep = build_federation(results)
        fmt = (output_format or "json").lower()
        if fmt == "json":
            return rep.as_dict()
        if fmt in ("markdown", "md"):
            return _encode_report(to_markdown(rep))
        if fmt == "html":
            return _encode_report(to_html(rep))
        return {"error": f"unknown output_format: {output_format}"}

    def get_rule(
            rule_id: Annotated[str, _F(description=(
                "Exact rule id to describe, e.g. 'rbac-wildcard-verbs'. See list_rules "
                "for the catalog."))]) -> dict:
        """Full machine-readable metadata for ONE detection rule: stable id and version,
        owning shard, severity, detection method and surface (scan vs runtime), MITRE /
        OWASP / CIS / NSA-CISA mappings, the evidence it needs, its declared detection
        confidence, references, whether it needs node access or a live runtime feed, and
        known false-positive patterns. Use it to explain WHY a finding fired and how far to
        trust it, without re-running a scan. Returns an `error` key for an unknown id."""
        rule = platform.registry.rules.get(rule_id)
        if rule is None:
            return {"error": f"unknown rule id {rule_id!r}; see list_rules"}
        return rule.metadata()

    def explain_finding(
            scan_id: Annotated[Optional[str], _F(description=(
                "Saved scan to read the finding from (see list_reports). Omit for the "
                "most recent saved scan."))] = None,
            rule_id: Annotated[Optional[str], _F(description=(
                "Rule id of the finding to explain. Combine with resource_name (and "
                "namespace) when one rule fired on several resources."))] = None,
            resource_name: Annotated[Optional[str], _F(description=(
                "Name of the affected resource, to pick one finding when a rule fired "
                "more than once."))] = None,
            namespace: _Namespace = None,
            limit: Annotated[int, _F(description=(
                "Maximum number of explanations to return when the filters match several "
                "findings (default 5, worst first)."))] = 5,
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Explain a finding in full, structured detail, everything an analyst needs to
        judge it without opening a report: what is wrong, why it matters, the exact
        evidence the rule keyed on, the affected resource and its owner, whether it is
        internet-reachable and the hop chain that makes it so, whether its ServiceAccount
        can escalate to cluster-admin, any RUNTIME evidence that names this same resource,
        which kill-chain step it feeds, the four factors that produced its risk score, the
        standards/MITRE it maps to, how to reproduce it, and a confidence score with the
        reasons behind it. Filter with rule_id / resource_name / namespace; without
        filters it explains the worst findings in the scan."""
        from ..core.explain import explain_finding as _explain
        from ..core.report_store import ReportStore
        from ..core.threat_matrix import attack_paths, build_threat_matrix

        try:
            result = ReportStore(reports_dir).resolve(scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r}"}
        if result is None:
            return {"error": f"no stored reports in {reports_dir!r}, run a scan first"}

        picked = [f for f in result.findings
                  if f.severity.weight > 0
                  and (not rule_id or f.rule_id == rule_id)
                  and (not resource_name or f.resource.name == resource_name)
                  and (not namespace or f.resource.namespace == namespace)]
        if not picked:
            return {"error": "no finding in that scan matches the given filters",
                    "scan_id": result.scan_id}
        picked.sort(key=lambda f: (f.severity.order, f.score), reverse=True)
        path = attack_paths(build_threat_matrix(result, platform.registry.rules),
                            result.runtime, cluster=result.cluster_name)
        return {
            "scan_id": result.scan_id,
            "cluster": result.cluster_name,
            "matched": len(picked),
            "explanations": [
                _explain(f, rule=platform.registry.rules.get(f.rule_id),
                         runtime=result.runtime, attack_path=path,
                         cluster=result.cluster_name)
                for f in picked[:max(1, limit)]],
        }

    def get_runtime_events(
            scan_id: _ScanIdOpt = None,
            source: Annotated[str, _F(description=(
                "Which events to return: 'all' (default), 'kmw' or 'falco' select by "
                "DETECTOR, 'audit' or 'drift' select by event STREAM. An unrecognised "
                "value is ignored and named in `warnings` rather than silently applied."
            ))] = "all",
            severity: Annotated[str, _F(description=(
                "Comma-separated severities to keep, e.g. 'CRITICAL,HIGH'. Empty keeps all."
            ))] = "",
            namespace: _Namespace = None,
            since: Annotated[str, _F(description=(
                "Only events newer than this age: '90s', '15m', '2h', '7d', '1w', or a "
                "number of seconds. Empty keeps all. An event with no readable timestamp "
                "is kept, because dropping it would let a time filter hide evidence."
            ))] = "",
            limit: Annotated[int, _F(description=(
                "Maximum events to return (default 50, capped at 1000). `total` and "
                "`matched` report the full counts behind the limit."
            ))] = 50,
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Read the runtime events already stored on a saved scan: Falco alerts, curated
        K8sMatrixWarden runtime detections, Kubernetes audit records and config drift, with
        their correlation verdict, provenance and identity.

        This is the READ side of the runtime feed, and the answer to "what has actually been
        observed in this cluster". It stores nothing and recomputes nothing: the records are
        reshaped from the scan's own runtime block by the same
        `core/runtime_events.query_runtime` the web dashboard's `GET /api/runtime` calls, so
        the two surfaces cannot disagree about what was seen.

        Ingestion is a different operation. `evaluate_runtime_events` and
        `correlate_runtime` judge a batch you supply; `refresh_runtime_feed` pulls a fresh
        batch from Falco in the cluster. This tool only reads what is already recorded.

        Each event carries `detection_source` (kmw | falco), `provider`, `source` (the
        event stream), `correlation` (confirmed | corroborated | runtime-only),
        `freshness` and `identity_status`, so a relayed provider verdict is never mistaken
        for one of this project's own.
        """
        from ..core.report_store import ReportStore
        from ..core.runtime_events import query_runtime
        try:
            result = ReportStore(reports_dir).resolve(scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r}"}
        if result is None:
            return {"error": "no saved scan to read runtime events from, scan first"}
        return query_runtime(result, limit=limit, source=source, severity=severity,
                             namespace=namespace or "", since=since)

    def refresh_runtime_feed(
            scan_id: _ScanIdOpt = None,
            falco_namespace: Annotated[str, _F(description=(
                "Namespace Falco runs in (default 'falco')."
            ))] = "falco",
            kubeconfig: _Kubeconfig = None,
            context: _Context = None,
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """Pull the current Falco events from the cluster, correlate them against a saved
        scan, and persist the result so `get_runtime_events` can read them back.

        Read-only with respect to Kubernetes: it reads Falco's pod logs and writes only to
        this tool's own report store. The counterpart push path (falcosidekick POSTing to
        `/api/runtime`) is unaffected and is still the way to get a live stream.

        Needs cluster access. Without it the call fails with a reason rather than returning
        an empty feed, because "no events" and "could not look" are different answers and
        only one of them means the cluster is quiet.
        """
        from ..core.falco_feed import build_runtime_feed
        from ..core.report_store import ReportStore
        store = ReportStore(reports_dir)
        try:
            result = store.resolve(scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r}"}
        if result is None:
            return {"error": "no saved scan to correlate against, scan first"}
        try:
            collector = platform.make_collector(mock=False, kubeconfig=kubeconfig,
                                                context=context)
            feed = build_runtime_feed(collector, result.findings,
                                      Scope(ScopeLevel.CLUSTER),
                                      namespace=falco_namespace or "falco")
        except RuntimeError as exc:
            return {"error": f"live Falco pull needs cluster access: {exc}"}
        if feed is None:
            return {"scan_id": result.scan_id, "runtime": None,
                    "message": f"no Falco events found in namespace "
                               f"{falco_namespace!r}",
                    "warnings": list(getattr(collector, "warnings", []))}
        result.runtime = feed
        store.save(result)
        return {"scan_id": result.scan_id, "runtime": feed,
                "warnings": list(getattr(collector, "warnings", []))}

    def get_cluster_coverage(
            scan_id: _ScanIdOpt = None,
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """How much of the cluster a saved scan actually READ, and therefore how much
        weight its risk score carries (§5). Returns evidence coverage and assessment
        confidence as percentages plus a per-resource-type and per-domain breakdown
        (`ok` / `partial` / `skipped`, with the reason a type was skipped, e.g. RBAC
        forbidden or an absent API group), the scan's own warnings, and `evidence_ok`,
        which is False when the cluster could not be read at all. Low coverage never hides
        a finding, it tells you the clean-looking parts may simply not have been visible."""
        from ..core.report_store import ReportStore
        try:
            result = ReportStore(reports_dir).resolve(scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r}"}
        if result is None:
            return {"error": f"no stored reports in {reports_dir!r}, run a scan first"}
        return {"scan_id": result.scan_id, "generated_at": result.generated_at,
                "mode": result.mode, "evidence_ok": result.evidence_ok,
                "warnings": list(result.warnings),
                "risk": result.risk.as_dict(),
                "aggregation": _agg(result),
                "coverage": result.coverage or {
                    "note": "this scan predates coverage tracking"}}

    def posture_history(
            scan_id: _ScanIdOpt = None,
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR) -> dict:
        """What CHANGED since the previous scan of the same cluster: findings that are
        new, resolved, still persistent, or regressed (previously fixed and now back),
        plus per-severity deltas and the risk-score direction. Finding identity is the
        stable rule+resource key, so 'resolved' means that exact check stopped firing on
        that exact object, and a finding whose rule was not re-run lands in
        `not_rescanned` rather than being reported as fixed. Also returns the store's
        MTTD/MTTR timeline (how long findings have been open, and when ones that were
        fixed got fixed). Needs at least one saved scan; two for a comparison."""
        from ..core.posture import latest_change
        from ..core.report_store import ReportStore
        store = ReportStore(reports_dir)
        try:
            change = latest_change(store, scan_id)
        except FileNotFoundError:
            return {"error": f"no stored report with scan-id {scan_id!r}"}
        if not change:
            return {"error": f"no stored reports in {reports_dir!r}, run a scan first"}
        return {**change, "timeline": store.timeline()}

    # ================================================================== #
    # LAYER 4, Platform: least-privilege RBAC generation
    # ================================================================== #
    def run_doctor(
            probe_llm: Annotated[bool, _F(description=(
                "Also make one tiny live call to the configured LLM to verify credentials "
                "and model name. Off by default: without it nothing leaves this machine."
            ))] = False) -> dict:
        """Full platform health and consistency check, the same one `k8smatrixwarden
        doctor` runs: shards and rules loaded, configuration validity, MITRE taxonomy and
        composite aliases resolving, MCP tool registration, every report format rendering,
        the runtime catalog, optional dependencies, the optional LLM, and the read-only
        safety invariants.

        Broader than `validate_platform`, which answers only "did the rule registry load
        cleanly". Use this to answer "is this installation healthy and is the read-only
        guarantee still intact", which is what an operator means by "is it working".

        A missing OPTIONAL capability is reported as NOT CONFIGURED, never as a failure:
        an absent PDF library is a thing you have not installed, not a thing that is broken.
        """
        from .. import doctor as _doctor
        sections = _doctor.run_checks(platform, probe_llm=probe_llm)
        return _doctor.summarize(sections)

    def start_web_server(
            host: Annotated[str, _F(description=(
                "Address to bind. Loopback (127.0.0.1, the default) is the only address "
                "allowed unless allow_remote is set, because the dashboard has NO "
                "authentication of its own."
            ))] = "127.0.0.1",
            port: Annotated[int, _F(description="TCP port, 1-65535 (default 8080).")] = 8080,
            reports_dir: _ReportsDir = _DEFAULT_REPORTS_DIR,
            allow_scan: Annotated[bool, _F(description=(
                "Allow the dashboard's in-browser scan button. True by default; set False "
                "to serve saved reports read-only."
            ))] = True,
            allow_remote: Annotated[bool, _F(description=(
                "Required to bind a non-loopback address. The dashboard has no "
                "authentication, so anyone who can reach the port can read every saved "
                "report. Leave off unless you have put your own auth in front of it."
            ))] = False) -> dict:
        """Start the Security Dashboard in the background and return its URL immediately.

        The same WebApp and HTTP server `k8smatrixwarden web` runs, started on a daemon
        thread instead of blocking, so an MCP client can bring the dashboard up without
        asking anyone to open a terminal. One dashboard per process: starting again returns
        the running one rather than binding a second socket.

        Two things are refused rather than warned about, because the caller here is a
        program and a warning it does not read is not a safeguard:
          * a non-loopback bind without `allow_remote`, which would publish an
            unauthenticated dashboard onto the network;
          * a client-supplied kubeconfig over a remote bind, which would execute that
            kubeconfig's credential plugin as this user.

        A port already in use comes back as a structured error, not an exception.
        """
        from ..web.server import is_loopback, start_background
        if not isinstance(port, int) or not 1 <= port <= 65535:
            return {"error": f"invalid port {port!r}, expected an integer 1-65535"}
        if not is_loopback(host) and not allow_remote:
            return {"error": (f"refusing to bind {host!r}: the dashboard has no "
                              f"authentication, so a non-loopback bind publishes every "
                              f"saved report to anyone who can reach the port. Pass "
                              f"allow_remote=true if that is genuinely what you want.")}
        return start_background(host=host, port=port, reports_dir=reports_dir,
                                allow_scan=allow_scan,
                                allow_remote_kubeconfig=False)

    def get_web_server_status() -> dict:
        """Is the Security Dashboard running in this process, and where?

        Reports `running`, and when it is, the host, port, URL, report directory, whether
        in-browser scanning is enabled, and uptime. A serving thread that has died is
        reported as not running rather than advertising a URL nothing answers.
        """
        from ..web.server import background_status
        return background_status()

    def stop_web_server() -> dict:
        """Stop the Security Dashboard started by `start_web_server`.

        Safe to call when nothing is running (returns `not-running`). Only affects a
        dashboard this process started; a `k8smatrixwarden web` running in its own terminal
        is somebody else's process and is deliberately left alone.
        """
        from ..web.server import stop_background
        return stop_background()

    def generate_rbac_manifest(
            service_account: Annotated[str, _F(description=(
                "Name of the ServiceAccount the scanner runs as. Default "
                "'k8smatrixwarden-scanner'."))] = "k8smatrixwarden-scanner",
            namespace: Annotated[str, _F(description=(
                "Namespace for the ServiceAccount and bindings. Default "
                "'k8smatrixwarden-system'."))] = "k8smatrixwarden-system",
            create_namespace: Annotated[bool, _F(description=(
                "Include a Namespace object in the manifest (default True). Set False if "
                "the namespace already exists."))] = True,
            bind: Annotated[bool, _F(description=(
                "True (default) returns a full deployable manifest (Namespace + "
                "ServiceAccount + per-shard ClusterRole/ClusterRoleBinding); False returns "
                "just the bare ClusterRoles for review."))] = True) -> dict:
        """Generate the least-privilege RBAC k8smatrixwarden needs to scan a real cluster, every
        verb is get/list/watch, never a write. bind=True returns a full deployable
        manifest (Namespace + ServiceAccount + per-shard ClusterRole/ClusterRoleBinding);
        bind=False returns just the bare ClusterRoles for review. Review before
        `kubectl apply`, this tool only generates the manifest, it never applies it."""
        if bind:
            return platform.loader.deployment_manifest(
                service_account=service_account, namespace=namespace,
                create_namespace=create_namespace)
        return {"cluster_roles": platform.loader.scoped_roles()}

    return {
        # 1. knowledge
        "list_rules": list_rules,
        "resolve_selector": resolve_selector,
        "get_kubectl_command": get_kubectl_command,
        "list_kubectl_commands": list_kubectl_commands,
        "get_tool_commands": get_tool_commands,
        "list_tool_commands": list_tool_commands,
        "lookup_cve": lookup_cve,
        "list_cves": list_cves,
        "get_compliance_ruleset": get_compliance_ruleset,
        "get_taxonomy": get_taxonomy,
        "mitre_coverage": mitre_coverage,
        "list_shards": list_shards,
        "list_namespaces": list_namespaces,
        "detect_cluster_provider": detect_cluster_provider,
        "validate_platform": validate_platform,
        # 2. scan / audit / runtime
        "preview_scan": preview_scan,
        "run_scan": run_scan,
        "interpret_query": interpret_query,
        "intelligent_scan": intelligent_scan,
        "run_cis_benchmark": run_cis_benchmark,
        "run_compliance_audit": run_compliance_audit,
        "evaluate_runtime_events": evaluate_runtime_events,
        "correlate_runtime": correlate_runtime,
        "detect_drift": detect_drift,
        "deploy_falco": deploy_falco,
        "list_runtime_detections": list_runtime_detections,
        "build_threat_matrix": build_threat_matrix,
        "build_attack_path": build_attack_path,
        "analyze_rbac_paths": analyze_rbac_paths,
        "analyze_network_policy": analyze_network_policy,
        # 3. reports / analysis of a stored scan
        "list_reports": list_reports,
        "download_report": download_report,
        "federation_blast_radius": federation_blast_radius,
        "get_rule": get_rule,
        "explain_finding": explain_finding,
        "get_cluster_coverage": get_cluster_coverage,
        "get_runtime_events": get_runtime_events,
        "refresh_runtime_feed": refresh_runtime_feed,
        "posture_history": posture_history,
        # 4. platform
        "generate_rbac_manifest": generate_rbac_manifest,
        "run_doctor": run_doctor,
        # 5. application lifecycle, so a client never has to ask for a terminal
        "start_web_server": start_web_server,
        "get_web_server_status": get_web_server_status,
        "stop_web_server": stop_web_server,
    }


#: MCP stdio uses STDOUT for the protocol itself, so every log line goes to stderr. A
#: single stray print to stdout corrupts the JSON-RPC stream and the client disconnects.
def _log(event: str, **fields) -> None:
    """One structured line on stderr: `ts=... event=... k=v ...`.

    The MCP SDK logs only "Processing request of type CallToolRequest", which does not say
    which tool ran, how long it took, or whether it failed, so a failing session cannot be
    debugged from the log alone. These lines close that gap and nothing more.

    Values are never tool ARGUMENTS or RESULTS. Arguments can carry a kubeconfig path and
    results routinely carry finding detail; both are the caller's data and neither belongs
    in a log by default. Argument NAMES are logged, which is enough to see what was asked
    without recording what was said.
    """
    import sys as _sys
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
    print(f"ts={stamp} event={event} {parts}".rstrip(), file=_sys.stderr, flush=True)


def observe(name: str, fn):
    """Wrap one tool so its call is observable: start, duration, outcome, result size.

    A pass-through in every other respect. The wrapper does not touch arguments, does not
    change the return value, and re-raises whatever the tool raised, so behaviour is
    identical with logging on or off.
    """
    import functools
    import time
    import uuid

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        request_id = uuid.uuid4().hex[:12]
        # Names only. A value could be a kubeconfig path or a namespace the operator would
        # rather not have in a shared log.
        _log("tool.started", request_id=request_id, tool=name,
             args=",".join(sorted(kwargs)) or "-")
        started = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            _log("tool.failed", request_id=request_id, tool=name,
                 duration_ms=round((time.perf_counter() - started) * 1000),
                 error=type(exc).__name__)
            raise
        duration = round((time.perf_counter() - started) * 1000)
        # A tool that returns {"error": ...} succeeded as a call and failed as an
        # operation. Logging those the same way would hide every handled failure.
        status = ("tool.error" if isinstance(result, dict) and "error" in result
                  else "tool.completed")
        _log(status, request_id=request_id, tool=name, duration_ms=duration,
             result_bytes=_size(result))
        return result

    return wrapped


def _size(result) -> int:
    """Serialized size of a result, for the log. Never the content."""
    try:
        return len(json.dumps(result, default=str))
    except Exception:
        return -1


def serve(config_path: Optional[str] = None) -> None:
    """Run the MCP server over stdio (requires the `mcp` SDK)."""
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore
    except Exception as exc:
        # Do NOT claim the SDK is missing, very often it is installed, just not
        # visible to *this* interpreter. MCP clients spawn the server with a
        # stripped environment, which hides a per-user site-packages directory
        # (where `pip install` silently lands when the interpreter's own
        # site-packages isn't writable). Report the interpreter, the real
        # exception, and the user-site state so the log alone explains it.
        import site
        import sys as _sys
        try:
            usersite = site.getusersitepackages() if site.ENABLE_USER_SITE else "DISABLED"
        except Exception:
            usersite = "unavailable"
        raise SystemExit(
            f"The MCP Python SDK could not be imported: {type(exc).__name__}: {exc}\n"
            f"  interpreter : {_sys.executable}\n"
            f"  user-site   : {usersite}\n"
            "Install it for THIS interpreter:\n"
            f'  "{_sys.executable}" -m pip install mcp\n'
            "If it IS installed but lives in a per-user site-packages directory, an "
            "MCP client's stripped environment cannot see it, install it into the "
            "interpreter's own site-packages, use a virtualenv, or point the client "
            "at an interpreter that has it.\n"
            "The same datasets are available in-process via "
            "k8smatrixwarden.mcp.server.build_tools() without the SDK.")

    tools = build_tools(config_path)
    app = FastMCP("k8smatrixwarden-mcp")
    _log("server.starting", tools=len(tools))
    for name, fn in tools.items():
        app.tool(name=name)(observe(name, fn))
    _log("server.ready", tools=len(tools), transport="stdio")
    app.run()


if __name__ == "__main__":  # pragma: no cover
    serve()
