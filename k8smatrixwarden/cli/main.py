"""
k8smatrixwarden CLI (§7, §16.4), argparse-based (stdlib only, always runnable).

Commands:
  scan       run a scan by scope × selector, OR a natural-language query
  rules      list / inspect the rule registry
  coverage   show MITRE tactic coverage
  report     render the last scan (alias of scan --output)
  roles      print the per-plugin scoped RBAC roles (§20/§21)
  mcp        run the MCP server (needs the mcp SDK) or list its tools
  doctor     validate the platform (taxonomy, aliases, duplicate rules)
"""
from __future__ import annotations

import argparse
import sys

from ..bootstrap import build_platform
from ..core.models import (ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity)
from ..core.report_store import DEFAULT_DIR as _DEFAULT_REPORTS_DIR
from ..agents.orchestrator import Orchestrator
from ..agents.scanner import ScannerAgent


def _add_scope_args(p):
    g = p.add_argument_group("scope (choose one; default: cluster)")
    g.add_argument("--namespace", "-n")
    g.add_argument("--pod")
    g.add_argument("--workload", help="KIND/name, e.g. Deployment/api")
    g.add_argument("--node")
    g.add_argument("--image")
    g.add_argument("--helm-release")


def _add_selector_args(p):
    g = p.add_argument_group("selector (combine freely; default: all rules)")
    g.add_argument("--tactic", action="append", default=[])
    g.add_argument("--technique", action="append", default=[],
                   help="technique id/name or composite alias (e.g. 'Container Escape')")
    g.add_argument("--module", action="append", default=[], help="domain shard name")
    g.add_argument("--rule", action="append", default=[], dest="rule_ids")
    g.add_argument("--alias", action="append", default=[])
    g.add_argument("--framework", action="append", default=[], help="CIS | NSA | OWASP")
    g.add_argument("--severity-min", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])


def _build_scope(a) -> Scope:
    if getattr(a, "namespace", None):
        return Scope(ScopeLevel.NAMESPACE, namespace=a.namespace)
    if getattr(a, "pod", None):
        return Scope(ScopeLevel.POD, name=a.pod, namespace=getattr(a, "namespace", None))
    if getattr(a, "workload", None):
        kind, _, name = a.workload.partition("/")
        return Scope(ScopeLevel.WORKLOAD, kind=kind, name=name)
    if getattr(a, "node", None):
        return Scope(ScopeLevel.NODE, name=a.node)
    if getattr(a, "image", None):
        return Scope(ScopeLevel.IMAGE, image=a.image)
    if getattr(a, "helm_release", None):
        return Scope(ScopeLevel.HELM_RELEASE, name=a.helm_release)
    return Scope(ScopeLevel.CLUSTER)


def _build_selector(a) -> Selector:
    sev = Severity.parse(a.severity_min) if getattr(a, "severity_min", None) else None
    return Selector(tactics=a.tactic, techniques=a.technique, modules=a.module,
                    rule_ids=a.rule_ids, aliases=a.alias, frameworks=a.framework,
                    severity_min=sev)


def _warn_ignored_live_flags(a) -> None:
    """Warn if --context/--kubeconfig were given but the scan is not actually live, 
    otherwise a forgotten --live silently runs against the mock cluster."""
    if not getattr(a, "live", False) and (getattr(a, "context", None)
                                          or getattr(a, "kubeconfig", None)):
        print("warning: --kubeconfig/--context are ignored without --live "
              "(scanning the bundled MOCK cluster). Add --live to scan a real cluster.",
              file=sys.stderr)


def _attach_runtime_feed(result, collector, request, a) -> None:
    """On a live scan, pull recent Falco alerts from the cluster and bake the correlation +
    drift straight into `result.runtime`, so the dashboard shows "what is being exploited
    right now" without any manual event paste. Best-effort and fully additive: any problem
    is surfaced as a warning line and the static scan result is returned unchanged. Skipped
    for mock scans and when --no-runtime is given."""
    if getattr(a, "mock", False) or not getattr(a, "live", False):
        return
    if getattr(a, "no_runtime", False):
        return
    from ..core.falco_feed import since_to_seconds, build_runtime_feed

    ns = getattr(a, "falco_namespace", None) or "falco"
    try:
        feed = build_runtime_feed(collector, result.findings, request.scope, namespace=ns,
                                  since_seconds=since_to_seconds(getattr(a, "falco_since", None)))
    except Exception as exc:  # never let the runtime feed break a completed scan
        print(f"warning: Falco feed skipped ({exc})", file=sys.stderr)
        return
    if not feed:
        # collector already recorded a warning explaining why (no Falco, no JSON, RBAC).
        return
    result.runtime = feed
    c, d = feed["correlation"], feed["drift"]
    print(f"[runtime] pulled {feed['events_seen']} Falco event(s) from ns/{ns} → "
          f"{c['confirmed_exploitation']} confirmed exploited, "
          f"{c['correlated']} correlated, {d['drift_count']} config drift",
          file=sys.stderr)


# --------------------------------------------------------------------------- #
def cmd_scan(a) -> int:
    platform = build_platform(a.config)
    orch = Orchestrator(platform)

    if a.query:
        interp = orch.interpret(" ".join(a.query))
        request = interp.request
        if not a.yes:
            print(orch.confirmation_summary(interp))
            if a.dry_run:
                return 0
    else:
        request = ScanRequest(scope=_build_scope(a), selector=_build_selector(a),
                              mode=ScanMode.SYNC, output=a.output)
        try:
            resolved = orch.scanner.resolve(request)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if a.dry_run:
            print(f"Scope={request.scope.describe()}  "
                  f"Selector={request.selector.describe()}")
            print(f"→ resolves to {len(resolved)} rule(s): {', '.join(resolved)}")
            return 0

    mode_label = "mock" if (a.mock or not a.live) else "live"
    _warn_ignored_live_flags(a)
    try:
        collector = platform.make_collector(mock=(mode_label == "mock"),
                                            fixture=a.fixture, kubeconfig=a.kubeconfig,
                                            context=a.context)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        result = orch.run(request, collector, mode_label=mode_label,
                          name=getattr(a, "name", None) or "")
    except RuntimeError as exc:
        # A clean, actionable message (e.g. cluster unreachable), not a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # Live runtime feed: pull Falco alerts and correlate them into the result BEFORE we
    # render/persist, so the saved report + dashboard carry the runtime correlation.
    _attach_runtime_feed(result, collector, request, a)

    for w in getattr(collector, "warnings", []):
        print(f"warning: {w}", file=sys.stderr)

    # PDF and XLSX are binary: they are written to a file rather than printed, and their
    # optional dependency is reported as a clean error rather than a traceback.
    if a.output in ("pdf", "xlsx"):
        try:
            rendered = platform.reporting.render(result, a.output)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        out_path = (a.output_file
                    or f"k8smatrixwarden-report-{result.scan_id}.{a.output}")
        with open(out_path, "wb") as fh:
            fh.write(rendered)
        label = "PDF" if a.output == "pdf" else "Excel workbook"
        print(f"📄 {label} written to {out_path} ({len(rendered):,} bytes)")
    else:
        rendered = platform.reporting.render(result, a.output)
        print(rendered)
        if a.output_file:
            with open(a.output_file, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print(f"\n[written] {a.output_file}", file=sys.stderr)

    # Persist to the shared report store by default so the scan shows up in the web
    # dashboard (`k8smatrixwarden web`). Opt out with --no-save for a throwaway run.
    if not getattr(a, "no_save", False):
        from ..core.report_store import ReportStore
        path = ReportStore(a.reports_dir).save(result)
        print(f"[saved] {result.display_name}\n"
              f"  {result.scan_id} → {path}\n"
              f"  view in dashboard: k8smatrixwarden web    ·    "
              f"download: k8smatrixwarden report download --scan-id {result.scan_id}",
              file=sys.stderr)

    if a.fail_on:
        floor = Severity.parse(a.fail_on).order
        if any(f.severity.order >= floor for f in result.findings):
            return 1
    return 0


def cmd_rules(a) -> int:
    platform = build_platform(a.config)
    rules = platform.registry.rules.all()
    if a.module:
        rules = [r for r in rules if r.owning_shard == a.module]
    if a.tactic:
        rules = [r for r in rules
                 if any(m.tactic.value.lower() == a.tactic.lower() for m in r.mitre)]
    print(f"{len(rules)} rule(s):")
    for r in sorted(rules, key=lambda x: (x.owning_shard, x.id)):
        tags = ",".join(sorted({m.tactic.value for m in r.mitre}))
        print(f"  {r.severity.emoji} {r.id:<34} [{r.owning_shard}]  "
              f"surface={r.surface}  owasp={r.owasp or '-'}  mitre=[{tags}]")
    print("\nAll registry rules are scan-surface (point-in-time). Runtime-surface "
          "detections\n(Falco/audit/drift) live in the Runtime Agent, see "
          "`mcp list_runtime_detections`.")
    return 0


def cmd_coverage(a) -> int:
    platform = build_platform(a.config)
    print("MITRE tactic coverage (rules per tactic):")
    for tactic, n in platform.coverage().items():
        bar = "█" * n
        print(f"  {tactic:<22} {n:>2}  {bar}")
    print(f"\nTotal rules: {platform.rule_count()} across "
          f"{len(platform.registry.shard_names())} shards")
    return 0


def cmd_roles(a) -> int:
    import json
    platform = build_platform(a.config)
    if a.bind:
        manifest = platform.loader.deployment_manifest(
            service_account=a.service_account, namespace=a.sa_namespace,
            create_namespace=not a.no_create_namespace)
        out = json.dumps(manifest, indent=2)
    else:
        out = json.dumps(platform.loader.scoped_roles(), indent=2)
    print(out)
    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"\n[written] {a.output_file}", file=sys.stderr)
    return 0


def cmd_doctor(a) -> int:
    """Full platform health check (§19): shards, configuration, rules, taxonomy, MCP,
    report formats, runtime catalog, optional LLM, optional dependencies, and the
    read-only safety invariants. Exits 1 only on a FAIL, a missing OPTIONAL capability is
    reported as NOT CONFIGURED and never fails the command."""
    from .. import doctor as doc
    platform = build_platform(a.config)
    sections = doc.run_checks(platform, probe_llm=a.probe)
    if a.output == "json":
        import json as _json
        print(_json.dumps(doc.summarize(sections), indent=2))
    else:
        print(doc.render_text(sections, verbose=a.verbose))
    return 0 if doc.summarize(sections)["ok"] else 1


def cmd_chat(a) -> int:
    from ..bootstrap import build_platform
    from .chat import run_chat
    platform = build_platform(a.config)
    _warn_ignored_live_flags(a)
    mock = not a.live
    return run_chat(platform, mock=mock, fixture=a.fixture, kubeconfig=a.kubeconfig,
                    context=a.context)


def cmd_cis(a) -> int:
    import json as _json
    from ..bootstrap import build_platform
    from ..frameworks.cis import CISBenchmarkEngine, render_markdown, render_text
    from ..frameworks.kube_bench_adapter import maybe_load

    platform = build_platform(a.config)
    engine = CISBenchmarkEngine(platform)
    mode_label = "mock" if (a.mock or not a.live) else "live"
    _warn_ignored_live_flags(a)
    try:
        collector = platform.make_collector(mock=(mode_label == "mock"),
                                            fixture=a.fixture, kubeconfig=a.kubeconfig,
                                            context=a.context)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    kb = maybe_load(a.kube_bench_json)
    report = engine.evaluate(collector, kube_bench_results=kb, profile=a.profile)

    if a.output == "json":
        out = _json.dumps(report.as_dict(), indent=2)
    elif a.output in ("markdown", "md"):
        out = render_markdown(report)
    else:
        out = render_text(report, show="all" if a.show_all else "fail")
    print(out)

    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"\n[written] {a.output_file}", file=sys.stderr)

    if a.fail_on_fail and report.counts["FAIL"] > 0:
        return 1
    return 0


def cmd_compliance(a) -> int:
    """Map cluster posture onto governance frameworks (PCI DSS / SOC 2 / ISO 27001 /
    NIST 800-53) and emit an auditor-facing report."""
    from ..bootstrap import build_platform
    from ..frameworks.compliance import run_audit, framework_keys
    from ..frameworks import compliance_report as cr

    frameworks = None
    if a.frameworks:
        frameworks = [f for f in a.frameworks.split(",") if f]
        bad = [f for f in frameworks if f not in set(framework_keys())]
        if bad:
            print(f"error: unknown framework(s): {bad}. Valid: {framework_keys()}",
                  file=sys.stderr)
            return 2

    mode_label = "mock" if (a.mock or not a.live) else "live"
    _warn_ignored_live_flags(a)
    try:
        report = run_audit(build_platform(a.config), mock=(mode_label == "mock"),
                           fixture=a.fixture, kubeconfig=a.kubeconfig, context=a.context,
                           profile=a.profile, frameworks=frameworks,
                           kube_bench_json=a.kube_bench_json)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    fmt = (a.output or "markdown").lower()
    binary = fmt == "pdf"
    if fmt == "json":
        import json as _json
        out = _json.dumps(report.as_dict(), indent=2)
    elif fmt == "html":
        out = cr.to_html(report)
    elif fmt == "pdf":
        try:
            out = cr.to_pdf(report)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        out = cr.to_markdown(report)

    if a.output_file:
        with open(a.output_file, "wb" if binary else "w",
                  **({} if binary else {"encoding": "utf-8"})) as fh:
            fh.write(out)
        print(f"[written] {a.output_file}", file=sys.stderr)
    elif binary:
        print("error: pdf output requires --output-file", file=sys.stderr)
        return 2
    else:
        print(out)

    total_fail = sum(f.counts["FAIL"] for f in report.frameworks)
    if a.fail_on_fail and total_fail > 0:
        return 1
    return 0


def cmd_federation(a) -> int:
    """Cross-cluster blast radius from the newest saved scan of each cluster in the store."""
    from ..core.federation import build_federation, latest_per_cluster
    from ..core import federation_report as fr
    from ..core.report_store import ReportStore

    store = ReportStore(a.reports_dir) if a.reports_dir else ReportStore()
    rep = build_federation(latest_per_cluster(store))
    fmt = (a.output or "markdown").lower()
    if fmt == "json":
        import json as _json
        out = _json.dumps(rep.as_dict(), indent=2)
    elif fmt == "html":
        out = fr.to_html(rep)
    else:
        out = fr.to_markdown(rep)
    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[written] {a.output_file}", file=sys.stderr)
    else:
        print(out)
    return 0


def cmd_posture(a) -> int:
    """What changed since the previous scan of the same cluster (§16)."""
    from ..core.posture import latest_change
    from ..core.report_store import ReportStore
    from ..core.timeutil import format_ist

    store = ReportStore(a.reports_dir)
    try:
        change = latest_change(store, a.scan_id)
    except FileNotFoundError:
        print(f"error: no stored report with scan-id '{a.scan_id}'", file=sys.stderr)
        return 2
    if not change:
        print(f"No stored reports in '{a.reports_dir}'. Run a scan first.")
        return 0
    if a.output == "json":
        import json as _json
        print(_json.dumps({**change, "timeline": store.timeline()}, indent=2))
        return 0

    print(f"Security posture change, {format_ist(change['current_generated_at'])}")
    print(f"  {change['summary']}\n")
    print(f"  {'SEVERITY':<10} {'PREVIOUS':>9} {'CURRENT':>8} {'DELTA':>7}")
    for sev, counts in change["counts"].items():
        arrow = "↑" if counts["delta"] > 0 else ("↓" if counts["delta"] < 0 else " ")
        print(f"  {sev:<10} {counts['previous']:>9} {counts['current']:>8} "
              f"{arrow}{abs(counts['delta']):>6}")
    for label, key in (("Regressed (previously fixed, back again)", "regressed"),
                       ("New", "new"), ("Resolved", "resolved")):
        rows = change[key]
        if not rows:
            continue
        print(f"\n  {label} ({len(rows)}):")
        for row in rows[:15]:
            print(f"    {row['severity']:<9} {row['rule_id']:<32} {row['resource']}")
        if len(rows) > 15:
            print(f"    … (+{len(rows) - 15} more)")
    if change["not_rescanned"]:
        print(f"\n  {len(change['not_rescanned'])} earlier finding(s) were NOT re-scanned "
              f"by this run,\n  so they are neither confirmed fixed nor still open.")
    return 0


def cmd_report(a) -> int:
    """List and download stored scan reports (§16.4)."""
    from ..core.report_store import ReportStore
    store = ReportStore(a.reports_dir)

    if a.report_cmd == "list":
        reports = store.list(limit=a.limit)
        if not reports:
            print(f"No stored reports in '{a.reports_dir}'. Run a scan first "
                  f"(scans are saved automatically unless --no-save).")
            return 0
        from ..core.timeutil import format_ist
        print(f"{len(reports)} stored report(s) in '{a.reports_dir}':\n")
        print(f"  {'NAME':<26} {'WHEN':<22} {'RATING':<9} {'RISK':<5} "
              f"{'FIND':<5} SCAN ID (download key)")
        for r in reports:
            name = (r.name or "N/A")[:26]
            print(f"  {name:<26} {format_ist(r.generated_at):<22} {r.rating:<9} "
                  f"{r.risk_score:<5} {r.total:<5} {r.scan_id}")
        print("\nDownload:  k8smatrixwarden report download --scan-id <ID> "
              "--format markdown --output report.md")
        return 0

    # download
    try:
        result = store.resolve(a.scan_id)
    except FileNotFoundError:
        print(f"error: no stored report with scan-id '{a.scan_id}' in '{a.reports_dir}'",
              file=sys.stderr)
        return 2
    if result is None:
        print(f"error: no stored reports in '{a.reports_dir}' (scan with --save first)",
              file=sys.stderr)
        return 2

    try:
        rendered = platform_render(a, result)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if a.format in ("pdf", "xlsx"):
        if not a.output:
            print(f"error: --output PATH is required for --format {a.format} "
                  "(binary content can't be printed to the terminal)", file=sys.stderr)
            return 2
        with open(a.output, "wb") as fh:
            fh.write(rendered)
        print(f"📄 Downloaded {result.scan_id} as {a.format} → {a.output} "
              f"({len(rendered):,} bytes)")
    elif a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"📄 Downloaded {result.scan_id} as {a.format} → {a.output} "
              f"({len(rendered):,} bytes)")
    else:
        print(rendered)
    return 0


def platform_render(a, result) -> str:
    platform = build_platform(a.config)
    return platform.reporting.render(result, a.format)


def cmd_matrix(a) -> int:
    """Render the Kubernetes Threat Matrix for a scan (or global coverage), §12."""
    import json as _json
    from ..core.threat_matrix import build_threat_matrix
    from ..core.threat_matrix_render import (render_markdown as tm_md,
                                             render_text as tm_text)
    platform = build_platform(a.config)

    if a.coverage:
        from ..web.app import _empty_result
        result = _empty_result(platform)
    elif a.scan_id:
        from ..core.report_store import ReportStore
        try:
            result = ReportStore(a.reports_dir).resolve(a.scan_id)
        except FileNotFoundError:
            print(f"error: no stored report '{a.scan_id}'", file=sys.stderr)
            return 2
        if result is None:
            print("error: no stored reports (scan with --save first)", file=sys.stderr)
            return 2
    else:
        request = ScanRequest(scope=_build_scope(a), selector=_build_selector(a),
                              mode=ScanMode.SYNC)
        mode_label = "mock" if (a.mock or not a.live) else "live"
        _warn_ignored_live_flags(a)
        try:
            collector = platform.make_collector(mock=(mode_label == "mock"),
                                                fixture=a.fixture, kubeconfig=a.kubeconfig,
                                                context=a.context)
            result = Orchestrator(platform).run(request, collector, mode_label=mode_label)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    tm = build_threat_matrix(result, platform.registry.rules)
    if a.output == "json":
        out = _json.dumps(tm.as_dict(), indent=2)
    elif a.output in ("markdown", "md"):
        out = tm_md(tm)
    else:
        out = tm_text(tm)
    print(out)
    if a.output_file:
        with open(a.output_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"\n[written] {a.output_file}", file=sys.stderr)
    return 0


def cmd_web(a) -> int:
    """Launch the Security Dashboard web interface (§3.1, §19)."""
    from ..web.server import serve
    try:
        serve(host=a.host, port=a.port, reports_dir=a.reports_dir, config_path=a.config,
              allow_scan=not a.no_scan, open_browser=a.open,
              allow_remote_kubeconfig=a.allow_remote_kubeconfig)
    except OSError as exc:
        print(f"error: could not start web server on {a.host}:{a.port}, {exc}",
              file=sys.stderr)
        return 2
    return 0


def cmd_mcp(a) -> int:
    from ..mcp import server
    if a.list_tools:
        tools = server.build_tools(a.config)
        print("MCP tools:", ", ".join(tools.keys()))
        return 0
    server.serve(a.config)
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="k8smatrixwarden",
                                description="K8sMatrixWarden v1.0, MITRE-aligned scanner")
    p.add_argument("--config", help="path to a config JSON overriding defaults")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run a scan (by args or natural language)")
    s.add_argument("query", nargs="*", help="natural-language query, e.g. "
                   "\"scan production for Persistence\"")
    _add_scope_args(s)
    _add_selector_args(s)
    s.add_argument("--output", "-o", default="terminal",
                   choices=["terminal", "text", "markdown", "json", "sarif", "html",
                            "pdf", "xlsx"])
    s.add_argument("--output-file", help="for -o pdf, defaults to "
                   "k8smatrixwarden-report-<scan_id>.pdf if omitted")
    s.add_argument("--mock", action="store_true", help="use the bundled mock cluster")
    s.add_argument("--live", action="store_true", help="scan the live cluster")
    s.add_argument("--fixture", help="path to a custom mock cluster JSON")
    s.add_argument("--kubeconfig", help="path to a kubeconfig file (default: ~/.kube/config)")
    s.add_argument("--context", help="kubeconfig context to use (default: current-context)")
    s.add_argument("--dry-run", action="store_true",
                   help="resolve the selector and show the rule set without scanning")
    s.add_argument("--yes", "-y", action="store_true", help="skip confirmation")
    s.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="exit 1 if a finding at/above this severity is found (CI mode)")
    s.add_argument("--name", help="human name for this scan; the report is named/identified "
                   "as '<name> + date + time' and is easy to find in the web dashboard")
    s.add_argument("--save", action="store_true",
                   help="(deprecated) scans are saved by default now; this flag is a no-op")
    s.add_argument("--no-save", action="store_true",
                   help="do NOT persist this scan to the report store (skips the dashboard)")
    s.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR,
                   help=f"report store directory (shared default: {_DEFAULT_REPORTS_DIR}; "
                        f"override with $K8SMATRIXWARDEN_REPORTS_DIR)")
    rt = s.add_argument_group("runtime feed (live only; auto-correlates Falco alerts)")
    rt.add_argument("--no-runtime", action="store_true",
                    help="do NOT pull Falco alerts on a --live scan (static findings only)")
    rt.add_argument("--falco-namespace", default="falco",
                    help="namespace the Falco DaemonSet runs in (default: falco)")
    rt.add_argument("--falco-since", default="1h",
                    help="how far back to read Falco logs, e.g. 30m / 1h / 2h (default: 1h)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list the rule registry")
    r.add_argument("--module")
    r.add_argument("--tactic")
    r.set_defaults(func=cmd_rules)

    c = sub.add_parser("coverage", help="show MITRE tactic coverage")
    c.set_defaults(func=cmd_coverage)

    ro = sub.add_parser("roles", help="print per-plugin scoped RBAC roles")
    ro.add_argument("--bind", action="store_true",
                    help="emit a full deployable manifest (Namespace + ServiceAccount + "
                    "ClusterRoles + ClusterRoleBindings) instead of bare ClusterRoles")
    ro.add_argument("--service-account", default="k8smatrixwarden-scanner")
    ro.add_argument("--sa-namespace", default="k8smatrixwarden-system")
    ro.add_argument("--no-create-namespace", action="store_true",
                    help="assume --sa-namespace already exists")
    ro.add_argument("--output-file")
    ro.set_defaults(func=cmd_roles)

    d = sub.add_parser("doctor", help="platform health & consistency check")
    d.add_argument("--probe", action="store_true",
                   help="also make one tiny live call to the configured LLM to verify "
                        "credentials and model name (no network without this)")
    d.add_argument("--verbose", "-v", action="store_true",
                   help="list the items behind every check, not just failures")
    d.add_argument("--output", "-o", default="text", choices=["text", "json"])
    d.set_defaults(func=cmd_doctor)

    ch = sub.add_parser("chat", help="interactive conversational security assistant")
    ch.add_argument("--live", action="store_true", help="scan the live cluster")
    ch.add_argument("--fixture", help="custom mock cluster JSON")
    ch.add_argument("--kubeconfig")
    ch.add_argument("--context", help="kubeconfig context to use")
    ch.set_defaults(func=cmd_chat)

    ci = sub.add_parser("cis", help="run the full CIS Kubernetes Benchmark v1.8 (130 controls)")
    ci.add_argument("--mock", action="store_true")
    ci.add_argument("--live", action="store_true")
    ci.add_argument("--fixture")
    ci.add_argument("--kubeconfig")
    ci.add_argument("--context", help="kubeconfig context to use")
    ci.add_argument("--kube-bench-json", help="kube-bench --json output to resolve "
                    "node file-permission controls")
    ci.add_argument("--profile", default="self-managed",
                    choices=["self-managed", "eks", "gke", "aks"],
                    help="managed profiles mark provider-owned control-plane controls N/A")
    ci.add_argument("--output", "-o", default="terminal",
                    choices=["terminal", "text", "markdown", "json"])
    ci.add_argument("--output-file")
    ci.add_argument("--show-all", action="store_true",
                    help="also list manual / node-dependent controls")
    ci.add_argument("--fail-on-fail", action="store_true",
                    help="exit 1 if any control FAILs (CI mode)")
    ci.set_defaults(func=cmd_cis)

    co = sub.add_parser("compliance",
                        help="audit against PCI DSS / SOC 2 / ISO 27001 / NIST 800-53")
    co.add_argument("--mock", action="store_true")
    co.add_argument("--live", action="store_true")
    co.add_argument("--fixture")
    co.add_argument("--kubeconfig")
    co.add_argument("--context", help="kubeconfig context to use")
    co.add_argument("--kube-bench-json", help="kube-bench --json output to resolve "
                    "node file-permission controls")
    co.add_argument("--profile", default="auto",
                    choices=["auto", "self-managed", "eks", "gke", "aks"],
                    help="CIS profile driving the underlying benchmark (auto-detects)")
    co.add_argument("--frameworks", help="comma-separated subset, e.g. "
                    "'PCI-DSS-4.0,SOC2,ISO-27001-2022,NIST-800-53-r5' (default: all)")
    co.add_argument("--output", "-o", default="markdown",
                    choices=["markdown", "json", "html", "pdf"])
    co.add_argument("--output-file", help="write here (required for pdf)")
    co.add_argument("--fail-on-fail", action="store_true",
                    help="exit 1 if any requirement FAILs (CI mode)")
    co.set_defaults(func=cmd_compliance)

    fed = sub.add_parser("federation",
                         help="cross-cluster blast radius from saved per-cluster scans")
    fed.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR,
                     help=f"report store to correlate (default: {_DEFAULT_REPORTS_DIR})")
    fed.add_argument("--output", "-o", default="markdown",
                     choices=["markdown", "json", "html"])
    fed.add_argument("--output-file")
    fed.set_defaults(func=cmd_federation)

    po = sub.add_parser("posture",
                        help="what changed since the previous scan of the same cluster")
    po.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    po.add_argument("--scan-id", help="compare this scan (default: the latest)")
    po.add_argument("--output", "-o", default="text", choices=["text", "json"])
    po.set_defaults(func=cmd_posture)

    fmts = ["terminal", "text", "markdown", "json", "sarif", "html", "pdf", "xlsx"]
    rp = sub.add_parser("report", help="list / download stored scan reports")
    rpsub = rp.add_subparsers(dest="report_cmd", required=True)
    rl = rpsub.add_parser("list", help="list stored reports")
    rl.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    rl.add_argument("--limit", type=int)
    rl.set_defaults(func=cmd_report)
    rd = rpsub.add_parser("download",
                          help="re-render a stored report in any format, to any filename")
    rd.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    rd.add_argument("--scan-id", help="scan id to download (default: latest)")
    rd.add_argument("--format", "-f", default="markdown", choices=fmts)
    rd.add_argument("--output", "-o", help="output filename (default: print to stdout)")
    rd.set_defaults(func=cmd_report)

    m = sub.add_parser("mcp", help="run the MCP server (or --list-tools)")
    m.add_argument("--list-tools", action="store_true")
    m.set_defaults(func=cmd_mcp)

    w = sub.add_parser("web", help="launch the Security Dashboard web interface")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8080)
    w.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    w.add_argument("--no-scan", action="store_true",
                   help="serve saved reports read-only; disable the in-dashboard scan button")
    w.add_argument("--open", action="store_true", help="open a browser at startup")
    w.add_argument("--allow-remote-kubeconfig", action="store_true",
                   help="accept a kubeconfig in the request body even on a non-loopback "
                        "bind. Loading one executes its credential plugin as this user, "
                        "so only use this behind your own authentication.")
    w.set_defaults(func=cmd_web)

    mx = sub.add_parser("matrix",
                        help="print the Kubernetes Threat Matrix (a scan's, or global coverage)")
    _add_scope_args(mx)
    _add_selector_args(mx)
    mx.add_argument("--scan-id", help="build the matrix from a saved report instead of scanning")
    mx.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    mx.add_argument("--coverage", action="store_true",
                    help="show global detection coverage (all rules), not a specific scan")
    mx.add_argument("--mock", action="store_true")
    mx.add_argument("--live", action="store_true")
    mx.add_argument("--fixture")
    mx.add_argument("--kubeconfig")
    mx.add_argument("--context")
    mx.add_argument("--output", "-o", default="text", choices=["text", "markdown", "json"])
    mx.add_argument("--output-file")
    mx.set_defaults(func=cmd_matrix)

    return p


def _force_utf8() -> None:
    # Windows consoles default to cp1252 and choke on emoji/box-drawing. Force UTF-8.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


def main(argv=None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
