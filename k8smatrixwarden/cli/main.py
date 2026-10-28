"""
k8smatrixwarden CLI (§7, §16.4), argparse-based (stdlib only, always runnable).

Commands:
  scan       run a scan by scope × selector, OR a natural-language query
  rules      list / inspect the rule registry
  coverage   show MITRE tactic coverage
  report     render the last scan (alias of scan --output)
  roles      print the per-plugin scoped RBAC roles (§20/§21)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from ..bootstrap import build_platform
from ..core.models import (ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity)
from ..core.report_store import DEFAULT_DIR as _DEFAULT_REPORTS_DIR
from ..web.server import DEFAULT_PORT as _WEB_PORT
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
        if getattr(a, "manifests", None):
            from ..core.manifests import MANIFEST_MODULES, ManifestEvidenceCollector
            mode_label = "manifests"
            collector = ManifestEvidenceCollector(a.manifests, helm=not a.no_helm,
                                                  helm_set=a.helm_set)
            for note in collector.skipped:
                print(f"note: {note}", file=sys.stderr)
            if request.selector.is_empty():
                request.selector.modules = list(MANIFEST_MODULES)
        else:
            collector = platform.make_collector(mock=(mode_label == "mock"),
                                                fixture=a.fixture, kubeconfig=a.kubeconfig,
                                                context=a.context,
                                                grype=getattr(a, "grype", False))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    from ..core.suppressions import discover as _discover_suppressions
    suppressions, supp_problems = _discover_suppressions(a.reports_dir, a.suppressions)
    for p in supp_problems:
        print(f"warning: {p}", file=sys.stderr)
    try:
        result = orch.run(request, collector, mode_label=mode_label,
                          name=getattr(a, "name", None) or "", suppressions=suppressions)
    except RuntimeError as exc:
        # A clean, actionable message (e.g. cluster unreachable), not a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # Live runtime feed: pull Falco alerts and correlate them into the result BEFORE we
    # render/persist, so the saved report + dashboard carry the runtime correlation.
    _attach_runtime_feed(result, collector, request, a)

    for w in getattr(collector, "warnings", []):
        print(f"warning: {w}", file=sys.stderr)

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

    if result.suppressed:
        print(f"[accepted risks] {len(result.suppressed)} finding(s) suppressed", file=sys.stderr)
    for n in result.suppression_notes:
        print(f"warning: {n}", file=sys.stderr)

    judged = result.findings
    if a.baseline:
        from ..core.suppressions import new_since
        base = _load_baseline(a.baseline, a.reports_dir)
        if base is None:
            print(f"error: baseline '{a.baseline}' is neither a saved scan id nor a JSON report",
                  file=sys.stderr)
            return 2
        judged = new_since(result.findings, base.findings)
        print(f"[baseline] {len(judged)} new finding(s) since {base.display_name}; "
              f"{len(result.findings) - len(judged)} already known", file=sys.stderr)
        for f in sorted(judged, key=lambda f: -f.severity.order)[:20]:
            print(f"  NEW {f.severity.label:<8} {f.rule_id}  {f.resource}", file=sys.stderr)
    if a.comment_file:
        with open(a.comment_file, "w", encoding="utf-8") as fh:
            fh.write(_pr_comment(result, judged, bool(a.baseline), a.fail_on))
        print(f"[written] {a.comment_file}", file=sys.stderr)
    if a.fail_on:
        floor = Severity.parse(a.fail_on).order
        if any(f.severity.order >= floor for f in judged):
            return 1
    return 0


def _pr_comment(result, judged, is_baseline: bool, fail_on) -> str:
    """Markdown for a pull-request comment: what this change adds (or, with no baseline, the
    top open issues), each with the one-line fix. Short on purpose; people read these."""
    from ..core.remediation import fix_for
    rows = sorted(judged, key=lambda f: (-f.severity.order, -f.score))[:15]
    head = (f"### K8sMatrixWarden: {len(judged)} new finding(s) in this change" if is_baseline
            else f"### K8sMatrixWarden: {len(judged)} open finding(s)")
    gate = ""
    if fail_on:
        floor = Severity.parse(fail_on).order
        bad = sum(1 for f in judged if f.severity.order >= floor)
        gate = (f"\n\n**{'❌ Blocking' if bad else '✅ Passing'}**: {bad} at {fail_on} or worse.")
    if not rows:
        return head + gate + "\n\nNothing to fix. ✔\n"
    body = ["| Severity | Issue | Where | Fix |", "|---|---|---|---|"]
    for f in rows:
        fix = fix_for(f.rule_id).get("how", "").replace("|", "/").replace("\n", " ")
        body.append(f"| {f.severity.label} | {f.title} | `{f.resource}` | {fix} |")
    more = f"\n\n…and {len(judged) - len(rows)} more." if len(judged) > len(rows) else ""
    sup = f"\n\n_{len(result.suppressed)} accepted risk(s) hidden._" if result.suppressed else ""
    return head + gate + "\n\n" + "\n".join(body) + more + sup + "\n"


def _load_baseline(ref: str, reports_dir):
    """A baseline is a saved scan id or a JSON report written with `-o json --output-file`."""
    from ..core.report_store import ReportStore
    from ..core.results import ScanResult
    if os.path.isfile(ref):
        try:
            with open(ref, encoding="utf-8") as fh:
                return ScanResult.from_dict(json.load(fh))
        except Exception:
            return None
    try:
        return ReportStore(reports_dir).resolve(ref)
    except (OSError, ValueError):
        return None


def cmd_notify(a) -> int:
    from ..core.notify import send, slack_payload
    from ..core.report_store import ReportStore
    store = ReportStore(a.reports_dir)
    result = store.resolve(a.scan_id) if a.scan_id else (store.latest() if hasattr(store, "latest") else None)
    if result is None:
        reports = store.list(limit=1)
        result = store.resolve(reports[0].scan_id) if reports else None
    if result is None:
        print("error: no saved scan to report. Run `k8smatrixwarden check --save` first.", file=sys.stderr)
        return 2
    payload = slack_payload(result, a.min_severity, a.dashboard_url or "")
    if a.dry_run:
        print(payload["text"])
        return 0
    url = a.webhook_url or os.environ.get("K8SMW_SLACK_WEBHOOK", "")
    if not url:
        print("error: give --webhook-url or set K8SMW_SLACK_WEBHOOK (use --dry-run to preview)",
              file=sys.stderr)
        return 2
    try:
        status = send(url, payload)
    except Exception as exc:
        print(f"error: could not post: {exc}", file=sys.stderr)
        return 2
    print(f"posted ({status})")
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


def cmd_cis(a) -> int:
    import json as _json
    from ..bootstrap import build_platform
    from ..frameworks.cis import CISBenchmarkEngine, render_markdown, render_text

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
    report = engine.evaluate(collector, profile=a.profile)

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


def cmd_posture(a) -> int:
    """What changed since the previous scan of the same cluster (§16)."""
    from ..core.posture import latest_change, posture_scope
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
        print(_json.dumps({**change, "timeline": store.timeline(
            scope=posture_scope(store, a.scan_id))}, indent=2))
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

    if a.output:
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


def cmd_topology(a) -> int:
    """Print the network topology of a scan (new, or a stored one)."""
    import json as _json
    platform = build_platform(a.config)
    if a.scan_id:
        from ..core.report_store import ReportStore
        try:
            result = ReportStore(a.reports_dir).resolve(a.scan_id)
        except FileNotFoundError:
            result = None
        if result is None:
            print(f"error: no stored report '{a.scan_id}'", file=sys.stderr)
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
    topo = result.topology
    if a.output == "json":
        print(_json.dumps(topo, indent=2))
        return 0
    s = topo.get("summary", {})
    print(f"{s.get('workloads', 0)} workloads · {s.get('services', 0)} services · "
          f"{s.get('ingresses', 0)} ingresses · {s.get('edges', 0)} edges")
    print("internet-exposed:", ", ".join(s.get("internet_exposed", [])) or "none")
    print("open (no ingress policy):", ", ".join(s.get("open_workloads", [])) or "none")
    for n in topo.get("notes", []):
        print("note:", n)
    for e in topo.get("edges", []):
        print(f"  {e['from']} -[{e['kind']}]-> {e['to']}   ({e['evidence']})")
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
                   choices=["terminal", "text", "markdown", "json", "sarif", "html", "brief"])
    s.add_argument("--output-file", help="also write the report here")
    s.add_argument("--mock", action="store_true", help="use the bundled mock cluster")
    s.add_argument("--live", action="store_true", help="scan the live cluster")
    s.add_argument("--manifests", nargs="+", metavar="PATH",
                   help="scan YAML/JSON files, folders or Helm charts instead of a cluster (for CI)")
    s.add_argument("--no-helm", action="store_true", help="with --manifests, do not render Helm charts")
    s.add_argument("--helm-set", action="append", default=[], metavar="KEY=VALUE",
                   help="with --manifests, a value passed to `helm template --set`")
    s.add_argument("--fixture", help="path to a custom mock cluster JSON")
    s.add_argument("--kubeconfig", help="path to a kubeconfig file (default: ~/.kube/config)")
    s.add_argument("--context", help="kubeconfig context to use (default: current-context)")
    s.add_argument("--grype", action="store_true",
                   help="with --live, scan the running images for known CVEs using Grype")
    s.add_argument("--suppressions", action="append", default=[], metavar="FILE",
                   help="accepted-risk file (YAML/JSON); .k8smatrixwarden-ignore.yaml in the "
                        "current folder and the dashboard's own list are always used too")
    s.add_argument("--baseline", metavar="SCAN_ID_OR_JSON",
                   help="a previous scan; with --fail-on, only findings new since it can fail the run")
    s.add_argument("--comment-file", metavar="FILE",
                   help="write a short Markdown summary (new findings with fixes) for a PR comment")
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

    nt = sub.add_parser("notify", help="post the latest scan summary to Slack (or a compatible webhook)")
    nt.add_argument("--webhook-url", help="https URL (or set K8SMW_SLACK_WEBHOOK)")
    nt.add_argument("--scan-id", help="default: the most recent saved scan")
    nt.add_argument("--min-severity", default="HIGH", choices=["MEDIUM", "HIGH", "CRITICAL"])
    nt.add_argument("--dashboard-url", help="link to include, e.g. http://dashboard.internal:8765")
    nt.add_argument("--dry-run", action="store_true", help="print the message instead of sending it")
    nt.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    nt.set_defaults(func=cmd_notify)

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

    ci = sub.add_parser("cis", help="run the full CIS Kubernetes Benchmark v1.8 (130 controls)")
    ci.add_argument("--mock", action="store_true")
    ci.add_argument("--live", action="store_true")
    ci.add_argument("--fixture")
    ci.add_argument("--kubeconfig")
    ci.add_argument("--context", help="kubeconfig context to use")
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

    po = sub.add_parser("posture",
                        help="what changed since the previous scan of the same cluster")
    po.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    po.add_argument("--scan-id", help="compare this scan (default: the latest)")
    po.add_argument("--output", "-o", default="text", choices=["text", "json"])
    po.set_defaults(func=cmd_posture)

    fmts = ["terminal", "text", "markdown", "json", "sarif", "html", "brief"]
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

    tp = sub.add_parser("topology", help="print the network topology (who can reach whom)")
    _add_scope_args(tp)
    _add_selector_args(tp)
    tp.add_argument("--scan-id", help="use a saved report instead of scanning")
    tp.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    tp.add_argument("--mock", action="store_true")
    tp.add_argument("--live", action="store_true")
    tp.add_argument("--fixture")
    tp.add_argument("--kubeconfig")
    tp.add_argument("--context")
    tp.add_argument("--output", "-o", default="text", choices=["text", "json"])
    tp.set_defaults(func=cmd_topology)

    w = sub.add_parser("web", help="launch the Security Dashboard web interface")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=_WEB_PORT,
                   help=f"dashboard port (shared default: {_WEB_PORT}; "
                        f"override for CLI and MCP alike with "
                        f"$K8SMATRIXWARDEN_WEB_PORT)")
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


CHECK_HELP = """usage: k8smatrixwarden check [PATH ...] [options]

The everyday command. With no PATH it checks the cluster your kubectl points at; with files,
folders or Helm charts it checks those before they are deployed. Prints what to fix first.

  PATH ...            YAML/JSON files, folders or Helm charts to check (no cluster needed)
  --context NAME      kubeconfig context (default: the current one)
  -n, --namespace NS  only this namespace
  --grype             also scan running images for CVEs (needs the grype program)
  --fail-on LEVEL     exit 1 if any open finding is LEVEL or worse (LOW MEDIUM HIGH CRITICAL)
  --baseline REF      with --fail-on, only findings new since this scan id / JSON report count
  --suppressions F    accepted-risk file (also reads .k8smatrixwarden-ignore.yaml)
  --name TEXT         name this scan
  --save              keep the result so `k8smatrixwarden web` shows it
  -o, --output FMT    brief (default), markdown, json, sarif, html, text
"""


def _check_to_scan(argv: list) -> list:
    """`check` is `scan` with sensible defaults: brief output, a real target, nothing saved
    unless asked (a CI run should not fill a disk)."""
    p = argparse.ArgumentParser(prog="k8smatrixwarden check", add_help=False)
    p.add_argument("paths", nargs="*")
    p.add_argument("--context")
    p.add_argument("--namespace", "-n")
    p.add_argument("--grype", action="store_true")
    p.add_argument("--fail-on")
    p.add_argument("--baseline")
    p.add_argument("--suppressions", action="append", default=[])
    p.add_argument("--name")
    p.add_argument("--save", action="store_true")
    p.add_argument("--output", "-o", default="brief")
    p.add_argument("--reports-dir", default=_DEFAULT_REPORTS_DIR)
    a, extra = p.parse_known_args(argv)
    out = ["scan", "-y", "-o", a.output, "--reports-dir", a.reports_dir] + extra
    out += ["--manifests"] + a.paths if a.paths else ["--live"]
    for flag, val in (("--context", a.context), ("--namespace", a.namespace),
                      ("--fail-on", a.fail_on), ("--baseline", a.baseline), ("--name", a.name)):
        if val:
            out += [flag, val]
    for s in a.suppressions:
        out += ["--suppressions", s]
    if a.grype and not a.paths:
        out += ["--grype"]
    if not a.save:
        out += ["--no-save"]
    return out


def main(argv=None) -> int:
    _force_utf8()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["check"]:
        if {"-h", "--help"} & set(argv[1:]):
            print(CHECK_HELP)
            return 0
        argv = _check_to_scan(argv[1:])
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
