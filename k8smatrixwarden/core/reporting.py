"""
Reporting Engine (§18.2), rich, multi-format, audit-grade security reports.

Renders a ScanResult in seven formats, each designed to be genuinely useful rather than a
flat dump. Every finding, in every format, carries the same report-grade sections
(sourced from `core.finding_context.build_finding_context()`, the single shared content
layer): Summary, Standards & Benchmark Mapping (with reference links), MITRE ATT&CK
Mapping (with reference links), Impact, and Validation/reproduction steps.

  terminal , rich panels + per-severity tables (falls back to `text` with no `rich`)
  text     , grouped, sectioned plain-text (zero dependency)
  markdown , the flagship: frontmatter, verdict, risk gauge, coverage dashboards,
              full per-finding report cards, an appendix
  json     , full structured data + a summary block + the same per-finding context
  sarif    , SARIF 2.1 with security-severity, tags, rich help.markdown, fingerprints
  html     , self-contained, responsive, dark/light card report with the same sections
  pdf      , a print/share-ready audit document (title page, executive summary,
              coverage, full per-finding write-ups); requires the optional `pdf` extra
              (`pip install -e ".[pdf]"`), see core/pdf_report.py. Returns `bytes`, not
              `str`, the only format that does; callers must branch on this.

Tag-based filtering stays first-class because tags are finding metadata (§18.2).
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from .models import Finding, Severity
from .results import ScanResult
from .threat_matrix_render import THREAT_MATRIX_CSS
from .timeutil import format_ist


def finding_anchor(rule_id: str, kind: str = "", name: str = "",
                   namespace: Optional[str] = None) -> str:
    """Stable, URL-safe HTML anchor for a finding, so any surface (the web dashboard's
    Findings / Threat Matrix / Attack views) can deep-link straight to a finding's card
    in the rendered report via ``/report/<scan_id>#<anchor>``. The same slug is computed
    client-side in the dashboard JS, so both sides agree without shipping it in the data."""
    raw = f"{rule_id}-{kind}-{name}-{namespace or ''}"
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return "f-" + (slug or "finding")


def _finding_anchor(f: Finding) -> str:
    r = f.resource
    return finding_anchor(f.rule_id, r.kind, r.name, r.namespace)

try:  # optional pretty terminal output
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False

_SEV_DISPLAY = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


class ReportingEngine:
    def __init__(self, registry=None):
        #: optional RuleRegistry, supplies the threat matrix's *coverage* layer (which
        #: techniques have a rule at all, beyond what this scan hit). Set by bootstrap so
        #: `platform.reporting` renders the full 3-state matrix; a bare ReportingEngine()
        #: still works (findings-only matrix). See core/threat_matrix.py.
        self.registry = registry

    def render(self, result: ScanResult, fmt: str = "terminal"):
        """Render in the requested format. Every format returns `str` EXCEPT `pdf`,
        which returns raw `bytes`, callers must check the format and write/handle it
        accordingly (binary file mode, base64-encode for a JSON/text transport, etc.)."""
        fmt = (fmt or "terminal").lower()
        if fmt == "pdf":
            return self.pdf(result)
        if fmt in ("xlsx", "excel"):
            return self.xlsx(result)
        return {
            "terminal": self.terminal, "text": self.text,
            "markdown": self.markdown, "md": self.markdown,
            "json": self.json, "sarif": self.sarif, "html": self.html,
        }.get(fmt, self.terminal)(result)

    # ================================================================== #
    # PDF (requires the optional `pdf` extra, fpdf2)
    # ================================================================== #
    def pdf(self, result: ScanResult) -> bytes:
        from .pdf_report import render_pdf
        return render_pdf(result)

    # ================================================================== #
    # XLSX (requires the optional `excel` extra, openpyxl)
    # ================================================================== #
    def xlsx(self, result: ScanResult) -> bytes:
        from .excel_report import render_xlsx
        return render_xlsx(result)

    # ================================================================== #
    # TERMINAL (rich)
    # ================================================================== #
    def terminal(self, result: ScanResult) -> str:
        if not _RICH:
            return self.text(result)
        # A plain `Console(record=True)` still writes every `console.print(...)` straight to
        # the real stdout while *also* recording it, so callers that print the returned
        # string (cli cmd_scan does) would emit the whole report twice. Render into an
        # in-memory sink instead: this stays a pure string-builder like every other
        # renderer, so the single caller-side print emits it exactly once.
        import io
        console = Console(record=True, width=100, file=io.StringIO())
        r = result.risk
        c = result.counts

        summary = (
            f"[bold]{r.rating_emoji} Risk {r.cluster_risk}/10 ({r.rating})[/bold]   "
            f"Security score [bold]{r.security_score}/100[/bold]\n"
            f"Scope [cyan]{result.request.scope.describe()}[/cyan]   "
            f"Selector [cyan]{result.request.selector.describe()}[/cyan]   "
            f"Mode {result.mode}   Rules {len(result.resolved_rule_ids)}\n"
            f"🔴 {c['CRITICAL']} Critical   🟠 {c['HIGH']} High   "
            f"🟡 {c['MEDIUM']} Medium   🟢 {c['LOW']} Low")
        # Coverage belongs next to the score wherever the score appears: a 9.9 from 95%
        # coverage is a different statement from a 9.9 from 40%, and the terminal was the
        # only surface showing the score without it.
        cov = result.coverage or {}
        if cov:
            summary += (f"\nEvidence coverage {cov.get('coverage_pct')}% "
                        f"({cov.get('coverage_basis', 'measured')})   "
                        f"Assessment confidence {cov.get('confidence_pct')}% "
                        f"({cov.get('confidence_label', '')})")
        console.print(Panel(summary, title=f"🛡️  K8s Security Report · {result.scan_id}",
                            border_style=_rich_border(r.rating), expand=True))

        warns = scan_warning_lines(result)
        if warns:
            console.print(Panel("\n".join(f"• {w}" for w in warns),
                                title="⚠️  Scan warnings", border_style="dark_orange",
                                expand=True))

        # Live runtime evidence, above the findings tables: "this one is being exploited
        # right now" outranks any static severity ordering below it.
        rt_lines = _runtime_lines(result)
        if rt_lines:
            summary_line, *detail = [ln for ln in rt_lines if not ln.startswith("─")]
            confirmed = (_runtime_summary(result) or {}).get("confirmed", 0)
            console.print(Panel("\n".join([summary_line] + [f"• {d.strip()}"
                                                            for d in detail]),
                                title="📡 Runtime correlation (live feed)",
                                border_style="red" if confirmed else "cyan",
                                expand=True))

        findings = _display_findings(result.findings)
        if not findings:
            console.print("[green]✅ No findings for this scan.[/green]")
            return console.export_text()

        for sev in _SEV_DISPLAY:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            table = Table(title=f"{sev.emoji} {sev.label} ({len(group)})",
                          show_lines=False, expand=True, border_style=_rich_sev(sev),
                          title_justify="left")
            table.add_column("Rule", style="dim", no_wrap=True)
            table.add_column("Resource")
            table.add_column("MITRE", no_wrap=True)
            table.add_column("Finding")
            for f in group:
                tag = "⚡" if len(f.tactics) > 1 else " "
                table.add_row(f"{tag}{f.rule_id}", str(f.resource),
                              _mitre_short(f), f.message)
            console.print(table)

        return console.export_text()

    # ================================================================== #
    # TEXT (plain, zero-dep)
    # ================================================================== #
    def text(self, result: ScanResult) -> str:
        r = result.risk
        c = result.counts
        total = result.total()
        rule = "═" * 78
        # Left-aligned banner (no right border), emoji render 2-wide and would break a
        # right border's alignment, so we deliberately avoid one.
        out = [
            rule,
            f"  🛡️  K8s SECURITY REPORT  ·  {result.scan_id}",
            rule,
            f"  Generated : {result.generated_at}",
            f"  Scope     : {result.request.scope.describe()}",
            f"  Selector  : {result.request.selector.describe()}",
            f"  Mode      : {result.mode}   ·   Rules run: {len(result.resolved_rule_ids)}",
            "  " + "─" * 60,
            f"  RISK   {r.rating_emoji} {r.cluster_risk}/10 ({r.rating})"
            f"   ·   Security score {r.security_score}/100",
            f"  {_risk_gauge(r.cluster_risk)}",
            "  " + "─" * 60,
        ]
        # How much of the cluster the verdict above is based on. Printed next to the score
        # so the two are read together, a 9.7 from 40% coverage is a different statement
        # from a 9.7 from 100%.
        out += [f"  {line}" for line in _coverage_lines(result)]
        # Runtime correlation sits beside coverage: both qualify what the findings mean.
        out += [f"  {line}" for line in _runtime_lines(result)]
        warns = scan_warning_lines(result)
        if warns:
            out += [f"  ⚠️  SCAN WARNINGS ({len(warns)})"]
            out += [f"     - {w}" for w in warns]
            out += ["  " + "─" * 60]
        for sev in _SEV_DISPLAY:
            n = c[sev.label]
            out.append(f"  {sev.emoji} {sev.label:<9} {n:>3}   "
                       f"{_bar(_frac(n, total), 30)}  {_pct(n, total)}")
        out.append(rule)

        findings = _display_findings(result.findings)
        for sev in _SEV_DISPLAY:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            out += ["", f"── {sev.emoji} {sev.label} FINDINGS ({len(group)}) "
                    + "─" * (55 - len(sev.label))]
            for i, f in enumerate(group, 1):
                amp = "  ⚡ multi-tactic" if len(f.tactics) > 1 else ""
                out.append(f"\n  {i}. {f.title}, {f.resource}{amp}")
                out.append(f"     rule   : {f.rule_id}  [{f.owning_shard}]")
                out.append(f"     mitre  : {_mitre_long(f) or '-'}")
                out.append(f"     owasp  : {_owasp_label(f.owasp)}   "
                           f"cis: {', '.join(f.cis) or '-'}")
                out.append(f"     impact : exploitability={f.exploitability.label} · "
                           f"blast={f.blast_radius.label} · score={round(f.score, 1)}")
                if _vector_label(f):
                    out.append(f"     vector : {_vector_label(f)} — {f.path_reason}")
                out.append(f"     detail : {f.message}")
                from .finding_context import build_finding_context
                ctx = build_finding_context(f)
                if ctx.standards:
                    out.append("     standards : " + "  ".join(
                        f"{s.framework.split()[0]}:{s.control}" for s in ctx.standards))
                out.append(f"     why    : {_truncate(ctx.impact, 140)}")
                if ctx.validation_steps:
                    out.append(f"     verify : {ctx.validation_steps[0]}")
        if not findings:
            out += ["", "  ✅ No findings for this scan."]
        return "\n".join(out)

    # ================================================================== #
    # MARKDOWN (flagship)
    # ================================================================== #
    def markdown(self, result: ScanResult) -> str:
        r = result.risk
        c = result.counts
        total = result.total()
        findings = _display_findings(result.findings)
        multi = [f for f in findings if len(f.tactics) > 1]

        md: list[str] = []

        # ---- frontmatter ------------------------------------------------ #
        # scan name is free user input, escape quotes so the YAML frontmatter stays valid
        _yaml_name = str(result.name).replace("\\", "\\\\").replace('"', '\\"')
        md += [
            "---",
            'title: "K8s Security Report"',
            f'name: "{_yaml_name}"',
            f'cluster: "{result.cluster_name}"',
            f'scan_id: "{result.scan_id}"',
            f'generated_at: "{result.generated_at}"',
            f'tool: "k8smatrixwarden {result.tool_version}"',
            f'mode: "{result.mode}"',
            f'scope: "{result.request.scope.describe()}"',
            f'selector: "{result.request.selector.describe()}"',
            f"rules_run: {len(result.resolved_rule_ids)}",
            f"risk_score: {r.cluster_risk}",
            f"security_score: {r.security_score}",
            f'rating: "{r.rating}"',
            f"critical: {c['CRITICAL']}", f"high: {c['HIGH']}",
            f"medium: {c['MEDIUM']}", f"low: {c['LOW']}",
            f"tactics_covered: {len(result.by_tactic)}",
            "---",
            "",
            f"# 🛡️ K8s Security Report",
            "",
            f"{_status_badges(result)}",
            "",
            f"> {_verdict(r.rating)}",
            *_warning_md(result),
            "",
        ]

        # ---- table of contents ----------------------------------------- #
        md += [
            "<a id=\"top\"></a>",
            "## Contents",
            "",
            "1. [Executive Summary](#summary)",
            "2. [Kubernetes Threat Matrix](#matrix)",
            "3. [Coverage & Exposure](#coverage)",
            "4. [Findings](#findings)"
            + (" · [⚡ Attack-Path Amplified](#attackpaths)" if multi else ""),
            "5. [Appendix](#appendix)",
            "",
            "---",
            "",
        ]

        # ---- executive summary ----------------------------------------- #
        md += [
            "<a id=\"summary\"></a>",
            "## 1. 📊 Executive Summary",
            "",
            f"**Overall risk:** {r.rating_emoji} **{r.cluster_risk} / 10 "
            f"({r.rating})**  ·  **Security score:** {r.security_score} / 100",
            "",
            "```",
            f"Risk  {_risk_gauge(r.cluster_risk)}",
            "```",
            "",
            "| Severity | Count | Share |",
            "|:--|--:|:--|",
        ]
        for sev in _SEV_DISPLAY:
            n = c[sev.label]
            md.append(f"| {sev.emoji} {sev.label} | **{n}** | "
                      f"`{_bar(_frac(n, total), 18)}` {_pct(n, total)} |")
        md += [
            f"| **Total** | **{total}** | |",
            "",
            f"- **Findings:** {total} actionable "
            f"({c['CRITICAL']} critical, {c['HIGH']} high, {c['MEDIUM']} medium, "
            f"{c['LOW']} low)",
            f"- **MITRE ATT&CK tactics implicated:** {len(result.by_tactic)} / 9",
            f"- **Attack-path amplified findings:** {len(multi)} "
            f"(one issue enabling multiple tactics)" if multi else
            "- **Attack-path amplified findings:** 0",
            f"- **Rules evaluated:** {len(result.resolved_rule_ids)} across "
            f"{len(result.by_shard)} domain(s)",
            "",
            "[↑ top](#top)",
            "",
            "---",
            "",
        ]

        # ---- threat matrix ---------------------------------------------- #
        from .threat_matrix import build_threat_matrix
        from .threat_matrix_render import render_markdown as _tm_md
        tm = build_threat_matrix(result, self.registry)
        md += ["<a id=\"matrix\"></a>", "## 2. 🗺️ Kubernetes Threat Matrix", "",
               _tm_md(tm, heading_level=3, include_heading=False), "",
               _attack_path_md(tm),
               "[↑ top](#top)", "", "---", ""]

        # ---- coverage --------------------------------------------------- #
        md += ["<a id=\"coverage\"></a>", "## 3. 🎯 Coverage & Exposure", ""]
        md += _coverage_md(result)
        md += _runtime_md(result)

        if result.by_tactic:
            md += ["### By MITRE ATT&CK Tactic", "",
                   "| Tactic | Findings | Distribution |", "|:--|--:|:--|"]
            mx = max(result.by_tactic.values())
            for tactic, n in sorted(result.by_tactic.items(), key=lambda kv: -kv[1]):
                md.append(f"| {tactic} | {n} | `{_bar(_frac(n, mx), 16)}` |")
            md.append("")

        if result.by_shard:
            md += ["### By Security Domain (shard)", "",
                   "| Domain | Findings |", "|:--|--:|"]
            for shard, n in sorted(result.by_shard.items(), key=lambda kv: -kv[1]):
                md.append(f"| `{shard}` | {n} |")
            md.append("")

        owasp = _by_owasp(findings)
        if owasp:
            md += ["### OWASP Kubernetes Top 10 (2025)", "",
                   "| ID | Category | Findings |", "|:--|:--|--:|"]
            for code in sorted(owasp):
                md.append(f"| [`{code}`]({owasp_url(code)}) | "
                          f"{_owasp_names().get(code, 'N/A')} | {owasp[code]} |")
            md.append("")
        md += ["[↑ top](#top)", "", "---", ""]

        # ---- attack paths ---------------------------------------------- #
        if multi:
            md += [
                "<a id=\"attackpaths\"></a>",
                "## ⚡ Attack-Path Amplified Findings",
                "",
                "These single issues each enable **multiple** MITRE tactics, so an attacker "
                "can chain them, they are scored higher and should be fixed first.",
                "",
                "| Finding | Resource | Tactics enabled |",
                "|:--|:--|:--|",
            ]
            for f in sorted(multi, key=lambda x: -x.score):
                tactics = " → ".join(t.value for t in f.tactics)
                md.append(f"| **{f.title}** | `{f.resource}` | {tactics} |")
            md += ["", "---", ""]

        # ---- findings --------------------------------------------------- #
        md += ["<a id=\"findings\"></a>", "## 4. 🚨 Findings", ""]
        if not findings:
            md += ["_No findings for this scan._ ✅", ""]
        for sev in _SEV_DISPLAY:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            md += [f"<a id=\"sev-{sev.label.lower()}\"></a>",
                   f"### {sev.emoji} {sev.label}, {len(group)} finding(s)", ""]
            for i, f in enumerate(group, 1):
                md += _finding_card(f, i)
        md += ["[↑ top](#top)", "", "---", ""]

        # ---- appendix --------------------------------------------------- #
        md += [
            "<a id=\"appendix\"></a>",
            "## 5. 📎 Appendix",
            "",
            "<details><summary><strong>Scan metadata</strong></summary>",
            "",
            "| Key | Value |", "|:--|:--|",
            f"| Scan ID | `{result.scan_id}` |",
            f"| Generated | {result.generated_at} |",
            f"| Tool version | k8smatrixwarden {result.tool_version} |",
            f"| Mode | {result.mode} |",
            f"| Scope | {result.request.scope.describe()} |",
            f"| Selector | {result.request.selector.describe()} |",
            f"| Rules evaluated | {len(result.resolved_rule_ids)} |",
            "",
            "</details>",
            "",
            "<details><summary><strong>Rules evaluated in this scan</strong></summary>",
            "",
            "```",
            ("\n".join(_wrap_ids(result.resolved_rule_ids)) or "(none)"),
            "```",
            "",
            "</details>",
            "",
            "---",
            f"<sub>Generated by 🛡️ k8smatrixwarden {result.tool_version}, "
            f"MITRE ATT&CK-aligned Kubernetes security scanner.</sub>",
        ]
        return "\n".join(md)

    # ================================================================== #
    # JSON (structured + summary + per-finding context)
    # ================================================================== #
    def json(self, result: ScanResult) -> str:
        doc = result.as_dict()
        c = result.counts
        total = result.total()
        doc["summary"] = {
            "rating": result.risk.rating,
            "risk_score": result.risk.cluster_risk,
            "security_score": result.risk.security_score,
            "total_findings": total,
            "severity_percent": {s.label: _pct_num(c[s.label], total)
                                 for s in _SEV_DISPLAY},
            "attack_path_amplified": sum(1 for f in result.findings
                                         if len(f.tactics) > 1 and f.severity.weight),
            "owasp": _by_owasp(result.findings),
            # How much of the cluster this verdict is actually based on (§5). Reported
            # beside the score, never folded into it: a low-coverage scan reports its
            # findings in full and says the assessment is less complete.
            "evidence_coverage_pct": result.coverage.get("coverage_pct"),
            "assessment_confidence_pct": result.coverage.get("confidence_pct"),
            "assessment_confidence": result.coverage.get("confidence_label"),
        }
        # Full Kubernetes Threat Matrix projection (§12), same structure the HTML/web
        # heatmap and the MCP build_threat_matrix tool return, so a JSON/API consumer gets
        # the adversary-behaviour map, not just a flat finding list.
        from .threat_matrix import attack_paths, build_threat_matrix
        _tm = build_threat_matrix(result, self.registry)
        doc["threat_matrix"] = _tm.as_dict()
        # Kill-chain exploit path derived from the matrix's hit cells (§12), which
        # tactics an attacker can actually string together in this cluster.
        doc["attack_path"] = attack_paths(_tm, result.runtime,
                                          cluster=result.cluster_name)
        # attach the full report-grade context to each finding: summary, standards &
        # benchmark mapping (with links), MITRE mapping (with links), impact, and
        # validation steps, the same data every other renderer (markdown/html/sarif/pdf)
        # sources from build_finding_context(), so a JSON/API consumer never sees less
        # than a human-facing report does.
        from .finding_context import build_finding_context
        for fd, f in zip(doc["findings"], result.findings):
            ctx = build_finding_context(f)
            fd["summary"] = ctx.summary
            fd["impact"] = ctx.impact
            fd["validation_steps"] = ctx.validation_steps
            fd["standards"] = [{"framework": s.framework, "control": s.control,
                               "title": s.title, "url": s.url} for s in ctx.standards]
            fd["mitre_mapping"] = [{"tactic": m.tactic, "technique_id": m.technique_id,
                                    "technique_name": m.technique_name, "url": m.url}
                                   for m in ctx.mitre]
        return json.dumps(doc, indent=2)

    # ================================================================== #
    # SARIF 2.1 (GitHub Code Scanning-ready)
    # ================================================================== #
    def sarif(self, result: ScanResult) -> str:
        from .finding_context import build_finding_context

        rules: dict[str, dict] = {}
        results = []
        for f in result.findings:
            if f.severity.weight == 0:
                continue
            if f.rule_id not in rules:
                ctx = build_finding_context(f)
                help_uri = (ctx.standards[0].url if ctx.standards else
                           (ctx.mitre[0].url if ctx.mitre else
                            "https://owasp.org/www-project-kubernetes-top-ten/"))
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": ctx.summary},
                    "helpUri": help_uri,
                    "help": {"text": ctx.impact or f.message,
                             "markdown": _sarif_help_md(ctx)},
                    "defaultConfiguration": {"level": _sarif_level(f.severity)},
                    "properties": {
                        "security-severity": _security_severity(f.severity),
                        "tags": _sarif_tags(f),
                        "owasp": f.owasp,
                        "mitre": [m.technique_id for m in f.mitre],
                        "cis": f.cis,
                        "shard": f.owning_shard,
                        "impact": ctx.impact,
                        "standards": [{"framework": s.framework, "control": s.control,
                                      "url": s.url} for s in ctx.standards],
                        "validationSteps": ctx.validation_steps,
                    },
                }
            results.append({
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "partialFingerprints": {
                    "k8smatrixwarden/v1": f"{f.rule_id}:{f.resource.namespace}:"
                                 f"{f.resource.kind}:{f.resource.name}"},
                "properties": {"security-severity": _security_severity(f.severity),
                    # per-finding: the reachability vector varies by pod, so it lives on the
                    # result, not the rule (owasp/mitre/cis are rule-level, exploitable_by isn't)
                    **({"exploitableBy": f.exploitable_by, "attackVector": f.path_reason}
                       if f.exploitable_by else {})},
                "locations": [{"logicalLocations": [{
                    "name": str(f.resource), "kind": f.resource.kind,
                    "fullyQualifiedName": _fqn(f)}]}],
            })
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "k8smatrixwarden",
                    "fullName": "k8smatrixwarden, MITRE ATT&CK-aligned Kubernetes scanner",
                    "version": result.tool_version,
                    "informationUri": "https://owasp.org/www-project-kubernetes-top-ten/",
                    "rules": list(rules.values()),
                }},
                "results": results,
                "properties": {"scan_id": result.scan_id,
                               "risk_score": result.risk.cluster_risk,
                               "rating": result.risk.rating},
            }],
        }
        return json.dumps(doc, indent=2)

    # ================================================================== #
    # HTML (self-contained, responsive, dark/light)
    # ================================================================== #
    def html(self, result: ScanResult) -> str:
        r = result.risk
        c = result.counts
        total = result.total()
        findings = _display_findings(result.findings)

        chips = (f"<span class='sev crit'>🔴 {c['CRITICAL']} Critical</span>"
                 f"<span class='sev high'>🟠 {c['HIGH']} High</span>"
                 f"<span class='sev med'>🟡 {c['MEDIUM']} Medium</span>"
                 f"<span class='sev low'>🟢 {c['LOW']} Low</span>")

        from .finding_context import build_finding_context

        cards = []
        for f in findings:
            ctx = build_finding_context(f)

            # Chips: the technique / standard IDs are themselves clickable, each deep-linking
            # to its authoritative reference (MITRE per-technique page, OWASP Top 10, CIS
            # benchmark), so a reader can jump straight from the ID to its source.
            mitre_tags = " ".join(
                f"<a class='tag mitre' href='{_esc(m.url)}' target='_blank' rel='noopener' "
                f"title='View {_esc(m.technique_id)} on MITRE ATT&amp;CK'>{_esc(m.tactic)} · "
                f"{_esc(m.technique_id)}</a>" for m in ctx.mitre)
            std_tags = "".join(
                f"<a class='tag std' href='{_esc(s.url)}' target='_blank' rel='noopener' "
                f"title='{_esc(s.framework)} {_esc(s.control)} reference'>"
                f"{_esc(s.framework.split()[0])} {_esc(s.control)}</a>" for s in ctx.standards)
            amp = "<span class='tag amp'>⚡ multi-tactic</span>" if len(f.tactics) > 1 else ""

            mitre_rows = "".join(
                f"<tr><td>{_esc(m.tactic)}</td><td>{_esc(m.technique_name)} "
                f"<a href='{_esc(m.url)}' target='_blank' rel='noopener'>"
                f"<code>{_esc(m.technique_id)}</code></a></td>"
                f"<td><a href='{_esc(m.url)}' target='_blank' rel='noopener'>Reference</a></td></tr>"
                for m in ctx.mitre) or "<tr><td colspan='3' class='muted'>Not mapped to a " \
                "MITRE ATT&amp;CK technique.</td></tr>"
            std_rows = "".join(
                f"<tr><td>{_esc(s.framework)}</td>"
                f"<td><a href='{_esc(s.url)}' target='_blank' rel='noopener'>{_esc(s.control)}</a>"
                f", {_esc(s.title)}</td>"
                f"<td><a href='{_esc(s.url)}' target='_blank' rel='noopener'>Reference</a></td></tr>"
                for s in ctx.standards) or "<tr><td colspan='3' class='muted'>No named " \
                "standard or benchmark maps to this finding.</td></tr>"

            validation_html = ("<details><summary>Validation, how to reproduce</summary>"
                               f"<pre class='cmd'>{_esc(chr(10).join(ctx.validation_steps))}"
                               "</pre></details>")

            cards.append(
                f"<div class='card {f.severity.label.lower()}' id='{_finding_anchor(f)}'>"
                f"<div class='chead'><span class='badge {f.severity.label.lower()}'>"
                f"{f.severity.emoji} {f.severity.label}</span>"
                f"<span class='ctitle'>{_esc(f.title)}</span>"
                f"<code class='res'>{_esc(str(f.resource))}</code>{amp}</div>"
                f"<div class='csummary'>{_esc(ctx.summary)}</div>"
                f"<div class='cmsg'><strong>Detected:</strong> {_esc(f.message)}</div>"
                f"<div class='tags'>{mitre_tags}{std_tags}"
                f"<span class='tag'>score {round(f.score,1)}</span>"
                f"<span class='tag'>{_esc(f.owning_shard)}</span></div>"
                f"<details><summary>Standards &amp; Benchmark Mapping</summary>"
                f"<table class='ctx-table'>{std_rows}</table></details>"
                f"<details><summary>MITRE ATT&amp;CK Mapping</summary>"
                f"<table class='ctx-table'>{mitre_rows}</table></details>"
                f"{_exposure_html(f)}"
                f"<div class='cimpact'><strong>Impact:</strong> {_esc(ctx.impact)}</div>"
                f"{validation_html}"
                f"</div>")

        filters = ("<button data-f='all' class='on'>All</button>"
                   "<button data-f='critical'>Critical</button>"
                   "<button data-f='high'>High</button>"
                   "<button data-f='medium'>Medium</button>"
                   "<button data-f='low'>Low</button>")

        from .threat_matrix import build_threat_matrix
        from .threat_matrix_render import render_html_grid
        matrix_html = ("<section class='matrix'><h2>Kubernetes Threat Matrix</h2>"
                       + render_html_grid(build_threat_matrix(result, self.registry))
                       + "</section>")

        return _HTML_TMPL.format(
            css=_HTML_CSS, js=_HTML_JS + THEME_JS, scan=_esc(result.scan_id),
            matrix=matrix_html, themebtn=THEME_BUTTON,
            warnings=warning_banner_html(result),
            coverage=_coverage_html(result) + _runtime_html(result),
            cluster=_esc(result.cluster_name), rating=r.rating,
            risk=r.cluster_risk, sec=r.security_score,
            rating_emoji=r.rating_emoji, rating_class=r.rating.lower(),
            scope=_esc(result.request.scope.describe()),
            selector=_esc(result.request.selector.describe()),
            mode=result.mode, rules=len(result.resolved_rule_ids),
            generated=_esc(format_ist(result.generated_at)),
            verdict=_esc(_verdict(r.rating)),
            chips=chips, filters=filters,
            gaugepct=min(100, round(r.cluster_risk * 10)),
            cards=("".join(cards) or "<p class='ok'>✅ No findings for this scan.</p>"),
            total=total, tactics=len(result.by_tactic))


# ======================================================================= #
# helpers
# ======================================================================= #
def _coverage_lines(result: ScanResult) -> list[str]:
    """Evidence coverage / assessment confidence, plus the domains that were not fully
    readable. Empty for a scan saved before coverage tracking existed, so old reports
    render exactly as they did."""
    from .coverage import summary_line
    cov = result.coverage
    if not cov:
        return []
    lines = [summary_line(cov)]
    gaps = [f"{name} {d['coverage_pct']}%"
            for name, d in cov.get("domains", {}).items() if d["coverage_pct"] < 100]
    if gaps:
        lines.append("Partly/never read: " + ", ".join(gaps))
        lines.append("Low coverage does not hide findings; it means the parts that look "
                     "clean may simply not have been visible.")
    lines.append("─" * 60)
    return lines


def _runtime_rows(result: ScanResult) -> list[tuple]:
    """(confidence, freshness, tactic, resource, namespace, falco rule) per correlation.

    One extraction, shared by every renderer, so the surfaces cannot disagree about what
    the runtime feed said. Empty when the scan pulled no runtime feed at all, which is the
    normal case for a mock scan or a `--no-runtime` live scan."""
    rt = getattr(result, "runtime", None) or {}
    corr = rt.get("correlation") or {}
    rows = []
    for c in corr.get("correlations", []):
        rt_view = c.get("runtime") or {}
        # Who detected it, in the analyst's words rather than the model's: a curated rule
        # is ours, anything else is the provider's verdict relayed under its own name.
        detector = ("K8sMatrixWarden" if rt_view.get("detection_source", "kmw") == "kmw"
                    else "Falco")
        supporting = rt_view.get("supporting_evidence") or ""
        # Identity quality is reported beside the correlation, because "not confirmed"
        # because we could not place the event is a different statement from "not
        # confirmed" because the event was about something else.
        identity = (rt_view.get("event") or {}).get("identity_status") or "complete"
        rows.append((c.get("confidence", "?"), c.get("freshness", "unknown"),
                     c.get("tactic", ""), c.get("resource", ""),
                     c.get("namespace", ""), rt_view.get("rule_id", ""),
                     detector, supporting, identity))
    return rows


def _runtime_summary(result: ScanResult) -> Optional[dict]:
    """Headline runtime numbers, or None when there was no feed."""
    rt = getattr(result, "runtime", None) or {}
    if not rt:
        return None
    corr = rt.get("correlation") or {}
    dc = rt.get("detection_coverage") or {}
    return {"source": rt.get("source", "runtime"),
            "cluster": rt.get("cluster", ""),
            "events": rt.get("events_seen", 0),
            # Detection accounting: how the provider's events were dispositioned.
            "kmw_rules": dc.get("kmw_rules"),
            "kmw_matches": dc.get("kmw_matches"),
            "falco_relays": dc.get("falco_relays"),
            "unusable": dc.get("unusable_events"),
            "discarded": dc.get("discarded"),
            "identity": rt.get("identity_coverage") or {},
            "alerts": corr.get("total_alerts", 0),
            "confirmed": corr.get("confirmed_exploitation", 0),
            "correlated": corr.get("correlated", 0),
            "runtime_only": corr.get("runtime_only", 0),
            "collected_at": rt.get("collected_at", "")}


def _runtime_lines(result: ScanResult) -> list[str]:
    """Runtime correlation for the text/terminal reports.

    Until this existed the runtime feed was collected, correlated and stored, and then
    appeared in no rendered report at all: an operator whose Falco feed said three findings
    were being actively exploited read a report that never mentioned it. `confirmed` is the
    strongest statement this tool makes, so it belongs in the format people actually read.
    """
    s = _runtime_summary(result)
    if not s:
        return []
    lines = [f"Runtime feed ({s['source']}): {s['events']} event(s), {s['alerts']} alert(s), "
             f"{s['confirmed']} confirmed as active exploitation."]
    if s.get("kmw_matches") is not None:
        lines.append(
            f"Detection: {s['kmw_matches']} by curated rule, {s['falco_relays']} relayed "
            f"from Falco, {s['unusable']} unusable, {s['discarded']} discarded.")
    ident = s.get("identity") or {}
    if ident:
        lines.append(
            f"Identity: {ident.get('complete', 0)} complete "
            f"({ident.get('recovered_from_container_id', 0)} recovered from container id), "
            f"{ident.get('partial', 0)} partial, {ident.get('ambiguous', 0)} ambiguous, "
            f"{ident.get('unknown', 0)} unknown.")
    for conf, fresh, tactic, resource, ns, rule, detector, supporting, identity in             _runtime_rows(result)[:10]:
        age = "" if fresh == "recent" else f" [{fresh}]"
        extra = f"  (+ {supporting})" if supporting else ""
        ident = "" if identity == "complete" else f"  identity:{identity}"
        lines.append(f"  {conf.upper():<13}{age} {tactic} on {resource or '(unplaceable)'} "
                     f"({ns or '-'}) via {rule} [{detector}]{ident}{extra}")
    if s["confirmed"]:
        lines.append("CONFIRMED means a live event named the same resource as a static "
                     "finding, not merely the same namespace.")
    lines.append("─" * 60)
    return lines


def _runtime_md(result: ScanResult) -> list[str]:
    """Markdown rendering of the same runtime block."""
    s = _runtime_summary(result)
    if not s:
        return []
    md = ["### 📡 Runtime correlation (live feed)", "",
          "| Metric | Value |", "|---|---|",
          f"| Source | {s['source']} |",
          f"| Cluster | {s['cluster'] or 'unlabelled'} |",
          f"| Events ingested | {s['events']} |",
          f"| Alerts raised | {s['alerts']} |",
          f"| Confirmed exploitation | {s['confirmed']} |",
          f"| Detected by curated rules | {s.get('kmw_matches')} |",
          f"| Relayed from Falco | {s.get('falco_relays')} |",
          f"| Unusable (reason recorded) | {s.get('unusable')} |",
          f"| Silently discarded | {s.get('discarded')} |",
          f"| Identity complete | {(s.get('identity') or {}).get('complete')} |",
          f"| Identity partial | {(s.get('identity') or {}).get('partial')} |",
          f"| Identity ambiguous | {(s.get('identity') or {}).get('ambiguous')} |",
          f"| Identity unknown | {(s.get('identity') or {}).get('unknown')} |",
          f"| Corroborated | {s['correlated']} |",
          f"| Runtime-only | {s['runtime_only']} |", ""]
    rows = _runtime_rows(result)
    if rows:
        md += ["| Confidence | Freshness | Identity | Tactic | Resource | Namespace | "
               "Detection | Detected by | Supporting |",
               "|---|---|---|---|---|---|---|---|---|"]
        md += [f"| {c} | {f} | {ident} | {t} | `{r or '(unplaceable)'}` | {ns or '—'} | "
               f"`{rule}` | {det} | {('`' + sup + '`') if sup else '—'} |"
               for c, f, t, r, ns, rule, det, sup, ident in rows[:25]]
        md += ["", "> `confirmed` means a live event named the same resource as a static "
               "finding. `corroborated` means the behaviour matches the same tactic in the "
               "same namespace, which is weaker. A `historical` freshness means the "
               "behaviour WAS seen, not that it is happening now.", ""]
    return md


def _runtime_html(result: ScanResult) -> str:
    """HTML rendering of the same runtime block, for the format a stakeholder opens."""
    s = _runtime_summary(result)
    if not s:
        return ""
    rows = _runtime_rows(result)
    body = "".join(
        f"<tr><td><span class='pill {('crit' if c == 'confirmed' else 'warn')}'>{_esc(c)}"
        f"</span></td><td>{_esc(f)}</td><td>{_esc(t)}</td><td><code>{_esc(r)}</code></td>"
        f"<td>{_esc(ns)}</td><td><code>{_esc(rule)}</code></td><td>{_esc(det)}</td>"
        f"<td>{_esc(ident)}</td>"
        f"<td>{('<code>' + _esc(sup) + '</code>') if sup else '&mdash;'}</td></tr>"
        for c, f, t, r, ns, rule, det, sup, ident in rows[:25])
    return (
        "<section class='card'><h2>📡 Runtime correlation (live feed)</h2>"
        f"<p>{s['events']} event(s) from <code>{_esc(s['source'])}</code> on cluster "
        f"<code>{_esc(s['cluster'] or 'unlabelled')}</code>: <strong>{s['confirmed']}"
        "</strong> confirmed as active exploitation, "
        f"{s['correlated']} corroborated, {s['runtime_only']} runtime-only.</p>"
        + (f"<p class='muted'>Detection: {s.get('kmw_matches')} by K8sMatrixWarden curated "
           f"rule, {s.get('falco_relays')} relayed from Falco, {s.get('unusable')} unusable "
           f"(reason recorded), <strong>{s.get('discarded')}</strong> silently discarded.</p>"
           if s.get("kmw_matches") is not None else "")
        + (f"<table><thead><tr><th>Confidence</th><th>Freshness</th><th>Tactic</th>"
           f"<th>Resource</th><th>Namespace</th><th>Detection</th><th>Detected by</th>"
           f"<th>Identity</th><th>Supporting</th></tr></thead>"
           f"<tbody>{body}</tbody></table>" if rows else "")
        + "<p class='muted'><em>confirmed</em> means a live event named the same resource "
          "as a static finding; <em>corroborated</em> is the same tactic in the same "
          "namespace, which is weaker. <em>historical</em> freshness means the behaviour "
          "was seen, not that it is happening now.</p></section>")


def _coverage_html(result: ScanResult) -> str:
    """Evidence coverage and assessment confidence for the HTML report.

    The markdown and text reports have carried this since coverage existed; the HTML one
    did not, which meant the format a stakeholder actually opens was the one that could
    not say how much of the cluster was read. Coverage is security meaning, not
    formatting, so every format states it.
    """
    cov = result.coverage
    if not cov:
        return ""
    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{d['coverage_pct']}%</td>"
        f"<td>{_esc(d.get('coverage_basis', 'measured'))}</td></tr>"
        for name, d in cov.get("domains", {}).items())
    unread = cov.get("unread_kinds") or []
    note = (f"<p class='muted'>Not read: <code>{_esc(', '.join(unread))}</code>. Findings "
            f"are reported in full regardless; the unread parts are unassessed, not "
            f"clean.</p>" if unread else "")
    return (f"<section class='matrix'><h2>Evidence coverage &amp; assessment confidence</h2>"
            f"<p>Evidence coverage <strong>{cov['coverage_pct']}%</strong> "
            f"(basis: {_esc(cov.get('coverage_basis', 'measured'))}) &middot; "
            f"assessment confidence <strong>{cov['confidence_pct']}%</strong> "
            f"({_esc(cov['confidence_label'])})</p>"
            f"<table class='ctx-table'>"
            f"<tr><th>Domain</th><th>Coverage</th><th>Basis</th></tr>{rows}</table>"
            f"{note}</section>")


def _coverage_md(result: ScanResult) -> list[str]:
    """Markdown rendering of the same coverage block."""
    cov = result.coverage
    if not cov:
        return []
    md = ["### 🔍 Evidence coverage & assessment confidence", "",
          f"| Metric | Value |", "|---|---|",
          f"| Evidence coverage | {cov['coverage_pct']}% |",
          # How the number was arrived at travels with it: a `heuristic` total must never
          # be read as a count.
          f"| Coverage basis | {cov.get('coverage_basis', 'measured')} |",
          f"| Assessment confidence | {cov['confidence_pct']}% "
          f"({cov['confidence_label']}) |", ""]
    domains = cov.get("domains", {})
    if domains:
        md += ["| Domain | Coverage | Basis |", "|---|---|---|"]
        md += [f"| {name} | {d['coverage_pct']}% | {d.get('coverage_basis', 'measured')} |"
               for name, d in domains.items()]
        md.append("")
    if cov.get("unread_kinds"):
        md += [f"> Not read: `{'`, `'.join(cov['unread_kinds'])}`. Findings are reported "
               f"in full regardless; the unread parts are simply unassessed, not clean.",
               ""]
    return md


def _display_findings(findings: list[Finding]) -> list[Finding]:
    from .scoring import RiskScoringEngine
    ranked = RiskScoringEngine.rank(findings)
    real = [f for f in ranked if f.severity.weight > 0]
    return real if real else []


def _vector_label(f: Finding) -> str:
    """Short attack-vector label from the reachability pass; '' if the finding wasn't
    analysed (non-pod resource). See core/reachability.py."""
    if "ingress" in f.exploitable_by:
        return "🔴 Internet-reachable"
    if "pod-privilege" in f.exploitable_by:
        return "🟡 Post-breach only"
    return ""


def _exposure_html(f: Finding) -> str:
    """The same reachability / NetworkPolicy / RBAC structure as `_exposure_section`, for
    the HTML report. Both read the fields the scanner already computed, so the two
    renderings cannot disagree about what was found."""
    blocks = []
    if f.exploit_path:
        hops = " &rarr; ".join(f"<code>{_esc(str(n.get('kind')))}/"
                               f"{_esc(str(n.get('name')))}</code>"
                               for n in f.exploit_path if n.get("name"))
        rows = "".join(f"<tr><td><code>{_esc(str(n.get('kind')))}/"
                       f"{_esc(str(n.get('name')))}</code></td>"
                       f"<td>{_esc(str(n.get('detail', '')))}</td></tr>"
                       for n in f.exploit_path if n.get("detail"))
        blocks.append(f"<details><summary>Reachability chain</summary>"
                      f"<div class='cmsg'>{hops}</div>"
                      f"<table class='ctx-table'>{rows}</table></details>")

    net = f.network_context or {}
    if net:
        ing, egr = net.get("ingress", {}), net.get("egress", {})
        rows = "".join(
            f"<tr><td>{d}</td><td><code>{_esc(str(b.get('status', 'unknown')))}</code></td>"
            f"<td>{_esc(str(b.get('reason', '')))}</td></tr>"
            for d, b in (("Ingress", ing), ("Egress", egr)))
        peers = "".join(
            f"<tr><td colspan='3'>{_esc(str(p.get('description', '')))} "
            f"<span class='muted'>(policy {_esc(str(p.get('policy', '?')))})</span></td></tr>"
            for p in (ing.get("peers", []) + egr.get("peers", []))[:10]
            if p.get("description"))
        blocks.append(f"<details><summary>NetworkPolicy</summary>"
                      f"<table class='ctx-table'>{rows}{peers}</table></details>")

    if f.rbac_paths:
        shortest = min(f.rbac_paths, key=lambda p: p.get("hops", 99))
        hops = " &rarr; ".join(f"<code>{_esc(str(n.get('kind')))}/"
                               f"{_esc(str(n.get('name')))}</code>"
                               for n in shortest.get("nodes", []))
        rows = "".join(
            f"<tr><td><code>{_esc(str((e.get('from') or {}).get('name')))}</code></td>"
            f"<td>{_esc(str(e.get('relationship')))}</td>"
            f"<td><code>{_esc(str((e.get('to') or {}).get('name')))}</code></td>"
            f"<td>{_esc(str(e.get('reason', '')))}</td></tr>"
            for e in shortest.get("edges", []))
        blocks.append(f"<details><summary>RBAC escalation path "
                      f"({len(f.rbac_paths)} found)</summary>"
                      f"<div class='cmsg'>{hops}</div>"
                      f"<table class='ctx-table'>{rows}</table></details>")
    return "".join(blocks)


def _exposure_section(f: Finding) -> list[str]:
    """The structural evidence behind the attack-vector line: the hop chain, the evaluated
    NetworkPolicy posture, and the RBAC escalation path.

    The scanner computes all three per workload finding (core/reachability.py,
    core/netpol.py, core/rbac_graph.py). Rendering only the prose summary threw the
    structure away at the last step, so a report could say "this ServiceAccount can reach
    cluster-admin" without ever naming the binding that grants it.
    """
    out: list[str] = []
    if f.exploit_path:
        chain = "  →  ".join(f"`{n.get('kind')}/{n.get('name')}`"
                             for n in f.exploit_path if n.get("name"))
        out += ["##### 🧭 Reachability Chain", "", chain, ""]
        detail = [n for n in f.exploit_path if n.get("detail")]
        if detail:
            out += ["| Hop | Why it reaches the next |", "|:--|:--|"]
            out += [f"| `{n.get('kind')}/{n.get('name')}` | {n['detail']} |"
                    for n in detail]
            out.append("")

    net = f.network_context or {}
    if net:
        ing, egr = net.get("ingress", {}), net.get("egress", {})
        out += ["##### 🌐 NetworkPolicy", "",
                "| Direction | Status | Detail |", "|:--|:--|:--|",
                f"| Ingress | `{ing.get('status', 'unknown')}` | {ing.get('reason', '')} |",
                f"| Egress | `{egr.get('status', 'unknown')}` | {egr.get('reason', '')} |",
                ""]
        peers = [p for p in (ing.get("peers", []) + egr.get("peers", []))
                 if p.get("description")]
        if peers:
            out += ["Allowed peers:", ""]
            out += [f"- {p['description']}"
                    + (f" on {', '.join(str(x.get('port')) for x in p['ports'])}"
                       if p.get("ports") else "")
                    + f"  _(policy `{p.get('policy', '?')}`)_"
                    for p in peers[:10]]
            out.append("")

    if f.rbac_paths:
        shortest = min(f.rbac_paths, key=lambda p: p.get("hops", 99))
        out += ["##### 🔑 RBAC Escalation Path", "",
                "  →  ".join(f"`{n.get('kind')}/{n.get('name')}`"
                             for n in shortest.get("nodes", [])),
                "",
                "| From | Relationship | To | Because |", "|:--|:--|:--|:--|"]
        for e in shortest.get("edges", []):
            frm, to = e.get("from", {}), e.get("to", {})
            out.append(f"| `{frm.get('kind')}/{frm.get('name')}` | {e.get('relationship')} "
                       f"| `{to.get('kind')}/{to.get('name')}` | {e.get('reason', '')} |")
        out.append("")
        if len(f.rbac_paths) > 1:
            out += [f"_{len(f.rbac_paths)} escalation path(s) found; the shortest is shown. "
                    f"Capabilities: "
                    f"{', '.join(sorted({p.get('capability', '') for p in f.rbac_paths}))}._",
                    ""]
    return out


def _finding_card(f: Finding, i: int) -> list[str]:
    """A full, report-grade finding write-up, the seven sections a professional scan
    report is expected to carry: Summary, Standards & Benchmark Mapping, MITRE ATT&CK
    Mapping, Impact, Validation (how to reproduce), and Evidence. All content beyond the
    raw Finding fields comes from build_finding_context(), the single place this and every
    other renderer (html/json/sarif/pdf) source it from."""
    from .finding_context import build_finding_context
    ctx = build_finding_context(f)
    amp = " ⚡ Attack-Path Amplified" if len(f.tactics) > 1 else ""

    rows = [
        f"| **Rule ID** | `{f.rule_id}` |",
        f"| **Domain** | `{f.owning_shard}` |",
        f"| **Exploitability** | {f.exploitability.label} |",
        f"| **Blast radius** | {f.blast_radius.label} |",
        f"| **Risk score** | {round(f.score, 2)} |",
    ]
    if _vector_label(f):
        rows.append(f"| **Attack vector** | {_vector_label(f)} — {f.path_reason} |")

    out = [
        f"#### {i}. {f.severity.emoji} {f.title}{amp}",
        "",
        f"`{f.resource}`",
        "",
        "##### Summary",
        "",
        ctx.summary,
        "",
        f"> **Detected:** {f.message}",
        "",
        "| | |",
        "|:--|:--|",
        *rows,
        "",
    ]
    out += _exposure_section(f)

    # ---- standards & benchmark mapping ------------------------------- #
    out += ["##### 📚 Standards & Benchmark Mapping", ""]
    if ctx.standards:
        out += ["| Framework | Control | Reference |", "|:--|:--|:--|"]
        for s in ctx.standards:
            out.append(f"| {s.framework} | [{s.control}]({s.url}), {s.title} | "
                       f"[Reference]({s.url}) |")
        out.append("")
    else:
        out += ["_No named standard or benchmark control maps to this finding._", ""]

    # ---- MITRE ATT&CK mapping ------------------------------------------ #
    out += ["##### 🎯 MITRE ATT&CK Mapping", ""]
    if ctx.mitre:
        out += ["| Tactic | Technique | Reference |", "|:--|:--|:--|"]
        for m in ctx.mitre:
            out.append(f"| {m.tactic} | {m.technique_name} ([`{m.technique_id}`]({m.url})) | "
                       f"[Reference]({m.url}) |")
        out.append("")
    else:
        out += ["_Not mapped to a MITRE ATT&CK for Containers technique._", ""]

    # ---- impact --------------------------------------------------------- #
    out += ["##### 💥 Impact", "", ctx.impact, ""]

    # ---- validation / reproduction --------------------------------------- #
    out += ["##### ✅ Validation, How to Reproduce / Verify", "",
            "Run this to confirm the finding, and again after any change to confirm it "
            "cleared:", "", "```bash"]
    out += ctx.validation_steps
    out += ["```", ""]

    if f.evidence:
        out += ["<details><summary>🔎 Evidence</summary>", "", "```json",
                json.dumps(f.evidence, indent=2, default=str), "```", "</details>", ""]
    out.append("---")
    out.append("")
    return out


# -- OWASP names (lazy cached) ------------------------------------------ #
# The OWASP category names and their direct per-ID owasp.org links live in
# finding_context (one loader, one taxonomy file), re-exported here because the pdf
# renderer and the markdown summary both import them from this module.
from .finding_context import _owasp_names, owasp_url  # noqa: E402


def _owasp_label(code: Optional[str]) -> str:
    if not code:
        return "N/A"
    name = _owasp_names().get(code)
    return f"`{code}` {name}" if name else f"`{code}`"


def _by_owasp(findings: list[Finding]) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        if f.severity.weight and f.owasp:
            out[f.owasp] = out.get(f.owasp, 0) + 1
    return out


# -- MITRE ---------------------------------------------------------------- #
def _mitre_short(f: Finding) -> str:
    return f.mitre[0].technique_id if f.mitre else ""


def _mitre_long(f: Finding) -> str:
    return " · ".join(f"{m.tactic.value} → {m.technique_name} (`{m.technique_id}`)"
                      for m in f.mitre)


# -- bars / gauges / math ------------------------------------------------- #
def _frac(n: int, total: int) -> float:
    return (n / total) if total else 0.0


def _bar(frac: float, width: int) -> str:
    frac = max(0.0, min(1.0, frac))
    filled = round(frac * width)
    return "█" * filled + "░" * (width - filled)


def _attack_path_md(tm) -> str:
    """Markdown for the kill-chain exploit path derived from the matrix's hit cells."""
    from .threat_matrix import attack_paths
    a = attack_paths(tm)
    if not a["steps"]:
        return ""
    reach = ("⚠️ reaches **Impact** (full kill-chain)" if a["reaches_impact"]
             else "stops before Impact")
    lines = ["### 🎯 Kill-chain exploit path", "",
             f"**{a['tactic_count']} tactics chained** · {reach}", "",
             "`" + a["chain"].replace(" -> ", "` → `") + "`", ""]
    for i, s in enumerate(a["steps"], 1):
        techs = ", ".join(t["technique_name"] for t in s["techniques"][:4])
        lines.append(f"{i}. **{s['tactic']}** ({s['worst_severity']}), {techs}")
    return "\n".join(lines + [""])


def _risk_gauge(risk: float) -> str:
    return f"[{_bar(risk / 10.0, 30)}] {risk}/10"


def _pct(n: int, total: int) -> str:
    return f"{round(100 * n / total)}%" if total else "0%"


def _pct_num(n: int, total: int) -> float:
    return round(100 * n / total, 1) if total else 0.0


def _verdict(rating: str) -> str:
    return {
        "Excellent": "This cluster is in excellent shape. Maintain current controls and "
                     "watch for configuration drift.",
        "Good": "Good posture overall. Clear the remaining medium-severity findings to "
                "tighten it further.",
        "Fair": "Fair posture. Several high-severity issues need prioritized attention "
                "before they are chained together.",
        "Poor": "Poor posture. Critical, likely-exploitable issues are present and should "
                "be addressed promptly.",
        "Critical": "Critical risk. The cluster has severe, likely-exploitable exposures "
                    "requiring immediate action.",
        "Unknown": UNSCANNED_VERDICT,
    }.get(rating, "")


#: Shown wherever a rating would be, when the collector could not read the cluster.
UNSCANNED_VERDICT = (
    "Posture is UNKNOWN, the scan could not read this cluster, so it inspected nothing. "
    "The zero findings below mean 'nothing was looked at', not 'nothing is wrong'. "
    "Fix the access problem listed under Scan warnings and re-run.")


def warning_banner_html(result: ScanResult) -> str:
    """The scan-incomplete / partial-coverage banner. Shared by the HTML report and the
    web dashboard's per-scan pages so both tell the same story."""
    warns = scan_warning_lines(result)
    if not warns:
        return ""
    cls = "danger" if not result.evidence_ok else "warn"
    head = ("🛑 Scan incomplete, this cluster was not read"
            if not result.evidence_ok else "⚠️ Partial coverage")
    items = "".join(f"<li>{_esc(w)}</li>" for w in warns)
    return (f"<div class='callout {cls}'><strong>{head}</strong>"
            f"<ul class='warnlist'>{items}</ul></div>")


def _warning_md(result: ScanResult) -> list[str]:
    warns = scan_warning_lines(result)
    if not warns:
        return []
    head = ("🛑 **Scan incomplete**" if not result.evidence_ok
            else "⚠️ **Partial coverage**")
    return ["", f"> {head}", *[f"> - {w}" for w in warns]]


def scan_warning_lines(result: ScanResult) -> list[str]:
    """Human lines describing why a scan's coverage is partial or absent, or [] when the
    scan read the cluster cleanly. Single source for every renderer and the dashboard."""
    out: list[str] = []
    if not result.evidence_ok:
        out.append("This scan could not read the cluster, no resource type could be "
                   "collected. Results are NOT evidence of a secure cluster.")
    elif result.warnings:
        out.append("This scan ran with partial coverage, some resource types could not "
                   "be read, so findings on them are missing.")
    out += list(result.warnings)
    return out


def _status_badges(result: ScanResult) -> str:
    r = result.risk
    return (f"**Scan** `{result.scan_id}` · **Generated** {result.generated_at} · "
            f"**Mode** `{result.mode}`\n\n"
            f"{r.rating_emoji} **Risk {r.cluster_risk}/10 ({r.rating})** · "
            f"**Security {r.security_score}/100** · "
            f"**{result.total()} findings** · "
            f"**{len(result.resolved_rule_ids)} rules** · "
            f"**scope** `{result.request.scope.describe()}`")


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _wrap_ids(ids: list[str], per_line: int = 4) -> list[str]:
    lines = []
    for i in range(0, len(ids), per_line):
        lines.append(", ".join(ids[i:i + per_line]))
    return lines


# -- SARIF helpers -------------------------------------------------------- #
def _sarif_help_md(ctx) -> str:
    """GitHub Code Scanning (and most other SARIF viewers) render `help.markdown` in
    preference to `help.text` when both are present, give it the same substance as the
    markdown/html reports rather than the one-line `help.text` fallback."""
    lines = [f"**Impact:** {ctx.impact}", ""]
    if ctx.standards:
        lines.append("**Standards & Benchmark Mapping:**")
        lines += [f"- {s.framework}, {s.control}: [{s.title}]({s.url})" for s in ctx.standards]
        lines.append("")
    if ctx.validation_steps:
        lines += ["**Validation:**", "```bash", *ctx.validation_steps, "```"]
    return "\n".join(lines)



def _sarif_level(sev: Severity) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "INFO": "note"}[sev.label]


def _security_severity(sev: Severity) -> str:
    # GitHub uses a 0-10 CVSS-like scale to sort/threshold.
    return {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0",
            "LOW": "2.5", "INFO": "0.0"}[sev.label]


def _sarif_tags(f: Finding) -> list[str]:
    tags = ["security", "kubernetes", f.owning_shard]
    if f.owasp:
        tags.append(f"owasp/{f.owasp}")
    for m in f.mitre:
        tags.append(f"mitre/{m.technique_id}")
    for cc in f.cis:
        tags.append(f"cis/{cc}")
    return tags


def _fqn(f: Finding) -> str:
    ns = f.resource.namespace or "-"
    return f"{ns}/{f.resource.kind}/{f.resource.name}"


def _rich_sev(sev: Severity) -> str:
    return {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow",
            "LOW": "green", "INFO": "grey50"}[sev.label]


def _rich_border(rating: str) -> str:
    return {"Excellent": "green", "Good": "green", "Fair": "yellow",
            "Poor": "dark_orange", "Critical": "red"}.get(rating, "white")


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# -- HTML template -------------------------------------------------------- #
_HTML_CSS = """
/* Design tokens. --bg = page canvas (soft neutral), --card = raised surface (white),
   --sunken = inset fill (code chips, tracks, inputs). Light is the default; the dark
   palette applies via the OS preference OR the in-page toggle (data-theme, listed after
   the media query so a click always wins). */
:root{--bg:#f5f6f8;--fg:#0f172a;--muted:#5b6675;--card:#ffffff;--bd:#e5e8ec;--sunken:#f1f3f6;
 --crit:#d92d20;--high:#e04f16;--med:#c07600;--low:#12894a;--info:#6b7482;--accent:#0e7490;
 --ring:rgba(14,116,144,.3);--shadow:0 1px 2px rgba(16,24,40,.04),0 1px 3px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0a0e16;--fg:#e7ecf3;--muted:#94a1b5;
 --card:#131a25;--bd:#232c3b;--sunken:#1b2230;--crit:#ff6a5e;--high:#ff9a4d;--med:#e2b53f;
 --low:#43cf7f;--info:#8b97a9;--accent:#22d3ee;--ring:rgba(34,211,238,.32);
 --shadow:0 1px 2px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.4)}}
:root[data-theme=light]{--bg:#f5f6f8;--fg:#0f172a;--muted:#5b6675;--card:#ffffff;--bd:#e5e8ec;
 --sunken:#f1f3f6;--crit:#d92d20;--high:#e04f16;--med:#c07600;--low:#12894a;--info:#6b7482;
 --accent:#0e7490;--ring:rgba(14,116,144,.3);--shadow:0 1px 2px rgba(16,24,40,.04),0 1px 3px rgba(16,24,40,.06)}
:root[data-theme=dark]{--bg:#0a0e16;--fg:#e7ecf3;--muted:#94a1b5;--card:#131a25;--bd:#232c3b;
 --sunken:#1b2230;--crit:#ff6a5e;--high:#ff9a4d;--med:#e2b53f;--low:#43cf7f;--info:#8b97a9;
 --accent:#22d3ee;--ring:rgba(34,211,238,.32);--shadow:0 1px 2px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.4)}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
 background:var(--bg);color:var(--fg);line-height:1.55;-webkit-font-smoothing:antialiased;
 text-rendering:optimizeLegibility;font-feature-settings:'cv02','cv03','cv04','tnum'}
/* Use the viewport instead of a narrow column: the matrix grid, findings tables and
   attack map are all wide, dense surfaces that were being squeezed by a 1000px cap. */
.wrap{max-width:1720px;margin:0 auto;padding:1.5rem 2rem}
@media(max-width:820px){.wrap{padding:1rem .9rem}}
.themebtn{background:var(--card);color:var(--fg);border:1.5px solid var(--bd);
 border-radius:20px;padding:.4rem .85rem;font:inherit;font-size:.82rem;font-weight:600;
 cursor:pointer;line-height:1.2}
.themebtn:hover{border-color:var(--accent);color:var(--accent)}
.themebar{display:flex;justify-content:flex-end;margin-bottom:-1.6rem}
h1{font-size:1.6rem;margin:.2rem 0}.sub{color:var(--muted);font-size:.9rem}
.hero{border:1px solid var(--bd);border-radius:14px;padding:1.25rem;background:var(--card);
 margin:1rem 0}
.gauge{height:12px;border-radius:8px;background:linear-gradient(90deg,#1a7f37,#9a6700,#bc4c00,#cf222e);
 position:relative;margin:.75rem 0}
.gauge .pin{position:absolute;top:-4px;width:4px;height:20px;background:var(--fg);border-radius:2px}
.score{font-size:2rem;font-weight:700}.score.critical,.score.poor{color:var(--crit)}
.score.fair{color:var(--med)}.score.good,.score.excellent{color:var(--low)}
.score.unknown{color:var(--muted)}
.sev{display:inline-block;padding:.15rem .55rem;margin:.15rem .3rem .15rem 0;border-radius:20px;
 font-size:.85rem;border:1px solid var(--bd);background:var(--bg)}
.filters{margin:1rem 0}.filters button{background:var(--card);color:var(--fg);border:1px solid var(--bd);
 border-radius:20px;padding:.35rem .8rem;margin-right:.4rem;cursor:pointer;font-size:.85rem}
.filters button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.card{border:1px solid var(--bd);border-left-width:5px;border-radius:10px;padding:.9rem 1rem;
 margin:.75rem 0;background:var(--card)}
.card.critical{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}
.card.flash{box-shadow:0 0 0 2px var(--accent);animation:cardflash 2s ease-out 1}
@keyframes cardflash{0%{box-shadow:0 0 0 4px var(--accent)}100%{box-shadow:0 0 0 2px var(--accent)}}
.chead{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}
.badge{font-size:.72rem;font-weight:700;padding:.1rem .5rem;border-radius:6px;color:#fff}
.badge.critical{background:var(--crit)}.badge.high{background:var(--high)}
.badge.medium{background:var(--med)}.badge.low{background:var(--low)}
.ctitle{font-weight:600}.res{background:var(--bg);border:1px solid var(--bd);border-radius:6px;
 padding:.05rem .4rem;font-size:.82rem;color:var(--muted)}
.csummary{margin:.5rem 0;color:var(--fg);font-size:.95rem}
.cmsg{margin:.5rem 0;color:var(--muted);font-size:.85rem}
.cimpact{margin:.6rem 0;padding:.55rem .7rem;background:var(--bg);border:1px solid var(--bd);
 border-left:3px solid var(--high);border-radius:0 8px 8px 0;font-size:.85rem}
.tags{margin:.4rem 0}.tag{display:inline-block;font-size:.72rem;padding:.1rem .45rem;margin:.12rem .3rem .12rem 0;
 border:1px solid var(--bd);border-radius:20px;color:var(--muted);background:var(--bg)}
.tag.mitre{border-color:var(--accent);color:var(--accent)}
.tag.owasp{border-color:var(--high);color:var(--high)}
.tag.std{border-color:var(--low);color:var(--low)}
.tag.amp{border-color:var(--crit);color:var(--crit);font-weight:600}
a.tag{text-decoration:none;cursor:pointer}a.tag:hover{filter:brightness(1.15);text-decoration:underline}
table.ctx-table code{background:var(--bg);border:1px solid var(--bd);border-radius:4px;padding:0 .3rem}
details{margin-top:.5rem}summary{cursor:pointer;font-size:.85rem;color:var(--accent)}
pre.cmd{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:.7rem;
 overflow:auto;font-size:.82rem;white-space:pre-wrap}
table.ctx-table{width:100%;border-collapse:collapse;margin-top:.4rem;font-size:.82rem}
table.ctx-table td{padding:.35rem .5rem;border-bottom:1px solid var(--bd);vertical-align:top}
table.ctx-table tr:last-child td{border-bottom:none}
table.ctx-table a{color:var(--accent)}
.muted{color:var(--muted);font-size:.85rem}
.callout{margin:.6rem 0;padding:.6rem .75rem;border-radius:0 8px 8px 0;font-size:.85rem}
.callout.warn{background:var(--bg);border:1px solid var(--bd);border-left:3px solid var(--high)}
.callout.danger{background:var(--bg);border:1px solid var(--crit);border-left:5px solid var(--crit)}
.callout.danger strong{color:var(--crit)}
.refs{margin-top:.5rem;font-size:.78rem;color:var(--muted)}
.refs a{color:var(--accent)}
ul.warnlist{margin:.4rem 0 0;padding-left:1.1rem;font-size:.82rem;color:var(--muted)}
.ok{color:var(--low);font-size:1.1rem}
section.matrix{margin:1.5rem 0}section.matrix>h2,body>h2{font-size:1.2rem;margin:1.5rem 0 .5rem}
footer{color:var(--muted);font-size:.8rem;margin-top:2rem;border-top:1px solid var(--bd);padding-top:1rem}
""" + THREAT_MATRIX_CSS

_HTML_JS = """
document.querySelectorAll('.filters button').forEach(function(b){
 b.onclick=function(){
  document.querySelectorAll('.filters button').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on');var f=b.dataset.f;
  document.querySelectorAll('.card').forEach(function(c){
   c.style.display=(f==='all'||c.classList.contains(f))?'':'none';});};});
function focusHash(){
 if(!location.hash) return;
 var el=null; try{el=document.querySelector(location.hash);}catch(e){}
 if(!el) return;
 el.style.display='';                 // ensure a filtered-out card is shown when targeted
 document.querySelectorAll('.card.flash').forEach(function(c){c.classList.remove('flash');});
 el.classList.add('flash');
 el.scrollIntoView({behavior:'smooth',block:'center'});
}
window.addEventListener('load',focusHash);
window.addEventListener('hashchange',focusHash);
"""

# Light/dark toggle. Every colour in every surface already comes from a CSS variable, so
# flipping `data-theme` on <html> re-themes the whole page, no per-element work. The
# choice is remembered in localStorage; with nothing stored the OS preference still wins.
THEME_BUTTON = ("<button class='themebtn' type='button' onclick='toggleTheme()' "
                "title='Switch between light and dark'>◐ Theme</button>")

THEME_JS = """
(function(){
 var root=document.documentElement, KEY='k8smw-theme';
 function osDark(){return window.matchMedia
   && window.matchMedia('(prefers-color-scheme:dark)').matches;}
 function label(){
  var d=root.getAttribute('data-theme')||(osDark()?'dark':'light');
  document.querySelectorAll('.themebtn').forEach(function(b){
   b.textContent=(d==='dark'?'☀ Light':'☾ Dark');});
 }
 // Light is the product default: with nothing stored, pin light explicitly so it wins
 // over a dark OS preference. A saved choice (either way) always takes precedence.
 try{var s=localStorage.getItem(KEY); root.setAttribute('data-theme',s||'light');}
 catch(e){root.setAttribute('data-theme','light');}
 window.toggleTheme=function(){
  var d=root.getAttribute('data-theme')||(osDark()?'dark':'light');
  d=(d==='dark')?'light':'dark';
  root.setAttribute('data-theme',d);
  try{localStorage.setItem(KEY,d);}catch(e){}
  label();
 };
 if(document.readyState==='loading')
   document.addEventListener('DOMContentLoaded',label); else label();
})();
"""

_HTML_TMPL = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>K8s Security Report · {scan}</title><style>{css}</style></head>
<body><div class="wrap">
<div class="themebar">{themebtn}</div>
<h1>K8s Security Report</h1>
<div class="sub">{cluster} · scan <code>{scan}</code> · {generated} · mode {mode}</div>
<div class="hero">
 <div class="score {rating_class}">{rating_emoji} {risk}/10 <span style="font-size:1rem">({rating})</span></div>
 <div class="gauge"><div class="pin" style="left:{gaugepct}%"></div></div>
 <div>Security score <strong>{sec}/100</strong> · <strong>{total}</strong> findings ·
  <strong>{tactics}/9</strong> MITRE tactics · <strong>{rules}</strong> rules ·
  scope <code>{scope}</code> · selector <code>{selector}</code></div>
 <p>{verdict}</p>
 <div>{chips}</div>
</div>
{warnings}
{coverage}
{matrix}
<h2>Findings</h2>
<div class="filters">{filters}</div>
{cards}
<footer>Generated by k8smatrixwarden, MITRE ATT&amp;CK-aligned Kubernetes security scanner.</footer>
</div><script>{js}</script></body></html>"""
