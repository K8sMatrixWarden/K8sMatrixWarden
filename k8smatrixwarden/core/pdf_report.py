"""
PDF Report (§18.2 extension), a professional, print/share-ready audit document.

Mirrors the markdown report's structure exactly (title page -> executive summary ->
coverage -> findings, each with Summary / Standards & Benchmark Mapping / MITRE ATT&CK
Mapping / Impact / Validation) so the two formats never disagree about what a finding
means, both read from the same `core.finding_context.build_finding_context()`.

Requires the optional `fpdf2` dependency (`pip install -e ".[pdf]"`), imported lazily so
the core engine stays dependency-free when PDF output isn't needed. Uses only the three
built-in PDF core fonts (Helvetica/Courier), no font embedding, no external resources.
"""
from __future__ import annotations

from typing import Optional

from .models import Finding, Severity
from .results import ScanResult

_SEV_DISPLAY = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

# RGB triples, same semantic palette as the HTML/markdown reports.
_INK = (31, 35, 40)
_MUTED = (87, 96, 106)
_LINE = (208, 215, 222)
_BG_ALT = (246, 248, 250)
_ACCENT = (9, 105, 218)
_SEV_RGB = {
    "CRITICAL": (207, 34, 46), "HIGH": (188, 76, 0),
    "MEDIUM": (154, 103, 0), "LOW": (26, 127, 55),
}
_SEV_BG = {
    "CRITICAL": (253, 236, 236), "HIGH": (255, 241, 230),
    "MEDIUM": (253, 246, 227), "LOW": (238, 241, 246),
}

# The 3 built-in PDF core fonts (Helvetica/Times/Courier) only support Latin-1, no
# em-dashes, arrows, curly quotes, or emoji, all of which the shared finding_context.py
# knowledge base uses freely (correctly, markdown/html/json/sarif are all full Unicode).
# Rather than degrade that shared content, or embed a Unicode TrueType font just to
# avoid it, sanitize text to a close ASCII equivalent at the point it enters the PDF.
_UNICODE_ASCII = {
    "N/A": "--", "–": "-", "‑": "-", "→": "->", "←": "<-",
    "‘": "'", "’": "'", "“": '"', "”": '"', "…": "...",
    "•": "-", "×": "x", " ": " ",
}


def _ascii(text) -> str:
    s = str(text)
    for uni, rep in _UNICODE_ASCII.items():
        s = s.replace(uni, rep)
    try:
        s.encode("latin-1")
    except UnicodeEncodeError:
        s = s.encode("latin-1", errors="replace").decode("latin-1")
    return s


def render_pdf(result: ScanResult) -> bytes:
    """The single entry point. Returns raw PDF bytes, callers must write them in
    binary mode (unlike every other report format, which is plain text)."""
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise RuntimeError(
            "PDF report generation requires the 'fpdf2' package. "
            "Install it (`pip install fpdf2`) or use a text-based format "
            "(markdown/html/json/sarif/text/terminal)."
        ) from exc

    from .finding_context import build_finding_context
    from .scoring import RiskScoringEngine

    findings = [f for f in RiskScoringEngine.rank(result.findings) if f.severity.weight > 0]

    pdf = _make_pdf(FPDF)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.alias_nb_pages()

    _title_page(pdf, result)
    _executive_summary(pdf, result, findings)
    _coverage(pdf, result, findings)
    _runtime_section(pdf, result)
    if findings:
        _findings_section(pdf, findings, build_finding_context)
    else:
        pdf.add_page()
        _h1(pdf, "Findings")
        _body(pdf, "No findings for this scan.")
    _appendix(pdf, result)

    out = pdf.output()
    return bytes(out)


# ======================================================================= #
# PDF class with branded header/footer, built lazily from the caller's FPDF class so
# this module never imports fpdf2 at module load time (it must stay importable, and the
# rest of the engine dependency-free, when the optional `pdf` extra isn't installed).
# ======================================================================= #
def _make_pdf(fpdf_cls):
    class _ReportPDF(fpdf_cls):
        # Belt-and-suspenders Unicode sanitization: every direct cell()/multi_cell()
        # call in this module is covered here; Table/Row cells are additionally
        # sanitized explicitly at each call site (§_coverage/_executive_summary) since
        # fpdf2's table renderer batches and draws cells internally rather than calling
        # back through these methods.
        def cell(self, w=None, h=None, text="", *args, **kwargs):
            return super().cell(w, h, _ascii(text), *args, **kwargs)

        def multi_cell(self, w, h=None, text="", *args, **kwargs):
            return super().multi_cell(w, h, _ascii(text), *args, **kwargs)

        def header(self):
            if self.page_no() == 1:
                return
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*_MUTED)
            self.cell(0, 8, "K8sMatrixWarden Security Report")
            self.ln(12)
            self.set_draw_color(*_LINE)
            self.line(10, 16, self.w - 10, 16)
            self.set_y(20)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*_MUTED)
            self.set_draw_color(*_LINE)
            self.line(10, self.get_y(), self.w - 10, self.get_y())
            self.ln(2)
            self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")

    return _ReportPDF()


# ======================================================================= #
# layout helpers
# ======================================================================= #
def _h1(pdf, text: str) -> None:
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 12, text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


def _h2(pdf, text: str) -> None:
    _ensure_space(pdf, 16)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*_LINE)
    pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
    pdf.ln(3)


def _h3(pdf, text: str, color=_INK) -> None:
    _ensure_space(pdf, 10)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*color)
    pdf.cell(0, 7, text, new_x="LMARGIN", new_y="NEXT")


def _body(pdf, text: str, size: int = 10, color=_INK) -> None:
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.5, text or "-", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _mono(pdf, text: str, fill=_BG_ALT, size: int = 8.5) -> None:
    pdf.set_font("Courier", "", size)
    pdf.set_text_color(*_INK)
    pdf.set_fill_color(*fill)
    pdf.multi_cell(0, 5, text, fill=True, border=0, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _link_line(pdf, label: str, url: str) -> None:
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 6, f"-> {label}", new_x="LMARGIN", new_y="NEXT", link=url)


def _ensure_space(pdf, needed_mm: float) -> None:
    """fpdf2's auto_page_break only fires once a cell/multi_cell call itself would
    overflow, it can still leave a lone heading orphaned at the very bottom of a page.
    Call this before starting a block that should stay together with what follows it."""
    if pdf.get_y() + needed_mm > pdf.page_break_trigger:
        pdf.add_page()


def _kv_table(pdf, rows: list[tuple]) -> None:
    pdf.set_font("Helvetica", "", 9.5)
    for k, v in rows:
        pdf.set_text_color(*_MUTED)
        pdf.cell(48, 6, k)
        pdf.set_text_color(*_INK)
        pdf.multi_cell(0, 6, str(v), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


# ======================================================================= #
# sections
# ======================================================================= #
def _title_page(pdf, result: ScanResult) -> None:
    pdf.add_page()
    r = result.risk
    pdf.ln(30)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 14, "Kubernetes Security Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 8, "K8sMatrixWarden -- MITRE ATT&CK-Aligned Security Assessment",
            align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(14)

    sev_rgb = _SEV_RGB.get(r.rating.upper(), _MUTED) if r.rating.upper() in _SEV_RGB \
        else {"Excellent": (26, 127, 55), "Good": (26, 127, 55), "Fair": (154, 103, 0),
             "Poor": (188, 76, 0), "Critical": (207, 34, 46)}.get(r.rating, _MUTED)
    box_w = 100
    x = (pdf.w - box_w) / 2
    pdf.set_xy(x, pdf.get_y())
    pdf.set_fill_color(*_SEV_BG.get(r.rating.upper(), (246, 248, 250)) if
                       r.rating.upper() in _SEV_BG else (246, 248, 250))
    pdf.set_draw_color(*sev_rgb)
    pdf.rect(x, pdf.get_y(), box_w, 34, style="DF")
    pdf.set_xy(x, pdf.get_y() + 4)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*sev_rgb)
    pdf.cell(box_w, 12, f"{r.cluster_risk} / 10", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(box_w, 8, r.rating.upper(), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_MUTED)
    pdf.cell(box_w, 6, f"Security score {r.security_score}/100", align="C",
            new_x="LMARGIN", new_y="NEXT")

    pdf.ln(16)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_MUTED)
    meta = [
        ("Cluster", result.cluster_name), ("Scan ID", result.scan_id),
        ("Generated", result.generated_at), ("Mode", result.mode),
        ("Scope", result.request.scope.describe()),
        ("Selector", result.request.selector.describe()),
        ("Rules evaluated", str(len(result.resolved_rule_ids))),
    ]
    tw = 130
    x = (pdf.w - tw) / 2
    for k, v in meta:
        pdf.set_x(x)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(*_INK)
        pdf.cell(38, 6, k)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*_MUTED)
        pdf.cell(0, 6, str(v), new_x="LMARGIN", new_y="NEXT")


def _scan_warnings(pdf, result: ScanResult) -> None:
    """Lead the executive summary with the reason coverage was partial or absent, so a
    shared PDF can never be read as a clean bill of health for a cluster that was never
    successfully read. Same text as every other renderer (reporting.scan_warning_lines)."""
    from .reporting import scan_warning_lines
    warns = scan_warning_lines(result)
    if not warns:
        return
    # The _PDF subclass already runs _ascii() over every cell/multi_cell payload.
    rgb = _SEV_RGB["CRITICAL"] if not result.evidence_ok else _SEV_RGB["HIGH"]
    pdf.set_text_color(*rgb)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "SCAN INCOMPLETE" if not result.evidence_ok else "PARTIAL COVERAGE",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for w in warns[:20]:
        pdf.multi_cell(0, 4.6, "- " + w, new_x="LMARGIN", new_y="NEXT")
    if len(warns) > 20:
        pdf.cell(0, 4.6, f"... and {len(warns) - 20} more",
                 new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*_INK)
    pdf.ln(2)


def _executive_summary(pdf, result: ScanResult, findings: list[Finding]) -> None:
    pdf.add_page()
    _h1(pdf, "1. Executive Summary")
    r = result.risk
    c = result.counts
    total = result.total()
    _scan_warnings(pdf, result)
    _body(pdf, f"Overall risk {r.cluster_risk}/10 ({r.rating}) -- security score "
              f"{r.security_score}/100, based on {total} actionable finding(s) across "
              f"{len(result.resolved_rule_ids)} rule(s) evaluated in "
              f"{len(result.by_shard)} domain(s).")
    pdf.ln(2)

    with pdf.table(col_widths=(38, 25, 25, 87), text_align=("LEFT", "RIGHT", "RIGHT", "LEFT"),
                  borders_layout="HORIZONTAL_LINES") as table:
        hdr = table.row()
        for h in ("Severity", "Count", "Share", ""):
            hdr.cell(h)
        for sev in _SEV_DISPLAY:
            n = c[sev.label]
            pct = round(100 * n / total) if total else 0
            row = table.row()
            row.cell(_ascii(sev.label))
            row.cell(str(n))
            row.cell(f"{pct}%")
            row.cell(_ascii_bar(pct, 40))
    pdf.ln(2)

    multi = [f for f in findings if len(f.tactics) > 1]
    _kv_table(pdf, [
        ("MITRE tactics implicated", f"{len(result.by_tactic)} / 9"),
        ("Attack-path amplified findings", str(len(multi))),
        ("Domains (shards) involved", str(len(result.by_shard))),
    ])


def _runtime_section(pdf, result: ScanResult) -> None:
    """Live runtime correlation, for the format that gets emailed to a stakeholder.

    Reuses the shared extraction in reporting.py so the PDF cannot state a different number
    of confirmed exploitations than the terminal did."""
    from .reporting import _runtime_rows, _runtime_summary
    summary = _runtime_summary(result)
    if not summary:
        return
    pdf.add_page()
    _h2(pdf, "Runtime correlation (live feed)")
    _body(pdf, _ascii(
        f"Source {summary['source']} on cluster {summary['cluster'] or 'unlabelled'}: "
        f"{summary['events']} event(s) ingested, {summary['alerts']} alert(s) raised, "
        f"{summary['confirmed']} confirmed as active exploitation, "
        f"{summary['correlated']} corroborated, {summary['runtime_only']} runtime-only."))
    if summary.get("kmw_matches") is not None:
        _body(pdf, _ascii(
            f"Detection: {summary['kmw_matches']} by K8sMatrixWarden curated rule, "
            f"{summary['falco_relays']} relayed from the Falco provider, "
            f"{summary['unusable']} unusable with a recorded reason, "
            f"{summary['discarded']} silently discarded."))
    rows = _runtime_rows(result)
    if not rows:
        return
    _h3(pdf, "Correlated runtime evidence")
    with pdf.table(col_widths=(22, 18, 30, 48, 24, 44, 24),
                   text_align="LEFT", borders_layout="HORIZONTAL_LINES") as table:
        head = table.row()
        for col in ("Confidence", "Freshness", "Tactic", "Resource", "Namespace",
                    "Detection", "Detected by"):
            head.cell(col)
        for conf, fresh, tactic, resource, ns, rule, detector, _sup, _ident in rows[:25]:
            row = table.row()
            for value in (conf, fresh, tactic, resource, ns, rule, detector):
                row.cell(_ascii(str(value)))
    pdf.ln(2)
    _body(pdf, _ascii(
        "confirmed means a live event named the same resource as a static finding; "
        "corroborated means the same tactic in the same namespace, which is weaker. "
        "A historical freshness means the behaviour was seen, not that it is happening now."))


def _coverage(pdf, result: ScanResult, findings: list[Finding]) -> None:
    _h2(pdf, "2. Coverage & Exposure")
    if result.by_tactic:
        _h3(pdf, "By MITRE ATT&CK Tactic")
        mx = max(result.by_tactic.values())
        with pdf.table(col_widths=(70, 20, 90), text_align=("LEFT", "RIGHT", "LEFT"),
                      borders_layout="HORIZONTAL_LINES") as table:
            for tactic, n in sorted(result.by_tactic.items(), key=lambda kv: -kv[1]):
                row = table.row()
                row.cell(_ascii(tactic))
                row.cell(str(n))
                row.cell(_ascii_bar(round(100 * n / mx), 40))
        pdf.ln(2)

    owasp = {}
    for f in findings:
        if f.owasp:
            owasp[f.owasp] = owasp.get(f.owasp, 0) + 1
    if owasp:
        from .reporting import _owasp_names
        names = _owasp_names()
        _h3(pdf, "By OWASP Kubernetes Top 10 (2025)")
        with pdf.table(col_widths=(20, 100, 20), borders_layout="HORIZONTAL_LINES") as table:
            for code in sorted(owasp):
                row = table.row()
                row.cell(code)
                row.cell(_ascii(names.get(code, "-")))
                row.cell(str(owasp[code]))
        pdf.ln(2)


def _findings_section(pdf, findings: list[Finding], build_finding_context) -> None:
    _h2(pdf, "3. Findings")
    for sev in _SEV_DISPLAY:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        _ensure_space(pdf, 14)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*_SEV_RGB[sev.label])
        pdf.cell(0, 10, f"{sev.label} -- {len(group)} finding(s)",
                new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        for i, f in enumerate(group, 1):
            _finding_block(pdf, f, i, build_finding_context)


def _finding_block(pdf, f: Finding, i: int, build_finding_context) -> None:
    ctx = build_finding_context(f)
    sev_rgb = _SEV_RGB[f.severity.label]
    sev_bg = _SEV_BG[f.severity.label]

    _ensure_space(pdf, 30)
    # -- header strip -------------------------------------------------- #
    pdf.set_fill_color(*sev_bg)
    pdf.rect(10, pdf.get_y(), pdf.w - 20, 9, style="F")
    pdf.set_xy(12, pdf.get_y() + 1.5)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*sev_rgb)
    amp = "  [Attack-Path Amplified]" if len(f.tactics) > 1 else ""
    pdf.cell(0, 6, f"{i}. {f.title}{amp}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 6, str(f.resource), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    _h3(pdf, "Summary")
    _body(pdf, ctx.summary)
    _h3(pdf, "Detected")
    _body(pdf, f.message, color=_MUTED)

    kv = [("Rule ID", f.rule_id), ("Domain", f.owning_shard),
         ("Exploitability", f.exploitability.label),
         ("Blast radius", f.blast_radius.label), ("Risk score", str(round(f.score, 2)))]
    if f.exploitable_by:
        vec = "Internet-reachable" if "ingress" in f.exploitable_by else "Post-breach only"
        kv.append(("Attack vector", f"{vec} -- {f.path_reason}"))
    _kv_table(pdf, kv)

    _h3(pdf, "Standards & Benchmark Mapping")
    if ctx.standards:
        for s in ctx.standards:
            _body(pdf, f"{s.framework} -- {s.control}: {s.title}", size=9.5)
            _link_line(pdf, "Reference", s.url)
    else:
        _body(pdf, "No named standard or benchmark control maps to this finding.",
              size=9.5, color=_MUTED)
    pdf.ln(1)

    _h3(pdf, "MITRE ATT&CK Mapping")
    if ctx.mitre:
        for m in ctx.mitre:
            _body(pdf, f"{m.tactic} -- {m.technique_name} ({m.technique_id})", size=9.5)
            _link_line(pdf, "Reference", m.url)
    else:
        _body(pdf, "Not mapped to a MITRE ATT&CK for Containers technique.",
              size=9.5, color=_MUTED)
    pdf.ln(1)

    _h3(pdf, "Impact")
    _body(pdf, ctx.impact)

    _h3(pdf, "Validation -- How to Reproduce / Verify")
    _mono(pdf, "\n".join(ctx.validation_steps))

    pdf.set_draw_color(*_LINE)
    pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
    pdf.ln(5)


def _appendix(pdf, result: ScanResult) -> None:
    _ensure_space(pdf, 30)
    _h2(pdf, "4. Appendix")
    _kv_table(pdf, [
        ("Scan ID", result.scan_id), ("Generated", result.generated_at),
        ("Tool version", f"K8sMatrixWarden {result.tool_version}"),
        ("Mode", result.mode), ("Scope", result.request.scope.describe()),
        ("Selector", result.request.selector.describe()),
        ("Rules evaluated", str(len(result.resolved_rule_ids))),
    ])
    _h3(pdf, "Rules evaluated in this scan")
    _mono(pdf, ", ".join(result.resolved_rule_ids) or "(none)", size=7.5)


def _ascii_bar(pct: int, width: int) -> str:
    pct = max(0, min(100, pct))
    filled = round(width * pct / 100)
    return "#" * filled + "." * (width - filled)
