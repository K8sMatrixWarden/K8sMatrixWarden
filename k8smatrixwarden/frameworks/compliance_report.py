"""
Renderers for a ComplianceReport, the auditor-facing view. Markdown and HTML reuse the
same GitHub-styled shell + theme toggle as the security report (core.reporting), so a
per-scan report and its compliance audit look like one product. PDF reuses the fpdf2
scaffold from core.pdf_report.

Deliberately narrative-first: each framework leads with an attestation sentence
("N findings block PCI DSS attestation"), then a per-requirement table of
status / evidence / blocking findings, what an assessor reads, not a technical dump.
"""
from __future__ import annotations

from ..core.reporting import _HTML_CSS, _esc, THEME_BUTTON, THEME_JS
from .compliance import (ComplianceReport, PASS, FAIL, PARTIAL, MANUAL, NEEDS_REVIEW,
                         NOT_ASSESSED)

_STATUS_LABEL = {PASS: "Pass", FAIL: "Fail", PARTIAL: "Partial", MANUAL: "Manual",
                 NEEDS_REVIEW: "Needs review", NOT_ASSESSED: "Not assessed"}
_STATUS_EMOJI = {PASS: "✅", FAIL: "❌", PARTIAL: "🟠", MANUAL: "🔶",
                 NEEDS_REVIEW: "🔎", NOT_ASSESSED: "⚪"}
_STATUS_CLS = {PASS: "low", FAIL: "crit", PARTIAL: "high", MANUAL: "med",
               NEEDS_REVIEW: "high", NOT_ASSESSED: "muted"}
_ORDER = [FAIL, PARTIAL, NEEDS_REVIEW, MANUAL, NOT_ASSESSED, PASS]


# ---------------------------------------------------------------- markdown --- #
def to_markdown(report: ComplianceReport) -> str:
    L = ["# Compliance Audit\n"]
    L.append(f"Scan `{report.scan_id or 'N/A'}` · cluster `{report.cluster or 'N/A'}` · "
             f"profile `{report.profile or 'N/A'}` · {report.generated_at or ''}\n")
    L.append("> Assesses the **Kubernetes-relevant subset** of each framework, derived from "
             "the CIS Kubernetes Benchmark v1.8 and OWASP Kubernetes Top 10. A requirement "
             "shown as *Not assessed* has no automated cluster check and needs manual "
             "attestation, it is never counted as passing.\n")
    for fw in report.frameworks:
        c = fw.counts
        L.append(f"\n## {fw.name}\n")
        L.append(f"**{fw.attestation}**\n")
        L.append(f"Pass rate (of assessed): **{fw.pass_pct}%** · "
                 f"{_STATUS_EMOJI[FAIL]} {c[FAIL]} fail · {_STATUS_EMOJI[PARTIAL]} {c[PARTIAL]} partial · "
                 f"{_STATUS_EMOJI[NEEDS_REVIEW]} {c[NEEDS_REVIEW]} needs-review · "
                 f"{_STATUS_EMOJI[MANUAL]} {c[MANUAL]} manual · {_STATUS_EMOJI[NOT_ASSESSED]} "
                 f"{c[NOT_ASSESSED]} not assessed · {_STATUS_EMOJI[PASS]} {c[PASS]} pass\n")
        L.append(f"_{fw.scope_note}_\n")
        L.append("\n| Requirement | Status | Evidence | Blocking findings |")
        L.append("|---|---|---|---|")
        for r in sorted(fw.requirements, key=lambda x: _ORDER.index(x.status)):
            bf = "; ".join(f"{b.title} (`{str(b.resource)}`)"
                           for b in r.blocking_findings[:3]) or "N/A"
            if len(r.blocking_findings) > 3:
                bf += f" +{len(r.blocking_findings)-3} more"
            L.append(f"| **{_esc(r.id)}** {_esc(r.title)} | "
                     f"{_STATUS_EMOJI[r.status]} {_STATUS_LABEL[r.status]} | "
                     f"{_esc(r.detail)} | {_esc(bf)} |")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------- html --- #
def to_html(report: ComplianceReport, *, standalone: bool = True) -> str:
    tabs, panels = [], []
    for i, fw in enumerate(report.frameworks):
        on = " on" if i == 0 else ""
        tabs.append(f"<button class='cf-tab{on}' onclick=\"cfShow('{_esc(fw.key)}')\" "
                    f"id='cft-{_esc(fw.key)}'>{_esc(fw.short)}</button>")
        panels.append(_framework_panel(fw, active=(i == 0)))
    # Standalone pages own the theme button; when embedded (in a page with its own topbar
    # + theme toggle) we drop ours and let the host page's THEME_JS run.
    themebar = f"<div class='themebar'>{THEME_BUTTON}</div>" if standalone else ""
    body = f"""
{themebar}
<h1>Compliance Audit</h1>
<div class='sub'>Scan <code>{_esc(report.scan_id or 'N/A')}</code> · cluster
 <code>{_esc(report.cluster or 'N/A')}</code> · profile <code>{_esc(report.profile or 'N/A')}</code>
 · {_esc(report.generated_at or '')}</div>
<div class='cf-note'>Covers the Kubernetes-relevant subset of each framework (CIS Benchmark v1.8 and OWASP Kubernetes Top 10). <b>Not assessed</b> means no automated check exists; it needs manual attestation and never counts as a pass.</div>
<div class='cf-tabs'>{''.join(tabs)}</div>
{''.join(panels)}
"""
    if not standalone:
        return f"<style>{_CF_CSS}</style>{body}<script>{_CF_JS}</script>"
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Compliance Audit · K8sMatrixWarden</title>"
            f"<style>{_HTML_CSS}{_CF_CSS}</style></head><body><div class='wrap'>"
            f"{body}</div><script>{_CF_JS}{THEME_JS}</script></body></html>")


def _framework_panel(fw, *, active: bool) -> str:
    c = fw.counts
    rows = []
    for r in sorted(fw.requirements, key=lambda x: _ORDER.index(x.status)):
        bf = ""
        if r.blocking_findings:
            items = "".join(
                f"<li><span class='sevdot {b.severity.label.lower()}'></span>{_esc(b.title)} "
                f"<code>{_esc(str(b.resource))}</code></li>"
                for b in r.blocking_findings[:6])
            more = (f"<li class='muted'>+{len(r.blocking_findings)-6} more</li>"
                    if len(r.blocking_findings) > 6 else "")
            bf = f"<ul class='cf-bf'>{items}{more}</ul>"
        cis = " ".join(f"<span class='cf-chip'>CIS {_esc(m['id'])}</span>"
                       for m in r.cis_controls)
        ow = " ".join(f"<span class='cf-chip ow'>{_esc(o)}</span>" for o in r.owasp)
        rows.append(f"""
<tr class='cf-row {_STATUS_CLS[r.status]}'>
  <td class='cf-id'><b>{_esc(r.id)}</b><div class='cf-rt'>{_esc(r.title)}</div>
    <div class='cf-maps'>{cis}{ow}</div></td>
  <td><span class='cf-badge {_STATUS_CLS[r.status]}'>{_STATUS_EMOJI[r.status]} {_STATUS_LABEL[r.status]}</span></td>
  <td class='cf-ev'>{_esc(r.detail)}{bf}</td>
</tr>""")
    disp = "block" if active else "none"
    return f"""
<div class='cf-panel' id='cfp-{_esc(fw.key)}' style='display:{disp}'>
  <div class='cf-attest {"fail" if c[FAIL] else "ok"}'>{_esc(fw.attestation)}</div>
  <div class='cf-summary'>
    <span class='cf-pill low'>Pass {c[PASS]}</span>
    <span class='cf-pill crit'>Fail {c[FAIL]}</span>
    <span class='cf-pill high'>Partial {c[PARTIAL]}</span>
    <span class='cf-pill high'>Needs review {c[NEEDS_REVIEW]}</span>
    <span class='cf-pill med'>Manual {c[MANUAL]}</span>
    <span class='cf-pill muted'>Not assessed {c[NOT_ASSESSED]}</span>
    <span class='cf-pct'>{fw.pass_pct}% of assessed pass</span>
  </div>
  <div class='cf-scope'>{_esc(fw.scope_note)}</div>
  <table class='cf-table'>
    <thead><tr><th>Requirement</th><th>Status</th><th>Evidence &amp; blocking findings</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>"""


_CF_CSS = """
.cf-note{font-size:.85rem;color:var(--muted);border-left:3px solid var(--bd);
 padding:.5rem .8rem;margin:1rem 0;background:var(--card);border-radius:0 8px 8px 0}
.cf-tabs{display:flex;gap:.3rem;flex-wrap:wrap;border-bottom:1px solid var(--bd);margin:1.2rem 0 1rem}
.cf-tab{background:none;border:0;border-bottom:2px solid transparent;padding:.6rem 1rem;
 font:inherit;font-size:.9rem;font-weight:600;color:var(--muted);cursor:pointer;margin-bottom:-1px}
.cf-tab:hover{color:var(--fg)}.cf-tab.on{color:var(--accent);border-bottom-color:var(--accent)}
.cf-attest{font-size:.98rem;font-weight:650;padding:.85rem 1.05rem;border-radius:10px;margin:.5rem 0 1rem;line-height:1.5}
.cf-attest.fail{background:color-mix(in srgb,var(--crit) 8%,var(--card));color:var(--crit);border:1px solid color-mix(in srgb,var(--crit) 32%,var(--bd))}
.cf-attest.ok{background:color-mix(in srgb,var(--low) 8%,var(--card));color:var(--low);border:1px solid color-mix(in srgb,var(--low) 32%,var(--bd))}
.cf-summary{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin-bottom:.6rem}
.cf-pill{font-size:.72rem;font-weight:650;padding:.2rem .55rem;border-radius:6px;color:#fff}
.cf-pill.low{background:var(--low)}.cf-pill.crit{background:var(--crit)}
.cf-pill.high{background:var(--high)}.cf-pill.med{background:var(--med)}
.cf-pill.muted{background:var(--muted)}
.cf-pct{font-size:.82rem;color:var(--muted);margin-left:auto;font-weight:600}
.cf-scope{font-size:.8rem;color:var(--muted);font-style:italic;margin-bottom:1rem}
.cf-table{width:100%;border-collapse:collapse;font-size:.87rem}
.cf-table th{text-align:left;color:var(--muted);font-size:.66rem;text-transform:uppercase;
 letter-spacing:.1em;font-family:var(--mono);font-weight:600;padding:.55rem .6rem;border-bottom:1px solid var(--bd)}
.cf-table td{padding:.7rem .6rem;border-bottom:1px solid var(--bd);vertical-align:top}
.cf-row.crit{background:color-mix(in srgb,var(--crit) 5%,transparent)}
.cf-id{max-width:320px}.cf-rt{font-size:.8rem;color:var(--muted);margin-top:.15rem}
.cf-maps{margin-top:.4rem;display:flex;gap:.3rem;flex-wrap:wrap}
.cf-chip{font-size:.68rem;padding:.1rem .45rem;border-radius:6px;border:1px solid var(--bd);
 color:var(--muted);background:var(--bg)}
.cf-chip.ow{border-color:var(--accent);color:var(--accent)}
.cf-badge{font-size:.7rem;font-weight:650;padding:.2rem .55rem;border-radius:6px;
 white-space:nowrap;color:#fff}
.cf-badge.low{background:var(--low)}.cf-badge.crit{background:var(--crit)}
.cf-badge.high{background:var(--high)}.cf-badge.med{background:var(--med)}
.cf-badge.muted{background:var(--info)}
.cf-ev{color:var(--fg)}.cf-bf{margin:.5rem 0 0;padding-left:1rem;font-size:.83rem}
.cf-bf li{margin:.2rem 0;color:var(--muted)}
.sevdot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:.4rem;vertical-align:1px}
.sevdot.critical{background:var(--crit)}.sevdot.high{background:var(--high)}
.sevdot.medium{background:var(--med)}.sevdot.low{background:var(--low)}
"""

_CF_JS = """
function cfShow(key){
  document.querySelectorAll('.cf-panel').forEach(p=>p.style.display='none');
  document.querySelectorAll('.cf-tab').forEach(t=>t.classList.remove('on'));
  var p=document.getElementById('cfp-'+key); if(p)p.style.display='block';
  var t=document.getElementById('cft-'+key); if(t)t.classList.add('on');
}
"""


# -------------------------------------------------------------------- pdf --- #
def to_pdf(report: ComplianceReport) -> bytes:
    """Print/share-ready audit PDF. Reuses the security report's fpdf2 scaffold so the two
    documents share branding; requires the optional `fpdf2` extra."""
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise RuntimeError(
            "PDF generation requires 'fpdf2' (`pip install fpdf2`). Use markdown/html/json "
            "instead.") from exc
    from ..core.pdf_report import (_make_pdf, _h1, _h2, _h3, _body, _ensure_space,
                                   _INK, _MUTED, _ACCENT)
    _SEV = {FAIL: (207, 34, 46), PARTIAL: (188, 76, 0), NEEDS_REVIEW: (188, 76, 0),
            MANUAL: (154, 103, 0), NOT_ASSESSED: (87, 96, 106), PASS: (26, 127, 55)}

    pdf = _make_pdf(FPDF)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.alias_nb_pages()
    pdf.add_page()
    _h1(pdf, "Compliance Audit")
    _body(pdf, f"Scan {report.scan_id or '-'}  |  cluster {report.cluster or '-'}  |  "
               f"profile {report.profile or '-'}  |  {report.generated_at or ''}", color=_MUTED)
    _body(pdf, "Assesses the Kubernetes-relevant subset of each framework, derived from CIS "
               "Kubernetes Benchmark v1.8 + OWASP Kubernetes Top 10. A requirement marked "
               "'Not assessed' has no automated cluster check and needs manual attestation "
               "- it is never counted as passing.", color=_MUTED)

    for fw in report.frameworks:
        c = fw.counts
        _h2(pdf, fw.name)
        _h3(pdf, fw.attestation, color=(_SEV[FAIL] if c[FAIL] else _SEV[PASS]))
        _body(pdf, f"Pass {c[PASS]}  |  Fail {c[FAIL]}  |  Partial {c[PARTIAL]}  |  "
                   f"Needs review {c[NEEDS_REVIEW]}  |  Manual {c[MANUAL]}  |  "
                   f"Not assessed {c[NOT_ASSESSED]}  "
                   f"({fw.pass_pct}% of assessed pass)", color=_MUTED)
        _body(pdf, fw.scope_note, color=_MUTED, size=9)
        for r in sorted(fw.requirements, key=lambda x: _ORDER.index(x.status)):
            _ensure_space(pdf, 22)
            maps = ", ".join([f"CIS {m['id']}" for m in r.cis_controls] + list(r.owasp))
            _h3(pdf, f"[{_STATUS_LABEL[r.status].upper()}] {r.id} - {r.title}",
                color=_SEV[r.status])
            _body(pdf, r.detail, size=9)
            if maps:
                _body(pdf, f"Maps to: {maps}", color=_MUTED, size=8.5)
            for b in r.blocking_findings[:6]:
                _body(pdf, f"  - [{b.severity.label}] {b.title}  ({str(b.resource)})",
                      color=_MUTED, size=8.5)
            if len(r.blocking_findings) > 6:
                _body(pdf, f"  ... +{len(r.blocking_findings)-6} more", color=_MUTED, size=8.5)
    return bytes(pdf.output())
