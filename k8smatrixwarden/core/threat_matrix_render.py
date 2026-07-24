"""
Threat Matrix renderers, one matrix (core.threat_matrix.ThreatMatrix), three surfaces:

    render_text    , a compact per-tactic text summary (terminal / plain reports)
    render_markdown, an overview table + per-tactic technique tables (markdown reports)
    render_html_grid, a self-contained ATT&CK-Navigator-style heatmap FRAGMENT (no <html>
                      wrapper), reused by both the HTML report and the web dashboard

Cell colour encodes state: a HIT cell is painted by its worst finding severity; a COVERED
cell (rule exists, nothing found this scan) is neutral-positive; a GAP cell (no rule yet) is
muted, so the same three-state legend reads identically in every surface.
"""
from __future__ import annotations

from .threat_matrix import MatrixCell, ThreatMatrix

_SEV_HEAT = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}


def _cell_class(cell: MatrixCell) -> str:
    if cell.hit:
        sev = cell.max_severity
        return "hit " + (_SEV_HEAT.get(sev.label, "hit") if sev else "hit")
    if cell.covered:
        return "covered"
    if cell.covered_runtime:
        return "runtime"
    return "gap"


# ======================================================================= #
# TEXT
# ======================================================================= #
def render_text(tm: ThreatMatrix) -> str:
    s = tm.summary()
    out = [
        "KUBERNETES THREAT MATRIX  ·  " + tm.scan_id,
        f"  scope {tm.scope}  ·  tactics hit {s['tactics_hit']}/{s['tactics_total']}  ·  "
        f"techniques hit {s['techniques_hit']}/{s['techniques_total']}  "
        f"(covered {s['techniques_covered']})",
        "  " + "─" * 66,
    ]
    for col in tm.columns:
        sev = col.max_severity
        marker = sev.emoji if sev else (
            "🟦" if any(c.covered for c in col.cells)
            else "🟣" if any(c.covered_runtime for c in col.cells) else "▫️")
        out.append(f"  {marker} {col.tactic:<22} hit {col.hit_count}/{len(col.cells)}"
                   f"   findings {col.finding_count}")
        for cell in col.cells:
            if not cell.hit:
                continue
            sv = cell.max_severity
            out.append(f"        {sv.emoji if sv else '•'} {cell.technique_name} "
                       f"({cell.technique_id or 'N/A'}) ×{cell.count}")
    out.append("  " + "─" * 66)
    out.append("  legend:  severity emoji = hit · 🟦 = scan rule, none found · "
               "🟣 = runtime-only detection · ▫️ = no detection yet")
    return "\n".join(out)


# ======================================================================= #
# MARKDOWN
# ======================================================================= #
def render_markdown(tm: ThreatMatrix, *, heading_level: int = 2,
                    include_heading: bool = True) -> str:
    s = tm.summary()
    h = "#" * heading_level
    md = [f"{h} 🗺️ Kubernetes Threat Matrix", ""] if include_heading else []
    md += [
        f"Findings from this scan projected onto the [Kubernetes Threat Matrix]"
        f"({tm.summary()['reference']}) (MITRE ATT&CK for Containers). "
        f"**{s['tactics_hit']} / {s['tactics_total']}** tactics implicated · "
        f"**{s['techniques_hit']} / {s['techniques_total']}** techniques triggered "
        f"(**{s['coverage_pct']}%** of the matrix has detection coverage).",
        "",
        "| Tactic | Techniques hit | Findings | Worst |",
        "|:--|:--:|--:|:--:|",
    ]
    for col in tm.columns:
        sev = col.max_severity
        md.append(f"| **{col.tactic}** | {col.hit_count} / {len(col.cells)} "
                  f"| {col.finding_count} | {sev.emoji if sev else 'N/A'} |")
    md += ["", f"{h}# Technique Detail", ""]

    for col in tm.columns:
        if col.hit_count == 0 and col.finding_count == 0:
            covered = sum(1 for c in col.cells if c.covered)
            md.append(f"- **{col.tactic}**, no findings "
                      f"({covered}/{len(col.cells)} techniques have coverage)")
            continue
        md += [f"{h}## {col.tactic}", "",
               "| State | Technique | ATT&CK | Findings | Resources |",
               "|:--:|:--|:--|--:|:--|"]
        for cell in col.cells:
            icon = _md_state_icon(cell)
            tid = f"[`{cell.technique_id}`]({cell.url()})" if cell.technique_id else "N/A"
            res = ", ".join(f"`{r}`" for r in cell.as_dict()["resources"][:3])
            if cell.count > 3:
                res += f", … (+{cell.count - 3})"
            md.append(f"| {icon} | {cell.technique_name} | {tid} | "
                      f"{cell.count or 'N/A'} | {res or 'N/A'} |")
        md.append("")
    md += ["> **Legend**, 🔴🟠🟡🟢 hit (painted by worst finding severity) · "
           "🟦 covered (a scan rule exists, nothing found this scan) · "
           "🟣 runtime-only (no scan rule; the Runtime Agent detects it live) · "
           "▫️ gap (no detection yet).", ""]
    return "\n".join(md)


def _md_state_icon(cell: MatrixCell) -> str:
    if cell.hit:
        sev = cell.max_severity
        return sev.emoji if sev else "🔵"
    if cell.covered:
        return "🟦"
    return "🟣" if cell.covered_runtime else "▫️"


# ======================================================================= #
# HTML GRID (fragment, no <html>/<head>; caller supplies the page + CSS)
# ======================================================================= #
def render_html_grid(tm: ThreatMatrix, *, coverage_only: bool = False) -> str:
    """Render the heatmap.

    `coverage_only=True` is the standalone /matrix page: there is no scan overlaid, so
    every hit-derived number is structurally 0. Reporting "0/9 tactics implicated · 0
    findings mapped" there is not a result, it is a category error, the page is about
    *detection coverage*. In that mode the stat tiles and the per-column counter switch to
    the covered/total axis, and the hit legend entries are dropped.
    """
    from .reporting import _esc
    s = tm.summary()
    cols_html = []
    for col in tm.columns:
        cells_html = []
        for cell in col.cells:
            d = cell.as_dict()
            badge = (f"<span class='tmcount'>{cell.count}</span>" if cell.count else "")
            sub = (f"<span class='tmtid'>{_esc(cell.technique_id)}</span>"
                   if cell.technique_id else "")
            title = _esc(_cell_tooltip(cell))
            cells_html.append(
                f"<a class='tmcell {_cell_class(cell)}' href='{_esc(cell.url())}' "
                f"target='_blank' rel='noopener' title='{title}'>"
                f"<span class='tmname'>{_esc(cell.technique_name)}</span>{sub}{badge}</a>")
        sev = col.max_severity
        head_sev = sev.label.lower() if sev else ("cov" if any(c.covered for c in col.cells) else "")
        if coverage_only:
            head_sev = "cov" if any(c.covered for c in col.cells) else ""
            counter = (f"{sum(1 for c in col.cells if c.covered)}/{len(col.cells)} "
                       f"with a rule")
        else:
            counter = f"{col.hit_count}/{len(col.cells)}"
        cols_html.append(
            f"<div class='tmcol'>"
            f"<div class='tmhead {head_sev}'>{_esc(col.tactic)}"
            f"<span class='tmhits'>{counter}</span></div>"
            f"{''.join(cells_html)}</div>")

    if coverage_only:
        legend = (
            "<div class='tmlegend'>"
            "<span><i class='sw covered'></i>Scan rule exists</span>"
            "<span><i class='sw runtime'></i>Runtime-only detection</span>"
            "<span><i class='sw gap'></i>No detection yet (coverage gap)</span></div>")
        stats = (
            f"<div class='tmstats'>"
            f"<div><b>{s['techniques_covered']}</b>/{s['techniques_total']}"
            f"<span>techniques with a detection rule</span></div>"
            f"<div><b>{s['coverage_pct']}%</b><span>matrix coverage</span></div>"
            f"<div><b>{s['tactics_covered']}</b>/{s['tactics_total']}"
            f"<span>tactics with coverage</span></div>"
            f"<div><b>+{s['techniques_runtime_only']}</b>"
            f"<span>more covered at runtime only</span></div>"
            f"<div><b>{s['rule_count']}</b><span>rules mapped to the matrix</span></div>"
            f"</div>")
    else:
        legend = (
            "<div class='tmlegend'>"
            "<span><i class='sw crit'></i>Critical</span><span><i class='sw high'></i>High</span>"
            "<span><i class='sw med'></i>Medium</span><span><i class='sw low'></i>Low</span>"
            "<span><i class='sw covered'></i>Scan rule (no finding)</span>"
            "<span><i class='sw runtime'></i>Runtime-only detection</span>"
            "<span><i class='sw gap'></i>No detection yet</span></div>")
        stats = (
            f"<div class='tmstats'>"
            f"<div><b>{s['tactics_hit']}</b>/{s['tactics_total']}<span>tactics implicated</span></div>"
            f"<div><b>{s['techniques_hit']}</b>/{s['techniques_total']}<span>techniques triggered</span></div>"
            f"<div><b>{s['coverage_pct']}%</b><span>matrix coverage</span></div>"
            f"<div><b>{s['finding_count']}</b><span>findings mapped</span></div></div>")

    return (f"{stats}{legend}"
            f"<div class='tmgrid'>{''.join(cols_html)}</div>")


def _cell_tooltip(cell: MatrixCell) -> str:
    parts = [cell.technique_name]
    if cell.technique_id:
        parts.append(f"({cell.technique_id})")
    if cell.hit:
        sev = cell.max_severity
        parts.append(f", {cell.count} finding(s), worst {sev.label if sev else '?'}")
        rules = cell.as_dict()["finding_rule_ids"]
        if rules:
            parts.append("· " + ", ".join(rules[:6]))
    elif cell.covered:
        parts.append(", scan rule exists, no finding this scan")
    elif cell.covered_runtime:
        rt = ", ".join(sorted(set(cell.runtime_rule_ids))[:4])
        parts.append(f", no scan rule; detected at runtime by {rt}")
    else:
        parts.append(", no detection yet")
    return " ".join(parts)


# Self-contained CSS for the grid, injected once by whatever page hosts render_html_grid().
THREAT_MATRIX_CSS = """
/* runtime-only coverage: a distinct hue from both "scan rule" green and "gap" grey */
:root{--rt:#8250df}
@media (prefers-color-scheme:dark){:root{--rt:#a371f7}}
:root[data-theme=light]{--rt:#8250df}
:root[data-theme=dark]{--rt:#a371f7}
.tmstats{display:flex;flex-wrap:wrap;gap:.6rem;margin:.5rem 0 1rem}
.tmstats>div{flex:1;min-width:120px;background:var(--card);border:1px solid var(--bd);
 border-radius:10px;padding:.6rem .8rem}
.tmstats b{font-size:1.5rem;display:inline-block;margin-right:.35rem}
.tmstats span{display:block;color:var(--muted);font-size:.75rem}
.tmlegend{display:flex;flex-wrap:wrap;gap:.75rem;font-size:.75rem;color:var(--muted);margin-bottom:.9rem}
.tmlegend span{display:inline-flex;align-items:center;gap:.3rem}
.tmlegend i.sw{width:12px;height:12px;border-radius:3px;display:inline-block;border:1px solid var(--bd)}
.tmgrid{display:grid;grid-template-columns:repeat(9,minmax(120px,1fr));gap:6px;overflow-x:auto;
 padding-bottom:.5rem}
.tmcol{display:flex;flex-direction:column;gap:5px}
.tmhead{font-size:.72rem;font-weight:700;text-align:center;padding:.4rem .3rem;border-radius:8px;
 background:var(--card);border:1px solid var(--bd);position:sticky;top:0;line-height:1.2}
.tmhead .tmhits{display:block;font-weight:400;color:var(--muted);font-size:.68rem}
.tmhead.critical,.tmhead.high{color:#fff}
.tmhead.critical{background:var(--crit);border-color:var(--crit)}
.tmhead.high{background:var(--high);border-color:var(--high)}
.tmhead.medium{background:var(--med);border-color:var(--med);color:#fff}
.tmhead.low,.tmhead.cov{border-color:var(--low)}
.tmcell{display:block;text-decoration:none;border:1px solid var(--bd);border-radius:7px;
 padding:.4rem .45rem;font-size:.72rem;line-height:1.25;color:var(--fg);background:var(--card);
 position:relative;transition:transform .06s}
.tmcell:hover{transform:translateY(-1px);box-shadow:0 2px 6px rgba(0,0,0,.15)}
.tmcell .tmname{display:block}
.tmcell .tmtid{display:block;font-size:.62rem;opacity:.7;font-family:ui-monospace,monospace}
.tmcell .tmcount{position:absolute;top:4px;right:5px;font-size:.62rem;font-weight:700;
 background:rgba(0,0,0,.28);color:#fff;border-radius:10px;padding:0 .35rem}
.tmcell.gap{opacity:.5;border-style:dashed}
.tmcell.covered{border-color:var(--low);border-left:3px solid var(--low)}
.tmcell.runtime{border-color:var(--rt);border-left:3px dashed var(--rt)}
.tmcell.hit{color:#fff;border:none}
.tmcell.hit.crit{background:var(--crit)}
.tmcell.hit.high{background:var(--high)}
.tmcell.hit.med{background:var(--med)}
.tmcell.hit.low{background:var(--low)}
i.sw.crit{background:var(--crit)}i.sw.high{background:var(--high)}
i.sw.med{background:var(--med)}i.sw.low{background:var(--low)}
i.sw.covered{background:transparent;border-left:3px solid var(--low)}
i.sw.runtime{background:transparent;border-left:3px dashed var(--rt)}
i.sw.gap{background:transparent;border-style:dashed}
@media(max-width:900px){.tmgrid{grid-template-columns:repeat(9,150px)}}
"""
