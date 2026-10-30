"""
HTML for the web dashboard.

The dashboard is a self-contained client-side app: `dashboard_page()` ships an inline-JS
shell that fetches `/api/dashboard` once and renders every view (KPIs, findings table with
search/filter/sort, interactive threat-matrix heatmap, attack path, runtime correlation)
in the browser. Zero external hosts, zero build step, theme-aware, the same constraints the
HTML report honours. The per-scan report page and the standalone matrix page stay
server-rendered (they reuse the ReportingEngine / threat-matrix grid directly).
"""
from __future__ import annotations

from ..core.reporting import _HTML_CSS, _esc, THEME_BUTTON, THEME_JS
from ..core.results import ScanResult

_DASH_CSS = """

.topbar{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;border-bottom:1px solid var(--bd);
 padding:.2rem 0 1.1rem;margin-bottom:1.6rem}
.topbar .brand{font-size:1.18rem;font-weight:750;margin:0;color:var(--fg);display:flex;align-items:center;gap:.6rem;
 letter-spacing:-.021em}
.topbar .brand .mark{width:1.65rem;height:1.65rem;border-radius:7px;flex:0 0 auto;
 background:linear-gradient(150deg,var(--accent),#155e75);
 display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:.78rem;font-weight:800;letter-spacing:-.04em;font-family:var(--mono)}
.topbar .brand .kw{color:var(--muted);font-weight:600}
.topbar .grow{flex:1}
.topbar a.nav{font-size:.855rem;color:var(--muted);text-decoration:none;padding:.44rem .8rem;
 border:1px solid transparent;border-radius:9px;font-weight:550;transition:color .15s,background .15s}
.topbar a.nav:hover{color:var(--fg);background:var(--sunken)}
.topbar a.nav.on,.topbar a.nav[style]{color:var(--accent);background:var(--sunken)}
.topbar .navlinks{display:flex;gap:.15rem;overflow-x:auto;max-width:100%;scrollbar-width:none}
.topbar a.nav{white-space:nowrap}
.crumbs{font-size:.83rem;color:var(--muted);margin-bottom:.8rem}
.crumbs a{color:var(--accent);text-decoration:none;font-weight:500}
.empty{color:var(--muted);padding:2.4rem 1.5rem;text-align:center;border:1px dashed var(--bd);border-radius:16px;background:var(--card)}
.panel{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:1.3rem 1.35rem;margin:1.1rem 0;box-shadow:none;overflow-x:auto}
.panel h2{font-size:.9rem;font-weight:650;margin:.1rem 0 1.05rem;color:var(--fg);letter-spacing:-.01em;
 display:flex;align-items:center;gap:.5rem}
.panel h2::before{content:'';width:3px;height:.95em;background:var(--accent);border-radius:2px;flex:0 0 auto}
.pill{display:inline-flex;align-items:center;gap:.32rem;font-size:.72rem;font-weight:650;padding:.2rem .6rem;
 border-radius:999px;color:var(--fg);background:var(--sunken);border:1px solid var(--bd)}
.pill::before{content:'';width:.42rem;height:.42rem;border-radius:50%;background:currentColor;opacity:.9}
.pill.Critical{color:var(--crit)}.pill.Poor{color:var(--high)}
.pill.Fair{color:var(--med)}.pill.Good,.pill.Excellent{color:var(--low)}
.pill.Unknown{color:var(--info)}
"""

# The dashboard app's own styling, a calm, dense security console. Severity colours and
# base tokens live in reporting._HTML_CSS (theme-aware via data-theme); this sheet owns the
# component system layered on top. Every selector here is emitted by _APP_JS, restyle
# freely, but do not rename classes/ids the JS depends on.
_APP_CSS = """
:root{--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
 --mono:ui-monospace,'SF Mono','Segoe UI Mono',Menlo,Consolas,monospace;
 --ease-out:cubic-bezier(0.16,1,0.3,1)}
body{font-family:var(--font);-webkit-font-smoothing:antialiased;letter-spacing:-.006em}
code,.mono{font-family:var(--mono);font-size:.9em}
/* tabs, flat underline nav, console register */
.tabs{display:flex;gap:1.35rem;border-bottom:1px solid var(--bd);margin:1.6rem 0 1.5rem;flex-wrap:wrap}
.tab{padding:.55rem 0;font-size:.8rem;font-weight:600;color:var(--muted);cursor:pointer;
 border:0;background:none;border-bottom:1.5px solid transparent;margin-bottom:-1px;
 transition:color .15s,border-color .15s;letter-spacing:.005em}
.tab:hover{color:var(--fg)}
.tab.on{color:var(--fg);border-bottom-color:var(--accent)}
.view{display:none}.view.on{display:block;animation:fade .28s var(--ease-out)}
@keyframes fade{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
/* report selector */
.skl{display:grid;gap:1rem}.skl>div{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.skl i{display:block;border-radius:14px;background:linear-gradient(90deg,var(--sunken) 25%,var(--card) 50%,var(--sunken) 75%);background-size:200% 100%;animation:shim 1.3s infinite}@keyframes shim{to{background-position:-200% 0}}
.tb-search kbd{white-space:nowrap}
@media(max-width:700px){.tb{position:static}.tb-sel{width:100%}.tb-sel span{display:none}.tb-sel select{width:100%;max-width:none;min-width:0}.tb-meta{width:100%}.tb-search kbd{display:none}}.tb{position:sticky;top:0;z-index:40;background:color-mix(in srgb,var(--bg) 92%,transparent);backdrop-filter:blur(8px);margin:0 0 1rem;padding:.55rem 0 .4rem}
.tb-row{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap}
.tb-sel{display:flex;align-items:center;gap:.5rem;font-size:.64rem;font-weight:650;text-transform:uppercase;letter-spacing:.11em;color:var(--muted)}
.tb-sel select{background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:9px;padding:.45rem .6rem;font:inherit;font-size:.82rem;max-width:380px;text-transform:none;letter-spacing:0}
.tb-meta{color:var(--muted);font-size:.78rem}
.tb-search{flex:1 1 260px;display:flex;justify-content:space-between;align-items:center;gap:.6rem;background:var(--card);color:var(--muted);border:1px solid var(--bd);border-radius:10px;padding:.5rem .75rem;font:inherit;font-size:.84rem;cursor:text;text-align:left}
.tb-search:hover{border-color:var(--accent)}.tb-search kbd,.cp kbd{font-family:var(--mono);font-size:.7rem;border:1px solid var(--bd);border-radius:5px;padding:.05rem .35rem;background:var(--sunken)}
.tb-chip{border:1px solid var(--bd);background:var(--card);border-radius:999px;padding:.35rem .75rem;font:inherit;font-size:.78rem;font-weight:650;cursor:pointer}
.tb-chip.ok{color:var(--low);cursor:default}.tb-chip.warn{color:var(--med);border-color:color-mix(in srgb,var(--med) 40%,var(--bd))}.tb-chip.bad{color:var(--crit);border-color:var(--crit)}
.tb-go{padding:.45rem 1rem}
.tb-detail{display:none;margin-top:.5rem;border:1px solid var(--bd);border-left:4px solid var(--med);border-radius:10px;background:var(--card);padding:.6rem .9rem;font-size:.82rem}
.tb-detail.on{display:block}.tb-detail ul{margin:.2rem 0 .4rem;padding-left:1.1rem}.tb-detail p{margin:0;color:var(--muted)}
.cp{position:fixed;inset:0;z-index:100;background:rgba(10,15,25,.45);display:none;align-items:flex-start;justify-content:center;padding-top:12vh}.cp.on{display:flex}
.cp-box{width:min(640px,92vw);background:var(--card);border:1px solid var(--bd);border-radius:14px;box-shadow:0 24px 60px rgba(0,0,0,.35);overflow:hidden}
.cp-box input{width:100%;box-sizing:border-box;border:0;border-bottom:1px solid var(--bd);background:transparent;color:var(--fg);padding:1rem 1.1rem;font:inherit;font-size:1rem;outline:0}
.cp-list{max-height:52vh;overflow:auto;padding:.4rem}.cp-g{font-size:.66rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);padding:.6rem .7rem .2rem}
.cp-i{display:flex;justify-content:space-between;gap:1rem;padding:.5rem .7rem;border-radius:8px;cursor:pointer;font-size:.88rem}.cp-i small{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:50%}
.cp-i.on{background:var(--sunken);color:var(--accent)}.cp-none{padding:1.2rem;color:var(--muted);text-align:center}.cp-foot{border-top:1px solid var(--bd);padding:.5rem .9rem;font-size:.72rem;color:var(--muted);display:flex;gap:1rem}
.repbar{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap;background:var(--card);
 border:1px solid var(--bd);border-radius:10px;padding:.6rem .85rem;margin:1.1rem 0;box-shadow:none}
.repbar label{font-size:.64rem;font-weight:650;text-transform:uppercase;letter-spacing:.11em;color:var(--muted);font-family:var(--mono)}
.repbar select{background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:9px;
 padding:.5rem .7rem;font-size:.85rem;font-weight:500;min-width:280px;max-width:100%}
.repbar select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.repbar .meta{font-size:.8rem;color:var(--muted);margin-left:auto}
/* deep-link finding rows */
.findlink{display:flex;align-items:center;gap:.6rem;text-decoration:none;color:var(--fg);
 padding:.55rem .7rem;border:1px solid var(--bd);border-radius:10px;margin:.4rem 0;background:var(--card);
 transition:border-color .16s,transform .16s,box-shadow .16s}
.findlink:hover{border-color:color-mix(in srgb,var(--accent) 40%,var(--bd));transform:translateX(2px);box-shadow:var(--shadow)}
.findlink{min-width:0}
.fl2 .fl-m{flex:1;min-width:0;display:flex;flex-direction:column;gap:.1rem}.fl2 .fl-m b{font-size:.86rem;font-weight:620}.fl2 .fl-m small{color:var(--muted);font-size:.76rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.findlink .fl-t{font-weight:600;font-size:.85rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.findlink .fl-r{color:var(--muted);font-size:.78rem;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.findlink .fl-s{font-weight:650;font-size:.75rem;color:var(--muted);flex:0 0 auto;font-variant-numeric:tabular-nums}
.findlink .fl-go{color:var(--accent);font-size:1rem;flex:0 0 auto}
/* ---- KPI stat tiles ------------------------------------------------------
   Five metrics on ONE row. The previous 4-column track with 5 tiles orphaned the
   fifth onto a row of its own at the lead tile's width, which read as a layout bug
   rather than emphasis. The lead tile stays dominant via a wider first track, so the
   asymmetry is deliberate and the row still closes. */
.kpis{display:grid;grid-template-columns:1.55fr repeat(4,minmax(0,1fr));gap:.75rem;margin:1rem 0 1.15rem}
/* Below the five-across breakpoint the lead tile takes the full row and the remaining
   four form a 2x2. Five tiles into three columns leaves a hole in the second row, which
   is the same orphan defect one breakpoint down. */
@media(max-width:1240px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
 .kpi.lead{grid-column:1/-1}}
@media(max-width:520px){.kpis{grid-template-columns:minmax(0,1fr)}}
.kpi{position:relative;background:var(--card);border:1px solid var(--bd);border-radius:11px;
 padding:.95rem 1.05rem 1rem;overflow:hidden;display:flex;flex-direction:column;
 transition:border-color .16s var(--ease-out)}
.kpi:hover{border-color:color-mix(in srgb,var(--accent) 28%,var(--bd))}
.kpi::before{content:'';position:absolute;left:0;right:0;top:0;height:2px;background:var(--bd)}
/* Label above value: an operator scans the row for a metric name, then reads its number. */
.kpi .l{color:var(--muted);font-size:.68rem;font-weight:700;text-transform:uppercase;
 letter-spacing:.11em;font-family:var(--mono);margin:0 0 .55rem;display:flex;align-items:center;gap:.3rem}
.kpi .n{font-size:1.75rem;font-weight:750;line-height:1;letter-spacing:-.032em;margin-top:auto;
 font-variant-numeric:tabular-nums;font-feature-settings:'tnum';display:flex;align-items:baseline}
.kpi .s{font-size:.735rem;margin-top:.45rem;color:var(--muted);line-height:1.35;
 display:flex;align-items:center;gap:.3rem;min-height:1.1em}
.kpi.lead{padding:1.05rem 1.2rem 1.1rem}
.kpi.lead .n{font-size:2.7rem}
.kpi.crit .n{color:var(--crit)}.kpi.crit::before{background:var(--crit)}
.kpi.warn .n{color:var(--high)}.kpi.warn::before{background:var(--high)}
.kpi.good .n{color:var(--low)}.kpi.good::before{background:var(--low)}
.kpi.unk .n{color:var(--info)}.kpi.unk::before{background:var(--info)}
.kpi .n .max{font-size:.8rem;font-weight:600;color:var(--muted);margin-left:.15rem;letter-spacing:0;font-family:var(--mono)}
.kpi.lead .n .max{font-size:1.05rem}
/* Trend deltas read as indicators, not sentences. */
.delta{display:inline-flex;align-items:center;gap:.25rem;font-size:.7rem;font-weight:700;
 padding:.14rem .42rem;border-radius:5px;font-variant-numeric:tabular-nums;letter-spacing:.01em}
.delta.up{color:var(--crit);background:color-mix(in srgb,var(--crit) 13%,transparent)}
.delta.down{color:var(--low);background:color-mix(in srgb,var(--low) 13%,transparent)}
.delta.flat{color:var(--muted);background:var(--sunken)}
.up{color:var(--crit);font-weight:650}.down{color:var(--low);font-weight:650}
/* An inline help affordance. Replaces the explanatory paragraphs that used to sit
   between the readouts and break the scan path: the prose is still there, on hover,
   attached to the number it explains. */
.hint{display:inline-flex;align-items:center;justify-content:center;width:.92rem;height:.92rem;
 border-radius:50%;border:1px solid var(--bd);background:var(--sunken);color:var(--muted);
 font-size:.58rem;font-weight:800;font-family:var(--mono);cursor:help;flex:0 0 auto;
 line-height:1;transition:color .15s,border-color .15s}
.hint:hover{color:var(--accent);border-color:var(--accent)}
/* ---- metric strip: severity + exposure as sibling instrument cards ------- */
.strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:.75rem;margin:0 0 1.15rem}
.mcard{background:var(--card);border:1px solid var(--bd);border-radius:11px;padding:.85rem 1.05rem .95rem}
.mcard .mh{display:flex;align-items:center;gap:.45rem;margin-bottom:.7rem}
.mcard .mh .mt{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.11em;
 color:var(--muted);font-family:var(--mono)}
.mcard .mh .mn{margin-left:auto;font-size:.72rem;color:var(--muted);font-variant-numeric:tabular-nums;font-family:var(--mono)}
/* severity distribution, the signature readout under the KPIs */
.sevbar{display:flex;height:7px;border-radius:4px;overflow:hidden;margin:0 0 .6rem;background:var(--sunken);
 box-shadow:inset 0 0 0 1px var(--bd)}
.sevbar span{display:block;height:100%;transition:filter .15s}
.sevbar span:hover{filter:brightness(1.15)}
.sevbar .s-CRITICAL{background:var(--crit)}.sevbar .s-HIGH{background:var(--high)}
.sevbar .s-MEDIUM{background:var(--med)}.sevbar .s-LOW{background:var(--low)}.sevbar .s-INFO{background:var(--info)}
/* Legend as structured indicators: tabular figures so counts align into a column
   the eye can compare down. */
.sevleg{display:flex;flex-wrap:wrap;gap:.35rem 1.4rem;font-size:.72rem;color:var(--muted);letter-spacing:.01em}
.sevleg>span{display:inline-flex;align-items:baseline;gap:.4rem}
.sevleg b{color:var(--fg);font-weight:700;font-variant-numeric:tabular-nums;font-family:var(--mono);font-size:.8rem}
.sevleg i{width:7px;height:7px;border-radius:2px;display:inline-block;flex:0 0 auto;align-self:center}
.sevleg .s-CRITICAL{background:var(--crit)}.sevleg .s-HIGH{background:var(--high)}
.sevleg .s-MEDIUM{background:var(--med)}.sevleg .s-LOW{background:var(--low)}.sevleg .s-INFO{background:var(--info)}
/* pod exposure buckets (reachability) reuse the sevbar idiom, worst-wins colours */
.sevbar .x-internet_admin,.sevleg .x-internet_admin{background:var(--crit)}
.sevbar .x-internet,.sevleg .x-internet{background:var(--high)}
.sevbar .x-admin,.sevleg .x-admin{background:var(--med)}
.sevbar .x-internal,.sevleg .x-internal{background:var(--low)}
/* ---- cluster telemetry --------------------------------------------------
   Node readiness + pod phase. Hierarchy is explicit: a header row owns the verdict,
   a metric row owns the numbers, and each bar sits under a labelled rail with its
   counts right-aligned, so the two rails compare against a shared right edge. */
.clus{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:.7rem;margin:.1rem 0 1.1rem}
.clus .cm{background:var(--sunken);border:1px solid var(--bd);border-radius:9px;padding:.7rem .8rem .75rem}
.clus .cm .ck{color:var(--muted);font-size:.66rem;font-weight:700;text-transform:uppercase;
 letter-spacing:.11em;font-family:var(--mono);margin-bottom:.45rem}
.clus .cm .cv{font-size:1.45rem;font-weight:750;line-height:1;letter-spacing:-.03em;
 font-variant-numeric:tabular-nums;font-feature-settings:'tnum'}
.clus .cm .cv .sub{font-size:.78rem;font-weight:600;color:var(--muted);margin-left:.1rem;font-family:var(--mono)}
.clus .cm .cs{font-size:.71rem;margin-top:.4rem;color:var(--muted);line-height:1.3}
.clus .cm.bad .cv{color:var(--crit)}.clus .cm.warn .cv{color:var(--high)}
.clus .cm.ok .cv{color:var(--low)}.clus .cm.unk .cv{color:var(--info);font-size:1.1rem}
.rail{margin-top:.85rem}
.rail .rl{display:flex;align-items:baseline;gap:.5rem;margin-bottom:.4rem}
.rail .rl .rt{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.11em;
 color:var(--muted);font-family:var(--mono)}
.rail .rl .rn{margin-left:auto;font-size:.72rem;color:var(--muted);font-family:var(--mono);font-variant-numeric:tabular-nums}
.hstate{display:inline-flex;align-items:center;gap:.4rem;font-size:.68rem;font-weight:700;
 padding:.2rem .6rem;border-radius:6px;letter-spacing:.04em;text-transform:uppercase;
 border:1px solid transparent;font-family:var(--mono)}
.hstate::before{content:'';width:.42rem;height:.42rem;border-radius:50%;background:currentColor}
.hstate.healthy{color:var(--low);background:color-mix(in srgb,var(--low) 14%,transparent);border-color:color-mix(in srgb,var(--low) 30%,transparent)}
.hstate.converging{color:var(--med);background:color-mix(in srgb,var(--med) 16%,transparent);border-color:color-mix(in srgb,var(--med) 32%,transparent)}
.hstate.degraded{color:var(--crit);background:color-mix(in srgb,var(--crit) 14%,transparent);border-color:color-mix(in srgb,var(--crit) 30%,transparent)}
.hstate.partial{color:var(--high);background:color-mix(in srgb,var(--high) 15%,transparent);border-color:color-mix(in srgb,var(--high) 30%,transparent)}
.hstate.unknown{color:var(--info);background:color-mix(in srgb,var(--info) 15%,transparent);border-color:color-mix(in srgb,var(--info) 30%,transparent)}
.sevbar .n-ready,.sevleg .n-ready{background:var(--low)}
.sevbar .n-not_ready,.sevleg .n-not_ready{background:var(--crit)}
.sevbar .n-unknown,.sevleg .n-unknown{background:var(--info)}
.sevbar .p-Running,.sevleg .p-Running{background:var(--low)}
.sevbar .p-Pending,.sevleg .p-Pending{background:var(--med)}
.sevbar .p-Failed,.sevleg .p-Failed{background:var(--crit)}
.sevbar .p-Succeeded,.sevleg .p-Succeeded{background:var(--info)}
.sevbar .p-Unknown,.sevleg .p-Unknown{background:var(--muted)}
/* ---- cluster telemetry card --------------------------------------------
   A four-column SecOps readout: infrastructure health, workload privilege, cluster-edge
   exposure, runtime sensor. Each column is self-contained, so a bar always sits directly
   under the counter it describes rather than spanning the card and belonging to nothing. */
.tgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;
 border:1px solid var(--bd);border-radius:10px;overflow:hidden;background:var(--sunken)}
@media(max-width:1180px){.tgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:640px){.tgrid{grid-template-columns:minmax(0,1fr)}}
.tcol{padding:.8rem .9rem .85rem;display:flex;flex-direction:column;gap:.7rem;
 border-right:1px solid var(--bd);background:var(--card)}
.tcol:last-child{border-right:0}
@media(max-width:1180px){
  .tcol:nth-child(even){border-right:0}
  .tcol:nth-child(-n+2){border-bottom:1px solid var(--bd)}
}
@media(max-width:640px){
  .tcol{border-right:0;border-bottom:1px solid var(--bd)}
  .tcol:last-child{border-bottom:0}
}
/* Column heading, the same micro-label register the KPI tiles use. */
.tch{display:flex;align-items:center;gap:.4rem;font-size:.66rem;font-weight:700;
 text-transform:uppercase;letter-spacing:.11em;color:var(--muted);font-family:var(--mono);
 padding-bottom:.5rem;border-bottom:1px solid var(--bd)}
.tch .tci{margin-left:auto;font-weight:600;letter-spacing:.04em;text-transform:none}
/* A metric: label, value, and its own bar immediately beneath. */
.tm .tmk{font-size:.665rem;font-weight:650;text-transform:uppercase;letter-spacing:.09em;
 color:var(--muted);font-family:var(--mono);display:flex;align-items:baseline;gap:.4rem}
.tm .tmk .tmn{margin-left:auto;font-variant-numeric:tabular-nums;letter-spacing:.02em}
.tm .tmv{font-size:1.32rem;font-weight:750;line-height:1.05;letter-spacing:-.03em;
 margin:.2rem 0 .35rem;font-variant-numeric:tabular-nums;font-feature-settings:'tnum'}
.tm .tmv .sub{font-size:.76rem;font-weight:600;color:var(--muted);margin-left:.08rem;font-family:var(--mono)}
.tm.ok .tmv{color:var(--low)}.tm.warn .tmv{color:var(--high)}
.tm.bad .tmv{color:var(--crit)}.tm.unk .tmv{color:var(--info);font-size:1rem}
/* Compact stacked bar, paired with the metric above it. */
.mbar{display:flex;height:5px;border-radius:3px;overflow:hidden;background:var(--sunken);
 box-shadow:inset 0 0 0 1px var(--bd)}
.mbar span{display:block;height:100%}
.mleg{display:flex;flex-wrap:wrap;gap:.2rem .7rem;margin-top:.4rem;font-size:.68rem;color:var(--muted)}
.mleg>span{display:inline-flex;align-items:center;gap:.32rem}
.mleg i{width:6px;height:6px;border-radius:2px;flex:0 0 auto}
.mleg b{color:var(--fg);font-weight:700;font-family:var(--mono);font-variant-numeric:tabular-nums}
/* Risk rows: a named posture metric, its count, and a share-of-total rail. */
.trow{display:flex;flex-direction:column;gap:.28rem}
.trow .trh{display:flex;align-items:baseline;gap:.5rem;font-size:.755rem}
.trow .trh .trl{color:var(--fg);font-weight:550}
.trow .trh .trv{margin-left:auto;font-weight:750;font-family:var(--mono);
 font-variant-numeric:tabular-nums;font-size:.83rem}
.trow .trh .trs{font-size:.68rem;color:var(--muted);font-family:var(--mono)}
.trow.zero .trh .trv{color:var(--low)}
.trow.hot .trh .trv{color:var(--crit)}
.trow.warm .trh .trv{color:var(--high)}
.trail{height:4px;border-radius:3px;background:var(--sunken);box-shadow:inset 0 0 0 1px var(--bd);overflow:hidden}
.trail span{display:block;height:100%;border-radius:3px}
/* Key/value footer inside a column (version, namespace count). */
.tkv{display:flex;flex-wrap:wrap;gap:.35rem .9rem;margin-top:auto;padding-top:.6rem;
 border-top:1px solid var(--bd)}
.tkv>div{display:flex;flex-direction:column;gap:.15rem;min-width:0}
.tkv .kk{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.11em;
 color:var(--muted);font-family:var(--mono)}
.tkv .kv{font-size:.79rem;font-weight:650;color:var(--fg);font-variant-numeric:tabular-nums;
 white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tkv .kv.mono{font-family:var(--mono);font-size:.75rem}
/* Sensor heartbeat. */
.beat{display:inline-flex;align-items:center;gap:.4rem;font-size:.68rem;font-weight:700;
 padding:.18rem .55rem;border-radius:6px;letter-spacing:.04em;text-transform:uppercase;
 font-family:var(--mono);border:1px solid transparent}
.beat::before{content:'';width:.42rem;height:.42rem;border-radius:50%;background:currentColor}
.beat.live{color:var(--low);background:color-mix(in srgb,var(--low) 14%,transparent);border-color:color-mix(in srgb,var(--low) 30%,transparent)}
.beat.idle{color:var(--info);background:color-mix(in srgb,var(--info) 15%,transparent);border-color:color-mix(in srgb,var(--info) 30%,transparent)}
.beat.off{color:var(--high);background:color-mix(in srgb,var(--high) 15%,transparent);border-color:color-mix(in srgb,var(--high) 30%,transparent)}
.tnote{font-size:.7rem;color:var(--muted);line-height:1.4}
/* ---- scan context bar ---------------------------------------------------
   Was a raw monospace run-on line that read as debug output. Now labelled fields:
   each fact carries its own key, so scope / mode / time / id are distinguishable
   without parsing separators. */
.ctxbar{display:flex;align-items:stretch;flex-wrap:wrap;gap:0;background:var(--card);
 border:1px solid var(--bd);border-radius:10px;margin:0 0 1rem;overflow:hidden}
.ctxbar .cf{display:flex;flex-direction:column;gap:.22rem;padding:.6rem .95rem;min-width:0;
 flex:0 1 auto;position:relative}
/* Divider as an inset pseudo-rule rather than a border: when the bar wraps, a trailing
   border-right paints a rule at the end of a row with nothing after it. This draws
   BEFORE each field except the first in its row, and a wrapped field starts a new row
   at x=0, so the rule is suppressed by the same left-edge test. */
.ctxbar .cf+.cf::before{content:'';position:absolute;left:0;top:.55rem;bottom:.55rem;
 width:1px;background:var(--bd)}
.ctxbar .cf .cfk{font-size:.66rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;
 color:var(--muted);font-family:var(--mono)}
.ctxbar .cf .cfv{font-size:.78rem;color:var(--fg);font-weight:600;white-space:nowrap;overflow:hidden;
 text-overflow:ellipsis;font-variant-numeric:tabular-nums}
.ctxbar .cf .cfv.mono{font-family:var(--mono);font-size:.735rem;font-weight:550}
.ctxbar .cf.inv{margin-left:auto}
.ctxbar .cf.inv .cfv{display:flex;gap:.7rem}
.ctxbar .cf.inv b{font-weight:700;font-family:var(--mono)}
/* A vertical divider cannot know it sits at the start of a wrapped row, so below the
   wrap point the bar becomes an explicit grid: no vertical rules, row rules instead.
   That removes the dangling dividers rather than trying to detect the wrap in CSS. */
@media(max-width:820px){
  .ctxbar{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}
  .ctxbar .cf{margin-left:0}
  .ctxbar .cf+.cf::before{display:none}
  .ctxbar .cf:nth-child(n+3){border-top:1px solid var(--bd)}
  .ctxbar .cf:nth-child(even){border-left:1px solid var(--bd)}
  .ctxbar .cf.inv{grid-column:1/-1;border-left:0;margin-left:0}
}
.sysline{font-family:var(--mono);font-size:.735rem;color:var(--muted);margin:.1rem 0 .6rem;
 display:flex;align-items:center;flex-wrap:wrap;gap:.55rem;letter-spacing:.01em}
.sysline .dot{width:3px;height:3px;border-radius:50%;background:var(--bd);display:inline-block;flex:0 0 auto}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;margin:1.25rem 0}@media(max-width:820px){.grid2{grid-template-columns:1fr}}
.fm{font-size:.8rem;color:var(--muted);line-height:1.5}
.fm code,code{background:var(--sunken);padding:.08rem .38rem;border-radius:5px;border:1px solid var(--bd);overflow-wrap:anywhere}
/* controls */
.ctl{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;margin:1rem 0}
.ctl input,.ctl select{background:var(--card);color:var(--fg);border:1px solid var(--bd);
 border-radius:9px;padding:.52rem .75rem;font-size:.87rem;transition:border-color .15s,box-shadow .15s}
.ctl input:focus,.ctl select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.ctl input[type=search]{flex:1;min-width:220px}
.chip{font-size:.76rem;padding:.4rem .85rem;border-radius:999px;border:1px solid var(--bd);
 background:var(--card);color:var(--muted);cursor:pointer;transition:all .16s;font-weight:600}
.chip:hover{border-color:color-mix(in srgb,var(--accent) 45%,var(--bd));color:var(--fg)}
.chip.on{color:#fff;border-color:transparent}
.chip.on[data-sev=CRITICAL]{background:var(--crit)}.chip.on[data-sev=HIGH]{background:var(--high)}
.chip.on[data-sev=MEDIUM]{background:var(--med)}.chip.on[data-sev=LOW]{background:var(--low)}
/* findings table */
table.ft{width:100%;border-collapse:separate;border-spacing:0;font-size:.855rem}
table.ft th{text-align:left;color:var(--muted);font-weight:600;font-size:.66rem;text-transform:uppercase;
 letter-spacing:.1em;font-family:var(--mono);padding:.55rem .65rem;border-bottom:1px solid var(--bd);cursor:pointer;white-space:nowrap;position:sticky;top:0;background:var(--card);z-index:1}
table.ft td{padding:.68rem .65rem;border-bottom:1px solid var(--bd);vertical-align:top}
table.ft tbody tr{transition:background .12s}
table.ft tbody tr:hover td{background:var(--sunken)}
table.ft td b{font-weight:600}
/* severity + status badges, tinted, calm, high-contrast */
.sev{display:inline-block;font-size:.68rem;font-weight:700;padding:.16rem .5rem;border-radius:6px;
 letter-spacing:.02em;line-height:1.35;border:1px solid transparent}
.sev.CRITICAL{color:var(--crit);background:color-mix(in srgb,var(--crit) 14%,transparent);border-color:color-mix(in srgb,var(--crit) 30%,transparent)}
.sev.HIGH{color:var(--high);background:color-mix(in srgb,var(--high) 15%,transparent);border-color:color-mix(in srgb,var(--high) 30%,transparent)}
.sev.MEDIUM{color:var(--med);background:color-mix(in srgb,var(--med) 16%,transparent);border-color:color-mix(in srgb,var(--med) 32%,transparent)}
.sev.LOW{color:var(--low);background:color-mix(in srgb,var(--low) 15%,transparent);border-color:color-mix(in srgb,var(--low) 30%,transparent)}
.sev.INFO{color:var(--info);background:color-mix(in srgb,var(--info) 16%,transparent);border-color:color-mix(in srgb,var(--info) 30%,transparent)}
/* matrix */
.mx{display:grid;grid-template-columns:repeat(9,1fr);gap:6px;margin:1rem 0;overflow-x:auto}
.mxcol{display:flex;flex-direction:column;gap:5px;min-width:80px}
.mxh{font-size:.62rem;font-weight:600;color:var(--muted);text-align:center;height:2.8em;line-height:1.2;
 display:flex;align-items:center;justify-content:center;text-transform:uppercase;letter-spacing:.05em;font-family:var(--mono)}
.cell{border-radius:7px;padding:.4rem .35rem;font-size:.62rem;min-height:38px;border:1px solid var(--bd);
 cursor:default;color:#fff;display:flex;flex-direction:column;justify-content:center;gap:2px;transition:transform .2s var(--ease-out),box-shadow .2s}
.cell.gap{background:var(--sunken);color:var(--muted);border-color:var(--bd)}.cell.covered{background:var(--low);border-color:transparent}
.cell.runtime{background:color-mix(in srgb,var(--rt) 12%,transparent);color:var(--rt);border:1px dashed var(--rt);font-weight:600}
.cell.hit{cursor:pointer;border-color:transparent}.cell.hit:hover{transform:scale(1.06);box-shadow:0 3px 8px rgba(16,24,40,.2)}
.cell.hit[data-sev=CRITICAL]{background:var(--crit)}.cell.hit[data-sev=HIGH]{background:var(--high)}
.cell.hit[data-sev=MEDIUM]{background:var(--med)}.cell.hit[data-sev=LOW]{background:var(--low)}
.cell .c{font-weight:800;font-size:.78rem}
.leg{display:flex;gap:1.2rem;font-size:.75rem;color:var(--muted);flex-wrap:wrap;margin-top:.7rem}
.leg i{display:inline-block;width:13px;height:13px;border-radius:4px;vertical-align:-2px;margin-right:.4rem}
/* attack path */
.flow{display:flex;align-items:stretch;gap:.7rem;flex-wrap:wrap;margin:1rem 0}
.step{background:var(--card);border:1px solid var(--bd);border-left:2px solid var(--crit);border-radius:9px;
 padding:.85rem .9rem;min-width:150px;flex:1;box-shadow:none;cursor:pointer;
 transition:transform .2s var(--ease-out),border-color .2s,background .2s}
.step:hover{transform:translateY(-2px);background:var(--sunken)}
.step.sel{box-shadow:0 0 0 2px var(--accent);transform:translateY(-2px)}
.step .t{font-weight:650;font-size:.88rem;color:var(--fg);display:flex;align-items:center;justify-content:space-between;gap:.4rem;letter-spacing:-.01em}
.step .t .num{font-size:.68rem;font-weight:700;color:var(--muted);background:var(--sunken);border:1px solid var(--bd);border-radius:50%;
 width:1.5em;height:1.5em;display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto}
.step .k{font-size:.75rem;color:var(--muted);margin-top:.4rem;line-height:1.45}
.step .cnt{font-size:.72rem;color:var(--muted);margin-top:.5rem;font-weight:600}
.arrow{display:flex;align-items:center;color:var(--bd);font-size:1.3rem;padding:0 .2rem}
.reach{font-weight:650}.reach.y{color:var(--crit)}.reach.n{color:var(--low)}
.tchip{display:inline-block;font-size:.72rem;padding:.22rem .6rem;margin:.15rem .3rem .15rem 0;border-radius:999px;
 border:1px solid var(--bd);background:var(--card);color:var(--muted)}
.clk{cursor:pointer}
/* attack path, force graph (cytoscape) */
#atk-graph{height:520px;border:1px solid var(--bd);border-radius:12px;margin-top:1rem;background:var(--sunken);position:relative}
.atk-tip{position:absolute;display:none;pointer-events:none;background:var(--fg);color:var(--bg);
 font-size:.72rem;font-weight:600;padding:.32rem .55rem;border-radius:7px;white-space:nowrap;z-index:5;
 box-shadow:0 4px 12px rgba(16,24,40,.25)}
.graphhint{font-size:.76rem;color:var(--muted);margin-top:.5rem;line-height:1.5}
/* resource-layer attack routes, and the RBAC / network detail they carry */
.rpath{border:1px solid var(--bd);border-radius:10px;padding:.75rem .85rem;margin:.7rem 0;background:var(--sunken)}
.rphead{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap;margin-bottom:.55rem}
.hops{display:flex;align-items:center;flex-wrap:wrap;gap:.3rem;margin:.35rem 0 .5rem}
.hop{display:inline-flex;align-items:baseline;gap:.35rem;font-size:.79rem;font-family:var(--mono);
 background:var(--card);border:1px solid var(--bd);border-radius:7px;padding:.2rem .5rem;cursor:help}
.hop.obs{border-color:var(--crit);box-shadow:inset 2px 0 0 var(--crit)}
.hop .hk{font-size:.66rem;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.harrow{color:var(--muted);font-size:.8rem}
.plist{margin:.4rem 0 .2rem;padding-left:1.1rem;font-size:.79rem;line-height:1.7}
.plist code{font-size:.92em}
.rbacpath{display:flex;align-items:center;flex-wrap:wrap;gap:.3rem;margin:.3rem 0 .5rem}
.impact{background:var(--sunken);border:1px solid var(--bd);border-radius:12px;padding:.9rem 1rem;margin-top:.8rem;font-size:.83rem}
.impact>div{margin-bottom:.5rem}
/* risk bars */
.bar{display:flex;align-items:center;gap:.8rem;margin-bottom:.7rem}
.barl{width:170px;font-size:.8rem;flex:0 0 auto;font-weight:550}
.bart{flex:1;height:24px;background:var(--sunken);border-radius:7px;overflow:hidden;border:1px solid var(--bd)}
.barf{height:100%;display:flex;align-items:center;justify-content:flex-end;padding-right:.6rem;color:#fff;
 font-size:.71rem;font-weight:650;white-space:nowrap;min-width:fit-content;border-radius:7px}
.trendbars{display:flex;align-items:flex-end;gap:6px;height:100px;margin-top:1rem}
.tb{flex:1;border-radius:5px 5px 0 0;min-height:8px;transition:opacity .2s}
/* runtime */
.rr{display:flex;align-items:center;gap:.6rem;font-size:.86rem;padding:.5rem 0;border-bottom:1px solid var(--bd)}
.rr:last-child{border-bottom:0}
.rrdot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.rrdot.ok{background:var(--low);box-shadow:0 0 0 3px color-mix(in srgb,var(--low) 20%,transparent)}
.rrdot.gap{background:var(--high);box-shadow:0 0 0 3px color-mix(in srgb,var(--high) 20%,transparent)}
.rrn{margin-left:auto;font-size:.75rem;color:var(--muted)}.rrn.warn{color:var(--high);font-weight:600}
textarea{width:100%;min-height:140px;background:var(--card);color:var(--fg);border:1px solid var(--bd);
 border-radius:11px;padding:.85rem;font-family:var(--mono);font-size:.82rem;transition:border-color .15s,box-shadow .15s}
textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
button.btn{background:var(--accent);color:#fff;border:0;border-radius:9px;padding:.6rem 1.15rem;
 font-size:.87rem;font-weight:600;cursor:pointer;transition:filter .15s,transform .15s,box-shadow .15s;box-shadow:var(--shadow)}
button.btn:hover{filter:brightness(1.07);transform:translateY(-1px);box-shadow:0 4px 12px var(--ring)}
button.btn:active{transform:translateY(0);filter:brightness(.97)}
button.btn.ghost{background:var(--card);color:var(--fg);border:1px solid var(--bd);box-shadow:none}
button.btn.ghost:hover{background:var(--sunken);border-color:color-mix(in srgb,var(--accent) 45%,var(--bd));filter:none}
.corr{border:1px solid var(--bd);border-left:3px solid var(--info);background:var(--card);border-radius:10px;padding:.85rem .9rem;margin-bottom:.6rem;box-shadow:var(--shadow)}
.corr.confirmed{border-left-color:var(--crit)}.corr.corroborated{border-left-color:var(--high)}
.corr.runtime-only{border-left-color:var(--info)}
.corr-cands{margin:.2rem 0 .3rem 1.1rem;padding:0;font-size:.78rem;color:var(--muted)}.corr-cands li{margin:.1rem 0}
.badge{display:inline-block;font-size:.66rem;font-weight:700;padding:.16rem .5rem;border-radius:6px;text-transform:uppercase;letter-spacing:.03em;border:1px solid transparent}
.badge.confirmed{color:var(--crit);background:color-mix(in srgb,var(--crit) 14%,transparent);border-color:color-mix(in srgb,var(--crit) 30%,transparent)}
.badge.corroborated{color:var(--high);background:color-mix(in srgb,var(--high) 15%,transparent);border-color:color-mix(in srgb,var(--high) 30%,transparent)}
.badge.runtime-only{color:var(--info);background:color-mix(in srgb,var(--info) 15%,transparent);border-color:color-mix(in srgb,var(--info) 30%,transparent)}
/* scan form */
.scanform{display:flex;flex-wrap:wrap;gap:.9rem;align-items:end}
.scanform label{font-size:.74rem;color:var(--muted);display:block;margin-bottom:.4rem;font-weight:600}
.scanform input,.scanform select{background:var(--card);color:var(--fg);border:1px solid var(--bd);
 border-radius:9px;padding:.52rem .75rem;font-size:.87rem;min-width:150px;transition:border-color .15s,box-shadow .15s}
.scanform input:focus,.scanform select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.scanform .kc{display:flex;flex-direction:column;gap:.35rem;min-width:270px}
.scanform .kc input[type=file]{padding:.4rem;font-size:.8rem}
.scanform .kc-or{font-size:.72rem;color:var(--muted);text-align:center;margin:.1rem 0}
#kubeconfigfilename{font-size:.74rem;color:var(--muted)}
#scanmsg{font-size:.84rem;margin-top:.9rem;color:var(--muted);font-weight:500}
.scanerr,.scanwarn{margin-top:.7rem;border-radius:10px;padding:.8rem .9rem;border:1px solid var(--bd)}
.scanerr{border-left:3px solid var(--crit);background:color-mix(in srgb,var(--crit) 5%,var(--card))}
.scanwarn{border-left:3px solid var(--high);background:color-mix(in srgb,var(--high) 5%,var(--card))}
.scanerr pre{margin:.4rem 0 0;white-space:pre-wrap;font-family:var(--mono);font-size:.78rem;color:var(--fg)}
.scanwarn ul{margin:.35rem 0 0;padding-left:1.1rem;font-size:.79rem}
/* scan-health banners, an unread cluster must never read as a clean one */
.healthbar{border-radius:12px;padding:.95rem 1.1rem;margin:1.1rem 0;border:1px solid var(--bd)}
.healthbar.bad{border-color:color-mix(in srgb,var(--crit) 45%,var(--bd));border-left:4px solid var(--crit);background:color-mix(in srgb,var(--crit) 5%,var(--card))}
.healthbar.partial{border-left:4px solid var(--high);background:color-mix(in srgb,var(--high) 5%,var(--card))}
.healthbar .hb-t{font-weight:700;font-size:.92rem}
.healthbar.bad .hb-t{color:var(--crit)}.healthbar.partial .hb-t{color:var(--high)}
.healthbar .hb-l{margin:.5rem 0 .4rem;padding-left:1.15rem;font-size:.8rem;color:var(--muted)}
.healthbar .hb-f{font-size:.82rem;color:var(--fg)}
.healthnote{border-left:3px solid var(--crit);background:color-mix(in srgb,var(--crit) 6%,var(--card));border:1px solid color-mix(in srgb,var(--crit) 25%,var(--bd));
 border-radius:10px;padding:.6rem .8rem;margin:0 0 .9rem;font-size:.83rem;font-weight:550;color:var(--crit)}
a{color:var(--accent)}
/* inline finding details, expands below the table, no navigation away */
table.ft tbody tr.sel td{background:color-mix(in srgb,var(--accent) 8%,var(--card))}
table.ft tbody tr.sel td:first-child{box-shadow:inset 2px 0 0 var(--accent)}
table.ft tbody tr.fdrow>td{padding:.15rem 0 1rem;border-bottom:1px solid var(--bd);background:transparent}
table.ft tbody tr.fdrow:hover>td{background:transparent}
.fdrow .fdcard{margin:.25rem 0 .2rem}
.fcaret{display:inline-block;transition:transform .2s;color:var(--muted);font-size:1rem}
.fcaret.open{transform:rotate(90deg);color:var(--accent)}
.fdcard{border:1px solid var(--bd);border-top:2px solid var(--accent);border-radius:12px;background:var(--card);
 padding:1.2rem 1.3rem;margin:1rem 0 .2rem;animation:fdopen .26s var(--ease-out)}
@keyframes fdopen{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.fdcard .fdh{display:flex;align-items:flex-start;gap:.9rem}
.fdcard .fdt{flex:1;min-width:0}
.fdcard h3{font-size:1.02rem;font-weight:650;margin:.35rem 0 0;letter-spacing:-.012em;line-height:1.35}
.fdsub{display:flex;flex-wrap:wrap;gap:.45rem;align-items:center}
.fdclose{background:var(--card);border:1px solid var(--bd);border-radius:8px;color:var(--muted);cursor:pointer;
 font-size:.76rem;font-weight:600;padding:.42rem .75rem;font-family:var(--font);display:inline-flex;align-items:center;gap:.35rem;transition:all .15s;flex:0 0 auto}
.fdclose:hover{color:var(--fg);border-color:color-mix(in srgb,var(--accent) 45%,var(--bd));background:var(--sunken)}
.fdmeta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0 1rem;margin:1.05rem 0;
 border-top:1px solid var(--bd);border-bottom:1px solid var(--bd);padding:.55rem 0}
.fdmeta .m{padding:.45rem 0}
.fdmeta .mk{font-size:.6rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-family:var(--mono);margin-bottom:.25rem}
.fdmeta .mv{font-size:.84rem;color:var(--fg);font-weight:500;word-break:break-word}
.fdsec{margin:.95rem 0}
.fdsec .sh{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-family:var(--mono);margin-bottom:.45rem}
.fdsec p{margin:0;font-size:.87rem;line-height:1.6;color:var(--fg)}
.fdchips{display:flex;flex-wrap:wrap;gap:.35rem}
pre.fdev{background:var(--sunken);border:1px solid var(--bd);border-radius:8px;padding:.75rem .85rem;
 font-family:var(--mono);font-size:.77rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;margin:0;overflow:auto;max-height:280px}
.fdfoot{margin-top:1.05rem;padding-top:.9rem;border-top:1px solid var(--bd);display:flex;gap:.9rem;flex-wrap:wrap;align-items:baseline}
.fdlink{color:var(--accent);text-decoration:none;font-weight:600;font-size:.85rem}
.fdlink:hover{text-decoration:underline}
/* export menu + toast */
.exp{position:relative}
.exp summary{list-style:none;cursor:pointer}
.exp summary::-webkit-details-marker{display:none}
.exp summary.btn{display:inline-flex;align-items:center;gap:.4rem;background:var(--accent);color:#fff;
 border:1px solid var(--accent);border-radius:9px;padding:.5rem .95rem;font-size:.83rem;font-weight:650;
 box-shadow:var(--shadow);white-space:nowrap}
.exp summary.btn:hover{filter:brightness(1.07)}
.exp[open] summary.btn{filter:brightness(.94)}
.exp-menu{position:absolute;right:0;top:calc(100% + .4rem);z-index:20;background:var(--card);
 border:1px solid var(--bd);border-radius:10px;box-shadow:0 8px 24px rgba(16,24,40,.14);
 padding:.35rem;min-width:172px;display:flex;flex-direction:column;gap:.1rem}
.exp-menu button{text-align:left;background:none;border:0;border-radius:7px;padding:.5rem .7rem;
 font:inherit;font-size:.84rem;color:var(--fg);cursor:pointer;transition:background .12s,color .12s}
.exp-menu button:hover{background:var(--sunken);color:var(--accent)}
.toast{position:fixed;right:1.1rem;bottom:1.1rem;z-index:100;background:var(--fg);color:var(--bg);
 font-size:.85rem;font-weight:550;padding:.7rem 1rem;border-radius:10px;box-shadow:0 8px 24px rgba(16,24,40,.25);
 opacity:0;transform:translateY(8px);pointer-events:none;transition:opacity .2s,transform .2s;max-width:min(90vw,360px)}
.toast.show{opacity:1;transform:none}
.toast.err{background:var(--crit);color:#fff}
/* ---- accessibility affordances ------------------------------------------
   Keyboard operators reach the same controls a mouse does. */
.vh{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.skip{position:absolute;left:-9999px;top:0;z-index:200;background:var(--accent);color:#fff;
 padding:.6rem 1rem;border-radius:0 0 9px 0;font-size:.85rem;font-weight:650;text-decoration:none}
.skip:focus{left:0}
main:focus{outline:none}
.view[hidden]{display:none!important}
/* Promoted controls get the same focus treatment as native ones. */
.cell[tabindex],.step[tabindex],.chip[tabindex],tr.clk[tabindex],table.ft th[tabindex]{outline-offset:-2px}
tr.clk:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
table.ft th[onclick]{cursor:pointer;user-select:none}
/* Nav wrapped into three stacked rows on a phone. One scrolling rail instead. */
.navlinks{display:flex;align-items:center;gap:.15rem;flex-wrap:wrap;min-width:0}
@media(max-width:820px){
  .topbar{flex-wrap:nowrap;gap:.35rem}
  .topbar .brand{font-size:1rem;flex:0 0 auto}
  .topbar .grow{display:none}
  .navlinks{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none;margin-left:auto;
   -webkit-overflow-scrolling:touch}
  .navlinks::-webkit-scrollbar{display:none}
  .topbar a.nav{white-space:nowrap;padding:.4rem .55rem;font-size:.8rem}
}
/* ---- production polish --------------------------------------------------
   Scrollbars, panel headers, alignment and contrast details that separate a working
   layout from a finished console. */
/* Scrollbars: the browser default light track cut a bright band through every dark
   surface. Themed, thin, and only as visible as it needs to be. */
*{scrollbar-width:thin;scrollbar-color:var(--bd) transparent}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bd);border-radius:6px;border:2px solid var(--bg);
 background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:var(--muted);background-clip:padding-box;border:2px solid var(--bg)}
::-webkit-scrollbar-corner{background:transparent}
/* Panel headers carry an optional right-aligned meta slot, so a panel's context sits on
   its title line instead of as a loose paragraph underneath it. */
.panel h2 .pmeta{margin-left:auto;font-size:.735rem;font-weight:500;color:var(--muted);
 letter-spacing:0;text-transform:none;font-family:var(--font)}
.panel h2 .hstate+.pmeta{margin-left:.1rem}
/* Tabular figures wherever numbers stack, so digits align into columns. */
table.ft td,.barf,.rrn,.kpi .s,.repbar .meta{font-variant-numeric:tabular-nums}
/* Findings table: sticky header needed a solid backdrop and a real bottom rule, or rows
   scrolled through it. */
table.ft th{background:var(--card);box-shadow:inset 0 -1px 0 var(--bd)}
table.ft tbody tr:last-child td{border-bottom:0}
/* Report bar: align the control row on a single baseline and give the select room. */
.repbar{padding:.65rem .9rem}
.repbar select{font-variant-numeric:tabular-nums}
/* Tabs: a slightly heavier active rule reads as a selected state at a glance. */
.tab{padding:.6rem .1rem}
.tab.on{border-bottom-width:2px}
/* Focus visibility, keyboard operators included. */
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
/* Muted text was the lowest-contrast element on the page and carried real information
   (counts, captions, metadata). Lift it a step without losing the hierarchy. */
.fm,.sysline,.kpi .s{color:var(--muted)}
.mcard .mh .mn,.rail .rl .rn{font-variant-numeric:tabular-nums}
@media (prefers-reduced-motion:reduce){*{animation-duration:.001ms!important;transition-duration:.001ms!important}}
@media(max-width:640px){.wrap{padding:1rem .8rem}.kpi .n{font-size:1.9rem}.tabs{width:100%}}
"""


def layout(title: str, body: str, *, extra_css: str = "") -> str:
    # THEME_JS runs last so it can label any .themebtn the body rendered.
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_esc(title)}</title><style>{_HTML_CSS}{_DASH_CSS}{_SIDE_CSS}{_AMBIENT_CSS}{extra_css}</style></head>"
            f"<body><canvas id='ambient' aria-hidden='true'></canvas><a class='skip' href='#main'>Skip to content</a>"
            f"<div class='wrap'><main id='main' tabindex='-1'>{body}</main></div>"
            f"<script>{THEME_JS}</script><script>{_AMBIENT_JS}</script></body></html>")


_NAV_ICONS = {
    "overview": "<rect x='3' y='3' width='7' height='9' rx='1.5'/><rect x='14' y='3' width='7' height='5' rx='1.5'/><rect x='14' y='12' width='7' height='9' rx='1.5'/><rect x='3' y='16' width='7' height='5' rx='1.5'/>",
    "issues": "<path d='M12 3l10 18H2z'/><path d='M12 10v5M12 18v.5'/>",
    "graph": "<circle cx='5' cy='6' r='2.5'/><circle cx='19' cy='6' r='2.5'/><circle cx='12' cy='18' r='2.5'/><path d='M7 7l4 9M17 7l-4 9M7.5 6h9'/>",
    "matrix": "<rect x='3' y='3' width='5' height='5'/><rect x='10' y='3' width='5' height='5'/><rect x='17' y='3' width='4' height='5'/><rect x='3' y='10' width='5' height='5'/><rect x='10' y='10' width='5' height='5'/><rect x='17' y='10' width='4' height='5'/><rect x='3' y='17' width='5' height='4'/><rect x='10' y='17' width='5' height='4'/>",
    "cluster": "<path d='M12 3l8 4v10l-8 4-8-4V7z'/><path d='M4 7l8 4 8-4M12 11v10'/>",
    "runtime": "<path d='M3 12h4l2-6 4 12 2-6h6'/>",
    "scans": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "tasks": "<path d='M5 4h14M5 12h14M5 20h14'/><path d='M3 4l.5.5L5 3M3 12l.5.5L5 11M3 20l.5.5L5 19'/>",
    "changes": "<path d='M4 7h12M4 12h16M4 17h9'/><path d='M18 5l3 2-3 2M16 15l3 2-3 2'/>",
    "incident": "<circle cx='11' cy='11' r='6'/><path d='M20 20l-4.5-4.5M11 8v3l2 1'/>",
    "start": "<circle cx='12' cy='12' r='9'/><path d='M10 8l6 4-6 4z'/>",
    "policies": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M8 12h8M8 9h8M8 15h5'/>",
    "deps": "<circle cx='12' cy='5' r='2.5'/><circle cx='5' cy='19' r='2.5'/><circle cx='19' cy='19' r='2.5'/><path d='M12 7.5v4M12 11.5L6 17M12 11.5l6 5.5'/>",
    "build": "<rect x='3' y='3' width='7' height='7' rx='1'/><rect x='14' y='3' width='7' height='7' rx='1'/><rect x='3' y='14' width='7' height='7' rx='1'/><path d='M17.5 14v7M14 17.5h7'/>",
    "risks": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M9 12l2 2 4-4'/>",
}

# (sidebar key, label, href, group)  The dashboard views are addressed by hash and switched in
# place by the page's own script; everything else is a real page.
_NAV = [
    ("start", "Start here", "/#start", None),
    ("overview", "Overview", "/#overview", None),
    ("issues", "Issues", "/#issues", "Investigate"),
    ("graph", "Attack paths", "/graph", "Investigate"),
    ("matrix", "Threat matrix", "/#matrix", "Investigate"),
    ("changes", "What changed", "/#changes", "Investigate"),
    ("incident", "Investigate a workload", "/#incident", "Investigate"),
    ("cluster", "Cluster", "/#cluster", "Environment"),
    ("policies", "Policy review", "/#policies", "Environment"),
    ("runtime", "Runtime", "/#runtime", "Environment"),
    ("deps", "Dependencies", "/#deps", "Environment"),
    ("build", "Build an app", "/#build", "Build"),
    ("scans", "Scans", "/#scans", "Scans"),
    ("tasks", "Tasks", "/#tasks", "Scans"),
    ("risks", "Accepted risks", "/#risks", "Scans"),
]
# pages other than the dashboard name themselves with their own key
_ACTIVE = {"home": "", "graph": "graph", "matrix": "matrix", "runtime-events": "runtime",
           "runtime": "runtime"}


def _topbar(active: str = "") -> str:
    """The left navigation, shared by every page. On the dashboard the script marks the current
    view from the URL hash; other pages pass their own key."""
    cur = _ACTIVE.get(active, active)
    out, group = [], object()
    for key, label, href, grp in _NAV:
        if grp != group:
            group = grp
            if grp:
                out.append(f"<div class='side-h'>{grp}</div>")
        on = " class='on' aria-current='page'" if key == cur else ""
        badge = {"issues": "<span class='cnt' id='nav-issues'></span>",
                 "graph": "<span class='cnt' id='nav-paths'></span>"}.get(key, "")
        out.append(f"<a data-nav='{key}' href='{href}'{on}><svg viewBox='0 0 24 24' fill='none' "
                   f"stroke='currentColor' stroke-width='1.8' stroke-linecap='round' "
                   f"stroke-linejoin='round' aria-hidden='true'>{_NAV_ICONS[key]}</svg>"
                   f"<span>{label}</span>{badge}</a>")
    return ("<nav class='side' aria-label='Primary'>"
            "<div class='side-top'><a class='brand' href='/'><span class='mark' aria-hidden='true'>K8</span>"
            "K8sMatrixWarden</a>"
            "<button class='side-btn' type='button' aria-label='Menu' aria-expanded='false' "
            "onclick=\"var n=this.closest('.side');var o=n.classList.toggle('open');"
            "this.setAttribute('aria-expanded',o)\">&#9776;</button></div>"
            "<div class='side-body'>" + "".join(out) +
            "<div class='side-foot'><a class='side-api' href='/api/reports'>API</a>"
            "<button class='side-amb' type='button' aria-pressed='true' title='Ambient background' "
            "onclick='window.__ambient&&window.__ambient()'>&#10022; Ambient</button>"
            + THEME_BUTTON + "</div></div></nav>")


_AMBIENT_CSS = """
#ambient{position:fixed;left:0;top:0;width:100vw;height:100vh;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1}
/* cards are a touch see-through so the characters under the cursor can show through them */
.panel,.mc-c,.cv-tile,.cv-a,.ap,.sg-bar,.sg-detail,.sg-chain,.repbar,.mcard{background:color-mix(in srgb,var(--card) 82%,transparent)}
.side-amb{background:none;border:1px solid var(--bd);border-radius:8px;color:var(--muted);font-size:.78rem;padding:.3rem .55rem;cursor:pointer}
.side-amb[aria-pressed='true']{color:var(--accent);border-color:var(--accent)}
@media print{#ambient{display:none}}
"""

_AMBIENT_JS = r"""
/* Ambient background: columns of characters drift down the page. Most are invisible; the ones
   near the pointer light up, so moving the mouse reveals what is flowing underneath.
   Off for reduced-motion and touch by default, paused when the tab is hidden, 30 fps at most. */
(function(){
  var c=document.getElementById('ambient'); if(!c||!c.getContext) return;
  var KEY='k8smw-ambient', ctx=c.getContext('2d');
  var saved=null; try{saved=localStorage.getItem(KEY)}catch(e){}
  var calm=matchMedia('(prefers-reduced-motion: reduce)').matches||matchMedia('(hover: none)').matches;
  var on=saved?saved==='on':!calm;
  var FS=15,R=230,GL='01abcdef{}[]<>/\\:;=+-*#$@%&kKsS8.',W,H,cols=[],mx=-1e4,my=-1e4,raf=0,last=0,base='#8a94a6',hot='#2cc5d8';
  function colors(){var cs=getComputedStyle(document.documentElement);base=cs.getPropertyValue('--muted').trim()||base;hot=cs.getPropertyValue('--accent').trim()||hot;}
  function rc(){return GL.charAt((Math.random()*GL.length)|0);}
  function size(){
    var d=Math.min(window.devicePixelRatio||1,2);W=innerWidth;H=innerHeight;c.width=W*d;c.height=H*d;
    ctx.setTransform(d,0,0,d,0,0);ctx.font=FS+'px ui-monospace,SFMono-Regular,Menlo,monospace';ctx.textBaseline='top';
    cols=[];for(var i=0,n=Math.ceil(W/FS);i<n;i++){var len=8+((Math.random()*22)|0),g=[];for(var k=0;k<len;k++)g.push(rc());
      cols.push({x:i*FS,y:Math.random()*H,v:25+Math.random()*70,g:g,lit:Math.random()<.3});}
  }
  function frame(t){
    raf=requestAnimationFrame(frame); if(t-last<33) return; var dt=Math.min((t-last)/1000,.1); last=t;
    ctx.clearRect(0,0,W,H);
    for(var i=0;i<cols.length;i++){
      var col=cols[i]; col.y+=col.v*dt;
      if(col.y-col.g.length*FS>H){col.y=-Math.random()*H*.4;col.v=25+Math.random()*70;col.lit=Math.random()<.3;}
      if(Math.random()<.04) col.g[(Math.random()*col.g.length)|0]=rc();
      var dx=col.x-mx; if(dx<0)dx=-dx; var near=dx<R;
      for(var k=0;k<col.g.length;k++){
        var gy=col.y-k*FS; if(gy<-FS||gy>H) continue;
        var a=col.lit?(1-k/col.g.length)*.10:0, h=0;
        if(near){var dy=gy-my,d=Math.sqrt(dx*dx+dy*dy); if(d<R){h=1-d/R;h=h*h*(col.lit?1:.9);}}
        if(h>a){ctx.fillStyle=hot;ctx.globalAlpha=h;} else if(a>.01){ctx.fillStyle=base;ctx.globalAlpha=a;} else continue;
        ctx.fillText(col.g[k],col.x,gy);
      }
    }
    ctx.globalAlpha=1;
  }
  function start(){if(!raf&&!document.hidden){last=0;raf=requestAnimationFrame(frame);}}
  function stop(){if(raf){cancelAnimationFrame(raf);raf=0;} ctx.clearRect(0,0,W,H);}
  function sync(){document.querySelectorAll('.side-amb').forEach(function(b){b.setAttribute('aria-pressed',on);});}
  window.__ambient=function(v){on=(typeof v==='boolean')?v:!on;try{localStorage.setItem(KEY,on?'on':'off')}catch(e){} sync(); on?start():stop();};
  addEventListener('pointermove',function(e){mx=e.clientX;my=e.clientY;},{passive:true});
  document.addEventListener('pointerleave',function(){mx=my=-1e4;});
  addEventListener('resize',function(){size();});
  document.addEventListener('visibilitychange',function(){document.hidden?stop():(on&&start());});
  new MutationObserver(colors).observe(document.documentElement,{attributes:true});
  colors();size();sync();if(on)start();
})();
"""

_SIDE_CSS = """
.side{position:fixed;left:0;top:0;bottom:0;width:236px;z-index:40;display:flex;flex-direction:column;
 background:var(--card);border-right:1px solid var(--bd);padding:1rem .75rem;overflow-y:auto}
.side-top{display:flex;align-items:center;justify-content:space-between;padding:0 .35rem .9rem}
.side .brand{font-size:1.05rem;font-weight:750;color:var(--fg);text-decoration:none;display:flex;align-items:center;gap:.55rem;letter-spacing:-.02em}
.side .brand .mark{width:1.6rem;height:1.6rem;border-radius:7px;background:linear-gradient(150deg,var(--accent),#155e75);
 display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:.75rem;font-weight:800;font-family:var(--mono)}
.side-btn{display:none;background:none;border:1px solid var(--bd);border-radius:8px;color:var(--fg);font-size:1.1rem;padding:.2rem .55rem;cursor:pointer}
.side-body{display:flex;flex-direction:column;gap:.1rem;flex:1}
.side-h{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:700;margin:1.1rem .6rem .3rem}
.side a[data-nav]{display:flex;align-items:center;gap:.65rem;padding:.55rem .65rem;border-radius:9px;color:var(--muted);
 text-decoration:none;font-size:.88rem;font-weight:560;border:1px solid transparent}
.side a[data-nav] svg{width:18px;height:18px;flex:0 0 auto}
.side a[data-nav]:hover{background:var(--sunken);color:var(--fg)}
.side a[data-nav].on{background:var(--sunken);color:var(--accent);border-color:var(--bd)}
.side a[data-nav] span:not(.cnt){flex:1}
.side .cnt{font-size:.7rem;font-weight:700;background:var(--bd);color:var(--fg);border-radius:999px;padding:.05rem .45rem;min-width:1.3rem;text-align:center}
.side .cnt:empty{display:none}
.side-foot{margin-top:auto;padding-top:1rem;display:flex;align-items:center;justify-content:space-between;gap:.5rem;border-top:1px solid var(--bd)}
.side-api{font-size:.8rem;color:var(--muted);text-decoration:none;padding:.3rem .5rem}.side-api:hover{color:var(--fg)}
.wrap{max-width:none!important;margin:0!important;padding-left:calc(236px + 1.75rem)!important;padding-right:1.75rem!important}
@media(max-width:900px){
 .side{position:sticky;width:auto;border-right:0;border-bottom:1px solid var(--bd);padding:.6rem .8rem;overflow:visible}
 .side-top{padding-bottom:0}.side-btn{display:block}
 .side-body{display:none;padding-top:.6rem}.side.open .side-body{display:flex}
 .wrap{padding:0 .8rem 1rem!important}
}
"""


def topology_page(result: ScanResult) -> str:
    """The Security graph page (web/graph_page.py)."""
    from .graph_page import graph_page
    return graph_page(result, layout, _topbar, _APP_CSS + _MC_CSS)


_MC_CSS = """
.mc{display:grid;grid-template-columns:1fr 1.3fr 1.3fr;gap:.9rem;margin:1rem 0}
@media(max-width:1100px){.mc{grid-template-columns:1fr 1fr}}.mc-more2{margin-top:.7rem;font-size:.78rem}.mc-more2 a{color:var(--accent);text-decoration:none;font-weight:550}@media(max-width:620px){.mc{grid-template-columns:1fr}}
.mc-c{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:1rem 1.1rem;min-width:0}
.mc-c h3{font-size:.74rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:0 0 .6rem;font-weight:650}
.mc-risk{text-align:center;border-top:3px solid var(--bd)}.mc-risk.crit{border-top-color:var(--crit)}.mc-risk.warn{border-top-color:var(--med)}.mc-risk.good{border-top-color:var(--low)}
.dial{width:100%;max-width:210px;display:block;margin:0 auto}.dial .gn{font-size:34px;font-weight:750;fill:var(--fg)}.dial .gs{font-size:11px;fill:var(--muted)}
.mc-rate{font-size:1.15rem;font-weight:750;margin-top:-.2rem}.mc-sub{font-size:.78rem;color:var(--muted);margin-top:.25rem}
.mc-d .delta{margin-right:.3rem}
.mc-row{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.donut{flex:0 0 auto}.donut .dn{font-size:25px;font-weight:750;fill:var(--fg)}.donut .ds{font-size:10px;fill:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.mc-leg{list-style:none;margin:0;padding:0;flex:1;min-width:110px}
.mc-leg li{display:flex;align-items:center;gap:.45rem;font-size:.82rem;padding:.2rem 0}
.mc-leg i{width:.65rem;height:.65rem;border-radius:3px;flex:0 0 auto}.mc-leg span{flex:1;color:var(--muted)}.mc-leg b{font-variant-numeric:tabular-nums}
.mc-tiles{display:grid;grid-template-columns:1fr 1fr;gap:.55rem}
.mc-t{border:1px solid var(--bd);border-radius:10px;padding:.6rem .7rem;background:var(--sunken)}
.mc-t b{display:block;font-size:1.55rem;line-height:1.1;font-variant-numeric:tabular-nums}.mc-t span{font-size:.74rem;color:var(--muted);line-height:1.25;display:block}
.mc-t small{color:var(--muted);font-size:.7rem}
.mc-t.crit b{color:var(--crit)}.mc-t.warn b{color:var(--high)}.mc-t.good b{color:var(--low)}
.mc-inv{display:flex;gap:.4rem 1rem;flex-wrap:wrap;font-size:.76rem;color:var(--muted);margin-top:.7rem;padding-top:.6rem;border-top:1px solid var(--bd)}
.mc-inv b{color:var(--fg);font-variant-numeric:tabular-nums}
.drivers summary{cursor:pointer;font-weight:650;font-size:.9rem}.drivers[open] summary{margin-bottom:.8rem}
.mc-more{margin-left:auto;font-size:.78rem;font-weight:550;color:var(--accent);text-decoration:none}
.ap-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:.8rem}
.ap{display:block;text-decoration:none;color:var(--fg);border:1px solid var(--bd);border-radius:12px;padding:.8rem .9rem;background:var(--sunken);transition:transform .12s,box-shadow .12s}
.ap:hover{transform:translateY(-2px);box-shadow:0 6px 16px rgba(16,24,40,.1)}
.ap-h{display:flex;align-items:center;gap:.5rem;font-size:.78rem;color:var(--muted);margin-bottom:.7rem}.ap-h b{margin-left:auto;color:var(--fg)}
.ap-c{display:flex;align-items:flex-start;gap:.15rem;overflow-x:auto;padding-bottom:.2rem}
.ap-n{flex:0 0 auto;width:64px;text-align:center}.ap-n i{display:flex;width:34px;height:34px;margin:0 auto .25rem;border:2px solid var(--bd);border-radius:50%;
 align-items:center;justify-content:center;font-style:normal;background:var(--card);font-size:.95rem}
.ap-n em{display:block;font-style:normal;font-size:.66rem;color:var(--muted);line-height:1.2;word-break:break-word}
.ap-a{align-self:flex-start;margin-top:.45rem;color:var(--muted)}
"""


_CV_CSS = """

.po-head h2{margin:.2rem 0 .1rem}.po-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.7rem;margin:.8rem 0 1rem}
.po-tile{display:flex;flex-direction:column;gap:.25rem;align-items:flex-start;text-align:left;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:.8rem .9rem;cursor:pointer;color:var(--fg);font:inherit;position:relative}
.po-tile:hover{border-color:var(--accent)}.po-tile.on{border-color:var(--accent);box-shadow:0 0 0 2px var(--sunken)}
.po-tile b{font-size:.92rem}.po-n{font-size:.78rem;color:var(--muted);line-height:1.35}.po-tile small{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.po-dot{position:absolute;top:.85rem;right:.85rem;width:10px;height:10px;border-radius:50%;background:var(--low)}
.po-tile.warn .po-dot{background:var(--med)}.po-tile.bad .po-dot{background:var(--crit)}
.po-tile.ok small{color:var(--low)}.po-tile.warn small{color:var(--med)}.po-tile.bad small{color:var(--crit)}
.po-grid{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(280px,1fr);gap:1rem;align-items:start}@media(max-width:1000px){.po-grid{grid-template-columns:1fr}}
.po-dh{display:flex;gap:.7rem;align-items:center}.po-dh h3{margin:0;font-size:1.1rem}.po-lead{margin:.7rem 0 .9rem;color:var(--muted);font-size:.9rem;line-height:1.5;max-width:68ch}
.po-act{display:flex;gap:1rem;align-items:center;flex-wrap:wrap;margin-bottom:.9rem;font-size:.86rem}
.po-learn{border:1px solid var(--bd);border-radius:10px;padding:.55rem .8rem;margin-bottom:1rem}.po-learn summary{cursor:pointer;font-size:.84rem;color:var(--muted)}.po-learn p{margin:.5rem 0 0;font-size:.84rem;color:var(--muted);line-height:1.45}
.po-rl{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:.4rem}
.po-side h3{margin:0 0 .2rem;font-size:.95rem}.po-m{width:100%;border-collapse:collapse;font-size:.82rem}.po-m th{text-align:center;color:var(--muted);font-weight:600;font-size:.7rem;padding:.3rem .2rem}.po-m th:first-child,.po-m td:first-child{text-align:left}
.po-m td{padding:.4rem .2rem;border-top:1px solid var(--bd);text-align:center}.po-m small{display:block;color:var(--muted);font-size:.7rem}
.po-c{width:26px;height:26px;border-radius:50%;border:0;cursor:pointer;font-weight:700;font-size:.8rem}.po-c.ok{background:rgba(26,127,55,.15);color:var(--low)}.po-c.bad{background:rgba(209,36,47,.14);color:var(--crit)}
.pol-h{display:flex;flex-wrap:wrap;gap:.7rem;align-items:center;margin-bottom:.6rem}.pol-h h3{margin:0;font-size:1.02rem}.pol-big{color:var(--muted);font-size:.86rem;margin-left:auto}
.pol-g{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:.8rem}.pol-g p{margin:.25rem 0 0;color:var(--muted);font-size:.84rem;line-height:1.45}
.pol details{border-top:1px solid var(--bd);padding-top:.6rem}.pol summary{cursor:pointer;color:var(--muted);font-size:.84rem;margin-bottom:.5rem}
.pol-a{display:flex;flex-wrap:wrap;gap:1rem;align-items:center;margin-top:.8rem;font-size:.86rem}
.st-step{display:flex;gap:1rem;background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:1rem 1.1rem;margin-bottom:.8rem}
.st-step.done{opacity:.8}.st-n{flex:0 0 2rem;height:2rem;border-radius:50%;background:var(--sunken);color:var(--accent);display:grid;place-items:center;font-weight:700}
.st-step.done .st-n{background:rgba(26,127,55,.15);color:var(--low)}.st-b{flex:1}.st-b h3{margin:.1rem 0 .3rem;font-size:1rem}
.st-a{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.7rem}.st-iss{display:flex;gap:.6rem;align-items:center;margin:.3rem 0;font-size:.86rem}.st-iss small{color:var(--muted)}
.st-gl{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1rem;margin:.8rem 0 0;font-size:.86rem}.st-gl dt{font-weight:650}.st-gl dd{margin:0;color:var(--muted)}
.b-wrap{display:grid;gap:1rem}.b-top{display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;align-items:flex-end}
.b-top h2{margin:0 0 .3rem}.b-help{color:var(--muted);font-size:.86rem;margin:.2rem 0 .6rem;max-width:62ch}
.b-names{display:flex;gap:.8rem;align-items:end;flex-wrap:wrap}.b-names label,.b-fields label{font-size:.74rem;color:var(--muted);font-weight:600;display:block}
.b-names input,.b-fields input,.b-fields select,.b-fields textarea{display:block;margin-top:.3rem;width:100%;box-sizing:border-box;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:9px;padding:.5rem .65rem;font:inherit;font-size:.86rem}
.b-names input{width:200px}.b-ghost{background:none;border:1px solid var(--bd);color:var(--muted);border-radius:9px;padding:.5rem .8rem;cursor:pointer}
.b-grid{display:grid;grid-template-columns:230px minmax(320px,1fr) minmax(300px,420px);gap:1rem;align-items:start}
@media(max-width:1100px){.b-grid{grid-template-columns:1fr 1fr}.b-res{grid-column:1/-1}}@media(max-width:700px){.b-grid{grid-template-columns:1fr}}
.b-grid h3{margin:0 0 .7rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.b-tile{display:flex;gap:.6rem;padding:.6rem;border:1px solid var(--bd);border-radius:10px;margin-bottom:.5rem;cursor:grab;background:var(--card)}
.b-tile:hover,.b-tile:focus{border-color:var(--accent);outline:0}.b-tile small,.b-card small{display:block;color:var(--muted);font-size:.74rem;line-height:1.3;margin-top:.15rem}
.b-dot{width:10px;height:10px;border-radius:50%;flex:0 0 auto;margin-top:.35rem}
.b-canvas{min-height:130px;border:2px dashed var(--bd);border-radius:12px;padding:.6rem;display:grid;gap:.5rem}
.b-canvas.over{border-color:var(--accent);background:var(--sunken)}
.b-card{display:flex;gap:.6rem;align-items:center;padding:.6rem .7rem;border:1px solid var(--bd);border-radius:10px;background:var(--card);cursor:pointer}
.b-card>div{flex:1}.b-card.on{border-color:var(--accent);box-shadow:0 0 0 2px var(--sunken)}
.b-drop{display:grid;gap:.5rem;justify-items:center;text-align:center;padding:1rem;color:var(--muted)}
.b-tpls{display:grid;gap:.5rem;width:100%}.b-tpls button{text-align:left;border:1px solid var(--bd);background:var(--card);border-radius:10px;padding:.6rem .8rem;cursor:pointer;color:var(--fg);font:inherit}
.b-tpls button:hover{border-color:var(--accent)}.b-tpls small{display:block;color:var(--muted);font-size:.76rem;margin-top:.15rem}
.b-form{margin-top:1rem;border-top:1px solid var(--bd);padding-top:.9rem}.b-fh{display:flex;gap:.5rem;align-items:center}.b-fh a{margin-left:auto;font-size:.84rem}
.b-fields{display:grid;gap:.75rem}.b-fields small{display:block;color:var(--muted);font-weight:400;margin-top:.25rem;font-size:.74rem}
.b-chk{display:block}.b-chk input{width:auto;display:inline;margin:0 .4rem 0 0}.b-adv{border:1px solid var(--bd);border-radius:9px;padding:.6rem .75rem}.b-adv summary{cursor:pointer;font-size:.84rem;color:var(--muted)}
.b-empty{color:var(--muted);font-size:.86rem;padding:.8rem}.b-warn{border-left:3px solid var(--med);background:var(--sunken);padding:.6rem .8rem;border-radius:8px}.b-warn p{margin:.3rem 0 0}
.b-tabs{display:flex;gap:.3rem;margin-bottom:.8rem}.b-tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:.4rem .7rem;cursor:pointer;color:var(--muted);font:inherit;font-size:.84rem}
.b-tabs button.on{color:var(--accent);border-color:var(--accent);font-weight:650}
.b-verdict{padding:.6rem .8rem;border-radius:9px;font-weight:650;font-size:.88rem;margin-bottom:.7rem}.b-verdict.ok{background:rgba(26,127,55,.12);color:var(--low)}.b-verdict.bad{background:rgba(209,36,47,.1);color:var(--crit)}
.b-iss{border-top:1px solid var(--bd);padding:.6rem 0;cursor:pointer}.b-iss b{margin:0 .4rem}.b-iss small{color:var(--muted)}.b-iss p{margin:.3rem 0 0;font-size:.82rem;color:var(--muted)}
.tk-seg{display:inline-flex;border:1px solid var(--bd);border-radius:10px;overflow:hidden;margin:.2rem 0 .9rem}
.tk-seg button{background:var(--card);color:var(--muted);border:0;padding:.5rem .95rem;font:inherit;font-size:.84rem;cursor:pointer}
.tk-seg button.on{background:var(--sunken);color:var(--accent);font-weight:650}
.tk-fields{display:flex;flex-wrap:wrap;gap:.9rem;align-items:end;margin:.7rem 0}
.tk-fields label{font-size:.74rem;color:var(--muted);font-weight:600;display:block}
.tk-fields input,.tk-fields textarea{display:block;margin-top:.35rem;min-width:220px;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:9px;padding:.55rem .7rem;font:inherit;font-size:.86rem}
.tk-wide{flex:1 1 100%}.tk-wide input,.tk-wide textarea{width:100%;box-sizing:border-box}
.tk-chk{display:flex!important;align-items:center;gap:.5rem;font-weight:500!important}.tk-chk input{min-width:0;margin:0}
.tk-row{border-top:1px solid var(--bd);padding:.7rem 0}.tk-row:first-child{border-top:0}
.tk-main{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center}.tk-main small{color:var(--muted)}
.tk-act{margin-left:auto;display:flex;gap:.9rem;font-size:.84rem}
.tk-err{margin-top:.4rem;color:var(--crit);font-size:.84rem}.tk-last{margin-top:.3rem;font-family:ui-monospace,monospace;font-size:.76rem}
.tk-log{margin:.55rem 0 0;background:var(--sunken);border:1px solid var(--bd);border-radius:9px;padding:.7rem;max-height:280px;overflow:auto;font-size:.74rem;white-space:pre-wrap}
.cv-head{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap;margin:.2rem 0 .9rem}.cv-head h2{margin:0;font-size:1.25rem}
.cv-ver{margin-left:auto;font-size:.8rem;color:var(--muted);font-family:var(--mono)}
.cv-st{display:inline-block;font-size:.74rem;font-weight:650;padding:.12rem .55rem;border-radius:999px;border:1px solid var(--bd);background:var(--sunken)}
.cv-st.ok{color:var(--low)}.cv-st.warn{color:var(--med)}.cv-st.bad{color:var(--crit);border-color:var(--crit)}
.cv-ok{color:var(--muted);font-size:.8rem}
.cv-calm{border:1px solid var(--bd);border-left:4px solid var(--low);border-radius:10px;padding:.8rem 1rem;background:var(--card);margin-bottom:1rem;font-size:.9rem}
.cv-attn{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:.6rem;margin-bottom:1rem}
.cv-a{display:grid;grid-template-columns:auto 1fr auto;gap:.1rem .6rem;align-items:center;text-align:left;border:1px solid var(--bd);border-radius:10px;
 padding:.65rem .8rem;background:var(--card);color:var(--fg);cursor:pointer}
.cv-a:hover{border-color:var(--accent)}.cv-a b{font-size:.86rem}.cv-a small{grid-column:2;color:var(--muted);font-size:.76rem}.cv-a i{grid-row:1/3;grid-column:3;font-style:normal;color:var(--muted);font-size:1.3rem}
.cv-vt{width:100%;border-collapse:collapse;font-size:.78rem;margin:.3rem 0}.cv-drawer:has(.cv-vt){width:min(620px,100vw)}.cv-vt td code{word-break:break-all;font-size:.72rem}.cv-vt .sev{white-space:nowrap}.cv-vt small{display:block}.cv-vt th{text-align:left;color:var(--muted);font-weight:600;padding:.25rem .4rem}.cv-vt td{padding:.3rem .4rem;border-top:1px solid var(--bd);vertical-align:top}
.cv-tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.6rem;margin-bottom:1rem}
.cv-tile{display:flex;flex-direction:column;align-items:flex-start;gap:.1rem;text-align:left;border:1px solid var(--bd);border-radius:12px;padding:.7rem .85rem;background:var(--card);color:var(--fg);cursor:pointer;min-width:0}
.cv-tile:hover{border-color:var(--accent);transform:translateY(-1px)}.cv-tile.on{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent);background:var(--sunken)}
.cv-n{font-size:1.65rem;font-weight:750;line-height:1.1;font-variant-numeric:tabular-nums}.cv-l{font-size:.78rem;font-weight:650}
.cv-tile small{font-size:.7rem;color:var(--muted);line-height:1.3}.cv-tile em{font-style:normal;font-size:.7rem;font-weight:650}
.cv-tile.bad em,.cv-tile.bad .cv-n{color:var(--crit)}.cv-tile.warn em{color:var(--med)}
.cv-body{margin:0 0 1rem}.cv-bar{display:flex;gap:.7rem 1rem;flex-wrap:wrap;align-items:center;margin-bottom:.6rem}
.cv-ttl{flex:1 1 280px}.cv-ttl h2{margin:0;font-size:1.05rem}.cv-ttl span{font-size:.8rem;color:var(--muted)}
.cv-q{flex:0 1 240px;padding:.45rem .65rem;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg);font-size:.85rem}
.cv-f{display:flex;gap:.3rem;flex-wrap:wrap}.cv-f button{border:1px solid var(--bd);background:var(--card);color:var(--muted);border-radius:999px;padding:.28rem .7rem;font-size:.76rem;cursor:pointer}
.cv-f button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.cv-count{font-size:.76rem;color:var(--muted);margin:.2rem 0 .4rem}.cv-scroll{overflow-x:auto;max-height:560px;overflow-y:auto}
.cv-t{width:100%;border-collapse:collapse;font-size:.84rem}.cv-t th{position:sticky;top:0;background:var(--card);text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:.4rem .6rem;border-bottom:1px solid var(--bd);white-space:nowrap}
.cv-t th button{all:unset;cursor:pointer}.cv-t td{padding:.5rem .6rem;border-bottom:1px solid var(--bd);vertical-align:top}
.cv-t tbody tr{cursor:pointer}.cv-t tbody tr:hover,.cv-t tbody tr:focus{background:var(--sunken);outline:none}
.cv-t td small{display:block;color:var(--muted);font-size:.72rem;margin-top:.1rem}.cv-t code{font-size:.76rem}.cv-none{text-align:center;color:var(--muted);padding:1.5rem}
.cv-chip{display:inline-block;font-size:.68rem;padding:.08rem .45rem;margin:.08rem .15rem .08rem 0;border-radius:999px;border:1px solid var(--bd);background:var(--sunken)}
.cv-chip.hot{border-color:var(--crit);color:var(--crit)}
.cv-drawer{position:fixed;top:0;right:0;bottom:0;width:min(420px,100vw);z-index:60;background:var(--card);border-left:1px solid var(--bd);box-shadow:-12px 0 32px rgba(16,24,40,.22);
 padding:1.2rem 1.2rem 2rem;overflow:auto;transform:translateX(105%);transition:transform .2s ease}
.b-layer{display:flex;gap:.6rem;align-items:flex-start;border-top:1px solid var(--bd);padding:.5rem 0;font-size:.82rem}.b-layer>div{flex:1}.b-layer small,.b-layer em{display:block;color:var(--muted);font-style:normal;margin-top:.1rem}.b-layer.warn em,.b-layer.bad em{color:var(--fg)}.b-comp{list-style:none;margin:.3rem 0 0;padding:0;font-size:.78rem}.b-comp li.hd{color:var(--muted);text-transform:uppercase;font-size:.68rem;letter-spacing:.05em}.b-comp li.on{color:var(--ok,#1a7f37)}.b-comp li.off{color:var(--bad,#d1242f)}.b-appr{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.4rem}.b-appr label{font-size:.7rem;color:var(--muted)}.b-appr input{display:block;font-size:.78rem;padding:.2rem .4rem;max-width:9.5rem}.b-side{font-size:.72rem;color:var(--muted);white-space:nowrap}.b-scan{margin:.3rem 0 .6rem}.b-designs{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin-top:.6rem}.b-designs select{max-width:16rem}
.bd{display:grid;gap:.9rem}
.bd-head{display:flex;flex-wrap:wrap;gap:.8rem 1.2rem;align-items:center;justify-content:space-between;padding:.7rem 1rem}
.bd-id{display:flex;flex-direction:column;gap:.1rem}.bd-id small{color:var(--muted);font-size:.74rem;padding-left:.55rem}
.bd-app{font-size:1.2rem;font-weight:700;color:var(--fg);background:transparent;border:1px solid transparent;border-radius:8px;padding:.2rem .5rem;width:15rem;max-width:100%}
.bd-app:hover,.bd-app:focus{border-color:var(--bd);background:var(--card);outline:0}
.bd-state{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap}.bd-state small{color:var(--muted)}
.bd-acts{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.bd-btn{background:var(--card);border:1px solid var(--bd);color:var(--fg);border-radius:9px;padding:.4rem .75rem;font-size:.82rem;cursor:pointer;list-style:none}
.bd-btn:hover{border-color:var(--accent)}.bd-btn::-webkit-details-marker{display:none}
.bd-menu{position:relative}.bd-pop{margin-top:.6rem}
.bd-sep{border-top:1px solid var(--bd);margin:.8rem 0}
.bd-row2{display:flex;gap:.4rem;margin-top:.5rem}
.bd-grid{display:grid;grid-template-columns:270px minmax(0,1fr) 400px;gap:.9rem;align-items:start}
@media(max-width:1180px){.bd-grid{grid-template-columns:250px minmax(0,1fr)}.bd-panel{grid-column:1/-1}}
@media(max-width:760px){.bd-grid{grid-template-columns:1fr}}
.bd-list.over{outline:2px dashed var(--accent)}
.bd-lh{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;margin:.1rem 0 .5rem;display:flex;gap:.4rem;align-items:center}
.bd-lh small{background:var(--sunken);border-radius:999px;padding:0 .45rem}.bd-add{margin-top:1.1rem}
.bd-row{display:flex;gap:.55rem;align-items:center;width:100%;text-align:left;background:transparent;border:1px solid transparent;border-radius:9px;padding:.45rem .5rem;cursor:pointer;color:var(--fg)}
.bd-row:hover{background:var(--sunken)}.bd-row.on{background:var(--sunken);border-color:var(--accent)}
.bd-rt{flex:1;min-width:0}.bd-rt b{display:block;font-size:.84rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bd-rt small{display:block;color:var(--muted);font-size:.72rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bd-dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.bd-tm{margin:.5rem 0}.bd-tmh{display:flex;justify-content:space-between;align-items:center;font-size:.8rem;margin:.6rem 0 .2rem}.bd-tmi{display:flex;gap:.5rem;font-size:.76rem;padding:.2rem 0}.bd-tmi.on span{color:var(--ok,#1a7f37)}.bd-tmi.off span{color:var(--crit,#d1242f)}.bd-tmi small{display:block;color:var(--muted)}.bd-resid{margin:.3rem 0;padding-left:1.1rem;font-size:.76rem;color:var(--muted)}.bd-resid li{margin:.25rem 0}
.bd-env{font-size:.76rem;color:var(--muted);background:var(--sunken);border-radius:8px;padding:.45rem .6rem;margin-bottom:.6rem}.bd-choices{display:flex;flex-direction:column;gap:.35rem;margin-top:.5rem;align-items:flex-start}
.bd-fl{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;font-size:.8rem;padding:.3rem 0;border-top:1px solid var(--bd)}.bd-fl small{color:var(--muted);flex:1}.bd-cnt{float:right;color:var(--muted);font-weight:400;font-size:.74rem}.bd-th{display:flex;gap:.5rem;align-items:flex-start;font-size:.78rem;padding:.35rem 0;border-top:1px solid var(--bd)}.bd-th>div{flex:1;min-width:0}.bd-th small{display:block;color:var(--muted)}.bd-th small.r{font-style:italic}.bd-stride{background:var(--sunken);border-radius:6px;padding:.05rem .4rem;font-weight:700;font-size:.72rem}
.rt-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}.rt-head h2{margin:0}.rt-bar{display:flex;gap:.8rem;align-items:center;flex-wrap:wrap;margin-bottom:.8rem}.rt-bar .cv-q{max-width:20rem}
.rt-w{max-width:26rem;color:var(--muted);font-size:.8rem}.rt-step{margin:0 0 1.2rem}.rt-step h3{margin:.1rem 0 .6rem;font-size:.95rem}.rt-l{display:block;font-size:.78rem;color:var(--muted);font-weight:600}
.rt-l input,.rt-l select,.rt-l textarea,.rt-exc input,.rt-exc select{display:block;margin-top:.28rem;width:100%;box-sizing:border-box;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:9px;padding:.45rem .6rem;font:inherit;font-size:.86rem}
.rt-l small{display:block;color:var(--muted);font-weight:400;margin-top:.2rem;font-size:.74rem}.rt-exc{display:grid;grid-template-columns:12rem 1fr auto;gap:.5rem;margin-bottom:.4rem;align-items:center}.rt-exc select,.rt-exc input{margin:0}
.rt-agent .rt-ah{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}.rt-agent .rt-ah small{display:block;color:var(--muted)}.rt-ac{font-size:.82rem;margin:.4rem 0}.rt-bar2{height:8px;background:var(--sunken);border-radius:999px;overflow:hidden;margin:.5rem 0 .2rem}.rt-bar2 i{display:block;height:100%}.rt-bar2 i.ok{background:var(--ok,#1a7f37)}.rt-bar2 i.warn{background:var(--med,#d97706)}.rt-bar2 i.bad{background:var(--crit,#d1242f)}.rt-chips{display:flex;gap:.4rem;flex-wrap:wrap}
.rt-ul{margin:.3rem 0 .8rem;padding-left:1.2rem;font-size:.86rem}.rt-ul li{margin:.2rem 0}.rt-row{display:flex;gap:.6rem;align-items:flex-end;flex-wrap:wrap;margin:.6rem 0}.rt-ev{font-family:ui-monospace,monospace;font-size:.7rem}.rt-pre{white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:.72rem}
.bd-head{background:var(--card)!important;position:sticky;top:3.6rem;z-index:30;box-shadow:0 6px 14px -12px rgba(0,0,0,.35)}.bd-state{display:flex;gap:.7rem;align-items:center;flex-wrap:wrap}
.bd-prog{width:120px;height:6px;border-radius:999px;background:var(--sunken);overflow:hidden}.bd-prog i{display:block;height:100%;background:#1a7f37;border-radius:999px;transition:width .3s}
.bd-add{margin-top:1rem;border-top:1px solid var(--bd);padding-top:.6rem}.bd-add summary{cursor:pointer;font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;margin-bottom:.5rem}
.bd-nice summary{cursor:pointer;font-size:.76rem;color:var(--muted);padding:.35rem 0;border-top:1px solid var(--bd)}
@media(min-width:1181px){.bd-list,.bd-panel{position:sticky;top:8.2rem;max-height:calc(100vh - 9rem);overflow:auto}}
.dp-grid{display:grid;grid-template-columns:300px minmax(0,1fr);gap:.9rem;align-items:start}@media(max-width:900px){.dp-grid{grid-template-columns:1fr}}
.dp-list{max-height:calc(100vh - 12rem);overflow:auto}.dp-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:.6rem;margin:.7rem 0}.dp-t{border:1px solid var(--bd);border-radius:10px;padding:.5rem .7rem}.dp-t b{display:block;font-size:1.3rem}.dp-t b.r{color:#d1242f}.dp-t small{color:var(--muted);font-size:.72rem}
.dp-f{display:flex;gap:.35rem;flex-wrap:wrap;margin:.6rem 0}.bd-chip.on{border-color:var(--accent);background:var(--sunken)}
.dp-r{border-top:1px solid var(--bd)}.dp-rb{display:flex;gap:.5rem;align-items:center;width:100%;background:transparent;border:0;padding:.45rem .2rem;cursor:pointer;color:var(--fg);text-align:left;font:inherit}.dp-rb b{min-width:9rem;font-size:.84rem}.dp-rb small{flex:1;color:var(--muted);font-size:.74rem}
.dp-d{padding:.2rem .4rem .6rem;font-size:.78rem;color:var(--muted)}.dp-d b{color:var(--fg)}.dp-res{margin-top:.6rem;max-height:14rem;overflow:auto}
.bd-sf{border:1px solid var(--bd,#d0d7de);border-left:3px solid #3b82f6;border-radius:10px;padding:.6rem .8rem;margin-bottom:.9rem}.bd-sf.bad{border-left-color:#d1242f}.bd-sf.ok{border-left-color:#1a7f37}.bd-sfh{display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem}.bd-sf small{display:block;color:var(--muted);font-size:.76rem}.bd-sfr{display:flex;gap:.5rem;align-items:flex-start;padding:.3rem 0;border-top:1px solid var(--bd,#d0d7de);font-size:.8rem}.bd-sfr>div{flex:1;min-width:0}.bd-sfr.ok span{color:#1a7f37}.bd-sfr.bad span{color:#d1242f}.bd-sfr.opt span{color:var(--muted)}
.bd-gl{font-size:.66rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:.6rem .5rem .15rem;font-weight:700}.bd-none{color:var(--muted);font-size:.84rem;padding:.6rem .2rem}
.bd-pal{display:grid;gap:.55rem}.bd-pg{display:flex;flex-wrap:wrap;gap:.3rem;align-items:center}.bd-pg>span{width:100%;font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.bd-chip{display:inline-flex;gap:.35rem;align-items:center;background:var(--card);border:1px solid var(--bd);border-radius:999px;padding:.22rem .6rem;font-size:.76rem;color:var(--fg);cursor:pointer}
.bd-chip i{width:7px;height:7px;border-radius:50%}.bd-chip:hover{border-color:var(--accent)}
.bd-ih{display:flex;gap:.6rem;align-items:center;margin-bottom:.8rem}.bd-ih>div{flex:1}.bd-ih small{display:block;color:var(--muted);font-size:.78rem}
.bd-sec{border:1px solid var(--bd);border-radius:10px;margin:.5rem 0;background:var(--card)}
.bd-sec>summary{cursor:pointer;padding:.55rem .8rem;font-weight:650;font-size:.84rem;list-style:none}.bd-sec>summary::-webkit-details-marker{display:none}
.bd-sec>summary::before{content:'\\25B8';display:inline-block;margin-right:.45rem;color:var(--muted)}.bd-sec[open]>summary::before{content:'\\25BE'}
.bd-sec>div{padding:0 .8rem .8rem}
.bd-fields{display:grid;gap:.7rem}
.bd-insp label,.bd-pop label{display:block;font-size:.74rem;color:var(--muted);font-weight:600}
.bd-insp input:not([type=checkbox]),.bd-insp select,.bd-insp textarea,.bd-pop input:not([type=checkbox]),.bd-pop select{display:block;margin-top:.28rem;width:100%;box-sizing:border-box;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:9px;padding:.45rem .6rem;font:inherit;font-size:.86rem}
.bd-insp small,.bd-pop small{display:block;color:var(--muted);font-weight:400;margin-top:.2rem;font-size:.74rem}
.bd-chk{display:flex!important;gap:.5rem;align-items:flex-start}.bd-chk input{width:auto!important;margin:.15rem 0 0!important}.bd-chk span{flex:1}
.bd-scan{margin:-.2rem 0 .2rem}.bd-note{color:var(--muted);font-size:.8rem;margin:.4rem 0}
.bd-gh h2{margin:0 0 .3rem}.bd-gh p{color:var(--muted);font-size:.86rem;max-width:62ch;margin:.2rem 0 1rem}
.bd-gs{margin:1.2rem 0 .5rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.bd-gal{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:.6rem}
.bd-pat{text-align:left;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:.8rem;cursor:pointer;color:var(--fg);display:grid;gap:.3rem;align-content:start}
.bd-pat:hover,.bd-pat.on{border-color:var(--accent);box-shadow:0 0 0 2px var(--sunken)}.bd-pat b{font-size:.92rem}.bd-pat small{color:var(--muted);font-size:.78rem;line-height:1.35}
.bd-pat span{display:flex;gap:.25rem;flex-wrap:wrap;margin-top:.2rem}.bd-pat i{font-style:normal;font-size:.68rem;background:var(--sunken);border-radius:999px;padding:.05rem .5rem;color:var(--muted)}
.bd-tabs{display:flex;gap:.2rem;border-bottom:1px solid var(--bd);margin:-.2rem 0 .8rem}
.bd-tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:.45rem .8rem;cursor:pointer;color:var(--muted);font-weight:600;font-size:.84rem}
.bd-tabs button.on{color:var(--accent);border-color:var(--accent)}
.bd-ph{margin:.2rem 0 .5rem;font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.bd-todo{display:flex;gap:.6rem;align-items:center;border:1px solid var(--bd);border-left:3px solid var(--info);border-radius:9px;padding:.55rem .7rem;margin:.4rem 0;background:var(--card)}
.bd-todo.bad{border-left-color:var(--crit,#d1242f)}.bd-todo>div{flex:1;min-width:0}.bd-todo b{display:block;font-size:.84rem}.bd-todo small{display:block;color:var(--muted);font-size:.76rem;margin-top:.1rem}
.bd-good{background:var(--sunken);border-radius:9px;padding:.6rem .8rem;font-weight:600;font-size:.86rem;margin:.4rem 0;color:var(--ok,#1a7f37)}
.dp-tools{display:flex;gap:.9rem;flex-wrap:wrap;align-items:center}
.dp-tool{display:inline-flex;gap:.35rem;align-items:center;font-size:.82rem}
.dp-tool b,.dp-tool small{display:inline;font-size:.82rem}.dp-tool small{color:var(--muted)}
.bd-lg{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:.7rem 0 .2rem}
.bd-lr{border-top:1px solid var(--bd)}.bd-lt{display:flex;gap:.5rem;align-items:center;width:100%;background:none;border:0;padding:.45rem 0;cursor:pointer;color:var(--fg);text-align:left}
.bd-lt b{flex:1;font-size:.82rem;font-weight:600}.bd-lt i{font-style:normal;color:var(--muted)}
.bd-ld{padding:0 0 .7rem;font-size:.78rem;color:var(--muted)}.bd-ld p{margin:.2rem 0}.bd-ld p.d{color:var(--fg)}
.bd-comp{list-style:none;margin:.3rem 0;padding:0}.bd-comp li.hd{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em}.bd-comp li.on{color:var(--ok,#1a7f37)}.bd-comp li.off{color:var(--crit,#d1242f)}
.bd-appr{display:flex;gap:.5rem;flex-wrap:wrap;margin:.4rem 0}.bd-appr label{font-size:.68rem}.bd-appr input{display:block;font-size:.78rem;padding:.25rem .4rem;max-width:9rem;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:7px}
.bd-lock{display:flex;gap:.4rem;align-items:center;margin:.4rem 0}
.bd-fi{border-top:1px solid var(--bd);padding:.5rem 0;cursor:pointer;font-size:.8rem}.bd-fi b{margin:0 .4rem}.bd-fi small{display:block;color:var(--muted)}.bd-fi p{margin:.2rem 0;color:var(--muted)}
.bd-sub{display:flex;gap:.3rem;margin-bottom:.6rem}.bd-sub button{background:var(--card);border:1px solid var(--bd);border-radius:999px;padding:.25rem .75rem;cursor:pointer;font-size:.78rem;color:var(--muted)}.bd-sub button.on{color:var(--accent);border-color:var(--accent)}
.cv-drawer:has(.pf){width:min(780px,100vw)}.pf-bc{font-size:.78rem;margin:0 1.6rem .5rem 0;color:var(--muted)}.pf-bc a{color:var(--accent)}.pf-t{width:100%;font-size:.78rem}.pf-t tbody tr{cursor:pointer}.pf-t td small{display:block}.pf-chk{display:flex;gap:.4rem;flex-wrap:wrap}.pf-chain{font-size:.85rem;display:flex;gap:.4rem;flex-wrap:wrap;align-items:center}.pf-chain span{background:var(--sunken);padding:.15rem .5rem;border-radius:6px}
.cv-drawer.on{transform:none}.cv-x{position:absolute;top:.6rem;right:.8rem;background:none;border:0;font-size:1.6rem;color:var(--muted);cursor:pointer}
.cv-dk{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}.cv-drawer h3{margin:.2rem 0 .6rem;word-break:break-word}
.cv-chips{margin:.3rem 0 .6rem}.cv-facts{display:grid;grid-template-columns:auto 1fr;gap:.35rem .9rem;font-size:.82rem;margin:.6rem 0}
.cv-facts dt{color:var(--muted)}.cv-facts dd{margin:0;word-break:break-word}
.cv-dh{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:1rem 0 .3rem;font-weight:700}
.cv-iss{border-left:3px solid var(--info);background:var(--sunken);padding:.4rem .6rem;margin:.4rem 0;border-radius:0 8px 8px 0;font-size:.8rem}
.cv-iss b{display:block}.cv-iss small{display:block;color:var(--muted);margin-top:.15rem}.cv-links{margin-top:.8rem;font-size:.82rem}
.is-chips{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin:.2rem 0 .7rem}
.is-chip{display:inline-flex;align-items:center;gap:.4rem;border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:999px;padding:.28rem .75rem;font-size:.8rem;cursor:pointer}
.is-chip.on{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent);background:var(--sunken)}.is-sep{flex:0 0 1px;height:1.3rem;background:var(--bd);margin:0 .3rem}
.is-ctl{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.6rem}.is-ctl select{padding:.42rem .6rem;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg);font-size:.82rem}
.is-ctl .cv-q{flex:1 1 220px}
.is-g td{background:var(--sunken);font-size:.8rem;padding:.45rem .6rem}.is-g span{color:var(--muted);margin:0 .4rem;font-weight:500}
.cv-p{font-size:.86rem;line-height:1.55;margin:.2rem 0 .5rem}
.cv-code{position:relative;margin:.3rem 0 .6rem}.cv-code pre{margin:0;padding:.7rem .8rem;background:var(--sunken);border:1px solid var(--bd);border-radius:8px;font-size:.76rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
.cv-code button{position:absolute;top:.35rem;right:.4rem;font-size:.68rem;border:1px solid var(--bd);background:var(--card);color:var(--muted);border-radius:6px;padding:.1rem .45rem;cursor:pointer}
.cv-objs{margin:.2rem 0;padding-left:1.1rem;font-size:.8rem}.cv-objs li{margin:.15rem 0;word-break:break-word}
.mx-k{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.7rem;margin:.2rem 0 .9rem}
.mx-k .mc-t.crit b{color:var(--crit)}.mx-k .mc-t.warn b{color:var(--med)}.mx-k .mc-t.good b{color:var(--low)}
.mxh small{display:block;font-weight:500;color:var(--muted);font-size:.68rem;margin-top:.1rem}.cell.dim{opacity:.18}.cell.clk{cursor:pointer}
.cv-coll summary{cursor:pointer;font-weight:650;font-size:.92rem;display:flex;gap:.6rem;align-items:center}.cv-tc{margin-top:.6rem}
"""


def dashboard_page(has_scan: bool = False) -> str:
    """Client-side dashboard shell. All data comes from GET /api/dashboard."""
    shell = (_topbar("home")
             + "<h1 class='vh'>Kubernetes security dashboard</h1>"
             + "<div id='app'><div class='skl' aria-busy='true' aria-label='Loading dashboard'><i style='height:54px'></i><div><i style='height:240px'></i><i style='height:240px'></i><i style='height:240px'></i></div><i style='height:200px'></i></div></div>")
    # Vendored (no CDN), loaded before _APP_JS so `cytoscape` exists when boot() runs.
    cyto = "<script src='/vendor/cytoscape.min.js'></script>"
    return layout("K8sMatrixWarden · Dashboard", shell + cyto + _APP_JS, extra_css=_APP_CSS + _MC_CSS + _CV_CSS)



_RUNTIME_JS = """<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let ROWS = [], OPEN = null;

// Who owns the verdict. A curated K8sMatrixWarden rule and a relayed Falco rule are
// different claims and must never look alike.
function detPill(r){
  const d = r.detection_source;
  if (r.kind === 'drift') return "<span class='tag high' title='K8sMatrixWarden compared the pod&#39;s declared securityContext against its observed behaviour'>DRIFT</span>";
  if (d === 'kmw')   return "<span class='tag low' title='Detected by a curated K8sMatrixWarden runtime rule'>KMW</span>";
  if (d === 'falco') return "<span class='tag info' title='Relayed from the Falco provider; not a K8sMatrixWarden rule'>Falco</span>";
  return "<span class='tag muted' title='This report predates the provenance model'>Unknown</span>";
}
const SRC_LABEL = {falco:'Falco', audit:'Audit', drift:'Drift'};
function srcPill(r){
  const s = r.source;
  const help = {falco:'Syscall stream', audit:'Kubernetes API audit stream',
                drift:'Declared-vs-observed comparison'}[s] || 'Source not recorded';
  return `<span class='tag muted' title='${esc(help)}'>${esc(SRC_LABEL[s] || s || 'Unrecorded')}</span>`;
}
const CORR_LABEL = {confirmed:'Confirmed', 'runtime-only':'Runtime only',
                    corroborated:'Corroborated', drift:'Drift'};
function corrPill(c){
  const cls = {confirmed:'critical','runtime-only':'medium',corroborated:'high',
               drift:'critical'}[c] || 'info';
  return `<span class='tag ${cls}'>${esc(CORR_LABEL[c] || c)}</span>`;
}
function identPill(r){
  if (r.identity_status === 'complete') return '';
  const miss = (r.identity_missing || []).join(', ');
  return `<span class='tag medium' title='${esc(r.identity_reason || '')}'>Identity: ${esc(r.identity_status)}${miss ? ' (' + esc(miss) + ')' : ''}</span>`;
}
function detail(r){
  const row = (k, v) => (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length))
      ? '' : `<tr><td class='k'>${esc(k)}</td><td><code>${esc(Array.isArray(v) ? v.join(', ') : v)}</code></td></tr>`;
  return `<tr class='det'><td colspan='8'><div class='detbox'>
    <div class='fm' style='margin-bottom:.5rem'>${esc(r.verdict || r.title || '')}</div>
    <table class='kv'>
      ${row('event id', r.event_id)}${row('timestamp', r.timestamp)}
      ${row('detected by', r.detection_source)}${row('provider', r.provider)}
      ${row('rule', r.rule)}${row('provider rule', r.provider_rule)}
      ${row('provider priority', r.provider_priority)}
      ${row('supporting evidence', r.supporting_evidence)}
      ${row('event source', r.source)}${row('severity', r.severity)}
      ${row('tactic', r.tactic)}${row('technique', r.technique_id ? (r.technique_id + ' ' + (r.technique_name||'')).trim() : null)}
      ${row('cluster', r.cluster)}${row('namespace', r.namespace)}
      ${row('workload', r.workload)}${row('pod', r.pod)}
      ${row('container', r.container)}${row('process', r.process)}
      ${row('correlation', r.correlation)}${row('freshness', r.freshness)}
      ${row('age (days)', r.age_days)}
      ${row('identity', r.identity_status)}${row('identity missing', r.identity_missing)}
      ${row('identity reason', r.identity_reason)}
      ${row('declared', r.declared)}${row('observed', r.observed)}
      ${row('matched findings', r.static_findings)}
    </table></div></td></tr>`;
}

function render(d){
  const q = document.getElementById('rt-q');
  ROWS = d.events || [];
  const warn = (d.warnings || []).length
    ? `<div class='warn'>${d.warnings.map(w => esc(w)).join('<br/>')}</div>` : '';
  const s = d.summary || {};
  const kv = o => Object.entries(o || {}).map(([k, v]) => `${esc(k)} ${v}`).join(' · ') || 'None';
  // Which cluster these events are FROM, and which scan they were stored on. The feed
  // shows the latest saved scan unless one is named, and with more than one cluster in
  // the store that is not self-evident -- an operator validating EKS should not have to
  // infer that they are looking at yesterday's laptop events.
  const head = `<div class='fm rt-target'><strong>Cluster: ${esc(d.cluster || 'unknown')}</strong>`
    + ` · scan ${esc(d.scan_id || '-')}`
    + (d.feed_source ? ` · feed ${esc(d.feed_source)}` : '')
    + `</div>`
    + `<div class='kpis'>
      <div class='kpi'><div class='n'>${d.matched}</div><div class='l'>Matching events</div></div>
      <div class='kpi'><div class='n'>${d.total}</div><div class='l'>Stored on this scan</div></div>
      <div class='kpi'><div class='n'>${(s.by_detector||{}).kmw || 0}</div><div class='l'>Curated (K8sMatrixWarden)</div></div>
      <div class='kpi'><div class='n'>${(s.by_detector||{}).falco || 0}</div><div class='l'>Falco (relayed)</div></div>
    </div>
    <div class='fm' style='margin:.5rem 0'>By correlation: ${kv(s.by_correlation)} · by identity: ${kv(s.by_identity)}</div>`;

  if (!ROWS.length){
    q.innerHTML = warn + head + "<div class='empty'>No runtime events match. This does not mean nothing happened. Widen the filters, or pull a fresh feed from the Runtime tab on the dashboard.</div>";
    return;
  }
  const rows = ROWS.map((r, i) => `
    <tr class='ev' data-i='${i}'>
      <td><code>${esc((r.timestamp || '').replace('T', ' ').slice(0, 19) || 'Unknown')}</code></td>
      <td>${detPill(r)} ${srcPill(r)}</td>
      <td><code>${esc(r.rule)}</code>${r.supporting_evidence ? `<div class='fm'>+ ${esc(r.supporting_evidence)}</div>` : ''}</td>
      <td><span class='sev ${esc(r.severity)}'>${esc(r.severity)}</span></td>
      <td>${esc(r.tactic)}${r.technique_id ? `<div class='fm'>${esc(r.technique_id)}</div>` : ''}</td>
      <td>${esc(r.namespace || 'N/A')}</td>
      <td>${esc(r.workload || r.pod || 'N/A')}${identPill(r)}</td>
      <td>${corrPill(r.correlation)} ${freshPill(r)}</td>
    </tr>` + (OPEN === i ? detail(r) : '')).join('');
  q.innerHTML = warn + head + `<table class='rt'>
      <thead><tr><th>Time</th><th>Detected by</th><th>Rule</th><th>Severity</th>
      <th>Tactic</th><th>Namespace</th><th>Workload / Pod</th><th>Correlation</th></tr></thead>
      <tbody>${rows}</tbody></table>
      <div class='fm' style='margin-top:.6rem'>Showing ${d.returned} of ${d.matched} matching (${d.total} stored). Select a row for the full event.</div>`;
  q.querySelectorAll('tr.ev').forEach(tr => tr.onclick = () => {
    const i = Number(tr.dataset.i);
    OPEN = (OPEN === i) ? null : i;
    render(LAST);
  });
}

let LAST = {events: []};
function load(){
  const p = new URLSearchParams();
  ['source','severity','namespace','since','limit'].forEach(k => {
    const v = document.getElementById('f-' + k).value.trim();
    if (v) p.set(k, v);
  });
  document.getElementById('rt-q').innerHTML = "<div class='empty'>Loading events…</div>";
  fetch('/api/runtime?' + p.toString())
    .then(r => r.json())
    .then(d => { if (d.error){ document.getElementById('rt-q').innerHTML = `<div class='empty'>${esc(d.error)}</div>`; return; } LAST = d; OPEN = null; render(d); })
    .catch(e => { document.getElementById('rt-q').innerHTML = `<div class='empty'>${esc(e)}</div>`; });
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('rt-go').onclick = load;
  document.querySelectorAll('.f').forEach(el => el.onchange = load);
  load();
});

</script>"""

_RUNTIME_CSS = """
.ops-panel{border:1px solid var(--bd);border-radius:8px;padding:.7rem .9rem;
  margin:.7rem 0;background:var(--card)}
.ops-head{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.ops-detail{margin-top:.4rem;color:var(--muted);font-size:.85rem;word-break:break-all}
.ops-msg{margin-top:.35rem;color:var(--muted);word-break:break-word}
.ops-msg.bad{color:var(--crit)}

.falco-panel{border:1px solid var(--bd);border-radius:8px;padding:.6rem .8rem;
  margin:.6rem 0;background:var(--card)}
.falco-row{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.falco-msg{margin-top:.4rem;color:var(--muted);word-break:break-word}
.falco-msg.bad{color:var(--crit)}
.btn.danger{border-color:var(--crit);color:var(--crit)}
.btn:disabled{opacity:.45;cursor:not-allowed}

table.rt{width:100%;border-collapse:collapse;font-size:.83rem}
table.rt th{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--bd);
  color:var(--muted);font-weight:600;white-space:nowrap}
table.rt td{padding:.45rem .5rem;border-bottom:1px solid var(--bd);vertical-align:top}
table.rt tr.ev{cursor:pointer}
table.rt tr.ev:hover{background:var(--sunken)}
.detbox{background:var(--sunken);padding:.7rem .9rem;border-radius:6px;margin:.2rem 0 .6rem}
table.kv{border-collapse:collapse;font-size:.8rem}
table.kv td{padding:.15rem .6rem .15rem 0;vertical-align:top}
table.kv td.k{color:var(--muted);white-space:nowrap}
.rtbar{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.6rem 0 1rem}
.rtbar input,.rtbar select{background:var(--sunken);color:var(--fg);border:1px solid var(--bd);
  border-radius:6px;padding:.35rem .5rem;font-size:.82rem;font-family:inherit}
.rt-target{margin:.35rem 0;color:var(--muted)}.rt-target.bad{color:var(--high)}
.warn{background:var(--sunken);border-left:3px solid var(--med);padding:.5rem .7rem;
  border-radius:4px;margin-bottom:.7rem;font-size:.82rem}
.tag.muted{background:var(--sunken);color:var(--muted)}
"""


def runtime_page() -> str:
    """Read-only Runtime Events page. All data comes from GET /api/runtime."""
    controls = (
        "<div class='rtbar'>"
        "<label class='fm'>Source "
        "<select id='f-source' class='f'>"
        "<option value='all'>All sources</option><option value='kmw'>K8sMatrixWarden (curated)</option>"
        "<option value='falco'>Falco (relayed)</option><option value='audit'>Kubernetes audit</option>"
        "<option value='drift'>Configuration drift</option></select></label>"
        "<label class='fm'>Severity <input id='f-severity' class='f' size='14' "
        "placeholder='CRITICAL,HIGH'></label>"
        "<label class='fm'>Namespace <input id='f-namespace' class='f' size='14' "
        "placeholder='default'></label>"
        "<label class='fm'>Since <input id='f-since' class='f' size='8' "
        "placeholder='2h'></label>"
        "<label class='fm'>Limit <input id='f-limit' class='f' size='5' "
        "placeholder='50'></label>"
        "<button class='btn' id='rt-go'>Apply</button></div>")
    head = ("<h1 style='font-size:1.3rem;margin:.2rem 0'>Runtime Events</h1>"
            "<div class='sub'>Read-only view of runtime evidence already stored on the "
            "latest scan. Ingestion is unchanged: <code>POST /api/runtime</code> still "
            "receives events from Falco / falcosidekick.</div>"
            "<div class='fm' style='margin:.5rem 0'>"
            "<span class='tag low'>KMW</span> a curated K8sMatrixWarden rule owns the "
            "verdict &nbsp; <span class='tag info'>Falco</span> the provider's own rule, "
            "relayed under its name &nbsp; <span class='tag high'>DRIFT</span> declared "
            "securityContext contradicted by observed behaviour</div>")
    # Lifecycle controls deliberately do NOT live here. This page is the event feed; the
    # buttons that install and remove the thing producing the events belong on the Runtime
    # page, where an operator goes to manage the integration rather than to read it.
    crumb = ("<div class='crumbs'><a href='/'>Dashboard</a> › Runtime Events</div>")
    body = (_topbar("runtime-events") + crumb + head + controls
            + "<div id='rt-q' role='status' aria-live='polite'><div class='empty'>Loading events…</div></div>" + _RUNTIME_JS)
    return layout("K8sMatrixWarden · Runtime Events", body,
                  extra_css=_APP_CSS + _RUNTIME_CSS)


def error_page(status: int, message: str) -> str:
    return layout(f"K8sMatrixWarden · {status}",
                  _topbar() + f"<div class='empty'><h2>{status}</h2><p>{_esc(message)}</p>"
                  "<p><a href='/'>← Return to dashboard</a></p></div>")


# The whole dashboard app, vanilla JS, no framework, no external hosts.
_APP_JS = r"""
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEV = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const SEVVAR = {CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};
let D=null;
let activeTab='overview';

// -- shared helpers ---------------------------------------------------- //
const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function fmtTime(ts){                       // stored timestamps are IST wall-clock
  const m=String(ts||'').match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if(!m) return esc(ts||'N/A');
  return `${+m[3]} ${MONTHS[+m[2]-1]} ${m[1]}, ${m[4]}:${m[5]} IST`;
}
const slug=s=>String(s||'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');
function findingAnchor(f){                  // must match core.reporting.finding_anchor
  const r=f.resource||{};
  const raw=`${f.rule_id}-${r.kind||''}-${r.name||''}-${r.namespace||''}`;
  return 'f-'+(slug(raw)||'finding');
}
const OWASP_HOME='https://owasp.org/www-project-kubernetes-top-ten/';
function owaspLink(code){          // K03 -> its own owasp.org page, not the landing page
  if(!code) return '';
  const u=((D&&D.owasp_urls)||{})[code]||OWASP_HOME;
  return ` · <a href='${esc(u)}' target='_blank' rel='noopener'
    onclick='event.stopPropagation()' title='OWASP Kubernetes Top 10, ${esc(code)}'>OWASP ${esc(code)}</a>`;
}
function emptyView(){
  return `<div class='panel'><h2>Welcome. Run your first scan</h2>
    <div class='fm'>Nothing has been scanned yet. Pick what to scan; the dashboard fills in when it finishes.</div>
    <div id='tk-form'>${tkForm()}</div></div><div class='panel'><h2>Tasks</h2><div id='tk-list'></div></div>`;
}
/* ---- scan health -------------------------------------------------------
   A scan that could not read the cluster has zero findings because nothing was
   inspected. Every surface that shows a score, a count or a matrix has to say so, or
   the dashboard reads as "all clear". `healthBanner()` sits above the tabs (so it is
   visible on every one) and `healthNote()` repeats it inside the individual views. */
const scanOk = () => !D || !D.scan || D.scan.evidence_ok !== false;
const scanWarnings = () => (D && D.scan && D.scan.warnings) || [];
function healthBanner(){
  const w=scanWarnings(); if(!w.length) return '';
  const bad=!scanOk();
  return `<div class='healthbar ${bad?'bad':'partial'}'>
    <div class='hb-t'>${bad?'&#128721; Scan incomplete, this cluster was not read'
                          :'&#9888; Partial coverage, some resource types were unreadable'}</div>
    <ul class='hb-l'>${w.slice(0,12).map(x=>`<li>${esc(x)}</li>`).join('')}
      ${w.length>12?`<li>… ${w.length-12} more</li>`:''}</ul>
    <div class='hb-f'>${bad?'Findings, scores and the threat matrix below are NOT evidence of a secure cluster. Fix the access problem above and re-scan.'
                          :'Findings on the resource types listed above are missing from this scan.'}</div>
  </div>`;
}
function healthNote(){
  if(scanOk()) return '';
  return `<div class='healthnote'>&#128721; Not a result, this scan could not read the
    cluster, so nothing below was actually observed.</div>`;
}
function render(){
  CP.all=null;
  $('#app').innerHTML = `
    ${topBar()}
    <div id='v-start' class='view' role='region' aria-label='Start here'>${startView()}</div>
    <div id='v-overview' class='view' role='region' aria-label='Overview'>${overview()}</div>
    <div id='v-findings' class='view' role='region' aria-label='Issues'>${issuesView()}</div>
    <div id='v-changes' class='view' role='region' aria-label='What changed'>${changesView()}</div>
    <div id='v-incident' class='view' role='region' aria-label='Investigate a workload'>${incidentView()}</div>
    <div id='v-matrix' class='view' role='region' aria-label='Threat matrix'>${matrixView()}</div>
    <div id='v-cluster' class='view' role='region' aria-label='Cluster'>${clusterView()}</div>
    <div id='v-policies' class='view' role='region' aria-label='Policy review'>${policiesView()}</div>
    <div id='v-runtime' class='view' role='region' aria-label='Runtime'>${runtimeView()}</div>
    <div id='v-scan' class='view' role='region' aria-label='Scans'>${scanView()}</div>
    <div id='v-deps' class='view' role='region' aria-label='Dependencies'>${depsView()}</div>
    <div id='v-build' class='view' role='region' aria-label='Build an app'>${builderView()}</div>
    <div id='v-tasks' class='view' role='region' aria-label='Tasks'>${tasksView()}</div>
    <div id='v-risks' class='view' role='region' aria-label='Accepted risks'>${risksView()}</div>
    <aside id='drawer' class='cv-drawer' aria-live='polite'></aside>
    <div id='cp' class='cp' onclick='cpOverlay(event,this)' role='dialog' aria-label='Search'><div class='cp-box'><input id='cp-q' placeholder='Search issues, workloads, images, namespaces, pages…' oninput='cpFilter(this.value)' onkeydown='cpKey(event)' autocomplete='off'><div id='cp-list' class='cp-list'></div><div class='cp-foot'><span><kbd>&uarr;</kbd> <kbd>&darr;</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div></div></div>`;
  isRefresh(); wireScan(); showTab(routeFromHash()); enhanceA11y(); navBadges();
}
/* ---- top bar: which scan, global search, and one-line scan health ---------------------------------- */
let tbOpen=false;
function topBar(){
  const cur=D.selected_scan_id||D.scan.scan_id, w=scanWarnings(), bad=!scanOk();
  const opts=(D.history||[]).map(r=>`<option value='${esc(r.scan_id)}' ${r.scan_id===cur?'selected':''}>${esc(r.name||r.scan_id)} · ${fmtTime(r.generated_at)} · ${esc(r.rating)} ${r.risk_score}/10</option>`).join('');
  const health=bad?`<button type='button' class='tb-chip bad' onclick='tbToggle()'>&#128721; Cluster not read</button>`
    :w.length?`<button type='button' class='tb-chip warn' onclick='tbToggle()' title='Some resource types could not be read'>&#9888; Partial coverage · ${w.length}</button>`
    :`<span class='tb-chip ok'>&#10003; Fully read</span>`;
  return `<div class='tb'><div class='tb-row'>
    <label class='tb-sel'><span>Scan</span><select id='rptpick' onchange='loadReport(this.value)' aria-label='Choose a scan'>${opts}</select></label>
    <span class='tb-meta'>${esc(D.scan.mode)} · ${esc(D.scan.scope)}</span>
    <button type='button' class='tb-search' onclick='cpOpen()' aria-label='Search'><span>Search issues, workloads, images…</span><kbd>Ctrl K</kbd></button>
    ${health}<button type='button' class='btn tb-go' onclick="location.hash='#tasks'">Scan now</button></div>
    <div id='tb-detail' class='tb-detail ${tbOpen?'on':''}'>${w.length?`<ul>${w.slice(0,12).map(x=>`<li>${esc(x)}</li>`).join('')}${w.length>12?`<li>… ${w.length-12} more</li>`:''}</ul>
      <p>${bad?'Scores and the matrix are NOT evidence of a secure cluster. Fix the access problem and re-scan.':'Findings on the unreadable resource types are missing from this scan. Grant the scanner get/list on them, or ignore if you do not use them.'}</p>`:''}</div></div>`;
}
function tbToggle(){ tbOpen=!tbOpen; const d=$('#tb-detail'); if(d) d.classList.toggle('on',tbOpen); }
/* ---- command palette: Ctrl/Cmd+K or / ---------------------------------------------------------------- */
let CP={sel:0,res:[],all:null};
const CP_PAGES=[['Start here','start'],['Overview','overview'],['Issues','issues'],['Threat matrix','matrix'],['What changed','changes'],['Investigate a workload','incident'],['Cluster','cluster'],['Policy review','policies'],['Runtime','runtime'],['Dependencies','deps'],['Build an app','build'],['Scans','scans'],['Tasks','tasks'],['Accepted risks','risks']];
function cpIndex(){
  if(CP.all) return CP.all; const a=[];
  CP_PAGES.forEach(([t,h])=>a.push({g:'Go to',t,s:'page',k:t,go:()=>{location.hash='#'+h}}));
  a.push({g:'Go to',t:'Attack paths',s:'page',k:'attack paths graph',go:()=>{location.href='/graph?scan_id='+encodeURIComponent(D.scan.scan_id)}});
  (D.workload_issues||[]).slice().sort((x,y)=>(y.score||0)-(x.score||0)).forEach(i=>a.push({g:'Issues',t:i.title,s:`${i.severity} · ${i.workload}`,k:[i.title,i.workload,i.rule_id,i.namespace,i.owner].join(' '),go:()=>{location.hash='#issues'; setTimeout(()=>openIssueByGroup(i.aggregation_group),50)}}));
  cvRows('workloads').forEach(w=>a.push({g:'Workloads',t:w.name,s:`${w.kind} · ${w.namespace||'-'}${w.internet?' · internet':''}`,k:[w.name,w.namespace,w.kind,...(w.images||[])].join(' '),go:()=>incOpen(w.id)}));
  cvRows('images').forEach(i=>a.push({g:'Images',t:i.image.split('/').pop(),s:`${i.total||0} CVEs`,k:i.image,go:()=>{cvSec='images'; location.hash='#cluster'; setTimeout(()=>{cvRefresh()},50)}}));
  cvRows('namespaces').forEach(n=>a.push({g:'Namespaces',t:n.name,s:`${n.workloads} workloads`,k:n.name,go:()=>{cvSec='namespaces'; location.hash='#cluster'; setTimeout(cvRefresh,50)}}));
  return CP.all=a;
}
function cpOpen(){ let o=$('#cp'); if(!o) return; o.classList.add('on'); const i=$('#cp-q'); i.value=''; cpFilter(''); setTimeout(()=>i.focus(),20); }
function kEnter(ev,fn,arg){ if(ev.key==='Enter') window[fn](arg); }
function cpOverlay(ev,el){ if(ev.target===el) cpClose(); }
function cpClose(){ const o=$('#cp'); if(o) o.classList.remove('on'); }
function cpFilter(q){
  q=q.trim().toLowerCase(); const all=cpIndex();
  const words=q.split(/\s+/).filter(Boolean);
  let res=words.length?all.filter(x=>words.every(w=>(x.t+' '+x.k).toLowerCase().includes(w))):all.filter(x=>x.g==='Go to');
  const order=['Go to','Issues','Workloads','Images','Namespaces']; const seen={};
  res=res.filter(x=>(seen[x.g]=(seen[x.g]||0)+1)<=(words.length?6:20)).sort((a,b)=>order.indexOf(a.g)-order.indexOf(b.g));
  CP.res=res; CP.sel=0; cpPaint();
}
function cpPaint(){
  let g=''; const b=$('#cp-list'); if(!b) return;
  b.innerHTML=CP.res.length?CP.res.map((r,i)=>{ const h=r.g!==g?`<div class='cp-g'>${esc(r.g)}</div>`:''; g=r.g;
    return h+`<div class='cp-i ${i===CP.sel?'on':''}' onmousemove='CP.sel=${i};cpPaint()' onclick='cpGo(${i})'><b>${esc(r.t)}</b><small>${esc(r.s)}</small></div>`}).join(''):"<div class='cp-none'>No matches.</div>";
  const on=b.querySelector('.cp-i.on'); if(on) on.scrollIntoView({block:'nearest'});
}
function cpGo(i){ const r=CP.res[i]; cpClose(); if(r) r.go(); }
function cpKey(e){
  if(e.key==='ArrowDown'){ CP.sel=Math.min(CP.res.length-1,CP.sel+1); cpPaint(); e.preventDefault(); }
  else if(e.key==='ArrowUp'){ CP.sel=Math.max(0,CP.sel-1); cpPaint(); e.preventDefault(); }
  else if(e.key==='Enter'){ cpGo(CP.sel); }
}
document.addEventListener('keydown',e=>{
  const typing=/INPUT|TEXTAREA|SELECT/.test((document.activeElement||{}).tagName||'');
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){ e.preventDefault(); if(D&&D.has_scan) cpOpen(); }
  else if(e.key==='/'&&!typing&&D&&D.has_scan){ e.preventDefault(); cpOpen(); }
  else if(e.key==='Escape') cpClose();
});
function reportBar(){
  const cur=D.selected_scan_id||D.scan.scan_id;
  const opts=(D.history||[]).map(r=>`<option value='${esc(r.scan_id)}' ${r.scan_id===cur?'selected':''}>`
    +`${esc(r.scan_id)}, ${fmtTime(r.generated_at)} · ${esc(r.rating)} (${r.risk_score}/10) · ${r.total} findings</option>`).join('');
  return `<div class='repbar'>
    <label for='rptpick'>Report</label>
    <select id='rptpick' onchange='loadReport(this.value)'>${opts}</select>
    <span class='meta'>${esc(D.scan.scope)} · ${esc(D.scan.mode)} · ${fmtTime(D.scan.generated_at)} · <code>${esc(D.scan.scan_id)}</code></span>
  </div>`;
}
/* ---- routing: one sidebar item per view, the URL hash is the address ------------------
   The sidebar (server-rendered, shared by every page) links to /#issues etc. A view id is the
   container's name; the hash is what a person bookmarks. */
const ROUTES={overview:'overview',findings:'issues',matrix:'matrix',cluster:'cluster',runtime:'runtime',scan:'scans',tasks:'tasks',risks:'risks',build:'build',deps:'deps',policies:'policies',start:'start',changes:'changes',incident:'incident'};
function routeFromHash(){
  let first='overview'; try{ if(!localStorage.getItem('k8smw-seen')){ localStorage.setItem('k8smw-seen','1'); first='start'; } }catch(e){}
  const h=(location.hash||'#'+first).slice(1);
  const hit=Object.entries(ROUTES).find(([,v])=>v===h);
  return hit?hit[0]:'overview';
}
function navBadges(){
  const set=(id,v)=>{const e=document.getElementById(id); if(e) e.textContent=v};
  set('nav-issues',(D.workload_issues||[]).length||'');
  set('nav-paths',window.__pathCount||'');
}
function showTab(id){
  activeTab=id;
  document.querySelectorAll('.view').forEach(v=>{v.classList.remove('on');v.setAttribute('hidden','')});
  const v=$('#v-'+id); if(v){v.classList.add('on');v.removeAttribute('hidden');}
  document.querySelectorAll('.side a[data-nav]').forEach(a=>{
    const on=a.dataset.nav===ROUTES[id];
    a.classList.toggle('on',on); if(on) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current');});
  const want='#'+ROUTES[id];
  if(location.hash!==want) history.replaceState(null,'',want);
  window.scrollTo(0,0);
}
window.addEventListener('hashchange',()=>{ if(D) showTab(routeFromHash()); });
function hero(){
  const s=D.scan, t=D.trend||[], d=t.length>1?(t[t.length-1][1]-t[t.length-2][1]):null;
  // A trend delta is an indicator, not a sentence. Badge, tabular figures, one glance.
  const delta = d===null?`<span class='s'></span>`
    :d<0?`<span class='s'><span class='delta down' title='Risk score fell ${Math.abs(d).toFixed(1)} since the previous scan'>&darr; ${Math.abs(d).toFixed(1)}</span> vs previous</span>`
    :d>0?`<span class='s'><span class='delta up' title='Risk score rose ${d.toFixed(1)} since the previous scan'>&uarr; ${d.toFixed(1)}</span> vs previous</span>`
    :`<span class='s'><span class='delta flat'>No change</span> vs previous</span>`;
  const hp=(s.counts.CRITICAL||0)+(s.counts.HIGH||0);
  const cov=D.threat_matrix.summary.coverage_pct;
  // Cluster never read: show "N/A" rather than a 0.0 risk / Excellent rating that a reader
  // would take as a passing grade for a cluster nothing was collected from.
  if(!scanOk()){
    return `<div class='kpis'>
      <div class='kpi lead unk'><div class='l'>Risk score</div><div class='n'>N/A</div><div class='s'>Not measurable</div></div>
      <div class='kpi unk'><div class='l'>Security posture</div><div class='n'>Unknown</div><div class='s'>Cluster not read</div></div>
      <div class='kpi unk'><div class='l'>Workload issues</div><div class='n'>N/A</div><div class='s'>Nothing inspected</div></div>
      <div class='kpi unk'><div class='l'>Critical &amp; high</div><div class='n'>N/A</div><div class='s'>Nothing inspected</div></div>
      <div class='kpi unk'><div class='l'>Detection coverage</div><div class='n'>${cov}<span class='max'>%</span></div><div class='s'>Rules loaded, not applied</div></div>
    </div>`;
  }
  return missionControl(delta);
}
/* ---- mission control -----------------------------------------------------------------
   The first screen answers three questions in order: how bad (gauge), what kind (severity
   donut of REMEDIATION UNITS, not raw resource findings), and how exposed (the toxic
   combinations an attacker can actually walk). Inventory sits beside them the way the
   Kubernetes dashboard shows workload health. Every number is server-computed. */
const SEVHEX={CRITICAL:'#d1242f',HIGH:'#e8590c',MEDIUM:'#d29a00',LOW:'#1a7f37',INFO:'#6c757d'};
function donut(segs,center,sub,size){
  size=size||132; const r=size/2-11, c=2*Math.PI*r, tot=segs.reduce((a,x)=>a+x.n,0)||1;
  let off=0;
  const arcs=segs.filter(x=>x.n>0).map(x=>{const len=x.n/tot*c;
    const a=`<circle cx='${size/2}' cy='${size/2}' r='${r}' fill='none' stroke='${x.c}' stroke-width='14'
      stroke-dasharray='${Math.max(len-1.5,0.5)} ${c}' stroke-dashoffset='${-off}' transform='rotate(-90 ${size/2} ${size/2})'>
      <title>${esc(x.l)}: ${x.n}</title></circle>`; off+=len; return a}).join('');
  return `<svg class='donut' width='${size}' height='${size}' viewBox='0 0 ${size} ${size}' role='img' aria-label='${esc(sub||'')}'>
    <circle cx='${size/2}' cy='${size/2}' r='${r}' fill='none' stroke='var(--sunken)' stroke-width='14'/>${arcs}
    <text x='50%' y='49%' text-anchor='middle' class='dn'>${center}</text>
    <text x='50%' y='63%' text-anchor='middle' class='ds'>${esc(sub||'')}</text></svg>`;
}
function gauge(score,color){
  const r=70,cx=90,cy=84,len=Math.PI*r, f=Math.max(0,Math.min(score/10,1));
  return `<svg class='dial' viewBox='0 0 180 104' role='img' aria-label='Risk score ${score} of 10'>
    <path d='M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${cx+r} ${cy}' fill='none' stroke='var(--sunken)' stroke-width='14' stroke-linecap='round'/>
    <path d='M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${cx+r} ${cy}' fill='none' stroke='${color}' stroke-width='14' stroke-linecap='round'
      stroke-dasharray='${(len*f).toFixed(1)} ${len.toFixed(1)}'/>
    <text x='${cx}' y='${cy-12}' text-anchor='middle' class='gn'>${score.toFixed(1)}</text>
    <text x='${cx}' y='${cy+8}' text-anchor='middle' class='gs'>out of 10</text></svg>`;
}
function missionControl(delta){
  const s=D.scan, inv=D.inventory||{}, ph=inv.pod_phases||{}, ex=inv.exposure||{}, wp=inv.workload_posture||{};
  const rk=s.cluster_risk>=7?'crit':s.cluster_risk>=4?'warn':'good';
  const rc=s.cluster_risk>=7?SEVHEX.CRITICAL:s.cluster_risk>=4?SEVHEX.MEDIUM:SEVHEX.LOW;
  const wi=D.workload_issues||[], bySev={};
  wi.forEach(w=>bySev[w.severity]=(bySev[w.severity]||0)+1);
  const ORD=['CRITICAL','HIGH','MEDIUM','LOW','INFO'], cap=k=>k[0]+k.slice(1).toLowerCase();
  const segs=ORD.map(k=>({l:cap(k),n:bySev[k]||0,c:SEVHEX[k]}));
  const leg=segs.filter(x=>x.n).map(x=>`<li><i style='background:${x.c}'></i><span>${x.l}</span><b>${x.n}</b></li>`).join('');
  const nExp=(ex.internet_admin||0)+(ex.internet||0);
  const tile=(n,l,cls,note)=>`<div class='mc-t ${cls||''}'><b>${n}</b><span>${l}</span>${note?`<small>${note}</small>`:''}</div>`;
  return `<div class='mc'>
    <section class='mc-c mc-risk ${rk}' aria-label='Risk score'>
      <h3>Risk score</h3>${gauge(s.cluster_risk,rc)}
      <div class='mc-rate' style='color:${rc}'>${esc(s.rating)}</div>
      <div class='mc-sub'>${delta.replace(/class='s'/,"class='mc-d'")}</div>
      <div class='mc-sub'>${s.total} resource findings · ${wi.length} issues to fix</div>
    </section>
    <section class='mc-c' aria-label='Issues by severity'>
      <h3>Issues by severity <span class='hint' title='One issue = one rule on one owning workload. The Findings tab lists every resource-level finding behind them.'>?</span></h3>
      <div class='mc-row'>${donut(segs,wi.length,'issues')}<ul class='mc-leg'>${leg||'<li>No issues</li>'}</ul></div>
    </section>
    <section class='mc-c' aria-label='Exposure'>
      <h3>Exposure <span class='hint' title='Pods an attacker can reach from outside the cluster, and what the identity they run as can do.'>?</span></h3>
      <div class='mc-tiles'>
        ${tile(nExp,'Internet-reachable pods',nExp?'crit':'good')}
        ${tile(ex.internet_admin||0,'… running as cluster-admin',(ex.internet_admin||0)?'crit':'good')}
        ${tile(wp.privileged||0,'Privileged pods',(wp.privileged||0)?'warn':'good',`of ${wp.total||0}`)}
        ${tile(ex.admin||0,'Cluster-admin identities',(ex.admin||0)?'warn':'good')}
      </div>
      <div class='mc-more2'><a href='/#cluster'>Privilege, network and node detail in Cluster &rarr;</a></div>
    </section>
  </div>`;
}
/* Top attack paths, as the chain an attacker would walk. The server reports a route once per
   object Kubernetes generated (Deployment, ReplicaSet, Pod); a route is shown once. */
function attackCards(){
  const R=D.routes||{top:[]}; window.__pathCount=R.total||0;
  if(!R.top.length) return '';
  const ICON={Internet:'&#127760;',Service:'&#9741;',Ingress:'&#10142;',ServiceAccount:'&#128100;',ClusterRole:'&#128737;',Capability:'&#128273;',
    Deployment:'&#9638;',Pod:'&#9638;',DaemonSet:'&#9638;',StatefulSet:'&#9638;',CronJob:'&#9638;',Job:'&#9638;'};
  const card=p=>{const sev=p.severity;
    const chain=p.steps.map(s=>`<span class='ap-n' title='${esc(s.t)}: ${esc(s.n)}'><i style='border-color:${s.t==='Internet'?SEVHEX.HIGH:'var(--bd)'}'>${ICON[s.t]||'&#9679;'}</i><em>${esc(s.t==='Internet'?'Internet':s.n)}</em></span>`).join("<span class='ap-a'>&rsaquo;</span>");
    return `<a class='ap' href='/graph?scan_id=${encodeURIComponent(D.scan.scan_id)}' style='border-top:3px solid ${SEVHEX[sev]||'#6c757d'}' title='Open attack paths'>
      <div class='ap-h'><span class='sev ${sev}'>${sev}</span><span>${p.internet?'Internet-reachable':'Needs a foothold'}</span><b>${p.issues} issue${p.issues===1?'':'s'}</b></div>
      <div class='ap-c'>${chain}</div></a>`};
  return `<div class='panel' style='margin-top:1rem'><h2>Top attack paths
    <a class='mc-more' href='/graph?scan_id=${encodeURIComponent(D.scan.scan_id)}'>All ${R.total} routes &rarr;</a></h2>
    <div class='ap-grid'>${R.top.map(card).join('')}</div>
    <div class='fm' style='margin-top:.6rem'>${R.total} routes found, ${R.internet} reachable from the Internet; each hop is read off a real Service, binding or role.</div></div>`;
}
function agg(){ return D.aggregation||{}; }
const HEALTH_LABEL={healthy:'Operational',converging:'Converging',degraded:'Degraded',
                    partial:'Partially reported',unknown:'Not reported'};
function overview(){
  return `${healthNote()}${hero()}
  <div class='grid2'>
    <div class='panel'><h2>Fix these first</h2>${priorityList()}</div>
    <div class='panel'><h2>Where the risk sits</h2>${domainBars()}</div>
  </div>${scanOk()?attackCards():''}`;
}
/* Issues: what to fix, with the arithmetic behind the score one click away rather than on the
   landing screen. */
function riskDrivers(){
  return `<details class='panel drivers'><summary>What drives the risk score</summary>${riskContributors()}</details>`;
}
/* ---- Cluster: an explorable inventory --------------------------------------------------------
   Questions an engineer opens this with: is anything broken, what is running and where, what is
   exposed, who can do what, what does it depend on. The server sends a compact, secret-free
   summary of every object (core/cluster_inventory.py); this lays it out. A tile opens a table,
   a row opens a drawer with the facts and the issues on that object. */
let cvSec='workloads', cvQ='', cvFilter='', cvSort=null, cvOpen=null;
const cvInv=()=>D.cluster_inventory||{};
const cvRows=k=>((cvInv().sections||{})[k])||[];
const ago=ts=>{ if(!ts) return ''; const t=Date.parse(ts); if(isNaN(t)) return '';
  const m=(Date.now()-t)/60000; return m<60?Math.round(m)+'m':m<1440?Math.round(m/60)+'h':Math.round(m/1440)+'d'; };
const sevCount=i=>(i&&i.n)?`<span class='sev ${i.worst||'LOW'}' title='${i.n} issue(s), worst ${i.worst}'>${i.n}</span>`:"<span class='cv-ok'>0</span>";
const chip=(t,hot)=>`<span class='cv-chip${hot?' hot':''}'>${esc(t)}</span>`;
const HOT_FLAGS=new Set(['privileged','host-network','host-pid','host-ipc','host-path']);
const wlStatus=w=>{
  const bad=Object.entries(w.problems||{});
  if(w.kind==='CronJob') return w.suspended?"<span class='cv-st warn'>suspended</span>":`<span class='cv-st ok'>${esc(w.schedule||'scheduled')}</span>`;
  const want=w.desired!=null?w.desired:w.pods;
  const cls=bad.length?'bad':(w.ready<want?'warn':'ok');
  return `<span class='cv-st ${cls}'>${w.ready}/${want} ready</span>`+(bad.length?`<small>${bad.map(([r,c])=>c+'× '+esc(r)).join(', ')}</small>`:'')
    +(w.restarts>2?`<small>${w.restarts} restarts</small>`:'');
};
const vulnChips=r=>{ if(!r.scanned) return `<span class='cv-st warn'>${r.error?'scan failed':'not scanned'}</span>`;
  const c=r.counts||{}; const out=['Critical','High','Medium'].filter(k=>c[k]).map(k=>`<span class='sev ${k.toUpperCase()}'>${c[k]} ${k.toLowerCase()}</span>`).join(' ');
  return out||"<span class='cv-ok'>none above low</span>"; };
const vulnTable=top=>(top&&top.length)?`<table class='cv-vt'><tr><th>CVE / package</th><th>Severity</th><th>Fixed in</th></tr>`+top.map(m=>`<tr><td><a href='https://nvd.nist.gov/vuln/detail/${encodeURIComponent(m.id)}' target='_blank' rel='noopener'>${esc(m.id)}</a>${m.knownExploited?' '+chip('exploited',true):''}<small>${esc(m.package)} ${esc(m.version)}</small></td><td><span class='sev ${String(m.severity).toUpperCase()}'>${esc(m.severity)}</span></td><td>${(m.fixedIn||[]).length?'<code>'+esc(m.fixedIn.join(', '))+'</code>':m.fixState==='fixed'?'available':'<small>none yet</small>'}</td></tr>`).join('')+`</table>`:'';
const vulnHTML=s=>(s&&s.top&&s.top.length)?`<div class='cv-dh'>Vulnerabilities in <code>${esc(s.image||'')}</code></div>${vulnTable(s.top)}<p class='cv-p'><small>Scanned by Grype${s.dbBuilt?' (feed built '+esc(String(s.dbBuilt).slice(0,10))+')':''}, by the image digest this pod runs. Showing the worst ${s.top.length}.</small></p>`:'';
const CV={
 workloads:{title:'Workloads',hint:'Everything that runs pods, grouped by the controller that owns them.',
  filters:[['','All'],['problems','Failing or short'],['internet','Internet-exposed'],['privileged','Privileged or host access'],['issues','With issues']],
  match:(r,f)=>f==='problems'?(Object.keys(r.problems||{}).length||(r.desired!=null&&r.ready<r.desired)):f==='internet'?r.internet:
    f==='privileged'?(r.flags||[]).some(x=>HOT_FLAGS.has(x)):f==='issues'?r.issues.n>0:true,
  text:r=>[r.name,r.namespace,r.kind,r.sa,...(r.images||[])].join(' '),
  cols:[['Workload',r=>`<b>${esc(r.name)}</b><small>${esc(r.kind)} · ${esc(r.namespace||'-')}</small>`,r=>r.name],
        ['Status',wlStatus,r=>-(Object.keys(r.problems||{}).length*100+(r.restarts||0))],
        ['Image',r=>(r.images||[]).slice(0,2).map(i=>`<code>${esc(i.split('/').pop())}</code>`).join('<br>')||'-',r=>(r.images||[])[0]||''],
        ['Identity',r=>`<code>${esc(r.sa||'-')}</code>`,r=>r.sa||''],
        ['Risk flags',r=>(r.flags||[]).map(f=>chip(f,HOT_FLAGS.has(f))).join('')||"<span class='cv-ok'>none</span>",r=>-(r.flags||[]).filter(f=>HOT_FLAGS.has(f)).length],
        ['Exposure',r=>r.internet?chip('Internet',true):(r.ingress_policy?`<small>ingress ${esc(r.ingress_policy)}</small>`:'-'),r=>r.internet?0:1],
        ['Issues',r=>sevCount(r.issues),r=>-r.issues.n]],
  facts:r=>[['Kind',r.kind],['Namespace',r.namespace],['Pods',`${r.pods} (${Object.entries(r.phases||{}).map(([k,v])=>v+' '+k).join(', ')||'none'})`],
    ['Desired replicas',r.desired],['Restarts',r.restarts],['Images',(r.images||[]).map(i=>`<code>${esc(i)}</code>`).join('<br>')],
    ['Service account',r.sa],['Pod IPs',(r.ips||[]).join(', ')],['Ingress policy',r.ingress_policy],['Managed by',r.managed_by],['Created',ago(r.created)&&ago(r.created)+' ago']]},
 pods:{title:'Pods',hint:'Every pod, with where it runs, what it can do, and how it is wired to the network.',
  filters:[['','All'],['problems','Failing'],['privileged','Privileged or host access'],['internet','Internet-exposed'],['openeg','Open outbound']],
  match:(r,f)=>f==='problems'?!!r.problem||r.phase==='Failed'||r.phase==='Pending':f==='privileged'?(r.flags||[]).some(x=>HOT_FLAGS.has(x)):f==='internet'?r.internet:f==='openeg'?['unrestricted','allow-all'].includes(r.egress_policy):true,
  text:r=>[r.name,r.namespace,r.workload,r.node,r.ip,...(r.containers||[]).map(c=>c.image)].join(' '),
  cols:[['Pod',r=>`<b>${esc(r.name)}</b><small>${esc(r.namespace||'-')}</small>`,r=>r.name],
        ['State',r=>r.problem?`<span class='cv-st bad'>${esc(r.problem)}</span>`:`<span class='cv-st ${r.phase==='Running'||r.phase==='Succeeded'?'ok':'warn'}'>${esc(r.phase)}</span>`,r=>r.problem?0:1],
        ['Node / IP',r=>`${esc(r.node||'-')}<small>${esc(r.ip||'')}</small>`,r=>r.node||''],
        ['Risk flags',r=>(r.flags||[]).map(f=>chip(f,HOT_FLAGS.has(f))).join('')||"<span class='cv-ok'>none</span>",r=>-(r.flags||[]).filter(f=>HOT_FLAGS.has(f)).length],
        ['Network',r=>`<small>in ${esc(r.ingress_policy||'?')}<br>out ${esc(r.egress_policy||'?')}</small>`,r=>r.egress_policy||''],
        ['Issues',r=>sevCount(r.issues),r=>-r.issues.n]]},
 images:{title:'Images',hint:'What each running image contains, matched against known vulnerabilities by Grype. Judged by the digest that runs, so a patched rebuild clears it and a stale copy does not.',
  filters:[['','All'],['reach','Internet-reachable'],['kev','Known-exploited'],['crit','Critical'],['fixable','Fix available'],['unscanned','Not scanned']],
  match:(r,f)=>f==='reach'?r.internet:f==='kev'?r.kev>0:f==='crit'?(r.counts.Critical||0)>0:f==='fixable'?r.fixable>0:f==='unscanned'?!r.scanned:true,
  text:r=>[r.image,...r.workloads].join(' '),
  cols:[['Image',r=>`<b>${esc(r.image.split('/').pop())}</b><small>${esc(r.digest?r.digest.slice(0,19):'no digest reported')}</small>`,r=>r.image],
        ['Used by',r=>`${r.workloads.length} workload(s)`,r=>-r.workloads.length],['Vulnerabilities',vulnChips,r=>-((r.counts.Critical||0)*1000+(r.counts.High||0))],
        ['Reach',r=>[r.internet?chip('Internet-reachable',true):'',r.identity?chip('identity reaches secrets',true):''].join('')||'<small>isolated</small>',r=>-((r.internet?2:0)+(r.identity?1:0))],
        ['Fix available',r=>r.scanned?r.fixable:'-',r=>-r.fixable],['Exploited',r=>r.kev?chip(r.kev+' known',true):'-',r=>-r.kev],
        ['Priority',r=>r.score?`<b>${r.score}</b><small>risk score</small>`:'-',r=>-r.score]],
  facts:r=>[['Image',`<code>${esc(r.image)}</code>`],['Digest',r.digest?`<code>${esc(r.digest)}</code>`:''],['Used by',r.workloads.map(w=>`<code>${esc(w)}</code>`).join('<br>')],['Why this rank',r.score?`score ${r.score}: ${r.internet?'reachable from the Internet':'not reachable from the Internet'}${r.identity?', and its ServiceAccount can reach secrets':''}`:''],
    ['Scan problem',r.error],['Total matches',r.scanned?r.total:''],['Worst first',vulnTable(r.top)]]},
 nodes:{title:'Nodes',hint:'Machines running the pods: health, versions and how full they are.',
  filters:[['','All'],['problems','Not ready or under pressure']],match:(r,f)=>f==='problems'?(!r.ready||r.pressure.length):true,
  text:r=>[r.name,r.os,r.kubelet,r.ip].join(' '),
  cols:[['Node',r=>`<b>${esc(r.name)}</b><small>${esc(r.roles.join(', '))}</small>`,r=>r.name],
        ['Status',r=>r.ready?(r.pressure.length?`<span class='cv-st warn'>${esc(r.pressure.join(', '))}</span>`:"<span class='cv-st ok'>Ready</span>"):"<span class='cv-st bad'>Not ready</span>",r=>r.ready?1:0],
        ['Kubelet',r=>`<code>${esc(r.kubelet)}</code>`,r=>r.kubelet],['OS / runtime',r=>`${esc(r.os)}<small>${esc(r.runtime)}</small>`,r=>r.os],
        ['Capacity',r=>`${esc(r.cpu)} CPU · ${esc(r.memory)}`,r=>r.cpu],['Pods',r=>`${r.pods}${r.pods_cap?' / '+esc(r.pods_cap):''}`,r=>-r.pods]],
  facts:r=>[['Roles',r.roles.join(', ')],['Internal IP',r.ip],['Kernel',r.kernel],['Taints',(r.taints||[]).join(', ')||'none'],['Age',ago(r.created)&&ago(r.created)+' old']]},
 namespaces:{title:'Namespaces',hint:'Boundaries: what runs in each, and what protects it.',
  filters:[['','All'],['open','No NetworkPolicy'],['nopsa','No Pod Security enforcement'],['issues','With issues']],
  match:(r,f)=>f==='open'?(!r.system&&!r.policies):f==='nopsa'?(!r.system&&r.psa!=='restricted'):f==='issues'?r.issues.n>0:true,
  text:r=>r.name,
  cols:[['Namespace',r=>`<b>${esc(r.name)}</b>${r.system?'<small>system</small>':''}`,r=>r.name],['Workloads',r=>r.workloads,r=>-r.workloads],['Pods',r=>r.pods,r=>-r.pods],['Services',r=>r.services,r=>-r.services],
        ['NetworkPolicies',r=>r.policies?r.policies:chip('none',!r.system),r=>r.policies],
        ['Pod Security',r=>r.psa?chip(r.psa,r.psa!=='restricted'&&!r.system):chip('not enforced',!r.system),r=>r.psa||''],
        ['Quota / limits',r=>`${r.quota?'quota':'-'} · ${r.limits?'limits':'-'}`,r=>r.quota?0:1],['Issues',r=>sevCount(r.issues),r=>-r.issues.n]],
  facts:r=>[['Phase',r.phase],['Pod Security (enforce)',r.psa||'not set'],['ResourceQuota',r.quota?'yes':'no'],['LimitRange',r.limits?'yes':'no'],['Age',ago(r.created)&&ago(r.created)+' old']]},
 services:{title:'Services',hint:'How traffic reaches workloads, and which are reachable from outside.',
  filters:[['','All'],['external','Externally exposed'],['noep','No ready endpoints']],match:(r,f)=>f==='external'?r.external:f==='noep'?(r.endpoints===0):true,
  text:r=>[r.name,r.namespace,r.type,r.selector].join(' '),
  cols:[['Service',r=>`<b>${esc(r.name)}</b><small>${esc(r.namespace)}</small>`,r=>r.name],['Type',r=>r.external?chip(r.type,true):esc(r.type),r=>r.type],
        ['Ports',r=>(r.ports||[]).map(esc).join('<br>')||'-',r=>(r.ports||[])[0]||''],['Backs',r=>(r.backends||[]).map(b=>`<code>${esc(b.split('/').slice(1).join('/'))}</code>`).join(' ')||'<small>no workload</small>',r=>(r.backends||[]).length],
        ['Endpoints',r=>r.endpoints==null?'-':r.endpoints===0?"<span class='cv-st bad'>0</span>":r.endpoints,r=>r.endpoints??-1],['Issues',r=>sevCount(r.issues),r=>-r.issues.n]],
  facts:r=>[['Type',r.type],['Cluster IP',r.cluster_ip],['Selector',r.selector],['External address',r.address],['Allowed source ranges',(r.source_ranges||[]).join(', ')||(r.type==='LoadBalancer'?'any (open)':'')],['Age',ago(r.created)&&ago(r.created)+' old']]},
 ingresses:{title:'Ingresses',hint:'HTTP entry points from outside the cluster.',filters:[['','All'],['notls','No TLS']],match:(r,f)=>f==='notls'?!(r.tls||[]).length:true,
  text:r=>[r.name,r.namespace,...(r.hosts||[])].join(' '),
  cols:[['Ingress',r=>`<b>${esc(r.name)}</b><small>${esc(r.namespace)}</small>`,r=>r.name],['Hosts',r=>(r.hosts||[]).map(esc).join('<br>'),r=>(r.hosts||[])[0]||''],
        ['TLS',r=>(r.tls||[]).length?"<span class='cv-st ok'>yes</span>":"<span class='cv-st bad'>no</span>",r=>(r.tls||[]).length],['Routes to',r=>(r.backends||[]).map(b=>`<code>${esc(b)}</code>`).join(' '),r=>(r.backends||[])[0]||''],
        ['Class',r=>esc(r.class||'-'),r=>r.class],['Issues',r=>sevCount(r.issues),r=>-r.issues.n]],
  facts:r=>[['Class',r.class],['Address',r.address]]},
 policies:{title:'Network policies',hint:'What is allowed to talk to what. A namespace with none is a flat network.',filters:[['','All']],match:()=>true,
  text:r=>[r.name,r.namespace,r.selects,r.effect].join(' '),
  cols:[['Policy',r=>`<b>${esc(r.name)}</b><small>${esc(r.namespace)}</small>`,r=>r.name],['Applies to',r=>esc(r.selects),r=>r.selects],['Effect',r=>esc(r.effect),r=>r.effect],
        ['Ingress rules',r=>r.ingress_rules,r=>r.ingress_rules],['Egress rules',r=>r.egress_rules,r=>r.egress_rules]],facts:r=>[['Types',r.types.join(', ')]]},
 identities:{title:'Service accounts',hint:'The identities workloads run as, and what they are bound to.',filters:[['','All'],['admin','Cluster-admin'],['unused','Not used by any workload']],
  match:(r,f)=>f==='admin'?r.admin:f==='unused'?r.used_by===0:true,text:r=>[r.name,r.namespace,...(r.roles||[])].join(' '),
  cols:[['Service account',r=>`<b>${esc(r.name)}</b><small>${esc(r.namespace)}</small>`,r=>r.name],['Used by',r=>r.used_by,r=>-r.used_by],
        ['Bound to',r=>(r.roles||[]).map(x=>chip(x,x.startsWith('cluster-admin'))).join('')||"<span class='cv-ok'>no bindings</span>",r=>r.admin?0:1],
        ['Token mount',r=>r.automount?'auto':'off',r=>r.automount?0:1]],facts:r=>[['Roles',(r.roles||[]).join(', ')||'none']]},
 bindings:{title:'Role bindings',hint:'Who is granted what. Wide grants are flagged.',filters:[['','All'],['risky','Wide grants'],['custom','Not built-in']],
  match:(r,f)=>f==='risky'?(r.grants||[]).length>0:f==='custom'?!r.builtin:true,text:r=>[r.name,r.role,...(r.subjects||[])].join(' '),
  cols:[['Binding',r=>`<b>${esc(r.name)}</b><small>${esc(r.kind)}${r.namespace?' · '+esc(r.namespace):''}</small>`,r=>r.name],['Role',r=>`<code>${esc(r.role)}</code>`,r=>r.role],
        ['Subjects',r=>(r.subjects||[]).slice(0,3).map(esc).join('<br>'),r=>(r.subjects||[])[0]||''],['Grants',r=>(r.grants||[]).map(g=>chip(g,true)).join('')||"<span class='cv-ok'>scoped</span>",r=>-(r.grants||[]).length]],
  facts:r=>[['Subjects',(r.subjects||[]).map(esc).join('<br>')],['Built-in',r.builtin?'yes':'no']]},
 config:{title:'Config & secrets',hint:'ConfigMaps and Secrets by name only. Values are never read.',filters:[['','All'],['Secret','Secrets'],['ConfigMap','ConfigMaps'],['unused','Not used by any pod']],
  match:(r,f)=>f==='unused'?r.used_by===0:(f==='Secret'||f==='ConfigMap')?r.kind===f:true,text:r=>[r.name,r.namespace,r.kind,r.type].join(' '),
  cols:[['Name',r=>`<b>${esc(r.name)}</b><small>${esc(r.namespace||'')}</small>`,r=>r.name],['Kind',r=>esc(r.kind),r=>r.kind],['Type / keys',r=>r.kind==='Secret'?esc(r.type||'-'):(r.keys??'-')+' key(s)',r=>r.type||''],
        ['Used by pods',r=>r.used_by,r=>-r.used_by],['Age',r=>esc(ago(r.created)||'-'),r=>r.created||'']],facts:r=>[]},
 storage:{title:'Storage',hint:'Volumes, claims and classes.',filters:[['','All'],['PVC','Claims'],['PV','Volumes'],['StorageClass','Classes']],match:(r,f)=>f?r.kind===f:true,text:r=>[r.name,r.namespace,r.class].join(' '),
  cols:[['Name',r=>`<b>${esc(r.name)}</b><small>${esc(r.kind)}${r.namespace?' · '+esc(r.namespace):''}</small>`,r=>r.name],['Status',r=>esc(r.status||'-'),r=>r.status],['Size',r=>esc(r.size||'-'),r=>r.size],
        ['Class / provisioner',r=>esc(r.class||'-'),r=>r.class],['Backing',r=>r.volume==='hostPath'?chip('hostPath',true):esc(r.volume||'-'),r=>r.volume],['In use',r=>r.used_by,r=>-r.used_by]],facts:r=>[]},
 events:{title:'Warning events',hint:'Recent things Kubernetes complained about.',filters:[['','All']],match:()=>true,text:r=>[r.object,r.reason,r.message,r.namespace].join(' '),
  cols:[['When',r=>esc(ago(r.last)||'-')+' ago',r=>r.last||''],['Object',r=>`<b>${esc(r.object)}</b><small>${esc(r.namespace||'')}</small>`,r=>r.object],['Reason',r=>chip(r.reason,true),r=>r.reason],
        ['Message',r=>esc(r.message),r=>r.message],['Count',r=>r.count,r=>-r.count]],facts:r=>[['Message',esc(r.message)]]},
 extensions:{title:'Extensions',hint:'CustomResourceDefinitions and aggregated APIs: surface that is not core Kubernetes.',filters:[['','All']],match:()=>true,text:r=>[r.name,r.group,r.kind].join(' '),
  cols:[['Name',r=>`<b>${esc(r.name)}</b>`,r=>r.name],['Kind',r=>esc(r.kind),r=>r.kind],['Group',r=>esc(r.group),r=>r.group],['Scope',r=>esc(r.scope),r=>r.scope],['Versions',r=>(r.versions||[]).map(esc).join(', '),r=>(r.versions||[])[0]||'']],facts:r=>[]}
};
function cvTiles(){
  const T=(cvInv().summary||{}).totals||{}, S=cvInv().summary||{}, ph=S.pod_phases||{}, wl=cvRows('workloads');
  const fail=wl.filter(w=>Object.keys(w.problems||{}).length||(w.desired!=null&&w.ready<w.desired)).length;
  const ns=cvRows('namespaces').filter(n=>!n.system), open=ns.filter(n=>!n.policies).length;
  const ext=cvRows('services').filter(s=>s.external).length, adm=cvRows('identities').filter(i=>i.admin).length;
  const tiles=[
   ['images','Images',T.images,T.images?`${cvRows('images').filter(i=>i.kev).length} with known-exploited`:'not scanned',T.images?'':'run with --grype',cvRows('images').some(i=>i.kev)?'bad':''],
   ['workloads','Workloads',T.workloads,`${S.pods||0} pods · ${ph.Running||0} running`,fail?`${fail} failing`:'',fail?'bad':''],
   ['pods','Pods',T.pods,`${ph.Running||0} running`,'',''],
   ['nodes','Nodes',T.nodes,`${S.nodes_ready||0} ready`,S.version||'',(S.nodes_ready||0)<(T.nodes||0)?'bad':''],
   ['namespaces','Namespaces',T.namespaces,`${ns.length-open} of ${ns.length} with a policy`,open?`${open} open`:'',open?'warn':''],
   ['services','Services',T.services,`${ext} externally exposed`,'',ext?'warn':''],
   ['ingresses','Ingresses',T.ingresses,'','',''],['policies','Network policies',T.policies,'','',''],
   ['identities','Service accounts',T.identities,adm?`${adm} cluster-admin`:'none cluster-admin','',adm?'warn':''],
   ['bindings','Role bindings',T.bindings,'','',''],['config','Config & secrets',T.config,'names only','',''],
   ['storage','Storage',T.storage,'','',''],['events','Warning events',T.events,'recent','',T.events?'warn':''],['extensions','Extensions',T.extensions,'CRDs & aggregated APIs','','']];
  return tiles.map(([k,l,n,sub,note,cls])=>`<button type='button' class='cv-tile ${cls} ${k===cvSec?'on':''}' data-sec='${k}' onclick='cvGo("${k}")'>
    <span class='cv-n'>${n??0}</span><span class='cv-l'>${esc(l)}</span><small>${esc(sub)}</small>${note?`<em>${esc(note)}</em>`:''}</button>`).join('');
}
function cvAttention(){
  const a=cvInv().attention||[];
  if(!a.length) return `<div class='cv-calm'>&#10003; Nothing needs attention: nodes are ready, pods are running and every namespace has a policy.</div>`;
  return `<div class='cv-attn'>${a.map(x=>`<button type='button' class='cv-a ${x.sev}' onclick='cvGo("${x.section}","${x.filter||''}")'>
    <span class='sev ${x.sev}'>${x.sev}</span><b>${esc(x.title)}</b><small>${esc(x.detail)}</small><i>&rsaquo;</i></button>`).join('')}</div>`;
}
function cvTable(){
  const c=CV[cvSec], all=cvRows(cvSec), cap=((cvInv().capped)||{})[cvSec];
  let rows=all.filter(r=>c.match(r,cvFilter));
  if(cvQ){const q=cvQ.toLowerCase(); rows=rows.filter(r=>c.text(r).toLowerCase().includes(q));}
  if(cvSort){const [i,dir]=cvSort, f=c.cols[i][2]; rows=[...rows].sort((a,b)=>{const x=f(a),y=f(b);return (x>y?1:x<y?-1:0)*dir});}
  const head=c.cols.map((col,i)=>`<th><button type='button' onclick='cvSortBy(${i})'>${esc(col[0])}${cvSort&&cvSort[0]===i?(cvSort[1]>0?' &#9650;':' &#9660;'):''}</button></th>`).join('');
  const body=rows.slice(0,400).map((r,i)=>`<tr tabindex='0' onclick='cvDetail(${all.indexOf(r)})' onkeydown='if(event.key==="Enter")cvDetail(${all.indexOf(r)})'>${c.cols.map(col=>`<td>${col[1](r)}</td>`).join('')}</tr>`).join('');
  return `<div class='cv-bar'><div class='cv-ttl'><h2>${esc(c.title)}</h2><span>${esc(c.hint)}</span></div>
    <input class='cv-q' type='search' placeholder='Search ${esc(c.title.toLowerCase())}…' value='${esc(cvQ)}' oninput='cvSearch(this.value)' aria-label='Search'>
    <div class='cv-f'>${c.filters.map(([k,l])=>`<button type='button' class='${k===cvFilter?'on':''}' onclick='cvSetFilter("${k}")'>${esc(l)}</button>`).join('')}</div></div>
    <div class='cv-count'>${rows.length} of ${all.length}${cap?` (first ${all.length} of ${cap} shown)`:''}${rows.length>400?', showing 400':''}</div>
    <div class='cv-scroll'><table class='cv-t'><thead><tr>${head}</tr></thead><tbody>${body||`<tr><td colspan='${c.cols.length}' class='cv-none'>Nothing matches.</td></tr>`}</tbody></table></div>`;
}
function cvIssuesFor(r){
  const key=r.id||'';
  if(!key||!r.issues||!r.issues.n) return '';
  const [ns,kind,name]=key.split('/');
  const wi=(D.workload_issues||[]).filter(w=>(w.workload_name===name)&&(w.workload_kind===kind)&&((w.namespace||'')===(ns||'')));
  return `<div class='cv-dh'>Issues (${wi.length})</div>`+wi.sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)).slice(0,30).map(w=>{
    const f=(D.findings||[]).find(x=>x.resource_finding_id===(w.resource_finding_ids||[])[0]);
    return `<div class='cv-iss' style='border-left-color:var(--${(SEVVAR[w.severity]||'info')})'><b>${esc(w.title)}</b>${f?esc(f.message||''):''}<small>${esc(w.severity)} · ${esc(w.rule_id)}</small></div>`}).join('')
    +`<div class='cv-links'><a href='javascript:cvToIssues("${esc(name)}")'>See in Issues &rarr;</a> · <a href='/graph?scan_id=${encodeURIComponent(D.scan.scan_id)}'>Attack paths &rarr;</a></div>`;
}
function cvDetail(i){
  const c=CV[cvSec], r=cvRows(cvSec)[i]; if(!r) return; cvOpen=i;
  const pk={namespaces:'namespace',workloads:'workload',pods:'pod',services:'service',ingresses:'ingress'}[cvSec];
  if(pk) return pfOpen(pk,pk==='namespace'?r.name:r.id,true);
  const facts=(c.facts?c.facts(r):[]).filter(([,v])=>v!==''&&v!=null&&v!==undefined&&v!==false);
  const title=r.name||r.object||r.role||'';
  drawerOpen(`<div class='cv-dk'>${esc(c.title)}${r.namespace?' · '+esc(r.namespace):''}</div><h3>${esc(title)}</h3>
    ${(r.flags||[]).length?`<div class='cv-chips'>${r.flags.map(f=>chip(f,HOT_FLAGS.has(f))).join('')}${r.internet?chip('Internet-exposed',true):''}</div>`:''}
    <dl class='cv-facts'>${facts.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${typeof v==='string'&&v.includes('<')?v:esc(v)}</dd>`).join('')}</dl>${cvSec==='workloads'?`<div class='cv-links'><a href='javascript:incOpen("${esc(r.id)}")'>Investigate this workload &rarr;</a></div>`:''}${cvIssuesFor(r)}`);
}
function cvClose(){ drawerClose(); }
/* ---- Profiles: one drill-down per resource, with everything an engineer checks first ----------
   Namespace > Workload > Pod, plus Service and Ingress, each linked to the things it touches, so
   nobody has to run kubectl and cross-reference by hand. Built only from the scan's own inventory. */
let PF=[];
const NP_LABEL={'unrestricted':['open to all','bad'],'allow-all':['allow-all rule','bad'],'restricted':['restricted','ok'],'deny-all':['deny all','ok'],'partial':['partly known','warn'],'unknown':['unknown','warn']};
const npChip=(s,names)=>{const [t,c]=NP_LABEL[s]||[s||'-','warn']; return `<span class='cv-st ${c}'>${esc(t)}</span>`+((names&&names.length)?` <small>${names.map(esc).join(', ')}</small>`:'');};
const PF_SEC=new Set(['NET_ADMIN','SYS_ADMIN','SYS_PTRACE','SYS_MODULE','NET_RAW','DAC_READ_SEARCH','ALL']);
const pfFind=(k,id)=>{ if(k==='namespace') return cvRows('namespaces').find(n=>n.name===id);
  const sec={workload:'workloads',pod:'pods',service:'services',ingress:'ingresses'}[k]; return cvRows(sec).find(r=>r.id===id); };
const pfA=(k,id,label)=>`<a href='javascript:pfOpen("${k}","${esc(id)}")'>${esc(label)}</a>`;
const pfTable=(head,rows)=>rows.length?`<table class='cv-t pf-t'><thead><tr>${head.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.slice(0,15).join('')}</tbody></table>`+(rows.length>15?`<div class='fm'>+${rows.length-15} more not shown; use the table filters on the Cluster tab to narrow</div>`:''):"<div class='cv-none'>none</div>";
const pfRow=(k,id,cells)=>`<tr tabindex='0' onclick='pfOpen("${k}","${esc(id)}")' onkeydown='if(event.key==="Enter")pfOpen("${k}","${esc(id)}")'>${cells.map(c=>`<td>${c}</td>`).join('')}</tr>`;
const pfSec=(t,h)=>`<div class='cv-dh'>${esc(t)}</div>${h}`;
const pfFacts=rows=>{ const f=rows.filter(([,v])=>v!==''&&v!=null&&v!==false&&!(Array.isArray(v)&&!v.length)); if(!f.length) return ''; return `<dl class='cv-facts'>${f.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${typeof v==='string'&&v.includes('<')?v:esc(v)}</dd>`).join('')}</dl>`; };
const pfCtr=c=>{ const t=[]; if(c.privileged) t.push(chip('privileged',true)); if(c.root) t.push(chip('runs as root',true)); if(c.priv_esc) t.push(chip('can escalate'));
  if(!c.read_only_fs) t.push(chip('writable fs')); (c.caps_add||[]).forEach(x=>t.push(chip('+'+x,PF_SEC.has(x)))); if(!c.caps_drop_all) t.push(chip('caps kept'));
  if(!c.limits) t.push(chip('no limits')); (c.host_ports||[]).forEach(p=>t.push(chip('hostPort '+p,true))); return t.join('')||"<span class='cv-ok'>hardened</span>"; };
const pfCtrTable=cs=>pfTable(['Container','Image','Security context'],(cs||[]).map(c=>`<tr><td><b>${esc(c.name)}</b>${(c.ports||[]).length?`<small>ports ${c.ports.join(', ')}</small>`:''}</td><td><code>${esc((c.image||'').split('/').pop())}</code></td><td>${pfCtr(c)}</td></tr>`));
const pfEvents=pred=>{ const e=cvRows('events').filter(pred).slice(0,6); return pfSec('Recent warnings',e.length?e.map(x=>`<div class='cv-iss'><b>${esc(x.reason)} <small>×${x.count}</small></b>${esc(x.message)}<small>${esc(x.object)}</small></div>`).join(''):"<div class='cv-none'>none recorded</div>"); };
const pfIssues=(ns,name,kind)=>{ const wi=(D.workload_issues||[]).filter(w=>(w.namespace||'')===(ns||'')&&(name?(w.workload_name===name&&(!kind||w.workload_kind===kind)):true)).sort((a,b)=>(b.score||0)-(a.score||0));
  return pfSec(`Issues (${wi.length})`,wi.length?wi.slice(0,name?30:12).map(w=>`<div class='cv-iss' style='border-left-color:var(--${(SEVVAR[w.severity]||'info')})'><b>${esc(w.title)}</b>${name?'':`<small>${esc(w.workload_kind)} ${esc(w.workload_name)}</small>`}<small>${esc(w.severity)} &middot; ${esc(w.rule_id)}</small></div>`).join('')+(name?`<div class='cv-links'><a href='javascript:cvToIssues("${esc(name)}")'>See in Issues &rarr;</a></div>`:''):"<div class='cv-none'>none</div>"); };
const pfWlCells=w=>[`<b>${esc(w.name)}</b><small>${esc(w.kind)}</small>`,wlStatus(w),(w.flags||[]).filter(f=>HOT_FLAGS.has(f)).map(f=>chip(f,true)).join('')||"<span class='cv-ok'>-</span>",w.internet?chip('Internet',true):'-',sevCount(w.issues)];
function pfNs(n){
  const ws=cvRows('workloads').filter(w=>w.namespace===n.name), sv=cvRows('services').filter(s=>s.namespace===n.name), ig=cvRows('ingresses').filter(i=>i.namespace===n.name),
        ids=cvRows('identities').filter(i=>i.namespace===n.name), po=cvRows('policies').filter(p=>p.namespace===n.name);
  const chk=(ok,t,bad)=>`<span class='cv-st ${ok?'ok':'warn'}'>${ok?'&#10003; ':''}${esc(ok?t:bad)}</span>`;
  return `<div class='cv-chips'>${n.exposed?chip(n.exposed+' Internet-exposed',true):''}${n.open_ingress?chip(n.open_ingress+' open to all inbound',true):''}${n.open_egress?chip(n.open_egress+' open outbound'):''}${n.privileged?chip(n.privileged+' privileged/host access',true):''}</div>`
   +pfFacts([['Phase',n.phase],['Workloads / pods',`${n.workloads} / ${n.pods}`],['Not healthy',n.unhealthy?`${n.unhealthy} workload(s)`:''],['Age',ago(n.created)&&ago(n.created)+' old']])
   +pfSec('Protection',`<div class='pf-chk'>${chk(n.policies>0,n.policies+' NetworkPolicy','no NetworkPolicy: flat network')}${chk(!!n.psa,'PSA enforce: '+n.psa,'no Pod Security enforce label')}${chk(n.quota,'ResourceQuota','no ResourceQuota')}${chk(n.limits,'LimitRange','no LimitRange')}</div>`)
   +pfSec(`Workloads (${ws.length})`,pfTable(['Workload','Status','Host access','Exposure','Issues'],ws.map(w=>pfRow('workload',w.id,pfWlCells(w)))))
   +pfSec(`Services (${sv.length})`,pfTable(['Service','Type','Ports','Ready endpoints'],sv.map(s=>pfRow('service',s.id,[`<b>${esc(s.name)}</b>`,s.external?chip(s.type,true):esc(s.type),esc((s.ports||[]).join(', ')),s.endpoints===0?"<span class='cv-st bad'>0</span>":esc(s.endpoints??'?')]))))
   +pfSec(`Ingresses (${ig.length})`,pfTable(['Ingress','Hosts','TLS'],ig.map(i=>pfRow('ingress',i.id,[`<b>${esc(i.name)}</b>`,esc((i.hosts||[]).join(', ')),(i.tls||[]).length?"<span class='cv-st ok'>yes</span>":"<span class='cv-st bad'>no</span>"]))))
   +pfSec(`Service accounts (${ids.length})`,pfTable(['Account','Used by','Roles'],ids.map(i=>`<tr><td><code>${esc(i.name)}</code>${i.admin?chip('cluster-admin',true):''}</td><td>${i.used_by}</td><td>${esc((i.roles||[]).join(', ')||'none')}</td></tr>`)))
   +pfSec(`Network policies (${po.length})`,pfTable(['Policy','Selects','Effect'],po.map(p=>`<tr><td><code>${esc(p.name)}</code></td><td>${esc(p.selects)}</td><td>${esc(p.effect)}<small>in ${p.ingress_rules} / out ${p.egress_rules} rules</small></td></tr>`)))
   +pfEvents(e=>e.namespace===n.name)+pfIssues(n.name);
}
function pfExposure(r){
  const ig=cvRows('ingresses').filter(i=>i.namespace===r.namespace&&(i.backends||[]).some(b=>(r.services||[]).includes(b)));
  if(!(r.services||[]).length) return "<div class='cv-none'>No Service selects this workload: it is only reachable by pod IP.</div>";
  const sv=r.services.map(s=>pfA('service',`${r.namespace}/Service/${s}`,s)).join(', ');
  return `<div class='pf-chain'>${ig.length?`<span>Internet</span> &rarr; <span>${ig.map(i=>pfA('ingress',i.id,i.name)).join(', ')}</span> &rarr; `:''}<span>${sv}</span> &rarr; <b>${esc(r.name)}</b></div>`
    +(r.internet?`<p class='cv-p'><small>Reachable from the Internet through this chain.</small></p>`:'');
}
function pfWl(r){
  const idn=cvRows('identities').find(i=>i.namespace===r.namespace&&i.name===r.sa), pods=cvRows('pods').filter(p=>p.workload===r.id);
  return `<div class='cv-chips'>${(r.flags||[]).map(f=>chip(f,HOT_FLAGS.has(f))).join('')}${r.internet?chip('Internet-exposed',true):''}</div>`
   +pfFacts([['Namespace',pfA('namespace',r.namespace,r.namespace)],['Status',wlStatus(r)],['Pods',`${r.pods} (${Object.entries(r.phases||{}).map(([k,v])=>v+' '+k).join(', ')||'none'})`],['Restarts',r.restarts],
     ['Images',(r.images||[]).map(i=>`<code>${esc(i)}</code>`).join('<br>')],['Runs as',r.sa?`<code>${esc(r.sa)}</code>`+(idn?` <small>${idn.admin?'cluster-admin; ':''}${esc((idn.roles||[]).join(', ')||'no roles')}${idn.automount?'; token auto-mounted':''}</small>`:''):''],
     ['Managed by',r.managed_by],['Age',ago(r.created)&&ago(r.created)+' old']])
   +pfSec('How it is reached',pfExposure(r))
   +pfSec('Network policy',pfFacts([['Inbound',npChip(r.ingress_policy,r.ingress_policies)],['Outbound',npChip(r.egress_policy,r.egress_policies)]]))
   +pfSec('Containers',pfCtrTable(r.containers))
   +pfSec(`Pods (${pods.length})`,pfTable(['Pod','State','Restarts','Node'],pods.map(p=>pfRow('pod',p.id,[`<b>${esc(p.name)}</b>`,p.problem?`<span class='cv-st bad'>${esc(p.problem)}</span>`:esc(p.phase),p.restarts,esc(p.node||'-')]))))
   +pfEvents(e=>e.namespace===r.namespace&&String(e.object||'').split('/')[1]&&String(e.object).split('/')[1].startsWith(r.name))
   +pfIssues(r.namespace,r.name,r.kind)+`<div class='cv-links'><a href='javascript:incOpen("${esc(r.id)}")'>Investigate this workload &rarr;</a></div>`;
}
function pfPod(r){
  const w=cvRows('workloads').find(x=>x.id===r.workload);
  return `<div class='cv-chips'>${(r.flags||[]).map(f=>chip(f,HOT_FLAGS.has(f))).join('')}${r.internet?chip('Internet-exposed',true):''}</div>`
   +pfFacts([['Namespace',pfA('namespace',r.namespace,r.namespace)],['Workload',w?pfA('workload',w.id,w.kind+' '+w.name):''],['State',r.problem?`<span class='cv-st bad'>${esc(r.problem)}</span>`:esc(r.phase)],['Restarts',r.restarts],
     ['Node / IP',`${r.node||'-'} / ${r.ip||'-'}`],['Runs as',r.sa&&`<code>${esc(r.sa)}</code>`],['Age',ago(r.created)&&ago(r.created)+' old']])
   +pfSec('Containers',pfCtrTable(r.containers))
   +pfSec('Mounts and references (names only)',pfFacts([['Secrets',(r.secrets||[]).map(x=>`<code>${esc(x)}</code>`).join(', ')],['ConfigMaps',(r.configmaps||[]).map(x=>`<code>${esc(x)}</code>`).join(', ')],
     ['Volume claims',(r.claims||[]).map(x=>`<code>${esc(x)}</code>`).join(', ')],['Host paths',(r.host_paths||[]).map(x=>chip(x,true)).join('')]])||"<div class='cv-none'>none</div>")
   +pfSec('Network',pfFacts([['Inbound',npChip(r.ingress_policy,r.ingress_policies)],['Outbound',npChip(r.egress_policy,r.egress_policies)],
     ['Services',(r.services||[]).map(s=>pfA('service',`${r.namespace}/Service/${s}`,s)).join(', ')],['Ingresses',(r.ingresses||[]).map(i=>pfA('ingress',`${r.namespace}/Ingress/${i}`,i)).join(', ')]]))
   +pfEvents(e=>e.object==='Pod/'+r.name&&e.namespace===r.namespace)+(w?pfSec('Issues on its workload',pfIssues(r.namespace,w.name,w.kind).replace(/^<div class='cv-dh'>[^<]*<\/div>/,'')):'');
}
function pfSvc(r){
  const ws=(r.backends||[]).map(b=>cvRows('workloads').find(w=>w.id===b)).filter(Boolean), ig=cvRows('ingresses').filter(i=>i.namespace===r.namespace&&(i.backends||[]).includes(r.name));
  return `<div class='cv-chips'>${r.external?chip(r.type+' (external)',true):chip(r.type)}</div>`
   +pfFacts([['Namespace',pfA('namespace',r.namespace,r.namespace)],['Cluster IP',r.cluster_ip],['Ports',(r.ports||[]).join(', ')],['Selector',r.selector&&`<code>${esc(r.selector)}</code>`],
     ['Ready endpoints',r.endpoints===0?"<span class='cv-st bad'>0: nothing is serving this</span>":r.endpoints],['External address',r.address],['Allowed sources',(r.source_ranges||[]).join(', ')||(r.type==='LoadBalancer'?"<span class='cv-st bad'>any</span>":'')]])
   +pfSec(`Routes to (${ws.length})`,pfTable(['Workload','Status','Issues'],ws.map(w=>pfRow('workload',w.id,[`<b>${esc(w.name)}</b><small>${esc(w.kind)}</small>`,wlStatus(w),sevCount(w.issues)]))))
   +pfSec(`Exposed by ingress (${ig.length})`,pfTable(['Ingress','Hosts'],ig.map(i=>pfRow('ingress',i.id,[`<b>${esc(i.name)}</b>`,esc((i.hosts||[]).join(', '))]))))
   ;
}
function pfIng(r){
  const sv=(r.backends||[]).map(b=>cvRows('services').find(s=>s.namespace===r.namespace&&s.name===b)).filter(Boolean);
  return `<div class='cv-chips'>${(r.tls||[]).length?chip('TLS'):chip('no TLS',true)}</div>`
   +pfFacts([['Namespace',pfA('namespace',r.namespace,r.namespace)],['Class',r.class],['Hosts',(r.hosts||[]).join(', ')],['TLS hosts',(r.tls||[]).join(', ')||"<span class='cv-st bad'>none</span>"],['Address',r.address]])
   +pfSec(`Backends (${sv.length})`,pfTable(['Service','Type','Ready endpoints'],sv.map(s=>pfRow('service',s.id,[`<b>${esc(s.name)}</b>`,esc(s.type),s.endpoints===0?"<span class='cv-st bad'>0</span>":esc(s.endpoints??'?')]))));
}
const PF_KIND={namespace:['Namespace',pfNs,n=>n.name],workload:['Workload',pfWl,r=>r.name],pod:['Pod',pfPod,r=>r.name],service:['Service',pfSvc,r=>r.name],ingress:['Ingress',pfIng,r=>r.name]};
function pfOpen(k,id,reset){
  const r=pfFind(k,id); if(!r) return;
  if(reset) PF=[]; const at=PF.findIndex(x=>x.k===k&&x.id===id); if(at>=0) PF=PF.slice(0,at+1); else PF.push({k,id,label:PF_KIND[k][0]+' '+PF_KIND[k][2](r)});
  pfRender();
}
function pfBack(i){ PF=PF.slice(0,i+1); pfRender(); }
function pfRender(){
  const cur=PF[PF.length-1]; if(!cur) return; const r=pfFind(cur.k,cur.id); if(!r) return; const [kind,fn,nm]=PF_KIND[cur.k];
  const bc=`<nav class='pf-bc' aria-label='Path'><a href='javascript:drawerClose()'>Cluster</a>`+PF.map((x,i)=>` &rsaquo; `+(i<PF.length-1?`<a href='javascript:pfBack(${i})'>${esc(x.label)}</a>`:`<b>${esc(x.label)}</b>`)).join('')+`</nav>`;
  drawerOpen(`<div class='pf'>${bc}<div class='cv-dk'>${esc(kind)}${r.namespace&&cur.k!=='namespace'?' &middot; '+esc(r.namespace):''}</div><h3>${esc(nm(r))}</h3>${fn(r)}</div>`);
  const d=$('#drawer'); if(d) d.scrollTop=0;
}
function cvToIssues(name){ isQ=name.toLowerCase(); isNs=''; isDom=''; isTac=''; isFlags.clear(); isSev.clear(); drawerClose(); location.hash='#issues'; const v=$('#v-findings'); if(v) v.innerHTML=issuesView(); isRefresh(); }
function cvRefresh(){ $('#cv-tiles').innerHTML=cvTiles(); $('#cv-body').innerHTML=cvTable(); }
function cvGo(sec,filter){ cvSec=sec; cvFilter=filter||''; cvQ=''; cvSort=null; cvClose(); cvRefresh(); const b=$('#cv-body'); if(b) b.scrollIntoView({behavior:'smooth',block:'start'}); }
function cvSetFilter(f){ cvFilter=f; cvRefresh(); }
function cvSearch(v){ cvQ=v; $('#cv-body').innerHTML=cvTable(); const q=$('.cv-q'); if(q){q.focus(); q.setSelectionRange(v.length,v.length);} }
function cvSortBy(i){ cvSort=(cvSort&&cvSort[0]===i)?[i,-cvSort[1]]:[i,1]; $('#cv-body').innerHTML=cvTable(); }
/* Evidence coverage, as the engineer needs it: which resource types the scan could read, how
   many objects each held, and, for anything it could not read, why. A silent gap here is the
   difference between "no findings" and "nothing was looked at". */
function cvCollected(){
  const c=D.coverage||{}, k=c.kinds||{}, names=Object.keys(k).sort();
  if(!names.length) return '';
  const bad=names.filter(n=>k[n].status!=='ok');
  const rows=names.map(n=>{const v=k[n];
    return `<tr><td><b>${esc(n)}</b></td><td><span class='cv-st ${v.status==='ok'?'ok':v.status==='partial'?'warn':'bad'}'>${esc(v.status)}</span></td><td>${v.count??''}</td><td><small>${esc(v.reason||'')}</small></td></tr>`}).join('');
  return `<details class='panel cv-coll' ${bad.length?'open':''}><summary>Data collected by this scan
      <span class='cv-st ${bad.length?'warn':'ok'}'>${bad.length?bad.length+' not fully read':'all '+names.length+' resource types read'}</span></summary>
    <p class='fm'>The scan lists each resource type from the API once. If one cannot be read (permission, missing API group,
      very large list) it is shown here, and findings that depend on it are missing rather than clean.
      ${bad.length?'Grant the scanner <code>get/list</code> on the types below, then scan again.':'Nothing is missing, so a quiet result is a real one.'}</p>
    <table class='cv-t cv-tc'><thead><tr><th>Resource type</th><th>Read</th><th>Objects</th><th>Note</th></tr></thead><tbody>${rows}</tbody></table></details>`;
}
function clusterView(){
  const inv=cvInv();
  if(!inv.sections) return `${healthNote()}<div class='panel'><div class='fm'>This scan was saved before the cluster inventory existed. Run a new scan to see it.</div></div>${cvCollected()}`;
  const h=(D.inventory||{}).health||{}, hs={healthy:'ok',converging:'warn',degraded:'bad'}[h.state]||'warn';
  return `${healthNote()}<div class='cv'>
    <div class='cv-head'><h2>Cluster</h2><span class='cv-st ${hs}'>${esc(HEALTH_LABEL[h.state]||h.state||'')}</span>
      <span class='fm'>${esc(h.reason||'')}</span><span class='cv-ver'>Kubernetes ${esc((inv.summary||{}).version||'')}</span></div>
    ${cvAttention()}
    <div id='cv-tiles' class='cv-tiles'>${cvTiles()}</div>
    <div id='cv-body' class='panel cv-body'>${cvTable()}</div>
    ${cvCollected()}</div>`;
}
/* ---- shared drawer: one slide-over for every kind of detail -------------------------------- */
function drawerOpen(html){ const d=$('#drawer'); if(!d) return;
  d.innerHTML=`<button class='cv-x' type='button' onclick='drawerClose()' aria-label='Close'>&times;</button>`+html; d.classList.add('on'); }
function drawerClose(){ const d=$('#drawer'); if(d) d.classList.remove('on'); }
function copyText(t){ try{navigator.clipboard.writeText(t)}catch(e){} }
const techUrl=id=>id?`https://attack.mitre.org/techniques/${String(id).replace('.','/')}/`:'';

/* ---- Issues: one row per thing to fix --------------------------------------------------------
   A row is a rule on an owning workload (the unit an engineer actually edits). The resource-level
   findings behind it (Deployment, ReplicaSet, Pod) are its evidence and live in the drawer, so the
   same flaw is never listed three times. */
let isOwn='', isQ='', isNs='', isDom='', isTac='', isGroup='', isSev=new Set(), isFlags=new Set(), isSort='priority', isDir=1;
function issuesData(){
  if(D.__iss) return D.__iss;
  const byId={}; (D.findings||[]).forEach(f=>byId[f.resource_finding_id]=f);
  D.__iss=(D.workload_issues||[]).map((w,i)=>{
    const f=byId[(w.resource_finding_ids||[])[0]]||{}, tags=f.exploitable_by||[];
    return {i,w,f,exposed:tags.includes('ingress'),admin:tags.includes('rbac-escalation'),
      text:[w.title,w.rule_id,w.workload,w.namespace,w.owner,w.owning_shard,(w.tactics||[]).join(' ')].join(' ').toLowerCase()};});
  return D.__iss;
}
const issueFlags=r=>[r.exposed?chip('Internet-exposed',true):'',r.admin?chip('cluster-admin identity',true):''].join('');
function issueMatch(r){
  const w=r.w;
  if(isSev.size&&!isSev.has(w.severity)) return false;
  if(isOwn&&(w.owner||'')!==isOwn) return false;
  if(isNs&&(isNs==='__cluster'?!!w.namespace:(w.namespace||'')!==isNs)) return false;
  if(isDom&&w.owning_shard!==isDom) return false;
  if(isTac&&!(w.tactics||[]).includes(isTac)) return false;
  if(isFlags.has('exposed')&&!r.exposed) return false;
  if(isFlags.has('admin')&&!r.admin) return false;
  if(isQ&&!r.text.includes(isQ)) return false;
  return true;
}
const ISORT={priority:r=>-(r.w.score||0),severity:r=>SEV.indexOf(r.w.severity),issue:r=>r.w.title,where:r=>r.w.workload,domain:r=>r.w.owning_shard};
function issuesView(){
  const all=issuesData(), owners=[...new Set(all.map(r=>r.w.owner||''))].filter(Boolean).sort(), nss=[...new Set(all.map(r=>r.w.namespace||''))].sort(), doms=[...new Set(all.map(r=>r.w.owning_shard))].sort(),
    tacs=[...new Set(all.flatMap(r=>r.w.tactics||[]))].sort();
  return `${riskDrivers()}<div class='panel cv-body'>${healthNote()}
    <div class='cv-bar'><div class='cv-ttl'><h2>Issues</h2><span>${all.length} things to fix, behind ${(D.findings||[]).length} resource-level findings. Click one for why, how to fix it and how to check.</span></div></div>
    <div id='is-chips' class='is-chips'></div>
    <div class='is-ctl'>
      <input class='cv-q' type='search' placeholder='Search issue, rule, workload…' value='${esc(isQ)}' oninput='isQ=this.value.toLowerCase();isRefresh()' aria-label='Search issues'>
      ${owners.length>1?`<select onchange='isOwn=this.value;isRefresh()' aria-label='Owner'><option value=''>All owners</option>${owners.map(o=>`<option ${o===isOwn?'selected':''}>${esc(o)}</option>`).join('')}</select>`:''}
      <select onchange='isNs=this.value;isRefresh()' aria-label='Namespace'><option value=''>All namespaces</option>${nss.map(n=>{const v=n||'__cluster';return `<option value='${esc(v)}' ${v===isNs?'selected':''}>${esc(n||'cluster-wide (no namespace)')}</option>`}).join('')}</select>
      <select onchange='isDom=this.value;isRefresh()' aria-label='Domain'><option value=''>All domains</option>${doms.map(d=>`<option value='${esc(d)}' ${d===isDom?'selected':''}>${esc(domainName(d))}</option>`).join('')}</select>
      <select onchange='isTac=this.value;isRefresh()' aria-label='Tactic'><option value=''>All tactics</option>${tacs.map(t=>`<option ${t===isTac?'selected':''}>${esc(t)}</option>`).join('')}</select>
      <select onchange='isGroup=this.value;isRefresh()' aria-label='Group by'><option value=''>No grouping</option>
        ${[['workload','Group by workload'],['rule','Group by rule'],['namespace','Group by namespace'],['domain','Group by domain']].map(([k,l])=>`<option value='${k}' ${k===isGroup?'selected':''}>${l}</option>`).join('')}</select>
    </div>
    <div id='is-body'></div></div>`;
}
function isToggleSev(s){ isSev.has(s)?isSev.delete(s):isSev.add(s); isRefresh(); }
function isToggleFlag(f){ isFlags.has(f)?isFlags.delete(f):isFlags.add(f); isRefresh(); }
function isSortBy(k){ if(isSort===k) isDir*=-1; else{isSort=k;isDir=1;} isRefresh(); }
function isRefresh(){
  if(!$('#is-body')) return;
  const all=issuesData(), counts={}; all.forEach(r=>counts[r.w.severity]=(counts[r.w.severity]||0)+1);
  $('#is-chips').innerHTML=SEV.slice(0,4).filter(s=>counts[s]).map(s=>`<button type='button' class='is-chip ${isSev.has(s)?'on':''}' data-sev='${s}' aria-pressed='${isSev.has(s)}' onclick='isToggleSev("${s}")'><span class='sev ${s}'>${s}</span> ${counts[s]}</button>`).join('')
    +`<span class='is-sep'></span>`+[['exposed','Internet-exposed',all.filter(r=>r.exposed).length],['admin','Cluster-admin identity',all.filter(r=>r.admin).length]]
    .map(([k,l,n])=>`<button type='button' class='is-chip ${isFlags.has(k)?'on':''}' aria-pressed='${isFlags.has(k)}' onclick='isToggleFlag("${k}")'>${l} <b>${n}</b></button>`).join('');
  let rows=all.filter(issueMatch);
  const key=ISORT[isSort]; rows=[...rows].sort((a,b)=>{const x=key(a),y=key(b);return (x>y?1:x<y?-1:0)*isDir||((b.w.score||0)-(a.w.score||0));});
  const row=r=>`<tr tabindex='0' onclick='openIssue(${r.i})' onkeydown='if(event.key==="Enter")openIssue(${r.i})'>
    <td><span class='sev ${r.w.severity}'>${r.w.severity}</span></td>
    <td><b>${esc(r.w.title)}</b><small><code>${esc(r.w.rule_id)}</code></small></td>
    <td><b>${esc(r.w.workload)}</b><small>${esc(r.w.namespace||'cluster-wide')}${r.w.resource_count>1?' · '+r.w.resource_count+' objects':''}</small></td>
    <td>${issueFlags(r)||"<span class='cv-ok'>-</span>"}</td><td><small>${esc(domainName(r.w.owning_shard))}</small></td>
    <td>${(r.w.tactics||[]).slice(0,2).map(t=>chip(t)).join('')}</td><td>${(r.w.score||0).toFixed(0)}</td></tr>`;
  const gk={workload:r=>r.w.workload,rule:r=>r.w.title,namespace:r=>r.w.namespace||'cluster-wide',domain:r=>domainName(r.w.owning_shard)}[isGroup];
  let body;
  if(gk){ const g={}; rows.forEach(r=>(g[gk(r)]=g[gk(r)]||[]).push(r));
    body=Object.entries(g).sort((a,b)=>Math.min(...a[1].map(r=>SEV.indexOf(r.w.severity)))-Math.min(...b[1].map(r=>SEV.indexOf(r.w.severity)))||b[1].length-a[1].length)
      .map(([k,v])=>`<tr class='is-g'><td colspan='7'><b>${esc(k)}</b> <span>${v.length} issue${v.length===1?'':'s'}</span> <span class='sev ${SEV[Math.min(...v.map(r=>SEV.indexOf(r.w.severity)))]}'>${SEV[Math.min(...v.map(r=>SEV.indexOf(r.w.severity)))]}</span></td></tr>`+v.map(row).join('')).join('');
  } else body=rows.slice(0,500).map(row).join('');
  const h=(k,l)=>`<th><button type='button' onclick='isSortBy("${k}")'>${l}${isSort===k?(isDir>0?' &#9650;':' &#9660;'):''}</button></th>`;
  $('#is-body').innerHTML=`<div class='cv-count'>${rows.length} of ${all.length} issues${rows.length>500&&!gk?', showing 500':''}</div>
    <div class='cv-scroll'><table class='cv-t'><thead><tr>${h('severity','Severity')}${h('issue','Issue')}${h('where','Where')}<th>Why it is urgent</th>${h('domain','Domain')}<th>Tactic</th>${h('priority','Score')}</tr></thead>
    <tbody>${body||"<tr><td colspan='7' class='cv-none'>Nothing matches.</td></tr>"}</tbody></table></div>`;
}
function openIssueByGroup(g){ const r=issuesData().find(x=>x.w.aggregation_group===g); if(r) openIssue(r.i); }
function openIssue(i){
  const r=issuesData()[i]; if(!r) return; const w=r.w, f=r.f;
  drawerOpen(`<div class='cv-dk'>Issue · ${esc(w.namespace||'cluster-wide')}</div><h3>${esc(w.title)}</h3>
    <div class='cv-chips'><span class='sev ${w.severity}'>${w.severity}</span> ${issueFlags(r)}</div>
    <dl class='cv-facts'><dt>Where</dt><dd><b>${esc(w.workload)}</b></dd><dt>Rule</dt><dd><code>${esc(w.rule_id)}</code></dd>
      <dt>Owner</dt><dd>${esc(w.owner||'-')}${w.owner_source&&w.owner_source!=='namespace'?` <small>(label ${esc(w.owner_source)})</small>`:''}</dd><dt>Domain</dt><dd>${esc(domainName(w.owning_shard))}</dd><dt>Tactics</dt><dd>${(w.tactics||[]).map(esc).join(', ')||'-'}</dd>
      <dt>Score</dt><dd>${(w.score||0).toFixed(1)}</dd></dl>
    ${f.message?`<div class='cv-iss' style='border-left-color:var(--${SEVVAR[w.severity]||'info'})'>${esc(f.message)}</div>`:''}
    <div id='is-ctx'><div class='fm'>Loading why it matters and how to fix it…</div></div>
    <div class='cv-dh'>Affected objects (${w.resource_count})</div>
    <ul class='cv-objs'>${(w.resources||[]).slice(0,40).map(x=>`<li><code>${esc(x)}</code></li>`).join('')}</ul>
    <div class='cv-links'><a href='javascript:cvOpenWorkload("${esc(w.workload_name||'')}")'>Show in Cluster &rarr;</a> · <a href='/graph?scan_id=${encodeURIComponent(D.scan.scan_id)}'>Attack paths &rarr;</a> · <a href='javascript:incOpen("${esc((w.namespace||'')+'/'+(w.workload_kind||'')+'/'+(w.workload_name||''))}")'>Investigate &rarr;</a> · <a href='javascript:acceptRisk("${esc(w.rule_id)}","${esc((w.namespace||'')+'/'+(w.workload_kind||'*')+'/'+(w.workload_name||'*'))}")'>Accept risk &rarr;</a></div>`);
  if(f.resource) loadIssueCtx(f);
}
function ctxFill(d,f){
  const box=$('#is-ctx'); if(!box) return;
  const fx=d.fix||{}, ex=d.explanation||{};
  const std=(ex.standards||[]).map(s=>s.url?`<a class='tchip' href='${esc(s.url)}' target='_blank' rel='noopener'>${esc(s.framework)} ${esc(s.control)}</a>`:`<span class='tchip'>${esc(s.framework)} ${esc(s.control)}</span>`).join('');
  const mit=(ex.mitre||[]).map(m=>`<a class='tchip' href='${esc(m.url||techUrl(m.technique_id))}' target='_blank' rel='noopener'>${esc(m.tactic)} · ${esc(m.technique_id||'')} ${esc(m.technique_name||'')}</a>`).join('');
  const vs=(d.validation||[]).join('\n');
  box.innerHTML=`${d.impact?`<div class='cv-dh'>Why it matters</div><p class='cv-p'>${esc(d.impact)}</p>`:''}
    ${d.summary?`<div class='cv-dh'>What it is</div><p class='cv-p'>${esc(d.summary)}</p>`:''}
    ${exposureHTML(ex)}
    ${vulnHTML(ex.image_scan)}
    ${fx.how?`<div class='cv-dh'>How to fix it</div><p class='cv-p'>${esc(fx.how)}</p>
      ${fx.change?`<div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc(fx.change)}</pre></div>`:''}`:''}
    ${(fx.check||vs)?`<div class='cv-dh'>How to check</div><div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc([fx.check,vs].filter(Boolean).join('\n'))}</pre></div>`:''}
    ${(mit||std)?`<div class='cv-dh'>Mapped to</div><div class='cv-chips'>${mit}${std}</div>`:''}`;
}
function loadIssueCtx(f){
  const a=findingAnchor(f);
  if(FCTX[a]){ ctxFill(FCTX[a],f); return; }
  fetch(`/api/finding?scan_id=${encodeURIComponent(D.scan.scan_id)}&anchor=${encodeURIComponent(a)}`).then(r=>r.json())
    .then(d=>{ if(d&&!d.error){FCTX[a]=d; ctxFill(d,f);} else {const b=$('#is-ctx'); if(b) b.innerHTML="<div class='fm'>No extra context for this finding.</div>";} })
    .catch(()=>{const b=$('#is-ctx'); if(b) b.innerHTML="<div class='fm'>Could not load context.</div>";});
}
function cvOpenWorkload(name){ cvSec='workloads'; cvFilter=''; cvQ=name; cvSort=null; drawerClose(); location.hash='#cluster'; if($('#cv-body')) cvRefresh(); }

/* ---- Threat matrix: where the cluster is exposed, and where the scanner is blind ---------------- */
let mxFilter='';
function matrixView(){
  const sm=D.threat_matrix.summary, cols=D.threat_matrix.columns;
  const gaps=cols.reduce((a,c)=>a+c.cells.filter(x=>x.state==='gap').length,0);
  const k=(n,l,sub,cls)=>`<div class='mc-t ${cls||''}'><b>${n}</b><span>${l}</span><small>${sub}</small></div>`;
  const flt=[['','All techniques'],['hit','Exposed here'],['covered','Checked, nothing found'],['gap','No rule: blind spot']];
  return `${healthNote()}<div class='mx-k'>
    ${k(sm.techniques_hit,'techniques exposed',`across ${sm.tactics_hit} of ${sm.tactics_total} tactics`,sm.techniques_hit?'crit':'good')}
    ${k(sm.techniques_covered-sm.techniques_hit,'checked, nothing found',"a rule exists and found no issue",'good')}
    ${k(gaps,'blind spots',"techniques with no rule: silence means nothing",gaps?'warn':'good')}
    ${k(sm.coverage_pct+'%','detection coverage',`${sm.rule_count} rules over ${sm.techniques_total} techniques`)}</div>
  <div class='panel'><div class='cv-bar'><div class='cv-ttl'><h2>MITRE ATT&amp;CK for Containers</h2><span>Click a technique for what was found, which rules look for it, and what is not checked.</span></div>
    <div class='cv-f'>${flt.map(([v,l])=>`<button type='button' class='${v===mxFilter?'on':''}' onclick='mxFilter="${v}";mxRender()'>${l}</button>`).join('')}</div></div>
    <div id='mx-grid'>${mxGrid()}</div>
    <div class='leg'><span><i style='background:var(--crit)'></i>Exposed (colour = worst severity)</span><span><i style='background:var(--low)'></i>Rule exists, nothing found</span><span><i style='background:var(--muted)'></i>No rule</span></div></div>`;
}
function mxGrid(){
  const cols=D.threat_matrix.columns;
  return `<div class='mx'>`+cols.map((c,ci)=>`<div class='mxcol'><div class='mxh'>${esc(c.tactic)}<small>${c.techniques_hit}/${c.techniques_total}</small></div>`+
    c.cells.map((cell,xi)=>{const st=cell.state, dim=mxFilter&&mxFilter!==st?' dim':'';
      return `<div class='cell ${st}${dim} clk' ${st==='hit'?`data-sev='${cell.max_severity||''}'`:''} tabindex='0' role='button' onclick='openTechnique(${ci},${xi})' onkeydown='if(event.key==="Enter")openTechnique(${ci},${xi})'>
        ${esc(cell.technique_name)}${cell.count?`<span class='c'>${cell.count}</span>`:''}</div>`}).join('')+`</div>`).join('')+`</div>`;
}
function mxRender(){ const g=$('#mx-grid'); if(g) g.innerHTML=mxGrid(); document.querySelectorAll('.cv-f button').forEach(()=>{}); const v=$('#v-matrix'); if(v) v.innerHTML=matrixView(); }
function openTechnique(ci,xi){
  const col=D.threat_matrix.columns[ci], c=col.cells[xi];
  const titles={}; (D.workload_issues||[]).forEach(w=>titles[w.rule_id]=w.title);
  const issues=(D.workload_issues||[]).filter(w=>(c.finding_rule_ids||[]).includes(w.rule_id)&&(w.tactics||[]).includes(col.tactic))
    .sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity));
  const state={hit:['Exposed in this cluster','bad'],covered:['Checked, nothing found','ok'],gap:['Not checked: no rule covers this','warn']}[c.state]||['',''];
  const rules=[...(c.rule_ids||[])].map(r=>`<li><code>${esc(r)}</code>${titles[r]?` &middot; ${esc(titles[r])}`:''}</li>`).join('');
  const rt=(c.runtime_rule_ids||[]).map(r=>`<li><code>${esc(r)}</code> <small>runtime</small></li>`).join('');
  drawerOpen(`<div class='cv-dk'>${esc(col.tactic)}</div><h3>${esc(c.technique_name)}</h3>
    <div class='cv-chips'><span class='cv-st ${state[1]}'>${state[0]}</span>${c.technique_id?`<a class='tchip' href='${esc(c.url||techUrl(c.technique_id))}' target='_blank' rel='noopener'>${esc(c.technique_id)} &#8599;</a>`:''}</div>
    ${c.state==='gap'?`<p class='cv-p'>No rule in this scanner looks for this technique, so a clean result here is not evidence of safety. Check it another way (runtime detection, an admission policy, or a dedicated scanner).</p>`:''}
    ${c.state==='covered'?`<p class='cv-p'>${(c.rule_ids||[]).length} rule(s) check for this technique and found nothing in this scan.</p>`:''}
    ${issues.length?`<div class='cv-dh'>Issues using this technique (${issues.length})</div>`+issues.slice(0,40).map(w=>`<button type='button' class='cv-a ${w.severity}' style='width:100%;margin:.3rem 0' onclick='openIssueByGroup("${esc(w.aggregation_group)}")'><span class='sev ${w.severity}'>${w.severity}</span><b>${esc(w.title)}</b><small>${esc(w.workload)}${w.namespace?' · '+esc(w.namespace):''}</small><i>&rsaquo;</i></button>`).join(''):''}
    ${(rules||rt)?`<div class='cv-dh'>Rules that look for it</div><ul class='cv-objs'>${rules}${rt}</ul>`:''}`);
}

// What the risk score is actually made of. Rendered straight from the server's own
// breakdown, the browser does no scoring arithmetic of its own.
function riskContributors(){
  const x=D.risk_explanation||{};
  if(!x.by_severity) return "<div class='fm'>No scored findings in this scan.</div>";
  const rows=Object.entries(x.by_tactic||{}).slice(0,6).map(([k,v])=>
    `<div class='bar'><div class='barl'>${esc(k)}</div><div class='bart'>
      <div class='barf' style='width:${Math.max(v.share_pct,6)}%;background:var(--accent)'>${v.share_pct}% · ${v.issues} issue${v.issues===1?'':'s'}</div></div></div>`).join('');
  // `resource` here is the server's pre-rendered string, not the {kind,name,namespace}
  // object findingAnchor() needs, so these rows are plain text rather than deep links.
  const top=(x.top_contributors||[]).slice(0,3).map(f=>
    `<div class='findlink'>
      <span class='sev ${f.severity}'>${f.severity}</span>
      <span class='fl-t'>${esc(f.rule_id)}</span>
      <span class='fl-r'><code>${esc(f.workload)}${f.namespace?' ('+esc(f.namespace)+')':''}</code></span>
      <span class='fl-go'>${f.share_pct}%</span></div>`).join('');
  return `<div class='fm'>Raw score ${x.raw_total} over ${x.scored_issues} workload issues,
    saturated to ${x.cluster_risk}/10. <code>${esc(x.formula||'')}</code></div>
    <div style='margin:.6rem 0'>${rows}</div>${top}`;
}
function posturePanel(){
  const p=D.posture;
  if(!p||!p.current_scan_id) return "<div class='fm'>No previous scan of this cluster to compare against.</div>";
  if(!p.previous_scan_id) return `<div class='fm'>${esc(p.summary)}</div>`;
  const cells=Object.entries(p.counts||{}).map(([sev,v])=>{
    const dir=v.delta>0?'up':v.delta<0?'down':'fm';
    const sign=v.delta>0?'+':'';
    return `<div class='kpi'><div class='n'>${v.current}</div><div class='l'>${esc(sev)}</div>
      <div class='s ${dir}'>${v.previous} &rarr; ${v.current} (${sign}${v.delta})</div></div>`}).join('');
  const list=(title,items,cls)=>items.length
    ? `<div class='fm' style='margin-top:.7rem'><b>${title} (${items.length})</b></div>`
      + items.slice(0,5).map(f=>`<div class='findlink ${cls}'><span class='sev ${f.severity}'>${f.severity}</span>
          <span class='fl-t'>${esc(f.rule_id)}</span><span class='fl-r'><code>${esc(f.resource)}</code></span></div>`).join('')
    : '';
  return `<div class='fm'>${esc(p.summary)}</div>
    <div class='kpis' style='margin:.8rem 0'>${cells}</div>
    ${list('Regressed (previously fixed, back again)',p.regressed||[],'')}
    ${list('New',p.new||[],'')}
    ${list('Resolved',p.resolved||[],'')}
    ${(p.not_rescanned||[]).length?`<div class='fm' style='margin-top:.6rem'>${p.not_rescanned.length}
      earlier finding(s) were <b>not re-scanned</b> by this run, so they are neither confirmed
      fixed nor still open.</div>`:''}`;
}
function priorityList(){
  const top=[...(D.workload_issues||[])].sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||b.score-a.score)
    .filter(w=>w.severity==='CRITICAL'||w.severity==='HIGH').slice(0,6);
  if(!top.length) return "<div class='fm'>No Critical or High severity issues.</div>";
  return top.map(w=>`<a class='findlink fl2' href='javascript:openIssueByGroup("${esc(w.aggregation_group)}")' title='Why it matters and how to fix it'
      style='border-left:3px solid var(--${w.severity.toLowerCase()})'>
    <span class='sev ${w.severity}'>${w.severity}</span>
    <span class='fl-m'><b>${esc(w.title)}</b><small>${esc(w.workload)}${w.namespace?' · '+esc(w.namespace):''}</small></span>
    <span class='fl-s'>${(w.score||0).toFixed(0)}</span><span class='fl-go'>&rsaquo;</span></a>`).join('')
    + `<div class='fm' style='margin-top:.6rem'><a href='#issues'>See all ${(D.workload_issues||[]).length} issues &rarr;</a></div>`;
}
function domainBars(){
  const by={}; (D.workload_issues||D.findings).forEach(f=>{(by[f.owning_shard||'other']=by[f.owning_shard||'other']||[]).push(f)});
  const rows=Object.entries(by).map(([k,v])=>({k,n:v.length,w:Math.max(...v.map(f=>SEV.length-SEV.indexOf(f.severity)))}))
    .sort((a,b)=>b.w-a.w||b.n-a.n);
  const mx=Math.max(...rows.map(r=>r.n),1);
  return rows.map(r=>{const worst=SEV[SEV.length-r.w];
    return `<div class='bar'><div class='barl'>${esc(domainName(r.k))}</div><div class='bart'>
    <div class='barf' style='width:${Math.max(r.n/mx*100,14)}%;background:var(--${SEVVAR[worst]||'info'})'>${r.n} issue${r.n===1?'':'s'} · ${worst}</div></div></div>`}).join('');
}
function trendBars(){
  const t=(D.trend||[]).filter(p=>typeof p[1]==='number');
  if(t.length<2) return "<div class='fm'>At least two scans are required to plot a trend.</div>";
  const vals=t.map(p=>p[1]),lo=Math.min(...vals),hi=Math.max(...vals),sp=(hi-lo)||1;
  const bars=t.slice(-12).map(([ts,v])=>{const h=10+Math.round(70*(v-lo)/sp);
    const c=v>=7?'crit':v>=4?'high':'low';return `<div class='tb' title='${esc(fmtTime(ts))}: ${v}' style='height:${h}%;background:var(--${c})'></div>`}).join('');
  const f=vals[0],l=vals[vals.length-1],ar=l<f?"<span class='down'>improving</span>":l>f?"<span class='up'>worsening</span>":'flat';
  return `<div class='fm'>Latest ${l} vs first ${f} · ${ar}</div><div class='trendbars'>${bars}</div>`;
}
function runtimeReadiness(){
  const rt=D.runtime, ex=rt.exposed_tactics||[];
  let covered=0;
  const rows=ex.map(t=>{const r=rt.by_tactic[t]||[];if(r.length){covered++;
    return `<div class='rr'><span class='rrdot ok'></span>${esc(t)}<span class='rrn'>${r.length} detection${r.length!==1?'s':''}</span></div>`}
    return `<div class='rr'><span class='rrdot gap'></span>${esc(t)}<span class='rrn warn'>no runtime detection</span></div>`}).join('');
  return `<div class='fm'>${covered} of ${ex.length} exposed tactics have runtime detection · ${rt.armed} detections active</div>${rows}
    <div class='fm' style='margin-top:.5rem'>Pull live events in the <a href='javascript:showTab("runtime")'>Runtime</a> tab.</div>`;
}
/* ---- findings ---- */
// Workload view: the same findings grouped by the object an operator would edit. A grouping
// of the resource-level table, never a replacement for it -- that table stays exactly as it
// was, and clicking a workload row here reveals the resource findings underneath it.
// Report-grade context (summary, impact, verification) is loaded on demand when a finding
// is expanded and cached by anchor, so the dashboard payload stays lean and a re-render
// (filter/sort) refills instantly from cache.
const FCTX={};
function exposureHTML(x){
  if(!x) return '';
  let out='';
  const n=x.network||{};
  if(n.evaluated){
    out+=`<div class='fdsec'><div class='sh'>Network</div>
      <div class='fm'>Ingress ${netStatusPill(n.ingress_status)} ${esc((n.ingress||{}).reason||'')}</div>
      <div class='fm'>Egress ${netStatusPill(n.egress_status)} ${esc((n.egress||{}).reason||'')}</div>
      ${n.confirmed_isolation?"<div class='fm'>Confirmed isolation.</div>"
        :"<div class='fm muted'>Not confirmed isolation, an unevaluable or absent policy is not protection.</div>"}
    </div>`;
  }
  const rb=x.rbac||{};
  if(rb.escalates && rb.shortest){
    const edges=((rb.paths||[])[0]||{}).edges||[];
    const hops=(rb.shortest.chain||'').split(' -> ').map(h=>
      `<span class='hop'>${esc(h)}</span>`).join("<span class='harrow'>&rarr;</span>");
    const rows=edges.map(e=>`<li><code>${esc(((e.from)||{}).name||'')}</code> ${esc(e.relationship||'')}
      <code>${esc(((e.to)||{}).name||'')}</code> , ${esc(e.reason||'')}</li>`).join('');
    out+=`<div class='fdsec'><div class='sh'>RBAC escalation</div>
      <div class='rbacpath'>${hops}</div>
      <div class='fm'>${esc(rb.shortest.summary||'')} · capabilities: ${(rb.capabilities||[]).map(esc).join(', ')}</div>
      ${rows?`<ul class='plist'>${rows}</ul>`:''}</div>`;
  }else if(rb.note){
    out+=`<div class='fdsec'><div class='sh'>RBAC escalation</div><p class='fm muted'>${esc(rb.note)}</p></div>`;
  }
  const cf=x.confidence||{};
  if(cf.label){
    out+=`<div class='fdsec'><div class='sh'>Confidence</div>
      <div class='fm'>${esc(cf.label)} (${Math.round((cf.score||0)*100)}%) , ${(cf.reasons||[]).map(esc).join('; ')}</div></div>`;
  }
  return out;
}
/* ---- attack path (force graph, cytoscape) ---------------------------
   Nodes = findings; an edge links two findings that share a resource
   across consecutive kill-chain stages (the same Pod hit at Initial
   Access, then again at Impact). Click a node to light up its connected
   component and see (a) every other stage that resource is still
   exposed at, remediating this finding alone won't clear those, and
   (b) sibling findings that reach the SAME stage via a different
   resource/technique, i.e. what remediation still leaves open. */
function freshPill(f, days){
  if(!f || f==='none' || f==='recent') return '';
  const age = (days||days===0) ? ` (${Math.round(days)}d old)` : '';
  const cls = f==='historical' ? 'medium' : 'info';
  const help = f==='historical'
    ? 'This behaviour WAS observed, but not recently. It is not evidence of current activity.'
    : 'The runtime event carried no usable timestamp, so its age is unknown.';
  return `<span class='tag ${cls}' title='${esc(help)}'>${esc(f)}${age}</span>`;
}
function netStatusPill(s){
  const cls={'allow-all':'critical','unrestricted':'high','partial':'medium',
             'unknown':'medium','restricted':'low','deny-all':'low'}[s]||'info';
  return `<span class='tag ${cls}' title='${esc(NET_HELP[s]||'')}'>${esc(s||'unknown')}</span>`;
}
const NET_HELP={
  'unrestricted':'No NetworkPolicy governs this direction (Kubernetes default: allowed).',
  'allow-all':'A policy governs it but a rule admits every peer. Not isolation.',
  'restricted':'Governed, limited to named peers.',
  'deny-all':'Governed with no rules: nothing may pass.',
  'partial':'A selector could not be evaluated. The restriction is UNCONFIRMED, and is not treated as isolation.',
  'unknown':'No NetworkPolicy evidence was collected.'};
/* ---- runtime ---- */
/* ---- Dependencies: what each running image contains, what is vulnerable, and what is really loaded ---- */
let DP={imgs:null,tools:{},db:{},sel:null,rep:null,f:'fix',q:'',res:null,busy:'',err:'',timer:null,open:{},install:null,installTried:false};
const dpPost=async(a,b)=>{ const r=await fetch('/api/deps/'+a,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}); const d=await r.json().catch(()=>({error:'Bad reply'})); if(!r.ok) throw new Error(d.error||'Failed'); return d; };
function depsView(){ setTimeout(dpInit,0); return `<div id='dp-root'><div class='panel'><div class='bd-none'>Loading…</div></div></div>`; }
async function dpInit(){ if(DP.imgs) return dpRender(); await dpLoad(); }
async function dpLoad(){
  try{ const d=await dpPost('images'); DP.imgs=d.images; DP.tools=d.tools; DP.db=d.db||{}; DP.install=d.install; DP.err=d.error||''; }
  catch(e){ DP.err=e.message; DP.imgs=DP.imgs||[]; }
  // syft/grype ship with the tool: provision them once, automatically, the first time they're missing.
  const missing=!DP.tools.syft||!DP.tools.grype;
  if(missing&&!DP.installTried&&(!DP.install||DP.install.state!=='running')){ DP.installTried=true; return dpInstall(); }
  dpRender();
  const installing=DP.install&&DP.install.state==='running';
  const busy=installing||(DP.imgs||[]).some(i=>i.job&&i.job.state==='running');
  clearTimeout(DP.timer); if(busy&&activeTab==='deps') DP.timer=setTimeout(dpLoad,installing?3000:4000);
  if(DP.sel&&!busy&&DP.rep&&DP.rep.image&&DP.rep.image.key!==DP.sel) dpOpen(DP.sel);
}
async function dpInstall(force){ try{ const d=await dpPost('install',force?{db:true}:{}); DP.install=d.install||{state:'running'}; DP.tools=d.tools||DP.tools; DP.db=d.db||DP.db; }catch(e){ DP.err=e.message; } dpRender(); clearTimeout(DP.timer); DP.timer=setTimeout(dpLoad,3000); }
const dpWl=i=>(i.workloads||[]).slice(0,3).map(w=>esc(w.namespace+'/'+w.name)).join(', ')+((i.workloads||[]).length>3?` +${i.workloads.length-3}`:'');
function dpChip(i){
  if(i.job&&i.job.state==='running') return `<span class='cv-st warn'>building SBOM…</span>`;
  if(i.job&&i.job.state==='error') return `<span class='cv-st bad' title='${esc(i.job.error)}'>SBOM failed</span>`;
  return i.sbom?`<span class='cv-st ok'>SBOM ready</span>`:`<span class='cv-st info'>no SBOM yet</span>`;
}
function dpRender(){
  const el=$('#dp-root'); if(!el) return; const T=DP.tools||{}, im=DP.imgs||[];
  const miss=[!T.syft&&'syft',!T.grype&&'grype'].filter(Boolean);
  const head=`<div class='panel rt-head'><div><h2>Dependencies</h2><small class='fm'>Every image your pods run, what is inside it, which parts are vulnerable, and which parts the container really loads.</small></div>
    <div class='rt-row'><button class='btn' type='button' onclick='dpBuild(true)' ${miss.length||DP.busy?'disabled':''}>Build SBOMs for all images</button></div></div>
    ${dpToolsBox(miss)}
    ${DP.err?`<div class='bd-todo bad'><div><b>${esc(DP.err)}</b></div></div>`:''}
    <div class='panel'><label class='rt-l'>Where does a package run?<input id='dp-q' value='${esc(DP.q)}' placeholder='log4j, openssl, curl…' onkeydown='if(event.key==="Enter")dpSearch()'><small>Searches the SBOMs already built. ${im.filter(i=>i.sbom).length} of ${im.length} images have one.</small></label>${DP.res?dpResults():''}</div>`;
  const list=im.length?im.map(i=>`<button type='button' class='bd-row ${DP.sel===i.key?'on':''}' onclick='dpOpen("${esc(i.key)}")'><span class='bd-rt'><b>${esc(i.image.split('/').pop())}</b><small>${dpWl(i)}</small></span>${dpChip(i)}</button>`).join(''):`<div class='bd-none'>No running images found. Scan a cluster first.</div>`;
  el.innerHTML=`${head}<div class='dp-grid'><aside class='panel dp-list'><div class='bd-lh'>Running images <small>${im.length}</small></div>${list}</aside><main class='panel dp-main' id='dp-main'>${dpMain()}</main></div>`;
}
function dpToolsBox(miss){
  const T=DP.tools||{}, db=DP.db||{}, ins=DP.install, running=ins&&ins.state==='running';
  const dbOk=db.state==='valid';
  const ageDays=db.built?Math.floor((Date.now()-Date.parse(db.built))/864e5):null;
  const dbStale=dbOk&&ageDays!=null&&ageDays>7;   // match the live-scan staleness warning
  // tool pill: ok (ready) / warn (installing) / bad (missing)
  const pill=(label,ok,note)=>{ const cls=ok?'ok':(running?'warn':'bad'), mk=ok?'✓':(running?'…':'✗');
    return `<span class='dp-tool'><b class='cv-st ${cls}'>${mk} ${ok?'Ready':(running?'Installing…':'Missing')}</b> ${label}${note?` <small>${esc(note)}</small>`:''}</span>`; };
  // DB pill carries its own warn state for a stale-but-valid DB
  const dbMk=running?'…':(dbOk?(dbStale?'!':'✓'):'✗'), dbCls=running?'warn':(dbOk?(dbStale?'warn':'ok'):'bad');
  const dbTxt=running?'Updating…':(dbOk?(dbStale?ageDays+' days old':'Ready'):'Missing');
  const dbNote=dbOk?('built '+(db.built||'').slice(0,10)):(db.state==='no-grype'?'needs grype':'');
  const strip=`<div class='dp-tools'>
    ${pill('syft',!!T.syft,'SBOM builder')}
    ${pill('grype',!!T.grype,'CVE scanner')}
    <span class='dp-tool'><b class='cv-st ${dbCls}'>${dbMk} ${dbTxt}</b> Vulnerability DB${dbNote?` <small>${esc(dbNote)}</small>`:''}</span>
  </div>`;
  const err=ins&&ins.state==='error'?Object.entries(ins.result||{}).filter(([,v])=>v&&v.error).map(([k,v])=>k+': '+v.error).join('; '):'';
  const foot=running?`<small class='fm'>Downloading the official binaries and the vulnerability database. First run takes a minute or two.</small>`
    : err?`<small class='fm'>${esc(err)}</small> <button class='btn' type='button' onclick='dpInstall()'>Retry</button>`
    : miss.length?`<button class='btn' type='button' onclick='dpInstall()'>Install ${miss.join(' & ')}</button>`
    : !dbOk?`<button class='btn' type='button' onclick='dpInstall()'>Download vulnerability DB</button>`
    : `<button class='btn' type='button' onclick='dpInstall(true)'>Update DB</button>`;
  return `<div class='bd-todo ${(miss.length||!dbOk||dbStale)&&!running?'bad':''}'><div style='flex:1'>${strip}</div>${foot}</div>`;
}
function dpResults(){
  const r=DP.res; if(!r.results.length) return `<div class='bd-none'>No package matches in ${r.searched} SBOM(s).${r.searched<r.images?' Build the rest to widen the search.':''}</div>`;
  return `<div class='dp-res'>${r.results.map(h=>`<div class='bd-fl'><b>${esc(h.name)} ${esc(h.version)}</b><small>${esc(h.type)} · ${h.images.length} image(s) · ${h.workloads.map(w=>esc(w.namespace+'/'+w.name)).join(', ')}</small></div>`).join('')}</div>`;
}
async function dpSearch(){ DP.q=$('#dp-q').value; try{ DP.res=await dpPost('search',{q:DP.q}); DP.err=''; }catch(e){ DP.err=e.message; } dpRender(); }
async function dpBuild(all,key){ DP.busy='x'; try{ await dpPost('generate',all?{all:true}:{keys:[key]}); }catch(e){ DP.err=e.message; } DP.busy=''; await dpLoad(); }
async function dpOpen(key){
  DP.sel=key; DP.rep=null; DP.err=''; dpRender();
  const i=(DP.imgs||[]).find(x=>x.key===key); if(!i||!i.sbom) return;
  try{ DP.rep=await dpPost('report',{key}); }catch(e){ DP.err=e.message; }
  dpRender();
}
async function dpObserve(){
  if(!confirm('This runs read-only commands inside up to 3 pods of this image (it reads /proc to see which files are loaded). Nothing is changed. It needs permission to exec into pods. Continue?')) return;
  DP.busy='observe'; dpRender();
  try{ const d=await dpPost('observe',{key:DP.sel,confirm:'observe'}); DP.err=d.observed?'':'Could not observe: '+d.pods.map(p=>p.error).filter(Boolean).join('; ')+'. Images without a shell cannot be observed this way.'; }catch(e){ DP.err=e.message; }
  DP.busy=''; await dpLoad(); await dpOpen(DP.sel);
}
async function dpExport(fmt){ try{ const r=await fetch('/api/deps/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:DP.sel,format:fmt})}); if(!r.ok) throw new Error((await r.json()).error); const b=await r.blob(); const a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download='sbom-'+fmt+'.json'; a.click(); }catch(e){ DP.err=e.message; dpRender(); } }
const DPUSE={'in-use':['ok','in use'],'in-running-archive':['ok','inside a running jar'],'not-seen':['info','not seen'],'cannot-tell':['info','cannot tell'],'not-observed':['info','not checked']};
const DPKIND={direct:'direct',indirect:'indirect',unknown:'unknown'};
function dpMain(){
  if(!DP.sel) return `<div class='bd-none'>Pick an image. Build its SBOM first if it has none.</div>`;
  const i=(DP.imgs||[]).find(x=>x.key===DP.sel); if(!i) return '';
  if(!i.sbom) return `<h3>${esc(i.image)}</h3><p class='bd-note'>Used by ${dpWl(i)}</p><button class='btn' type='button' onclick='dpBuild(false,"${esc(i.key)}")' ${DP.tools.syft?'':'disabled'}>Build SBOM for this image</button><p class='bd-note'>This pulls the image and lists everything inside it. It can take a minute or two.</p>`;
  const r=DP.rep; if(!r) return `<div class='bd-none'>Loading…</div>`;
  const s=r.summary, F=DP.f;
  const rows=r.packages.filter(p=>F==='all'||(F==='fix'&&p.worst&&['in-use','in-running-archive'].includes(p.usage))||(F==='vuln'&&p.worst)||(F==='use'&&['in-use','in-running-archive'].includes(p.usage))||(F==='unseen'&&p.usage==='not-seen')||(F==='direct'&&p.kind==='direct'));
  const tile=(n,l,c)=>`<div class='dp-t'><b class='${c||''}'>${n}</b><small>${l}</small></div>`;
  const f=(k,l)=>`<button type='button' class='bd-chip ${F===k?'on':''}' onclick='DP.f="${k}";dpRender()'>${l}</button>`;
  const obs=r.observation;
  return `<div class='bd-ih'><div><b>${esc(r.image.image)}</b><small>${esc(s.distro)} · used by ${dpWl(r.image)}</small></div><button class='bd-btn' type='button' onclick='dpExport("cyclonedx-json")'>Export CycloneDX</button><button class='bd-btn' type='button' onclick='dpExport("spdx-json")'>Export SPDX</button></div>
   <div class='dp-tiles'>${tile(s.packages,'packages')}${tile(s.direct+' / '+s.indirect,'direct / indirect')}${tile(s.vulnerable,'vulnerable',s.vulnerable?'r':'')}${tile(s.observed?s.inUse:'—','in use at runtime')}${tile(s.observed?s.fixFirst:'—','vulnerable and in use',s.fixFirst?'r':'')}</div>
   ${s.vulnError?`<div class='bd-todo bad'><div><b>Vulnerability match failed</b><small>${esc(s.vulnError)}</small></div></div>`:''}
   <div class='bd-env'>${obs?`Runtime check ${esc(obs.at)} on ${obs.pods.filter(p=>p.ok).length} pod(s). A package that is <b>not seen</b> is not proven unused: Python and Node modules and files read once at startup cannot be seen this way.`:`Presence is not use. Check which of these packages the container really loads.`} <button class='btn' type='button' onclick='dpObserve()' ${DP.busy==='observe'?'disabled':''}>${DP.busy==='observe'?'Checking…':obs?'Check again':'Check what is in use'}</button></div>
   ${DP.err?`<div class='bd-todo bad'><div><b>${esc(DP.err)}</b></div></div>`:''}
   <div class='dp-f'>${f('fix','Fix first')}${f('vuln','Vulnerable')}${f('use','In use')}${f('unseen','Not seen')}${f('direct','Direct')}${f('all','All')}</div>
   ${rows.length?rows.slice(0,300).map(dpRow).join(''):`<div class='bd-none'>${F==='fix'&&!s.observed?'Run the runtime check to see which vulnerable packages are really loaded.':'Nothing matches this filter.'}</div>`}${rows.length>300?`<div class='bd-none'>+${rows.length-300} more. Narrow the filter.</div>`:''}`;
}
function dpRow(p){
  const [c,l]=DPUSE[p.usage]||['info',p.usage], k='p'+p.id, op=DP.open[k];
  const sev=p.worst?`<span class='sev ${esc(p.worst.toUpperCase())}'>${esc(p.worst)}</span>`:'';
  const v=op?`<div class='dp-d'>${p.vulns.map(x=>`<div><b>${esc(x.id)}</b> ${esc(x.severity)}${x.kev?' · <b>known exploited</b>':''}${x.fixedIn.length?' · fixed in '+esc(x.fixedIn.join(', ')):' · no fix yet'}</div>`).join('')}${p.neededBy.length?`<div>Needed by: ${p.neededBy.map(esc).join(', ')}</div>`:''}${p.needs.length?`<div>Needs: ${p.needs.map(esc).join(', ')}</div>`:''}<div class='fm'>${p.paths.slice(0,2).map(esc).join(' · ')}</div></div>`:'';
  return `<div class='dp-r'><button type='button' class='dp-rb' onclick='DP.open["${k}"]=!DP.open["${k}"];dpRender()'><b>${esc(p.name)}</b><small>${esc(p.version)} · ${esc(p.type)}</small><span class='cv-st info'>${DPKIND[p.kind]}</span><span class='cv-st ${c}'>${l}</span>${sev}</button>${v}</div>`;
}
/* ---- Runtime: what is deployed, a guided way to add a rule, and Falco itself --------------------
   Four sub-tabs. Overview is the correlation view that was always here. Rules lists every rule in play
   and what it watches in plain words. Create rule turns a few fields into a Falco rule and proves it on
   example events before anything ships. Falco shows whether it is running and, only if the operator
   opted in, deploys it into its own namespace. */
let RT={tab:'overview',cat:null,beh:null,status:null,plan:null,run:null,pollT:null,filter:'all',q:'',open:null,
  spec:null,gen:null,tests:null,engine:null,customEv:[],msg:'',busy:'',defaultsLoaded:false,confirm:false,example:'',stats:null,tuning:{},health:null,cov:null,agents:null,agentErr:'',alerts:{slack_webhook:'',min_priority:'warning'},sim:null,hist:null,helm:null,helmT:null};
const rtNewSpec=()=>({name:'',description:'',behavior:'',values:{},scope:{namespaces:'',exclude_namespaces:'',images:'',containers_only:true},exceptions:[],priority:'',stage:'audit',tactic:'',technique:''});
async function rtApi(action,body){ try{ const r=await fetch('/api/runtime-rules/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); const d=await r.json(); d._ok=r.ok; d._status=r.status; return d; }catch(e){ return {_ok:false,error:'Could not reach the dashboard.'}; } }
function runtimeView(){ setTimeout(rtInit,0); return `<div id='rt-root'>${rtShell()}</div>`; }
async function rtInit(){
  if(!RT.beh){ const b=await rtApi('behaviors'); if(b._ok) RT.beh=b; }
  if(!RT.cat){ const c=await rtApi('catalog',{}); if(c._ok) RT.cat=c; }
  rtRefresh(); const s=await rtApi('falco-status'); if(s._ok||s.state){ RT.status=s; } rtRefresh();
}
function rtRefresh(){ const r=$('#rt-root'); if(r) r.innerHTML=rtShell(); }
function rtTab(t){ RT.tab=t; if(t==='create'&&!RT.spec){ RT.spec=rtNewSpec(); } rtRefresh(); if(t==='falco'&&!RT.plan) rtPlan(); if(t==='coverage'&&!RT.cov) rtLoadCov(); if(t==='agents'&&!RT.agents) rtLoadAgents(); }
const rtStateChip=s=>!s?"<span class='cv-st warn'>checking Falco…</span>":({healthy:['ok','running'],partial:['warn','partly covered'],unhealthy:['bad','not working'],'not-installed':['warn','not installed'],unreachable:['warn','cluster not reachable']}[s.state]||['warn',s.state]).reduce((a,b)=>`<span class='cv-st ${a}'>Falco: ${b}</span>`);
function rtShell(){
  const tabs=[['overview','Overview'],['rules','Rules'],['create','Create a rule'],['coverage','Coverage'],['agents','Agents'],['falco','Falco']];
  const st=RT.status;
  const head=`<div class='panel rt-head'><div><h2>Runtime security</h2><small class='fm'>${st&&st.message?esc(st.message):'Rules that watch what containers actually do, and Falco, the engine that runs them.'}</small></div><div>${rtStateChip(st)}</div></div>
    <div class='bd-tabs' role='tablist'>${tabs.map(([t,l])=>`<button type='button' role='tab' class='${RT.tab===t?'on':''}' onclick='rtTab("${t}")'>${l}</button>`).join('')}</div>`;
  let body='';
  if(RT.tab==='overview') body=`<div class='panel'><h2>Runtime detection coverage</h2>${runtimeReadiness()}</div>`+runtimeFeed();
  else if(RT.tab==='rules') body=rtRulesHTML();
  else if(RT.tab==='create') body=rtCreateHTML();
  else if(RT.tab==='coverage') body=rtCoverageHTML();
  else if(RT.tab==='agents') body=rtAgentsHTML();
  else body=rtFalcoHTML();
  return head+body;
}
/* ---- Rules ---- */
function rtAll(){ const c=RT.cat||{curated:[],default:[],custom:[]}; return [...c.custom,...c.curated,...c.default]; }
function rtRulesHTML(){
  if(!RT.cat) return `<div class='panel'><div class='cv-none'>Loading rules…</div></div>`;
  const all=rtAll(), kinds=[['all','All'],['curated','K8sMatrixWarden'],['default',"Falco's own"],['custom','Mine']];
  let rows=all.filter(r=>RT.filter==='all'||r.kind===RT.filter); if(RT.q){ const q=RT.q.toLowerCase(); rows=rows.filter(r=>[r.name,r.tactic,r.technique,r.watches,r.source].join(' ').toLowerCase().includes(q)); }
  const cnt=k=>k==='all'?all.length:all.filter(r=>r.kind===k).length;
  const status=r=>r.kind==='curated'?"<span class='cv-st ok'>always on</span>":r.kind==='default'?(RT.status&&RT.status.state==='healthy'?"<span class='cv-st ok'>in Falco</span>":"<span class='cv-st warn'>needs Falco</span>")
     :(r.deployed?(r.changed_since_deploy?"<span class='cv-st warn'>changed, redeploy</span>":"<span class='cv-st ok'>deployed</span>"):"<span class='cv-st warn'>saved, not deployed</span>");
  const dflt=(RT.cat.default||[]).length?'':`<div class='bd-todo info'><div><b>Falco's own rules are not loaded yet</b><small>${esc(RT.cat.default_error||'Load the reference list of the rules Falco ships with. It is the current upstream list and may differ slightly from your cluster version.')}</small></div><button class='bd-btn' type='button' onclick='rtLoadDefaults()'>Load Falco's default rules</button></div>`;
  return `<div class='panel'><div class='rt-bar'><div class='bd-sub'>${kinds.map(([k,l])=>`<button type='button' class='${RT.filter===k?'on':''}' onclick='RT.filter="${k}";rtRefresh()'>${l} (${cnt(k)})</button>`).join('')}</div>
      <button class='bd-btn' type='button' onclick='rtLoadStats()' title='Reads Falco&#39;s recent alerts from the cluster'>Load fire counts</button><button class='bd-btn' type='button' onclick='rtExport()'>Export my rules</button><button class='bd-btn' type='button' onclick='rtImport()'>Import rules</button>
      <input class='cv-q' type='search' placeholder='Search rules, tactics, techniques…' value='${esc(RT.q)}' oninput='RT.q=this.value;rtRefresh();var i=$(".rt-bar .cv-q");if(i){i.focus();i.setSelectionRange(RT.q.length,RT.q.length);}'></div>${dflt}
    <div class='cv-scroll'><table class='cv-t'><thead><tr><th>Rule</th><th>Engine</th><th>Detects</th><th>Priority</th><th>MITRE</th><th>Fired (24h)</th><th>Status</th></tr></thead><tbody>${rows.map(r=>`<tr tabindex='0' onclick='rtOpenRule("${esc(r.id)}")' onkeydown='if(event.key==="Enter")rtOpenRule("${esc(r.id)}")'><td><b>${esc(r.name)}</b></td><td>${esc(r.engine)}<small>${esc(r.source)}</small></td><td class='rt-w'>${esc((r.watches||'').slice(0,140))}</td><td>${esc(r.priority)}</td><td>${esc(r.tactic)}<small>${esc(r.technique)}</small></td><td>${RT.stats?((RT.stats.stats[r.name]||{}).fires??0):'-'}</td><td>${status(r)}</td></tr>`).join('')||`<tr><td colspan='7' class='cv-none'>Nothing matches.</td></tr>`}</tbody></table></div></div>`;
}
async function rtLoadStats(){ RT.msg='Reading alerts…'; const d=await rtApi('rule-stats',{hours:24}); if(d._ok){ RT.stats=d; RT.tuning=d.tuning||{}; RT.msg=''; } else RT.msg=d.error||'Could not read alerts.'; rtRefresh(); }
async function rtExport(){ const d=await rtApi('export',{}); if(!d._ok||!d.pack.rules.length){ alert('You have no saved rules to export yet.'); return; }
  const blob=new Blob([JSON.stringify(d.pack,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='k8smatrixwarden-rules.json'; a.click(); URL.revokeObjectURL(a.href);
  const y=new Blob([d.yaml],{type:'text/yaml'}); const b=document.createElement('a'); b.href=URL.createObjectURL(y); b.download='k8smatrixwarden-falco-rules.yaml'; b.click(); URL.revokeObjectURL(b.href); }
function rtImport(){ const i=document.createElement('input'); i.type='file'; i.accept='.json,application/json'; i.onchange=async()=>{ const f=i.files[0]; if(!f) return; let pack; try{ pack=JSON.parse(await f.text()); }catch(e){ alert('That is not a rule pack file.'); return; }
  const d=await rtApi('import',{pack}); if(!d._ok){ alert(d.error||'Could not import.'); return; } RT.cat=Object.assign(RT.cat||{},{custom:d.custom}); RT.msg=`Imported ${d.imported.length}, skipped ${d.skipped.length} that already exist${d.errors.length?', '+d.errors.length+' had problems: '+d.errors.join('; '):''}.`; rtRefresh(); }; i.click(); }
async function rtLoadDefaults(){ RT.msg='Loading…'; const c=await rtApi('catalog',{defaults:true}); if(c._ok) RT.cat=c; rtRefresh(); }
function rtOpenRule(id){ const r=rtAll().find(x=>x.id===id); if(!r) return;
  const y=r.kind==='custom'?`<div class='cv-dh'>The Falco rule</div><div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre id='rt-y'>loading…</pre></div>`:'';
  drawerOpen(`<div class='cv-dk'>${esc(r.engine)} · ${esc(r.source)}</div><h3>${esc(r.name)}</h3>
   <div class='cv-chips'>${chip(r.priority,['CRITICAL','HIGH','EMERGENCY','ALERT'].includes(r.priority))}${r.tactic?chip(r.tactic):''}${r.technique?chip(r.technique):''}</div>
   <dl class='cv-facts'><dt>What it watches</dt><dd>${esc(r.watches||'')}</dd>${r.why?`<dt>Why it matters</dt><dd>${esc(r.why)}</dd>`:''}${r.condition?`<dt>Falco condition</dt><dd><code>${esc(r.condition)}</code></dd>`:''}
   ${r.kind==='custom'?`<dt>Stage</dt><dd>${r.stage==='audit'?'Audit: logs quietly at low priority':'Alert'}</dd><dt>Saved</dt><dd>${esc(r.saved)}${r.deployed?' · deployed '+esc(r.deployed):' · not deployed yet'}</dd>`:''}</dl>
   ${r.kind==='custom'?rtTuningHTML(r)+`<div class='cv-links'><a href='javascript:rtEdit("${esc(r.name)}")'>Edit this rule</a> · <a href='javascript:rtSim("${esc(r.name)}")'>Prove it on a cluster</a> · <a href='javascript:rtHistory("${esc(r.name)}")'>Version history</a> · <a href='javascript:rtDelete("${esc(r.name)}")'>Delete</a></div><div id='rt-aux'></div>`:''}${y}
   ${r.kind==='default'?`<p class='cv-p'><small>This is Falco's own rule. To change it, override it in your Falco custom rules; the guided builder makes new rules rather than editing these.</small></p>`:''}${r.kind==='curated'?`<p class='cv-p'><small>This rule runs inside K8sMatrixWarden on every event it receives, whatever Falco does.</small></p>`:''}`);
  if(r.kind==='custom') rtApi('generate',{spec:r.spec}).then(g=>{ const e=$('#rt-y'); if(e) e.textContent=g.yaml||g.error||''; }); }
function rtTuningHTML(r){ const t=RT.tuning[r.name], st=RT.stats&&RT.stats.stats[r.name];
  const adv=t?t.advice:null; const promote=r.stage==='audit'?`<button class='btn' type='button' onclick='rtPromote("${esc(r.name)}")'>Promote to alert</button>`:`<button class='bd-btn' type='button' onclick='rtDemote("${esc(r.name)}")'>Move back to audit</button>`;
  const sug=t&&t.suggestions.length?t.suggestions.map((x,i)=>`<div class='bd-todo info'><div><small>${esc(x.text)}</small></div><button class='bd-btn' type='button' onclick='rtAddExc("${esc(r.name)}",${i})'>Add exception</button></div>`).join(''):'';
  return `<div class='cv-dh'>Tuning</div>${st?`<p class='cv-p'><small>${st.fires} hit(s) in the last ${st.window_hours}h, last at ${esc(st.last)}.</small></p>`:`<p class='cv-p'><small>${RT.stats?'No hits in the window.':'Load fire counts on the Rules tab to see how often this fires.'}</small></p>`}${adv?`<div class='bd-todo ${adv.state==='noisy'?'bad':'info'}'><div><small>${esc(adv.text)}</small></div></div>`:''}${sug}<div class='rt-row'>${promote}</div>`; }
async function rtPromote(name){ await rtSetStage(name,'alert'); }
async function rtDemote(name){ await rtSetStage(name,'audit'); }
async function rtSetStage(name,stage){ const r=(RT.cat.custom||[]).find(x=>x.name===name); if(!r) return; const spec=JSON.parse(JSON.stringify(r.spec)); spec.stage=stage; const d=await rtApi('save',{spec}); if(d._ok){ RT.cat.custom=d.custom; drawerClose(); RT.msg=`'${name}' is now ${stage==='alert'?'alerting':'in audit'}. Redeploy from the Falco tab to apply it.`; rtRefresh(); } else alert(d.error||'Could not save.'); }
async function rtAddExc(name,i){ const t=RT.tuning[name]; if(!t) return; const x=t.suggestions[i]; const r=(RT.cat.custom||[]).find(y=>y.name===name); const spec=JSON.parse(JSON.stringify(r.spec)); spec.exceptions=(spec.exceptions||[]).concat([{field:x.field,values:[x.value]}]); const d=await rtApi('save',{spec}); if(d._ok){ RT.cat.custom=d.custom; drawerClose(); RT.msg=`Added an exception for ${x.value} to '${name}'. Redeploy to apply it.`; rtRefresh(); } }
async function rtSim(name){ const r=(RT.cat.custom||[]).find(x=>x.name===name); const p=await rtApi('simulate',{spec:r.spec}); const e=$('#rt-aux'); if(!e) return;
  e.innerHTML=`<div class='cv-dh'>Prove it on a cluster</div><p class='cv-p'><small>${esc(p.warning)}</small></p><div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc([p.setup,...p.commands,p.cleanup].join('\n'))}</pre></div>${p.event_generator_cmd?`<p class='cv-p'><small>Or with Falco's event generator:</small></p><div class='cv-code'><pre>${esc(p.event_generator_cmd)}</pre></div>`:''}<p class='cv-p'><small>${esc(p.expect)}</small></p>`; }
async function rtHistory(name){ const h=await rtApi('history',{name}); const e=$('#rt-aux'); if(!e) return; e.innerHTML=`<div class='cv-dh'>Version history</div>${(h.history||[]).length?h.history.map(x=>`<div class='bd-fl'><b>${esc(x.saved)}</b><small>${esc(x.stage)} · ${esc(x.priority)}${x.deployed?' · was deployed':''}</small><button class='bd-btn' type='button' onclick='rtRestore("${esc(name)}",${x.index})'>Restore</button></div>`).join(''):"<div class='cv-none'>No earlier versions yet.</div>"}`; }
async function rtRestore(name,i){ if(!confirm('Restore this version? The current one is kept in the history.')) return; const d=await rtApi('restore',{name,index:i}); if(d._ok){ RT.cat.custom=d.custom; drawerClose(); rtRefresh(); } }
function rtEdit(name){ const r=(RT.cat.custom||[]).find(x=>x.name===name); if(!r) return; const s=JSON.parse(JSON.stringify(r.spec)); ['names','cmdline_contains','parent_names','paths','process_names','destinations','ports','verbs','resources'].forEach(k=>{ if(Array.isArray((s.values||{})[k])) s.values[k]=s.values[k].join(', '); });
  ['namespaces','exclude_namespaces','images'].forEach(k=>{ if(Array.isArray(s.scope[k])) s.scope[k]=s.scope[k].join(', '); }); s.exceptions=(s.exceptions||[]).map(e=>({field:e.field,values:(e.values||[]).join(', ')}));
  RT.spec=s; RT.tests=null; RT.gen=null; RT.engine=null; drawerClose(); RT.tab='create'; rtRefresh(); rtGen(); }
async function rtDelete(name){ if(!confirm('Delete the rule "'+name+'"?')) return; const d=await rtApi('delete',{name}); if(d._ok){ RT.cat.custom=d.custom; drawerClose(); rtRefresh(); } }
/* ---- Create a rule ---- */
function rtSet(path,v){ const parts=path.split('.'); let o=RT.spec; for(let i=0;i<parts.length-1;i++) o=o[parts[i]]; o[parts[parts.length-1]]=v; RT.tests=null; RT.engine=null; rtQueue(); }
function rtPickBehavior(b){ RT.spec.behavior=b; const m=RT.beh.behaviors[b]; RT.spec.values={}; if(!RT.spec.priority) RT.spec.priority=m.priority; RT.spec.tactic=m.tactic; RT.spec.technique=m.technique; RT.tests=null; RT.gen=null; rtRefresh(); rtQueue(); }
function rtExample(id){ const e=(RT.beh.examples||[]).find(x=>x.id===id); if(!e) return; RT.spec=Object.assign(rtNewSpec(),JSON.parse(JSON.stringify(e.spec)),{stage:'audit'}); RT.spec.scope=Object.assign({namespaces:'',exclude_namespaces:'',images:'',containers_only:true},RT.spec.scope||{}); RT.spec.exceptions=[]; RT.tests=null; RT.engine=null; RT.example=id; rtRefresh(); rtGen(); }
let rtT=null; function rtQueue(){ clearTimeout(rtT); rtT=setTimeout(rtGen,450); }
async function rtGen(){ const s=RT.spec; if(!s||!s.behavior){ return; } const g=await rtApi('generate',{spec:s}); RT.gen=g; const e=$('#rt-gen'); if(e) e.innerHTML=rtGenHTML(); const sv=$('#rt-save'); if(sv) sv.disabled=!rtCanSave(); }
const rtCanSave=()=>RT.gen&&RT.gen._ok&&!(RT.gen.lint&&RT.gen.lint.errors.length)&&RT.tests&&RT.tests.ok;
function rtCreateHTML(){
  if(!RT.beh) return `<div class='panel'><div class='cv-none'>Loading…</div></div>`;
  const s=RT.spec||rtNewSpec(), B=RT.beh.behaviors;
  const cards=Object.entries(B).map(([k,m])=>`<button type='button' class='bd-pat ${s.behavior===k?'on':''}' onclick='rtPickBehavior("${k}")'><b>${esc(m.title)}</b><small>${esc(m.help)}</small></button>`).join('');
  const ex=`<label class='rt-l'>Or start from an example<select onchange='rtExample(this.value)'><option value=''>Choose an example…</option>${(RT.beh.examples||[]).map(e=>`<option value='${e.id}' ${RT.example===e.id?'selected':''}>${esc(e.title)}</option>`).join('')}</select></label>`;
  let form='';
  if(s.behavior){ const m=B[s.behavior], v=s.values||{};
    const fld=(label,val,path,ph,help)=>`<label class='rt-l'>${esc(label)}<input value='${esc(val||'')}' placeholder='${esc(ph||'')}' oninput='rtSet("${path}",this.value)'>${help?`<small>${esc(help)}</small>`:''}</label>`;
    form=`<div class='rt-step'><h3>2. Fill in the details</h3><div class='bd-fields'>${m.fields.map(([k,l,ph,h])=>fld(l,v[k],'values.'+k,ph,h)).join('')}</div></div>
     <div class='rt-step'><h3>3. Where should it apply?</h3><div class='bd-fields'>${m.source==='syscall'?`<label class='bd-chk'><input type='checkbox' ${s.scope.containers_only?'checked':''} onchange='rtSet("scope.containers_only",this.checked)'> <span>Only inside containers (ignore the node itself)</span></label>`:''}
       ${fld('Only these namespaces (optional)',s.scope.namespaces,'scope.namespaces','production, payments','Leave empty for every namespace.')}${fld('Never in these namespaces (optional)',s.scope.exclude_namespaces,'scope.exclude_namespaces','kube-system, monitoring','Skip places where this is normal.')}
       ${m.source==='syscall'?fld('Only these images (optional)',s.scope.images,'scope.images','nginx, myorg/api','Image repository names.'):''}</div></div>
     <div class='rt-step'><h3>4. What is allowed? (cuts false alarms)</h3>${(s.exceptions||[]).map((e,i)=>`<div class='rt-exc'><select onchange='rtExc(${i},"field",this.value)'>${Object.entries(RT.beh.exception_fields).map(([f,l])=>`<option value='${f}' ${e.field===f?'selected':''}>${esc(l)}</option>`).join('')}</select><input value='${esc(e.values||'')}' placeholder='values, comma separated' oninput='rtExc(${i},"values",this.value)'><button type='button' class='bd-btn' onclick='rtExcDel(${i})'>Remove</button></div>`).join('')}<button type='button' class='bd-btn' onclick='rtExcAdd()'>+ Add an exception</button><small class='fm'> Example: the monitoring agent is allowed to run a shell.</small></div>
     <div class='rt-step'><h3>5. Name it and choose how loud it is</h3><div class='bd-fields'>${fld('Rule name',s.name,'name','Shell in production')}${fld('What is it for? (optional)',s.description,'description','One sentence for the next person')}
       <label class='rt-l'>MITRE tactic<select onchange='rtSet("tactic",this.value)'>${RT.beh.tactics.map(t=>`<option ${s.tactic===t?'selected':''}>${esc(t)}</option>`).join('')}</select></label>${fld('MITRE technique',s.technique,'technique','T1059')}
       <label class='rt-l'>Priority<select onchange='rtSet("priority",this.value)'>${RT.beh.priorities.map(p=>`<option ${s.priority===p?'selected':''}>${p}</option>`).join('')}</select></label>
       <label class='rt-l'>Rollout<select onchange='rtSet("stage",this.value)'><option value='audit' ${s.stage==='audit'?'selected':''}>Audit first: log quietly, watch for false alarms</option><option value='alert' ${s.stage==='alert'?'selected':''}>Alert now at the chosen priority</option></select><small>Start with audit. Switch to alert once it has run clean for a few days.</small></label></div></div>`; }
  return `<div class='panel rt-create'><div class='rt-step'><h3>1. What do you want to catch?</h3><div class='bd-gal'>${cards}</div><div style='margin-top:.7rem'>${ex}</div></div>${form}</div>
   ${s.behavior?`<div class='panel'><div id='rt-gen'>${rtGenHTML()}</div></div>`:''}`;
}
function rtExc(i,k,v){ RT.spec.exceptions[i][k]=v; RT.tests=null; rtQueue(); }
function rtExcAdd(){ RT.spec.exceptions.push({field:'proc.name',values:''}); rtRefresh(); }
function rtExcDel(i){ RT.spec.exceptions.splice(i,1); RT.tests=null; rtRefresh(); rtQueue(); }
function rtGenHTML(){
  const g=RT.gen; if(!g) return `<div class='cv-none'>Fill in the details and the rule appears here.</div>`;
  if(!g._ok) return `<div class='bd-todo bad'><div><b>Not ready yet</b><small>${esc(g.error||'')}</small></div></div>`;
  const L=g.lint||{errors:[],warnings:[]}, t=RT.tests;
  const sum=(g.explain||[]).length?`<div class='cv-dh'>This rule fires when ALL of these are true</div><ul class='rt-ul'>${g.explain.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:'';
  const lint=`${L.errors.map(e=>`<div class='bd-todo bad'><div><b>${esc(e)}</b></div></div>`).join('')}${L.warnings.map(e=>`<div class='bd-todo info'><div><small>${esc(e)}</small></div></div>`).join('')}${!L.errors.length&&!L.warnings.length?"<div class='bd-good'>&#10003; The rule file is well formed.</div>":''}`;
  const tr=t?`<div class='${t.ok?'bd-good':'bd-todo bad'}'>${t.ok?'&#10003; ':''}${t.passed} of ${t.passed+t.failed} test events behaved as expected</div><div class='cv-scroll'><table class='cv-t'><thead><tr><th>Test</th><th>Expected</th><th>Result</th><th>Why</th></tr></thead><tbody>${t.cases.map((c,i)=>`<tr><td>${esc(c.label)}<small class='rt-ev' title='${esc(JSON.stringify(c.event))}'>${esc(Object.entries(c.event).slice(0,4).map(([k,v])=>k+'='+v).join(' · '))}</small></td><td>${c.expected==null?'-':c.expected?'fires':'quiet'}</td><td><span class='cv-st ${c.pass?'ok':'bad'}'>${c.fires?'fired':'quiet'}</span></td><td><small>${esc(c.stopped_by||'all conditions true')}</small></td></tr>`).join('')}</tbody></table></div>`:`<div class='cv-none'>Not tested yet.</div>`;
  const eng=RT.engine?(RT.engine.available===false?`<div class='bd-todo info'><div><small>${esc(RT.engine.message)}</small></div></div>`:`<div class='${RT.engine.ok?'bd-good':'bd-todo bad'}'>${RT.engine.ok?'&#10003; Falco accepts this rule':'Falco rejected the rule'}<small class='rt-pre'>${esc(RT.engine.output||'')}</small></div>`):'';
  return `${sum}<h3 class='bd-ph'>The Falco rule</h3><div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc(g.yaml)}</pre></div>${lint}
   <h3 class='bd-ph'>Test it before it ships</h3><p class='bd-note'>Each test is an example event. A good rule fires on the first and stays quiet on the near misses. The tests are run by K8sMatrixWarden against exactly the conditions above.</p>
   <div class='rt-row'><button class='btn' type='button' onclick='rtTest()'>Run the tests</button><button class='bd-btn' type='button' onclick='rtEngine()' title='Runs Falco itself (needs Docker) to confirm it can load the rule'>Check with Falco</button></div>${tr}${eng}
   <details class='bd-sec'><summary>Add your own test event</summary><div><label class='rt-l'>Event fields, one per line<textarea id='rt-ev' rows='5' placeholder='evt.type=execve&#10;container.id=abc&#10;proc.name=bash&#10;k8s.ns.name=production'></textarea></label>
     <div class='rt-row'><label class='rt-l'>Should this fire?<select id='rt-evx'><option value=''>Just show me</option><option value='true'>Yes, it should fire</option><option value='false'>No, it should stay quiet</option></select></label><button class='bd-btn' type='button' onclick='rtAddEvent()'>Add and test</button></div>${RT.customEv.length?`<small class='fm'>${RT.customEv.length} custom event(s) included.</small>`:''}</div></details>
   <div class='rt-row' style='margin-top:1rem'><button class='btn' id='rt-save' type='button' onclick='rtSave()' ${rtCanSave()?'':'disabled'}>Save rule</button><small class='fm'>${rtCanSave()?'Saved rules go to Falco when you deploy from the Falco tab.':'Run the tests and fix any failure first.'}</small></div>${RT.msg?`<div class='bd-note'>${esc(RT.msg)}</div>`:''}`;
}
async function rtTest(){ RT.busy='test'; const t=await rtApi('test',{spec:RT.spec,events:RT.customEv}); RT.tests=t._ok?t:{ok:false,passed:0,failed:1,cases:[{label:'Could not test',event:{},expected:null,fires:false,pass:false,stopped_by:t.error||''}]}; const e=$('#rt-gen'); if(e) e.innerHTML=rtGenHTML(); }
async function rtEngine(){ RT.engine={available:true,ok:null,output:'Asking Falco (the first run downloads its image)…'}; const e=$('#rt-gen'); if(e) e.innerHTML=rtGenHTML(); const r=await rtApi('validate',{spec:RT.spec,engine:true}); RT.engine=r.engine||{available:false,message:r.error||''}; const e2=$('#rt-gen'); if(e2) e2.innerHTML=rtGenHTML(); }
function rtAddEvent(){ const l=($('#rt-ev')||{}).value||'', x=($('#rt-evx')||{}).value; if(!l.trim()) return; RT.customEv.push({label:'Your event '+(RT.customEv.length+1),lines:l,expected:x===''?null:x==='true'}); rtTest(); }
async function rtSave(){ const d=await rtApi('save',{spec:RT.spec}); if(!d._ok){ RT.msg=d.error||'Could not save.'; } else { RT.cat=Object.assign(RT.cat||{},{custom:d.custom}); RT.msg='Saved. Open the Falco tab to deploy it.'; } const e=$('#rt-gen'); if(e) e.innerHTML=rtGenHTML(); }
/* ---- Coverage: attacker goals and Falco's own health ---- */
async function rtLoadCov(){ const c=await rtApi('coverage',{}); if(c._ok) RT.cov=c; rtRefresh(); }
async function rtLoadHealth(){ RT.health={state:'loading'}; rtRefresh(); RT.health=await rtApi('health',{hours:24}); rtRefresh(); }
function rtCoverageHTML(){
  const c=RT.cov; if(!c) return `<div class='panel'><div class='cv-none'>Working out coverage…</div></div>`;
  const h=RT.health; const hh=!h?`<button class='btn' type='button' onclick='rtLoadHealth()'>Check Falco's health</button>`:h.state==='loading'?"<div class='cv-none'>Reading Falco's logs…</div>":h.error?`<div class='bd-todo bad'><div><b>Could not check</b><small>${esc(h.error)}</small></div></div>`
    :`<div class='${h.state==='healthy'?'bd-good':'bd-todo bad'}'><div><b>${esc(h.message)}</b></div></div>${(h.pods||[]).map(p=>`<div class='bd-fl'><b>${esc(p.pod)}</b><small>${p.alerts} alert(s), ${p.dropped_events} dropped event(s)${p.last_alert?', last '+esc(p.last_alert):''}</small>${p.errors.map(e=>`<small class='rt-pre'>${esc(e)}</small>`).join('')}</div>`).join('')}<button class='bd-btn' type='button' onclick='rtLoadHealth()'>Check again</button>`;
  return `<div class='panel'><h2>Attacker goals covered</h2><p class='bd-note'>Only rules that are watching right now count: K8sMatrixWarden's own, Falco's defaults while Falco is running, and your rules once deployed. Saved-but-not-deployed rules are shown separately.</p>
    ${c.gaps.length?`<div class='bd-todo bad'><div><b>${c.gaps.length} goal(s) have no active rule</b><small>${esc(c.gaps.join(', '))}</small></div></div>`:"<div class='bd-good'>&#10003; Every attacker goal has at least one active rule.</div>"}
    <div class='cv-scroll'><table class='cv-t'><thead><tr><th>Attacker goal</th><th>Active rules</th><th>Saved, not deployed</th><th>Watching</th><th></th></tr></thead><tbody>${c.rows.map(r=>`<tr><td><b>${esc(r.tactic)}</b></td><td>${r.active}</td><td>${r.saved||'-'}</td><td class='rt-w'>${esc(r.rules.join(', '))}</td><td>${r.gap?`<button class='bd-btn' type='button' onclick='rtForTactic("${esc(r.tactic)}")'>Create a rule</button>`:"<span class='cv-st ok'>covered</span>"}</td></tr>`).join('')}</tbody></table></div></div>
   <div class='panel'><h2>Is Falco keeping up?</h2><p class='bd-note'>Falco can silently drop events when a node is busy, and fail to load a rule. Both mean attacks go unseen, so check them.</p>${hh}</div>`;
}
function rtForTactic(t){ RT.spec=rtNewSpec(); RT.spec.tactic=t; RT.tests=null; RT.gen=null; RT.tab='create'; rtRefresh(); }
/* ---- Agents: is the security software on every node and pod? ---- */
async function rtLoadAgents(){ RT.agents=null; const a=await rtApi('agents',{}); if(a._ok){ RT.agents=a; RT.agentErr=''; } else { RT.agents={agents:[],available:[],unknown:[],config:a.config||[],nodes:0,caveat:''}; RT.agentErr=a.error||'Could not read the cluster.'; } rtRefresh(); }
async function rtAgentSave(extra){ const cfg=(RT.agents&&RT.agents.config)||[]; const tracked=cfg.filter(a=>a.tracked&&!a.custom).map(a=>a.id), mins={}; cfg.forEach(a=>{ if(a.min_version) mins[a.id]=a.min_version; });
  const custom=cfg.filter(a=>a.custom).map(a=>({name:a.name,kind:a.kind,names:(a.names||[]),what:a.what}));
  const e=extra||{}; (e.track||[]).forEach(id=>{ if(!tracked.includes(id)) tracked.push(id); }); (e.untrack||[]).forEach(id=>{ const i=tracked.indexOf(id); if(i>=0) tracked.splice(i,1); }); if(e.min) mins[e.min[0]]=e.min[1]; if(e.custom) custom.push(e.custom);
  const d=await rtApi('agents-save',{tracked,min_versions:mins,custom}); if(d._ok||d.config){ RT.agents=d._ok?d:Object.assign(RT.agents||{},{config:d.config}); RT.agentErr=d._ok?'':(d.error||''); } else alert(d.error||'Could not save.'); rtRefresh(); }
function rtAgentCustom(){ const name=prompt('Name of the agent (e.g. Acme EDR)'); if(!name) return; const kind=confirm('Is it a DaemonSet (one per node)?\nOK = DaemonSet, Cancel = a sidecar container in each pod')?'daemonset':'sidecar'; const m=prompt(kind==='daemonset'?'Part of its DaemonSet name or image (e.g. acme-edr)':'Name of its container in each pod (e.g. acme-proxy)'); if(!m) return; rtAgentSave({custom:{name,kind,names:[m],what:''}}); }
function rtAgentsHTML(){
  const A=RT.agents; if(!A) return `<div class='panel'><div class='cv-none'>Reading your nodes and pods…</div></div>`;
  const bar=c=>`<div class='rt-bar2'><i style='width:${Math.round(c*100)}%' class='${c>=1?'ok':c>=.8?'warn':'bad'}'></i></div>`;
  const cards=A.agents.map(a=>`<div class='panel rt-agent ${a.status}'><div class='rt-ah'><div><b>${esc(a.name)}</b><small>${esc(a.vendor)} · ${a.kind==='sidecar'?'sidecar in each pod':'one per node'}</small></div><span class='cv-st ${a.status==='healthy'?'ok':a.status==='degraded'?'warn':'bad'}'>${a.status==='not-found'?'not found':a.status}</span></div>
     <small class='fm'>${esc(a.what)}</small>${a.status!=='not-found'?`${bar(a.coverage)}<div class='rt-ac'><b>${a.covered} of ${a.expected}</b> ${a.kind==='sidecar'?'pods':'nodes'} covered (${Math.round(a.coverage*100)}%)</div>`:''}
     ${Object.keys(a.versions).length?`<div class='rt-ac'>Versions: ${Object.entries(a.versions).map(([v,n])=>`<span class='tag ${a.below_min.includes(v)?'high':'info'}'>${esc(v)} × ${n}</span>`).join(' ')}</div>`:''}
     ${a.below_min.length?`<div class='bd-todo bad'><div><small>Below your minimum ${esc(a.min_version)}: ${a.below_min.map(esc).join(', ')}</small></div></div>`:''}
     ${a.unhealthy.length?`<details class='bd-sec' open><summary>Not working (${a.unhealthy.length})</summary><div>${a.unhealthy.slice(0,15).map(u=>`<div class='bd-fl'><small>${esc(u)}</small></div>`).join('')}</div></details>`:''}
     ${a.missing.length?`<details class='bd-sec'><summary>Missing from ${a.missing.length} ${a.kind==='sidecar'?'pod(s)':'node(s)'}</summary><div>${a.missing.slice(0,40).map(u=>`<div class='bd-fl'><small>${esc(u)}</small></div>`).join('')}</div></details>`:''}
     ${a.notes.map(n=>`<small class='fm'>${esc(n)}</small>`).join('<br>')}
     <div class='rt-row'><label class='rt-l' style='width:12rem'>Minimum version<input value='${esc(a.min_version||'')}' placeholder='e.g. 7.5.0' onchange='rtAgentSave({min:["${esc(a.id)}",this.value]})'></label><button class='bd-btn' type='button' onclick='rtAgentSave({untrack:["${esc(a.id)}"]})'>Stop tracking</button></div></div>`).join('');
  const avail=(A.available||[]).map(a=>`<button type='button' class='bd-chip' title='${esc(a.what)}' onclick='rtAgentSave({track:["${esc(a.id)}"]})'>+ ${esc(a.name)}</button>`).join('');
  const unk=(A.unknown||[]).length?`<h3 class='bd-ph'>DaemonSets we do not recognise</h3><p class='bd-note'>These run on nodes. If one is a security agent, track it so its coverage is checked.</p>${A.unknown.map(u=>`<div class='bd-fl'><b>${esc(u.name)}</b><small>${esc(u.namespace)} · ${esc(u.image)} · ${u.ready}/${u.desired} ready</small><button class='bd-btn' type='button' onclick='rtAgentSave({custom:{name:"${esc(u.name)}",kind:"daemonset",names:["${esc(u.name)}"],what:""}})'>Track it</button></div>`).join('')}`:'';
  return `<div class='panel'><h2>Security agents on your nodes and pods</h2><p class='bd-note'>${esc(A.caveat||'Pick the agents your organisation relies on. This page shows whether each one is on every node (or in every pod), healthy, and which versions are running.')}</p>${RT.agentErr?`<div class='bd-todo bad'><div><b>Could not read the cluster</b><small>${esc(RT.agentErr)}</small></div></div>`:''}
    <div class='cv-dh'>Add an agent to track</div><div class='rt-chips'>${avail||'<small class="fm">Everything in the catalog is already tracked.</small>'}<button type='button' class='bd-chip' onclick='rtAgentCustom()'>+ My own agent…</button></div></div>
    ${cards||`<div class='panel'><div class='cv-none'>No agents tracked yet. Add one above, for example Falco or your endpoint security sensor.</div></div>`}${unk?`<div class='panel'>${unk}</div>`:''}`;
}
/* ---- Falco ---- */
async function rtPlan(){ RT.plan=null; rtRefresh(); const p=await rtApi('falco-plan',{alerts:RT.alerts.slack_webhook?RT.alerts:null}); RT.plan=p; rtRefresh(); }
async function rtInstallHelm(){ RT.helm={state:'running'}; rtRefresh(); const r=await rtApi('helm-install',{}); RT.helm=r.install||{state:'running'}; rtRefresh(); rtHelmPoll(); }
async function rtHelmPoll(){ clearTimeout(RT.helmT); const r=await rtApi('helm-install',{}); RT.helm=r.install||RT.helm; if(r.install&&r.install.state==='running'){ RT.helmT=setTimeout(rtHelmPoll,3000); } else { rtRefresh(); rtPlan(); } }  // re-plan refreshes the checks
function rtFalcoHTML(){
  const st=RT.status; if(!st) return `<div class='panel'><div class='cv-none'>Checking the cluster…</div></div>`;
  const nodes=(st.nodes||[]).map(n=>`<tr><td>${esc(n.name)}</td><td><code>${esc(n.kernel)}</code></td><td>${esc(n.os)}</td></tr>`).join('');
  const statusCard=`<div class='panel'><h2>Falco in your cluster</h2><div class='bd-todo ${st.state==='healthy'?'info':st.state==='not-installed'||st.state==='unreachable'?'info':'bad'}'><div><b>${esc(st.message||'')}</b>${st.version?`<small>version ${esc(st.version)} · namespace ${esc(st.namespace)} · ${st.ready}/${st.desired} ready${st.sidekick?' · falcosidekick present':''}</small>`:''}${(st.problems||[]).map(p=>`<small>${esc(p)}</small>`).join('')}</div></div>
     ${st.node_count?`<details class='bd-sec'><summary>Nodes (${st.node_count})</summary><div><table class='cv-t'><thead><tr><th>Node</th><th>Kernel</th><th>OS</th></tr></thead><tbody>${nodes}</tbody></table></div></details>`:''}</div>`;
  const P=RT.plan; let deploy='';
  if(P===null) deploy=`<div class='panel'><div class='cv-none'>Preparing a safe preview…</div></div>`;
  else if(P.error) deploy=`<div class='panel'><div class='bd-todo bad'><div><b>Could not prepare the preview</b><small>${esc(P.error)}</small></div></div></div>`;
  else {
    const helmRun=RT.helm&&RT.helm.state==='running';
    const checks=P.preflight.map(c=>`<div class='bd-todo ${c.status==='bad'?'bad':c.status==='warn'?'info':'ok'}'><div><b>${c.status==='ok'?'&#10003; ':c.status==='bad'?'&#10007; ':'! '}${esc(c.title)}</b>${c.detail?`<small>${esc(c.detail)}</small>`:''}${c.id==='helm'&&RT.helm&&RT.helm.state==='error'?`<small class='fm'>${esc((RT.helm.result||{}).error||'Install failed')}</small>`:''}</div>${c.id==='helm'&&c.status==='bad'?`<button class='btn' type='button' ${helmRun?'disabled':''} onclick='rtInstallHelm()'>${helmRun?'Installing…':'Install Helm'}</button>`:''}</div>`).join('');
    const rend=P.renders?(P.renders.ok?`<div class='bd-note'>The chart renders cleanly: ${Object.entries(P.renders.kinds).map(([k,n])=>n+' '+k).join(', ')}. Nothing has been changed.</div>`:`<div class='bd-todo bad'><div><b>The chart did not render</b><small>${esc(P.renders.error)}</small></div></div>`):`<div class='bd-note'>Helm is not available here, so the chart was not rendered.</div>`;
    const cmds=P.commands.map(c=>(c.argv||[]).join(' ')+(c.stdin?'   # namespace manifest on stdin':'')).join('\n');
    const installed=st.state!=='not-installed'&&st.state!=='unreachable';
    const action=P.writes_enabled?`<label class='bd-chk'><input type='checkbox' ${RT.confirm?'checked':''} onchange='RT.confirm=this.checked;rtRefresh()'> <span>I understand this ${installed?'upgrades':'installs'} a privileged DaemonSet in the <b>${esc(P.namespace)}</b> namespace, and that nothing else in the cluster is changed.</span></label>
       <div class='rt-row'><button class='btn' type='button' ${RT.confirm&&!P.blocked&&!RT.run?'':'disabled'} onclick='rtDeploy()'>${installed?'Deploy my rules to Falco':'Deploy Falco'}</button>${installed&&st.helm_release?`<button class='bd-btn' type='button' onclick='rtRemove()'>Remove Falco</button>`:''}</div>${P.blocked?`<small class='fm'>A pre-flight check failed, so the button is off.</small>`:''}`
      :`<div class='bd-todo info'><div><b>Deploying from here is turned off</b><small>This dashboard is read-only by default. To let it deploy Falco, restart it with <code>K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1 k8smatrixwarden web</code>, or run the commands below yourself. They are the same ones the button would run.</small></div></div>`;
    deploy=`<div class='panel'><h2>${installed?'Update or remove Falco':'Deploy Falco safely'}</h2><p class='bd-note'>Everything below is a preview. It touches nothing until you confirm.</p><h3 class='bd-ph'>Checks</h3>${checks}${rend}
      <details class='bd-sec' ${RT.alerts.slack_webhook?'open':''}><summary>Send alerts to Slack (optional)</summary><div class='bd-fields'><label class='rt-l'>Slack webhook address<input type='password' autocomplete='off' value='${esc(RT.alerts.slack_webhook)}' placeholder='https://hooks.slack.com/services/…' onchange='RT.alerts.slack_webhook=this.value;RT.plan=null;rtPlan()'><small>Kept in a Kubernetes Secret in the falco namespace, never in the Helm values, the command line, or this page after you leave it.</small></label>
        <label class='rt-l'>Only alerts at or above<select onchange='RT.alerts.min_priority=this.value;rtPlan()'>${['notice','warning','error','critical','alert','emergency'].map(p=>`<option ${RT.alerts.min_priority===p?'selected':''}>${p}</option>`).join('')}</select></label></div></details>
      <details class='bd-sec'><summary>The exact commands</summary><div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc(cmds)}</pre></div></div></details>
      <details class='bd-sec'><summary>The settings it installs with (includes your saved rules)</summary><div class='cv-code'><pre>${esc(P.values)}</pre></div></details>${action}${rtRunHTML()}</div>`; }
  return statusCard+deploy;
}
function rtRunHTML(){ const r=RT.run; if(!r) return ''; return `<div class='rt-run'><h3 class='bd-ph'>${r.state==='running'?'Working…':r.state==='done'?'Done':'Stopped'}</h3>${r.steps.map(s=>`<div class='bd-fl'><span class='cv-st ${s.status==='done'?'ok':s.status==='failed'?'bad':'warn'}'>${s.status}</span><b>${esc(s.title)}</b>${s.output&&s.status==='failed'?`<small class='rt-pre'>${esc(s.output)}</small>`:''}</div>`).join('')}${r.state==='failed'?`<div class='bd-note'>The install is rolled back automatically if Helm started it. Nothing is left half-deployed.</div>`:''}</div>`; }
async function rtDeploy(){ RT.run={state:'running',steps:[{title:'Starting…',status:'running',output:''}]}; rtRefresh(); const r=await rtApi('falco-deploy',{confirm:'deploy-falco',alerts:RT.alerts.slack_webhook?RT.alerts:null}); if(!r._ok){ RT.run={state:'failed',steps:[{title:'Could not start',status:'failed',output:r.error||''}]}; rtRefresh(); return; } rtPoll(r.run); }
async function rtRemove(){ if(!confirm('Remove the Falco this tool installed?')) return; RT.run={state:'running',steps:[{title:'Starting…',status:'running',output:''}]}; rtRefresh(); const r=await rtApi('falco-remove',{confirm:'remove-falco'}); if(!r._ok){ RT.run={state:'failed',steps:[{title:'Could not start',status:'failed',output:r.error||''}]}; rtRefresh(); return; } rtPoll(r.run); }
async function rtPoll(id){ clearTimeout(RT.pollT); const r=await rtApi('falco-run',{run:id}); if(r.steps){ RT.run=r; rtRefresh(); } if(r.state==='running'){ RT.pollT=setTimeout(()=>rtPoll(id),2500); } else { const s=await rtApi('falco-status',{}); RT.status=s; const c=await rtApi('catalog',{}); if(c._ok) RT.cat=Object.assign(RT.cat||{},{custom:c.custom,curated:c.curated}); rtRefresh(); } }
function runtimeFeed(){
  const rc=D.runtime_correlation;
  const pre=rc&&rc.correlation?renderRuntime(rc.correlation,rc.drift||{drift:[],drift_count:0},rc)
    :"<div class='fm'>No runtime events recorded for this scan yet. If Falco is deployed, select Refresh. Otherwise, try it with sample events below.</div>";
  const meta=rc&&rc.collected_at?`last updated ${esc(String(rc.collected_at))} · ${rc.events_seen||0} event(s)`:'';
  return `<div class='panel'><h2>Runtime correlation &amp; drift</h2>
    <div class='fm'>Runtime events from Falco, correlated against this scan. Refresh pulls the latest from a deployed Falco.</div>
    <div class='ctl'>
      <button class='btn' onclick='refreshRuntime()'>&#8635; Refresh</button>
      <button class='b-ghost' type='button' onclick='runDemoEvents()' title='Push three synthetic events built from this scan&#39;s own findings through the real correlation pipeline, so you can see how it behaves with no Falco deployed'>&#9889; Try with sample events</button>
      <label class='fm' style='display:flex;align-items:center;gap:.4rem'><input type='checkbox' id='rtauto' onchange='toggleAutoRefresh()'> Auto-refresh every 30s</label>
      <span class='fm' id='rtmeta'>${meta}</span>
    </div>
    <div id='rtout' role='status' aria-live='polite'>${pre}</div></div>`;
}
async function runDemoEvents(){
  const out=$('#rtout');
  if(!out) return;
  out.innerHTML="<div class='fm'>Building sample events from this scan's own findings…</div>";
  let d; try{
    const r=await fetch('/api/runtime/demo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:D.scan.scan_id})});
    d=await r.json();
  }catch(e){ out.innerHTML=`<div class='fm' style='color:var(--crit)'>Could not reach the dashboard: ${esc(e.message)}</div>`; return; }
  if(d.error){ out.innerHTML=`<div class='fm' style='color:var(--crit)'>${esc(d.error)}</div>`; return; }
  D.runtime_correlation=d;
  out.innerHTML=`<div class='healthbar partial'><div class='hb-t'>&#9889; Sample data, not a real detection</div>
    <div class='fm'>These three events are synthetic, built from this scan's own findings, and pushed through the real correlation engine so you can see how confirmed / corroborated / runtime-only actually behave. Select Refresh to go back to live Falco events.</div></div>
    ${renderRuntime(d.correlation,d.drift,d)}`;
  const m=$('#rtmeta'); if(m)m.textContent='sample data · just now';
}
// Who owns this verdict: a curated K8sMatrixWarden rule, or Falco's own rule relayed
// under its name. An analyst must never have to guess which engine made the claim.
function detectorPill(rt){
  const kmw=!rt||(rt.detection_source||'kmw')==='kmw';
  return `<span class='tag ${kmw?'low':'info'}' title='${kmw?'Detected by a curated K8sMatrixWarden runtime rule':'Relayed from the Falco provider; not a K8sMatrixWarden rule'}'>${kmw?'KMW':'Falco'}</span>`;
}
// "Not confirmed because we could not place the event" is a different statement from
// "not confirmed because the event was about something else". Say which.
function identityNote(ev){
  const st=ev&&ev.identity_status; if(!st||st==='complete') return '';
  const miss=(ev.identity_missing||[]).join(', ');
  return `<div class='fm'><span class='tag medium' title='${esc(ev.identity_reason||"")}'>Identity: ${esc(st)}</span>${miss?` missing ${esc(miss)}`:''}</div>`;
}
function coverageStrip(rc){
  const d=rc&&rc.detection_coverage; if(!d) return '';
  const i=rc.identity_coverage||{};
  const idline=(i.complete!==undefined)?`<div class='fm'>Identity: <b>${i.complete}</b> complete (${i.recovered_from_container_id||0} recovered from container id) · ${i.partial} partial · ${i.ambiguous} ambiguous · ${i.unknown} unknown</div>`:'';
  return `<div class='fm' style='margin-top:.5rem'>Detection: <b>${d.kmw_matches}</b> by curated rule · <b>${d.falco_relays}</b> relayed from Falco · ${d.unusable_events} unusable (reason recorded) · <b>${d.discarded}</b> silently discarded</div>${idline}`;
}
// A "confirmed" correlation names a RESOURCE, not a specific weakness on it: when more
// than one static finding shares that resource and tactic, the event alone can't say
// which (if any) was the vector. Showing only the first candidate, with no hint there
// were others, silently hid exactly that ambiguity on the tool's strongest claim.
function staticCandidates(x){
  const n=x.static_count!=null?x.static_count:x.static_findings.length;
  if(!n) return '';
  if(n===1) return `<div class='fm'>static: ${esc(x.static_findings[0].title)} on <code>${esc(x.static_findings[0].resource)}</code></div>`;
  const shown=x.static_findings.length;
  return `<div class='fm'><span class='tag medium'>${n} candidate weaknesses</span> share this resource and tactic; the event does not say which:</div>
    <ul class='corr-cands'>${x.static_findings.map(f=>`<li>${esc(f.title)} on <code>${esc(f.resource)}</code></li>`).join('')}</ul>
    ${n>shown?`<div class='fm'>+${n-shown} more not shown</div>`:''}`;
}
function renderRuntime(c, dr, rc){
  dr=dr||{drift:[],drift_count:0};
  const corr=(c.correlations||[]).map(x=>`<div class='corr ${x.confidence}'>
    <span class='badge ${x.confidence}'>${x.confidence}</span> <b>${esc(x.tactic)}</b> · <span class='sev ${x.severity}'>${x.severity}</span> ${detectorPill(x.runtime)}
    <div class='fm' style='margin-top:.25rem'>runtime: ${esc(x.runtime.title)}</div>
    ${x.runtime.supporting_evidence?`<div class='fm'>also seen by <code>${esc(x.runtime.supporting_evidence)}</code> (same event, not a second finding)</div>`:''}
    ${identityNote(x.runtime.event)}
    ${staticCandidates(x)}
    <div class='fm'>&rarr; ${esc(x.verdict)}</div></div>`).join('');
  const drift=(dr.drift||[]).map(x=>`<div class='corr confirmed'><span class='badge confirmed'>DRIFT</span> <b>${esc(x.pod)}</b> (${esc(x.namespace)})
    <div class='fm' style='margin-top:.25rem'>declares <code>${esc(x.declared)}</code> but runtime shows <b>${esc(x.observed)}</b></div></div>`).join('');
  return `<div style='margin-top:.8rem'>
    <div class='kpis'>
      <div class='kpi crit'><div class='n'>${c.confirmed_exploitation}</div><div class='l'>Confirmed exploitation</div></div>
      <div class='kpi warn'><div class='n'>${c.correlated}</div><div class='l'>Correlated findings</div></div>
      <div class='kpi crit'><div class='n'>${dr.drift_count||0}</div><div class='l'>Configuration drift</div></div>
      <div class='kpi'><div class='n'>${c.total_alerts}</div><div class='l'>Runtime alerts</div></div>
    </div>
    ${coverageStrip(rc)}
    ${drift?`<h2 style='font-size:.95rem;margin:.6rem 0 .4rem'>Configuration drift (policy bypass)</h2>${drift}`:''}
    <h2 style='font-size:.95rem;margin:.6rem 0 .4rem'>Correlations</h2>${corr||"<div class='fm'>No correlations recorded.</div>"}</div>`;
}
let _rtTimer=null;
// A quiet Falco is not a broken Falco. Severity comes from the server's structured
// feed state, so the presentation cannot drift from what the backend actually decided.
// `ok`/`info` are neutral; only a real misconfiguration or failure raises the volume.
function feedNotice(d){
  const sev = d.severity || (d.error ? 'error' : 'info');
  const tone = {ok:'var(--low)', info:'var(--muted)', warning:'var(--high)',
                error:'var(--crit)'}[sev] || 'var(--muted)';
  const label = {ok:'', info:'', warning:'Check configuration', error:'Feed unavailable'
                }[sev] || '';
  const text = d.message || d.error || 'No runtime events found.';
  const fix = d.remediation
    ? `<div class='fm' style='margin-top:.35rem'><code>${esc(d.remediation)}</code></div>`
    : '';
  const head = label
    ? `<strong style="color:${tone}">${esc(label)}</strong> \u00b7 ` : '';
  return `<div class='fm' style="color:${tone}">${head}${esc(text)}</div>${fix}`;
}

async function refreshRuntime(){
  const out=$('#rtout'), m=$('#rtmeta');
  if(!out){ if(_rtTimer){clearInterval(_rtTimer);_rtTimer=null;} return; }  // tab gone
  out.innerHTML="<div class='fm'>Pulling runtime events…</div>";
  if(m) m.textContent='';   // clear any stale "sample data" note from a previous demo run
  let d; try{
    const r=await fetch('/api/runtime/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:D.scan.scan_id})});
    d=await r.json();
  }catch(e){ out.innerHTML=`<div class='fm' style='color:var(--crit)'>Could not refresh the runtime feed: ${esc(e.message)}</div>`; return; }
  if(d.error){ out.innerHTML=feedNotice(d); return; }
  if(!d.runtime){ out.innerHTML=feedNotice(d); return; }
  D.runtime_correlation=d.runtime;
  out.innerHTML=renderRuntime(d.runtime.correlation,d.runtime.drift,d.runtime);
  if(m) m.textContent=`last updated ${d.runtime.collected_at||''} · ${d.runtime.events_seen||0} event(s)`;
}
// ponytail: client-side setInterval, not server push, a 30s POST is cheap and needs zero
// new server infra; clears itself when the runtime view is gone.
function toggleAutoRefresh(){
  if(_rtTimer){clearInterval(_rtTimer);_rtTimer=null;}
  if($('#rtauto').checked){ _rtTimer=setInterval(refreshRuntime,30000); refreshRuntime(); }
}
/* ---- scan / history ---- */
function scanView(){
  const rows=D.history.map(r=>`<tr>
    <td><a href='javascript:loadReport("${esc(r.scan_id)}")'>${esc(r.name||r.scan_id)}</a>${r.name?`<div class='fm'><code>${esc(r.scan_id)}</code></div>`:''}</td>
    <td class='fm'>${fmtTime(r.generated_at)}</td>
    <td><span class='pill ${r.rating}'>${esc(r.rating)}</span></td>
    <td>${r.risk_score}</td><td>${r.total}</td><td><code>${esc(r.scope)}</code></td>
    <td><a href='javascript:loadReport("${esc(r.scan_id)}")'>Open</a> · <a href='/graph?scan_id=${esc(r.scan_id)}'>Attack paths</a> · <a href='/api/report/${esc(r.scan_id)}?format=json'>JSON</a></td></tr>`).join('');
  const po=D.posture||{}, nNew=(po.new||[]).length;
  return `<div class='panel'><div class='pol-h'><h2 style='margin:0'>Scans</h2><span class='fm'>${(D.history||[]).length} saved</span>
      <span class='pol-big'>${nNew?`${nNew} new issue(s) since the previous scan · <a href='#changes'>see what changed</a>`:'No new issues since the previous scan'}</span></div>
      <div class='st-a'><button class='btn' type='button' onclick="location.hash='#tasks'">Run a new scan</button></div></div>
    <div class='panel'><h2>Risk trend</h2>${trendBars()}</div>
    <div class='panel'><h2>Scan history</h2><table class='ft'><thead><tr>
    <th>Scan</th><th>Completed</th><th>Posture</th><th>Risk</th><th>Findings</th><th>Scope</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
/* ---- Tasks: run scans from here, watch them, open the result --------------------------------
   Each task is the same CLI scan an engineer would type, run by the server as a child process
   (web/tasks.py). The form is built once and the list repainted on a timer so typing is never lost. */
let TK={tasks:[],kinds:{},can_run:true,can_use_paths:true}, tkTimer=null, tkLog=null, tkKind='scan-live';
const TK_ST={queued:['warn','Queued'],running:['warn','Running'],done:['ok','Done'],failed:['bad','Failed'],cancelled:['','Cancelled']};
const tkDur=t=>{ const s=Math.round(((t.finished||Date.now()/1000)-(t.started||t.created))); return s<60?s+'s':Math.floor(s/60)+'m '+(s%60)+'s'; };
async function tkLoad(){
  try{ TK=await (await fetch('/api/tasks')).json(); }catch(e){ return; }
  if(D&&!D.has_scan&&(TK.tasks||[]).some(t=>t.status==='done'&&t.scan_id)){ location.reload(); return; }
  tkPaint(); clearTimeout(tkTimer);
  if((TK.tasks||[]).some(t=>t.status==='queued'||t.status==='running')) tkTimer=setTimeout(tkLoad,1500);
}
function tkForm(){
  const kinds=[['scan-live','Live cluster'],['scan-manifests','YAML / Helm'],['scan-sample','Demo cluster']]
    .filter(([k])=>k!=='scan-manifests'||TK.can_use_paths);
  const f={ 'scan-live':`<label>Context <input id='tk-ctx' placeholder='current kubectl context'></label>
      <label>Namespace <input id='tk-ns' placeholder='all namespaces'></label>
      ${TK.can_use_paths?`<label class='tk-wide'>Kubeconfig (optional) <input id='tk-kc' placeholder='path, e.g. C:\\Users\\me\\.kube\\config'></label>
      <label class='tk-wide'>…or pick a kubeconfig file <input type='file' id='tk-kcfile'></label>`:''}
      <label class='tk-chk'><input type='checkbox' id='tk-grype' checked> Scan running images for CVEs (Grype, slow the first time)</label>`,
    'scan-manifests':`<label class='tk-wide'>Files or folders (one per line) <textarea id='tk-paths' rows='3' placeholder='./k8s&#10;./charts/myapp'></textarea></label>`,
    'scan-sample':`<div class='fm'>Scans the bundled, deliberately insecure demo cluster. Nothing is read from your cluster.</div>`}[tkKind];
  return `<div class='tk-seg' role='tablist'>${kinds.map(([k,l])=>`<button type='button' role='tab' class='${k===tkKind?'on':''}' onclick='tkPick("${k}")'>${l}</button>`).join('')}</div>
    <div class='tk-fields'>${f}<label>Name (optional) <input id='tk-name' placeholder='e.g. before release 4.2'></label>
      <button class='btn' type='button' id='tk-run' onclick='tkRun()' ${TK.can_run?'':'disabled'}>Run task</button></div><div id='tk-msg' class='fm' role='status'></div>`;
}
function tkPick(k){ tkKind=k; const b=$('#tk-form'); if(b) b.innerHTML=tkForm(); }
function readFileText(f){ return new Promise((res,rej)=>{ const r=new FileReader(); r.onload=e=>res(e.target.result); r.onerror=()=>rej(r.error); r.readAsText(f); }); }
async function tkRun(){
  const v=id=>(($('#'+id)||{}).value||'').trim(), msg=$('#tk-msg'); msg.textContent='Starting…';
  const body={kind:tkKind,name:v('tk-name')};
  if(tkKind==='scan-live'){ body.context=v('tk-ctx'); body.namespace=v('tk-ns'); body.grype=!!($('#tk-grype')||{}).checked;
    const kcf=($('#tk-kcfile')||{}).files, kcp=v('tk-kc');
    if(kcf&&kcf[0]){ try{ body.kubeconfig_content=await readFileText(kcf[0]); }catch(e){ msg.textContent='Could not read the selected file.'; return; } }
    else if(kcp){ body.kubeconfig=kcp; } }
  if(tkKind==='scan-manifests') body.paths=v('tk-paths').split('\n').map(x=>x.trim()).filter(Boolean);
  const r=await fetch('/api/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json(); msg.textContent=r.ok?'':(d.error||'Could not start the task.'); if(r.ok){ tkLog=d.id; tkLoad(); }
}
async function tkCancel(id){ await fetch('/api/tasks/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); tkLoad(); }
function tkToggle(id){ tkLog=(tkLog===id?null:id); tkPaint(); }
async function tkOpenResult(id){ await loadReport(id); location.hash='#issues'; }
async function tkPaint(){
  const box=$('#tk-list'); if(!box) return;
  const ts=TK.tasks||[];
  if(!ts.length){ box.innerHTML="<div class='cv-none'>No tasks yet. Run one above; it appears here and keeps running if you leave this page.</div>"; return; }
  let full=null; if(tkLog){ try{ full=await (await fetch('/api/tasks/'+tkLog)).json(); }catch(e){} }
  box.innerHTML=ts.map(t=>{ const [c,l]=TK_ST[t.status]||['',t.status], act=t.status==='queued'||t.status==='running';
    return `<div class='tk-row'><div class='tk-main'><span class='cv-st ${c}'>${l}</span><b>${esc(t.title)}</b><small>${esc(t.detail||'')}</small>
      <span class='fm'>${esc(new Date(t.created*1000).toLocaleString([], {day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'}))} · ${tkDur(t)}</span>
      <span class='tk-act'>${t.status==='done'&&t.scan_id?`<a href='javascript:tkOpenResult("${esc(t.scan_id)}")'>Open result &rarr;</a>`:''}
        <a href='javascript:tkToggle("${esc(t.id)}")'>${tkLog===t.id?'Hide log':'Log'}</a>${act?` <a href='javascript:tkCancel("${esc(t.id)}")'>Cancel</a>`:''}</span></div>
      ${t.error?`<div class='tk-err'>${esc(t.error)}</div>`:(act&&t.log.length?`<div class='fm tk-last'>${esc(t.log[t.log.length-1])}</div>`:'')}
      ${tkLog===t.id&&full?`<pre class='tk-log'>${esc('$ '+full.command+'\n'+(full.log||[]).join('\n'))}</pre>`:''}</div>`; }).join('');
}
function tasksView(){
  setTimeout(tkLoad,0);
  return `<div class='panel'><h2>Run a task</h2><div id='tk-form'>${tkForm()}</div></div>
    <div class='panel'><h2>Tasks</h2><div id='tk-list'></div></div>`;
}
/* ---- Accepted risks: findings the team has decided to live with, each with a reason ----------- */
let RK={suppressions:[]}, rkPre=null;
async function rkLoad(){ try{ RK=await (await fetch('/api/suppressions')).json(); }catch(e){} rkPaint(); }
function acceptRisk(rule,resource){ rkPre={rule,resource}; location.hash='#risks'; drawerClose(); setTimeout(()=>{ rkFill(); const r=$('#rk-reason'); if(r) r.focus(); },50); }
function rkFill(){ if(!rkPre) return; const s=(id,v)=>{const e=$('#'+id); if(e) e.value=v}; s('rk-rule',rkPre.rule); s('rk-res',rkPre.resource); }
async function rkAdd(){
  const v=id=>(($('#'+id)||{}).value||'').trim(), msg=$('#rk-msg');
  const r=await fetch('/api/suppressions',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({rule:v('rk-rule'),resource:v('rk-res'),reason:v('rk-reason'),owner:v('rk-owner'),expires:v('rk-exp')})});
  const d=await r.json(); if(!r.ok){ msg.textContent=d.error||'Could not save.'; return; }
  rkPre=null; ['rk-rule','rk-res','rk-reason','rk-owner','rk-exp'].forEach(i=>{const e=$('#'+i); if(e) e.value=''}); msg.textContent='Saved. It applies from the next scan.'; rkLoad();
}
async function rkDel(id){ await fetch('/api/suppressions/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); rkLoad(); }
function rkPaint(){
  const b=$('#rk-list'); if(!b) return; const s=RK.suppressions||[];
  b.innerHTML=s.length?`<table class='cv-t'><thead><tr><th>Rule</th><th>Where</th><th>Reason</th><th>Owner</th><th>Expires</th><th></th></tr></thead><tbody>${s.map(x=>
    `<tr><td><code>${esc(x.rule)}</code></td><td><code>${esc(x.resource)}</code></td><td>${esc(x.reason)}</td><td>${esc(x.owner||'-')}</td>
      <td>${x.expires?(x.expired?`<span class='cv-st bad'>expired ${esc(x.expires)}</span>`:esc(x.expires)):"<span class='cv-st warn'>never</span>"}</td>
      <td><a href='javascript:rkDel("${esc(x.id)}")'>Remove</a></td></tr>`).join('')}</tbody></table>`:"<div class='cv-none'>None yet. Accept a risk from an issue's detail panel, or add one above.</div>";
}
function risksView(){
  setTimeout(()=>{ rkLoad(); rkFill(); },0);
  const rules=[...new Set((D.findings||[]).map(f=>f.rule_id))].sort();
  const sup=(D.scan&&D.scan.suppressed)||[], notes=(D.scan&&D.scan.suppression_notes)||[];
  return `<div class='panel'><h2>Accept a risk</h2><div class='fm'>Hides a finding from the score and the issue list in future scans, with your reason on record. Expiry makes it come back for review.</div>
    <div class='tk-fields'><label>Rule <input id='rk-rule' list='rk-rules' placeholder='e.g. workload-run-as-root'></label><datalist id='rk-rules'>${rules.map(r=>`<option value='${esc(r)}'>`).join('')}</datalist>
      <label>Where <input id='rk-res' placeholder='namespace/Kind/name (wildcards ok), blank = anywhere'></label>
      <label class='tk-wide'>Reason (required) <input id='rk-reason' placeholder='why this is acceptable, ticket link'></label>
      <label>Owner <input id='rk-owner' placeholder='who answers for it'></label><label>Expires <input id='rk-exp' type='date'></label>
      <button class='btn' type='button' onclick='rkAdd()'>Accept risk</button></div><div id='rk-msg' class='fm' role='status'></div></div>
    <div class='panel'><h2>Accepted risks</h2><div id='rk-list'></div></div>
    ${notes.length?`<div class='panel'><h2>Needs attention</h2>${notes.map(n=>`<div class='cv-iss' style='border-left-color:var(--med)'>${esc(n)}</div>`).join('')}</div>`:''}
    ${sup.length?`<div class='panel'><h2>Hidden in this scan (${sup.length})</h2><table class='cv-t'><thead><tr><th>Finding</th><th>Where</th><th>Reason</th><th>Owner</th></tr></thead><tbody>${sup.slice(0,200).map(x=>`<tr><td>${esc(x.title)}<small> ${esc(x.severity)}</small></td><td><code>${esc(x.resource)}</code></td><td>${esc(x.reason)}</td><td>${esc(x.owner||'-')}</td></tr>`).join('')}</tbody></table></div>`:''}`;
}
/* ---- Build: pick a pattern, tune a few fields, see exactly what is protected ---------------------
   Left: what is in the design. Middle: the one thing you are editing. Right: a short to-do list
   (what is missing, loosened or blocked), then the files. The safe settings are always on; the
   panel on the right says what that buys you, and what loosening costs. Nothing is applied to a
   cluster: you download the chart and run the `helm install` line. */
const BT={
 namespace:{g:'Config',n:'Namespace',s:'A fenced-off area with quotas and Pod Security',c:'#6f42c1'},
 workload:{g:'App',n:'App',s:'Runs your container: service, job, schedule or database',c:'#0b7285'},
 service:{g:'Traffic',n:'Service',s:'A stable address for your app',c:'#1a7f37'},
 ingress:{g:'Traffic',n:'Ingress',s:'Puts your app on the web, with HTTPS',c:'#e8590c'},
 networkpolicy:{g:'Traffic',n:'Network rule',s:'Who may talk to what',c:'#d1242f'},
 serviceaccount:{g:'Identity',n:'Service account',s:'The identity your app runs as',c:'#9c36b5'},
 role:{g:'Identity',n:'Permissions',s:'What that identity may do in Kubernetes',c:'#7048e8'},
 secret:{g:'Identity',n:'Secret from vault',s:'Pulled from your secret store; never typed here',c:'#c2255c'},
 configmap:{g:'Config',n:'Settings',s:'Plain, non-secret settings',c:'#5c7cfa'},
 pdb:{g:'Reliability',n:'Keep-alive rule',s:'Maintenance cannot take every copy down',c:'#868e96'},
 hpa:{g:'Reliability',n:'Autoscaler',s:'Adds copies under load',c:'#0ca678'},
 storage:{g:'Config',n:'Disk',s:'Persistent storage mounted into an app',c:'#e67700'},
 certificate:{g:'Traffic',n:'Certificate',s:'HTTPS certificate issued and renewed by cert-manager',c:'#f08c00'}};
const BORDER=['namespace','workload','service','ingress','certificate','networkpolicy','serviceaccount','role','secret','storage','configmap','pdb','hpa'];
const BGROUPS=[['App',['workload']],['Traffic',['service','ingress','networkpolicy']],['Identity & secrets',['serviceaccount','role','secret']],['Reliability',['pdb','hpa']],['Config',['namespace','configmap']]];
const BCAT=[
 ['Run something',[['Service','workload',{},'Runs all the time: web, API, worker'],['Database','workload',{kind:'StatefulSet',replicas:1,port:5432,storage:'20Gi'},'Own disk and a stable name'],
   ['Scheduled job','workload',{kind:'CronJob'},'Runs on a schedule'],['One-off job','workload',{kind:'Job'},'Runs once and stops'],['Node agent','workload',{kind:'DaemonSet'},'One copy on every node']]],
 ['Reach it',[['Service address','service',{},'A stable address'],['Ingress (web)','ingress',{},'Puts it on the web with HTTPS'],['Certificate','certificate',{},'Auto-issued HTTPS certificate'],['Network rule','networkpolicy',{},'Who may talk to what']]],
 ['Identity & secrets',[['Service account','serviceaccount',{},'Its own identity'],['Permissions','role',{},'What the identity may do'],['Secret from vault','secret',{},'Pulled from your secret store']]],
 ['Storage & config',[['Disk','storage',{},'Persistent volume for a Service'],['Settings','configmap',{},'Plain settings'],['Namespace','namespace',{},'Fenced-off area with quotas']]],
 ['Reliability',[['Keep-alive rule','pdb',{},'Survives node maintenance'],['Autoscaler','hpa',{},'Adds copies under load']]]];
const BIMG='nginxinc/nginx-unprivileged:1.27.2-alpine';
const BDEF={workload:{kind:'Deployment',image:BIMG,port:8080,replicas:2,cpu:'250m',memory:'256Mi',serviceAccount:'',env:[],writableRoot:false,runAsRoot:false,probes:true,secretEnv:[],reason:'',schedule:'0 2 * * *',storage:'5Gi'},
  service:{port:80,kind:'ClusterIP',target:'',sourceRanges:[],reason:''},ingress:{host:'app.example.com',tls:true,target:'',reason:''},serviceaccount:{readsApi:false,reason:''},
  networkpolicy:{mode:'default-deny',target:'',from:'',to:'',port:'',cidr:'',fromPod:'',toPod:''},configmap:{data:{}},pdb:{target:'',minAvailable:1},hpa:{target:'',minReplicas:2,maxReplicas:6,cpuPercent:70},
  secret:{store:'cluster-secret-store',keys:[],reason:''},role:{serviceAccount:'',preset:'read-config',rules:[{resources:['configmaps'],verbs:['get','list','watch']}],reason:''},
  storage:{target:'',size:'10Gi',path:'/data',storageClass:''},certificate:{target:'',issuer:'letsencrypt-prod'},
  namespace:{psa:'restricted',quotaCpu:'4',quotaMemory:'8Gi',reason:''}};
const BPATTERNS=[
 {id:'web',n:'Public web app',who:'Customer-facing site or API behind HTTPS',t:['App','Service','Ingress','HTTPS','Autoscale'],make:a=>[
   {type:'workload',name:a},{type:'service',name:a,target:a},{type:'ingress',name:a,host:a+'.example.com',target:a},
   {type:'networkpolicy',name:'allow-ingress',mode:'allow-from',target:a,from:'ingress-nginx',fromPod:'ingress-nginx',port:'8080'},{type:'pdb',name:a,target:a},{type:'hpa',name:a,target:a}]},
 {id:'api',n:'Internal service / API',who:'Reachable only from inside the cluster, by one named caller',t:['App','Service','Own identity'],make:a=>[
   {type:'serviceaccount',name:a},{type:'workload',name:a,serviceAccount:a},{type:'service',name:a,target:a},
   {type:'networkpolicy',name:'allow-caller',mode:'allow-from',target:a,from:'frontend',port:'8080'},{type:'pdb',name:a,target:a}]},
 {id:'worker',n:'Background worker',who:'Queue consumer or stream processor with no inbound traffic',t:['App','No address'],make:a=>[
   {type:'workload',name:a,port:8080}]},
 {id:'cron',n:'Scheduled job',who:'Runs on a schedule, like a nightly report or cleanup',t:['CronJob'],make:a=>[
   {type:'workload',name:a,kind:'CronJob',schedule:'0 2 * * *'}]},
 {id:'job',n:'One-off job',who:'A migration or batch task that runs once and stops',t:['Job'],make:a=>[
   {type:'workload',name:a,kind:'Job'}]},
 {id:'db',n:'Database / stateful service',who:'Needs its own disk and a stable name',t:['StatefulSet','Storage','Locked-down access'],make:a=>[
   {type:'workload',name:a,kind:'StatefulSet',replicas:1,port:5432,storage:'20Gi'},{type:'service',name:a,target:a,port:5432},
   {type:'networkpolicy',name:'allow-app',mode:'allow-from',target:a,from:'api',port:'5432'}]},
 {id:'operator',n:'Controller / operator',who:'Watches the Kubernetes API, with only the permissions it needs',t:['Own identity','API access','Permissions'],make:a=>[
   {type:'serviceaccount',name:a,readsApi:true,reason:'Controller or operator that manages cluster objects'},{type:'workload',name:a,serviceAccount:a,replicas:2},
   {type:'role',name:a+'-role',serviceAccount:a,preset:'leader-election',reason:'Operator that must change cluster objects',rules:[{resources:['leases'],verbs:['get','list','watch','create','update']}]}]},
 {id:'static',n:'Static website',who:'Plain files served by nginx, small and cheap',t:['App','Service','Ingress','HTTPS'],make:a=>[
   {type:'workload',name:a,replicas:2,cpu:'100m',memory:'128Mi'},{type:'service',name:a,target:a},{type:'ingress',name:a,host:a+'.example.com',target:a},
   {type:'networkpolicy',name:'allow-ingress',mode:'allow-from',target:a,from:'ingress-nginx',fromPod:'ingress-nginx',port:'8080'},{type:'pdb',name:a,target:a}]},
 {id:'three',n:'Three-tier app',who:'Web, API and database, each allowed to call only the next',t:['3 apps','HTTPS','Locked-down calls'],make:a=>[
   {type:'workload',name:a+'-web'},{type:'service',name:a+'-web',target:a+'-web'},{type:'ingress',name:a+'-web',host:a+'.example.com',target:a+'-web'},
   {type:'networkpolicy',name:'allow-ingress',mode:'allow-from',target:a+'-web',from:'ingress-nginx',fromPod:'ingress-nginx',port:'8080'},
   {type:'workload',name:a+'-api'},{type:'service',name:a+'-api',target:a+'-api'},
   {type:'networkpolicy',name:'api-from-web',mode:'allow-from',target:a+'-api',from:a+'-web',port:'8080'},
   {type:'networkpolicy',name:'web-to-api',mode:'allow-to',target:a+'-web',to:a+'-api',port:'8080'},
   {type:'workload',name:a+'-db',kind:'StatefulSet',replicas:1,port:5432,storage:'20Gi'},{type:'service',name:a+'-db',target:a+'-db',port:5432},
   {type:'networkpolicy',name:'db-from-api',mode:'allow-from',target:a+'-db',from:a+'-api',port:'5432'},
   {type:'networkpolicy',name:'api-to-db',mode:'allow-to',target:a+'-api',to:a+'-db',port:'5432'},
   {type:'pdb',name:a+'-web',target:a+'-web'},{type:'pdb',name:a+'-api',target:a+'-api'}]}];
const BREASONS={
 root:['Vendor or third-party image only runs as root','Legacy application, migration to non-root is planned','Needs to bind a privileged port (below 1024)','Installs or changes files at start-up'],
 writable:['App writes cache or temp files and cannot use a mounted volume','Vendor image requires a writable filesystem','Legacy application, migration is planned'],
 public:['Customer-facing API that must be reachable from the internet','Partner integration reachable from known partners','Temporary access for testing, to be removed'],
 notls:['TLS ends at an upstream load balancer or CDN','Private network only, no outside access','Temporary non-production environment'],
 api:['Controller or operator that manages cluster objects','Reads ConfigMaps, Secrets or Pods through the API','Leader election or service discovery'],
 rbac:['Reads Secrets the app needs at runtime','Operator that must change cluster objects','Temporary access for a migration, to be removed'],
 psa:['Needs privileged pods (network, storage or monitoring agent)','Third-party chart is not yet compatible with restricted','Moving in stages: baseline now, restricted later']};
let B={app:'my-app',ns:'my-app',registries:'',pullSecret:'',signing:'',guardrails:'warn',transport:{mode:'',mesh:'linkerd',issuer:'internal-ca',reason:''},complete:null,locks:[],approvals:{},comps:[],sel:null,tab:'security',files:'yaml',showAll:false,open:{},out:null,err:'',errComp:'',timer:null,seq:0,designs:[],presets:null,pattern:''};
try{ const s=JSON.parse(localStorage.getItem('k8smw-builder')||'null'); if(s&&s.comps) B=Object.assign(B,s,{out:null,err:'',timer:null,open:{},showAll:false,tab:['security','threats','files','drift'].includes(s.tab)?s.tab:'security'}); }catch(e){}
const bSave=()=>{ try{ localStorage.setItem('k8smw-builder',JSON.stringify({app:B.app,ns:B.ns,registries:B.registries,pullSecret:B.pullSecret,signing:B.signing,guardrails:B.guardrails,transport:B.transport,complete:B.complete,locks:B.locks,approvals:B.approvals,comps:B.comps,sel:B.sel,tab:B.tab,files:B.files,pattern:B.pattern})); }catch(e){} };
const bSpec=()=>({app:B.app,namespace:B.ns,registries:B.registries||'',pullSecret:B.pullSecret||'',signing:B.signing?{publicKey:B.signing}:{},guardrails:B.guardrails||'warn',transport:B.transport||{},locks:B.locks||[],approvals:B.approvals||{},components:B.comps});
const bSig=()=>{ try{ return JSON.stringify(bSpec()); }catch(e){ return ''; } };
const bIsComplete=()=>!!(B.complete&&B.complete.sig===bSig());
const bNames=t=>B.comps.filter(c=>c.type===t).map(c=>c.name);
const bServing=()=>B.comps.filter(c=>c.type==='workload'&&['Deployment','StatefulSet'].includes(c.kind||'Deployment')).map(c=>c.name);
const bPeers=()=>{ const s=new Set(bNames('workload')); cvRows('workloads').forEach(w=>s.add(w.name)); cvRows('namespaces').forEach(n=>s.add(n.name)); return [...s].filter(Boolean).sort(); };
function bMake(type,extra,list){ const base=Object.assign({},JSON.parse(JSON.stringify(BDEF[type]||{})),{type},extra||{});
  if(!base.name) base.name=type==='namespace'?B.ns:(type==='workload'?B.app:B.app+'-'+type); let n=base.name,k=2; while((list||B.comps).some(c=>c.type===type&&c.name===n)) n=base.name+'-'+(k++); base.name=n; return base; }
function bAdd(type,extra){ const c=bMake(type,extra);
  const w=bServing(); if(type==='service'&&w.length===1&&!c.target) c.target=w[0];
  if(type==='ingress'&&bNames('service').length===1&&!c.target) c.target=bNames('service')[0];
  if((type==='pdb'||type==='hpa')&&w.length===1&&!c.target) c.target=w[0];
  if(type==='role'&&bNames('serviceaccount').length===1&&!c.serviceAccount) c.serviceAccount=bNames('serviceaccount')[0];
  const dep=B.comps.filter(x=>x.type==='workload'&&(x.kind||'Deployment')==='Deployment').map(x=>x.name);
  if(type==='storage'&&dep.length===1&&!c.target) c.target=dep[0];
  if(type==='certificate'&&bNames('ingress').length===1&&!c.target) c.target=bNames('ingress')[0];
  if(type==='networkpolicy'&&!(extra&&extra.mode)&&B.comps.some(x=>x.type==='networkpolicy')){ c.mode='allow-from'; if(w.length===1) c.target=w[0]; c.name=B.app+'-allow'; }
  B.comps.push(c); B.sel=B.comps.length-1; B.pattern=B.pattern||''; bRender(true); }
async function bPattern(id){ const p=BPATTERNS.find(x=>x.id===id); if(!p) return; if(B.comps.length&&!confirm('Replace the current design with "'+p.n+'"?')) return;
  B.comps=[]; B.locks=[]; B.approvals={}; B.complete=null; B.transport={mode:'',mesh:'linkerd',issuer:'internal-ca',reason:''}; p.make(B.app).forEach(c=>B.comps.push(bMake(c.type,c,B.comps))); B.pattern=p.id; B.sel=B.comps.findIndex(c=>c.type==='workload'); await bAddMissing(true); }
function bRemove(i){ B.comps.splice(i,1); B.sel=B.comps.length?Math.min(i,B.comps.length-1):null; bRender(true); }
function bSel(i){ B.sel=i; bList(); bInsp(); if(B.tab==='threats') bPanel(); bSave(); const e=$('#bd-insp'); if(e&&e.scrollIntoView&&innerWidth<1100) e.scrollIntoView({behavior:'smooth',block:'start'}); }
function bClear(){ if(!B.comps.length||confirm('Remove everything and start over?')){ B.comps=[]; B.sel=null; B.pattern=''; B.locks=[]; B.approvals={}; B.complete=null; bRender(true); } }
function bDrag(ev,type){ ev.dataTransfer.setData('text/plain',type); ev.dataTransfer.effectAllowed='copy'; }
function bDrop(ev){ ev.preventDefault(); const l=$('#bd-list'); if(l) l.classList.remove('over'); const t=ev.dataTransfer.getData('text/plain'); if(BT[t]) bAdd(t); }
function bSet(i,f,v){ const c=B.comps[i]; if(!c) return;
  if(f==='name'){ const old=c.name; B.comps.forEach(x=>{ if(x===c) return; ['target','from','to','serviceAccount'].forEach(k=>{ if(x[k]===old) x[k]=v; }); }); }
  if(f==='preset'&&c.type==='role'){ c.preset=v; if(B.presets&&B.presets[v]) c.rules=JSON.parse(JSON.stringify(B.presets[v].rules)); bInsp(); bList(); bQueue(); bSave(); return; }
  if(f==='rules'&&c.type==='role'){ c.preset='custom'; c.rules=String(v).split('\n').map(l=>l.trim()).filter(l=>l.includes(':')).map(l=>{const k=l.indexOf(':'); return {resources:l.slice(0,k).split(',').map(x=>x.trim()).filter(Boolean),verbs:l.slice(k+1).split(',').map(x=>x.trim()).filter(Boolean)}}); bList(); bQueue(); bSave(); return; }
  if(f==='keys'&&c.type==='secret'){ c.keys=String(v).split('\n').map(l=>l.trim()).filter(l=>l.includes('=')).map(l=>{const k=l.indexOf('='); return {name:l.slice(0,k).trim(),remote:l.slice(k+1).trim()}}); bList(); bQueue(); bSave(); return; }
  if(f==='secretEnv'){ c[f]=String(v).split('\n').map(l=>l.trim()).filter(l=>l.includes('=')).map(l=>{const k=l.indexOf('='), r=l.slice(k+1).trim(), [sec,key]=r.split(':'); return {name:l.slice(0,k).trim(),secret:(sec||'').trim(),key:(key||'').trim()}}); bQueue(); bSave(); return; }
  if(f==='sourceRanges'){ c[f]=String(v).split('\n').map(x=>x.trim()).filter(Boolean); bQueue(); bSave(); return; }
  if(f==='env'||f==='data'){ c[f]=bKV(v,f); } else c[f]=v;
  if(['kind','tls','readsApi','runAsRoot','writableRoot','psa','mode'].includes(f)||(f==='kind'&&c.type==='service')) bInsp();
  bList(); bQueue(); bSave(); }
function bKV(text,f){ const rows=String(text).split('\n').map(l=>l.trim()).filter(l=>l.includes('=')).map(l=>{const k=l.indexOf('='); return [l.slice(0,k).trim(),l.slice(k+1).trim()]});
  return f==='env'?rows.map(([name,value])=>({name,value})):Object.fromEntries(rows); }
const bKVText=(c,f)=>f==='env'?(c.env||[]).map(e=>e.name+'='+e.value).join('\n'):Object.entries(c.data||{}).map(([k,v])=>k+'='+v).join('\n');
function bQueue(){ clearTimeout(B.timer); B.timer=setTimeout(bCheck,350); }
async function bCheck(){
  const seq=++B.seq;
  if(!B.comps.length){ B.out=null; B.err=''; B.errComp=''; bHead(); bPanel(); return; }
  try{ const r=await fetch('/api/build/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(bSpec())});
    const d=await r.json(); if(seq!==B.seq) return; if(d.presets) B.presets=d.presets; B.env=d.env||B.env||{};
    if(r.ok){ B.out=d; B.err=''; B.errComp=''; B.paths=d.attack_paths||[]; } else { B.out=d.layers?{layers:d.layers}:null; B.paths=[]; B.err=d.error||'Could not build this.'; B.errComp=d.component||''; } }
  catch(e){ if(seq!==B.seq) return; B.err='Could not reach the dashboard.'; B.errComp=''; }
  bHead(); bList(); bPanel(); bSecFor();
}
async function bDownload(){
  const todo=bTodo().must.length; if(todo&&!confirm(todo+' thing(s) are still open in the Security tab. Download the chart anyway?')) return;
  const r=await fetch('/api/build/chart',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(bSpec())});
  if(!r.ok){ const d=await r.json(); B.err=d.error||'Could not build the chart.'; bPanel(); return; }
  const a=document.createElement('a'); a.href=URL.createObjectURL(await r.blob()); a.download=B.app+'.tgz'; a.click(); URL.revokeObjectURL(a.href);
}
async function bAddMissing(quiet){
  for(let n=0;n<5;n++){
    const r=await fetch('/api/build/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(bSpec())});
    const d=await r.json(); if(!d.layers) break; if(d.presets) B.presets=d.presets; B.out=r.ok?d:{layers:d.layers};
    const ls=d.layers.layers.filter(l=>l.status==='off'&&l.add&&!l.optional); if(!ls.length) break;
    ls.forEach(l=>{ const a=l.add; B.comps.push(bMake(a.type,a.type==='namespace'?Object.assign({},a,{name:B.ns}):a)); });
  }
  if(!quiet) B.sel=null; bRender(true);
}
/* ---- helpers for the editor ---- */
const bOpts=(arr,cur,blank)=>(blank?`<option value=''>${esc(arr.length?blank:blank.replace(/^Pick/,'Nothing to pick yet: add'))}</option>`:'')+arr.map(v=>{const [val,l]=Array.isArray(v)?v:[v,v]; return `<option value='${esc(val)}' ${val===cur?'selected':''}>${esc(l)}</option>`}).join('');
function bField(i,f,label,val,o){ o=o||{}; const h=o.help?`<small>${o.help}</small>`:'';
  if(o.select) return `<label>${label}<select onchange='bSet(${i},"${f}",this.value)'>${o.select}</select>${h}</label>`;
  if(o.check) return `<label class='bd-chk'><input type='checkbox' ${val?'checked':''} onchange='bSet(${i},"${f}",this.checked)'> <span>${label}${h}</span></label>`;
  if(o.area) return `<label>${label}<textarea rows='3' oninput='bSet(${i},"${f}",this.value)' placeholder='${esc(o.ph||'')}'>${esc(val)}</textarea>${h}</label>`;
  if(o.list) return `<label>${label}<input list='${o.list}' value='${esc(val??'')}' oninput='bSet(${i},"${f}",this.value)' placeholder='${esc(o.ph||'')}'>${h}</label>`;
  return `<label>${label}<input value='${esc(val??'')}' type='${o.num?'number':'text'}' oninput='bSet(${i},"${f}",${o.num?'+this.value':'this.value'})' placeholder='${esc(o.ph||'')}'>${h}</label>`; }
function bReason(i,kind){ const c=B.comps[i], list=BREASONS[kind], cur=c.reason||'', other=c._other||(cur&&!list.includes(cur));
  return `<label>Business reason (required)<select onchange='bPickReason(${i},this.value)'><option value=''>Choose a reason…</option>${list.map(v=>`<option ${v===cur?'selected':''}>${esc(v)}</option>`).join('')}<option value='__other' ${other?'selected':''}>Other (write your own)</option></select></label>`
    +(other?bField(i,'reason','Your reason',cur,{ph:'short explanation or ticket link'}):''); }
function bPickReason(i,v){ const c=B.comps[i]; if(!c) return; if(v==='__other'){ c._other=true; c.reason=''; } else { c._other=false; c.reason=v; } bInsp(); bQueue(); bSave(); }
const bSec=(t,h,open)=>`<details class='bd-sec' ${open?'open':''}><summary>${t}</summary><div class='bd-fields'>${h}</div></details>`;
function bFormFor(i){
  const c=B.comps[i]; if(!c) return '';
  const f=(k,l,o)=>bField(i,k,l,c[k],o), nm=f('name','Name',{help:'Lowercase letters, numbers and dashes.'}), kind=c.kind||'Deployment';
  const serving=['Deployment','StatefulSet'].includes(kind);
  const body={
   storage:()=>bSec('Basics',nm+f('target','Mounted into',{select:bOpts(B.comps.filter(x=>x.type==='workload'&&(x.kind||'Deployment')==='Deployment').map(x=>x.name),c.target,'Pick a service'),help:'A database already gets its own disk.'})+f('size','Size',{ph:'10Gi'})+f('path','Folder inside the container',{ph:'/data'})+f('storageClass','Storage class (optional)',{ph:'leave blank for the cluster default'}),true),
   certificate:()=>bSec('Basics',nm+f('target','For the ingress',{select:bOpts(bNames('ingress'),c.target,'Pick an ingress')})+f('issuer','Issuer (ClusterIssuer name)',{ph:'letsencrypt-prod',help:'The cert-manager issuer your cluster uses.'}),true),
   workload:()=>bSec('Basics',f('kind','Type',{select:bOpts([['Deployment','Service: runs all the time (web, API, worker)'],['StatefulSet','Database or stateful service: own disk, stable name'],['CronJob','Scheduled job: runs on a schedule'],['Job','One-off job: runs once and stops'],['DaemonSet','Node agent: one copy on every node']],kind)})
       +nm+f('image','Container image',{help:'Use a fixed version, never <code>latest</code>; a digest (<code>@sha256:…</code>) is best.'})
       +`<div class='bd-scan'><button type='button' class='bd-btn' onclick='bPinDigest(${i})'>Pin to digest</button> <button type='button' class='bd-btn' onclick='bScanImage(${i})'>Scan for known vulnerabilities</button><div id='b-scan-out' class='bd-note'></div></div>`
       +(serving?f('port','Port your app listens on',{num:1})+f('replicas','Copies to run',{num:1,help:'2 or more keeps it up during updates.'}):'')
       +(kind==='CronJob'?f('schedule','Schedule',{ph:'0 2 * * *',help:'Five parts: minute hour day month weekday. <code>0 2 * * *</code> is 2am every day.'}):'')
       +(kind==='StatefulSet'?f('storage','Disk size',{ph:'20Gi'}):''),true)
     +bSec('Runs as',f('serviceAccount','Identity',{select:bOpts(bNames('serviceaccount'),c.serviceAccount,'(default, no API access)'),help:'Add a Service account for its own identity.'}),false)
     +bSec('Size',f('cpu','CPU limit',{ph:'250m'})+f('memory','Memory limit',{ph:'256Mi'}),false)
     +bSec('Settings and secrets',bField(i,'env','Environment variables (KEY=value per line)',bKVText(c,'env'),{area:1,ph:'LOG_LEVEL=info',help:'Not for passwords.'})
       +bField(i,'secretEnv','Secrets (ENV_NAME=secret-name:key)',(c.secretEnv||[]).map(e=>e.name+'='+e.secret+(e.key?':'+e.key:'')).join('\n'),{area:1,ph:'DB_PASSWORD=shop-db:password',help:'Points at a Secret that already exists. The value never enters this design.'})
       +(serving?bField(i,'probes','Health checks (restart a stuck copy)',c.probes,{check:1}):''),false)
     +bSec('Loosen a safe default',bField(i,'writableRoot','App must write to its own filesystem',c.writableRoot,{check:1,help:'Not recommended.'})+bField(i,'runAsRoot','App must run as root',c.runAsRoot,{check:1,help:'Not recommended.'})
       +((c.runAsRoot||c.writableRoot)?bReason(i,c.runAsRoot?'root':'writable'):''),!!(c.runAsRoot||c.writableRoot)),
   service:()=>bSec('Basics',nm+f('target','Sends traffic to',{select:bOpts(bServing(),c.target,'Pick an app')})+f('port','Port',{num:1})
       +f('kind','Who can reach it',{select:bOpts([['ClusterIP','Only things inside the cluster (safe)'],['LoadBalancer','The public internet (needs a reason)'],['NodePort','Every node, on a high port']],c.kind)})
       +(c.kind==='LoadBalancer'?bField(i,'sourceRanges','Allowed source addresses (one per line)',(c.sourceRanges||[]).join('\n'),{area:1,ph:'203.0.113.0/24',help:'Leave out to allow the whole internet.'}):'')
       +(c.kind!=='ClusterIP'?bReason(i,'public'):''),true),
   ingress:()=>bSec('Basics',nm+f('target','Sends traffic to',{select:bOpts(bNames('service'),c.target,'Pick a service')})+f('host','Web address',{ph:'app.example.com'})
       +bField(i,'tls','Use HTTPS',c.tls,{check:1,help:'Needs a TLS secret named <code>'+esc(c.name)+'-tls</code> or cert-manager.'})+(!c.tls?bReason(i,'notls'):''),true),
   serviceaccount:()=>bSec('Basics',nm+bField(i,'readsApi','Needs to talk to the Kubernetes API',c.readsApi,{check:1,help:'Leave off unless your app lists or changes cluster objects.'})+(c.readsApi?bReason(i,'api'):''),true),
   networkpolicy:()=>bSec('Basics',nm+f('mode','What it does',{select:bOpts([['default-deny','Block all traffic by default (start here)'],['allow-dns','Allow name lookups (DNS)'],['allow-from','Allow one source to reach an app'],['allow-to','Allow an app to call one destination'],['allow-egress-cidr','Allow an app to call an outside address range']],c.mode)})
       +((['allow-from','allow-to','allow-egress-cidr'].includes(c.mode))?f('target',c.mode==='allow-from'?'App being protected':'App that makes the call',{select:bOpts(bNames('workload'),c.target,'Pick an app')}):'')
       +(c.mode==='allow-from'?f('from','May be reached by',{list:'b-peers',ph:'pick, or type an app or namespace',help:'Suggestions come from this design and the last scanned cluster.'}):'')
       +(c.mode==='allow-from'&&c.from&&!bNames('workload').includes(c.from)?f('fromPod','Only this pod inside it (label app.kubernetes.io/name)',{ph:'ingress-nginx',help:'Without this, every pod in that namespace is trusted.'}):'')
       +(c.mode==='allow-to'?f('to','May call',{list:'b-peers',ph:'pick, or type an app or namespace'}):'')
       +(c.mode==='allow-to'&&c.to&&!bNames('workload').includes(c.to)?f('toPod','Only this pod inside it (label app.kubernetes.io/name)',{ph:'postgres',help:'Without this, every pod in that namespace may be called.'}):'')
       +(c.mode==='allow-egress-cidr'?f('cidr','Outside address range',{ph:'203.0.113.0/24',help:'The whole internet (0.0.0.0/0) is refused.'}):'')
       +((['allow-from','allow-to','allow-egress-cidr'].includes(c.mode))?f('port','Port (blank = every port)',{ph:'5432 or 53/UDP',help:'Name the port. A rule without one opens every port.'}):''),true),
   configmap:()=>bSec('Basics',nm+bField(i,'data','Settings (KEY=value per line)',bKVText(c,'data'),{area:1,ph:'FEATURE_X=on',help:'Never put passwords or tokens here.'}),true),
   pdb:()=>bSec('Basics',nm+f('target','Protects',{select:bOpts(bServing(),c.target,'Pick an app')})+f('minAvailable','Copies that must stay up',{num:1}),true),
   hpa:()=>bSec('Basics',nm+f('target','Scales',{select:bOpts(bServing(),c.target,'Pick an app')})+f('minReplicas','Fewest copies',{num:1})+f('maxReplicas','Most copies',{num:1})+f('cpuPercent','Add copies above this CPU %',{num:1}),true),
   secret:()=>bSec('Basics',nm+f('store','Secret store',{ph:'cluster-secret-store',help:'Your ClusterSecretStore (Vault, AWS Secrets Manager, ...).'})
       +bField(i,'keys','Keys (KEY=path/in/store per line)',(c.keys||[]).map(k=>k.name+'='+k.remote).join('\n'),{area:1,ph:'password=prod/shop/db/password',help:'Left: the key your app reads. Right: where it lives in the store.'}),true),
   role:()=>bSec('Basics',nm+f('serviceAccount','Gives permissions to',{select:bOpts(bNames('serviceaccount'),c.serviceAccount,'Pick a service account')})
       +f('preset','Start from a preset',{select:bOpts(Object.entries(B.presets||{}).map(([k,v])=>[k,v.label]).concat([['custom','Custom (edit the list)']]),c.preset)})
       +bField(i,'rules','Allowed (one per line: resources: verbs)',(c.rules||[]).map(r=>r.resources.join(',')+': '+r.verbs.join(',')).join('\n'),{area:1,ph:'configmaps: get,list,watch',help:'No wildcards. Verbs: get list watch create update patch delete.'})
       +(((c.rules||[]).some(r=>r.verbs.some(v=>!['get','list','watch'].includes(v))||r.resources.some(x=>['secrets','pods/exec','roles','rolebindings','serviceaccounts'].includes(x))))?bReason(i,'rbac'):''),true),
   namespace:()=>bSec('Basics',nm+f('psa','Pod Security level',{select:bOpts([['restricted','restricted: strongest (recommended)'],['baseline','baseline: blocks the worst'],['privileged','privileged: no protection']],c.psa)})
       +(c.psa!=='restricted'?bReason(i,'psa'):'')+f('quotaCpu','Total CPU for this namespace',{ph:'4'})+f('quotaMemory','Total memory',{ph:'8Gi'}),true)}[c.type]();
  return body;
}
async function bPinDigest(i){ const c=B.comps[i], o=$('#b-scan-out'); if(!o||!c) return; o.textContent='Asking the registry for '+c.image+'…';
  try{ const r=await fetch('/api/build/digest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({image:c.image})}); const d=await r.json();
    if(!r.ok||d.error){ o.textContent=d.error||'Could not look it up.'; return; } c.image=d.pinned; bInsp(); bList(); bQueue(); bSave(); const n=$('#b-scan-out'); if(n) n.textContent=d.already?'Already pinned.':'Pinned to '+d.digest.slice(0,19)+'…'; }
  catch(e){ o.textContent='Could not reach the dashboard.'; } }
async function bScanImage(i){ const c=B.comps[i], o=$('#b-scan-out'); if(!o||!c) return; o.textContent='Scanning '+c.image+' (the first scan downloads the vulnerability feed and can take a few minutes)…';
  try{ const r=await fetch('/api/build/imagescan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({image:c.image})}); const d=await r.json();
    if(!r.ok||d.error){ o.textContent=d.error||'Could not scan.'; return; } if(!d.available){ o.textContent=d.message; return; }
    const k=d.counts||{}; o.innerHTML=d.total?`${['Critical','High','Medium','Low'].filter(x=>k[x]).map(x=>`<span class='sev ${x.toUpperCase()}'>${k[x]} ${x.toLowerCase()}</span>`).join(' ')||'only negligible findings'} &middot; ${d.fixable} have a fix${d.kev?` &middot; <b>${d.kev} known-exploited</b>`:''}`:'No known vulnerabilities found.'; }
  catch(e){ o.textContent='Could not reach the dashboard.'; } }
/* ---- the to-do list: what to do next, in order ---- */
function bTodo(){
  const must=[], nice=[], LY=(B.out&&B.out.layers)||{layers:[],problems:[]};
  const probs=LY.problems||[]; probs.forEach(p=>must.push({k:'err',title:'Fix this first',why:p.message,comp:p.component}));
  if(B.err&&!probs.some(p=>p.message===B.err)) must.push({k:'err',title:'Finish the design',why:B.err,comp:B.errComp});
  LY.layers.forEach((l,i)=>{
    if(l.status==='off'&&!l.optional) must.push({k:'off',title:l.title,why:l.detail||l.why,layer:i,add:l.add,choices:l.choices});
    else if(l.status==='off'&&l.optional) nice.push({k:'opt',title:l.title,why:l.detail||l.why,layer:i,add:l.add});
    else if(l.status==='blocked') must.push({k:'blocked',title:l.title+' is locked',why:l.detail,layer:i});
    else if(l.status==='loosened') must.push({k:'loose',title:l.title+' is loosened',why:l.detail,layer:i,choices:l.choices});
  });
  (B.paths||[]).forEach(p=>{ const item={k:'path',title:'Attack path: '+(p.target||'').replace(/^id:Capability:/,''),why:p.summary,sev:p.severity}; if(p.internet||['HIGH','CRITICAL'].includes(p.severity)) must.push(item); else nice.push(item); });
  const RL={'workload-run-as-root':'non-root','workload-writable-root-fs':'read-only-fs','net-ingress-no-tls':'tls','net-lb-no-source-range':'no-public-service','net-nodeport-service':'no-public-service','compliance-psa-not-restricted':'ns-fence'};
  const covered=new Set(LY.layers.filter(l=>l.status==='covered').map(l=>l.id));
  ((B.out&&B.out.check&&B.out.check.issues)||[]).filter(x=>['CRITICAL','HIGH'].includes(x.severity)&&!covered.has(RL[x.rule]||(String(x.rule).startsWith('rbac-')?'least-privilege-rbac':''))).forEach(x=>must.push({k:'scan',title:x.title,why:x.fix||x.where,comp:x.component,sev:x.severity}));
  return {must,nice,LY};
}
function bHead(){
  const el=$('#bd-head'); if(!el) return; const T=bTodo(), n=T.must.length, has=B.comps.length, done=bIsComplete();
  const changed=!!B.complete&&!done;
  const pill=!has?`<span class='cv-st warn'>Pick a pattern to begin</span>`:(!B.out&&!B.err)?`<span class='cv-st warn'>Checking…</span>`:done?`<span class='cv-st ok'>&#10003; Design complete</span>`
    :n?`<span class='cv-st bad'>${n} to fix before you can finish</span>`:`<span class='cv-st ok'>&#10003; Nothing left to fix, ready to finish</span>`;
  const on=T.LY.layers.filter(l=>!l.optional&&['on','covered'].includes(l.status)).length, tot=T.LY.layers.filter(l=>!l.optional).length;
  const primary=!has?'':done?`<button type='button' class='btn' onclick='bDownload()'>Download chart</button>`:`<button type='button' class='btn' onclick='bFinish()'>${n?'Review and finish ('+n+')':'Finish design'}</button>`;
  el.innerHTML=`<div class='bd-id'><input class='bd-app' id='bd-app' value='${esc(B.app)}' oninput='bApp(this.value,this)' onblur='bAppTrim(this)' aria-label='App name' placeholder='app-name'><small>namespace <b>${esc(B.ns)}</b></small></div>
    <div class='bd-state'>${pill}${changed?`<small>changed since you finished it</small>`:''}${has&&tot?`<div class='bd-prog' title='${on} of ${tot} required protections are on'><i style='width:${Math.round(100*on/tot)}%'></i></div><small>${on} of ${tot} protections on</small>`:''}</div>
    <div class='bd-acts'><button type='button' class='bd-btn' onclick='bPick()'>Patterns</button>
      <button type='button' class='bd-btn' onclick='bSettings()'>Designs &amp; settings</button>
      <button type='button' class='bd-btn' onclick='bClear()'>Start over</button>${has&&!done?`<button type='button' class='bd-btn' onclick='bDownload()'>Download chart</button>`:''}${primary}</div>`;
}
/* Finishing: tell the tool (and the next person) the design is done. Any later edit changes the signature, so it reverts to draft. */
function bFinish(){
  const T=bTodo();
  if(T.must.length){ drawerOpen(`<div class='cv-dk'>Before you can finish</div><h3>${T.must.length} thing${T.must.length>1?'s':''} left</h3><p class='bd-note'>Each is a protection that is missing, loosened without cover, or a field that needs fixing. Fix them, or loosen on purpose with a reason.</p>${T.must.map(x=>bTodoCard(x)).join('')}<div class='rt-row'><button class='bd-btn' type='button' onclick='drawerClose()'>Keep designing</button></div>`); return; }
  bCompleteDrawer(bIsComplete());
}
function bCompleteDrawer(done){
  const LY=(B.out&&B.out.layers)||{layers:[]}, tm=B.out&&B.out.threat_model, sm=tm&&tm.summary, env=(B.out&&B.out.env)||B.env||{};
  const acc=LY.layers.filter(l=>l.status==='covered'), opts=LY.layers.filter(l=>l.optional&&l.status==='off');
  const req=LY.layers.filter(l=>!l.optional), okn=req.filter(l=>['on','covered'].includes(l.status)).length;
  const body=`<div class='bd-good'>&#10003; ${okn} of ${req.length} protections are on.${B.out&&B.out.check?` Scanner rating: ${esc(B.out.check.rating||'')}.`:''}</div>
   ${sm?`<p class='cv-p'><small>Threat model: ${sm.mitigated||0} mitigated, ${sm.partial||0} partly, <b>${sm.open||0} open</b>, ${sm.residual||0} accepted risks.</small></p>`:''}
   <p class='cv-p'><small>${(B.paths||[]).length?(B.paths.length+' attack path(s) remain, see the Threats tab.'):'No attack path found by our own analysis.'}</small></p>
   ${acc.length?`<div class='cv-dh'>What you accepted on purpose</div>${acc.map(l=>`<p class='cv-p'><b>${esc(l.title)}</b><small>${esc(l.reason||'')}${l.approval&&l.approval.by?' · approved by '+esc(l.approval.by):''}</small></p>`).join('')}`:''}
   ${opts.length?`<div class='cv-dh'>Nice to have, not done (${opts.length})</div><p class='cv-p'><small>${opts.map(l=>esc(l.title)).join(' · ')}</small></p>`:''}
   <div class='cv-dh'>This design assumes</div><p class='cv-p'><small>${env.scanned?`Network plugin ${esc(env.cni||'not detected')}, service mesh ${esc(env.mesh||'none')}, cert-manager ${env.certmanager?'present':'absent'} (from your last scan).`:'A cluster you have not scanned, so these cannot be checked.'} Guardrail policy needs Kubernetes 1.30 or later. It does not cover vulnerable application code, runtime attacks, or the nodes themselves.</small></p>`;
  if(!done){ drawerOpen(`<div class='cv-dk'>Review</div><h3>Ready to finish</h3>${body}<div class='rt-row'><button class='btn' type='button' onclick='bMarkComplete()'>Mark design as complete</button><button class='bd-btn' type='button' onclick='drawerClose()'>Keep designing</button></div>`); return; }
  drawerOpen(`<div class='cv-dk'>Done</div><h3>Design complete</h3><p class='bd-note'>Finished ${esc(new Date(B.complete.at).toLocaleString())}. Any change turns it back into a draft until you finish it again.</p>${body}
   <div class='cv-dh'>Next</div><div class='rt-row'><button class='btn' type='button' onclick='bDownload()'>Download the Helm chart</button><button class='bd-btn' type='button' onclick='bDesignSave()'>Save as a reusable design</button><button class='bd-btn' type='button' onclick='drawerClose();B.tab="files";bPanel()'>Show install command</button></div>
   <div class='rt-row'><button class='bd-btn' type='button' onclick='bReopen()'>Reopen for editing</button></div>`);
}
function bMarkComplete(){ B.complete={at:new Date().toISOString(),sig:bSig()}; bSave(); bHead(); bCompleteDrawer(true); }
function bReopen(){ B.complete=null; bSave(); drawerClose(); bHead(); }
function bSettings(){
  drawerOpen(`<div class='cv-dk'>Build</div><h3>Designs &amp; settings</h3><div class='bd-pop'><div class='bd-fields'>
    <label>Namespace<input id='b-ns' value='${esc(B.ns)}' oninput='B.ns=this.value;bQueue();bSave();bHead()'><small>Where everything in this design is created.</small></label>
    <label>Trusted registries<input id='b-reg' value='${esc(B.registries||'')}' placeholder='registry.example.com/team, ghcr.io/acme' oninput='B.registries=this.value;bQueue();bSave()'><small>Images must start with one of these. Leave blank to allow any.</small></label>
    <label>Guardrails in the cluster<select onchange='B.guardrails=this.value;bQueue();bSave()'>${[['warn','Warn on violations'],['deny','Block violations'],['off','Off']].map(([v,l])=>`<option value='${v}' ${(B.guardrails||'warn')===v?'selected':''}>${l}</option>`).join('')}</select><small>An admission policy built from this design. Needs Kubernetes 1.30 or later.</small></label></div>
    <label>Image pull secret<input value='${esc(B.pullSecret||'')}' placeholder='artifactory-pull' oninput='B.pullSecret=this.value;bQueue();bSave()'><small>Name of the Secret (type docker-registry) in the namespace that lets pods pull from your private registry.</small></label>
    <label>Image signing public key (cosign, PEM)<textarea rows='4' placeholder='-----BEGIN PUBLIC KEY-----' oninput='B.signing=this.value;bQueue();bSave()'>${esc(B.signing||'')}</textarea><small>Adds an admission policy (Kyverno) that refuses images not signed with this key.</small></label>
    <div class='bd-sep'></div><div class='bd-fields'>
    <label>Encryption between services<select onchange='bSetTr("mode",this.value)'>${[['','Not chosen yet'],['mesh','Service mesh: easiest, no app changes'],['certs','A certificate per app (cert-manager)'],['none','None (needs a reason)']].map(([v,l])=>`<option value='${v}' ${B.transport.mode===v?'selected':''}>${l}</option>`).join('')}</select>
      <small>A network rule says who may connect; it does not hide or prove who is calling. Pick one so calls cannot be read or faked.</small></label>
    ${B.transport.mode==='mesh'?`<label>Which mesh<select onchange='bSetTr("mesh",this.value)'>${[['linkerd','Linkerd (simplest)'],['istio','Istio ambient (no sidecars)']].map(([v,l])=>`<option value='${v}' ${B.transport.mesh===v?'selected':''}>${l}</option>`).join('')}</select><small>It must already be installed in the cluster.</small></label>`:''}
    ${B.transport.mode==='certs'?`<label>Certificate issuer<input value='${esc(B.transport.issuer)}' oninput='bSetTr("issuer",this.value)'><small>Name of your cert-manager ClusterIssuer. Each app must be set up to serve HTTPS with its certificate.</small></label>`:''}
    ${B.transport.mode==='none'?`<label>Business reason (required)<select onchange='bSetTr("reason",this.value)'><option value=''>Choose a reason…</option>${['One service only, no calls between services','Encryption is handled inside the app itself','Traffic stays on one node','Temporary: a mesh rollout is planned'].map(v=>`<option ${B.transport.reason===v?'selected':''}>${esc(v)}</option>`).join('')}</select></label>`:''}</div>
    <div class='bd-sep'></div><div id='b-designs' class='bd-designs'></div></div>`);
  bPaintDesigns();
}
function bSetTr(k,v){ B.transport=Object.assign({},B.transport,{[k]:v}); if(k==='mode'||k==='mesh') bSettings(); bQueue(); bSave(); }
function bApp(v,inp){ const clean=String(v).toLowerCase().replace(/[^a-z0-9-]+/g,'-').replace(/^-+/,'').slice(0,40); if(inp&&inp.value!==clean) inp.value=clean; v=clean; const keep=B.ns===B.app||!B.ns; B.app=v; if(keep) B.ns=v; bQueue(); bSave(); const s=document.querySelector('.bd-id small b'); if(s) s.textContent=B.ns; const n=$('#b-ns'); if(n) n.value=B.ns; }
function bAppTrim(inp){ const t=inp.value.replace(/-+$/,''); if(t!==inp.value){ inp.value=t; bApp(t,inp); } }
function bPick(){ B.sel=null; bInsp(true); const e=$('#bd-insp'); if(e&&e.scrollIntoView) e.scrollIntoView({behavior:'smooth',block:'start'}); }
function bList(){
  const el=$('#bd-list'); if(!el) return; const bad=((B.out&&B.out.check&&B.out.check.issues)||[]).filter(x=>['CRITICAL','HIGH'].includes(x.severity));
  const sub=c=>({workload:`${c.kind||'Deployment'} · ${(c.image||'').split('/').pop()}`,service:c.target?'to '+c.target:'pick an app',ingress:c.host,
    networkpolicy:c.mode==='default-deny'?'blocks all by default':c.mode==='allow-dns'?'name lookups':c.mode==='allow-to'?(c.target||'?')+' calls '+(c.to||c.cidr||'?'):c.mode==='allow-egress-cidr'?(c.target||'?')+' calls '+(c.cidr||'?'):(c.from||'?')+' to '+(c.target||'?'),
    serviceaccount:c.readsApi?'API access on':'no API access',configmap:Object.keys(c.data||{}).length+' setting(s)',pdb:'min '+c.minAvailable,hpa:(c.minReplicas||'')+'-'+(c.maxReplicas||'')+' copies',
    role:(c.serviceAccount||'?')+' · '+(c.rules||[]).length+' rule(s)',storage:(c.size||'')+' at '+(c.path||'/')+' for '+(c.target||'?'),certificate:'for '+(c.target||'?')+' via '+(c.issuer||'?'),secret:(c.keys||[]).length+' key(s)',namespace:'Pod Security: '+c.psa}[c.type]||'');
  const row=i=>{ const c=B.comps[i], T=BT[c.type], n=bad.filter(x=>x.component===c.name).length;
    return `<button type='button' class='bd-row ${B.sel===i?'on':''}' onclick='bSel(${i})'><span class='bd-dot' style='background:${T.c}'></span><span class='bd-rt'><b>${esc(c.name)}</b><small>${esc(T.n)} · ${esc(sub(c))}</small></span>${n?`<span class='sev HIGH' title='Security problems on this component'>${n}</span>`:''}</button>`};
  const LG=[['Environment',['namespace']],['App',['workload']],['Traffic',['service','ingress','certificate','networkpolicy']],['Identity & secrets',['serviceaccount','role','secret']],['Storage & config',['storage','configmap']],['Reliability',['pdb','hpa']]];
  const rows=LG.map(([g,ts])=>{ const ix=B.comps.map((c,i)=>i).filter(i=>ts.includes(B.comps[i].type)); return ix.length?`<div class='bd-gl'>${esc(g)}</div>`+ix.map(row).join(''):''; }).join('');
  const cat=BCAT.map(([g,items])=>`<div class='bd-pg'><span>${esc(g)}</span>${items.map(([l,t,x,h])=>`<button type='button' class='bd-chip' draggable='true' ondragstart='bDrag(event,"${t}")' onclick='bAdd("${t}",${esc(JSON.stringify(x))})' title='${esc(h)}'><i style='background:${BT[t].c}'></i>${esc(l)}</button>`).join('')}</div>`).join('');
  const open=B.palOpen===undefined?!B.comps.length:B.palOpen;
  el.innerHTML=`<div class='bd-lh'>Your design <small>${B.comps.length}</small></div>${rows||`<div class='bd-none'>Nothing yet. Start from a pattern, or add a component below.</div>`}<details class='bd-add' ${open?'open':''} ontoggle='B.palOpen=this.open'><summary>Add a component</summary><div class='bd-pal'>${cat}</div></details>`;
}
function bInsp(gallery){
  const el=$('#bd-insp'); if(!el) return;
  if(!B.comps.length||B.sel==null||!B.comps[B.sel]||gallery===true){ el.innerHTML=bGallery(); return; }
  const c=B.comps[B.sel], T=BT[c.type];
  el.innerHTML=`<datalist id='b-peers'>${bPeers().map(x=>`<option value='${esc(x)}'>`).join('')}</datalist>
   <div id='bd-secfor'>${bSecForHTML(c)}</div><div class='bd-ih'><span class='bd-dot' style='background:${T.c}'></span><div><b>${esc(T.n)}</b><small>${esc(T.s)}</small></div><button type='button' class='bd-btn' onclick='bRemove(${B.sel})'>Remove</button></div>${bFormFor(B.sel)}`;
}
/* Security for the component being edited, live, so nobody has to finish the design to learn what it needs. */
function bSecForHTML(c){
  if(!c) return '';
  const T=BT[c.type], LY=B.out&&B.out.layers, nm=esc(T.n.toLowerCase());
  if(!LY||!LY.layers.length) return `<div class='bd-sf'><b>Security for this ${nm}</b><small>Checking…</small></div>`;
  const okS=l=>['on','covered'].includes(l.status);
  const rel=LY.layers.map((l,i)=>[l,i]).filter(([l])=>(l.types||[]).includes(c.type));
  if(!rel.length) return `<div class='bd-sf ok'><b>Security for this ${nm}</b><small>Nothing is specific to this component. Design-wide protections are in the Security tab.</small></div>`;
  const bad=rel.filter(([l])=>!okS(l)&&!l.optional);
  const row=([l,i])=>{ const ok=okS(l);
    return `<div class='bd-sfr ${ok?'ok':l.optional?'opt':'bad'}'><span>${ok?'&#10003;':l.optional?'&#9675;':'&#10007;'}</span><div><b>${esc(l.title)}${l.optional&&!ok?' <small>(optional)</small>':''}</b><small>${esc(ok?l.why:(l.detail||l.why))}</small></div>${ok?'':l.add?`<button type='button' class='bd-btn' onclick='bAddLayer(${i})'>Add</button>`:`<button type='button' class='bd-btn' onclick='bOpenLayer(${i})'>Why</button>`}</div>`; };
  const order=[...rel.filter(([l])=>!okS(l)&&!l.optional),...rel.filter(([l])=>!okS(l)&&l.optional),...rel.filter(([l])=>okS(l))];
  return `<div class='bd-sf ${bad.length?'bad':'ok'}'><div class='bd-sfh'><b>Security for this ${nm}</b><span class='cv-st ${bad.length?'bad':'ok'}'>${bad.length?bad.length+' to do':'all in place'}</span></div>${order.filter(([l])=>!l.optional&&!okS(l)).map(row).join('')}${rel.some(([l])=>okS(l))?`<details class='bd-nice'><summary>In place (${rel.filter(([l])=>okS(l)).length})</summary>${rel.filter(([l])=>okS(l)).map(row).join('')}</details>`:''}${rel.some(([l])=>l.optional&&!okS(l))?`<details class='bd-nice'><summary>Nice to have (${rel.filter(([l])=>l.optional&&!okS(l)).length})</summary>${rel.filter(([l])=>l.optional&&!okS(l)).map(row).join('')}</details>`:''}</div>`;
}
function bSecFor(){ const e=$('#bd-secfor'); if(e&&B.sel!=null&&B.comps[B.sel]) e.innerHTML=bSecForHTML(B.comps[B.sel]); }
function bGallery(){
  const mine=(B.designs||[]);
  return `<div class='bd-gh'><h2>${B.comps.length?'Switch pattern':'What are you deploying?'}</h2><p>Pick the closest match. Every pattern starts locked down: non-root, read-only, no extra powers, all traffic blocked except what it needs, and a cluster guardrail. You then change a few fields.</p></div>
   <div class='bd-gal'>${BPATTERNS.map(p=>`<button type='button' class='bd-pat ${B.pattern===p.id?'on':''}' onclick='bPattern("${p.id}")'><b>${esc(p.n)}</b><small>${esc(p.who)}</small><span>${p.t.map(x=>`<i>${esc(x)}</i>`).join('')}</span></button>`).join('')}</div>
   ${mine.length?`<h3 class='bd-gs'>Your saved designs</h3><div class='bd-gal'>${mine.map(d=>`<button type='button' class='bd-pat' onclick='bDesignOpen("${esc(d.name)}")'><b>${esc(d.name)}</b><small>${d.components} components, saved ${esc((d.saved||'').slice(0,10))}</small></button>`).join('')}</div>`:''}`;
}
/* ---- right panel ---- */
function bPanel(){
  const el=$('#bd-panel'); if(!el) return;
  const tabs=[['security','Security'],['threats','Threats'],['files','Files'],['drift','Drift']];
  const head=`<div class='bd-tabs' role='tablist'>${tabs.map(([t,l])=>`<button type='button' role='tab' class='${B.tab===t?'on':''}' onclick='B.tab="${t}";bSave();bPanel()'>${l}</button>`).join('')}</div>`;
  let body=''; if(B.tab==='security') body=bSecurityHTML(); else if(B.tab==='threats') body=bThreatsHTML(); else if(B.tab==='files') body=bFilesHTML(); else body=bDriftHTML();
  el.innerHTML=head+body;
}
const bST={on:['ok','on'],off:['bad','missing'],loosened:['bad','loosened'],covered:['ok','covered'],blocked:['bad','blocked']};
function bSecurityHTML(){
  if(!B.comps.length) return `<div class='bd-none'>Choose a pattern and the protections show up here, with what is still missing.</div>`;
  const T=bTodo(), LY=T.LY;
  if(!B.out&&!B.err) return `<div class='bd-none'>Checking…</div>`;
  const todo=T.must.length?T.must.map(x=>bTodoCard(x)).join(''):`<div class='bd-good'>&#10003; Nothing left to fix. Every required protection is on.</div>`;
  const miss=T.must.filter(x=>x.k==='off'&&x.add);
  const nice=T.nice.length?`<details class='bd-sec'><summary>Nice to have (${T.nice.length})</summary><div>${T.nice.map(x=>bTodoCard(x)).join('')}</div></details>`:'';
  const groups=[...new Set(LY.layers.map(l=>l.group))];
  const all=`<details class='bd-sec' ${B.showAll?'open':''} ontoggle='B.showAll=this.open'><summary>All protections (${LY.layers.length})</summary><div>${groups.map(g=>`<div class='bd-lg'>${esc(g)}</div>`+LY.layers.map((l,i)=>[l,i]).filter(([l])=>l.group===g).map(([l,i])=>bLayerRow(l,i)).join('')).join('')}</div></details>`;
  const ex=LY.covered?`<button class='bd-btn' type='button' onclick='bExportRisks()'>Record ${LY.covered} exception(s) in Accepted risks</button><div id='b-exp' class='bd-note'></div>`:'';
  const scan=(B.out&&B.out.check)?`<details class='bd-sec'><summary>Scanner check: ${B.out.check.rating} (${B.out.check.issues.length} finding${B.out.check.issues.length===1?'':'s'})</summary><div>${B.out.check.issues.length?B.out.check.issues.map(x=>`<div class='bd-fi' onclick='bGoto("${esc(x.component)}")'><span class='sev ${x.severity}'>${x.severity}</span><b>${esc(x.title)}</b><small>${esc(x.where)}</small><p>${esc(x.fix||'')}</p></div>`).join(''):`<div class='bd-note'>The scanner's own rules found nothing.</div>`}</div></details>`:'';
  const thr=(LY.threats||[]).length?`<details class='bd-sec'><summary>Threat model: what each protection stops</summary><div>${LY.threats.map(t=>`<div class='bd-tm'><div class='bd-tmh'><b>${esc(t.tactic)}</b><span class='cv-st ${t.covered===t.total?'ok':'warn'}'>${t.covered}/${t.total}</span></div>${t.items.map(i=>`<div class='bd-tmi ${['on','covered'].includes(i.status)?'on':'off'}'><span>${['on','covered'].includes(i.status)?'&#10003;':'&#10007;'}</span><div><b>${esc(i.title)}</b><small>${esc(i.threat)}</small></div></div>`).join('')}</div>`).join('')}
    <div class='bd-tmh'><b>Not covered by this design</b></div><ul class='bd-resid'>${(LY.residual||[]).map(r=>`<li>${esc(r)}</li>`).join('')}</ul></div></details>`:'';
  const env=(B.out&&B.out.env)||B.env||{}; const envLine=env.scanned?`<div class='bd-env'>Your cluster (from the last scan): network plugin <b>${esc(env.cni||'not detected')}</b> &middot; service mesh <b>${esc(env.mesh||'none')}</b> &middot; cert-manager <b>${env.certmanager?'yes':'no'}</b></div>`:`<div class='bd-env'>Run a scan of your cluster so this page can see its network plugin, service mesh and cert-manager.</div>`;
  return `${envLine}<h3 class='bd-ph'>To do</h3>${miss.length>1?`<button class='btn' type='button' onclick='bAddMissing()'>Add ${miss.length} missing protections</button>`:''}${todo}${ex}${nice}${thr}${all}${scan}`;
}
const bTS={mitigated:['ok','mitigated'],partial:['warn','partly'],open:['bad','open'],residual:['info','accepted risk']};
function bThreatsHTML(){
  if(!B.comps.length) return `<div class='bd-none'>Choose a pattern and this shows what an attacker can try at every hop, and what stops them.</div>`;
  const tm=B.out&&B.out.threat_model; if(!tm) return B.err?`<div class='bd-none'>Finish the design to see its threat model.</div>`:`<div class='bd-none'>Checking…</div>`;
  const sm=tm.summary, by={}; tm.threats.forEach(t=>{ (by[t.where]=by[t.where]||[]).push(t); });
  const LYS=((B.out.layers||{}).layers)||[], lyIdx=id=>LYS.findIndex(l=>l.id===id);
  const PILL={mitigated:['ok','Protected'],partial:['warn','Partly'],open:['bad','Exposed'],residual:['info','Accepted']};
  const ORD=['open','partial','residual','mitigated'];
  const mentions=(w,name)=>String(w).split(/[^a-z0-9-]+/i).includes(name);
  const compOf=w=>B.comps.findIndex(c=>mentions(w,c.name));
  const gaps=ts=>ts.filter(t=>t.status==='partial'||t.status==='open').length;
  const fix=c=>{ const i=lyIdx(c.id); if(i<0) return ''; return LYS[i].add?`<button type='button' class='bd-btn' onclick='bAddLayer(${i})'>Add</button>`:`<button type='button' class='bd-btn' onclick='bOpenLayer(${i})'>Fix</button>`; };
  const row=t=>{ const [c,l]=PILL[t.status]||['info',t.status]; const miss=t.controls.filter(x=>x.status!=='ok'&&!(LYS[lyIdx(x.id)]||{}).optional);
    return `<div class='bd-th'><div><b>${esc(t.abuse)}</b><small>${esc(t.category)}${t.controls.length?' · stopped by '+t.controls.map(x=>`${x.status==='ok'?'&#10003;':(LYS[lyIdx(x.id)]||{}).optional?'&#9675;':'&#10007;'} ${esc(x.title)}`).join(', '):''}</small>${t.residual?`<small class='r'>${esc(t.residual)}</small>`:''}${miss.length?`<div class='bd-choices'>${miss.map(x=>`<span>${esc(x.title)} ${fix(x)}</span>`).join('')}</div>`:''}</div><span class='cv-st ${c}'>${l}</span></div>`; };
  const total=tm.threats.length, stopped=sm.mitigated;
  const head=`<div class='bd-env'><b>${stopped} of ${total}</b> threats are stopped${sm.partial+sm.open?` · <b>${sm.partial+sm.open} need you</b>`:''}${sm.residual?` · ${sm.residual} accepted (outside this design)`:''}${tm.verified?'':' · network flows not verified'}</div>`;
  const c=B.sel!=null?B.comps[B.sel]:null;
  const mine=c?Object.entries(by).filter(([w])=>mentions(w,c.name)):[];
  const sel=c?`<h3 class='bd-ph'>For ${esc(c.name)}</h3>${mine.length?mine.map(([w,ts])=>`<div class='bd-tmh'><b>${esc(w)}</b><span class='bd-cnt'>${ts.filter(t=>t.status==='mitigated').length}/${ts.length} stopped</span></div>${[...ts].sort((x,y)=>ORD.indexOf(x.status)-ORD.indexOf(y.status)).map(row).join('')}`).join(''):`<div class='bd-none'>No threats are modelled for this component on its own. See the design-wide list below.</div>`}`:'';
  const rank=Object.entries(by).map(([w,ts])=>[w,ts,gaps(ts)]).filter(x=>x[2]).sort((x,y)=>y[2]-x[2]);
  const first=`<h3 class='bd-ph'>Where to look first</h3>${rank.length?rank.slice(0,6).map(([w,ts,n])=>{ const i=compOf(w); return `<div class='bd-fl'><b>${esc(w)}</b><small>${n} of ${ts.length} need attention</small>${i>=0?`<button type='button' class='bd-btn' onclick='bSel(${i})'>Open</button>`:''}</div>`; }).join(''):`<div class='bd-good'>&#10003; Every modelled threat is stopped or accepted.</div>`}`;
  const paths=(B.out.attack_paths||[]).length?`<h3 class='bd-ph'>How an attacker could get in</h3>${B.out.attack_paths.map(p=>`<div class='bd-todo ${p.internet||['HIGH','CRITICAL'].includes(p.severity)?'bad':'info'}'><div><b>${esc(p.severity)}${p.internet?' · from the internet':''}</b><small>${esc(p.summary)}</small></div></div>`).join('')}`:`<div class='bd-good'>&#10003; Our own attack-path analysis finds no route to anything sensitive in this design.</div>`;
  const flows=tm.flows.map(f=>`<div class='bd-fl'><b>${esc(f.from)} &rarr; ${esc(f.to)}</b><small>${esc(f.label)}</small>${f.verified===true?"<span class='cv-st ok'>verified allowed</span>":f.verified===false?"<span class='cv-st bad'>blocked end to end</span>":''}</div>`).join('');
  const full=Object.entries(by).map(([w,ts])=>`<details class='bd-sec'><summary>${esc(w)} <span class='bd-cnt'>${ts.filter(t=>t.status==='mitigated').length}/${ts.length}</span></summary><div>${ts.map(t=>{ const [k,l]=PILL[t.status]||['info',t.status]; return `<div class='bd-th'><span class='bd-stride'>${esc(t.stride)}</span><div><b>${esc(t.category)}: ${esc(t.abuse)}</b></div><span class='cv-st ${k}'>${l}</span></div>`; }).join('')}</div></details>`).join('');
  return `${head}${sel}${first}${paths}<details class='bd-sec'><summary>Advanced: full threat model (trust boundaries, data flows, STRIDE)</summary><div>
    <h3 class='bd-ph'>Trust boundaries</h3><ul class='bd-resid'>${tm.boundaries.map(b=>`<li>${esc(b)}</li>`).join('')}</ul>
    <h3 class='bd-ph'>Data flows</h3>${flows||"<div class='bd-none'>No calls between parts yet.</div>"}
    <h3 class='bd-ph'>Threats at each element and flow</h3>${full}</div></details>`;
}
function bTodoCard(x){
  const act=x.add?`<button type='button' class='bd-btn' onclick='bAddLayer(${x.layer})'>Add</button>`:x.comp?`<button type='button' class='bd-btn' onclick='bGoto("${esc(x.comp)}")'>Go to it</button>`:(x.layer!=null?`<button type='button' class='bd-btn' onclick='bOpenLayer(${x.layer})'>Fix</button>`:'');
  const cls=['err','blocked','off','loose','scan','path'].includes(x.k)&&!(x.k==='path'&&!x.sev)?'bad':'info';
  const ch=(x.choices||[]).length?`<div class='bd-choices'>${x.choices.map((c,j)=>`<button type='button' class='${c.recommended?'btn':'bd-btn'}' onclick='bChoose(${x.layer},${j})'>${esc(c.label)}${c.recommended?' (recommended)':''}</button>`).join('')}</div>`:'';
  return `<div class='bd-todo ${cls}'><div><b>${esc(x.title)}</b><small>${esc(x.why||'')}</small>${ch}</div>${ch?'':act}</div>`;
}
function bLayerRow(l,i){
  const [cls,t]=bST[l.status]||['info',l.status], open=!!B.open[l.id];
  let det='';
  if(open){
    const comp=(l.compensating||[]).length?`<ul class='bd-comp'><li class='hd'>Must be in place to loosen this</li>${l.compensating.map(c=>`<li class='${c.status}'>${c.status==='on'?'&#10003;':'&#10007;'} ${esc(c.title)}${c.status!=='on'&&c.add?` <a href='javascript:bAddComp(${i},"${esc(c.id)}")'>Add</a>`:''}</li>`).join('')}</ul>`:'';
    const ap=['loosened','covered','blocked'].includes(l.status)?`<div class='bd-appr'><label>Approved by<input value='${esc(l.approval.by)}' placeholder='name' onchange='bApprove("${l.id}","by",this.value)'></label><label>Ticket<input value='${esc(l.approval.ticket)}' placeholder='SEC-123' onchange='bApprove("${l.id}","ticket",this.value)'></label><label>Expires<input type='date' value='${esc(l.approval.expires)}' onchange='bApprove("${l.id}","expires",this.value)'></label></div>`:'';
    det=`<div class='bd-ld'><p>${esc(l.why)}</p>${l.reason?`<p><b>Reason on record:</b> ${esc(l.reason)}</p>`:''}${l.detail?`<p class='d'>${esc(l.detail)}</p>`:''}${comp}${ap}<label class='bd-lock'><input type='checkbox' ${l.locked?'checked':''} onchange='bLock("${l.id}",this.checked)'> Lock in this design (loosening needs a named approver)</label>${l.add?`<button type='button' class='bd-btn' onclick='bAddLayer(${i})'>Add</button>`:''}</div>`;
  }
  return `<div class='bd-lr ${cls}'><button type='button' class='bd-lt' onclick='bOpenLayer(${i},true)' aria-expanded='${open}'><span class='cv-st ${cls}'>${t}</span><b>${esc(l.title)}${l.optional?' <small>(optional)</small>':''}</b><i>${open?'&#9662;':'&#9656;'}</i></button>${det}</div>`;
}
function bChoose(li,ci){ const l=((B.out||{}).layers||{layers:[]}).layers[li]; const c=l&&(l.choices||[])[ci]; if(!c) return; B.transport=Object.assign({},B.transport,c.set); if(c.set.mode==='none'){ bSettings(); } bRender(true); }
function bOpenLayer(i,toggle){ const l=((B.out||{}).layers||{layers:[]}).layers[i]; if(!l) return; B.open[l.id]=toggle?!B.open[l.id]:true; B.showAll=true; B.tab='security'; bPanel(); }
function bGoto(name){ const i=B.comps.findIndex(c=>c.name===name); if(i>=0) bSel(i); }
function bAddLayer(i){ const l=((B.out||{}).layers||{layers:[]}).layers[i]; if(!l||!l.add) return; const a=l.add; bAdd(a.type,a.type==='namespace'?Object.assign({},a,{name:B.ns}):a); }
function bAddComp(i,cid){ const l=((B.out||{}).layers||{layers:[]}).layers[i]; const c=l&&(l.compensating||[]).find(x=>x.id===cid); if(c&&c.add){ const a=c.add; bAdd(a.type,a.type==='namespace'?Object.assign({},a,{name:B.ns}):a); } }
function bLock(id,on){ B.locks=(B.locks||[]).filter(x=>x!==id); if(on) B.locks.push(id); bQueue(); bSave(); }
function bApprove(id,k,v){ B.approvals=B.approvals||{}; B.approvals[id]=Object.assign({},B.approvals[id]||{},{[k]:v}); bQueue(); bSave(); }
async function bExportRisks(){ const m=$('#b-exp'); try{ const r=await fetch('/api/build/exceptions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(bSpec())}); const d=await r.json(); const ex=d.exceptions||[];
  if(!ex.length){ m.textContent='Nothing to record: no loosened control is fully covered yet.'; return; } let ok=0; for(const e of ex){ const x=await fetch('/api/suppressions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(e)}); if(x.ok) ok++; }
  m.textContent=ok+' of '+ex.length+' exception(s) added to Accepted risks, each with an expiry so it comes back for review.'; }catch(e){ m.textContent='Could not record them.'; } }
function bFilesHTML(){
  if(!B.comps.length) return `<div class='bd-none'>Files appear once the design has something in it.</div>`;
  if(B.err) return `<div class='bd-todo bad'><div><b>Not complete yet</b><small>${esc(B.err)}</small></div>${B.errComp?`<button type='button' class='bd-btn' onclick='bGoto("${esc(B.errComp)}")'>Go to it</button>`:''}</div>`;
  if(!B.out||!B.out.yaml) return `<div class='bd-none'>Checking…</div>`;
  const sub=`<div class='bd-sub'>${[['yaml','Manifests (YAML)'],['helm','Helm chart']].map(([t,l])=>`<button type='button' class='${B.files===t?'on':''}' onclick='B.files="${t}";bSave();bPanel()'>${l}</button>`).join('')}</div>`;
  if(B.files==='yaml') return sub+`<div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc(B.out.yaml)}</pre></div>`;
  return sub+`<p class='bd-note'>A real Helm chart: <code>values.yaml</code> holds the knobs, <code>templates/</code> the objects. Nothing is applied for you.</p><button class='btn' type='button' onclick='bDownload()'>Download ${esc(B.app)}.tgz</button>
    <div class='cv-dh'>Then, from the folder you saved it in</div><div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>tar xzf ${esc(B.app)}.tgz\n${esc(B.out.install)}</pre></div>`;
}
let BDR=null;
async function bDriftRun(){ const o=$('#b-drift-out'); if(o) o.textContent='Comparing…'; try{ const r=await fetch('/api/build/drift',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign(bSpec(),{scan_id:D.scan&&D.scan.scan_id}))}); BDR=await r.json(); }catch(e){ BDR={error:'Could not reach the dashboard.'}; } bPanel(); }
function bDriftHTML(){
  const head=`<p class='bd-note'>Compares this design with the cluster as it was in the selected scan, so you can see where reality moved away from what you designed.</p><button class='btn' type='button' onclick='bDriftRun()' ${B.comps.length?'':'disabled'}>Compare with ${esc((D.scan&&D.scan.name)||'the selected scan')}</button><div id='b-drift-out' class='bd-note'></div>`;
  if(!BDR) return head; if(BDR.error) return head+`<div class='bd-todo bad'><div><small>${esc(BDR.error)}</small></div></div>`;
  const it=BDR.items||[]; return head+`<div class='${it.some(x=>x.severity==='bad')?'bd-todo bad':'bd-good'}'>${it.length?`${it.length} difference(s) from the design`:'The cluster matches the design.'}</div>`
   +it.map(x=>`<div class='bd-fi'><span class='sev ${x.severity==='bad'?'HIGH':x.severity==='warn'?'MEDIUM':'LOW'}'>${x.severity}</span><b>${esc(x.object)}: ${esc(x.aspect)}</b><small>design: ${esc(String(x.design))} &middot; cluster: ${esc(String(x.live))}</small></div>`).join(''); }
/* ---- saved designs ---- */
async function bDesignsCall(body){ try{ const r=await fetch('/api/build/designs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); const d=await r.json(); if(!r.ok){ B.err=d.error||'Could not do that.'; bPanel(); return null; } return d; }catch(e){ B.err='Could not reach the dashboard.'; bPanel(); return null; } }
async function bDesignsLoad(){ const d=await bDesignsCall({op:'list'}); if(d){ B.designs=d.designs||[]; bPaintDesigns(); if(!B.comps.length) bInsp(); } }
function bPaintDesigns(){ const el=$('#b-designs'); if(!el) return; el.innerHTML=`<label>Saved designs<select id='b-dsel'><option value=''>${B.designs.length?'Choose…':'None yet'}</option>${B.designs.map(d=>`<option value='${esc(d.name)}'>${esc(d.name)} (${d.components})</option>`).join('')}</select></label>
  <div class='bd-row2'><button type='button' class='bd-btn' onclick='bDesignOpen()'>Open</button><button type='button' class='bd-btn' onclick='bDesignSave()'>Save as…</button><button type='button' class='bd-btn' onclick='bDesignDel()'>Delete</button></div>`; }
async function bDesignSave(){ const n=prompt('Name this design (e.g. secure-api-baseline)',B.app); if(!n) return; const d=await bDesignsCall({op:'save',name:n,spec:bSpec()}); if(d){ B.designs=d.designs; B.err=''; bPaintDesigns(); } }
async function bDesignOpen(name){ const n=name||($('#b-dsel')||{}).value; if(!n) return; const d=await bDesignsCall({op:'load',name:n}); if(!d) return; const sp=d.spec;
  B.app=sp.app; B.ns=sp.namespace; B.registries=sp.registries||''; B.pullSecret=sp.pullSecret||''; B.signing=(sp.signing&&sp.signing.publicKey)||''; B.guardrails=sp.guardrails||'warn'; B.transport=Object.assign({mode:'',mesh:'linkerd',issuer:'internal-ca',reason:''},sp.transport||{}); B.locks=sp.locks||[]; B.approvals=sp.approvals||{}; B.comps=sp.components||[]; B.sel=B.comps.findIndex(c=>c.type==='workload'); B.pattern=''; B.err=''; drawerClose(); bRender(true); }
async function bDesignDel(){ const n=($('#b-dsel')||{}).value; if(!n||!confirm('Delete the design "'+n+'"?')) return; const d=await bDesignsCall({op:'delete',name:n}); if(d){ B.designs=d.designs; bPaintDesigns(); } }
function bRender(check){ bHead(); bList(); bInsp(); bPanel(); if(check) bQueue(); bSave(); }
function builderView(){
  setTimeout(()=>{ if(B.sel==null||!B.comps[B.sel]) B.sel=B.comps.findIndex(c=>c.type==='workload'); if(B.sel<0) B.sel=B.comps.length?0:null; bRender(true); bDesignsLoad(); },0);
  return `<div class='bd'>
   <div id='bd-head' class='panel bd-head'></div>
   <div class='bd-grid'>
    <aside id='bd-list' class='panel bd-list' ondragover='event.preventDefault();this.classList.add("over")' ondragleave='this.classList.remove("over")' ondrop='bDrop(event)' aria-label='Your design'></aside>
    <main id='bd-insp' class='panel bd-insp' aria-live='polite'></main>
    <aside id='bd-panel' class='panel bd-panel' aria-label='Security and files'></aside>
   </div></div>`;
}
/* ---- Policy review: the handful of cluster policies that decide how bad a breach gets -----------
   Each card says what the policy is, whether the cluster has it, why it matters in plain words, and
   shows the evidence. Computed in the browser from the scan's secret-free inventory. */
const polNS=()=>cvRows('namespaces').filter(n=>!n.system);
function polCards(){
  const ns=polNS(), pols=cvRows('policies'), wl=cvRows('workloads'), svc=cvRows('services'), ing=cvRows('ingresses'), bnd=cvRows('bindings');
  const denyIn=new Set(pols.filter(p=>/default-deny/.test(p.effect||'')).map(p=>p.namespace));
  const noDeny=ns.filter(n=>!denyIn.has(n.name)), noPol=ns.filter(n=>!n.policies);
  const lowPsa=ns.filter(n=>n.psa!=='restricted'), noPsa=ns.filter(n=>!n.psa);
  const wide=bnd.filter(b=>!b.builtin&&(b.grants||[]).length), admins=cvRows('identities').filter(i=>i.admin);
  const noLim=ns.filter(n=>!n.quota||!n.limits);
  const hot=wl.filter(w=>(w.flags||[]).some(f=>HOT_FLAGS.has(f)));
  const ext=svc.filter(s=>s.external), noTls=ing.filter(i=>!(i.tls||[]).length);
  const st=(bad,miss)=>miss?['bad','Missing']:bad?['warn','Needs attention']:['ok','In place'];
  return [
   {k:'net',t:'Network isolation',s:st(noDeny.length,ns.length&&noPol.length===ns.length),
    big:ns.length?`${ns.length-noDeny.length} of ${ns.length} namespaces block traffic by default`:'No application namespaces found',
    what:'A NetworkPolicy decides which pods may talk to which. "Default deny" blocks everything and you then allow only what is needed.',
    why:'Without it, anything that gets into one pod can reach every other pod, including databases. This is how one small bug becomes a full breach.',
    good:'Every application namespace has a default-deny rule plus a few explicit allows.',
    rows:ns.map(n=>[n.name,n.policies+' rule(s)',denyIn.has(n.name)?'default deny':'<span class="cv-st bad">open</span>',n.workloads+' workload(s)']),head:['Namespace','Network rules','Default','Running'],
    act:noDeny.length?[['Add a block-by-default rule',`polFix("networkpolicy","${esc(noDeny[0].name)}")`]]:[],link:['/graph?scan_id='+encodeURIComponent(D.scan.scan_id),'See who can reach whom']},
   {k:'psa',t:'Pod Security level',s:st(lowPsa.length,ns.length&&noPsa.length===ns.length),
    big:ns.length?`${ns.length-lowPsa.length} of ${ns.length} namespaces enforce "restricted"`:'No application namespaces found',
    what:'Pod Security Admission refuses to start pods that break basic safety rules (privileged, root, host access). "restricted" is the strong setting.',
    why:'It is the safety net: even if someone writes an unsafe manifest, the cluster says no. Without it, nothing stops a privileged pod.',
    good:'Every application namespace is labelled pod-security.kubernetes.io/enforce=restricted.',
    rows:ns.map(n=>[n.name,n.psa?chip(n.psa,n.psa!=='restricted'):'<span class="cv-st bad">not enforced</span>',n.pods+' pod(s)']),head:['Namespace','Enforced level','Pods'],
    act:lowPsa.length?[['Add a namespace with restricted level',`polFix("namespace","${esc(lowPsa[0].name)}")`]]:[]},
   {k:'rbac',t:'Who has powerful access',s:st(wide.length||admins.length,0),
    big:`${admins.length} service account(s) are cluster-admin, ${wide.length} custom binding(s) grant wide access`,
    what:'RBAC bindings say who may do what in the cluster. Some grants (read all secrets, create pods, act as anyone) are close to full control.',
    why:'A stolen token from a service account with wide access gives an attacker the same power. Fewer powerful identities means a smaller blast radius.',
    good:'Only a few named admins. Apps get a narrow Role in their own namespace.',
    rows:wide.slice(0,40).map(b=>[`<b>${esc(b.name)}</b><small>${esc(b.kind)}</small>`,esc((b.subjects||[]).join(', ')),(b.grants||[]).map(g=>chip(g,true)).join('')]),head:['Binding','Given to','Can'],
    act:[],note:'Fix by deleting or narrowing the binding. This tool never changes your cluster.'},
   {k:'lim',t:'Resource limits and quotas',s:st(noLim.length,ns.length&&noLim.length===ns.length),
    big:ns.length?`${ns.length-noLim.length} of ${ns.length} namespaces have both a quota and default limits`:'No application namespaces found',
    what:'A ResourceQuota caps what a namespace can use; a LimitRange gives every container a default limit.',
    why:'One runaway or hijacked app (a crypto-miner, a memory leak) can otherwise starve everything else on the node.',
    good:'Each namespace has a quota, and containers declare limits.',
    rows:ns.map(n=>[n.name,n.quota?'yes':'<span class="cv-st bad">none</span>',n.limits?'yes':'<span class="cv-st bad">none</span>']),head:['Namespace','Quota','Default limits'],
    act:noLim.length?[['Add a namespace with a quota',`polFix("namespace","${esc(noLim[0].name)}")`]]:[]},
   {k:'wl',t:'Dangerous pod settings',s:st(hot.length,0),big:`${hot.length} workload(s) run with privileged or host access`,
    what:'Privileged mode, sharing the host network or process list, or mounting host folders removes the wall between a container and the machine under it.',
    why:'A break-out from such a pod is a break-in to the node, and from there to everything on it.',good:'No workload needs these. If one truly does, it is documented and isolated.',
    rows:hot.slice(0,40).map(w=>[`<b>${esc(w.name)}</b><small>${esc(w.kind)} · ${esc(w.namespace||'-')}</small>`,(w.flags||[]).filter(f=>HOT_FLAGS.has(f)).map(f=>chip(f,true)).join(''),w.internet?chip('Internet-exposed',true):'']),head:['Workload','Settings','Exposure'],
    act:[],note:'Fix by removing the setting in the workload\'s spec (see the issue for the exact lines).'},
   {k:'exp',t:'What is open to the internet',s:st(ext.length||noTls.length,0),big:`${ext.length} public service(s), ${noTls.length} ingress(es) without HTTPS`,
    what:'Services of type LoadBalancer/NodePort and Ingresses are the front doors of the cluster.',why:'Everything an attacker can reach without logging in starts here. Each open door should be on purpose.',
    good:'Only the doors you meant to open, all with HTTPS and source limits.',
    rows:ext.map(s=>[`<b>${esc(s.name)}</b><small>${esc(s.namespace)}</small>`,esc(s.type),(s.ports||[]).map(esc).join(', ')]).concat(noTls.map(i=>[`<b>${esc(i.name)}</b><small>${esc(i.namespace)}</small>`,'Ingress',chip('no HTTPS',true)])),head:['Name','Type','Detail'],
    act:[],link:['/graph?scan_id='+encodeURIComponent(D.scan.scan_id),'See the attack paths from the internet']}];
}
function polFix(type,ns){ B.ns=ns; if(type==='networkpolicy'&&!B.comps.some(c=>c.type==='networkpolicy')) bAdd('networkpolicy'); else bAdd(type,type==='namespace'?{name:ns}:{}); location.hash='#build'; }
let polSel=null;
function polPick(k){ polSel=k; const v=$('#v-policies'); if(v) v.innerHTML=policiesView(); }
function policiesView(){
  const inv=cvInv(); if(!inv.sections) return `<div class='panel'><div class='fm'>This scan was saved before the cluster inventory existed. Run a new scan to review policies.</div></div>`;
  const cards=polCards(), bad=cards.filter(c=>c.s[0]!=='ok').length;
  if(!polSel||!cards.some(c=>c.k===polSel)) polSel=(cards.find(c=>c.s[0]!=='ok')||cards[0]).k;
  const cur=cards.find(c=>c.k===polSel);
  const short={net:'Network rules',psa:'Pod Security',rbac:'Admin access',lim:'Quotas & limits',wl:'Pod settings',exp:'Internet exposure'};
  const tiles=cards.map(c=>`<button type='button' class='po-tile ${c.s[0]} ${c.k===polSel?'on':''}' onclick='polPick("${c.k}")'>
    <span class='po-dot'></span><b>${short[c.k]||esc(c.t)}</b><span class='po-n'>${esc(c.big)}</span><small>${c.s[1]}</small></button>`).join('');
  const ns=polNS(), pols=cvRows('policies'), denyIn=new Set(pols.filter(p=>/default-deny/.test(p.effect||'')).map(p=>p.namespace));
  const cell=(ok,txt,k)=>`<td><button type='button' class='po-c ${ok?'ok':'bad'}' onclick='polPick("${k}")' title='${esc(txt)}'>${ok?'&#10003;':'&#10005;'}</button></td>`;
  const matrix=ns.length?`<table class='po-m'><thead><tr><th>Namespace</th><th><a href='javascript:polPick("net")'>Default deny</a></th><th><a href='javascript:polPick("psa")'>Pod Security</a></th><th><a href='javascript:polPick("lim")'>Quota</a></th><th><a href='javascript:polPick("lim")'>Limits</a></th></tr></thead><tbody>${ns.map(n=>`<tr><td><b>${esc(n.name)}</b><small>${n.workloads} workload(s)</small></td>${cell(denyIn.has(n.name),'Network default deny','net')}${cell(n.psa==='restricted',n.psa||'not enforced','psa')}${cell(n.quota,'ResourceQuota','lim')}${cell(n.limits,'LimitRange','lim')}</tr>`).join('')}</tbody></table>`
    :"<div class='cv-none'>No application namespaces.</div>";
  const rows=cur.rows.length?`<div class='cv-scroll'><table class='cv-t'><thead><tr>${cur.head.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${cur.rows.map(r=>`<tr>${r.map(x=>`<td>${typeof x==='string'&&x.includes('<')?x:esc(x)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`:"<div class='cv-none'>Nothing to show.</div>";
  return `<div class='po-head'><div><h2>Policy review</h2><p class='b-help'>Six settings decide how far an attacker gets after one mistake. ${bad?`<b>${bad} need attention.</b>`:'All are in place.'} Pick one to see the evidence.</p></div></div>
    <div class='po-tiles'>${tiles}</div>
    <div class='po-grid'>
      <div class='panel po-detail'>
        <div class='po-dh'><span class='cv-st ${cur.s[0]}'>${cur.s[1]}</span><h3>${esc(cur.t)}</h3></div>
        <p class='po-lead'>${esc(cur.why)}</p>
        <div class='po-act'>${(cur.act||[]).map(([l,js])=>`<button class='btn' type='button' onclick='${js}'>${l}</button>`).join('')}${cur.link?`<a href='${cur.link[0]}'>${cur.link[1]} &rarr;</a>`:''}${cur.note?`<span class='fm'>${esc(cur.note)}</span>`:''}</div>
        <details class='po-learn'><summary>What it is and what good looks like</summary><p><b>What it is.</b> ${esc(cur.what)}</p><p><b>Good looks like.</b> ${esc(cur.good)}</p></details>
        <div class='po-rows'><div class='po-rl'>${cur.rows.length} item(s)</div>${rows}</div>
      </div>
      <div class='panel po-side'><h3>Namespace coverage</h3><p class='b-help'>Green means the protection is in place. Click a column to see its detail.</p>${matrix}</div>
    </div>`;
}
/* ---- Start here: a guided path for someone new, with live status on every step ----------------- */
const GLOSS=[['Pod','The smallest running unit: one or more containers that run together.'],['Namespace','A named area of the cluster that separates one team or app from another.'],
 ['Service account','The identity a pod uses when it talks to the Kubernetes API.'],['RBAC','The rules that say which identity may do what in the cluster.'],
 ['NetworkPolicy','A rule about which pods may talk to which. No rule means everyone can talk to everyone.'],['Ingress / LoadBalancer','The ways traffic from the internet reaches your apps.'],
 ['CVE','A publicly known security hole in software inside a container image.'],['Helm chart','A packaged set of Kubernetes files you install with one command.']];
function startView(){
  const iss=(D.workload_issues||[]).slice().sort((a,b)=>(b.score||0)-(a.score||0)), urgent=iss.filter(i=>['CRITICAL','HIGH'].includes(i.severity));
  let pol=0; try{ pol=polCards().filter(c=>c.s[0]!=='ok').length; }catch(e){}
  const step=(n,done,t,body,acts)=>`<div class='st-step ${done?'done':''}'><span class='st-n'>${done?'✔':n}</span><div class='st-b'><h3>${t}</h3>${body}<div class='st-a'>${acts}</div></div></div>`;
  const btn=(l,js,p)=>`<button type='button' class='${p?'btn':'b-ghost'}' onclick='${js}'>${l}</button>`;
  const top=urgent.slice(0,3).map(i=>`<div class='st-iss'><span class='sev ${i.severity}'>${i.severity}</span><b>${esc(i.title)}</b><small>${esc(i.workload)}</small></div>`).join('');
  return `<div class='panel'><h2>Welcome. Start here</h2><p class='b-help'>This tool <b>only reads</b> your cluster. It cannot change, delete or deploy anything, so you cannot break production by clicking around. Follow the steps in order; each one shows where you are.</p></div>
   ${step(1,true,'Look at what you have',`<p class='b-help'>The latest scan is <b>${esc(D.scan.name||D.scan.scan_id)}</b>: ${iss.length} thing(s) to fix, risk ${D.scan.cluster_risk??''}/10.</p>`,btn('Run a new scan',"location.hash='#tasks'")+btn('Switch scan',"location.hash='#scans'"))}
   ${step(2,!urgent.length,'Fix what is urgent first',urgent.length?`<p class='b-help'><b>${urgent.length}</b> serious issue(s). Highest first, because they are the ones an attacker can use. Each issue explains why, how to fix it and how to check.</p>${top}`:`<p class='b-help'>No critical or high issues.</p>`,btn('Open the issue list',"location.hash='#issues'",1))}
   ${step(3,!pol,'Review the policies that limit damage',`<p class='b-help'>${pol?`<b>${pol}</b> of 6 safety policies need attention.`:'All 6 safety policies are in place.'} These decide how far an attacker can get after one mistake.`,btn('Review the policies',"location.hash='#policies'",1))}
   ${step(4,false,'Build new things the safe way',`<p class='b-help'>Do not write YAML from scratch. Drag components together, keep the safe defaults, and download a Helm chart that already passes the checks.`,btn('Open the builder',"location.hash='#build'",1))}
   ${step(5,false,'Keep it clean',`<p class='b-help'>Re-scan after a fix to confirm it worked. If a finding is a deliberate choice, <b>accept the risk</b> with a reason and an end date so it is reviewed again, not forgotten.`,btn('Accepted risks',"location.hash='#risks'")+btn('Tasks',"location.hash='#tasks'"))}
   <details class='panel'><summary><b>Plain-language glossary</b></summary><dl class='st-gl'>${GLOSS.map(([t,d])=>`<dt>${t}</dt><dd>${d}</dd>`).join('')}</dl></details>`;
}
/* ---- What changed: the first question in any incident ---------------------------------------- */
function changesView(){
  const c=D.changes||{}, items=c.items||[], po=D.posture||{};
  if(!c.since) return `<div class='panel'><h2>What changed</h2><p class='b-help'>This is the first scan of this cluster, so there is nothing to compare yet. Run another scan later and every added, removed or modified workload, service and permission shows up here.</p><button class='btn' type='button' onclick="location.hash='#tasks'">Run a scan</button></div>`;
  const risky=items.filter(i=>i.risky), rest=items.filter(i=>!i.risky);
  const row=i=>`<tr><td>${chip(i.kind,i.kind==='added'&&i.risky)}</td><td>${esc(i.summary)}</td><td><code>${esc(i.namespace||'cluster')}</code></td>
    <td>${i.section==='workloads'&&i.kind!=='removed'?`<a href='javascript:void 0' onclick='return incFromChange(${JSON.stringify(i.namespace)},${JSON.stringify(i.name)})'>Investigate &rarr;</a>`:''}</td></tr>`;
  const tbl=a=>a.length?`<table class='cv-t'><thead><tr><th></th><th>Change</th><th>Namespace</th><th></th></tr></thead><tbody>${a.map(row).join('')}</tbody></table>`:"<div class='cv-none'>Nothing.</div>";
  return `<div class='panel'><h2>What changed</h2><p class='b-help'>Compared with <b>${esc(c.since.name)}</b>. Start with anything marked as risky: those changes made the cluster easier to attack.</p>
    <div class='cv-chips'>${chip((po.new||[]).length+' new issue(s)',(po.new||[]).length>0)}${chip((po.resolved||[]).length+' fixed',false)}${chip(items.length+' object change(s)',false)}</div></div>
    <div class='panel'><h2>Made it easier to attack (${risky.length})</h2>${tbl(risky)}</div>
    <div class='panel'><h2>Other changes (${rest.length})</h2>${tbl(rest)}</div>`;
}
function incFromChange(ns,name){ const w=cvRows('workloads').find(x=>x.name===name&&(x.namespace||'')===(ns||'')); if(w) incOpen(w.id); return false; }
/* ---- Investigate: one workload, everything known about it, in the order you would check ------- */
let INC=null;
const INC_RES={Deployment:'deploy',StatefulSet:'sts',DaemonSet:'ds',CronJob:'cronjob',Job:'job'};
function incOpen(id){ INC=id; location.hash='#incident'; const v=$('#v-incident'); if(v) v.innerHTML=incidentView(); window.scrollTo(0,0); }
function incPick(){ const v=(($('#inc-q')||{}).value||'').trim(); const w=cvRows('workloads').find(x=>x.id===v||x.name===v); if(w) incOpen(w.id); }
function incSteps(w,issues,svcs){
  const ns=w.namespace||'default', res=(INC_RES[w.kind]||'deploy')+'/'+w.name, k=`kubectl -n ${ns}`;
  const exposed=w.internet, escal=issues.some(i=>(i.title||'').toLowerCase().includes('cluster-admin')||(i.rule_id||'').startsWith('rbac'))||(D.findings||[]).some(f=>f.resource&&f.resource.name&&f.resource.name.startsWith(w.name)&&(f.exploitable_by||[]).includes('rbac-escalation'));
  const s=[{t:'Keep the evidence first',why:'Restarting or deleting a pod destroys its logs and anything in memory. Save them before you change anything.',
     cmds:[`${k} logs ${res} --all-containers --tail=1000 > ${w.name}-logs.txt`,`${k} get ${res} -o yaml > ${w.name}.yaml`,`${k} get events --sort-by=.lastTimestamp > ${w.name}-events.txt`]}];
  if(exposed) s.push({t:'Close the front door',danger:1,why:'It can be reached from the internet. Switching its service to internal-only stops new outside traffic while you investigate.',
     cmds:svcs.length?svcs.map(x=>`${k} patch svc ${x.name} -p '{"spec":{"type":"ClusterIP"}}'`):[`# find the Service or Ingress that exposes it: ${k} get svc,ingress`]});
  s.push({t:'Cut its network',danger:1,why:'A default-deny rule stops it from talking to anything, so a compromised pod cannot move sideways. Save as deny-all.yaml, then apply.',
     cmds:[`apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: deny-all-${w.name}, namespace: ${ns}}\nspec:\n  podSelector: {matchLabels: {app.kubernetes.io/name: ${w.name}}}   # use your pod labels\n  policyTypes: [Ingress, Egress]`,`kubectl apply -f deny-all.yaml`]});
  if(escal) s.push({t:'Assume its identity is stolen',why:'Its service account can reach secrets or has wide rights, so a compromised pod means those credentials are exposed. Check what it can do, rotate what it could read, and remove the binding.',
     cmds:[`kubectl auth can-i --list --as=system:serviceaccount:${ns}:${w.sa||'default'} -n ${ns}`,`kubectl get clusterrolebindings,rolebindings -A -o wide | grep ${w.sa||'default'}`]});
  if(['Deployment','StatefulSet'].includes(w.kind)) s.push({t:'Stop it (after the steps above)',danger:1,why:'Scaling to zero stops the process but not the cause. Do it once the evidence is saved.',cmds:[`${k} scale ${res} --replicas=0`]});
  s.push({t:'Fix the cause, then prove it',why:'Fix the issues listed above, run a new scan and confirm they are gone.',cmds:[]});
  return s;
}
function incidentView(){
  const wls=cvRows('workloads'), w=INC?wls.find(x=>x.id===INC):null;
  const quick=wls.slice().sort((a,b)=>(b.issues.n-a.issues.n)||((b.internet?1:0)-(a.internet?1:0))).slice(0,6);
  const picker=`<div class='panel'><h2>Investigate a workload</h2><p class='b-help'>Pick what is misbehaving or looks suspicious. You get its status, recent events, changes, risks, how an attacker could reach it, and a step-by-step containment checklist. Nothing here changes your cluster; commands are for you to run.</p>
    <div class='tk-fields'><label>Workload<input id='inc-q' list='inc-l' placeholder='start typing a name' value='${esc(w?w.id:'')}' onchange='incPick()'></label><datalist id='inc-l'>${wls.map(x=>`<option value='${esc(x.id)}'>`).join('')}</datalist>
    <button class='btn' type='button' onclick='incPick()'>Investigate</button></div>
    ${w?'':`<div class='cv-dh'>Most worth a look</div><div class='tk-fields'>${quick.map(x=>`<button type='button' class='b-ghost' onclick='incOpen("${esc(x.id)}")'>${esc(x.name)} <small>${x.issues.n} issue(s)${x.internet?' · internet':''}</small></button>`).join('')}</div>`}</div>`;
  if(!w) return picker+(INC?`<div class='panel'><div class='cv-none'>${esc(INC)} is not a running workload in this scan.</div></div>`:'');
  const issues=(D.workload_issues||[]).filter(i=>i.workload_name===w.name&&(i.namespace||'')===(w.namespace||'')).sort((a,b)=>(b.score||0)-(a.score||0));
  const evs=cvRows('events').filter(e=>(e.namespace||'')===(w.namespace||'')&&String(e.object||'').split('/')[1]&&String(e.object).split('/')[1].startsWith(w.name)).slice(0,8);
  const chg=((D.changes||{}).items||[]).filter(c=>c.name===w.name&&(c.namespace||'')===(w.namespace||''));
  const paths=((D.attack_path||{}).resource_paths||[]).filter(p=>(p.steps||[]).some(s=>s.node===w.name||String(s.node).startsWith(w.name+'-'))).slice(0,3);
  const imgs=cvRows('images').filter(i=>(i.workloads||[]).includes(w.id));
  const rt=((D.runtime_correlation||{}).correlations||[]).filter(c=>JSON.stringify(c).includes(w.name));
  const svcs=cvRows('services').filter(s=>(s.backends||[]).some(b=>b.includes('/'+w.name)));
  const owner=(issues[0]||{}).owner||'';
  const sec=(t,b)=>`<div class='panel'><h2>${t}</h2>${b}</div>`;
  const steps=incSteps(w,issues,svcs).map((s,i)=>`<div class='st-step'><span class='st-n'>${i+1}</span><div class='st-b'><h3>${esc(s.t)}${s.danger?` <span class='cv-st warn'>changes the cluster, you run it</span>`:''}</h3><p class='b-help'>${esc(s.why)}</p>
    ${s.cmds.length?`<div class='cv-code'><button type='button' onclick='copyText(this.nextElementSibling.textContent);this.textContent="Copied"'>Copy</button><pre>${esc(s.cmds.join('\n'))}</pre></div>`:`<div class='st-a'><button class='btn' type='button' onclick='cvToIssues("${esc(w.name)}")'>See its issues</button><button class='b-ghost' type='button' onclick="location.hash='#tasks'">Re-scan</button></div>`}</div></div>`).join('');
  return picker+`<div class='panel'><div class='pol-h'><h2 style='margin:0'>${esc(w.name)}</h2><span class='fm'>${esc(w.kind)} · ${esc(w.namespace||'-')}${owner?' · owner '+esc(owner):''}</span>${w.internet?chip('Internet-exposed',true):''}${(w.flags||[]).filter(f=>HOT_FLAGS.has(f)).map(f=>chip(f,true)).join('')}</div>
    <div class='cv-chips'>${wlStatus(w)}</div></div>`
   +sec('Right now',`<dl class='cv-facts'><dt>Pods</dt><dd>${w.pods} (${Object.entries(w.phases||{}).map(([k,v])=>v+' '+k).join(', ')||'none'})</dd><dt>Restarts</dt><dd>${w.restarts}</dd><dt>Runs as</dt><dd><code>${esc(w.sa||'-')}</code></dd>
      <dt>Images</dt><dd>${(w.images||[]).map(i=>`<code>${esc(i)}</code>`).join('<br>')}${imgs.map(i=>' '+vulnChips(i)).join('')}</dd></dl>
      <div class='cv-dh'>Recent warnings</div>${evs.length?evs.map(e=>`<div class='cv-iss' style='border-left-color:var(--med)'><b>${esc(e.reason)}</b> x${e.count} <small>${esc(ago(e.last))} ago</small><div>${esc(e.message)}</div></div>`).join(''):"<div class='cv-none'>No warning events.</div>"}`)
   +sec(`What changed (${chg.length})`,chg.length?chg.map(c=>`<div class='cv-iss' style='border-left-color:var(--${c.risky?'crit':'info'})'>${esc(c.summary)}</div>`).join(''):`<div class='cv-none'>${(D.changes||{}).since?'Nothing changed on this workload since the last scan.':'No earlier scan to compare with.'}</div>`)
   +sec(`Why it is risky (${issues.length})`,issues.length?issues.slice(0,10).map(i=>`<div class='st-iss'><span class='sev ${i.severity}'>${i.severity}</span><b>${esc(i.title)}</b><small>score ${(i.score||0).toFixed(1)}</small></div>`).join('')+`<div class='st-a'><button class='b-ghost' type='button' onclick='cvToIssues("${esc(w.name)}")'>Open all in Issues</button></div>`:"<div class='cv-none'>No open issues.</div>")
   +(paths.length?sec('How an attacker could reach it',paths.map(p=>`<div class='cv-iss' style='border-left-color:var(--crit)'>${(p.steps||[]).map(s=>esc(s.node)).join(' &rarr; ')}<small>${p.internet_reachable?' · from the internet':''}</small></div>`).join('')+`<div class='cv-links'><a href='/graph?scan_id=${encodeURIComponent(D.scan.scan_id)}'>See it on the graph &rarr;</a></div>`):'')
   +(rt.length?sec('Runtime alerts',`<div class='cv-iss' style='border-left-color:var(--crit)'><b>${rt.length} runtime event(s)</b> matched this workload. Treat the findings above as actively exploited.</div>`):'')
   +`<div class='panel'><h2>Containment checklist</h2><p class='b-help'>In this order, because evidence disappears when things restart. Commands are shown for you to copy and run; this tool never runs them.</p></div>`+steps;
}
function selectorOptions(){
  const s=(D&&D.selectors)||{};
  // The option VALUE stays the raw term the resolver expects; only the label is
  // humanised, so a domain reads "Cloud IAM" rather than `cloud_iam` while the
  // selector the server receives is unchanged.
  const grp=(label,arr,type,fmt)=>(arr&&arr.length)?`<optgroup label='${esc(label)}'>`+
    arr.map(v=>`<option value='${esc(type)}:${esc(v)}'>${esc(fmt?fmt(v):v)}</option>`).join('')+'</optgroup>':'';
  return `<option value=''>All rules</option>`
    +grp('MITRE tactics',s.tactics,'tactic')
    +grp('Security domains',s.modules,'module',domainName)
    +grp('Compliance frameworks',s.frameworks,'framework')
    +grp('Techniques',s.aliases,'alias');
}
function scanForm(){
  return `<div class='scanform'>
    <div><label>Scan name (optional)</label><input id='scanname' placeholder='e.g. Production nightly'></div>
    <div><label>Scope</label><select id='scope' onchange='toggleScope()'><option value='cluster'>Entire cluster</option><option value='namespace'>Single namespace</option></select></div>
    <div><label>Namespace</label><input id='ns' placeholder='Select namespace scope first' disabled></div>
    <div><label>Filter (optional)</label><select id='sel'>${selectorOptions()}</select></div>
    <div><label>Target</label><select id='mock' onchange='toggleLive()'><option value='0'>Live cluster</option><option value='1'>Sample cluster (offline fixture)</option></select></div>
    <div><label>Image CVEs (Grype)</label><select id='grype'><option value='0'>Off</option><option value='1'>Scan running images (slow on first run)</option></select></div>
    <div><label>Context</label><input id='ctx' placeholder='e.g. current-context'></div>
    ${kubeconfigField()}
    <button class='btn' id='run' onclick='runScan()'>Run scan</button></div><div id='scanmsg' role='status' aria-live='polite'></div>`;
}
/* The server refuses a request-body kubeconfig unless it is bound to loopback (loading one
   executes its credential plugin as the server's user). Don't offer a control that would
   always be rejected, explain instead. */
function kubeconfigField(){
  if(D && D.allow_client_kubeconfig===false){
    return `<div class='kc'><label>Kubeconfig</label>
      <div class='fm'>Not accepted, this server is not bound to localhost, and loading a
      kubeconfig would run its credential plugin here. Scan from the CLI on the server
      (<code>k8smatrixwarden scan --live</code>), or restart with
      <code>--allow-remote-kubeconfig</code> behind your own authentication.</div></div>`;
  }
  return `<div class='kc'><label>Kubeconfig (optional, live only)</label>
      <input id='kubeconfig' placeholder='type a path, e.g. C:\\Users\\me\\.kube\\config' oninput='onKubeconfigPath()'>
      <div class='kc-or'>or select a file from your system</div>
      <input type='file' id='kubeconfigfile' onchange='pickKubeconfig(this)'>
      <span id='kubeconfigfilename' class='fm'></span></div>`;
}
/* A browser can't reveal a picked file's real path, so read its contents and send them by
   value; the server writes a short-lived temp kubeconfig. Path box and file picker are
   mutually exclusive, the most recently used one wins. */
let KUBECONFIG_CONTENT=null;
function pickKubeconfig(input){
  const f=input.files&&input.files[0];
  const lbl=$('#kubeconfigfilename');
  if(!f){KUBECONFIG_CONTENT=null;if(lbl)lbl.textContent='';return;}
  const reader=new FileReader();
  reader.onload=e=>{KUBECONFIG_CONTENT=e.target.result;
    if(lbl)lbl.textContent='Selected: '+f.name+' ('+e.target.result.length+' bytes)';
    const path=$('#kubeconfig');if(path)path.value='';};   // file wins over a typed path
  reader.onerror=()=>{if(lbl)lbl.textContent='Could not read the selected file.';};
  reader.readAsText(f);
}
function onKubeconfigPath(){   // typing a path clears any picked file
  if($('#kubeconfig').value.trim()){
    KUBECONFIG_CONTENT=null;
    const fi=$('#kubeconfigfile');if(fi)fi.value='';
    const lbl=$('#kubeconfigfilename');if(lbl)lbl.textContent='';}
}
/* Context + kubeconfig only apply to a live (--live) scan; disable them for the mock cluster. */
function toggleLive(){const m=$('#mock');if(!m)return;const mock=m.value==='1';['#ctx','#kubeconfig','#kubeconfigfile'].forEach(id=>{const el=$(id);if(el)el.disabled=mock;});}
/* Namespace only applies when the Scope is "namespace"; disable it otherwise. */
function toggleScope(){const ns=$('#ns');if(ns)ns.disabled=($('#scope')?$('#scope').value:'cluster')!=='namespace';}
function wireScan(){toggleLive();toggleScope();}
async function runScan(){
  const btn=$('#run'),msg=$('#scanmsg');btn.disabled=true;msg.textContent='Scan in progress…';
  const mock=$('#mock').value==='1';
  const scope=$('#scope').value;
  const body={scan_name:$('#scanname').value||null,scope_level:scope,
    namespace:(scope==='namespace'?($('#ns').value||null):null),mock:mock};
  // The selector dropdown carries "<axis>:<value>" (e.g. "tactic:Persistence",
  // "module:rbac_identity"); split it into the structured selector field the API expects.
  const selVal=($('#sel')&&$('#sel').value)||'';
  if(selVal){
    const i=selVal.indexOf(':'), axis=selVal.slice(0,i), val=selVal.slice(i+1);
    const field={tactic:'tactics',module:'modules',framework:'frameworks',alias:'aliases'}[axis];
    if(field) body[field]=[val];
  }
  if(!mock){
    body.context=$('#ctx').value||null;
    body.grype=(($('#grype')||{}).value==='1');
    // the kubeconfig inputs are absent when the server won't accept one, see kubeconfigField()
    const kcPath=($('#kubeconfig')||{}).value||'';
    if(KUBECONFIG_CONTENT){body.kubeconfig_content=KUBECONFIG_CONTENT;}
    else if(kcPath.trim()){body.kubeconfig=kcPath.trim();}
  }
  try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok||d.error){
      // A live-scan failure (unreachable cluster, credential plugin that cannot get a
      // token) is multi-line and actionable, show it verbatim rather than truncating it
      // into a single unhelpful line.
      msg.innerHTML=`<div class='scanerr'><b>Scan failed</b><pre>${esc(d.error||('HTTP '+r.status))}</pre></div>`;
      btn.disabled=false;return;}
    const warn=(d.warnings&&d.warnings.length)
      ? `<div class='scanwarn'><b>${d.evidence_ok===false?'Scan incomplete: cluster not read'
          :'Partial coverage'}</b><ul>${d.warnings.slice(0,10).map(w=>`<li>${esc(w)}</li>`).join('')}</ul></div>`
      : '';
    msg.innerHTML='Scan complete · '+esc(d.rating)+' · risk '+d.risk+'/10 · '+d.total_findings+' findings. Reloading…'+warn;
    setTimeout(()=>location.reload(),warn?2600:800);
  }catch(e){msg.textContent='Scan request failed: '+e;btn.disabled=false;}
}
/* ---- toast ---- */
let _toastTimer=null;
function showToast(msg, ms, err){
  let t=$('#toast'); if(!t){ t=document.createElement('div'); t.id='toast'; t.setAttribute('role','status');
    t.setAttribute('aria-live','polite'); document.body.appendChild(t); }
  t.textContent=msg; t.className='toast show'+(err?' err':'');
  if(_toastTimer) clearTimeout(_toastTimer);
  if(ms) _toastTimer=setTimeout(()=>{ t.className='toast'; }, ms);
}
/* ---- keyboard operability ------------------------------------------------
   The dashboard drives a lot of interaction from onclick on non-native elements:
   severity chips, sortable headers, matrix cells, findings rows, kill-chain steps.
   Those are invisible to the keyboard and to assistive tech: no tab stop, no role,
   no way to activate them. Rather than hand-edit every render site (and miss the next
   one), this pass runs after each render and promotes anything clickable into a real
   control. Enter and Space activate, matching native button behaviour. */
const A11Y_ROLE={'cell':'button','step':'button','chip':'button'};
function enhanceA11y(root){
  (root||document).querySelectorAll('[onclick]').forEach(el=>{
    if(['BUTTON','A','INPUT','SELECT','TEXTAREA'].includes(el.tagName)) return;
    if(el.dataset.kb) return;                       // already promoted
    el.dataset.kb='1';
    if(el.tabIndex<0) el.tabIndex=0;
    const cls=(el.className||'').split(' ')[0];
    // A <tr> must keep its row semantics; overriding it with role=button would break
    // the table for a screen reader. It stays a row and simply becomes reachable.
    if(el.tagName!=='TR'&&el.tagName!=='TH'&&!el.getAttribute('role')&&A11Y_ROLE[cls])
      el.setAttribute('role',A11Y_ROLE[cls]);
    if(!el.hasAttribute('aria-label')&&!el.textContent.trim()&&el.title)
      el.setAttribute('aria-label',el.title);
  });
}
document.addEventListener('keydown',e=>{
  if(e.key!=='Enter'&&e.key!==' ') return;
  const el=e.target;
  if(!el||!el.dataset||!el.dataset.kb) return;
  if(['BUTTON','A','INPUT','SELECT','TEXTAREA'].includes(el.tagName)) return;
  e.preventDefault(); el.click();
});
const res=f=>{const r=f.resource||{};return r.kind+'/'+r.name+(r.namespace?' ('+r.namespace+')':'')};
// Humanise a domain/shard identifier for display only (workload_pod_security -> Workload
// Pod Security). Filtering/sorting still use the raw owning_shard value.
// Title-casing alone produced "Cloud Iam" and "Rbac Identity". Acronyms are restored
// after the pass, so a domain reads the way an operator writes it.
const DOMAIN_ACRONYM={Iam:'IAM',Rbac:'RBAC',Cis:'CIS',Api:'API'};
const domainName=s=>String(s||'').replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())
  .replace(/\b(Iam|Rbac|Cis|Api)\b/g,w=>DOMAIN_ACRONYM[w]);
async function loadReport(id){
  const r = await fetch('/api/dashboard?scan_id='+encodeURIComponent(id));
  D = await r.json();
  if(!D.has_scan){ $('#app').innerHTML = emptyView(); wireScan(); tkLoad(); return; }
  render();
}
async function boot(){
  document.addEventListener('keydown',e=>{if(e.key==='Escape') drawerClose();});
  const r = await fetch('/api/dashboard'); D = await r.json();
  if(!D.has_scan){ $('#app').innerHTML = emptyView(); wireScan(); tkLoad(); return; }
  render();
}
boot();
</script>
"""
