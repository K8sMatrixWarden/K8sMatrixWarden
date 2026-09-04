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
from ..core.threat_matrix import ThreatMatrix
from ..core.threat_matrix_render import render_html_grid

_DASH_CSS = """
.topbar{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;border-bottom:1px solid var(--bd);
 padding:.2rem 0 1.1rem;margin-bottom:1.6rem}
.topbar h1{font-size:1.18rem;font-weight:750;margin:0;color:var(--fg);display:flex;align-items:center;gap:.6rem;
 letter-spacing:-.021em}
.topbar h1 .mark{width:1.65rem;height:1.65rem;border-radius:7px;flex:0 0 auto;
 background:linear-gradient(150deg,var(--accent),#155e75);
 display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:.78rem;font-weight:800;letter-spacing:-.04em;font-family:var(--mono)}
.topbar h1 .kw{color:var(--muted);font-weight:600}
.topbar .grow{flex:1}
.topbar a.nav{font-size:.855rem;color:var(--muted);text-decoration:none;padding:.44rem .8rem;
 border:1px solid transparent;border-radius:9px;font-weight:550;transition:color .15s,background .15s}
.topbar a.nav:hover{color:var(--fg);background:var(--sunken)}
.topbar a.nav.on,.topbar a.nav[style]{color:var(--accent);background:var(--sunken)}
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
 --ease-spring:cubic-bezier(0.34,1.2,0.64,1);--ease-out:cubic-bezier(0.16,1,0.3,1)}
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
.findlink .fl-t{font-weight:600;font-size:.85rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.findlink .fl-r{color:var(--muted);font-size:.78rem;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.findlink .fl-s{font-weight:650;font-size:.75rem;color:var(--muted);flex:0 0 auto;font-variant-numeric:tabular-nums}
.findlink .fl-go{color:var(--accent);font-size:1rem;flex:0 0 auto}
/* KPI stat tiles, flat instrument readouts. A thin top rule carries the status colour;
   the lead tile (risk) is deliberately dominant to break the four-equal-tiles symmetry. */
.kpis{display:grid;grid-template-columns:1.5fr 1fr 1fr 1fr;gap:.9rem;margin:1.2rem 0}
@media(max-width:820px){.kpis{grid-template-columns:1fr 1fr}}
@media(max-width:520px){.kpis{grid-template-columns:1fr}}
.kpi{position:relative;background:var(--card);border:1px solid var(--bd);border-radius:10px;
 padding:1.05rem 1.15rem;overflow:hidden}
.kpi::before{content:'';position:absolute;left:0;right:0;top:0;height:2px;background:var(--bd)}
.kpi .n{font-size:1.85rem;font-weight:750;line-height:1;letter-spacing:-.03em;
 font-variant-numeric:tabular-nums;font-feature-settings:'tnum'}
.kpi .l{color:var(--muted);font-size:.66rem;margin-top:.6rem;font-weight:600;text-transform:uppercase;
 letter-spacing:.09em;font-family:var(--mono)}
.kpi .s{font-size:.74rem;margin-top:.4rem;color:var(--muted)}
.kpi.lead{grid-row:span 1;display:flex;flex-direction:column;justify-content:center;padding:1.15rem 1.3rem}
.kpi.lead .n{font-size:2.9rem}
.kpi.crit .n{color:var(--crit)}.kpi.crit::before{background:var(--crit)}
.kpi.warn .n{color:var(--high)}.kpi.warn::before{background:var(--high)}
.kpi.good .n{color:var(--low)}.kpi.good::before{background:var(--low)}
.kpi.unk .n{color:var(--info)}.kpi.unk::before{background:var(--info)}
.up{color:var(--crit);font-weight:650}.down{color:var(--low);font-weight:650}
/* severity distribution, the signature readout under the KPIs */
.sevbar{display:flex;height:8px;border-radius:5px;overflow:hidden;margin:.2rem 0 .5rem;border:1px solid var(--bd);background:var(--sunken)}
.sevbar span{display:block;height:100%}
.sevbar .s-CRITICAL{background:var(--crit)}.sevbar .s-HIGH{background:var(--high)}
.sevbar .s-MEDIUM{background:var(--med)}.sevbar .s-LOW{background:var(--low)}.sevbar .s-INFO{background:var(--info)}
.sevleg{display:flex;flex-wrap:wrap;gap:1.1rem;font-size:.72rem;color:var(--muted);font-family:var(--mono);letter-spacing:.02em}
.sevleg b{color:var(--fg);font-weight:700}
.sevleg i{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:.4rem;vertical-align:0}
.sevleg .s-CRITICAL{background:var(--crit)}.sevleg .s-HIGH{background:var(--high)}
.sevleg .s-MEDIUM{background:var(--med)}.sevleg .s-LOW{background:var(--low)}.sevleg .s-INFO{background:var(--info)}
/* pod exposure buckets (reachability) reuse the sevbar idiom, worst-wins colours */
.sevbar .x-internet_admin,.sevleg .x-internet_admin{background:var(--crit)}
.sevbar .x-internet,.sevleg .x-internet{background:var(--high)}
.sevbar .x-admin,.sevleg .x-admin{background:var(--med)}
.sevbar .x-internal,.sevleg .x-internal{background:var(--low)}
.sysline{font-family:var(--mono);font-size:.735rem;color:var(--muted);margin:.1rem 0 .6rem;
 display:flex;align-items:center;flex-wrap:wrap;gap:.55rem;letter-spacing:.01em}
.sysline .dot{width:3px;height:3px;border-radius:50%;background:var(--bd);display:inline-block;flex:0 0 auto}
.kpi .n .max{font-size:.85rem;font-weight:550;color:var(--muted);margin-left:.12rem;letter-spacing:0;font-family:var(--mono)}
.kpi.lead .n .max{font-size:1.1rem}
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
@media (prefers-reduced-motion:reduce){*{animation-duration:.001ms!important;transition-duration:.001ms!important}}
@media(max-width:640px){.wrap{padding:1rem .8rem}.kpi .n{font-size:1.9rem}.tabs{width:100%}}
"""


def layout(title: str, body: str, *, extra_css: str = "") -> str:
    # THEME_JS runs last so it can label any .themebtn the body rendered.
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_esc(title)}</title><style>{_HTML_CSS}{_DASH_CSS}{extra_css}</style></head>"
            f"<body><div class='wrap'>{body}</div>"
            f"<script>{THEME_JS}</script></body></html>")


def _topbar(active: str = "") -> str:
    def nav(href, label, key):
        star = " style='border-color:var(--accent)'" if key == active else ""
        return f"<a class='nav' href='{href}'{star}>{label}</a>"
    return ("<div class='topbar'>"
            "<h1><span class='mark'>K8</span>K8sMatrixWarden</h1><span class='grow'></span>"
            + nav("/", "Dashboard", "home")
            + nav("/runtime", "Runtime", "runtime")
            + nav("/matrix", "Coverage", "matrix")
            + nav("/compliance", "Compliance", "compliance")
            + nav("/federation", "Federation", "federation")
            + nav("/api/reports", "API", "api")
            + THEME_BUTTON
            + "</div>")


def dashboard_page(has_scan: bool = False) -> str:
    """Client-side dashboard shell. All data comes from GET /api/dashboard."""
    shell = (_topbar("home")
             + "<div id='app'><div class='empty'>Loading…</div></div>")
    # Vendored (no CDN), loaded before _APP_JS so `cytoscape` exists when boot() runs.
    cyto = "<script src='/vendor/cytoscape.min.js'></script>"
    return layout("K8sMatrixWarden · Dashboard", shell + cyto + _APP_JS, extra_css=_APP_CSS)


def matrix_page(tm: ThreatMatrix, *, result: ScanResult = None,
                title_note: str = "") -> str:
    # No scan overlaid => the standalone coverage page. Render coverage stats rather than
    # hit stats, which would all be a structural (and misleading) zero there.
    coverage_only = result is None
    crumb = ("<div class='crumbs'><a href='/'>Dashboard</a> › "
             + (f"<a href='/report/{_esc(tm.scan_id)}'>{_esc(tm.scan_id)}</a> › matrix"
                if not coverage_only else "coverage matrix") + "</div>")
    title = ("Detection Coverage" if coverage_only else "Kubernetes Threat Matrix")
    head = (f"<h1 style='font-size:1.3rem;margin:.2rem 0'>{title}</h1>"
            f"<div class='sub'>{_esc(title_note or ('scan ' + tm.scan_id))} · "
            + ("" if coverage_only else f"scope <code>{_esc(tm.scope)}</code> · ")
            + f"<a href='{tm.summary()['reference']}' target='_blank' rel='noopener'>"
            f"Redguard Kubernetes Threat Matrix ↗</a></div>"
            + ("<div class='fm' style='margin:.5rem 0 1rem'>What the scanner can detect "
               "across every rule. Open a scan's matrix to see a cluster's actual "
               "exposure.</div>" if coverage_only else ""))
    return layout("K8sMatrixWarden · Threat Matrix",
                  _topbar("matrix") + crumb + head
                  + render_html_grid(tm, coverage_only=coverage_only))


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
  return "<span class='tag muted' title='This report predates the provenance model'>unknown</span>";
}
function srcPill(r){
  const s = r.source;
  const help = {falco:'syscall stream', audit:'Kubernetes API audit stream',
                drift:'declared-vs-observed comparison'}[s] || 'unrecorded';
  return `<span class='tag muted' title='${esc(help)}'>${esc(s)}</span>`;
}
function corrPill(c){
  const cls = {confirmed:'critical','runtime-only':'medium',corroborated:'high',
               drift:'critical'}[c] || 'info';
  return `<span class='tag ${cls}'>${esc(c)}</span>`;
}
function identPill(r){
  if (r.identity_status === 'complete') return '';
  const miss = (r.identity_missing || []).join(', ');
  return `<span class='tag medium' title='${esc(r.identity_reason || '')}'>identity: ${esc(r.identity_status)}${miss ? ' (' + esc(miss) + ')' : ''}</span>`;
}
function freshPill(r){
  if (r.freshness === 'recent') return '';
  const age = (r.age_days || r.age_days === 0) ? ` ${Math.round(r.age_days)}d` : '';
  return `<span class='tag medium' title='Observed, but not recently. Not evidence of current activity.'>${esc(r.freshness)}${age}</span>`;
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
  const kv = o => Object.entries(o || {}).map(([k, v]) => `${esc(k)} ${v}`).join(' · ') || '—';
  const head = `<div class='kpis'>
      <div class='kpi'><div class='n'>${d.matched}</div><div class='l'>Matching events</div></div>
      <div class='kpi'><div class='n'>${d.total}</div><div class='l'>Stored on this scan</div></div>
      <div class='kpi'><div class='n'>${(s.by_detector||{}).kmw || 0}</div><div class='l'>Curated (KMW)</div></div>
      <div class='kpi'><div class='n'>${(s.by_detector||{}).falco || 0}</div><div class='l'>Falco fallback</div></div>
    </div>
    <div class='fm' style='margin:.5rem 0'>by correlation: ${kv(s.by_correlation)} · by identity: ${kv(s.by_identity)}</div>`;

  if (!ROWS.length){
    q.innerHTML = warn + head + "<div class='empty'>No runtime events match. This does not mean nothing happened &mdash; widen the filters, or pull a fresh feed from the Runtime tab on the dashboard.</div>";
    return;
  }
  const rows = ROWS.map((r, i) => `
    <tr class='ev' data-i='${i}'>
      <td><code>${esc((r.timestamp || '').replace('T', ' ').slice(0, 19) || 'unknown')}</code></td>
      <td>${detPill(r)} ${srcPill(r)}</td>
      <td><code>${esc(r.rule)}</code>${r.supporting_evidence ? `<div class='fm'>+ ${esc(r.supporting_evidence)}</div>` : ''}</td>
      <td><span class='sev ${esc(r.severity)}'>${esc(r.severity)}</span></td>
      <td>${esc(r.tactic)}${r.technique_id ? `<div class='fm'>${esc(r.technique_id)}</div>` : ''}</td>
      <td>${esc(r.namespace || '—')}</td>
      <td>${esc(r.workload || r.pod || '—')}${identPill(r)}</td>
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
  document.getElementById('rt-q').innerHTML = "<div class='empty'>Loading…</div>";
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
table.rt{width:100%;border-collapse:collapse;font-size:.83rem}
table.rt th{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);
  color:var(--muted);font-weight:600;white-space:nowrap}
table.rt td{padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
table.rt tr.ev{cursor:pointer}
table.rt tr.ev:hover{background:var(--sunken)}
.detbox{background:var(--sunken);padding:.7rem .9rem;border-radius:6px;margin:.2rem 0 .6rem}
table.kv{border-collapse:collapse;font-size:.8rem}
table.kv td{padding:.15rem .6rem .15rem 0;vertical-align:top}
table.kv td.k{color:var(--muted);white-space:nowrap}
.rtbar{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.6rem 0 1rem}
.rtbar input,.rtbar select{background:var(--sunken);color:var(--fg);border:1px solid var(--line);
  border-radius:6px;padding:.35rem .5rem;font-size:.82rem;font-family:inherit}
.warn{background:var(--sunken);border-left:3px solid var(--medium);padding:.5rem .7rem;
  border-radius:4px;margin-bottom:.7rem;font-size:.82rem}
.tag.muted{background:var(--sunken);color:var(--muted)}
"""


def runtime_page() -> str:
    """Read-only Runtime Events page. All data comes from GET /api/runtime."""
    controls = (
        "<div class='rtbar'>"
        "<label class='fm'>Source "
        "<select id='f-source' class='f'>"
        "<option value='all'>all</option><option value='kmw'>KMW curated</option>"
        "<option value='falco'>Falco fallback</option><option value='audit'>K8s audit</option>"
        "<option value='drift'>drift</option></select></label>"
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
    crumb = "<div class='crumbs'><a href='/'>Dashboard</a> › runtime events</div>"
    body = (_topbar("runtime") + crumb + head + controls
            + "<div id='rt-q'><div class='empty'>Loading…</div></div>" + _RUNTIME_JS)
    return layout("K8sMatrixWarden · Runtime Events", body,
                  extra_css=_APP_CSS + _RUNTIME_CSS)


def error_page(status: int, message: str) -> str:
    return layout(f"K8sMatrixWarden · {status}",
                  _topbar() + f"<div class='empty'><h2>{status}</h2><p>{_esc(message)}</p>"
                  "<p><a href='/'>← back to dashboard</a></p></div>")


# The whole dashboard app, vanilla JS, no framework, no external hosts.
_APP_JS = r"""
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEV = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const SEVVAR = {CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};
let D=null, fSev=new Set(), fText='', fTactic='', sortKey='score', sortDir=-1, fSel=null;
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
function reportUrl(f){                       // deep-link straight to the finding's card
  return `/report/${encodeURIComponent(D.scan.scan_id)}#${findingAnchor(f)}`;
}
function findLink(f){
  return `<a class='findlink' href='${reportUrl(f)}' target='_blank' rel='noopener' title='Open in report'>
    <span class='sev ${f.severity}'>${f.severity}</span>
    <span class='fl-t'>${esc(f.title)}</span>
    <span class='fl-r'><code>${esc(res(f))}</code></span>
    <span class='fl-s'>score ${(f.score||0).toFixed(0)}</span>
    <span class='fl-go'>&rsaquo;</span></a>`;
}
const OWASP_HOME='https://owasp.org/www-project-kubernetes-top-ten/';
function owaspLink(code){          // K03 -> its own owasp.org page, not the landing page
  if(!code) return '';
  const u=((D&&D.owasp_urls)||{})[code]||OWASP_HOME;
  return ` · <a href='${esc(u)}' target='_blank' rel='noopener'
    onclick='event.stopPropagation()' title='OWASP Kubernetes Top 10, ${esc(code)}'>OWASP ${esc(code)}</a>`;
}
function tacticFindings(tactic){
  return D.findings.filter(f=>(f.mitre||[]).some(m=>m.tactic===tactic))
    .sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||b.score-a.score);
}

async function boot(){
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&fSel!=null)closeFDetail();});
  const r = await fetch('/api/dashboard'); D = await r.json();
  if(!D.has_scan){ $('#app').innerHTML = emptyView(); wireScan(); return; }
  render();
}
async function loadReport(id){
  const r = await fetch('/api/dashboard?scan_id='+encodeURIComponent(id));
  D = await r.json(); fSel=null;
  if(!D.has_scan){ $('#app').innerHTML = emptyView(); wireScan(); return; }
  render();
}
function emptyView(){
  return `<div class='panel'><h2>Run your first scan</h2>
    <div class='fm'>No scans yet. Run one to populate the dashboard.</div>
    ${scanForm()}</div>`;
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
  $('#app').innerHTML = `
    ${reportBar()}
    ${healthBanner()}
    ${hero()}
    <div class='tabs'>
      ${tab('overview','Overview')}${tab('findings','Findings ('+D.scan.total+')')}
      ${tab('matrix','Threat Matrix')}${tab('attack','Attack Path')}
      ${tab('runtime','Runtime')}${tab('scan','Scans')}
    </div>
    <div id='v-overview' class='view'>${overview()}</div>
    <div id='v-findings' class='view'>${findingsView()}</div>
    <div id='v-matrix' class='view'>${matrixView()}</div>
    <div id='v-attack' class='view'>${attackView()}</div>
    <div id='v-runtime' class='view'>${runtimeView()}</div>
    <div id='v-scan' class='view'>${scanView()}</div>`;
  renderFindings(); wireScan(); initAttack(); showTab(activeTab);
}
function reportBar(){
  const cur=D.selected_scan_id||D.scan.scan_id;
  const opts=(D.history||[]).map(r=>`<option value='${esc(r.scan_id)}' ${r.scan_id===cur?'selected':''}>`
    +`${esc(r.scan_id)}, ${fmtTime(r.generated_at)} · ${esc(r.rating)} (${r.risk_score}/10) · ${r.total} findings</option>`).join('');
  return `<div class='repbar'>
    <label for='rptpick'>Report</label>
    <select id='rptpick' onchange='loadReport(this.value)'>${opts}</select>
    <span class='meta'>${(D.history||[]).length} scan${(D.history||[]).length!==1?'s':''} · viewing ${fmtTime(D.scan.generated_at)}</span>
    <details class='exp'><summary class='btn'>Export &#9662;</summary>
      <div class='exp-menu'>
        <button onclick="exportReport('pdf')">PDF report</button>
        <button onclick="exportReport('xlsx')">Excel workbook</button>
        <button onclick="exportReport('both')">Both</button>
      </div></details>
  </div>`;
}
const tab=(id,l)=>`<button class='tab${id===activeTab?' on':''}' onclick="showTab('${id}')" id='t-${id}'>${l}</button>`;
function showTab(id){
  activeTab=id;
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  const v=$('#v-'+id), t=$('#t-'+id);
  if(v)v.classList.add('on'); if(t)t.classList.add('on');
  if(id==='attack') ensureAttackGraph();     // needs a visible, sized container
}
function hero(){
  const s=D.scan, t=D.trend||[], d=t.length>1?(t[t.length-1][1]-t[t.length-2][1]):null;
  const delta = d===null?'':(d<0?`<div class='s down'>&darr; ${Math.abs(d).toFixed(1)} vs previous</div>`
    :d>0?`<div class='s up'>&uarr; ${d.toFixed(1)} vs previous</div>`:`<div class='s fm'>no change</div>`);
  const hp=(s.counts.CRITICAL||0)+(s.counts.HIGH||0);
  const cov=D.threat_matrix.summary.coverage_pct;
  const inv=D.inventory||null;
  const invBits=inv&&inv.pods?` <span class='dot'></span> ${inv.nodes} node${inv.nodes!==1?'s':''} <span class='dot'></span> ${inv.namespaces} ns <span class='dot'></span> ${inv.pods} pod${inv.pods!==1?'s':''}`:'';
  const meta=`<div class='sysline'>${esc(s.scope)} <span class='dot'></span> ${esc(s.mode)} <span class='dot'></span> ${fmtTime(s.generated_at)} <span class='dot'></span> ${esc(s.scan_id)}${invBits}</div>`;
  // Cluster never read: show "N/A" rather than a 0.0 risk / Excellent rating that a reader
  // would take as a passing grade for a cluster nothing was collected from.
  if(!scanOk()){
    return `${meta}<div class='kpis'>
      <div class='kpi unk'><div class='n'>N/A</div><div class='l'>Risk score</div><div class='s fm'>not measurable</div></div>
      <div class='kpi unk'><div class='n'>Unknown</div><div class='l'>Security posture</div><div class='s fm'>cluster not read</div></div>
      <div class='kpi unk'><div class='n'>N/A</div><div class='l'>Critical &amp; high</div><div class='s fm'>nothing inspected</div></div>
      <div class='kpi unk'><div class='n'>${cov}%</div><div class='l'>Detection coverage</div><div class='s fm'>rules ready, not applied</div></div>
    </div>`;
  }
  const rk=s.cluster_risk>=7?'crit':s.cluster_risk>=4?'warn':'good';
  const C=s.counts||{}, ORD=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const tot=ORD.reduce((a,k)=>a+(C[k]||0),0);
  const segs=ORD.filter(k=>C[k]).map(k=>`<span class='s-${k}' style='width:${(C[k]/tot*100).toFixed(2)}%' title='${k}: ${C[k]}'></span>`).join('');
  const cap=k=>k[0]+k.slice(1).toLowerCase();
  const leg=ORD.filter(k=>C[k]).map(k=>`<span><i class='s-${k}'></i><b>${C[k]}</b> ${cap(k)}</span>`).join('');
  return `${meta}
  <div class='kpis'>
    <div class='kpi lead ${rk}'><div class='n'>${s.cluster_risk.toFixed(1)}<span class='max'>/10</span></div><div class='l'>Risk score</div>${delta}</div>
    <div class='kpi ${rk}'><div class='n'>${esc(s.rating)}</div><div class='l'>Security posture</div><div class='s fm'>${s.total} resource findings</div></div>
    <div class='kpi'><div class='n'>${wlCount()}</div><div class='l'>Workload issues</div><div class='s fm'>${wlNote()}</div></div>
    <div class='kpi ${hp?'crit':'good'}'><div class='n'>${hp}</div><div class='l'>Critical &amp; high</div><div class='s fm'>${hp?'need attention':'all clear'}</div></div>
    <div class='kpi good'><div class='n'>${cov}<span class='max'>%</span></div><div class='l'>Detection coverage</div><div class='s fm'>${D.threat_matrix.summary.techniques_covered} techniques</div></div>
  </div>
  ${tot?`<div class='sevbar'>${segs}</div><div class='sevleg'>${leg}</div>`:''}
  ${wlExplain()}
  ${exposureBar()}`;
}
// The two counts are different questions and the dashboard says so in words, because a bare
// pair of numbers invites a reader to assume one of them is wrong.
//   resource findings , every Kubernetes object carrying a flaw, the evidence
//   workload issues   , one per (rule x owning workload), the number of separate fixes
// A Deployment's misconfiguration appears on the Deployment, its ReplicaSets and every Pod;
// that is three findings and one thing to fix.
function agg(){ return D.aggregation||{}; }
function wlCount(){ const a=agg(); return a.workload_issues!=null?a.workload_issues:'-'; }
function wlNote(){
  const a=agg(); if(a.workload_issues==null) return 'not computed for this scan';
  const d=a.duplication_factor||1;
  return d>1.05?`${d}x evidence per issue`:'one issue per finding';
}
function wlExplain(){
  const a=agg(); if(a.workload_issues==null) return '';
  if(!a.derived_resource_findings) return '';
  return `<div class='fm' style='margin:.5rem 0 0'>
    <b>${a.resource_findings}</b> resource-level findings are the evidence;
    <b>${a.workload_issues}</b> owning-workload issues are the separate fixes.
    ${a.derived_resource_findings} findings sit on Pods and ReplicaSets that Kubernetes
    generated from a controller, so they are evidence for an issue fixed on that controller.
    Nothing is hidden, the findings table below still lists every one.</div>`;
}
// Pod exposure bar (reachability): worst-wins buckets over EVERY pod, so the segments have an
// honest denominator. Reuses the sevbar/sevleg idiom. Renders nothing for pre-inventory scans.
function exposureBar(){
  const inv=D.inventory; if(!inv||!inv.pods) return '';
  const X=inv.exposure||{}, tot=inv.pods;
  const ORD=[['internet_admin','Internet + cluster-admin'],['internet','Internet-reachable'],
             ['admin','Cluster-admin SA'],['internal','Post-breach only']];
  const segs=ORD.filter(([k])=>X[k]).map(([k,lbl])=>`<span class='x-${k}' style='width:${(X[k]/tot*100).toFixed(2)}%' title='${lbl}: ${X[k]}'></span>`).join('');
  const leg=ORD.filter(([k])=>X[k]).map(([k,lbl])=>`<span><i class='x-${k}'></i><b>${X[k]}</b> ${lbl}</span>`).join('');
  return `<div class='sysline' style='margin-bottom:.3rem'>Pod exposure &mdash; how much of the cluster an attacker can actually reach</div>
    <div class='sevbar'>${segs}</div><div class='sevleg'>${leg}</div>`;
}
function overview(){
  return `${healthNote()}
  <div class='grid2'>
    <div class='panel'><h2>Fix first</h2>${priorityList()}</div>
    <div class='panel'><h2>Risk by domain</h2>${domainBars()}</div>
    <div class='panel'><h2>Why this score</h2>${riskContributors()}</div>
    <div class='panel'><h2>Evidence coverage</h2>${coveragePanel()}</div>
    <div class='panel'><h2>Attack surface</h2>${surfaceStrip()}</div>
    <div class='panel'><h2>Risk trend</h2>${trendBars()}</div>
  </div>
  <div class='panel'><h2>Since the last scan</h2>${posturePanel()}</div>
  <div class='panel'><h2>Runtime coverage</h2>${runtimeReadiness()}</div>`;
}
// What the risk score is actually made of. Rendered straight from the server's own
// breakdown, the browser does no scoring arithmetic of its own.
function riskContributors(){
  const x=D.risk_explanation||{};
  if(!x.by_severity) return "<div class='fm'>No scored findings.</div>";
  const rows=Object.entries(x.by_tactic||{}).slice(0,6).map(([k,v])=>
    `<div class='bar'><div class='barl'>${esc(k)}</div><div class='bart'>
      <div class='barf' style='width:${Math.max(v.share_pct,6)}%'>${v.share_pct}% · ${v.findings}</div></div></div>`).join('');
  // `resource` here is the server's pre-rendered string, not the {kind,name,namespace}
  // object findingAnchor() needs, so these rows are plain text rather than deep links.
  const top=(x.top_contributors||[]).slice(0,3).map(f=>
    `<div class='findlink'>
      <span class='sev ${f.severity}'>${f.severity}</span>
      <span class='fl-t'>${esc(f.rule_id)}</span>
      <span class='fl-r'><code>${esc(f.resource)}</code></span>
      <span class='fl-go'>${f.share_pct}%</span></div>`).join('');
  return `<div class='fm'>Raw score ${x.raw_total} over ${x.scored_findings} findings,
    saturated to ${x.cluster_risk}/10. <code>${esc(x.formula||'')}</code></div>
    <div style='margin:.6rem 0'>${rows}</div>${top}`;
}
// How much of the cluster this verdict rests on. Never used to soften a finding.
function coveragePanel(){
  const c=D.coverage;
  if(!c||!c.domains) return "<div class='fm'>Coverage was not recorded for this scan.</div>";
  const rows=Object.entries(c.domains).map(([k,v])=>
    `<div class='bar'><div class='barl'>${esc(k)}</div><div class='bart'>
      <div class='barf' style='width:${Math.max(v.coverage_pct,6)}%;background:var(--${v.coverage_pct>=100?'low':v.coverage_pct>=50?'med':'crit'})'>${v.coverage_pct}%</div>
      </div></div>`).join('');
  const unread=(c.unread_kinds||[]).length
    ? `<div class='fm' style='margin-top:.6rem'>Not read: <code>${c.unread_kinds.map(esc).join('</code>, <code>')}</code>.
       Those areas are <b>unassessed</b>, not clean.</div>` : '';
  return `<div class='fm'>Evidence coverage <b>${c.coverage_pct}%</b> ·
    assessment confidence <b>${c.confidence_pct}% (${esc(c.confidence_label)})</b></div>
    <div style='margin:.6rem 0'>${rows}</div>${unread}`;
}
// New / resolved / regressed vs the previous scan of the same cluster.
function posturePanel(){
  const p=D.posture;
  if(!p||!p.current_scan_id) return "<div class='fm'>No earlier scan to compare against.</div>";
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
  const top=[...D.findings].sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||b.score-a.score)
    .filter(f=>f.severity==='CRITICAL'||f.severity==='HIGH').slice(0,6);
  if(!top.length) return "<div class='fm'>No high-severity findings.</div>";
  return top.map(f=>`<a class='findlink' href='${reportUrl(f)}' target='_blank' rel='noopener' title='Open in report'
      style='border-left:3px solid var(--${f.severity.toLowerCase()})'>
    <span class='sev ${f.severity}'>${f.severity}</span>
    <span class='fl-t'>${esc(f.title)}</span>
    <span class='fl-r'><code>${esc(res(f))}</code></span>
    <span class='fl-go'>&rsaquo;</span></a>`).join('')
    + `<div class='fm' style='margin-top:.6rem'><a href='javascript:showTab("findings")'>See all ${D.scan.total} findings &rarr;</a></div>`;
}
function domainBars(){
  const by={}; D.findings.forEach(f=>{(by[f.owning_shard||'other']=by[f.owning_shard||'other']||[]).push(f)});
  const rows=Object.entries(by).map(([k,v])=>({k,n:v.length,w:Math.max(...v.map(f=>SEV.length-SEV.indexOf(f.severity)))}))
    .sort((a,b)=>b.w-a.w||b.n-a.n);
  const mx=Math.max(...rows.map(r=>r.n),1);
  return rows.map(r=>{const worst=SEV[SEV.length-r.w];
    return `<div class='bar'><div class='barl'>${esc(domainName(r.k))}</div><div class='bart'>
    <div class='barf' style='width:${Math.max(r.n/mx*100,14)}%;background:var(--${SEVVAR[worst]||'info'})'>${r.n} · ${worst}</div></div></div>`}).join('');
}
function surfaceStrip(){
  const cols=D.threat_matrix.columns, sm=D.threat_matrix.summary;
  const cells=cols.map(c=>{const st=c.techniques_hit?'hit':c.techniques_covered?'covered':'gap';
    const ab=c.tactic.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    const sev=(c.max_severity||'CRITICAL');
    const clickable=c.techniques_hit>0;
    const attrs=clickable?`data-sev='${sev}' class='cell ${st} clk' onclick='gotoAttack("${esc(c.tactic)}")'`:`class='cell ${st}'`;
    return `<div ${attrs} title="${esc(c.tactic)}${c.finding_count?': '+c.finding_count+' findings, click to open in Attack Path':''}" style='min-height:34px;text-align:center'>${ab}${c.finding_count?`<span class='c'>${c.finding_count}</span>`:''}</div>`}).join('');
  return `<div class='fm'>${sm.tactics_hit} of 9 tactics exposed · ${sm.techniques_hit} techniques hit. <b>Select a stage to open its attack path.</b></div>
    <div style='display:grid;grid-template-columns:repeat(9,1fr);gap:5px;margin:.6rem 0'>${cells}</div>
    <div class='leg'><span><i style='background:var(--crit)'></i>exposed</span><span><i style='background:var(--low)'></i>detectable</span><span><i style='background:var(--card);border:1px solid var(--bd)'></i>no rule</span></div>
    <div class='fm' style='margin-top:.5rem'><a href='javascript:showTab("attack")'>Open attack path &rarr;</a></div>`;
}
function gotoAttack(tactic){
  showTab('attack');
  focusStage(tactic);
  const el=document.getElementById('atk-'+slug(tactic));
  if(el) el.scrollIntoView({behavior:'smooth',block:'center'});
}
function trendBars(){
  const t=(D.trend||[]).filter(p=>typeof p[1]==='number');
  if(t.length<2) return "<div class='fm'>Run more scans over time to see the trend.</div>";
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
let wlOpen=null;
function workloadView(){
  const issues=D.workload_issues||[];
  if(!issues.length) return '';
  const rows=issues.map((i,ix)=>{
    const open=ix===wlOpen;
    const ev=open?`<tr class='wl-ev'><td colspan='6'><div class='fm'>
        Resource-level evidence for this issue:</div><ul>${
        (i.resources||[]).map(r=>`<li><code>${esc(r)}</code></li>`).join('')}</ul></td></tr>`:'';
    return `<tr class='clk${open?' sel':''}' onclick='wlOpen=${open?'null':ix};render()'>
      <td><code>${esc(i.workload)}</code>${i.namespace?` <span class='fm'>(${esc(i.namespace)})</span>`:''}</td>
      <td><span class='s-${i.severity}'></span> ${i.severity}</td>
      <td>${esc(i.rule_id)}</td>
      <td>${i.resource_count}${i.derived_resource_count?` <span class='fm'>(${i.derived_resource_count} derived)</span>`:''}</td>
      <td>${(i.tactics||[]).length}</td>
      <td>${(i.score||0).toFixed(2)}</td></tr>${ev}`;
  }).join('');
  return `<details class='panel' style='margin-top:1rem'>
    <summary><strong>Workload issues</strong> &middot; ${issues.length} separate fixes behind
      ${D.findings.length} resource-level findings</summary>
    <div class='fm' style='margin:.5rem 0'>One row per rule &times; owning workload. Click a
      row to see the resource-level findings that are its evidence.</div>
    <div class='tw'><table><thead><tr>
      <th>Workload</th><th>Severity</th><th>Rule</th><th>Resources</th><th>Tactics</th>
      <th>Score</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
}

function findingsView(){
  const chips=SEV.slice(0,4).map(s=>`<span class='chip' data-sev='${s}' onclick='toggleSev("${s}")'>${s}</span>`).join('');
  const tacs=[...new Set(D.findings.flatMap(f=>f.mitre.map(m=>m.tactic)))].sort();
  return workloadView()+`<div class='panel'>${healthNote()}
    <div class='ctl'>
      <input type='search' id='fsearch' placeholder='Search findings, rules, or resources…' oninput='fText=this.value.toLowerCase();renderFindings()'>
      ${chips}
      <select id='ftac' onchange='fTactic=this.value;renderFindings()'><option value=''>All tactics</option>${tacs.map(t=>`<option ${t===fTactic?'selected':''}>${esc(t)}</option>`).join('')}</select>
    </div>
    <div id='fcount' class='fm'></div>
    <table class='ft'><thead><tr>
      ${th('severity','Severity')}${th('title','Finding')}${th('owning_shard','Domain')}
      <th>Resource</th><th>Tactic</th>${th('score','Score')}<th></th>
    </tr></thead><tbody id='fbody'></tbody></table></div>`;
}
const th=(k,l)=>`<th onclick='setSort("${k}")'>${l} ${sortKey===k?(sortDir<0?'&#9662;':'&#9652;'):''}</th>`;
function setSort(k){ if(sortKey===k)sortDir*=-1; else{sortKey=k;sortDir=-1} renderFindings(); }
function toggleSev(s){ fSev.has(s)?fSev.delete(s):fSev.add(s);
  document.querySelectorAll('.chip[data-sev]').forEach(c=>c.classList.toggle('on',fSev.has(c.dataset.sev))); renderFindings(); }
function renderFindings(){
  if(!$('#fbody')) return;
  let rows=D.findings.filter(f=>{
    if(fSev.size&&!fSev.has(f.severity))return false;
    if(fTactic&&!f.mitre.some(m=>m.tactic===fTactic))return false;
    if(fText){const h=(f.title+' '+f.rule_id+' '+res(f)+' '+f.owning_shard).toLowerCase();if(!h.includes(fText))return false;}
    return true;});
  rows.sort((a,b)=>{let x=a[sortKey],y=b[sortKey];
    if(sortKey==='severity'){x=SEV.indexOf(a.severity);y=SEV.indexOf(b.severity);return (x-y)*-sortDir;}
    if(typeof x==='string')return x.localeCompare(y)*sortDir; return ((x||0)-(y||0))*sortDir;});
  $('#fcount').textContent = rows.length+' of '+D.findings.length+' findings';
  $('#fbody').innerHTML = rows.slice(0,400).map(f=>{const gi=D.findings.indexOf(f);const open=gi===fSel;
    const row=`<tr class='clk${open?' sel':''}' onclick='selFinding(${gi})' title='${open?'Collapse details':'View details'}'>
    <td><span class='sev ${f.severity}'>${f.severity}</span></td>
    <td><b>${esc(f.title)}</b><div class='fm'><code>${esc(f.rule_id)}</code></div></td>
    <td class='fm'>${esc(domainName(f.owning_shard))}</td>
    <td><code>${esc(res(f))}</code></td>
    <td class='fm'>${f.mitre.map(m=>esc(m.tactic)).join(', ')||'None'}</td>
    <td>${(f.score||0).toFixed(0)}</td>
    <td class='fm'><span class='fcaret${open?' open':''}'>&rsaquo;</span></td></tr>`;
    // Detail expands in place, directly under the row that was selected, so it is always
    // adjacent to the click (no scrolling to a panel elsewhere on the page).
    return open ? row+`<tr class='fdrow'><td colspan='7'>${findingDetailHTML(f)}</td></tr>` : row;
  }).join('')
    + (rows.length>400?`<tr><td colspan=7 class='fm'>${rows.length-400} more. Narrow the filter to see them.</td></tr>`:'');
  if(fSel!=null && D.findings[fSel]) fillFCtx(D.findings[fSel]);
}
// Report-grade context (summary, impact, verification) is loaded on demand when a finding
// is expanded and cached by anchor, so the dashboard payload stays lean and a re-render
// (filter/sort) refills instantly from cache.
const FCTX={};
function ctxHTML(c){
  const val=(c.validation||[]).map(v=>esc(v)).join('\n');
  return `${c.summary?`<div class='fdsec'><div class='sh'>Summary</div><p>${esc(c.summary)}</p></div>`:''}
    ${c.impact?`<div class='fdsec'><div class='sh'>Potential impact</div><p>${esc(c.impact)}</p></div>`:''}
    ${exposureHTML(c.explanation)}
    ${val?`<div class='fdsec'><div class='sh'>How to verify</div><pre class='fdev'>${val}</pre></div>`:''}`;
}
/* The graph analysis the backend already attached to this finding: which NetworkPolicy
   posture its pod has, and the exact RBAC hops its ServiceAccount can escalate through.
   Rendering only, no security judgement, every value is server-computed. */
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
function fillFCtx(f){
  const box=$('#fdctx'); if(!box) return;
  const anchor=findingAnchor(f);
  if(FCTX[anchor]){ box.innerHTML=ctxHTML(FCTX[anchor]); return; }
  fetch(`/api/finding?scan_id=${encodeURIComponent(D.scan.scan_id)}&anchor=${encodeURIComponent(anchor)}`)
    .then(r=>r.json()).then(d=>{ if(d && !d.error){ FCTX[anchor]=d;
      const b=$('#fdctx'); if(b && fSel!=null && findingAnchor(D.findings[fSel])===anchor) b.innerHTML=ctxHTML(d); }})
    .catch(()=>{});
}
/* Inline finding details: one open at a time, toggled from the row. Selection lives in
   fSel (index into D.findings) and is independent of filters/sort/search/pagination, so
   opening or closing never disturbs the list state. */
function selFinding(gi){
  fSel = (fSel===gi ? null : gi);
  renderFindings();
  if(fSel!=null){const dr=document.querySelector('#fbody tr.fdrow');
    if(dr) dr.scrollIntoView({behavior:'smooth',block:'nearest'});}
}
function closeFDetail(){ fSel=null; renderFindings(); }
function findingDetailHTML(f){
  const r=f.resource||{};
  const meta=[
    ['Resource', res(f)],
    ['Owner', r.owner_kind?`${r.owner_kind}/${r.owner_name||''}`:''],
    ['Domain', domainName(f.owning_shard)],
    ['Detection', [f.surface, f.detection_method].filter(Boolean).join(' · ')],
    ['Exploitability', f.exploitability],
    ['Blast radius', f.blast_radius],
    ['Risk score', (f.score||0).toFixed(1)],
    ['Attack vector', (f.exploitable_by||[]).includes('ingress')?'🔴 Internet-reachable'
      :((f.exploitable_by||[]).includes('pod-privilege')?'🟡 Post-breach only':'')],
    ['Vector detail', f.path_reason||''],
  ].filter(m=>m[1]);
  const metaHtml=meta.map(m=>`<div class='m'><div class='mk'>${esc(m[0])}</div><div class='mv'>${esc(m[1])}</div></div>`).join('');
  const mitre=(f.mitre||[]).map(m=>`<span class='tchip'>${esc(m.tactic)}${m.technique_id?` · ${esc(m.technique_id)}`:''}${m.technique_name?` ${esc(m.technique_name)}`:''}</span>`).join('');
  const std=[]; if(f.owasp)std.push('OWASP '+f.owasp); (f.cis||[]).forEach(c=>std.push('CIS '+c)); if(f.nsa_cisa)std.push('NSA/CISA '+f.nsa_cisa);
  const stdHtml=std.map(s=>`<span class='tchip'>${esc(s)}</span>`).join('');
  const labels=(r.labels&&Object.keys(r.labels).length)
    ?Object.entries(r.labels).slice(0,12).map(([k,v])=>`<span class='tchip'>${esc(k)}=${esc(v)}</span>`).join(''):'';
  const ev=f.evidence, evStr=ev?(typeof ev==='string'?ev:JSON.stringify(ev,null,2)):'';
  return `<div class='fdcard'>
    <div class='fdh'><div class='fdt'>
      <div class='fdsub'><span class='sev ${f.severity}'>${f.severity}</span><code>${esc(f.rule_id)}</code></div>
      <h3>${esc(f.title)}</h3></div>
      <button class='fdclose' onclick='closeFDetail()'>&#10005; Close</button></div>
    <div class='fdmeta'>${metaHtml}</div>
    <div id='fdctx'>${f.message?`<div class='fdsec'><div class='sh'>Summary</div><p>${esc(f.message)}</p></div>`:''}
      <div class='fm' style='color:var(--muted)'>Loading impact and verification…</div></div>
    ${mitre?`<div class='fdsec'><div class='sh'>MITRE ATT&amp;CK</div><div class='fdchips'>${mitre}</div></div>`:''}
    ${stdHtml?`<div class='fdsec'><div class='sh'>Compliance</div><div class='fdchips'>${stdHtml}</div></div>`:''}
    ${labels?`<div class='fdsec'><div class='sh'>Resource labels</div><div class='fdchips'>${labels}</div></div>`:''}
    ${evStr?`<div class='fdsec'><div class='sh'>Evidence</div><pre class='fdev'>${esc(evStr)}</pre></div>`:''}
    <div class='fdfoot'>
      <a class='fdlink' href='${reportUrl(f)}' target='_blank' rel='noopener'>Open full report &amp; remediation &#8599;</a>
      <span class='fm'>Fix steps and verification commands are in the report.</span>
    </div></div>`;
}
/* ---- matrix ---- */
function matrixView(){
  const cols=D.threat_matrix.columns;
  let html="<div class='panel'>"+healthNote()+"<div class='fm'>Select a highlighted cell to see its findings.</div><div class='mx'>";
  html+=cols.map(c=>{
    let col=`<div class='mxcol'><div class='mxh'>${esc(c.tactic)}</div>`;
    col+=c.cells.map(cell=>{const st=cell.state;const sev=cell.max_severity||'';
      return `<div class='cell ${st}' ${st==='hit'?`data-sev='${sev}' onclick='cellFindings(${JSON.stringify(cell.finding_rule_ids)},"${esc(cell.technique_name)}","${esc(cell.technique_id||'')}")'`:''} title="${esc(cell.technique_name)}${cell.technique_id?' ('+cell.technique_id+')':''}">
        ${esc(cell.technique_name)}${cell.count?`<span class='c'>${cell.count}</span>`:''}</div>`}).join('');
    return col+'</div>';}).join('');
  html+="</div><div class='leg'><span><i style='background:var(--crit)'></i>hit (by severity)</span><span><i style='background:var(--low)'></i>scan rule</span><span><i style='background:transparent;border:1px dashed var(--rt)'></i>runtime-only</span><span><i style='background:var(--card);border:1px solid var(--bd)'></i>no detection</span></div>";
  html+="<div id='cellout'></div></div>";
  return html;
}
function cellFindings(ruleIds,tech,tid){
  const fs=D.findings.filter(f=>ruleIds.includes(f.rule_id));
  const cards=fs.slice(0,40).map(f=>{
    const std=[]; (f.cis||[]).slice(0,2).forEach(c=>std.push('CIS '+c));
    const mit=(f.mitre||[]).map(m=>`${esc(m.technique_id||m.tactic)}`).slice(0,3).join(', ');
    return `<a class='findlink' href='${reportUrl(f)}' target='_blank' rel='noopener' title='Open in report'
        style='flex-wrap:wrap'>
      <span class='sev ${f.severity}'>${f.severity}</span>
      <span class='fl-t'>${esc(f.title)}</span>
      <span class='fl-go'>&rsaquo;</span>
      <div class='fm' style='flex-basis:100%;margin-top:.3rem'>
        <code>${esc(res(f))}</code> · score ${(f.score||0).toFixed(0)} · ${esc(domainName(f.owning_shard))}
        ${mit?` · MITRE ${esc(mit)}`:''}${owaspLink(f.owasp)}${std.length?` · ${esc(std.join(' · '))}`:''}</div>
      <div class='fm' style='flex-basis:100%;margin-top:.2rem'>${esc(f.message||'')}</div>
    </a>`}).join('');
  $('#cellout').innerHTML=`<div style='margin-top:.8rem;border-top:1px solid var(--bd);padding-top:.7rem'>
    <div style='font-weight:700;margin-bottom:.4rem'>${esc(tech)}${tid?` <code>${esc(tid)}</code>`:''}, ${fs.length} finding(s)</div>
    ${cards||"<div class='fm'>No findings.</div>"}</div>`;
}
/* ---- attack path (force graph, cytoscape) ---------------------------
   Nodes = findings; an edge links two findings that share a resource
   across consecutive kill-chain stages (the same Pod hit at Initial
   Access, then again at Impact). Click a node to light up its connected
   component and see (a) every other stage that resource is still
   exposed at, remediating this finding alone won't clear those, and
   (b) sibling findings that reach the SAME stage via a different
   resource/technique, i.e. what remediation still leaves open. */
let cy=null;
function attackView(){
  const a=D.attack_path;
  if(!a.steps||!a.steps.length) return `<div class='panel'>${healthNote()}<div class='fm'>${
    scanOk()?'No attack path, no findings mapped to tactics.'
            :'No attack path can be derived: the cluster was never read.'}</div></div>`;
  const steps=a.steps.map((s,i)=>`${i?`<div class='arrow'>&rarr;</div>`:''}
    <div class='step' id='atk-${slug(s.tactic)}' onclick='focusStage("${esc(s.tactic)}")'
        style='border-left-color:var(--${(s.worst_severity||'CRITICAL').toLowerCase()})'>
      <div class='t'><span>${esc(s.tactic)}</span><span class='num'>${i+1}</span></div>
      <div class='k'>${s.techniques.slice(0,3).map(t=>esc(t.technique_name)).join('<br>')}</div>
      <div class='cnt'>${tacticFindings(s.tactic).length} finding(s)</div>
    </div>`).join('');
  const rc=a.reaches_impact?"<span class='reach y'>reaches Impact, full kill-chain</span>":"<span class='reach n'>stops before Impact</span>";
  return `<div class='panel'><h2>Kill chain <span class='pill'>tactic layer</span></h2>${healthNote()}
    <div class='fm'>${a.tactic_count} tactics chained · ${rc}. This layer is kill-chain <em>ordering</em>, not causality: two findings in different stages are not claimed to be connected. The evidence-backed routes are below.</div>
    <div class='flow'>${steps}</div>
    <div class='fm' style='margin-top:.6rem'>Entry points: ${(a.entry_points||[]).map(e=>esc(e.technique_name)).join(', ')||'N/A'}</div>
    <div id='atk-graph'></div>
    <div class='graphhint'>Rows are kill-chain stages; node size and colour show severity; an edge means one resource is hit at both ends.
      <span id='atk-isolated'></span></div>
    <div id='atk-impact'></div></div>${resourcePathView()}`;
}
/* The resource layer: hop chains the backend read off real Services, NetworkPolicies and
   RBAC bindings. Everything rendered here is computed server-side, this only lays it out,
   so no security judgement lives in the browser. */
function pathConfPill(c){
  const cls={'observed':'critical','corroborated':'high','configuration-only':'info'}[c]||'info';
  return `<span class='tag ${cls}'>${esc(c||'configuration-only')}</span>`;
}
// "observed" says the behaviour was seen; freshness says whether it was seen recently.
// Rendering the first without the second is how a years-old alert reads as a live breach.
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
function resourcePathView(){
  const paths=(D.attack_path&&D.attack_path.resource_paths)||[];
  if(!paths.length) return '';
  const trunc=paths.some(p=>p.analysis_status==='truncated');
  const cards=paths.map((p,i)=>{
    const hops=p.steps.map(s=>{
      const obs=(p.observed_nodes||[]).includes(s.node);
      return `<span class='hop${obs?' obs':''}' title='${esc(s.reason||'')}'>
        <span class='hk'>${esc(s.node_type)}</span>${esc(s.node)}</span>`;
    }).join("<span class='harrow'>&rarr;</span>");
    const rt=(p.runtime_evidence||[]).map(e=>
      `<li><code>${esc(e.timestamp||'')}</code> ${esc(e.source||'')} · ${esc(e.title||e.rule_id||'')}
        <span class='muted'>${esc(e.resource||'')}${e.namespace?' ('+esc(e.namespace)+')':''}</span></li>`).join('');
    const fs=(p.supporting_findings||[]).map(f=>
      `<li><span class='sev ${esc((f.severity||'').toLowerCase())}'>${esc(f.severity)}</span>
        <code>${esc(f.rule_id)}</code> ${esc(f.resource)}</li>`).join('');
    return `<div class='rpath'>
      <div class='rphead'>${pathConfPill(p.confidence)}${freshPill(p.evidence_freshness,(p.runtime_evidence&&p.runtime_evidence[0]||{}).age_days)}
        ${p.internet_reachable?"<span class='tag critical'>internet-reachable</span>":"<span class='tag info'>post-breach only</span>"}
        <span class='muted'>${esc(p.namespace||'')}${p.cluster?' · '+esc(p.cluster):''}</span></div>
      <div class='hops'>${hops}</div>
      <div class='fm'>${esc(p.summary||'')}</div>
      ${fs?`<details><summary>${(p.supporting_findings||[]).length} supporting finding(s)</summary><ul class='plist'>${fs}</ul></details>`:''}
      ${rt?`<details><summary>${(p.runtime_evidence||[]).length} runtime event(s)</summary><ul class='plist'>${rt}</ul></details>`:''}
    </div>`;
  }).join('');
  return `<div class='panel'><h2>Evidence-backed routes <span class='pill'>resource layer</span></h2>
    <div class='fm'>${paths.length} route(s), each hop read off a real object (Service / Ingress / NetworkPolicy / RoleBinding / ClusterRole). Highlighted hops were named by a runtime event; the rest are configuration-derived.${
      trunc?" <strong>Analysis truncated</strong>, the strongest routes are shown.":''}</div>
    ${cards}</div>`;
}
function initAttack(){ cy=null; }               // old graph's container is gone after render()
function ensureAttackGraph(){ cy ? cy.resize() : buildAttackGraph(); }
function findingTactic(f,order){
  return f.mitre.map(m=>m.tactic).filter(t=>order.includes(t)).sort((a,b)=>order.indexOf(a)-order.indexOf(b))[0];
}
function buildAttackGraph(){
  const el=$('#atk-graph'); if(!el||typeof cytoscape==='undefined') return;
  const fg=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#222';
  const order=(D.attack_path.steps||[]).map(s=>s.tactic);
  const rKey=r=>`${r.kind}|${r.name}|${r.namespace||''}`;
  const nodes=D.findings.map((f,i)=>({f,i,tactic:findingTactic(f,order)})).filter(n=>n.tactic);
  const byRes={};
  nodes.forEach(n=>{const k=rKey(n.f.resource);(byRes[k]=byRes[k]||[]).push(n)});
  const edges=[];
  Object.values(byRes).forEach(group=>{
    if(group.length<2) return;
    group.sort((a,b)=>order.indexOf(a.tactic)-order.indexOf(b.tactic));
    for(let j=0;j<group.length-1;j++) edges.push({data:{id:'e'+group[j].i+'_'+group[j+1].i,source:''+group[j].i,target:''+group[j+1].i}});
  });
  // Only findings that chain across ≥2 stages via a shared resource answer "what's still
  // open", a lone node is already fully described by the text panel ("only finding tied
  // to this resource"). Drop it from the canvas rather than let it pad out as dead weight.
  const inChain=new Set(); edges.forEach(e=>{inChain.add(e.data.source);inChain.add(e.data.target)});
  const shown=nodes.filter(n=>inChain.has(''+n.i));
  const note=$('#atk-isolated');
  if(note) note.textContent=shown.length<nodes.length
    ?` · ${shown.length} chained across stages, ${nodes.length-shown.length} single-stage finding(s) not shown (see Findings tab).`:'';
  // Row = the finding's OWN tactic (its position in the fixed 9-stage order), not BFS
  // depth from a root, depth is relative to each resource's own chain length, so two
  // nodes at the same depth can be different tactics. Pinning y to the real tactic index
  // is what makes "this row is Privilege Escalation" an honest claim.
  const rows=order.filter(t=>shown.some(n=>n.tactic===t));
  const rowW=110, rowH=90;
  const byRow={}; shown.forEach(n=>(byRow[n.tactic]=byRow[n.tactic]||[]).push(n));
  const maxCount=Math.max(...Object.values(byRow).map(g=>g.length),1);
  const bandW=maxCount*rowW;
  const positions={};
  rows.forEach((t,ri)=>{
    const group=byRow[t];
    group.forEach((n,ci)=>{positions[n.i]={x:(ci-(group.length-1)/2)*rowW,y:ri*rowH};});
  });
  const strips=rows.map((t,ri)=>({data:{id:'bg-'+ri,label:t,tactic:t},
    position:{x:0,y:ri*rowH},classes:'stripbg',
    locked:true,grabbable:false,selectable:false}));
  cy=cytoscape({
    container:el,
    elements:[...strips,
      ...shown.map(n=>({data:{id:''+n.i,label:n.f.title,res:res(n.f),sev:n.f.severity,tactic:n.tactic},
        position:positions[n.i],classes:'fnode'})),
      ...edges],
    style:[
      {selector:'.stripbg',style:{'shape':'rectangle','width':bandW+140,'height':rowH-6,
        'background-color':n=>TACTIC_TINT[order.indexOf(n.data('tactic'))%TACTIC_TINT.length],
        'background-opacity':.22,'border-width':0,'label':'data(label)','font-size':11,'font-weight':700,
        'color':fg,'text-halign':'left','text-valign':'top','text-margin-x':-(bandW/2)+6,'text-margin-y':4,
        'z-index':0,'events':'no'}},
      {selector:'.fnode',style:{'background-color':n=>SEVCOLOR[n.data('sev')]||'#6c757d',
        'label':'data(label)','font-size':9,'color':fg,'text-wrap':'ellipsis','text-max-width':'80px',
        'width':n=>SEVSIZE[n.data('sev')]||16,'height':n=>SEVSIZE[n.data('sev')]||16,
        'text-valign':'bottom','text-margin-y':5,'border-width':0,'z-index':10}},
      {selector:'edge',style:{'width':1.4,'line-color':'#9a9a9a99','curve-style':'bezier',
        'target-arrow-color':'#9a9a9a99','target-arrow-shape':'triangle','arrow-scale':.8,'z-index':5}},
      {selector:'.dim',style:{'opacity':.12}},
      {selector:'.lit',style:{'opacity':1}},
      {selector:'node.lit',style:{'border-width':2,'border-color':'#2969ff'}},
      {selector:'node.stagehl',style:{'border-width':3,'border-color':'#2969ff'}},
    ],
    // Preset, not force-directed or breadthfirst, every node's row is its own tactic,
    // fixed to the real kill-chain order, so the coloured strips are a true legend.
    layout:{name:'preset',padding:24},
    wheelSensitivity:.25,
    minZoom:.2,maxZoom:3,
    boxSelectionEnabled:false,
    autoungrabify:false,
  });
  cy.on('tap','node',e=>{if(!e.target.hasClass('stripbg')) selectAttackNode(+e.target.id());});
  attachAttackTip(el);
  // The container was mid-reflow (its parent .view had just left display:none) when
  // cytoscape measured it, so the initial fit can be wrong, resize+fit once more now
  // that a layout pass has definitely completed.
  requestAnimationFrame(()=>{cy.resize();cy.fit(undefined,24);});
}
const SEVCOLOR={CRITICAL:'#d1242f',HIGH:'#bc4c00',MEDIUM:'#9a6700',LOW:'#1a7f37',INFO:'#6c757d'};
const SEVSIZE={CRITICAL:32,HIGH:26,MEDIUM:20,LOW:16,INFO:14};
const TACTIC_TINT=['#4C6EF5','#20C997','#94D82D','#F59F00','#F76707',
  '#E64980','#7048E8','#1098AD','#495057'];
function attachAttackTip(el){
  let tip=el.querySelector('.atk-tip');
  if(!tip){tip=document.createElement('div');tip.className='atk-tip';el.appendChild(tip);}
  cy.on('mouseover','node',e=>{
    const n=e.target, p=n.renderedPosition();
    tip.textContent=`${n.data('label')}, ${n.data('res')}`;
    tip.style.left=(p.x+14)+'px'; tip.style.top=(p.y-8)+'px'; tip.style.display='block';
  });
  cy.on('mouseout','node',()=>{tip.style.display='none'});
  cy.on('pan zoom drag',()=>{tip.style.display='none'});
}
function focusStage(tactic){
  document.querySelectorAll('#v-attack .step').forEach(s=>s.classList.toggle('sel',s.id==='atk-'+slug(tactic)));
  if(!cy) return;
  cy.nodes().removeClass('stagehl');
  const sel=cy.nodes('.fnode').filter(n=>n.data('tactic')===tactic);
  sel.addClass('stagehl');
  const strip=cy.nodes('.stripbg').filter(n=>n.data('tactic')===tactic);
  const fitTo=strip.union(sel);
  if(fitTo.length) cy.animate({fit:{eles:fitTo,padding:50}},{duration:280});
}
function selectAttackNode(idx){
  const f=D.findings[idx]; if(!f) return;
  const order=(D.attack_path.steps||[]).map(s=>s.tactic);
  const tactic=findingTactic(f,order);
  if(cy){
    cy.elements().removeClass('lit dim stagehl');
    const node=cy.$id(''+idx);
    let visited=cy.collection().union(node), frontier=node;
    while(frontier.length){const next=frontier.closedNeighborhood().nodes().difference(visited);visited=visited.union(next);frontier=next;}
    const comp=visited.union(visited.connectedEdges());
    cy.elements('.fnode, edge').difference(comp).addClass('dim');  // strips stay visible for row context
    comp.addClass('lit');
    cy.animate({fit:{eles:comp,padding:60}},{duration:280});
  }
  const rKey=r=>`${r.kind}|${r.name}|${r.namespace||''}`;
  const myKey=rKey(f.resource);
  const chain=[...new Map(D.findings.filter(o=>o!==f&&rKey(o.resource)===myKey)
    .flatMap(o=>o.mitre.filter(m=>order.includes(m.tactic)).map(m=>[m.tactic,o]))).entries()]
    .sort((a,b)=>order.indexOf(a[0])-order.indexOf(b[0]));
  const siblings=tacticFindings(tactic).filter(o=>o!==f);
  const chainRows=chain.map(([tac,o])=>`<a class='findlink' href='${reportUrl(o)}' target='_blank' rel='noopener'>
    <span class='sev ${o.severity}'>${o.severity}</span><span class='fl-t'>${esc(tac)}: ${esc(o.title)}</span>
    <span class='fl-go'>&rsaquo;</span></a>`).join('');
  const sibRows=siblings.slice(0,8).map(o=>`<a class='findlink' href='${reportUrl(o)}' target='_blank' rel='noopener'>
    <span class='sev ${o.severity}'>${o.severity}</span><span class='fl-t'>${esc(o.title)}</span>
    <span class='fl-r'><code>${esc(res(o))}</code></span><span class='fl-go'>&rsaquo;</span></a>`).join('');
  $('#atk-impact').innerHTML=`<div class='impact'>
    <div><b>${esc(f.title)}</b> on <code>${esc(res(f))}</code></div>
    <div>${chain.length?
      `This resource is also exposed at <b>${chain.length}</b> other stage(s), remediating this finding alone does <b>not</b> clear it from the kill-chain:`
      :`This is the only kill-chain finding tied to this resource, remediating it removes the resource from the chain entirely.`}
      ${chainRows}</div>
    <div>${siblings.length?
      `<b>${siblings.length}</b> other finding(s) still reach <b>${esc(tactic)}</b> via a different resource/technique, remediating this one does not block them:`
      :`No other finding reaches ${esc(tactic)}, remediating this closes the stage.`}
      ${sibRows}${siblings.length>8?`<div class='fm'>&hellip; ${siblings.length-8} more</div>`:''}</div>
  </div>`;
}
/* ---- runtime ---- */
function runtimeView(){
  const rc=D.runtime_correlation;
  const pre=rc&&rc.correlation?renderRuntime(rc.correlation,rc.drift||{drift:[],drift_count:0},rc)
    :"<div class='fm'>No runtime events yet. Select Refresh to pull the latest from the cluster.</div>";
  const meta=rc&&rc.collected_at?`last updated ${esc(String(rc.collected_at))} · ${rc.events_seen||0} event(s)`:'';
  return `<div class='panel'><h2>Runtime correlation &amp; drift</h2>
    <div class='fm'>Runtime events from Falco, correlated against this scan. Refresh pulls the latest.</div>
    <div class='ctl'>
      <button class='btn' onclick='refreshRuntime()'>&#8635; Refresh</button>
      <label class='fm' style='display:flex;align-items:center;gap:.4rem'><input type='checkbox' id='rtauto' onchange='toggleAutoRefresh()'> Auto-refresh every 30s</label>
      <span class='fm' id='rtmeta'>${meta}</span>
    </div>
    <div id='rtout'>${pre}</div></div>`;
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
  return `<div class='fm'><span class='tag medium' title='${esc(ev.identity_reason||"")}'>identity: ${esc(st)}</span>${miss?` missing ${esc(miss)}`:''}</div>`;
}
function coverageStrip(rc){
  const d=rc&&rc.detection_coverage; if(!d) return '';
  const i=rc.identity_coverage||{};
  const idline=(i.complete!==undefined)?`<div class='fm'>Identity: <b>${i.complete}</b> complete (${i.recovered_from_container_id||0} recovered from container id) · ${i.partial} partial · ${i.ambiguous} ambiguous · ${i.unknown} unknown</div>`:'';
  return `<div class='fm' style='margin-top:.5rem'>Detection: <b>${d.kmw_matches}</b> by curated rule · <b>${d.falco_relays}</b> relayed from Falco · ${d.unusable_events} unusable (reason recorded) · <b>${d.discarded}</b> silently discarded</div>${idline}`;
}
function renderRuntime(c, dr, rc){
  dr=dr||{drift:[],drift_count:0};
  const corr=(c.correlations||[]).map(x=>`<div class='corr ${x.confidence}'>
    <span class='badge ${x.confidence}'>${x.confidence}</span> <b>${esc(x.tactic)}</b> · <span class='sev ${x.severity}'>${x.severity}</span> ${detectorPill(x.runtime)}
    <div class='fm' style='margin-top:.25rem'>runtime: ${esc(x.runtime.title)}</div>
    ${x.runtime.supporting_evidence?`<div class='fm'>also seen by <code>${esc(x.runtime.supporting_evidence)}</code> (same event, not a second finding)</div>`:''}
    ${identityNote(x.runtime.event)}
    ${x.static_findings.length?`<div class='fm'>static: ${esc(x.static_findings[0].title)} on <code>${esc(x.static_findings[0].resource)}</code></div>`:''}
    <div class='fm'>&rarr; ${esc(x.verdict)}</div></div>`).join('');
  const drift=(dr.drift||[]).map(x=>`<div class='corr confirmed'><span class='badge confirmed'>DRIFT</span> <b>${esc(x.pod)}</b> (${esc(x.namespace)})
    <div class='fm' style='margin-top:.25rem'>declares <code>${esc(x.declared)}</code> but runtime shows <b>${esc(x.observed)}</b></div></div>`).join('');
  return `<div style='margin-top:.8rem'>
    <div class='kpis'>
      <div class='kpi crit'><div class='n'>${c.confirmed_exploitation}</div><div class='l'>Confirmed exploitation</div></div>
      <div class='kpi warn'><div class='n'>${c.correlated}</div><div class='l'>Correlated findings</div></div>
      <div class='kpi crit'><div class='n'>${dr.drift_count||0}</div><div class='l'>Config drift</div></div>
      <div class='kpi'><div class='n'>${c.total_alerts}</div><div class='l'>Runtime alerts</div></div>
    </div>
    ${coverageStrip(rc)}
    ${drift?`<h2 style='font-size:.95rem;margin:.6rem 0 .4rem'>Config drift (policy bypass)</h2>${drift}`:''}
    <h2 style='font-size:.95rem;margin:.6rem 0 .4rem'>Correlations</h2>${corr||"<div class='fm'>none</div>"}</div>`;
}
let _rtTimer=null;
async function refreshRuntime(){
  const out=$('#rtout');
  if(!out){ if(_rtTimer){clearInterval(_rtTimer);_rtTimer=null;} return; }  // tab gone
  out.innerHTML="<div class='fm'>Pulling runtime events…</div>";
  let d; try{
    const r=await fetch('/api/runtime/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:D.scan.scan_id})});
    d=await r.json();
  }catch(e){ out.innerHTML=`<div class='fm' style='color:var(--crit)'>Couldn't refresh: ${esc(e.message)}</div>`; return; }
  if(d.error){ out.innerHTML=`<div class='fm' style='color:var(--crit)'>${esc(d.error)}</div>`; return; }
  if(!d.runtime){ out.innerHTML=`<div class='fm'>${esc(d.message||'No runtime events found')}${d.warnings&&d.warnings.length?': '+esc(d.warnings.join('; ')):''}</div>`; return; }
  D.runtime_correlation=d.runtime;
  out.innerHTML=renderRuntime(d.runtime.correlation,d.runtime.drift,d.runtime);
  const m=$('#rtmeta'); if(m)m.textContent=`last updated ${d.runtime.collected_at||''} · ${d.runtime.events_seen||0} event(s)`;
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
    <td><a href='/report/${esc(r.scan_id)}'>${esc(r.name||r.scan_id)}</a>${r.name?`<div class='fm'><code>${esc(r.scan_id)}</code></div>`:''}</td>
    <td class='fm'>${fmtTime(r.generated_at)}</td>
    <td><span class='pill ${r.rating}'>${esc(r.rating)}</span></td>
    <td>${r.risk_score}</td><td>${r.total}</td><td><code>${esc(r.scope)}</code></td>
    <td><a href='javascript:loadReport("${esc(r.scan_id)}")'>view</a> · <a href='/report/${esc(r.scan_id)}'>report</a> · <a href='/report/${esc(r.scan_id)}/matrix'>matrix</a> · <a href='/api/report/${esc(r.scan_id)}?format=pdf' download>PDF</a> · <a href='/api/report/${esc(r.scan_id)}?format=xlsx' download>Excel</a> · <a href='/api/report/${esc(r.scan_id)}?format=json'>JSON</a></td></tr>`).join('');
  return `<div class='panel'><h2>New scan</h2>${scanForm()}</div>
    <div class='panel'><h2>Recent scans</h2><table class='ft'><thead><tr>
    <th>Scan</th><th>Run</th><th>Posture</th><th>Risk</th><th>Findings</th><th>Scope</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function selectorOptions(){
  const s=(D&&D.selectors)||{};
  const grp=(label,arr,type)=>(arr&&arr.length)?`<optgroup label='${esc(label)}'>`+
    arr.map(v=>`<option value='${esc(type)}:${esc(v)}'>${esc(v)}</option>`).join('')+'</optgroup>':'';
  return `<option value=''>All rules</option>`
    +grp('MITRE tactics',s.tactics,'tactic')
    +grp('Domains',s.modules,'module')
    +grp('Compliance frameworks',s.frameworks,'framework')
    +grp('Techniques',s.aliases,'alias');
}
function scanForm(){
  return `<div class='scanform'>
    <div><label>Scan name (optional)</label><input id='scanname' placeholder='e.g. Prod nightly'></div>
    <div><label>Scope</label><select id='scope' onchange='toggleScope()'><option value='cluster'>Whole cluster</option><option value='namespace'>Single namespace</option></select></div>
    <div><label>Namespace</label><input id='ns' placeholder='Select namespace scope first' disabled></div>
    <div><label>Filter (optional)</label><select id='sel'>${selectorOptions()}</select></div>
    <div><label>Target</label><select id='mock' onchange='toggleLive()'><option value='0'>Live cluster</option><option value='1'>Sample cluster</option></select></div>
    <div><label>Context</label><input id='ctx' placeholder='e.g. current-context'></div>
    ${kubeconfigField()}
    <button class='btn' id='run' onclick='runScan()'>Run scan</button></div><div id='scanmsg'></div>`;
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
    if(lbl)lbl.textContent='selected: '+f.name+' ('+e.target.result.length+' bytes)';
    const path=$('#kubeconfig');if(path)path.value='';};   // file wins over a typed path
  reader.onerror=()=>{if(lbl)lbl.textContent='could not read file';};
  reader.readAsText(f);
}
function onKubeconfigPath(){   // typing a path clears any picked file
  if($('#kubeconfig').value.trim()){
    KUBECONFIG_CONTENT=null;
    const fi=$('#kubeconfigfile');if(fi)fi.value='';
    const lbl=$('#kubeconfigfilename');if(lbl)lbl.textContent='';}
}
/* Context + kubeconfig only apply to a live (--live) scan; disable them for the mock cluster. */
function toggleLive(){const mock=$('#mock').value==='1';['#ctx','#kubeconfig','#kubeconfigfile'].forEach(id=>{const el=$(id);if(el)el.disabled=mock;});}
/* Namespace only applies when the Scope is "namespace"; disable it otherwise. */
function toggleScope(){const ns=$('#ns');if(ns)ns.disabled=($('#scope')?$('#scope').value:'cluster')!=='namespace';}
function wireScan(){toggleLive();toggleScope();}
async function runScan(){
  const btn=$('#run'),msg=$('#scanmsg');btn.disabled=true;msg.textContent='Running scan…';
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
      ? `<div class='scanwarn'><b>${d.evidence_ok===false?'Scan incomplete, cluster not read'
          :'Partial coverage'}</b><ul>${d.warnings.slice(0,10).map(w=>`<li>${esc(w)}</li>`).join('')}</ul></div>`
      : '';
    msg.innerHTML='Scan saved, '+esc(d.rating)+', '+d.risk+'/10, '+d.total_findings+' findings. Refreshing…'+warn;
    setTimeout(()=>location.reload(),warn?2600:800);
  }catch(e){msg.textContent='Error: '+e;btn.disabled=false;}
}
/* ---- export (PDF / Excel) ---- */
let _toastTimer=null;
function showToast(msg, ms, err){
  let t=$('#toast'); if(!t){ t=document.createElement('div'); t.id='toast'; document.body.appendChild(t); }
  t.textContent=msg; t.className='toast show'+(err?' err':'');
  if(_toastTimer) clearTimeout(_toastTimer);
  if(ms) _toastTimer=setTimeout(()=>{ t.className='toast'; }, ms);
}
async function _download(sid, fmt){
  const label=fmt==='xlsx'?'Excel':'PDF';
  showToast('Generating '+label+' report…', 0);   // persistent until resolved
  try{
    const r=await fetch('/api/report/'+encodeURIComponent(sid)+'?format='+fmt);
    if(!r.ok){ let m='Export failed'; try{ m=(await r.json()).error||m; }catch(e){} showToast(m, 5000, true); return false; }
    const blob=await r.blob(), url=URL.createObjectURL(blob), a=document.createElement('a');
    a.href=url; a.download='k8smatrixwarden-'+sid+'.'+fmt; document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
    showToast(label+' report downloaded', 2500);
    return true;
  }catch(e){ showToast('Export failed: '+esc(e.message), 5000, true); return false; }
}
async function exportReport(kind){
  document.querySelectorAll('details.exp').forEach(d=>d.open=false);   // close the menu
  const sid=D.scan.scan_id;
  if(kind==='both'){ if(await _download(sid,'pdf')) await _download(sid,'xlsx'); return; }
  await _download(sid, kind);
}
const res=f=>{const r=f.resource||{};return r.kind+'/'+r.name+(r.namespace?' ('+r.namespace+')':'')};
// Humanise a domain/shard identifier for display only (workload_pod_security -> Workload
// Pod Security). Filtering/sorting still use the raw owning_shard value.
const domainName=s=>String(s||'').replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
boot();
</script>
"""
