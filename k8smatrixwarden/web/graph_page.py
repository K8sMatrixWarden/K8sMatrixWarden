"""
Security Graph: the cluster as one explorable graph.

Namespaces are boxes, workloads are pies of their issue severities, and the lines are only
what the cluster's own objects establish: exposure (Internet -> Ingress/Service -> workload),
NetworkPolicy-allowed pod-to-pod flows, and the identity chain a workload runs as
(ServiceAccount -> binding -> role -> capability). Selecting an attack path lights up the chain.

Server side builds the data (the graph, the per-node issues and risk factors, the attack
paths); the browser only lays it out. Cytoscape is vendored, so the page works offline.
"""
from __future__ import annotations

import json
import re

from ..core.attack_path import resource_paths
from ..core.reporting import _esc
from ..core.remediation import fix_for

_QUOTED = re.compile(r"'([^']+)'")
_CONTROLLERS = {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job"}


def _worst(sevs):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return min(sevs, key=order.index) if sevs else ""


def _first(text):
    return text.split(". ")[0].rstrip(".") + "."


def _breaks(ids, p):
    """Where this route can be cut, in path order. Each is a change an engineer can make; the
    cheapest is usually the first (stop it being reachable) or the last (shrink what the
    identity can do). Derived from the hops and the rules on the route, nothing invented."""
    out, seen = [], set()
    rules = {x["rule_id"]: x["title"] for x in p["supporting_findings"]}
    for nid, kind, name in ids:
        if kind == "Service":
            out.append({"at": nid, "do": "Stop exposing it: set the Service to ClusterIP, or add loadBalancerSourceRanges / an authenticating gateway."})
        elif kind == "Ingress":
            out.append({"at": nid, "do": "Require TLS and authentication on the Ingress, or remove the route."})
        elif kind in ("Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod"):
            for rid, title in rules.items():
                if rid in seen or not fix_for(rid):
                    continue
                seen.add(rid)
                out.append({"at": nid, "do": f"{title}: {_first(fix_for(rid)['how'])}", "rule": rid})
        elif kind == "ServiceAccount":
            out.append({"at": nid, "do": "Give the workload its own ServiceAccount with no token mount unless it calls the API."})
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            out.append({"at": nid, "do": f"Remove or narrow binding '{name}': kubectl delete {kind.lower()} {name}"})
    return out


def build_graph(result) -> dict:
    """The page's data: nodes, edges, per-node issues and factors, attack paths."""
    topo = result.topology or {}
    nodes = {n["id"]: dict(n) for n in topo.get("nodes", [])}
    edges = [dict(e) for e in topo.get("edges", [])]
    exposed = set((topo.get("summary") or {}).get("internet_exposed", []))

    # ---- issues per node, and the risk factors a reader scans for first -----------------
    issues: dict[str, list] = {}
    factors: dict[str, set] = {}
    for f in result.findings:
        r = f.resource
        for cand in (f"{r.namespace}/{r.owner_kind}/{r.owner_name}",
                     f"{r.namespace}/{r.kind}/{r.name}"):
            if cand in nodes:
                # the same weakness on a Deployment, its ReplicaSet and its Pod is one issue
                if any(i["r"] == f.rule_id for i in issues.get(cand, [])):
                    break
                issues.setdefault(cand, []).append(
                    {"t": f.title, "s": f.severity.label, "m": f.message, "r": f.rule_id,
                     "k": str(r)})
                fs = factors.setdefault(cand, set())
                if f.rule_id == "workload-privileged-container":
                    fs.add("privileged")
                if f.rule_id == "workload-image-vulnerabilities":
                    kev = any(m.get("knownExploited") for m in (f.evidence or {}).get("top", []))
                    fs.add("known-exploited CVE" if kev else "vulnerable image")
                if "rbac-escalation" in (f.exploitable_by or []):
                    fs.add("cluster-admin identity")
                break
    for nid in exposed:
        factors.setdefault(nid, set()).add("internet-exposed")
    for nid, n in nodes.items():
        if n.get("type") == "workload" and n.get("ingress") in ("unrestricted", "allow-all"):
            factors.setdefault(nid, set()).add("no ingress policy")

    # ---- attack paths, mapped onto graph nodes ------------------------------------------
    raw = resource_paths(result.findings, None, limit=200)
    ctrl_names = {s["node"] for p in raw for s in p["steps"] if s["node_type"] in _CONTROLLERS}
    paths, seen = [], set()
    for p in raw:
        ns = p.get("namespace") or ""
        ids, ok = [], True
        for s in p["steps"]:
            kind, name = s["node_type"], s["node"]
            if kind in ("ReplicaSet", "Pod") and any(name.startswith(c + "-") for c in ctrl_names):
                ok = False                       # the same route, reported on a generated object
                break
            if kind == "Internet":
                nid = "internet"
            elif kind == "Service":
                m = _QUOTED.search(name)
                nid = f"{ns}/Service/{m.group(1) if m else name}"
            elif kind == "Ingress":
                nid = f"{ns}/Ingress/{name}"
            elif kind in ("ClusterRoleBinding", "ClusterRole", "Capability", "RoleBinding", "Role"):
                nid = f"id:{kind}:{name}"
            else:
                nid = f"{ns}/{kind}/{name}"
            ids.append((nid, kind, name))
        sig = tuple(i[0] for i in ids)
        if not ok or sig in seen or len(ids) < 2:
            continue
        seen.add(sig)
        for nid, kind, name in ids:
            if nid not in nodes:                 # identity hops are not in the topology
                nodes[nid] = {"id": nid, "type": "identity", "kind": kind, "name": name,
                              "namespace": ns if kind == "ServiceAccount" else None}
        for a, b in zip(ids, ids[1:]):
            if not any(e["from"] == a[0] and e["to"] == b[0] for e in edges):
                edges.append({"from": a[0], "to": b[0], "kind": "identity",
                              "evidence": "attack path"})
        wl = next((i[0] for i in ids if i[1] in _CONTROLLERS or i[1] == "Pod"), None)
        sevs = [x["severity"] for x in p["supporting_findings"]]
        paths.append({"id": len(paths), "nodes": [i[0] for i in ids],
                      "severity": p["worst_severity"], "internet": p["internet_reachable"],
                      "issues": len(p["supporting_findings"]), "workload": wl,
                      "confidence": p.get("confidence", ""), "summary": p.get("summary", ""),
                      "entry": p["entry_point"]["kind"], "target": p["target"]["name"],
                      "target_detail": p["target"].get("detail", ""),
                      "breaks": _breaks(ids, p),
                      "steps": [{"n": i[2], "t": i[1], "why": st.get("reason", "")}
                                for i, st in zip(ids, p["steps"])],
                      "findings": [{"t": x["title"], "s": x["severity"], "k": x["resource"]}
                                   for x in p["supporting_findings"]],
                      "title": " → ".join(i[2] if i[1] != "Internet" else "Internet"
                                          for i in ids if i[1] not in
                                          ("ClusterRoleBinding", "RoleBinding")),
                      "worst": _worst(sevs)})
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    paths.sort(key=lambda x: (not x["internet"], rank.get(x["severity"], 9), -x["issues"]))
    for i, p in enumerate(paths):
        p["id"] = i

    for nid, n in nodes.items():
        n["issues"] = len(issues.get(nid, []))
        n["worst"] = _worst([i["s"] for i in issues.get(nid, [])])
        n["factors"] = sorted(factors.get(nid, []))
    return {"nodes": list(nodes.values()), "edges": edges, "issues": issues, "paths": paths,
            "summary": topo.get("summary", {}), "notes": topo.get("notes", [])}


def graph_page(result, layout, topbar, css):
    data = build_graph(result)
    blob = json.dumps(data).replace("</", "<\\/")
    s = data["summary"]
    body = (topbar("graph")
            + f"<div class='crumbs'><a href='/'>Dashboard</a> › Security graph · "
              f"{_esc(result.scan_id)}</div>"
            + f"""
<div class='sg-head'><h1>Attack paths</h1>
  <span class='sg-sub'>{s.get('workloads', 0)} workloads · {s.get('services', 0)} services ·
  {len(data['paths'])} routes. Pick a route to see how it is walked; the graph is the surrounding context.</span></div>
<div class='sg-k'>
  <div class='mc-t crit'><b>{len(data['paths'])}</b><span>routes found</span><small>each hop read off a real object</small></div>
  <div class='mc-t crit'><b>{sum(1 for x in data['paths'] if x['internet'])}</b><span>reachable from the Internet</span><small>no foothold needed</small></div>
  <div class='mc-t warn'><b>{sum(1 for x in data['paths'] if x['target'] in ('read-secrets', 'cluster-admin') or 'secret' in x['target'])}</b><span>end at secrets or cluster-admin</span><small>the identity can go further</small></div>
  <div class='mc-t'><b>{len(s.get('internet_exposed', []))}</b><span>workloads exposed</span><small>reachable via Service or Ingress</small></div>
</div>
<div class='sg-bar' role='toolbar' aria-label='Graph filters'>
  <input id='sg-q' type='search' placeholder='Search name, namespace, rule…' autocomplete='off' aria-label='Search'>
  <label class='sg-c'><input type='checkbox' id='f-exp'> Internet-exposed</label>
  <label class='sg-c'><input type='checkbox' id='f-crit'> Critical only</label>
  <label class='sg-c'><input type='checkbox' id='f-ok'> Hide clean</label>
  <label class='sg-c'><input type='checkbox' id='f-id' checked> Identity</label>
  <div class='sg-seg' role='group' aria-label='Layout'>
    <button id='lay-g' class='on' aria-pressed='true'>Grouped</button>
    <button id='lay-f' aria-pressed='false'>Flow</button></div>
  <details class='sg-dd'><summary>Namespaces</summary><div id='sg-ns'></div></details>
  <details class='sg-dd'><summary>Legend</summary><ul class='sg-leg'>
    <li><i class='d' style='background:#d1242f'></i>Critical <i class='d' style='background:#bc4c00'></i>High
      <i class='d' style='background:#bf8700'></i>Medium <i class='d' style='background:#1a7f37'></i>Low</li>
    <li><i class='l' style='background:#e8590c'></i>Internet exposure</li>
    <li><i class='l' style='background:#7048e8'></i>Identity chain</li>
    <li><i class='l dash'></i>Allowed by NetworkPolicy</li></ul></details>
</div>
<div class='sg'>
  <section class='sg-main'>
    <div class='sg-ptable' id='sg-paths' aria-label='Attack paths'></div>
    <div id='sg-chain' class='sg-chain' aria-live='polite'></div>
    <div id='sg-graph' role='img' aria-label='Security graph'></div>
    <div class='sg-tools'>
      <button id='z-in' aria-label='Zoom in'>+</button><button id='z-out' aria-label='Zoom out'>−</button>
      <button id='z-fit' aria-label='Fit to screen'>⤢</button>
    </div>
  </section>
  <aside class='sg-detail' id='sg-detail' aria-live='polite'>
    <div class='sg-empty'>Select a route above, or a node, to see its issues, risk factors and connections.</div>
  </aside>
</div>
<script src='/vendor/cytoscape.min.js'></script>
<script>const G={blob};{GRAPH_JS}</script>""")
    return layout("K8sMatrixWarden · Security graph", body, extra_css=css + GRAPH_CSS)


GRAPH_CSS = """
.sg-head h1{font-size:1.25rem;margin:.1rem 0 .15rem}.sg-sub{color:var(--muted);font-size:.84rem;display:block;margin-bottom:.8rem}
.sg-bar{display:flex;align-items:center;gap:.5rem 1rem;flex-wrap:wrap;margin:0 0 .8rem;padding:.55rem .75rem;background:var(--card);
 border:1px solid var(--bd);border-radius:12px}
#sg-q{flex:1 1 200px;min-width:160px;padding:.45rem .65rem;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg);font-size:.85rem}
.sg-c{display:flex;gap:.4rem;align-items:center;font-size:.82rem;cursor:pointer;white-space:nowrap}
.sg-seg{display:flex;border:1px solid var(--bd);border-radius:8px;overflow:hidden}
.sg-seg button{padding:.38rem .8rem;border:0;background:var(--card);color:var(--muted);font-size:.8rem;cursor:pointer}
.sg-seg button.on{background:var(--accent);color:#fff}
.sg-dd{position:relative}.sg-dd summary{cursor:pointer;font-size:.82rem;padding:.38rem .7rem;border:1px solid var(--bd);border-radius:8px;list-style:none;color:var(--fg)}
.sg-dd summary::-webkit-details-marker{display:none}
.sg-dd>div,.sg-dd>ul{position:absolute;right:0;top:calc(100% + .35rem);z-index:20;min-width:220px;max-height:320px;overflow:auto;background:var(--card);
 border:1px solid var(--bd);border-radius:10px;padding:.6rem .75rem;box-shadow:0 8px 24px rgba(16,24,40,.18);margin:0;list-style:none}
.sg{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:1rem;align-items:start}
@media(max-width:1200px){.sg{grid-template-columns:1fr}}
.sg-detail{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:1rem;position:sticky;top:.6rem;max-height:calc(100vh - 1.2rem);overflow:auto}
@media(max-width:1200px){.sg-detail{position:static;max-height:none}}
#sg-ns label{display:flex;justify-content:space-between;gap:.4rem;font-size:.82rem;padding:.18rem 0;cursor:pointer}
#sg-ns span{color:var(--muted);font-variant-numeric:tabular-nums}
.sg-leg{font-size:.78rem;color:var(--muted)}.sg-leg li{margin:.3rem 0;display:flex;align-items:center;gap:.35rem;flex-wrap:wrap}
.sg-leg .d{width:.7rem;height:.7rem;border-radius:50%;display:inline-block}
.sg-leg .l{width:1.4rem;height:3px;display:inline-block;border-radius:2px}
.sg-leg .l.dash{background:repeating-linear-gradient(90deg,#777 0 4px,transparent 4px 7px)}
.sg-main{position:relative;min-width:0}
#sg-graph{height:calc(100vh - 17rem);min-height:460px;border:1px solid var(--bd);border-radius:12px;
 background:var(--sunken) radial-gradient(circle,rgba(120,130,150,.28) 1.2px,transparent 1.4px) 0 0/26px 26px}
.sg-k{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.7rem;margin:0 0 .8rem}
.sg-k .mc-t.crit b{color:var(--crit)}.sg-k .mc-t.warn b{color:var(--med)}
.sg-ptable{max-height:250px;overflow:auto;margin:0 0 .7rem;border:1px solid var(--bd);border-radius:12px;background:var(--card)}
.sg-ptable table{width:100%;border-collapse:collapse;font-size:.82rem}
.sg-ptable th{position:sticky;top:0;background:var(--card);text-align:left;font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:.4rem .6rem;border-bottom:1px solid var(--bd)}
.sg-ptable td{padding:.45rem .6rem;border-bottom:1px solid var(--bd);vertical-align:middle}
.sg-ptable tr.row{cursor:pointer}.sg-ptable tr.row:hover{background:var(--sunken)}.sg-ptable tr.row.on{background:var(--sunken);box-shadow:inset 3px 0 0 var(--accent)}
.sg-ptable small{color:var(--muted)}
.sg-brk{border-left:3px solid var(--low);background:var(--sunken);padding:.45rem .65rem;margin:.4rem 0;border-radius:0 8px 8px 0;font-size:.8rem;cursor:pointer}
.sg-brk b{display:block;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.1rem}
.sg-path{flex:0 0 auto;max-width:300px;text-align:left;border:1px solid var(--bd);border-left:4px solid var(--info);
 border-radius:10px;background:var(--card);color:var(--fg);padding:.55rem .7rem;cursor:pointer;font-size:.78rem}
.sg-path.on{outline:2px solid var(--accent)}
.sg-path b{display:block;font-size:.72rem;color:var(--muted);margin-bottom:.15rem;text-transform:uppercase;letter-spacing:.05em}
.sg-path span{display:block;line-height:1.35;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.sg-chain{display:none;align-items:flex-start;gap:0;overflow-x:auto;padding:.9rem 1rem;margin:0 0 .7rem;
 background:var(--card);border:1px solid var(--bd);border-radius:12px}
.sg-chain.on{display:flex}
.sg-step{flex:0 0 auto;width:118px;text-align:center;cursor:pointer;background:none;border:0;color:var(--fg);padding:0 .2rem}
.sg-step .ic{width:46px;height:46px;border-radius:50%;margin:0 auto .35rem;border:2.5px solid var(--info);background:#fff;
 display:flex;align-items:center;justify-content:center;position:relative}
.sg-step .ic img{width:24px;height:24px}
.sg-step .bd{position:absolute;top:-6px;right:-8px;min-width:19px;height:19px;border-radius:10px;color:#fff;font-size:.68rem;
 font-weight:700;display:flex;align-items:center;justify-content:center;padding:0 4px}
.sg-step b{display:block;font-size:.76rem;word-break:break-word;line-height:1.25}
.sg-step small{display:block;font-size:.66rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.sg-arrow{flex:0 0 auto;align-self:center;margin-top:-1.6rem;color:var(--muted);font-size:1.3rem;width:26px;text-align:center}
.sg-arrow.hot{color:var(--crit)}
.sg-mini{display:inline-flex;align-items:center;gap:2px;margin:.1rem 0 .25rem}
.sg-mini img{width:16px;height:16px;padding:2px;border-radius:50%;background:#fff;border:1.5px solid var(--bd)}
.sg-tools{position:absolute;right:.7rem;bottom:.7rem;display:flex;flex-direction:column;gap:.3rem}
.sg-tools button{width:2rem;height:2rem;border-radius:8px;border:1px solid var(--bd);background:var(--card);color:var(--fg);cursor:pointer;font-size:1rem}
.sg-empty{color:var(--muted);font-size:.85rem;line-height:1.5}
.sg-detail h2{font-size:1rem;margin:.1rem 0 .15rem;word-break:break-word}
.sg-detail .k{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.sg-chips{display:flex;gap:.3rem;flex-wrap:wrap;margin:.6rem 0}
.sg-chip{font-size:.72rem;padding:.18rem .5rem;border-radius:999px;border:1px solid var(--bd);background:var(--sunken)}
.sg-chip.hot{border-color:var(--crit);color:var(--crit)}
.sg-iss{border-left:3px solid var(--info);padding:.35rem .55rem;margin:.4rem 0;background:var(--sunken);border-radius:0 8px 8px 0;font-size:.8rem}
.sg-iss b{display:block}.sg-iss small{color:var(--muted);display:block;margin-top:.15rem}
.sg-links{font-size:.8rem;color:var(--muted);margin-top:.7rem}.sg-links code{font-size:.74rem}
"""

GRAPH_JS = r"""
window.addEventListener('load',function(){
  const el=document.getElementById('sg-graph');
  if(!el||typeof cytoscape==='undefined') return;
  const body=()=>getComputedStyle(document.body).color||'#222';
  const SEV={CRITICAL:'#d1242f',HIGH:'#bc4c00',MEDIUM:'#bf8700',LOW:'#1a7f37',INFO:'#6c757d'};
  const ORD=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const svg=(c,d)=>'data:image/svg+xml;utf8,'+encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`);
  const GL={
    internet:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    ingress:'<circle cx="12" cy="12" r="9"/><path d="M8 12h8M13 8l4 4-4 4"/>',
    service:'<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
    workload:'<path d="M12 3l8 4v10l-8 4-8-4V7z"/><path d="M4 7l8 4 8-4M12 11v10"/>',
    ServiceAccount:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-7 8-7s8 3 8 7"/>',
    ClusterRole:'<path d="M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z"/>',
    Role:'<path d="M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z"/>',
    Capability:'<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    ClusterRoleBinding:'<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>'};
  const glyph=n=>GL[n.type==='identity'?n.kind:n.type]||GL.workload;
  const fg=()=>body();
  const nodeColor=n=>n.type==='internet'?'#2969ff':n.type==='ingress'?'#e8590c':n.type==='service'?'#2969ff':
    n.type==='identity'?'#7048e8':(n.worst?SEV[n.worst]:'#1a7f37');
  const ringColor=n=>n.type==='workload'?(n.factors.includes('internet-exposed')?'#d1242f':'#9aa3b2'):nodeColor(n);
  const caption=n=>n.type==='workload'?`${n.kind||'Workload'}${n.pods>1?' ×'+n.pods:''}`:
    n.type==='service'?'Service · '+(n.service_type||''):n.type==='identity'?n.kind:
    n.type==='ingress'?'Ingress':'';
  const nsOf=n=>n.namespace||null;

  // ---- elements ------------------------------------------------------------------------
  const nsSet=new Map();
  G.nodes.forEach(n=>{const ns=nsOf(n); if(ns) nsSet.set(ns,(nsSet.get(ns)||0)+1)});
  const els=[];
  nsSet.forEach((c,ns)=>els.push({data:{id:'ns:'+ns,label:ns,type:'namespace'}}));
  G.nodes.forEach(n=>{
    const sev={}; (G.issues[n.id]||[]).forEach(i=>sev[i.s]=(sev[i.s]||0)+1);
    const d={id:n.id,type:n.type,label:n.name+(caption(n)?'\n'+caption(n):''),color:nodeColor(n),ring:ringColor(n),
      img:svg(nodeColor(n),GL[n.type==='identity'?n.kind:n.type]||GL.workload),ns:nsOf(n),
      issues:n.issues,worst:n.worst||'',exposed:n.factors.includes('internet-exposed')?1:0,
      size:n.type==='internet'?70:n.type==='workload'?Math.min(30+Math.sqrt(n.issues||0)*7,64):40,
      text:(n.name+' '+(n.namespace||'')+' '+(G.issues[n.id]||[]).map(i=>i.r+' '+i.t).join(' ')).toLowerCase()};
    // pie slices, one per severity present: the node IS its own severity mix
    ORD.forEach((s,i)=>{d['p'+(i+1)]=sev[s]?sev[s]:0});
    if(nsOf(n)) d.parent='ns:'+nsOf(n);
    els.push({data:d});
  });
  const ids=new Set(G.nodes.map(n=>n.id));
  G.edges.filter(e=>ids.has(e.from)&&ids.has(e.to)).forEach((e,i)=>
    els.push({data:{id:'e'+i,source:e.from,target:e.to,kind:e.kind,tip:e.kind+' · '+e.evidence}}));

  // each slice is that severity's share of the node's own issues
  const pieStyle={'pie-size':'100%'};
  ORD.forEach((s,i)=>{pieStyle['pie-'+(i+1)+'-background-color']=SEV[s]});
  const sliceSize=i=>n=>{const t=n.data('issues')||0;return t?100*n.data('p'+(i+1))/t:0};
  const style=[
    {selector:'node',style:{'width':'data(size)','height':'data(size)','background-color':'#fff','background-opacity':.96,
      'border-width':2.5,'border-color':'data(ring)','background-image':'data(img)','background-fit':'none',
      'background-width':'46%','background-height':'46%','label':'data(label)','font-size':10,'font-weight':600,
      'color':fg(),'text-wrap':'wrap','text-max-width':'130px','text-valign':'bottom','text-margin-y':5,'line-height':1.25}},
    {selector:'node[type="workload"][issues>0]',style:Object.assign({'background-opacity':1},pieStyle,
      (function(){const o={};ORD.forEach((s,i)=>{o['pie-'+(i+1)+'-background-size']=sliceSize(i)});return o})())},
    {selector:'node[type="internet"]',style:{'shape':'diamond','font-size':12,'font-weight':700}},
    {selector:'node[type="service"]',style:{'shape':'round-rectangle'}},
    {selector:'node[type="ingress"]',style:{'shape':'hexagon'}},
    {selector:'node[type="identity"]',style:{'shape':'round-rectangle','border-style':'dashed'}},
    {selector:'node[?exposed]',style:{'border-width':4}},
    {selector:':parent',style:{'padding':22,'shape':'round-rectangle'}},
    {selector:'node[type="namespace"]',style:{'background-color':'#7882a0','background-opacity':.08,
      'border-width':1.5,'border-style':'dashed','border-color':'rgba(120,130,160,.55)','label':'data(label)',
      'text-valign':'top','text-halign':'center','font-size':12,'font-weight':700,'color':fg(),'background-image':'none',
      'text-margin-y':-4}},
    {selector:'edge',style:{'width':1.6,'line-color':'rgba(110,120,200,.5)','curve-style':'bezier','target-arrow-shape':'triangle',
      'target-arrow-color':'rgba(110,120,200,.5)','arrow-scale':.8}},
    {selector:'edge[kind="exposes"]',style:{'line-color':'#e8590c','target-arrow-color':'#e8590c','width':2.4}},
    {selector:'edge[kind="identity"]',style:{'line-color':'#7048e8','target-arrow-color':'#7048e8','width':2,'display':'none'}},
    {selector:'edge[kind="identity"].hit, edge[kind="identity"].show',style:{'display':'element'}},
    {selector:'edge[kind="allowed"]',style:{'line-style':'dashed','line-color':'rgba(110,110,110,.7)','target-arrow-color':'rgba(110,110,110,.7)'}},
    {selector:'.dim',style:{'opacity':.12}},
    {selector:'.hit',style:{'opacity':1}},
    {selector:'edge.hit',style:{'width':4,'line-color':'#d1242f','target-arrow-color':'#d1242f','z-index':20}},
    {selector:'node.hit',style:{'border-width':4,'border-color':'#d1242f','z-index':20}},
    {selector:':selected',style:{'border-width':4,'border-color':'#2969ff'}}];
  const cy=cytoscape({container:el,elements:els,style,wheelSensitivity:.25,minZoom:.05,maxZoom:3,boxSelectionEnabled:false});
  window.sgCy=cy;

  // ---- layouts -------------------------------------------------------------------------
  let mode='grouped';
  function runLayout(){
    if(mode==='grouped'){
      cy.nodes('[ns]').forEach(n=>{ if(n.data('type')!=='namespace') n.move({parent:'ns:'+n.data('ns')}) });
      // Namespaces are boxes packed left to right; inside each, nodes sit in a grid with the
      // exposed and worst ones first. A force layout scatters unconnected workloads.
      const W=150,H=130,MAXW=1700,groups={};
      cy.nodes().filter(n=>n.data('type')!=='namespace'&&!n.hasClass('gone')&&n.data('ns')).forEach(n=>
        (groups[n.data('ns')]=groups[n.data('ns')]||[]).push(n));
      const rank=n=>(n.data('exposed')?-1e6:0)-(n.data('issues')||0)-(ORD.length-ORD.indexOf(n.data('worst')||'INFO'))*1e3;
      let x=300,y=0,rowH=0,maxX=0;
      Object.keys(groups).sort((a,b)=>groups[b].length-groups[a].length).forEach(ns=>{
        const list=groups[ns].sort((a,b)=>rank(a)-rank(b));
        const cols=Math.max(2,Math.ceil(Math.sqrt(list.length*1.2))),rows=Math.ceil(list.length/cols);
        const w=cols*W+60,h=rows*H+80;
        if(x>300&&x+w>MAXW){x=300;y+=rowH+60;rowH=0;}
        list.forEach((n,i)=>n.position({x:x+30+(i%cols)*W+W/2,y:y+70+Math.floor(i/cols)*H}));
        x+=w+50;rowH=Math.max(rowH,h);maxX=Math.max(maxX,x);});
      // identity hops that belong to no namespace (bindings, roles, capabilities): a 3-wide grid
      const idn=cy.nodes().filter(n=>n.data('type')==='identity'&&!n.data('ns')&&!n.hasClass('gone'));
      idn.forEach((n,i)=>n.position({x:maxX+80+(i%3)*W,y:70+Math.floor(i/3)*(H-30)}));
      const net=cy.nodes('[type="internet"]'); net.position({x:0,y:(y+rowH)/2});
      cy.layout({name:'preset',padding:30}).run();
    }else{
      cy.nodes().forEach(n=>{ if(n.data('type')!=='namespace') n.move({parent:null}) });
      cy.nodes('[type="namespace"]').style('display','none');
      const COL={internet:0,ingress:1,service:2,workload:3,identity:4};
      const cols={};
      cy.nodes().filter(n=>n.data('type')!=='namespace'&&!n.hasClass('gone')).forEach(n=>{
        const c=n.data('type')==='identity'&&n.data('label').includes('Capability')?5:COL[n.data('type')];
        (cols[c]=cols[c]||[]).push(n)});
      Object.entries(cols).forEach(([c,list])=>{
        list.sort((a,b)=>(b.data('issues')||0)-(a.data('issues')||0));
        list.forEach((n,i)=>n.position({x:c*230,y:(i-(list.length-1)/2)*82}));});
      cy.layout({name:'preset',padding:30}).run();
    }
    if(mode==='grouped') cy.nodes('[type="namespace"]').style('display','element');
    cy.fit(undefined,40);
  }

  // ---- filters ------------------------------------------------------------------------
  const nsOn=new Set(nsSet.keys());
  const q=document.getElementById('sg-q');
  function apply(){
    const term=q.value.trim().toLowerCase();
    const exp=document.getElementById('f-exp').checked, crit=document.getElementById('f-crit').checked,
      idn=document.getElementById('f-id').checked, ok=document.getElementById('f-ok').checked;
    cy.batch(()=>{
      cy.nodes().forEach(n=>{
        const t=n.data('type'); if(t==='namespace') return;
        let show=true;
        if(n.data('ns')&&!nsOn.has(n.data('ns'))) show=false;
        if(t==='identity'&&!idn) show=false;
        if(t==='workload'){
          if(exp&&!n.data('exposed')) show=false;
          if(crit&&n.data('worst')!=='CRITICAL') show=false;
          if(ok&&!n.data('issues')) show=false;
        }
        if(term&&t!=='internet'&&n.data('text').indexOf(term)<0) show=false;
        n.toggleClass('gone',!show); n.style('display',show?'element':'none');
      });
      cy.nodes('[type="namespace"]').forEach(p=>{
        const any=p.children().filter(c=>!c.hasClass('gone')).length>0;
        p.style('display',any?'element':'none');});
    });
  }
  ['f-exp','f-crit','f-id','f-ok'].forEach(i=>document.getElementById(i).addEventListener('change',()=>{apply();runLayout()}));
  q.addEventListener('input',()=>{apply()});
  q.addEventListener('change',()=>{runLayout()});
  const nsBox=document.getElementById('sg-ns');
  [...nsSet.keys()].sort().forEach(ns=>{
    const l=document.createElement('label');
    l.innerHTML=`<span style="color:var(--fg)"><input type="checkbox" checked> ${ns.replace(/[<&>]/g,'')}</span><span>${nsSet.get(ns)}</span>`;
    l.querySelector('input').addEventListener('change',e=>{e.target.checked?nsOn.add(ns):nsOn.delete(ns);apply();runLayout()});
    nsBox.appendChild(l);});
  const setMode=m=>{mode=m;document.getElementById('lay-g').classList.toggle('on',m==='grouped');
    document.getElementById('lay-f').classList.toggle('on',m==='flow');
    document.getElementById('lay-g').setAttribute('aria-pressed',m==='grouped');
    document.getElementById('lay-f').setAttribute('aria-pressed',m==='flow');
    if(m==='flow') mode='flow'; apply(); runLayout();};
  document.getElementById('lay-g').onclick=()=>setMode('grouped');
  document.getElementById('lay-f').onclick=()=>setMode('flow');
  document.getElementById('z-in').onclick=()=>cy.zoom({level:cy.zoom()*1.25,renderedPosition:{x:el.clientWidth/2,y:el.clientHeight/2}});
  document.getElementById('z-out').onclick=()=>cy.zoom({level:cy.zoom()/1.25,renderedPosition:{x:el.clientWidth/2,y:el.clientHeight/2}});
  document.getElementById('z-fit').onclick=()=>cy.fit(undefined,40);

  // ---- the selected path as a readable chain (the graph itself is for context) ----------
  const chain=document.getElementById('sg-chain');
  const eh=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  function drawChain(p){
    if(!p){chain.classList.remove('on');chain.innerHTML='';return;}
    chain.innerHTML=p.nodes.map((id,i)=>{
      const n=G.nodes.find(x=>x.id===id)||{name:id,type:'workload',factors:[]};
      const col=nodeColor(n), kind=n.type==='identity'?n.kind:(n.kind&&n.type==='workload'?n.kind:n.type);
      const crit=(G.issues[id]||[]).filter(x=>x.s==='CRITICAL').length, tot=(G.issues[id]||[]).length;
      const bd=tot?`<span class='bd' style='background:${crit?SEV.CRITICAL:SEV[n.worst]||SEV.MEDIUM}'>${tot}</span>`:'';
      const nm=n.type==='internet'?'Internet':n.name;
      return (i?`<span class='sg-arrow ${p.internet?'hot':''}'>→</span>`:'')+
        `<button type='button' class='sg-step' data-id="${eh(id)}"><div class='ic' style='border-color:${col}'>
          <img alt="" src="${svg(col,GL[n.type==='identity'?n.kind:n.type]||GL.workload)}">${bd}</div>
          <b>${eh(nm)}</b><small>${eh(kind)}</small></button>`}).join('');
    chain.classList.add('on');
    chain.querySelectorAll('.sg-step').forEach(b=>b.onclick=()=>{
      const n=cy.getElementById(b.dataset.id); if(n.length){cy.$(':selected').unselect();n.select();n.emit('tap');}});
  }

  const det0=document.getElementById('sg-detail');
  function pathDetail(p){
    if(!p){ det0.innerHTML="<div class='sg-empty'>Select a route above, or a node, to see its issues, risk factors and connections.</div>"; return; }
    det0.innerHTML=`<div class='k'>${p.internet?'Internet-reachable route':'Route from a foothold'}${p.confidence?' · '+eh(p.confidence):''}</div>
      <h2>${eh(p.title)}</h2>
      <div class='sg-chips'><span class='sg-chip hot'>${eh(p.severity)}</span><span class='sg-chip'>${p.issues} issue${p.issues===1?'':'s'}</span></div>
      <div class='k' style='margin-top:.6rem'>How it is walked</div>
      ${(p.steps||[]).map((st,i)=>`<div class='sg-iss' style='border-left-color:var(--accent)'><b>${i+1}. ${eh(st.t==='Internet'?'Internet':st.n)} <small style='display:inline'>${eh(st.t)}</small></b>${eh(st.why)}</div>`).join('')}
      ${(p.breaks||[]).length?`<div class='k' style='margin-top:.9rem'>Cut this route</div>`+p.breaks.map((b,i)=>`<div class='sg-brk' data-at="${eh(b.at)}"><b>${i+1}. at ${eh((G.nodes.find(x=>x.id===b.at)||{}).name||b.at)}</b>${eh(b.do)}</div>`).join(''):''}
      <div class='k' style='margin-top:.9rem'>Issues on this route</div>
      ${(p.findings||[]).map(f=>`<div class='sg-iss' style='border-left-color:${SEV[f.s]||'#6c757d'}'><b>${eh(f.t)}</b><small>${eh(f.s)} · ${eh(f.k)}</small></div>`).join('')||"<div class='sg-empty'>None recorded.</div>"}`;
  }

  det0.addEventListener('click',e=>{const b=e.target.closest('.sg-brk'); if(!b) return; const n=cy.getElementById(b.dataset.at); if(n.length){cy.animate({center:{eles:n},zoom:1},{duration:250});}});

  // ---- attack paths ---------------------------------------------------------------------
  const pbox=document.getElementById('sg-paths');
  let activePath=null;
  function showPath(p){
    cy.elements().removeClass('hit dim');
    if(p){
      const on=new Set(p.nodes);
      cy.elements().addClass('dim');
      cy.nodes().filter(n=>on.has(n.id())).addClass('hit').removeClass('dim');
      cy.nodes('[type="namespace"]').removeClass('dim');
      cy.edges().filter(e=>on.has(e.data('source'))&&on.has(e.data('target'))).addClass('hit').removeClass('dim');
      cy.fit(cy.nodes().filter(n=>on.has(n.id())),90);
    }
    pbox.querySelectorAll('tr.row').forEach(tr=>tr.classList.toggle('on',!!p&&G.paths[+tr.dataset.i]===p));
    activePath=p; drawChain(p); pathDetail(p);
  }
  if(!G.paths.length) pbox.innerHTML="<span class='sg-empty'>No attack paths found in this scan.</span>";
  if(G.paths.length){
    const rows=G.paths.map((p,ix)=>{
      const mini=p.nodes.map(id=>{const n=G.nodes.find(x=>x.id===id)||{};
        return `<img alt="" src="${svg(nodeColor(n),GL[n.type==='identity'?n.kind:n.type]||GL.workload)}">`}).join('<i style="color:var(--muted);font-style:normal">›</i>');
      return `<tr class='row' tabindex='0' data-i='${ix}'><td><span class='sev ${p.severity}'>${p.severity}</span></td>
        <td><div class='sg-mini'>${mini}</div><div><small></small></div></td>
        <td>${p.internet?"<span class='sg-chip hot'>Internet</span>":"<span class='sg-chip'>needs foothold</span>"}</td>
        <td><b>${eh(p.target)}</b></td><td>${p.issues}</td></tr>`}).join('');
    pbox.innerHTML=`<table><thead><tr><th>Severity</th><th>Route</th><th>Entry</th><th>Reaches</th><th>Issues</th></tr></thead><tbody>${rows}</tbody></table>`;
    pbox.querySelectorAll('tr.row').forEach(tr=>{const p=G.paths[+tr.dataset.i]; tr.querySelector('small').textContent=p.title;
      const go=()=>showPath(activePath===p?null:p); tr.onclick=go; tr.onkeydown=e=>{if(e.key==='Enter')go()};});
  }

  // ---- detail panel -----------------------------------------------------------------------
  const det=document.getElementById('sg-detail');
  const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  cy.on('tap','node',e=>{
    const d=e.target.data(); if(d.type==='namespace') return;
    cy.edges('.show').removeClass('show'); e.target.connectedEdges().addClass('show');
    const n=G.nodes.find(x=>x.id===d.id)||{}; const iss=(G.issues[d.id]||[]).slice().sort((a,b)=>ORD.indexOf(a.s)-ORD.indexOf(b.s));
    const conn=e.target.connectedEdges().map(x=>{const o=x.source().id()===d.id?x.target():x.source();
      return (x.source().id()===d.id?'→ ':'← ')+o.data('label').split('\n')[0]+' ('+x.data('kind')+')'});
    const chips=(n.factors||[]).map(f=>`<span class='sg-chip ${/exposed|admin|privileged/.test(f)?'hot':''}'>${esc(f)}</span>`).join('')||"<span class='sg-chip'>no risk factors</span>";
    det.innerHTML=`<div class='k'>${esc(n.type==='identity'?n.kind:n.type)}${n.namespace?' · '+esc(n.namespace):''}</div>
      <h2>${esc(n.name)}</h2>
      <div class='sg-chips'>${chips}</div>
      ${n.type==='workload'?`<div class='sg-links'>${n.pods} pod(s) · ingress <b>${esc(n.ingress)}</b> · egress <b>${esc(n.egress)}</b>${(n.ips||[]).length?'<br>pod IPs <code>'+esc(n.ips.join(', '))+'</code>':''}</div>`:''}
      <div class='k' style='margin-top:.9rem'>${iss.length} issue${iss.length===1?'':'s'}</div>
      ${iss.slice(0,40).map(i=>`<div class='sg-iss' style='border-left-color:${SEV[i.s]}'><b>${esc(i.t)}</b>${esc(i.m)}<small>${esc(i.s)} · ${esc(i.r)}</small></div>`).join('')||"<div class='sg-empty'>No issues on this resource.</div>"}
      ${iss.length>40?`<div class='sg-links'>… ${iss.length-40} more</div>`:''}
      <div class='k' style='margin-top:.9rem'>Connections</div>
      <div class='sg-links'>${conn.map(esc).join('<br>')||'none'}</div>`;
  });
  cy.on('tap',e=>{ if(e.target===cy){ showPath(null); } });

  const tip=document.createElement('div');tip.className='atk-tip';el.style.position='relative';el.appendChild(tip);
  cy.on('mouseover','node,edge',e=>{const t=e.target.data('tip')||e.target.data('label'); if(!t||e.target.data('type')==='namespace')return;
    const p=e.renderedPosition||e.target.renderedMidpoint();tip.textContent=String(t).replace('\n',' · ');
    tip.style.left=(p.x+14)+'px';tip.style.top=(p.y-8)+'px';tip.style.display='block';});
  cy.on('mouseout','node,edge',()=>{tip.style.display='none'});
  new MutationObserver(()=>cy.style().selector('node').style('color',fg()).update())
    .observe(document.documentElement,{attributes:true});
  // a big cluster would take a force layout minutes; start in flow mode past this size
  if(G.nodes.length>600){ setMode('flow'); } else { apply(); runLayout(); }
  if(G.paths.length) showPath(G.paths[0]);
});
"""
