"""
Cluster inventory: what is in the cluster, in the terms an engineer asks about it.

The scan already reads every object for its rules; this keeps a compact, secret-free summary
of each one so the dashboard can answer "what is running, where, is it healthy, is it exposed,
who can do what" without a second trip to the cluster. Rows carry NO manifests, no ConfigMap
values and no Secret data (Secrets are listed from metadata only).

Sections: nodes, namespaces, workloads, services, ingresses, policies, identities, bindings,
config, storage, events, extensions. Each is capped; the true total is kept beside it.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional

from . import netpol
from .evidence import Evidence
from .topology import _controller_index, _owner

ROW_CAP = 1500
_SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
HOT = {"privileged", "host-network", "host-pid", "host-ipc", "host-path"}
_SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease"}


def _md(o):
    return o.get("metadata", {}) or {}


def _ns(o):
    return _md(o).get("namespace")


def _worst(sevs):
    return min(sevs, key=_SEV.index) if sevs else ""


def _issue_index(findings):
    """node-id -> {n, worst}: distinct rules per owning resource, so one flaw reported on a
    Deployment, its ReplicaSet and its Pod is one issue."""
    seen: dict[str, dict] = {}
    for f in findings:
        r = f.resource
        for cand in (f"{r.namespace}/{r.owner_kind}/{r.owner_name}", f"{r.namespace}/{r.kind}/{r.name}"):
            if r.name:
                seen.setdefault(cand, {})[f.rule_id] = f.severity.label
    return {k: {"n": len(v), "worst": _worst(list(v.values()))} for k, v in seen.items()}


def _pod_state(pod):
    """(phase, problem) where problem is the reason an engineer would grep for."""
    st = pod.get("status", {}) or {}
    phase = st.get("phase") or "Unknown"
    problem = ""
    for c in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or []):
        s = c.get("state", {}) or {}
        w = s.get("waiting")
        if w and w.get("reason") not in (None, "PodInitializing", "ContainerCreating"):
            problem = w["reason"]
            break
        t = s.get("terminated")
        if t and t.get("exitCode") not in (0, None):
            problem = t.get("reason") or f"exit {t['exitCode']}"
    if not problem and phase == "Pending":
        for c in st.get("conditions") or []:
            if c.get("type") == "PodScheduled" and c.get("status") == "False":
                problem = c.get("reason") or "Unschedulable"
    if not problem and phase == "Failed":
        problem = st.get("reason") or "Failed"
    return phase, problem


def _flags(spec):
    out = []
    cs = Evidence.containers({"spec": spec})
    if any(Evidence.dig(c, "securityContext.privileged") is True for c in cs):
        out.append("privileged")
    for k, label in (("hostNetwork", "host-network"), ("hostPID", "host-pid"), ("hostIPC", "host-ipc")):
        if spec.get(k) is True:
            out.append(label)
    if any((v.get("hostPath") or {}).get("path") for v in spec.get("volumes") or []):
        out.append("host-path")
    if any(not Evidence.dig(c, "resources.limits") for c in cs):
        out.append("no-limits")
    if any(str(c.get("image", "")).endswith(":latest") or ":" not in str(c.get("image", "")).split("/")[-1]
           for c in cs):
        out.append("mutable-image")
    return out


def _container_facts(pod):
    """Per-container security facts an engineer checks first, read off the spec."""
    spec = pod.get("spec", {}) or {}
    psc = spec.get("securityContext", {}) or {}
    out = []
    for c in Evidence.containers(pod):
        sc = c.get("securityContext", {}) or {}
        caps = (sc.get("capabilities") or {})
        nonroot = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
        uid = sc.get("runAsUser", psc.get("runAsUser"))
        out.append({
            "name": c.get("name", ""), "image": c.get("image", ""),
            "privileged": sc.get("privileged") is True,
            "root": not (nonroot is True or (uid not in (None, 0))),
            "read_only_fs": sc.get("readOnlyRootFilesystem") is True,
            "priv_esc": sc.get("allowPrivilegeEscalation") is not False,
            "caps_add": sorted(caps.get("add") or []), "caps_drop_all": "ALL" in (caps.get("drop") or []),
            "limits": bool(Evidence.dig(c, "resources.limits")),
            "ports": [p.get("containerPort") for p in c.get("ports") or []],
            "host_ports": [p.get("hostPort") for p in c.get("ports") or [] if p.get("hostPort")]})
    return out


def _refs(pod):
    """(secrets, configmaps, claims) a pod mounts or injects, by name."""
    sec, cm, pvc = set(), set(), set()
    spec = pod.get("spec", {}) or {}
    for c in Evidence.containers(pod):
        for e in c.get("env") or []:
            vf = e.get("valueFrom") or {}
            if vf.get("secretKeyRef"):
                sec.add(vf["secretKeyRef"].get("name"))
            if vf.get("configMapKeyRef"):
                cm.add(vf["configMapKeyRef"].get("name"))
        for ef in c.get("envFrom") or []:
            if ef.get("secretRef"):
                sec.add(ef["secretRef"].get("name"))
            if ef.get("configMapRef"):
                cm.add(ef["configMapRef"].get("name"))
    for v in spec.get("volumes") or []:
        if v.get("secret"):
            sec.add(v["secret"].get("secretName"))
        if v.get("configMap"):
            cm.add(v["configMap"].get("name"))
        if v.get("persistentVolumeClaim"):
            pvc.add(v["persistentVolumeClaim"].get("claimName"))
    for ips in spec.get("imagePullSecrets") or []:
        sec.add(ips.get("name"))
    return sec - {None}, cm - {None}, pvc - {None}


def _role_summary(rules):
    """What a role lets its holder do, in the words a reviewer scans for."""
    flags = []
    for r in rules or []:
        verbs, res = set(r.get("verbs") or []), set(r.get("resources") or [])
        if "*" in verbs and "*" in res:
            flags.append("everything")
        elif "*" in verbs:
            flags.append("any verb")
        if ("secrets" in res or "*" in res) and verbs & {"get", "list", "*"}:
            flags.append("reads secrets")
        if verbs & {"bind", "escalate", "impersonate"}:
            flags.append("escalates")
        if ("pods/exec" in res) and verbs & {"create", "*"}:
            flags.append("exec into pods")
        if res & {"clusterroles", "clusterrolebindings", "rolebindings"} and verbs & {"create", "update", "patch", "*"}:
            flags.append("edits RBAC")
    return sorted(set(flags))


def _image_rows(evidence: Evidence, groups: dict, findings: tuple = ()) -> list:
    """One row per running image: where it runs and what Grype found in it. Empty when no
    image scan ran, so the dashboard can say "not scanned" instead of showing clean."""
    from .image_scan import _digest_of
    scans = {}
    for it in evidence.get("ImageVulnerability", all_scopes=True):
        sp = it.get("spec", {}) or {}
        scans[sp.get("digest") or sp.get("image")] = sp
    if not scans:
        return []
    rows: dict = {}
    for (ns, kind, name), ps in groups.items():
        for p in ps:
            st = p.get("status", {}) or {}
            for cs in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or []):
                key = _digest_of(cs.get("imageID", "")) or cs.get("image", "")
                if not cs.get("image"):
                    continue
                r = rows.setdefault(key, {"image": cs["image"], "digest": _digest_of(cs.get("imageID", "")),
                                          "workloads": set()})
                r["workloads"].add(f"{ns}/{kind}/{name}")
    # How the scoring engine ranked the findings raised on each image: its priority score, and
    # whether the pod is reachable from the Internet or runs as an identity that reaches secrets.
    hits: dict = defaultdict(list)
    for f in findings:
        if f.rule_id == "workload-image-vulnerabilities":
            ev = f.evidence or {}
            hits[ev.get("digest") or ev.get("image")].append(f)
    out = []
    for key, r in rows.items():
        fs = hits.get(key) or hits.get(r["image"]) or []
        sp = scans.get(key) or scans.get(r["image"]) or {}
        ms = sp.get("matches", []) or []
        counts = Counter(m["severity"] for m in ms)
        order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
        ms = sorted(ms, key=lambda m: (not m["knownExploited"], order.index(m["severity"]), -m["epss"]))
        out.append({"name": r["image"], "image": r["image"], "digest": r["digest"],
                    "workloads": sorted(r["workloads"]), "scanned": bool(sp) and "error" not in sp,
                    "error": sp.get("error", ""), "counts": dict(counts), "total": len(ms),
                    "fixable": sum(1 for m in ms if m["fixState"] == "fixed"),
                    "kev": sum(1 for m in ms if m["knownExploited"]), "top": ms[:15],
                    "dbBuilt": sp.get("dbBuilt", ""),
                    "score": round(max((f.score for f in fs), default=0.0), 1),
                    "internet": any("ingress" in (f.exploitable_by or []) for f in fs),
                    "identity": any("rbac-escalation" in (f.exploitable_by or []) for f in fs)})
    out.sort(key=lambda i: (-i["score"], -i["kev"], -i["counts"].get("Critical", 0)))
    return out


def build_cluster_inventory(evidence: Evidence, findings: list, topology: Optional[dict] = None) -> dict:
    topology = topology or {}
    issues = _issue_index(findings)
    tnodes = {n["id"]: n for n in topology.get("nodes", [])}
    exposed = set((topology.get("summary") or {}).get("internet_exposed", []))

    pods = evidence.get("Pod", all_scopes=True)
    replicasets = _controller_index(evidence.get("ReplicaSet", all_scopes=True))
    jobs = _controller_index(evidence.get("Job", all_scopes=True))

    # ---- workloads: pods grouped by controller, enriched from the controller's spec -----------
    groups: dict[tuple, list] = defaultdict(list)
    for p in pods:
        groups[(_ns(p),) + _owner(p, replicasets, jobs)].append(p)
    controllers = {}
    for kind in ("Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job"):
        for c in evidence.get(kind, all_scopes=True):
            controllers[(_ns(c), kind, _md(c).get("name"))] = c
    all_policies = evidence.get("NetworkPolicy", all_scopes=True)
    all_ns = evidence.get("Namespace", all_scopes=True)
    all_svcs = evidence.get("Service", all_scopes=True)
    all_ings = evidence.get("Ingress", all_scopes=True)
    workloads, pod_rows = [], []
    keys = set(groups) | {k for k in controllers if k[1] == "CronJob"}
    refs_by_pod: dict[tuple, tuple] = {}
    for (ns, kind, name) in sorted(keys, key=lambda k: (k[0] or "", k[1], k[2] or "")):
        ps = groups.get((ns, kind, name), [])
        ctrl = controllers.get((ns, kind, name))
        spec = Evidence.pod_spec(ctrl) if ctrl else (Evidence.pod_spec(ps[0]) if ps else {})
        phases, problems, restarts, ready = Counter(), Counter(), 0, 0
        for p in ps:
            ph, prob = _pod_state(p)
            phases[ph] += 1
            if prob:
                problems[prob] += 1
            st = p.get("status", {}) or {}
            restarts += sum(c.get("restartCount", 0) for c in st.get("containerStatuses") or [])
            if ph == "Running" and all(c.get("ready") for c in st.get("containerStatuses") or [{"ready": True}]):
                ready += 1
        desired = None
        if ctrl is not None:
            cs = ctrl.get("spec", {}) or {}
            desired = cs.get("replicas") if kind in ("Deployment", "StatefulSet") else None
        nid = f"{ns}/{kind}/{name}"
        tn = tnodes.get(nid, {})
        labels = _md(ctrl).get("labels", {}) if ctrl else (_md(ps[0]).get("labels", {}) if ps else {})
        row = {"id": nid, "kind": kind, "name": name, "namespace": ns, "pods": len(ps), "ready": ready,
               "desired": desired, "phases": dict(phases), "problems": dict(problems), "restarts": restarts,
               "images": sorted({c.get("image", "") for c in Evidence.containers({"spec": spec})}),
               "sa": spec.get("serviceAccountName") or ("default" if ps else ""),
               "flags": _flags(spec), "internet": nid in exposed,
               "ingress_policy": tn.get("ingress", ""), "ips": tn.get("ips", []),
               "issues": issues.get(nid, {"n": 0, "worst": ""}),
               "managed_by": (labels or {}).get("app.kubernetes.io/managed-by", ""),
               "created": _md(ctrl).get("creationTimestamp") if ctrl else _md(ps[0]).get("creationTimestamp") if ps else ""}
        plabels = (_md(ps[0]).get("labels", {}) or {}) if ps else (labels or {})
        ing_ev = netpol.evaluate(all_policies, ns, plabels, "Ingress", all_ns)
        egr_ev = netpol.evaluate(all_policies, ns, plabels, "Egress", all_ns)
        row["egress_policy"] = egr_ev["status"]
        row["ingress_policies"], row["egress_policies"] = ing_ev.get("policies", []), egr_ev.get("policies", [])
        row["services"] = sorted(_md(sv).get("name") for sv in all_svcs if _ns(sv) == ns
                                 and (sv.get("spec", {}) or {}).get("selector")
                                 and all(plabels.get(k) == v for k, v in sv["spec"]["selector"].items()))
        row["ingresses"] = sorted(_md(ig).get("name") for ig in all_ings if _ns(ig) == ns and any(
            sv in row["services"] for sv in
            [((pp.get("backend") or {}).get("service") or {}).get("name") for rr in (ig.get("spec") or {}).get("rules") or []
             for pp in (rr.get("http") or {}).get("paths") or []]))
        row["containers"] = _container_facts(ps[0]) if ps else (
            _container_facts({"spec": spec}) if spec else [])
        row["pod_names"] = sorted(_md(p).get("name") for p in ps)
        if kind == "CronJob" and ctrl:
            cs = ctrl.get("spec", {}) or {}
            row["schedule"] = cs.get("schedule", "")
            row["suspended"] = bool(cs.get("suspend"))
        workloads.append(row)
        for p in ps:
            refs_by_pod[(ns, _md(p).get("name"))] = _refs(p)
            ph, prob = _pod_state(p)
            st = p.get("status", {}) or {}
            sec_r, cm_r, pvc_r = refs_by_pod[(ns, _md(p).get("name"))]
            pod_rows.append({
                "id": f"{ns}/Pod/{_md(p).get('name')}", "name": _md(p).get("name"), "namespace": ns,
                "workload": nid, "phase": ph, "problem": prob,
                "restarts": sum(c.get("restartCount", 0) for c in st.get("containerStatuses") or []),
                "node": (p.get("spec", {}) or {}).get("nodeName", ""), "ip": st.get("podIP", ""),
                "sa": (p.get("spec", {}) or {}).get("serviceAccountName", ""),
                "containers": _container_facts(p), "flags": _flags(p.get("spec", {}) or {}),
                "secrets": sorted(sec_r), "configmaps": sorted(cm_r), "claims": sorted(pvc_r),
                "host_paths": sorted((v.get("hostPath") or {}).get("path") for v in (p.get("spec", {}) or {}).get("volumes") or []
                                     if (v.get("hostPath") or {}).get("path")),
                "ingress_policy": row["ingress_policy"], "egress_policy": row["egress_policy"],
                "ingress_policies": row["ingress_policies"], "egress_policies": row["egress_policies"],
                "services": row["services"], "ingresses": row["ingresses"], "internet": row["internet"],
                "issues": row["issues"], "created": _md(p).get("creationTimestamp", "")})

    used = {"secrets": Counter(), "configmaps": Counter(), "pvc": Counter()}
    for (ns, _), (sec, cm, pvc) in refs_by_pod.items():
        for n in sec:
            used["secrets"][(ns, n)] += 1
        for n in cm:
            used["configmaps"][(ns, n)] += 1
        for n in pvc:
            used["pvc"][(ns, n)] += 1

    # ---- nodes ---------------------------------------------------------------------------------------
    per_node = Counter((p.get("spec", {}) or {}).get("nodeName") for p in pods)
    nodes = []
    for n in evidence.get("Node", all_scopes=True):
        st, labels = n.get("status", {}) or {}, _md(n).get("labels", {}) or {}
        conds = {c.get("type"): c.get("status") for c in st.get("conditions") or []}
        info = st.get("nodeInfo", {}) or {}
        nodes.append({
            "name": _md(n).get("name"),
            "roles": sorted(k.split("/", 1)[1] or "control-plane" for k in labels if k.startswith("node-role.kubernetes.io/")) or ["worker"],
            "ready": conds.get("Ready") == "True",
            "pressure": [t for t in ("MemoryPressure", "DiskPressure", "PIDPressure") if conds.get(t) == "True"],
            "kubelet": info.get("kubeletVersion", ""), "os": info.get("osImage", ""),
            "kernel": info.get("kernelVersion", ""), "runtime": info.get("containerRuntimeVersion", ""),
            "cpu": (st.get("capacity") or {}).get("cpu", ""), "memory": (st.get("capacity") or {}).get("memory", ""),
            "pods_cap": (st.get("allocatable") or {}).get("pods", ""),
            "pods": per_node.get(_md(n).get("name"), 0),
            "taints": [f"{t.get('key')}:{t.get('effect')}" for t in (n.get("spec", {}) or {}).get("taints") or []],
            "ip": next((a.get("address") for a in st.get("addresses") or [] if a.get("type") == "InternalIP"), ""),
            "created": _md(n).get("creationTimestamp", "")})

    # ---- namespaces -------------------------------------------------------------------------------------
    policies = evidence.get("NetworkPolicy", all_scopes=True)
    svcs = evidence.get("Service", all_scopes=True)
    quotas = {_ns(q) for q in evidence.get("ResourceQuota", all_scopes=True)}
    limits = {_ns(q) for q in evidence.get("LimitRange", all_scopes=True)}
    wl_by_ns, issue_by_ns = Counter(), Counter()
    worst_by_ns: dict[str, list] = defaultdict(list)
    for w in workloads:
        wl_by_ns[w["namespace"]] += 1
    for nid, v in issues.items():
        ns = nid.split("/", 1)[0] if nid.count("/") >= 2 else ""
        if ns:
            issue_by_ns[ns] += v["n"]
            worst_by_ns[ns].append(v["worst"])
    namespaces = []
    for n in evidence.get("Namespace", all_scopes=True):
        name, labels = _md(n).get("name"), _md(n).get("labels", {}) or {}
        namespaces.append({
            "name": name, "phase": (n.get("status") or {}).get("phase", "Active"),
            "workloads": wl_by_ns.get(name, 0), "pods": sum(1 for p in pods if _ns(p) == name),
            "services": sum(1 for s in svcs if _ns(s) == name),
            "policies": sum(1 for p in policies if _ns(p) == name),
            "psa": labels.get("pod-security.kubernetes.io/enforce", ""),
            "quota": name in quotas, "limits": name in limits,
            "system": name in _SYSTEM_NS,
            "issues": {"n": issue_by_ns.get(name, 0), "worst": _worst(worst_by_ns.get(name, []))},
            "exposed": sum(1 for w in workloads if w["namespace"] == name and w["internet"]),
            "open_ingress": sum(1 for w in workloads if w["namespace"] == name and w["ingress_policy"] in ("unrestricted", "allow-all", "partial", "unknown")),
            "open_egress": sum(1 for w in workloads if w["namespace"] == name and w.get("egress_policy") in ("unrestricted", "allow-all", "partial", "unknown")),
            "unhealthy": sum(1 for w in workloads if w["namespace"] == name and (w["problems"] or (w["desired"] and w["ready"] < w["desired"]))),
            "privileged": sum(1 for w in workloads if w["namespace"] == name and any(f in HOT for f in w["flags"])),
            "ingresses": sum(1 for i in all_ings if _ns(i) == name),
            "psa_warn": labels.get("pod-security.kubernetes.io/warn", ""),
            "created": _md(n).get("creationTimestamp", "")})

    # ---- services, ingresses, policies ------------------------------------------------------------------------
    backs = defaultdict(list)
    for e in topology.get("edges", []):
        if e.get("kind") == "routes-to" and e["from"] in tnodes and tnodes[e["from"]].get("type") == "service":
            backs[e["from"]].append(e["to"])
    ready_eps = Counter()
    for sl in evidence.get("EndpointSlice", all_scopes=True):
        svc = (_md(sl).get("labels", {}) or {}).get("kubernetes.io/service-name")
        ready_eps[(_ns(sl), svc)] += sum(1 for e in sl.get("endpoints") or []
                                         if (e.get("conditions") or {}).get("ready", True))
    services = []
    for s in svcs:
        sp, nm, ns = s.get("spec", {}) or {}, _md(s).get("name"), _ns(s)
        sid = f"{ns}/Service/{nm}"
        lb = [(i.get("ip") or i.get("hostname")) for i in ((s.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []]
        services.append({
            "id": sid, "name": nm, "namespace": ns, "type": sp.get("type", "ClusterIP"),
            "cluster_ip": sp.get("clusterIP", ""), "external": sp.get("type") in ("NodePort", "LoadBalancer"),
            "ports": [f"{p.get('port')}{'→' + str(p.get('targetPort')) if p.get('targetPort') not in (None, p.get('port')) else ''}"
                      f"{'/' + p['protocol'] if p.get('protocol', 'TCP') != 'TCP' else ''}"
                      f"{' (node ' + str(p['nodePort']) + ')' if p.get('nodePort') else ''}" for p in sp.get("ports") or []],
            "selector": ", ".join(f"{k}={v}" for k, v in (sp.get("selector") or {}).items()),
            "endpoints": ready_eps.get((ns, nm)), "backends": sorted(backs.get(sid, [])),
            "address": ", ".join(x for x in lb if x), "source_ranges": sp.get("loadBalancerSourceRanges") or [],
            "issues": issues.get(sid, {"n": 0, "worst": ""}), "created": _md(s).get("creationTimestamp", "")})
    ingresses = []
    for i in evidence.get("Ingress", all_scopes=True):
        sp, ns, nm = i.get("spec", {}) or {}, _ns(i), _md(i).get("name")
        be = {((p.get("backend") or {}).get("service") or {}).get("name") for r in sp.get("rules") or []
              for p in (r.get("http") or {}).get("paths") or []}
        be.add(((sp.get("defaultBackend") or {}).get("service") or {}).get("name"))
        ingresses.append({
            "id": f"{ns}/Ingress/{nm}", "name": nm, "namespace": ns,
            "class": sp.get("ingressClassName") or (_md(i).get("annotations", {}) or {}).get("kubernetes.io/ingress.class", ""),
            "hosts": sorted({r.get("host") or "*" for r in sp.get("rules") or []}),
            "tls": [h for t in sp.get("tls") or [] for h in (t.get("hosts") or ["*"])],
            "backends": sorted(x for x in be if x),
            "address": ", ".join((x.get("ip") or x.get("hostname") or "") for x in ((i.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []),
            "issues": issues.get(f"{ns}/Ingress/{nm}", {"n": 0, "worst": ""}), "created": _md(i).get("creationTimestamp", "")})
    pol_rows = []
    for p in policies:
        sp = p.get("spec", {}) or {}
        types = sp.get("policyTypes") or ["Ingress"]
        sel = sp.get("podSelector") or {}
        deny = [t for t in types if not sp.get(t.lower())]
        pol_rows.append({
            "name": _md(p).get("name"), "namespace": _ns(p),
            "selects": ", ".join(f"{k}={v}" for k, v in (sel.get("matchLabels") or {}).items()) or ("all pods" if not sel.get("matchExpressions") else "expression"),
            "types": types, "ingress_rules": len(sp.get("ingress") or []), "egress_rules": len(sp.get("egress") or []),
            "effect": ("default-deny " + "+".join(t.lower() for t in deny)) if deny and not sel.get("matchLabels") else
                      ("isolates selected pods (" + "+".join(t.lower() for t in types) + ")"),
            "created": _md(p).get("creationTimestamp", "")})

    # ---- identities and bindings ------------------------------------------------------------------------------------
    roles = {("ClusterRole", None, _md(r).get("name")): r for r in evidence.get("ClusterRole", all_scopes=True)}
    roles.update({("Role", _ns(r), _md(r).get("name")): r for r in evidence.get("Role", all_scopes=True)})
    sa_use = Counter((w["namespace"], w["sa"]) for w in workloads if w["sa"])
    bindings, bound = [], defaultdict(list)
    for kind in ("ClusterRoleBinding", "RoleBinding"):
        for b in evidence.get(kind, all_scopes=True):
            rr, ns = b.get("roleRef", {}) or {}, _ns(b)
            role = roles.get((rr.get("kind"), None if rr.get("kind") == "ClusterRole" else ns, rr.get("name")))
            caps = _role_summary((role or {}).get("rules")) if role else (["everything"] if rr.get("name") == "cluster-admin" else [])
            subs = [f"{s.get('kind')} {(s.get('namespace') + '/') if s.get('namespace') else ''}{s.get('name')}" for s in b.get("subjects") or []]
            for s in b.get("subjects") or []:
                if s.get("kind") == "ServiceAccount":
                    bound[(s.get("namespace") or ns, s.get("name"))].append(f"{rr.get('name')}{'' if kind == 'ClusterRoleBinding' else ' (ns)'}")
            bindings.append({"kind": kind, "name": _md(b).get("name"), "namespace": ns,
                             "role": f"{rr.get('kind')}/{rr.get('name')}", "subjects": subs, "grants": caps,
                             "builtin": (_md(b).get("labels", {}) or {}).get("kubernetes.io/bootstrapping") == "rbac-defaults"
                                        or (_md(b).get("name") or "").startswith("system:"),
                             "created": _md(b).get("creationTimestamp", "")})
    identities = []
    for sa in evidence.get("ServiceAccount", all_scopes=True):
        ns, nm = _ns(sa), _md(sa).get("name")
        roles_held = sorted(set(bound.get((ns, nm), [])))
        identities.append({"name": nm, "namespace": ns, "used_by": sa_use.get((ns, nm), 0),
                           "automount": (sa.get("automountServiceAccountToken") is not False),
                           "roles": roles_held, "admin": any(r.startswith("cluster-admin") for r in roles_held),
                           "created": _md(sa).get("creationTimestamp", "")})

    # ---- config, storage, events, extensions --------------------------------------------------------------------------
    config = []
    for kind, bucket in (("ConfigMap", "configmaps"), ("Secret", "secrets")):
        for o in evidence.get(kind, all_scopes=True):
            ns, nm = _ns(o), _md(o).get("name")
            config.append({"kind": kind, "name": nm, "namespace": ns,
                           "keys": len(o.get("data") or {}) if kind == "ConfigMap" else None,
                           "type": o.get("type", "") if kind == "Secret" else "",
                           "used_by": used[bucket].get((ns, nm), 0), "created": _md(o).get("creationTimestamp", "")})
    storage = []
    for c in evidence.get("PersistentVolumeClaim", all_scopes=True):
        sp = c.get("spec", {}) or {}
        storage.append({"kind": "PVC", "name": _md(c).get("name"), "namespace": _ns(c),
                        "status": (c.get("status") or {}).get("phase", ""), "size": ((c.get("status") or {}).get("capacity") or {}).get("storage", "") or ((sp.get("resources") or {}).get("requests") or {}).get("storage", ""),
                        "class": sp.get("storageClassName", ""), "volume": sp.get("volumeName", ""),
                        "used_by": used["pvc"].get((_ns(c), _md(c).get("name")), 0)})
    for v in evidence.get("PersistentVolume", all_scopes=True):
        sp = v.get("spec", {}) or {}
        storage.append({"kind": "PV", "name": _md(v).get("name"), "namespace": None,
                        "status": (v.get("status") or {}).get("phase", ""), "size": (sp.get("capacity") or {}).get("storage", ""),
                        "class": sp.get("storageClassName", ""), "volume": "hostPath" if sp.get("hostPath") else "",
                        "used_by": 1 if (sp.get("claimRef") or {}).get("name") else 0})
    for c in evidence.get("StorageClass", all_scopes=True):
        storage.append({"kind": "StorageClass", "name": _md(c).get("name"), "namespace": None, "status": "",
                        "size": "", "class": c.get("provisioner", ""), "volume": c.get("reclaimPolicy", ""), "used_by": 0})
    events = []
    for e in evidence.get("Event", all_scopes=True):
        if e.get("type") != "Warning":
            continue
        reg = e.get("regarding") or e.get("involvedObject") or {}
        events.append({"namespace": reg.get("namespace") or _ns(e), "object": f"{reg.get('kind', '')}/{reg.get('name', '')}",
                       "reason": e.get("reason", ""), "message": (e.get("note") or e.get("message") or "")[:300],
                       "count": (e.get("series") or {}).get("count") or e.get("deprecatedCount") or e.get("count") or 1,
                       "last": e.get("eventTime") or e.get("deprecatedLastTimestamp") or e.get("lastTimestamp") or _md(e).get("creationTimestamp", "")})
    events.sort(key=lambda x: x["last"] or "", reverse=True)
    extensions = [{"kind": "CRD", "name": _md(c).get("name"), "group": (c.get("spec") or {}).get("group", ""),
                   "scope": (c.get("spec") or {}).get("scope", ""),
                   "versions": [v.get("name") for v in (c.get("spec") or {}).get("versions") or []]}
                  for c in evidence.get("CustomResourceDefinition", all_scopes=True)]
    extensions += [{"kind": "APIService", "name": _md(a).get("name"), "group": (a.get("spec") or {}).get("group", ""),
                    "scope": "aggregated", "versions": [(a.get("spec") or {}).get("version", "")]}
                   for a in evidence.get("APIService", all_scopes=True) if (a.get("spec") or {}).get("service")]

    images = _image_rows(evidence, groups, tuple(findings))
    sections = {"nodes": nodes, "namespaces": namespaces, "workloads": workloads, "pods": pod_rows, "services": services,
                "ingresses": ingresses, "policies": pol_rows, "identities": identities, "bindings": bindings,
                "config": config, "storage": storage, "events": events, "extensions": extensions,
                "images": images}
    totals = {k: len(v) for k, v in sections.items()}
    sections = {k: v[:ROW_CAP] for k, v in sections.items()}

    # ---- what needs attention, worst first ----------------------------------------------------------------------------
    attn = []
    bad = [n for n in nodes if not n["ready"] or n["pressure"]]
    if bad:
        attn.append({"sev": "CRITICAL", "section": "nodes", "title": f"{len(bad)} node(s) not healthy",
                     "detail": ", ".join(n["name"] for n in bad[:4])})
    probs = Counter()
    for w in workloads:
        for r, c in w["problems"].items():
            probs[r] += c
    if probs:
        attn.append({"sev": "HIGH", "section": "workloads", "filter": "problems",
                     "title": f"{sum(probs.values())} pod(s) failing to run",
                     "detail": ", ".join(f"{c}× {r}" for r, c in probs.most_common(4))})
    short = [w for w in workloads if w["desired"] and w["ready"] < w["desired"]]
    if short:
        attn.append({"sev": "MEDIUM", "section": "workloads", "filter": "problems",
                     "title": f"{len(short)} workload(s) below desired replicas",
                     "detail": ", ".join(f"{w['name']} {w['ready']}/{w['desired']}" for w in short[:4])})
    open_ns = [n["name"] for n in namespaces if not n["system"] and not n["policies"]]
    if open_ns:
        attn.append({"sev": "MEDIUM", "section": "namespaces", "title": f"{len(open_ns)} namespace(s) with no NetworkPolicy",
                     "detail": ", ".join(open_ns[:5])})
    if totals["events"]:
        top = Counter(e["reason"] for e in events)
        attn.append({"sev": "LOW", "section": "events", "title": f"{totals['events']} recent warning event(s)",
                     "detail": ", ".join(f"{c}× {r}" for r, c in top.most_common(4))})
    kev = [i for i in images if i["kev"]]
    if kev:
        attn.append({"sev": "CRITICAL", "section": "images", "filter": "kev",
                     "title": f"{len(kev)} running image(s) with a known-exploited vulnerability",
                     "detail": ", ".join(i["image"].split("/")[-1] for i in kev[:4])})
    attn.sort(key=lambda a: _SEV.index(a["sev"]))

    phases = Counter()
    for w in workloads:
        phases.update(w["phases"])
    summary = {"pods": len(pods), "pod_phases": dict(phases), "nodes_ready": sum(1 for n in nodes if n["ready"]),
               "workload_kinds": dict(Counter(w["kind"] for w in workloads)),
               "version": next((n["kubelet"] for n in nodes if n["kubelet"]), ""),
               "totals": totals}
    return {"summary": summary, "attention": attn, "sections": sections, "capped": {k: t for k, t in totals.items() if t > ROW_CAP}}
