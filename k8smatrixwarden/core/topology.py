"""
Network topology: who can talk to whom, read off the cluster's own objects.

    internet -> ingress -> service -> workload          (exposure edges)
    workload -> workload                                (allowed by NetworkPolicy)

Every edge cites its evidence. Nothing is inferred beyond what Services, EndpointSlices,
Ingresses and NetworkPolicies state; a constraint netpol.py cannot evaluate yields no edge
and a node status of `partial`/`unknown`, never a guess.

Workload -> workload edges are emitted only where the destination's ingress is governed by a
policy (`restricted`): those are the flows the cluster declares. A destination with no
governing policy accepts every pod, so it is listed in `summary.open_workloads` instead of as
an N x N wall of edges.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from . import netpol
from .evidence import Evidence

#: Pod-to-pod edges are always computed and counted; only the list handed to the UI is
#: capped, so a huge cluster keeps an exact `edges_total` without an unreadable graph.
MAX_EDGES_LISTED = 5000

_EXTERNAL_TYPES = {"NodePort", "LoadBalancer"}


def _labels(pod: dict) -> dict:
    return (pod.get("metadata", {}) or {}).get("labels", {}) or {}


def _owner(pod: dict, replicasets: dict, jobs: dict) -> tuple[str, str]:
    """(kind, name) of the workload a pod belongs to, one hop past ReplicaSet / Job."""
    md = pod.get("metadata", {}) or {}
    ns = md.get("namespace")
    refs = md.get("ownerReferences") or []
    ref = next((r for r in refs if r.get("controller")), refs[0] if refs else None)
    if not ref:
        return "Pod", md.get("name", "?")
    kind, name = ref.get("kind", "Pod"), ref.get("name", "?")
    hop = {"ReplicaSet": replicasets, "Job": jobs}.get(kind)
    if hop is not None:
        up = hop.get((ns, name))
        if up:
            return up
    return kind, name


def _nid(kind: str, ns: Optional[str], name: str) -> str:
    return f"{ns}/{kind}/{name}" if ns else f"{kind}/{name}"


def _controller_index(items: list[dict]) -> dict:
    out = {}
    for r in items:
        md = r.get("metadata", {}) or {}
        refs = md.get("ownerReferences") or []
        if refs:
            out[(md.get("namespace"), md.get("name"))] = (refs[0].get("kind"), refs[0].get("name"))
    return out


def _pod_ips(pod: dict) -> list[str]:
    st = pod.get("status", {}) or {}
    ips = [p.get("ip") for p in st.get("podIPs") or []] + [st.get("podIP")]
    return sorted({i for i in ips if i})


def _in_block(ip: str, cidr: str, excepted: list) -> Optional[bool]:
    try:
        addr = ipaddress.ip_address(ip)
        if addr not in ipaddress.ip_network(cidr, strict=False):
            return False
        return not any(addr in ipaddress.ip_network(x, strict=False) for x in excepted)
    except ValueError:
        return None


def _peer_matches(peer: dict, ns: Optional[str], labels: dict,
                  ips: list) -> Optional[bool]:
    """Does this policy peer admit a pod of (ns, labels, ips)? None = cannot tell."""
    if peer.get("allow_all") or peer.get("type") == "any":
        return True
    if peer.get("type") == "ipBlock":
        # A pod with no recorded IP (not yet scheduled) cannot be placed in a CIDR.
        results = [_in_block(i, peer.get("cidr", ""), peer.get("except") or []) for i in ips]
        if any(r is True for r in results):
            return True
        return None if not results or any(r is None for r in results) else False
    if not peer.get("evaluable", True):
        return None
    names = peer.get("namespaces")
    if names is None or ns not in names:
        return None if names is None else False
    return netpol.selector_matches(peer.get("pod_selector") or {}, labels)


def _admits(evaluation: dict, ns: Optional[str], labels: dict,
            ips: list) -> Optional[bool]:
    status = evaluation.get("status")
    if status in (netpol.UNRESTRICTED, netpol.ALLOW_ALL):
        return True
    if status == netpol.DENY_ALL:
        return False
    if status == netpol.RESTRICTED:
        results = [_peer_matches(p, ns, labels, ips) for p in evaluation["peers"]]
        if any(r is True for r in results):
            return True
        return None if any(r is None for r in results) else False
    return None


def build_topology(evidence: Evidence) -> dict:
    pods = evidence.get("Pod")
    policies = evidence.get("NetworkPolicy", all_scopes=True)
    namespaces = evidence.get("Namespace", all_scopes=True)
    services = evidence.get("Service")
    ingresses = evidence.get("Ingress")
    slices = evidence.get("EndpointSlice", all_scopes=True)
    replicasets = _controller_index(evidence.get("ReplicaSet", all_scopes=True))
    jobs = _controller_index(evidence.get("Job", all_scopes=True))

    # ---- workload nodes: pods grouped by their controller ------------------------------
    workloads: dict[str, dict] = {}
    pod_to_workload: dict[tuple, str] = {}
    for pod in pods:
        md = pod.get("metadata", {}) or {}
        ns, pname = md.get("namespace"), md.get("name")
        kind, name = _owner(pod, replicasets, jobs)
        wid = _nid(kind, ns, name)
        w = workloads.setdefault(wid, {
            "id": wid, "type": "workload", "kind": kind, "name": name, "namespace": ns,
            "labels": _labels(pod), "ips": [], "pods": 0, "internet_exposed": False})
        w["pods"] += 1
        w["ips"] = sorted(set(w["ips"]) | set(_pod_ips(pod)))
        pod_to_workload[(ns, pname)] = wid

    # ---- NetworkPolicy posture per workload (one evaluation each, not per pair) --------
    for w in workloads.values():
        ing = netpol.evaluate(policies, w["namespace"], w["labels"], "Ingress", namespaces)
        egr = netpol.evaluate(policies, w["namespace"], w["labels"], "Egress", namespaces)
        w["ingress"], w["egress"] = ing["status"], egr["status"]
        w["_ing"], w["_egr"] = ing, egr

    nodes: list[dict] = [{"id": "internet", "type": "internet", "name": "Internet"}]
    edges: list[dict] = []

    # ---- services -> workloads (EndpointSlice evidence first, selector as fallback) ----
    slice_pods: dict[tuple, set] = {}
    for sl in slices:
        md = sl.get("metadata", {}) or {}
        svc = (md.get("labels", {}) or {}).get("kubernetes.io/service-name")
        for ep in sl.get("endpoints") or []:
            ref = ep.get("targetRef") or {}
            if svc and ref.get("kind") == "Pod":
                slice_pods.setdefault((md.get("namespace"), svc), set()).add(ref.get("name"))
    service_ids: dict[tuple, str] = {}
    for svc in services:
        md = svc.get("metadata", {}) or {}
        ns, name = md.get("namespace"), md.get("name")
        stype = (svc.get("spec", {}) or {}).get("type", "ClusterIP")
        sid = _nid("Service", ns, name)
        service_ids[(ns, name)] = sid
        nodes.append({"id": sid, "type": "service", "name": name, "namespace": ns,
                      "service_type": stype})
        if stype in _EXTERNAL_TYPES:
            edges.append({"from": "internet", "to": sid, "kind": "exposes",
                          "evidence": f"{stype} Service"})
        backing, how = set(), "selector"
        if (ns, name) in slice_pods:
            how = "endpointslice"
            backing = {pod_to_workload[(ns, p)] for p in slice_pods[(ns, name)]
                       if (ns, p) in pod_to_workload}
        else:
            sel = (svc.get("spec", {}) or {}).get("selector") or {}
            if sel:
                backing = {w["id"] for w in workloads.values() if w["namespace"] == ns
                           and all(w["labels"].get(k) == v for k, v in sel.items())}
        for wid in sorted(backing):
            edges.append({"from": sid, "to": wid, "kind": "routes-to", "evidence": how})

    # ---- ingresses -> services ----------------------------------------------------------
    for ing in ingresses:
        md = ing.get("metadata", {}) or {}
        ns, name = md.get("namespace"), md.get("name")
        iid = _nid("Ingress", ns, name)
        nodes.append({"id": iid, "type": "ingress", "name": name, "namespace": ns})
        edges.append({"from": "internet", "to": iid, "kind": "exposes", "evidence": "Ingress"})
        spec = ing.get("spec", {}) or {}
        backends = {((spec.get("defaultBackend") or {}).get("service") or {}).get("name")}
        for rule in spec.get("rules") or []:
            for path in (rule.get("http") or {}).get("paths") or []:
                backends.add(((path.get("backend") or {}).get("service") or {}).get("name"))
        for b in sorted(x for x in backends if x and (ns, x) in service_ids):
            edges.append({"from": iid, "to": service_ids[(ns, b)], "kind": "routes-to",
                          "evidence": "Ingress backend"})

    # ---- internet exposure flag: a path internet -> ... -> workload ---------------------
    reached, frontier = set(), {"internet"}
    while frontier:
        nxt = {e["to"] for e in edges if e["from"] in frontier} - reached
        reached |= nxt
        frontier = nxt
    for w in workloads.values():
        w["internet_exposed"] = w["id"] in reached

    # ---- workload -> workload, where the destination's ingress is policy-governed ------
    notes: list[str] = []
    if not slices:
        notes.append("No EndpointSlices were read; Service -> workload edges use label "
                     "selectors instead of observed endpoints.")
    allowed_total = 0
    for dst in workloads.values():
        if dst["ingress"] != netpol.RESTRICTED:
            continue
        for src in workloads.values():
            if src is dst:
                continue
            into = _admits(dst["_ing"], src["namespace"], src["labels"], src["ips"])
            outof = _admits(src["_egr"], dst["namespace"], dst["labels"], dst["ips"])
            if into is True and outof is True:
                allowed_total += 1
                if len(edges) < MAX_EDGES_LISTED:
                    edges.append({"from": src["id"], "to": dst["id"], "kind": "allowed",
                                  "evidence": "NetworkPolicy " + ", ".join(dst["_ing"]["policies"])})
    if allowed_total > sum(e["kind"] == "allowed" for e in edges):
        notes.append(f"{allowed_total} allowed pod-to-pod edges; only the first "
                     f"{MAX_EDGES_LISTED} edges are listed, the count is exact.")

    for w in workloads.values():
        w.pop("_ing"), w.pop("_egr")
    nodes.extend(sorted(workloads.values(), key=lambda w: w["id"]))

    open_w = sorted(w["id"] for w in workloads.values() if w["ingress"] in
                    (netpol.UNRESTRICTED, netpol.ALLOW_ALL))
    summary = {
        "workloads": len(workloads),
        "services": len(service_ids),
        "ingresses": len(ingresses),
        "edges": len(edges),
        "allowed_edges_total": allowed_total,
        "internet_exposed": sorted(w["id"] for w in workloads.values() if w["internet_exposed"]),
        "open_workloads": open_w,
        "isolated_workloads": sorted(w["id"] for w in workloads.values()
                                     if w["ingress"] in (netpol.RESTRICTED, netpol.DENY_ALL)),
        "unknown_workloads": sorted(w["id"] for w in workloads.values()
                                    if w["ingress"] in (netpol.PARTIAL, netpol.UNKNOWN)),
        "namespaces_without_policy": sorted(
            {w["namespace"] for w in workloads.values()}
            - {(p.get("metadata", {}) or {}).get("namespace") for p in policies}),
    }
    return {"nodes": nodes, "edges": edges, "summary": summary, "notes": notes}
