"""Is every node and pod covered by the security agents the organisation relies on?

Mature organisations run agents: an endpoint sensor on every node, Falco, a log shipper, a mesh proxy
beside every pod. This module reads the cluster (read-only) and answers, per agent: how much of the
cluster it covers, which nodes or pods are missing it, whether its pods are healthy, and which versions
are running. It can say a pod is Ready and has not been restarting. It cannot say the agent is
reporting to its vendor's backend; Kubernetes does not know that, so the page says so.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

_SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease"}

CATALOG = [
    {"id": "falco", "name": "Falco", "vendor": "Falco project", "kind": "daemonset", "match": {"names": ["falco"], "images": ["falcosecurity/falco"], "exclude": ["sidekick", "exporter"]},
     "what": "Watches system calls on each node and raises runtime alerts."},
    {"id": "crowdstrike", "name": "CrowdStrike Falcon sensor", "vendor": "CrowdStrike", "kind": "daemonset", "match": {"names": ["falcon-sensor", "crowdstrike"], "images": ["falcon-sensor", "crowdstrike"]},
     "what": "Endpoint detection and response on each node."},
    {"id": "wiz", "name": "Wiz sensor", "vendor": "Wiz", "kind": "daemonset", "match": {"names": ["wiz-sensor"], "images": ["wiz-sensor"]},
     "what": "Runtime sensor reporting to the Wiz platform."},
    {"id": "datadog", "name": "Datadog agent", "vendor": "Datadog", "kind": "daemonset", "match": {"names": ["datadog"], "images": ["datadoghq/agent", "datadog/agent"], "exclude": ["cluster-agent", "operator"]},
     "what": "Metrics, logs and runtime security from each node."},
    {"id": "sysdig", "name": "Sysdig agent", "vendor": "Sysdig", "kind": "daemonset", "match": {"names": ["sysdig"], "images": ["sysdig/agent", "sysdig/vuln"]},
     "what": "Runtime detection and activity audit on each node."},
    {"id": "aqua", "name": "Aqua enforcer", "vendor": "Aqua", "kind": "daemonset", "match": {"names": ["aqua-agent", "aqua-enforcer"], "images": ["aquasec/enforcer", "aquasec/agent"]},
     "what": "Runtime protection on each node."},
    {"id": "prisma", "name": "Prisma Cloud Defender", "vendor": "Palo Alto", "kind": "daemonset", "match": {"names": ["twistlock-defender", "prisma"], "images": ["twistlock/defender", "twistlock"]},
     "what": "Runtime defense on each node."},
    {"id": "defender", "name": "Microsoft Defender sensor", "vendor": "Microsoft", "kind": "daemonset", "match": {"names": ["microsoft-defender", "defender-collector"], "images": ["microsoft-defender", "defender-collector"]},
     "what": "Defender for Containers sensor on each node."},
    {"id": "tetragon", "name": "Tetragon", "vendor": "Cilium", "kind": "daemonset", "match": {"names": ["tetragon"], "images": ["cilium/tetragon"], "exclude": ["operator"]},
     "what": "eBPF runtime observability and enforcement."},
    {"id": "fluentbit", "name": "Log shipper (Fluent Bit)", "vendor": "Fluent", "kind": "daemonset", "match": {"names": ["fluent-bit", "fluentd"], "images": ["fluent/fluent-bit", "fluent/fluentd"]},
     "what": "Ships container logs off the node, so evidence survives an incident."},
    {"id": "linkerd", "name": "Linkerd proxy", "vendor": "Linkerd", "kind": "sidecar", "match": {"containers": ["linkerd-proxy"]},
     "what": "Encrypts and authenticates each pod's traffic (mutual TLS)."},
    {"id": "istio", "name": "Istio proxy", "vendor": "Istio", "kind": "sidecar", "match": {"containers": ["istio-proxy"]},
     "what": "Encrypts and authenticates each pod's traffic (mutual TLS)."},
]


def _ver(v: str):
    m = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in m[:3]) if m else None


def _image_version(img: str) -> str:
    if "@sha256:" in img and ":" not in img.split("@")[0].rsplit("/", 1)[-1]:
        return "digest-only"
    tag = img.split("@")[0].rsplit(":", 1)[-1] if ":" in img.split("@")[0].rsplit("/", 1)[-1] else "latest"
    return tag


def _matches(name: str, images: list, m: dict) -> bool:
    n = name.lower()
    if any(x in n for x in m.get("exclude", [])):
        return False
    return any(x in n for x in m.get("names", [])) or any(any(x in i.lower() for x in m.get("images", [])) for i in images)


def _pod_ready(p: dict) -> bool:
    st = p.get("status") or {}
    return st.get("phase") == "Running" and any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions") or [])


def _restarts(p: dict) -> int:
    return sum(c.get("restartCount", 0) for c in (p.get("status") or {}).get("containerStatuses") or [])


def _problem(p: dict) -> str:
    for c in (p.get("status") or {}).get("containerStatuses") or []:
        w = (c.get("state") or {}).get("waiting") or {}
        if w.get("reason") in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"):
            return w["reason"]
    return ""


def _tolerates(taint: dict, tolerations: list) -> bool:
    for t in tolerations or []:
        if t.get("operator") == "Exists" and not t.get("key"):
            return True
        if t.get("key") == taint.get("key") and (t.get("operator") == "Exists" or t.get("value") == taint.get("value")) \
                and (not t.get("effect") or t.get("effect") == taint.get("effect")):
            return True
    return False


def evaluate(agent: dict, evidence) -> dict:
    """Coverage, health and versions for one agent, from the cluster read."""
    nodes = evidence.get("Node", all_scopes=True)
    pods = evidence.get("Pod", all_scopes=True)
    out = {"id": agent["id"], "name": agent["name"], "vendor": agent.get("vendor", ""), "kind": agent["kind"], "what": agent.get("what", ""),
           "min_version": agent.get("min_version", ""), "expected": 0, "covered": 0, "coverage": 0.0, "missing": [], "unhealthy": [],
           "versions": {}, "below_min": [], "namespaces": [], "notes": [], "status": "not-found"}
    m = agent["match"]
    if agent["kind"] == "sidecar":
        want = [x.lower() for x in m.get("containers", [])]
        elig = [p for p in pods if (p.get("metadata") or {}).get("namespace") not in _SYSTEM_NS and (p.get("status") or {}).get("phase") in ("Running", "Pending")
                and not any((o.get("kind") in ("Job",)) for o in (p.get("metadata") or {}).get("ownerReferences") or [])
                and (not agent.get("namespaces") or (p.get("metadata") or {}).get("namespace") in agent["namespaces"])]
        have = []
        for p in elig:
            cs = [c for c in ((p.get("spec") or {}).get("containers") or []) + ((p.get("spec") or {}).get("initContainers") or [])
                  if any(w in (c.get("name") or "").lower() for w in want)]
            if cs:
                have.append((p, cs[0]))
        if not have:
            out["notes"].append("No pod carries this sidecar.")
            return out
        out["expected"], out["covered"] = len(elig), len(have)
        have_ids = {id(p) for p, _ in have}
        out["missing"] = [f"{(p['metadata'] or {}).get('namespace')}/{p['metadata']['name']}" for p in elig if id(p) not in have_ids][:60]
        for p, c in have:
            v = _image_version(c.get("image", ""))
            out["versions"][v] = out["versions"].get(v, 0) + 1
            if not _pod_ready(p) or _problem(p):
                out["unhealthy"].append(f"{p['metadata'].get('namespace')}/{p['metadata']['name']}: {_problem(p) or 'not ready'}")
        out["namespaces"] = sorted({(p["metadata"] or {}).get("namespace") for p, _ in have})
    else:
        dss = [d for d in evidence.get("DaemonSet", all_scopes=True)
               if _matches((d.get("metadata") or {}).get("name") or "", [c.get("image", "") for c in (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []], m)]
        if not dss:
            out["notes"].append("No DaemonSet matches. If you run this agent another way (a Deployment, a node image), it cannot be seen from here.")
            return out
        node_names = [(n.get("metadata") or {}).get("name") for n in nodes]
        covered, healthy_nodes = set(), set()
        tol = []
        for d in dss:
            md = d.get("metadata") or {}
            tol += ((((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("tolerations")) or []
            out["namespaces"].append(md.get("namespace"))
            for c in (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []:
                pass
            for p in pods:
                pm = p.get("metadata") or {}
                if pm.get("namespace") != md.get("namespace"):
                    continue
                if any(o.get("kind") == "DaemonSet" and o.get("name") == md.get("name") for o in pm.get("ownerReferences") or []):
                    node = (p.get("spec") or {}).get("nodeName")
                    covered.add(node)
                    img = next(iter((p.get("spec") or {}).get("containers") or [{}]), {}).get("image", "")
                    v = _image_version(img)
                    out["versions"][v] = out["versions"].get(v, 0) + 1
                    if _pod_ready(p) and not _problem(p):
                        healthy_nodes.add(node)
                    else:
                        out["unhealthy"].append(f"{pm.get('name')} on {node}: {_problem(p) or 'not ready'}")
                    if _restarts(p) >= 5:
                        out["notes"].append(f"{pm.get('name')} has restarted {_restarts(p)} times.")
        out["expected"], out["covered"] = len(node_names), len(healthy_nodes & set(node_names))
        for n in nodes:
            nm = (n.get("metadata") or {}).get("name")
            if nm in healthy_nodes:
                continue
            taints = [t for t in ((n.get("spec") or {}).get("taints") or []) if t.get("effect") in ("NoSchedule", "NoExecute") and not _tolerates(t, tol)]
            why = f"tainted {taints[0].get('key')}:{taints[0].get('effect')}, the agent does not tolerate it" if taints and nm not in covered else \
                  ("agent pod is not healthy" if nm in covered else "no agent pod scheduled")
            out["missing"].append(f"{nm} ({why})")
        out["namespaces"] = sorted(set(out["namespaces"]))
    out["coverage"] = round(out["covered"] / out["expected"], 3) if out["expected"] else 0.0
    mv = _ver(agent.get("min_version", ""))
    if mv:
        out["below_min"] = sorted(v for v in out["versions"] if _ver(v) and _ver(v) < mv)
    vers = [v for v in out["versions"] if v != "digest-only"]
    if len(vers) > 1:
        out["notes"].append("More than one version is running: " + ", ".join(sorted(vers)) + ". A rollout may be stuck, or nodes are being left behind.")
    if "latest" in out["versions"]:
        out["notes"].append("A 'latest' tag is in use, so the real version cannot be known or pinned.")
    out["status"] = ("missing" if out["coverage"] == 0 else "degraded" if (out["coverage"] < 1 or out["unhealthy"] or out["below_min"]) else "healthy")
    return out


def unknown_daemonsets(evidence, agents: list) -> list[dict]:
    """DaemonSets that are not a known agent and not a core Kubernetes component: candidates the
    organisation may want to track (an agent we do not have a name for)."""
    core = ("kube-proxy", "calico-node", "aws-node", "kindnet", "cilium", "coredns", "csi", "ebs-csi", "efs-csi", "azure-ip", "cloud-node", "node-local-dns",
            "vpc-cni", "gke-metadata", "fluentbit-gke", "netd", "pdcsi", "konnectivity", "ip-masq", "nvidia", "weave-net", "flannel", "kube-flannel", "azure-cns")
    out = []
    for d in evidence.get("DaemonSet", all_scopes=True):
        md = d.get("metadata") or {}
        name = (md.get("name") or "")
        imgs = [c.get("image", "") for c in (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []]
        if any(c in name.lower() for c in core) or any(_matches(name, imgs, a["match"]) for a in agents if a["kind"] == "daemonset"):
            continue
        st = d.get("status") or {}
        out.append({"name": name, "namespace": md.get("namespace"), "image": imgs[0] if imgs else "", "ready": st.get("numberReady", 0), "desired": st.get("desiredNumberScheduled", 0)})
    return out


# ---- the organisation's own list of agents ---------------------------------------------------------
def _file(base: str) -> str:
    return os.path.join(base, "agents.json")


def load_agents(base: str) -> list[dict]:
    """Catalog entries, minus the ones switched off, plus custom ones, with any minimum versions set."""
    try:
        with open(_file(base), encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        cfg = {}
    tracked = set(cfg.get("tracked") or [])
    mins = cfg.get("min_versions") or {}
    out = []
    for a in CATALOG:
        out.append(dict(a, min_version=mins.get(a["id"], ""), tracked=a["id"] in tracked, custom=False))
    for c in cfg.get("custom") or []:
        out.append(dict(c, min_version=mins.get(c["id"], c.get("min_version", "")), tracked=True, custom=True))
    return out


def save_config(base: str, tracked: list, min_versions: dict, custom: list) -> None:
    clean_custom = []
    for c in custom or []:
        i = re.sub(r"[^a-z0-9-]", "-", str(c.get("name", "")).lower()).strip("-")[:40]
        names = [str(x).strip() for x in c.get("names") or [] if str(x).strip()]
        if not i or not names or c.get("kind") not in ("daemonset", "sidecar"):
            raise ValueError("A custom agent needs a name, a kind (daemonset or sidecar) and at least one name to match.")
        key = "containers" if c["kind"] == "sidecar" else "names"
        clean_custom.append({"id": "custom-" + i, "name": str(c["name"])[:60], "vendor": "Custom", "kind": c["kind"], "match": {key: names, "images": names if c["kind"] == "daemonset" else []},
                             "what": str(c.get("what", ""))[:160]})
    os.makedirs(base, exist_ok=True)
    mv = {k: str(v)[:20] for k, v in (min_versions or {}).items() if str(v).strip()}
    with open(_file(base), "w", encoding="utf-8") as fh:
        json.dump({"tracked": [str(x) for x in tracked], "min_versions": mv, "custom": clean_custom}, fh, indent=2)


def report(evidence, agents: list) -> dict:
    tracked = [a for a in agents if a.get("tracked")]
    return {"agents": [evaluate(a, evidence) for a in tracked],
            "available": [{"id": a["id"], "name": a["name"], "vendor": a.get("vendor", ""), "kind": a["kind"], "what": a.get("what", "")} for a in agents if not a.get("tracked")],
            "unknown": unknown_daemonsets(evidence, agents), "nodes": len(evidence.get("Node", all_scopes=True)),
            "caveat": "Ready and not restarting means the agent process is up. Whether it is reporting to its vendor's backend cannot be seen from the cluster."}
