"""
Build the DVKA artefacts from catalog.py:

    manifests/*.yaml                  apply to a DISPOSABLE cluster (kind / minikube)
    cluster_fixture.json              the same cluster as scanner evidence (no cluster needed)
    cluster_fixture_hardened.json     only the secure objects: the scanner must say nothing
    ground_truth.json                 the answer key run_eval.py scores against
    CATALOG.md                        the human-readable list

    python3 eval/dvka/build.py
"""
from __future__ import annotations

import copy
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import catalog as C  # noqa: E402

FILES = {"NS": "00-namespaces", "WL": "10-workloads", "RB": "20-rbac", "NET": "30-network",
         "SEC": "40-secrets", "AS": "50-attack-surface", "AP": "60-attack-path",
         "PRIO": "65-prioritisation", "GAP": "70-documented-gaps", "NEG": "80-secure-controls",
         "FP": "90-false-positive-probes"}


class _NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _labelled(o):
    """Tag every object so teardown.sh can remove exactly what DVKA created. The built-in
    `default` namespace is never tagged: it is not ours to delete."""
    if o["kind"] == "Namespace" and o["metadata"]["name"] == "default":
        return o
    o = copy.deepcopy(o)
    o["metadata"]["labels"] = {**o["metadata"].get("labels", {}),
                               "app.kubernetes.io/part-of": "dvka"}
    return o


def _key(o):
    m = o["metadata"]
    return (o["kind"], m.get("namespace"), m["name"])


# --------------------------------------------------------------------------- manifests ---
def write_manifests():
    out_dir = os.path.join(HERE, "manifests")
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.endswith(".yaml"):
            os.remove(os.path.join(out_dir, f))
    seen, files = set(), {}
    for e in C.ENTRIES:
        objs = [o for o in e.objects if _key(o) not in seen]
        if not objs or e.fixture_only and e.profile != "hardened-only":
            continue
        fname = "95-hardened-extras" if e.profile == "hardened-only" else FILES[e.category]
        note = (f"# ---- {e.id}: {e.title}"
                + (f"  [expects: {', '.join(e.expect)}]" if e.expect else
                   "  [expects: nothing]" if not e.gap else "  [documented gap]"))
        announced = set()
        for o in objs:
            seen.add(_key(o))
            # namespaces always come first, so `kubectl apply -f manifests/` works in order
            target = "00-namespaces" if o["kind"] == "Namespace" and e.profile != "hardened-only" else fname
            buf = files.setdefault(target, [])
            if target not in announced:
                announced.add(target)
                buf.append(note)
            o = _labelled(o)
            buf.append(yaml.dump(o, Dumper=_NoAlias, sort_keys=False).rstrip())
            buf.append("---")
    for fname, parts in sorted(files.items()):
        header = ("# DVKA: Damn Vulnerable Kubernetes Application. INTENTIONALLY INSECURE.\n"
                  "# Apply only to a disposable local cluster. See eval/README.md.\n")
        with open(os.path.join(out_dir, fname + ".yaml"), "w") as fh:
            fh.write(header + "\n".join(parts).rstrip("-\n") + "\n")
    return sorted(files)


# --------------------------------------------------------------------------- fixture ---
_BUCKET = {"Namespace": "namespaces", "Deployment": "deployments", "StatefulSet": "statefulsets",
           "DaemonSet": "daemonsets", "Job": "jobs", "CronJob": "cronjobs", "Pod": "pods",
           "Service": "services", "Ingress": "ingresses", "NetworkPolicy": "networkpolicies",
           "ServiceAccount": "serviceaccounts", "Secret": "secrets", "ConfigMap": "configmaps",
           "Role": "roles", "RoleBinding": "rolebindings", "ClusterRole": "clusterroles",
           "ClusterRoleBinding": "clusterrolebindings",
           "MutatingWebhookConfiguration": "mutatingwebhookconfigurations",
           "ValidatingWebhookConfiguration": "validatingwebhookconfigurations"}
_ALPHA = "bcdfghjklmnpqrstvwxz2456789"


def _rand(seed: str, n=5):
    h = sum(ord(c) * (i + 7) for i, c in enumerate(seed))
    out = ""
    for _ in range(n):
        h = (h * 1103515245 + 12345) & 0x7FFFFFFF
        out += _ALPHA[h % len(_ALPHA)]
    return out


class _Ip:
    def __init__(self):
        self.n = 1

    def next(self):
        self.n += 1
        return f"10.244.{self.n // 250}.{self.n % 250 + 1}"


def _pod(name, ns, template, ip, owner=None, node="worker-1"):
    meta = {"name": name, "namespace": ns, "labels": dict(template["metadata"]["labels"])}
    if owner:
        meta["ownerReferences"] = [{"kind": owner[0], "name": owner[1], "controller": True}]
    # the API server defaults a Pod's serviceAccountName to "default"; a template does not
    spec = {"serviceAccountName": "default", **copy.deepcopy(template["spec"]), "nodeName": node}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec,
            "status": {"phase": "Running", "podIP": ip, "podIPs": [{"ip": ip}],
                       "hostIP": "192.168.49.2"}}


def _expand(objs, ips):
    """Deployments / StatefulSets / DaemonSets / Jobs get the ReplicaSet and Pod a real
    cluster would have, because the scanner resolves findings past them to the owner."""
    out = []
    for o in objs:
        kind = o["kind"]
        out.append(o)
        m = o["metadata"]
        ns, name = m.get("namespace"), m["name"]
        if kind == "Deployment":
            tpl = o["spec"]["template"]
            h = _rand(name + "h", 10)
            rs = f"{name}-{h}"
            out.append({"apiVersion": "apps/v1", "kind": "ReplicaSet",
                        "metadata": {"name": rs, "namespace": ns, "labels": m["labels"],
                                     "ownerReferences": [{"kind": "Deployment", "name": name,
                                                          "controller": True}]},
                        "spec": {"selector": o["spec"]["selector"], "template": tpl}})
            out.append(_pod(f"{rs}-{_rand(name)}", ns, tpl, ips.next(), ("ReplicaSet", rs)))
        elif kind == "StatefulSet":
            out.append(_pod(f"{name}-0", ns, o["spec"]["template"], ips.next(),
                            ("StatefulSet", name)))
        elif kind == "DaemonSet":
            out.append(_pod(f"{name}-{_rand(name)}", ns, o["spec"]["template"], ips.next(),
                            ("DaemonSet", name)))
        elif kind == "Job":
            out.append(_pod(f"{name}-{_rand(name)}", ns, o["spec"]["template"], ips.next(),
                            ("Job", name)))
    return out


def _endpoint_slices(buckets):
    out = []
    for svc in buckets.get("services", []):
        sel = svc["spec"].get("selector") or {}
        ns, name = svc["metadata"]["namespace"], svc["metadata"]["name"]
        eps = [{"addresses": [p["status"]["podIP"]], "conditions": {"ready": True},
                "targetRef": {"kind": "Pod", "name": p["metadata"]["name"], "namespace": ns}}
               for p in buckets.get("pods", [])
               if p["metadata"]["namespace"] == ns and sel
               and all(p["metadata"]["labels"].get(k) == v for k, v in sel.items())]
        out.append({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
                    "metadata": {"name": f"{name}-{_rand(name, 5)}", "namespace": ns,
                                 "labels": {"kubernetes.io/service-name": name}},
                    "addressType": "IPv4", "endpoints": eps})
    return out


def _nodes():
    def n(name, control=False):
        labels = {"kubernetes.io/hostname": name}
        if control:
            labels["node-role.kubernetes.io/control-plane"] = ""
        return {"kind": "Node", "metadata": {"name": name, "labels": labels},
                "status": {"conditions": [{"type": "Ready", "status": "True"}],
                           "nodeInfo": {"kubeletVersion": "v1.29.4", "osImage": "Ubuntu 22.04",
                                        "containerRuntimeVersion": "containerd://1.7.13"}}}
    return [n("control-1", True), n("worker-1"), n("worker-2")]


def build_fixture(profile: str):
    keep = ("both",) if profile == "hardened" else ("vulnerable", "both")
    if profile == "hardened":
        keep = ("both", "hardened-only")
    objs, seen = [], set()
    for e in C.ENTRIES:
        if e.profile not in keep:
            continue
        for o in e.objects:
            if _key(o) not in seen:
                seen.add(_key(o))
                objs.append(copy.deepcopy(o))
    namespaces = {o["metadata"]["name"] for o in objs if o["kind"] == "Namespace"}
    # a default ServiceAccount exists in every namespace, as it does in a real cluster
    for ns in sorted(namespaces):
        k = ("ServiceAccount", ns, "default")
        if k not in seen:
            objs.append(C._sa(ns, "default"))
    objs = _expand(objs, _Ip())
    buckets: dict[str, list] = {}
    for o in objs:
        buckets.setdefault(_BUCKET.get(o["kind"], o["kind"].lower() + "s"), []).append(o)
    buckets.setdefault("namespaces", []).append(
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}})
    buckets["replicasets"] = [o for o in objs if o["kind"] == "ReplicaSet"]
    # the roles every cluster ships with, so a binding to `cluster-admin` resolves
    boot = {"kubernetes.io/bootstrapping": "rbac-defaults"}
    star = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    for name, rules in (("cluster-admin", star),
                        ("admin", [{"apiGroups": ["*"], "resources": ["*"],
                                    "verbs": ["get", "list", "create", "update", "delete"]}]),
                        ("edit", [{"apiGroups": ["*"], "resources": ["*"],
                                   "verbs": ["get", "list", "create", "update"]}]),
                        ("view", [{"apiGroups": ["*"], "resources": ["*"],
                                   "verbs": ["get", "list"]}])):
        buckets.setdefault("clusterroles", []).append({"apiVersion": "rbac.authorization.k8s.io/v1",
                                        "kind": "ClusterRole",
                                        "metadata": {"name": name, "labels": boot},
                                        "rules": rules})
    buckets["endpointslices"] = _endpoint_slices(buckets)
    buckets["nodes"] = _nodes()
    buckets["componentconfig"] = [C.CP_HARD if profile == "hardened" else C.CP_VULN]
    for k in ("deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "pods",
              "services", "ingresses", "networkpolicies", "serviceaccounts", "secrets",
              "configmaps", "roles", "rolebindings", "clusterroles", "clusterrolebindings"):
        buckets.setdefault(k, [])
    buckets["_meta"] = {"cluster": C.LAB, "profile": profile,
                        "note": "generated by eval/dvka/build.py; do not edit"}
    return buckets


# ----------------------------------------------------------------------- ground truth ---
def ground_truth():
    entries = []
    for e in C.ENTRIES:
        entries.append({
            "id": e.id, "category": e.category, "title": e.title,
            "resource": {"kind": e.kind, "namespace": e.namespace, "name": e.name},
            "expect": e.expect, "severity": e.severity, "mitre": e.mitre, "cis": e.cis,
            "why": e.why, "gap": e.gap, "gap_reason": e.gap_reason,
            "would_detect_with": e.would_detect_with, "negative": e.negative,
            "fp_probe": e.fp_probe, "fixture_only": e.fixture_only, "profile": e.profile,
            "grype_expect": e.grype_expect})
    runtime = []
    for r in C.RUNTIME:
        ev = {"source": "falco", "priority": "Warning", "time": "2026-10-15T09:55:00Z",
              "container_id": "0123456789ab", **r["event"]}
        runtime.append({"id": r["id"], "title": r["title"], "expect": r["expect"],
                        "against": r.get("against", "vulnerable"),
                        "why": r["why"], "event": ev})
    return {"lab": C.LAB, "now": "2026-10-15T10:00:00Z", "entries": entries, "runtime": runtime,
            "attack_path": {"workload": "ap-frontend", "namespace": C.VULN,
                            "service_account": "ap-frontend-sa", "service": "ap-frontend"},
            "prioritisation": {"higher": "ap-frontend", "lower": "prio-isolated",
                               "namespace": C.VULN}}


# --------------------------------------------------------------------------- CATALOG.md ---
NAMES = {"NS": "Namespace posture", "WL": "Workload & pod security", "RB": "RBAC & identity",
         "NET": "Network exposure", "SEC": "Secrets & credentials", "AS": "Attack surface",
         "CP": "Control plane & audit (fixture only)", "AP": "Attack path",
         "PRIO": "Prioritisation", "GAP": "Documented gaps (real weaknesses the scanner does not detect)",
         "NEG": "Secure controls (must not be flagged)",
         "FP": "False-positive probes (secure, but look like a weakness)"}


def write_catalog(gt):
    lines = ["# DVKA catalog", "",
             "Generated by `eval/dvka/build.py` from `catalog.py`. Do not edit by hand.", ""]
    n_exp = sum(len(e["expect"]) for e in gt["entries"] if not e["gap"])
    lines += [f"**{len(gt['entries'])} entries, {n_exp} expected findings, "
              f"{sum(e['gap'] for e in gt['entries'])} documented gaps, "
              f"{sum(e['negative'] for e in gt['entries'])} secure controls, "
              f"{len(gt['runtime'])} runtime scenarios.**", ""]
    for cat in ("NS", "WL", "RB", "NET", "SEC", "AS", "CP", "AP", "PRIO", "GAP", "NEG", "FP"):
        rows = [e for e in gt["entries"] if e["category"] == cat]
        if not rows:
            continue
        lines += [f"## {cat}: {NAMES[cat]}", "",
                  "| ID | Weakness | Resource | Expected rules | Sev | MITRE | CIS |",
                  "|---|---|---|---|---|---|---|"]
        for e in rows:
            r = e["resource"]
            res = "/".join(x for x in (r["kind"], r["namespace"], r["name"]) if x)
            exp = ", ".join(f"`{x}`" for x in e["expect"]) or ("**gap**" if e["gap"] else "none")
            lines.append(f"| {e['id']} | {e['title']}{' *(fixture only)*' if e['fixture_only'] else ''} "
                         f"| {res} | {exp} | {e['severity']} | {e['mitre']} | {e['cis']} |")
        gaps = [e for e in rows if e["gap"]]
        if gaps:
            lines += ["", "Why each gap is undetected, and what would catch it:", ""]
            lines += [f"- **{e['id']}**: {e['gap_reason']}. *Would detect with:* "
                      f"{e['would_detect_with']}." for e in gaps]
        lines.append("")
    lines += ["## RT: Runtime correlation scenarios", "",
              "| ID | Event | Expected tier | Why |", "|---|---|---|---|"]
    lines += [f"| {r['id']} | {r['title']} | {r['expect']} | {r['why']} |" for r in gt["runtime"]]
    lines.append("")
    with open(os.path.join(HERE, "CATALOG.md"), "w") as fh:
        fh.write("\n".join(lines))


def main():
    files = write_manifests()
    for profile, name in (("vulnerable", "cluster_fixture.json"),
                          ("hardened", "cluster_fixture_hardened.json")):
        with open(os.path.join(HERE, name), "w") as fh:
            json.dump(build_fixture(profile), fh, indent=1, sort_keys=False)
            fh.write("\n")
    gt = ground_truth()
    with open(os.path.join(HERE, "ground_truth.json"), "w") as fh:
        json.dump(gt, fh, indent=1)
        fh.write("\n")
    write_catalog(gt)
    print(f"{len(gt['entries'])} entries · manifests: {', '.join(files)}")


if __name__ == "__main__":
    main()
