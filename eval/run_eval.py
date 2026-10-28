"""
Score K8sMatrixWarden against the DVKA answer key.

    python3 eval/run_eval.py                  # scan the vulnerable + hardened fixtures, print the report
    python3 eval/run_eval.py --scale 20       # also time a cluster ~20x larger
    python3 eval/run_eval.py --fail-under 0.9 # exit 1 if recall or precision falls below 0.9

What is measured (the slide's measurement plan):
    recall         planted weaknesses detected / planted weaknesses the tool claims to cover
    precision      reported findings that are correct / reported findings
    false positive secure objects flagged (specificity), and the deliberate look-alike probes
    gaps           real weaknesses the tool does not cover: confirmed still undetected
    correlation    runtime events placed in the right tier (confirmed / corroborated / runtime-only)
    attack path    the Internet -> Service -> workload -> ServiceAccount -> Secrets chain
    prioritisation reachable + exploited findings must outrank isolated ones
    performance    scan time and peak memory

A finding is matched on (rule id, namespace, owning workload). The same weakness reported on a
Deployment, its ReplicaSet and its Pod is one finding.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
import time
import tracemalloc
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DVKA = os.path.join(ROOT, "eval", "dvka")
RESULTS = os.path.join(ROOT, "eval", "results")

from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events  # noqa: E402
from k8smatrixwarden.agents.scanner import ScannerAgent  # noqa: E402
from k8smatrixwarden.bootstrap import build_platform  # noqa: E402
from k8smatrixwarden.core.attack_path import resource_paths  # noqa: E402
from k8smatrixwarden.core.correlation import correlate  # noqa: E402
from k8smatrixwarden.core.models import ScanRequest  # noqa: E402


def _key(rule, ns, name):
    return (rule, ns or "", name)


def _finding_key(f):
    r = f.resource
    return _key(f.rule_id, r.namespace, r.owner_name or r.name)


def _scan(platform, fixture):
    col = platform.make_collector(mock=True, fixture=fixture)
    tracemalloc.start()
    t0 = time.perf_counter()
    result = ScannerAgent(platform).scan(ScanRequest(), col)
    secs = time.perf_counter() - t0
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return result, secs, peak


# --------------------------------------------------------------------------- scoring ---
def _in_lab(f, lab):
    """Is this finding about a DVKA object? A real cluster also has kube-system and friends,
    whose findings are true but are not what this key can judge."""
    r = f.resource
    ns, name = r.namespace or "", r.owner_name or r.name
    # a finding with no namespace (a ServiceAccount fan-out, a ClusterRole) is in the lab when
    # any lab object carries that name
    return (ns.startswith("dvka-") or (ns, name) in lab
            or (ns == "" and name in {n for _, n in lab}))


def score_detection(gt, result, live=False, grype=False):
    import catalog as C
    entries = gt["entries"]
    lab = {((o["metadata"].get("namespace") or ""), o["metadata"]["name"])
           for e in C.ENTRIES if e.profile != "hardened-only" for o in e.objects}
    findings = [f for f in result.findings if not live or _in_lab(f, lab)]
    outside = len(result.findings) - len(findings)
    expected, owner = {}, {}
    for e in entries:
        scanned = grype and e.get("grype_expect")
        if (e["gap"] and not scanned) or e["negative"]:
            continue
        if live and e["fixture_only"]:
            continue                      # cannot be planted on a real cluster
        r = e["resource"]
        for rule in e["expect"] + (e.get("grype_expect", []) if grype else []):
            k = _key(rule, r["namespace"], r["name"])
            expected[k] = e["id"]
            owner[k] = e["category"]
    found = {_finding_key(f): f for f in findings}
    tp = sorted(set(expected) & set(found))
    fn = sorted(set(expected) - set(found))
    fp = sorted(set(found) - set(expected))

    # classify every false positive
    neg_keys = {}
    for e in entries:
        if e["negative"]:
            r = e["resource"]
            neg_keys[(r["namespace"] or "", r["name"])] = e
    # every object of a negative entry, not just the one the key points at
    import catalog as C  # noqa: E402
    for e in C.ENTRIES:
        if e.negative:
            for o in e.objects:
                m = o["metadata"]
                neg_keys[(m.get("namespace") or "", m["name"])] = {"id": e.id, "fp_probe": e.fp_probe}
    gap_keys = {((e["resource"]["namespace"] or ""), e["resource"]["name"]): e
                for e in entries if e["gap"]}
    planted_keys = {(r[1], r[2]) for r in expected}
    fp_rows = []
    for rule, ns, name in fp:
        if (ns, name) in neg_keys:
            kind = "probe" if neg_keys[(ns, name)].get("fp_probe") else "secure-control"
            ref = neg_keys[(ns, name)]["id"]
        elif (ns, name) in gap_keys and (ns, name) not in planted_keys:
            kind, ref = "on-gap-resource", gap_keys[(ns, name)]["id"]
        else:
            kind, ref = "unexpected", "-"
        fp_rows.append({"rule": rule, "namespace": ns, "name": name, "class": kind, "ref": ref,
                        "shard": found[(rule, ns, name)].owning_shard})

    by_cat = defaultdict(lambda: [0, 0])
    for k in expected:
        by_cat[owner[k]][1] += 1
        if k in found:
            by_cat[owner[k]][0] += 1
    by_shard = defaultdict(lambda: [0, 0])
    exp_shard = {}
    for k in expected:
        exp_shard[k] = found[k].owning_shard if k in found else None
    for k, f in found.items():
        by_shard[f.owning_shard][1] += 1
        if k in expected:
            by_shard[f.owning_shard][0] += 1

    gaps = []
    for e in entries:
        if not e["gap"] or (grype and e.get("grype_expect")):
            continue
        key = ((e["resource"]["namespace"] or ""), e["resource"]["name"])
        hit = [r for r in fp_rows if (r["namespace"], r["name"]) == key]
        gaps.append({"id": e["id"], "title": e["title"], "detected": bool(hit),
                     "reason": e["gap_reason"], "would_detect_with": e["would_detect_with"]})
    negs = [e for e in entries if e["negative"] and e["profile"] in ("both", "vulnerable")]
    bad_negs = {r["ref"] for r in fp_rows if r["class"] in ("secure-control", "probe")}
    return {
        "outside_lab_findings": outside,
        "expected": len(expected), "found": len(found), "tp": len(tp), "fn": [list(k) for k in fn],
        "fp": fp_rows, "recall": len(tp) / len(expected) if expected else 1.0,
        "precision": len(tp) / len(found) if found else 1.0,
        "by_category": {c: {"detected": a, "expected": b, "recall": a / b}
                        for c, (a, b) in sorted(by_cat.items())},
        "by_shard": {s: {"correct": a, "reported": b, "precision": a / b}
                     for s, (a, b) in sorted(by_shard.items())},
        "gaps": gaps,
        "negatives": {"total": len(negs), "clean": len([n for n in negs if n["id"] not in bad_negs]),
                      "flagged": sorted(bad_negs)},
    }


def score_runtime(gt, results):
    rows, ok = [], 0
    agent = RuntimeAgent()
    for sc in gt["runtime"]:
        alerts = agent.evaluate_stream(normalize_events([sc["event"]]))
        result = results[sc.get("against", "vulnerable")]
        corr = correlate(result.findings, alerts, cluster=result.cluster_name,
                         now=gt["now"])["correlations"]
        got = corr[0]["confidence"] if corr else "no-alert"
        rows.append({"id": sc["id"], "title": sc["title"], "expected": sc["expect"], "got": got,
                     "ok": got == sc["expect"]})
        ok += got == sc["expect"]
    return {"correct": ok, "total": len(rows), "rows": rows}


def score_attack_path(gt, result):
    want = gt["attack_path"]
    chain = ["Internet", "Service", "Deployment", "ServiceAccount", "ClusterRoleBinding",
             "ClusterRole"]
    paths = resource_paths(result.findings, None, limit=500)
    for p in paths:
        names = [s["node"] for s in p["steps"]]
        if want["workload"] in names and want["service_account"] in names:
            kinds = [s["node_type"] for s in p["steps"]]
            return {"found": True, "internet_reachable": p["internet_reachable"],
                    "chain": kinds, "ends_at": p["target"]["name"],
                    "ok": kinds[:len(chain)] == chain and p["internet_reachable"]
                          and p["target"]["name"] == "read-secrets"}
    return {"found": False, "ok": False}


def score_image_priority(result):
    """The same CVE-laden image, once Internet-exposed and once isolated: exposure must win."""
    def worst(name):
        s = [i["score"] for i in result.workload_issues
             if i["workload_name"] == name and i["rule_id"] == "workload-image-vulnerabilities"]
        return max(s) if s else None
    hi, lo = worst("prio-vuln-exposed"), worst("gap-cve-image")
    return {"higher_score": hi, "lower_score": lo, "ok": hi is not None and lo is not None and hi > lo}


def score_priority(gt, result):
    pr = gt["prioritisation"]

    def worst(name):
        s = [i["score"] for i in result.workload_issues
             if i["workload_name"] == name and i["rule_id"] == "workload-privileged-container"]
        return max(s) if s else None
    hi, lo = worst(pr["higher"]), worst(pr["lower"])
    return {"higher_workload": pr["higher"], "higher_score": hi, "lower_workload": pr["lower"],
            "lower_score": lo, "ok": hi is not None and lo is not None and hi > lo}


# ------------------------------------------------------------------------- performance ---
def _scaled_fixture(src, n):
    with open(src) as fh:
        fx = json.load(fh)
    base_ns = "dvka-vuln"
    for i in range(n):
        ns = f"perf-{i}"
        fx["namespaces"].append({"kind": "Namespace", "metadata": {"name": ns}})
        for bucket in ("deployments", "replicasets", "pods", "services", "daemonsets",
                       "statefulsets", "cronjobs", "jobs", "endpointslices", "configmaps",
                       "serviceaccounts", "ingresses", "networkpolicies"):
            for o in [x for x in fx.get(bucket, []) if x["metadata"].get("namespace") == base_ns]:
                c = copy.deepcopy(o)
                c["metadata"]["namespace"] = ns
                c["metadata"]["name"] = f"{o['metadata']['name']}-{i}"
                fx[bucket].append(c)
    fd, path = tempfile.mkstemp(suffix=".json", prefix="dvka-scaled-")
    with os.fdopen(fd, "w") as fh:
        json.dump(fx, fh)
    return path, sum(len(v) for v in fx.values() if isinstance(v, list))


# ------------------------------------------------------------------------------ report ---
def pct(x):
    return f"{100 * x:.1f}%"


def render(r):
    d, o = r["detection"], []
    o.append("# K8sMatrixWarden evaluation against DVKA\n")
    if r.get("mode"):
        o.append(f"Live scan of `{r['cluster']}`: {r['findings']} findings in "
                 f"{r['scan_seconds']:.2f}s; "
                 f"{r['detection']['outside_lab_findings']} more findings are on objects "
                 f"outside DVKA (kube-system etc.) and are not scored.\n")
    else:
        o.append(f"Scan of the vulnerable fixture: {r['resources']} resources, "
                 f"{r['findings']} findings in {r['scan_seconds']:.2f}s "
                 f"(peak {r['peak_mb']:.1f} MB).\n")
    o.append("## Headline\n")
    o.append("| Measure | Result |\n|---|---|")
    o.append(f"| Recall (planted weaknesses detected) | **{pct(d['recall'])}** "
             f"({d['tp']}/{d['expected']}) |")
    o.append(f"| Precision (reported findings correct) | **{pct(d['precision'])}** "
             f"({d['tp']}/{d['found']}) |")
    n = d["negatives"]
    o.append(f"| Secure controls left unflagged | {n['clean']}/{n['total']} |")
    h = r["hardened"]
    o.append(f"| Hardened cluster: findings reported | {h['findings']} (expected 0) |")
    o.append(f"| Documented gaps confirmed undetected | "
             f"{sum(not g['detected'] for g in d['gaps'])}/{len(d['gaps'])} |")
    rt = r.get("runtime")
    if rt:
        o.append(f"| Runtime events in the right tier | {rt['correct']}/{rt['total']} |")
    o.append(f"| Attack path Internet to Secrets found | "
             f"{'yes' if r['attack_path']['ok'] else 'NO'} |")
    pr = r["priority"]
    o.append(f"| Exposed outranks isolated (same flaw) | "
             f"{'yes' if pr['ok'] else 'NO'} ({pr['higher_score']} vs {pr['lower_score']}) |")
    ip = r.get("image_priority")
    if ip:
        o.append(f"| Exposed vulnerable image outranks the isolated one | "
                 f"{'yes' if ip['ok'] else 'NO'} ({ip['higher_score']} vs {ip['lower_score']}) |")
    o.append("\n## Recall by category\n")
    o.append("| Category | Detected | Expected | Recall |\n|---|---|---|---|")
    for c, v in d["by_category"].items():
        o.append(f"| {c} | {v['detected']} | {v['expected']} | {pct(v['recall'])} |")
    o.append("\n## Precision by shard\n")
    o.append("| Shard | Correct | Reported | Precision |\n|---|---|---|---|")
    for s, v in d["by_shard"].items():
        o.append(f"| {s} | {v['correct']} | {v['reported']} | {pct(v['precision'])} |")
    o.append("\n## Missed (false negatives)\n")
    o += [f"- `{a}` on `{b}/{c}`" for a, b, c in d["fn"]] or ["- none"]
    o.append("\n## False positives\n")
    if d["fp"]:
        o.append("| Rule | Resource | Class | Ref |\n|---|---|---|---|")
        o += [f"| `{x['rule']}` | {x['namespace']}/{x['name']} | {x['class']} | {x['ref']} |"
              for x in d["fp"]]
    else:
        o.append("- none")
    o.append("\n## Documented gaps\n")
    o.append("| ID | Weakness | Still undetected | What would catch it |\n|---|---|---|---|")
    o += [f"| {g['id']} | {g['title']} | {'no, DETECTED' if g['detected'] else 'yes'} | "
          f"{g['would_detect_with']} |" for g in d["gaps"]]
    if rt:
        o.append("\n## Runtime correlation\n")
        o.append("| ID | Scenario | Expected | Got | |\n|---|---|---|---|---|")
        o += [f"| {x['id']} | {x['title']} | {x['expected']} | {x['got']} | "
              f"{'ok' if x['ok'] else 'MISMATCH'} |" for x in rt["rows"]]
    ap = r["attack_path"]
    o.append("\n## Attack path\n")
    o.append(f"- chain: {' -> '.join(ap.get('chain', [])) or 'not found'}"
             f"{' -> ' + ap['ends_at'] if ap.get('ends_at') else ''}")
    if r.get("scaled"):
        s = r["scaled"]
        o.append("\n## Performance\n")
        o.append(f"- {s['resources']} resources: scan {s['seconds']:.2f}s, "
                 f"peak {s['peak_mb']:.1f} MB (baseline {r['resources']} resources: "
                 f"{r['scan_seconds']:.2f}s, {r['peak_mb']:.1f} MB)")
    return "\n".join(o) + "\n"


def run(scale=0, runtime=False):
    sys.path.insert(0, DVKA)
    platform = build_platform()
    with open(os.path.join(DVKA, "ground_truth.json")) as fh:
        gt = json.load(fh)
    vuln = os.path.join(DVKA, "cluster_fixture.json")
    hard = os.path.join(DVKA, "cluster_fixture_hardened.json")
    result, secs, peak = _scan(platform, vuln)
    with open(vuln) as fh:
        resources = sum(len(v) for v in json.load(fh).values() if isinstance(v, list))
    hres, _, _ = _scan(platform, hard)
    report = {
        "resources": resources, "findings": len(result.findings), "scan_seconds": secs,
        "peak_mb": peak / 1e6, "detection": score_detection(gt, result),
        "attack_path": score_attack_path(gt, result),
        "priority": score_priority(gt, result),
        "hardened": {"findings": len(hres.findings),
                     "rules": sorted({f.rule_id for f in hres.findings})},
    }
    if runtime:                       # off by default: runtime is not evaluated for now
        report["runtime"] = score_runtime(gt, {"vulnerable": result, "hardened": hres})
    if scale:
        path, n = _scaled_fixture(vuln, scale)
        try:
            _, s2, p2 = _scan(platform, path)
        finally:
            os.unlink(path)
        report["scaled"] = {"resources": n, "seconds": s2, "peak_mb": p2 / 1e6, "scale": scale}
    return report


def run_live(context, grype=False):
    """Scan a real cluster the DVKA manifests were applied to."""
    sys.path.insert(0, DVKA)
    platform = build_platform()
    with open(os.path.join(DVKA, "ground_truth.json")) as fh:
        gt = json.load(fh)
    col = platform.make_collector(mock=False, context=context, grype=grype)
    t0 = time.perf_counter()
    result = ScannerAgent(platform).scan(ScanRequest(), col)
    secs = time.perf_counter() - t0
    det = score_detection(gt, result, live=True, grype=grype)
    return {"mode": f"live ({context})", "cluster": result.cluster_name,
            "resources": len(result.findings), "findings": len(result.findings),
            "scan_seconds": secs, "peak_mb": 0.0, "detection": det,
            "attack_path": score_attack_path(gt, result),
            "priority": score_priority(gt, result),
            "image_priority": score_image_priority(result) if grype else None,
            "hardened": {"findings": 0, "rules": []},
            "warnings": list(result.warnings)[:10],
            "coverage": {k: result.coverage.get(k) for k in ("coverage_pct", "unread_kinds")}}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scale", type=int, default=0, help="also time a cluster this many times larger")
    ap.add_argument("--fail-under", type=float, default=0.0,
                    help="exit 1 if recall or precision is below this")
    ap.add_argument("--live", action="store_true",
                    help="scan the cluster DVKA was applied to instead of the fixtures")
    ap.add_argument("--context", default="minikube", help="kubeconfig context for --live")
    ap.add_argument("--runtime", action="store_true", help="also score runtime correlation")
    ap.add_argument("--grype", action="store_true", help="with --live, also scan running images with Grype and score them")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the report")
    a = ap.parse_args()
    report = run_live(a.context, a.grype) if a.live else run(a.scale, a.runtime)
    os.makedirs(RESULTS, exist_ok=True)
    stem = "live" if a.live else "latest"
    with open(os.path.join(RESULTS, stem + ".json"), "w") as fh:
        json.dump(report, fh, indent=1)
    md = render(report)
    with open(os.path.join(RESULTS, stem + ".md"), "w") as fh:
        fh.write(md)
    print(json.dumps(report, indent=1) if a.json else md)
    d = report["detection"]
    return 0 if min(d["recall"], d["precision"]) >= a.fail_under else 1


if __name__ == "__main__":
    raise SystemExit(main())
