"""Running the rules well: how often each fires, whether Falco is keeping up, which attacker goals are
covered, and how to prove a rule on a real cluster. Pure functions over Falco's own output."""
from __future__ import annotations

import re
from collections import Counter
from typing import Optional

from .falco_feed import parse_falco_log
from .runtime_rules import TACTICS, normalize

_TOP_FIELDS = ("proc.name", "k8s.ns.name", "container.image.repository", "user.name", "fd.name")


def rule_stats(events: list, window_hours: int = 24) -> dict:
    """Per Falco rule: how many times it fired in the window, when last, and who triggered it."""
    out: dict = {}
    for e in events:
        r = e.get("rule")
        if not r or str(r).startswith("Falco internal"):
            continue
        s = out.setdefault(r, {"fires": 0, "last": "", "priority": e.get("priority", ""), "top": {f: Counter() for f in _TOP_FIELDS}})
        s["fires"] += 1
        s["last"] = max(s["last"], str(e.get("time", "")))
        for f in _TOP_FIELDS:
            v = (e.get("output_fields") or {}).get(f)
            if v not in (None, ""):
                s["top"][f][str(v)] += 1
    for s in out.values():
        s["top"] = {f: c.most_common(3) for f, c in s["top"].items() if c}
        s["window_hours"] = window_hours
    return out


_EXC_OF = {"proc.name": "proc.name", "k8s.ns.name": "k8s.ns.name", "container.image.repository": "container.image.repository", "user.name": "user.name"}


def suggest_exceptions(stat: dict, spec: dict) -> list[dict]:
    """When one program, namespace or image causes most of a noisy rule's hits, offer it as an exception
    (never applied automatically: an analyst must decide that it is really normal)."""
    out = []
    if not stat or stat["fires"] < 5:
        return out
    for field, items in stat["top"].items():
        if field not in _EXC_OF or not items:
            continue
        v, n = items[0]
        share = n / stat["fires"]
        if share >= 0.6:
            out.append({"field": field, "value": v, "share": round(share, 2),
                        "text": f"{n} of {stat['fires']} hits come from {field.split('.')[-1]} '{v}'. If that is normal, add it as an exception."})
    return out


def advice(stat: Optional[dict], stage: str) -> dict:
    """Plain next step for an audit-stage rule: quiet means ready, noisy means tune first."""
    if stage != "audit":
        return {"state": "alerting", "text": "Alerting. Watch the fire count; a rule that is never quiet gets ignored."}
    if not stat:
        return {"state": "quiet", "text": "No hits in the window. If this is a rule that should rarely fire, it is ready to promote to alert."}
    if stat["fires"] <= 3:
        return {"state": "quiet", "text": f"Only {stat['fires']} hit(s). Check them, then promote to alert."}
    return {"state": "noisy", "text": f"{stat['fires']} hits in {stat['window_hours']}h. Tune it with exceptions before alerting, or it will be ignored."}


_ERR = re.compile(r"(error|failed|LOAD_ERR|invalid)", re.I)


def health(logs: dict, window_hours: int = 24) -> dict:
    """Is Falco keeping up and loading its rules? From its own logs: dropped-event alerts, load errors, last event."""
    pods, total_drops, total_events = [], 0, 0
    for name, text in sorted(logs.items()):
        evs = parse_falco_log(text)
        drops = [e for e in evs if str(e.get("rule", "")).startswith("Falco internal: syscall event drop")]
        n_drops = 0
        for e in drops:
            f = e.get("output_fields") or {}
            try:
                n_drops += int(f.get("n_drops") or f.get("n_drops_buffer_total") or 1)
            except (TypeError, ValueError):
                n_drops += 1
        errors = [ln.strip()[:200] for ln in str(text).splitlines() if _ERR.search(ln) and not ln.lstrip().startswith("{") and "rule" in ln.lower()][:5]
        errors += [ln.strip()[:200] for ln in str(text).splitlines() if "initialization failed" in ln.lower() or "LOAD_ERR" in ln][:3]
        alerts = [e for e in evs if not str(e.get("rule", "")).startswith("Falco internal")]
        pods.append({"pod": name, "alerts": len(alerts), "drop_alerts": len(drops), "dropped_events": n_drops, "errors": sorted(set(errors))[:5],
                     "last_alert": max([str(e.get("time", "")) for e in alerts] or [""])})
        total_drops += n_drops
        total_events += len(alerts)
    errs = sum(1 for p in pods if p["errors"])
    state = "no-data" if not pods else ("errors" if errs else "dropping" if total_drops else "healthy")
    text = {"no-data": "No Falco logs could be read.", "errors": "Falco reported errors loading or running rules. Details below.",
            "dropping": f"Falco dropped about {total_drops} event(s): it could not keep up on at least one node, so attacks in those moments went unseen.",
            "healthy": "No dropped events and no rule errors in the logs read."}[state]
    return {"state": state, "message": text, "pods": pods, "alerts": total_events, "dropped_events": total_drops, "window_hours": window_hours}


def _tactic_title(t: str) -> str:
    t = (t or "").replace("_", " ").strip().title()
    return {"Command And Control": "Command and Control"}.get(t, t)


def mitre_coverage(rules: list, falco_state: str) -> dict:
    """For every attacker goal: which rules are actually watching for it now, which are only saved, and the gaps."""
    rows = {t: {"tactic": t, "active": [], "saved": []} for t in TACTICS}
    for r in rules:
        t = _tactic_title(r.get("tactic", ""))
        if not t:
            continue
        row = rows.setdefault(t, {"tactic": t, "active": [], "saved": []})
        k = r.get("kind")
        if k == "curated" or (k == "default" and falco_state in ("healthy", "partial") and r.get("enabled", True)) or (k == "custom" and r.get("deployed")):
            row["active"].append(r["name"])
        elif k == "custom":
            row["saved"].append(r["name"])
    out = []
    for t, row in rows.items():
        out.append({"tactic": t, "active": len(row["active"]), "saved": len(row["saved"]), "rules": row["active"][:6], "gap": not row["active"]})
    return {"rows": out, "gaps": [r["tactic"] for r in out if r["gap"]]}


def simulation_plan(spec: dict) -> dict:
    """How to prove a rule on a real cluster: commands a person runs in a THROWAWAY pod. This tool does not run them."""
    s = normalize(spec)
    b, v = s["behavior"], s["values"]
    ns = (s["scope"]["namespaces"] or ["<namespace>"])[0]
    pre = f"kubectl run kmw-sim -n {ns} --image=busybox:1.36 --restart=Never --command -- sleep 3600"
    cmds, action = [], ""
    if b == "process":
        n = (v["names"] or ["sh"])[0]
        cmds = [f"kubectl exec -n {ns} kmw-sim -- {n} -c 'echo kmw-test'" if n in ("sh", "ash", "bash") else f"kubectl exec -n {ns} kmw-sim -- {n} --version"]
        action = "syscall.RunShellUntrusted" if n in ("bash", "sh", "zsh", "ash") else ""
    elif b == "file_read":
        cmds = [f"kubectl exec -n {ns} kmw-sim -- cat {v['paths'][0].rstrip('/') + ('/' if v['paths'][0].endswith('/') else '')}"]
        action = "syscall.ReadSensitiveFileUntrusted" if any(p.startswith("/etc/") for p in v["paths"]) else ""
    elif b == "file_write":
        p = v["paths"][0].rstrip("/")
        cmds = [f"kubectl exec -n {ns} kmw-sim -- sh -c 'touch {p}/kmw-test-file'"]
        action = "syscall.WriteBelowBinaryDir" if any(x.startswith(("/bin", "/usr/bin", "/sbin", "/usr/sbin")) for x in v["paths"]) else ""
    elif b == "network_out":
        host = next((d for d in v["destinations"] if "/" not in d), "198.51.100.10")
        port = (v["ports"] or ["80"])[0]
        cmds = [f"kubectl exec -n {ns} kmw-sim -- wget -T 3 -q -O /dev/null http://{host}:{port}"]
    else:
        cmds = [f"kubectl auth can-i {v['verbs'][0]} {v['resources'][0]} -n {ns}   # an audit event is produced by the API call itself"]
    return {"namespace": ns, "setup": pre, "commands": cmds, "cleanup": f"kubectl delete pod kmw-sim -n {ns}", "event_generator": action,
            "event_generator_cmd": (f"helm install event-generator falcosecurity/event-generator -n {ns} --set config.actions=\"^{action}$\" --set config.loop=false" if action else ""),
            "expect": f"Within a minute the rule '{s['name']}' should appear in Falco's alerts, and its fire count on the Rules tab should rise by one.",
            "warning": "Run this only in a throwaway pod on a test or staging cluster. It deliberately does what an attacker would, so it will also trigger any other rule that watches the same behaviour."}
