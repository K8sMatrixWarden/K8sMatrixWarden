"""What changed between two scans of the same cluster, in the words an on-call engineer uses.

In an incident the first question is "what changed?". The scan already records the objects
(workloads with their images and flags, services, bindings, namespace policies), so comparing
two of them answers it with no extra collection. Each change says what it is, and is marked
`risky` when it makes the cluster easier to attack: something newly reachable from the
Internet, a new privileged workload, a wider binding, a weaker namespace policy.
"""
from __future__ import annotations

HOT = {"privileged", "host-network", "host-pid", "host-ipc", "host-path"}


def _index(rows, *keys):
    return {tuple(r.get(k) for k in keys): r for r in rows or []}


def _item(section, kind, name, ns, text, risky=False, detail=None):
    return {"section": section, "kind": kind, "name": name, "namespace": ns or "",
            "summary": text, "risky": bool(risky), "detail": detail or {}}


def _workloads(prev, cur, out):
    p, c = _index(prev, "namespace", "kind", "name"), _index(cur, "namespace", "kind", "name")
    for k, w in c.items():
        old = p.get(k)
        label = f"{w['kind']} {w['name']}"
        if not old:
            hot = [f for f in w.get("flags", []) if f in HOT]
            out.append(_item("workloads", "added", w["name"], w["namespace"],
                             f"New {label}" + (f", with {', '.join(hot)}" if hot else "")
                             + (", reachable from the Internet" if w.get("internet") else ""),
                             risky=bool(hot) or w.get("internet"),
                             detail={"images": w.get("images", [])}))
            continue
        if old.get("images") != w.get("images"):
            out.append(_item("workloads", "changed", w["name"], w["namespace"],
                             f"{label} now runs {', '.join(w.get('images', []))} "
                             f"(was {', '.join(old.get('images', []))})",
                             risky=any(i.endswith(":latest") or ":" not in i.split("/")[-1]
                                       for i in w.get("images", [])),
                             detail={"before": old.get("images"), "after": w.get("images")}))
        new_flags = sorted(set(w.get("flags", [])) - set(old.get("flags", [])))
        if new_flags:
            out.append(_item("workloads", "changed", w["name"], w["namespace"],
                             f"{label} gained {', '.join(new_flags)}", risky=bool(set(new_flags) & HOT)))
        if w.get("internet") and not old.get("internet"):
            out.append(_item("workloads", "changed", w["name"], w["namespace"],
                             f"{label} became reachable from the Internet", risky=True))
        if old.get("desired") != w.get("desired") and w.get("desired") is not None:
            out.append(_item("workloads", "changed", w["name"], w["namespace"],
                             f"{label} scaled from {old.get('desired')} to {w.get('desired')} replicas"))
        if old.get("sa") != w.get("sa"):
            out.append(_item("workloads", "changed", w["name"], w["namespace"],
                             f"{label} now runs as {w.get('sa')} (was {old.get('sa')})"))
    for k, w in p.items():
        if k not in c:
            out.append(_item("workloads", "removed", w["name"], w["namespace"], f"{w['kind']} {w['name']} is gone"))


def _services(prev, cur, out):
    p, c = _index(prev, "namespace", "name"), _index(cur, "namespace", "name")
    for k, s in c.items():
        old = p.get(k)
        if not old and s.get("external"):
            out.append(_item("services", "added", s["name"], s["namespace"],
                             f"New {s['type']} service {s['name']} open to the outside", risky=True))
        elif not old:
            out.append(_item("services", "added", s["name"], s["namespace"], f"New service {s['name']}"))
        elif s.get("external") and not old.get("external"):
            out.append(_item("services", "changed", s["name"], s["namespace"],
                             f"Service {s['name']} changed from {old.get('type')} to {s['type']} and is now open to the outside",
                             risky=True))
    for k, s in p.items():
        if k not in c:
            out.append(_item("services", "removed", s["name"], s["namespace"], f"Service {s['name']} is gone"))


def _bindings(prev, cur, out):
    p, c = _index(prev, "kind", "namespace", "name"), _index(cur, "kind", "namespace", "name")
    for k, b in c.items():
        old = p.get(k)
        wide = bool(b.get("grants")) and not b.get("builtin")
        who = ", ".join((b.get("subjects") or [])[:3])
        if not old:
            out.append(_item("access", "added", b["name"], b.get("namespace"),
                             f"New {b['kind']} {b['name']}: {who} get {b.get('role')}"
                             + (f" ({', '.join(b['grants'])})" if b.get("grants") else ""), risky=wide))
        elif old.get("role") != b.get("role") or old.get("subjects") != b.get("subjects"):
            out.append(_item("access", "changed", b["name"], b.get("namespace"),
                             f"{b['kind']} {b['name']} changed: {who} now get {b.get('role')}", risky=wide))
    for k, b in p.items():
        if k not in c:
            out.append(_item("access", "removed", b["name"], b.get("namespace"), f"{b['kind']} {b['name']} was removed"))


def _namespaces(prev, cur, out):
    p, c = _index(prev, "name"), _index(cur, "name")
    for k, n in c.items():
        old = p.get(k)
        if not old:
            out.append(_item("policies", "added", n["name"], "", f"New namespace {n['name']}"
                             + ("" if n.get("policies") else ", with no network rules"),
                             risky=not n.get("system") and not n.get("policies")))
            continue
        if old.get("policies") and not n.get("policies"):
            out.append(_item("policies", "changed", n["name"], "", f"Namespace {n['name']} lost all its network rules", risky=True))
        if old.get("psa") == "restricted" and n.get("psa") != "restricted":
            out.append(_item("policies", "changed", n["name"], "",
                             f"Namespace {n['name']} no longer enforces the restricted Pod Security level", risky=True))


def diff(prev: dict, cur: dict) -> list:
    """Changes between two cluster inventories (the `sections` of cluster_inventory)."""
    ps, cs = (prev or {}).get("sections", {}), (cur or {}).get("sections", {})
    out: list = []
    if not ps or not cs:
        return out
    _workloads(ps.get("workloads"), cs.get("workloads"), out)
    _services(ps.get("services"), cs.get("services"), out)
    _bindings(ps.get("bindings"), cs.get("bindings"), out)
    _namespaces(ps.get("namespaces"), cs.get("namespaces"), out)
    out.sort(key=lambda i: (not i["risky"], i["section"], i["name"]))
    return out
