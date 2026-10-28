"""Who owns a problem, so each team sees its own list.

Owner comes from labels the team already puts on its own objects, first match wins:
the workload's labels (`team`, `owner`, `app.kubernetes.io/team`), then its namespace's
labels or annotations, then the namespace name itself as a last resort. Nothing is guessed:
the label that decided it is recorded next to the owner so a wrong answer is easy to fix.
"""
from __future__ import annotations

KEYS = ("team", "owner", "app.kubernetes.io/team", "app.kubernetes.io/owner")


def _from(mapping: dict):
    for k in KEYS:
        if (mapping or {}).get(k):
            return mapping[k], k
    return None


def owner_of(labels: dict, ns_labels: dict, ns_annotations: dict, namespace):
    hit = _from(labels) or _from(ns_labels) or _from(ns_annotations)
    if hit:
        return {"owner": hit[0], "owner_source": hit[1]}
    return {"owner": namespace or "cluster-wide", "owner_source": "namespace"}


def annotate(issues: list, findings: list, namespaces: list) -> None:
    """Add `owner` and `owner_source` to each workload-issue dict, in place."""
    ns = {(n.get("metadata") or {}).get("name"): n.get("metadata") or {} for n in namespaces}
    by_id = {f.resource_finding_id: f for f in findings}
    for i in issues:
        f = by_id.get((i.get("resource_finding_ids") or [""])[0])
        meta = ns.get(i.get("namespace")) or {}
        i.update(owner_of(dict(getattr(f.resource, "labels", None) or {}) if f else {},
                          meta.get("labels") or {}, meta.get("annotations") or {}, i.get("namespace")))
