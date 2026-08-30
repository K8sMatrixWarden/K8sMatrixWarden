"""
Historical security posture (§16), what changed between two scans.

The report store already keeps every scan and a per-finding first/last-seen timeline. This
module turns that into the question a security lead actually asks: *did we get better or
worse, and because of what?*

Finding identity is the whole game. Two scans are comparable only through a STABLE key,
here `rule_id | kind | name | namespace`, the same key the store's timeline uses, so
"resolved" means the exact same rule on the exact same object stopped firing. Anything
looser (matching on title, or on rule id alone) would report a pod being rescheduled as a
fix.

Three honesty rules:

  * A finding is only `resolved` when the current scan actually looked for it, i.e. its
    rule was in the resolved rule set. A narrower re-scan silently "resolving" everything
    it did not run is the classic false-green, so those land in `not_rescanned`.
  * A `regression` is a finding that was previously seen, then resolved, and is back. That
    needs history, not two scans, so it is derived from the store's timeline when one is
    supplied.
  * Nothing here re-scores or re-ranks. It reports movement between two given results.
"""
from __future__ import annotations

from typing import Optional

from .models import Severity
from .results import ScanResult

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def finding_key(finding) -> str:
    """The stable cross-scan identity of a finding (same key as the store's timeline)."""
    r = finding.resource
    return "|".join([finding.rule_id or "", r.kind or "", r.name or "",
                     r.namespace or ""])


def _view(finding) -> dict:
    return {"key": finding_key(finding), "rule_id": finding.rule_id,
            "title": finding.title, "severity": finding.severity.label,
            "resource": str(finding.resource),
            "namespace": finding.resource.namespace}


def _real(result: ScanResult) -> dict:
    """Scoreable findings by key, INFO/engine-error rows are bookkeeping, not posture."""
    return {finding_key(f): f for f in result.findings if f.severity.weight > 0}


def compare(previous: Optional[ScanResult], current: ScanResult,
            timeline: Optional[dict] = None) -> dict:
    """Diff two scans into new / resolved / persistent / regressed, plus severity movement.

    `previous` may be None (the first scan ever), in which case everything is new and
    nothing can be claimed resolved."""
    cur = _real(current)
    prev = _real(previous) if previous is not None else {}
    rescanned = set(current.resolved_rule_ids)

    new_keys = [k for k in cur if k not in prev]
    gone = [k for k in prev if k not in cur]
    # Only a rule this scan actually RAN can resolve a finding. Everything else is simply
    # out of scope for this comparison and is reported as such, never as a fix.
    resolved_keys = [k for k in gone if prev[k].rule_id in rescanned]
    not_rescanned = [k for k in gone if prev[k].rule_id not in rescanned]
    persistent_keys = [k for k in cur if k in prev]

    changed = []
    for key in persistent_keys:
        before, after = prev[key].severity.label, cur[key].severity.label
        if before != after:
            changed.append({**_view(cur[key]), "severity_was": before,
                            "severity_now": after,
                            "direction": ("worse" if Severity.parse(after).order
                                          > Severity.parse(before).order else "better")})

    regressed = _regressions(new_keys, cur, timeline)
    regressed_keys = {r["key"] for r in regressed}

    counts = {sev: {"previous": _count(prev, sev), "current": _count(cur, sev)}
              for sev in _SEV_ORDER}
    for sev in _SEV_ORDER:
        counts[sev]["delta"] = counts[sev]["current"] - counts[sev]["previous"]

    return {
        "previous_scan_id": previous.scan_id if previous else None,
        "current_scan_id": current.scan_id,
        "previous_generated_at": previous.generated_at if previous else None,
        "current_generated_at": current.generated_at,
        "risk": {"previous": previous.risk.cluster_risk if previous else None,
                 "current": current.risk.cluster_risk,
                 "direction": _direction(previous, current)},
        "counts": counts,
        "new": [_view(cur[k]) for k in new_keys if k not in regressed_keys],
        "regressed": regressed,
        "resolved": [_view(prev[k]) for k in resolved_keys],
        "persistent": [_view(cur[k]) for k in persistent_keys],
        "not_rescanned": [_view(prev[k]) for k in not_rescanned],
        "summary": _summary(previous, current, new_keys, resolved_keys,
                            persistent_keys, regressed),
    }


def _regressions(new_keys: list, cur: dict, timeline: Optional[dict]) -> list[dict]:
    """A new-in-this-scan finding that the timeline shows was resolved before. That is a
    regression, materially different from something being found for the first time."""
    if not timeline:
        return []
    out = []
    for key in new_keys:
        entry = timeline.get(key)
        if entry and entry.get("resolved_at"):
            out.append({**_view(cur[key]), "resolved_at": entry["resolved_at"],
                        "first_seen": entry.get("first_seen")})
    return out


def _count(bucket: dict, severity: str) -> int:
    return sum(1 for f in bucket.values() if f.severity.label == severity)


def _direction(previous: Optional[ScanResult], current: ScanResult) -> str:
    if previous is None:
        return "baseline"
    before, after = previous.risk.cluster_risk, current.risk.cluster_risk
    if after > before:
        return "worse"
    if after < before:
        return "better"
    return "unchanged"


def _summary(previous, current, new_keys, resolved_keys, persistent_keys,
             regressed) -> str:
    if previous is None:
        return (f"First scan in this store: {len(new_keys)} finding(s) recorded as the "
                f"baseline, nothing to compare against yet.")
    return (f"vs {previous.display_name}: {len(new_keys)} new "
            f"({len(regressed)} of them regressions), {len(resolved_keys)} resolved, "
            f"{len(persistent_keys)} still open. Risk {previous.risk.cluster_risk} -> "
            f"{current.risk.cluster_risk} ({_direction(previous, current)}).")


def latest_change(store, scan_id: Optional[str] = None) -> dict:
    """Posture change for a stored scan against the previous scan OF THE SAME CLUSTER.

    Comparing across clusters would be meaningless, and comparing against a differently
    scoped scan of the same cluster is what `not_rescanned` guards. Returns {} when the
    store has nothing to compare."""
    reports = store.list()
    if not reports:
        return {}
    target = scan_id if any(r.scan_id == scan_id for r in reports) else reports[0].scan_id
    index = next(i for i, r in enumerate(reports) if r.scan_id == target)
    cluster = reports[index].cluster
    earlier = next((r for r in reports[index + 1:] if r.cluster == cluster), None)
    current = store.load(target)
    previous = store.load(earlier.scan_id) if earlier else None
    return compare(previous, current, timeline=store.raw_timeline())
