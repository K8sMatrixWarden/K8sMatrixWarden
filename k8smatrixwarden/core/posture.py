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

Four honesty rules:

  * A finding is only `resolved` when the current scan actually looked for it, i.e. its
    rule was in the resolved rule set. A narrower re-scan silently "resolving" everything
    it did not run is the classic false-green, so those land in `not_rescanned`. That set
    counts rules that RAN: a rule that crashed is excluded upstream, or a broken rule would
    report its own findings as fixed.
  * A finding is only `new` when it had not been seen before. If the previous scan never
    evaluated its rule, that scan's silence is not evidence of absence, so the finding was
    open the whole time and is reported as persistent. This is the false-green's mirror
    image: it would tell an analyst the cluster just got worse when nothing changed.
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

    appeared = [k for k in cur if k not in prev]
    gone = [k for k in prev if k not in cur]
    # Only a rule this scan actually RAN can resolve a finding. Everything else is simply
    # out of scope for this comparison and is reported as such, never as a fix.
    resolved_keys = [k for k in gone if prev[k].rule_id in rescanned]
    not_rescanned = [k for k in gone if prev[k].rule_id not in rescanned]
    in_both = [k for k in cur if k in prev]

    # The mirror image of a false resolution. If the PREVIOUS scan did not evaluate this
    # rule (a narrower selector, or the rule crashed), its absence there is not evidence the
    # finding went away, so its presence now is not evidence it appeared. Reporting it as
    # `new` tells an analyst the cluster just got worse when nothing changed. These are
    # still-open findings that the last scan simply did not look at.
    carried = _carried_over(appeared, cur, previous)
    new_keys = [k for k in appeared if k not in carried]
    persistent_keys = in_both + [k for k in appeared if k in carried]

    # Severity movement needs BOTH sides, so only findings present in both scans qualify.
    # A carried-over finding has no previous severity to compare against.
    changed = []
    for key in in_both:
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
        "persistent": [{**_view(cur[k]),
                        "unevaluated_in_previous_scan": k in carried}
                       for k in persistent_keys],
        "not_rescanned": [_view(prev[k]) for k in not_rescanned],
        "summary": _summary(previous, current, new_keys, resolved_keys,
                            persistent_keys, regressed, len(carried)),
        # The same comparison at the remediation level. Reported alongside, never instead:
        # the resource-level lists above remain the evidence.
        "workload": _workload_compare(previous, current, rescanned),
    }


def _workload_key(finding, cluster: str) -> str:
    """Cross-scan identity of a workload-level issue: rule x owning workload.

    Recomputed from the resource rather than read off `finding.aggregation_group`, because a
    report saved before workload aggregation existed carries no group and would otherwise
    compare as a different issue purely because of when it was written.
    """
    from .workload import aggregation_group
    return aggregation_group(finding, cluster)


def _workload_compare(previous: Optional[ScanResult], current: ScanResult,
                      rescanned: set) -> dict:
    """new / resolved / persistent at the (rule x owning workload) level.

    This is the level at which "did anything actually change?" can be answered. Kubernetes
    replaces Pods constantly: a rollout deletes Pod-abc, creates ReplicaSet-def and
    Pod-def-xyz, and every resource key changes even though the workload's configuration is
    identical. At resource level that is honestly reported as findings resolved and findings
    appeared; read as a posture summary it says the cluster changed when it did not.

    The rule about resolution is the same one the resource level uses and is not relaxed
    here: an issue counts as resolved only if the rule that raised it actually ran again.
    """
    def by_issue(result):
        if result is None:
            return {}
        cluster = getattr(result, "cluster_name", "") or ""
        out: dict = {}
        for finding in result.findings:
            if finding.severity.weight <= 0:
                continue
            out.setdefault(_workload_key(finding, cluster), finding)
        return out

    cur, prev = by_issue(current), by_issue(previous)
    appeared = [k for k in cur if k not in prev]
    gone = [k for k in prev if k not in cur]
    resolved = [k for k in gone if prev[k].rule_id in rescanned]
    not_rescanned = [k for k in gone if prev[k].rule_id not in rescanned]
    persistent = [k for k in cur if k in prev]

    def view(key, finding):
        from .workload import workload_id
        cluster = getattr(current, "cluster_name", "") or ""
        return {"key": key, "rule_id": finding.rule_id, "title": finding.title,
                "severity": finding.severity.label,
                "owning_workload_id": workload_id(finding.resource, cluster),
                "namespace": finding.resource.namespace}

    return {
        "previous_issues": len(prev),
        "current_issues": len(cur),
        "new": [view(k, cur[k]) for k in appeared],
        "resolved": [view(k, prev[k]) for k in resolved],
        "persistent": [view(k, cur[k]) for k in persistent],
        "not_rescanned": [view(k, prev[k]) for k in not_rescanned],
        "summary": (f"{len(appeared)} new, {len(resolved)} resolved, "
                    f"{len(persistent)} still open, at the (rule x owning workload) "
                    f"level"),
    }


def _carried_over(appeared: list, cur: dict, previous) -> set:
    """Of the findings absent from the previous scan, which cannot honestly be called new?

    The previous scan's own evaluated-rule set answers this exactly: if that scan never ran
    this rule, its silence carries no information, so the finding's presence now is not
    evidence that it appeared. This is the same authority the `resolved` gate uses, applied
    to the opposite direction, and it needs no timestamp comparison, which matters because
    `generated_at` has second resolution and two scans can share it.

    A finding whose rule the previous scan DID run is genuinely absent-then-present, and
    stays in `new` (or is picked up as a regression when history shows it was fixed)."""
    if previous is None:
        return set()                       # no previous scan: everything really is new
    evaluated_before = set(getattr(previous, "resolved_rule_ids", []) or [])
    return {k for k in appeared if (cur[k].rule_id or "") not in evaluated_before}


def _regressions(new_keys: list, cur: dict, timeline: Optional[dict]) -> list[dict]:
    """A new-in-this-scan finding that the timeline shows was resolved before. That is a
    regression, materially different from something being found for the first time.

    Both resolution fields are consulted. `resolved_at` is set while the finding is gone;
    once it comes back the store moves that date to `last_resolved_at`, so by the time this
    comparison runs against the CURRENT scan the evidence lives there."""
    if not timeline:
        return []
    out = []
    for key in new_keys:
        entry = timeline.get(key) or {}
        was_resolved = entry.get("resolved_at") or entry.get("last_resolved_at")
        if was_resolved:
            out.append({**_view(cur[key]), "resolved_at": was_resolved,
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
             regressed, carried: int = 0) -> str:
    if previous is None:
        return (f"First scan in this store: {len(new_keys)} finding(s) recorded as the "
                f"baseline, nothing to compare against yet.")
    # The carried-over count is stated rather than folded silently into "still open": those
    # findings are open, but this comparison cannot say whether they are recent.
    gap = (f" {carried} of the open finding(s) were not evaluated by the previous scan, so "
           f"no claim is made about when they appeared." if carried else "")
    return (f"vs {previous.display_name}: {len(new_keys)} new "
            f"({len(regressed)} of them regressions), {len(resolved_keys)} resolved, "
            f"{len(persistent_keys)} still open. Risk {previous.risk.cluster_risk} -> "
            f"{current.risk.cluster_risk} ({_direction(previous, current)}).{gap}")


def latest_change(store, scan_id: Optional[str] = None) -> dict:
    """Posture change for a stored scan against the previous scan OF THE SAME SCOPE.

    "Same scope" means same cluster AND same resource scope (`cluster-wide`,
    `namespace/production`, ...). Comparing across clusters is meaningless, and comparing a
    namespace-scoped scan against a cluster-wide one manufactures a wave of fake
    resolutions, everything outside the namespace simply was not looked at. The timeline
    used for regression detection is filtered to the same scope for the same reason.

    Returns {} when the store has nothing to compare."""
    reports = store.list()
    if not reports:
        return {}
    known = {r.scan_id for r in reports}
    if scan_id and scan_id not in known:
        # Asking about a scan that is not here is a question with no answer. Falling back
        # to the newest scan used to look helpful and was a silent wrong answer: the caller
        # asked what changed in scan X and got scan Y's diff, with nothing saying so. An
        # OMITTED scan_id still means "the latest", which is a different request.
        raise FileNotFoundError(f"no stored report with scan-id {scan_id!r}")
    target = scan_id if scan_id in known else reports[0].scan_id
    index = next(i for i, r in enumerate(reports) if r.scan_id == target)
    here = reports[index]
    scope = store.scope_key_of(here.cluster, here.scope)
    earlier = next((r for r in reports[index + 1:]
                    if store.scope_key_of(r.cluster, r.scope) == scope), None)
    current = store.load(target)
    previous = store.load(earlier.scan_id) if earlier else None
    return compare(previous, current, timeline=store.raw_timeline(scope=scope))
