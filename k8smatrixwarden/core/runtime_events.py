"""
The read model for `GET /api/runtime`: recent runtime events, flattened for reading.

This adds no storage. Runtime evidence already lives on the saved `ScanResult.runtime`
block, written by the pull feed (`scan --live`), the dashboard's Refresh, and the
falcosidekick push endpoint. A second event store would be a second source of truth and the
two would drift; this module only reshapes what is already there.

Two kinds of record land in one list, each keeping its own character rather than being
flattened into a common lie:

  * a correlation  , a runtime alert joined (or not) to a static finding
  * a drift record , a Pod behaving against its own declared securityContext

Both carry the provenance model: who detected it, under whose name, and how sure we are of
the resource it happened to.

Old saved scans predate parts of that model (a report written before provenance existed has
no `detection_source`). Every field is read defensively and reported as `unknown` rather
than guessed, so a year-old report still renders instead of erroring.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

#: Query values for `?source=`. `kmw` and `falco` select by DETECTOR; `audit` and `drift`
#: select by event stream, which is the distinction an operator actually asks about.
SOURCES = ("all", "kmw", "falco", "audit", "drift")

_DURATION = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.I)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_since(value) -> Optional[int]:
    """`?since=` as a number of seconds, or None when absent or unparseable.

    Accepts `90s`, `15m`, `2h`, `7d`, `1w`, or a bare number of seconds. Unparseable input
    returns None, meaning no time filter, and the caller reports it as a warning rather than
    silently narrowing the window, which would hide events.
    """
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        return int(text) or None
    match = _DURATION.match(text)
    if not match:
        return None
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2).lower()]


def _epoch(timestamp) -> float:
    """An ISO-8601 timestamp as epoch seconds, or 0.0 when it cannot be read.

    Events with no usable timestamp sort last rather than being dropped: an event that
    happened is still evidence, even when it cannot be placed in time.
    """
    if not timestamp:
        return 0.0
    from datetime import datetime, timezone
    text = str(timestamp).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _event_id(record: dict) -> str:
    """A stable id for one runtime event.

    Derived, not stored: reshaping the same event twice must produce the same id, and no id
    may change between requests. Hashes the fields that identify the observation rather than
    using a counter, so it survives re-reading the same report.
    """
    seed = "|".join(str(record.get(key) or "") for key in
                    ("kind", "timestamp", "rule", "detection_source", "namespace", "pod",
                     "process", "title"))
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]


def _workload_of(entry: dict) -> Optional[str]:
    """The workload a correlation points at, taken from the static finding it matched.

    Reported only when a finding actually named one. It is never inferred from the pod name,
    which would be exactly the resource-identity guessing the correlator refuses to do.
    """
    for finding in (entry.get("static_findings") or []):
        resource = (finding or {}).get("resource") if isinstance(finding, dict) else None
        if resource:
            return resource
    related = entry.get("related_finding") or {}
    return related.get("resource") or None


def _from_correlation(entry: dict, cluster: str) -> dict:
    runtime_view = entry.get("runtime") or {}
    event = runtime_view.get("event") or {}
    record = {
        "kind": "correlation",
        "timestamp": entry.get("timestamp") or runtime_view.get("timestamp") or "",
        # `source` is the event STREAM, `detection_source` the DETECTOR. Reports written
        # before the provenance model carry neither, so both state `unknown` rather than
        # assuming one.
        "source": runtime_view.get("source") or event.get("source") or "unknown",
        "detection_source": runtime_view.get("detection_source") or "unknown",
        "provider": runtime_view.get("provider") or "unknown",
        "rule": runtime_view.get("rule_id") or "",
        "title": runtime_view.get("title") or "",
        "provider_rule": runtime_view.get("provider_rule"),
        "provider_priority": runtime_view.get("provider_priority"),
        "supporting_evidence": runtime_view.get("supporting_evidence"),
        "severity": runtime_view.get("severity") or entry.get("severity") or "UNKNOWN",
        "tactic": entry.get("tactic") or "",
        "technique_id": runtime_view.get("technique_id"),
        "technique_name": runtime_view.get("technique_name"),
        "cluster": entry.get("cluster") or cluster or None,
        "namespace": entry.get("namespace") or event.get("namespace") or None,
        "pod": entry.get("resource") or event.get("pod") or None,
        "container": event.get("container") or None,
        "process": event.get("proc") or None,
        "workload": _workload_of(entry),
        "correlation": entry.get("confidence") or "unknown",
        "verdict": entry.get("verdict") or "",
        "freshness": entry.get("freshness") or "unknown",
        "age_days": entry.get("age_days"),
        "identity_status": event.get("identity_status") or "unknown",
        "identity_missing": event.get("identity_missing") or [],
        "identity_reason": event.get("identity_reason"),
        # Distinct rule ids, in order. One runtime event commonly matches the same rule on
        # several resources; listing that id five times reads as a duplication bug rather
        # than as "five findings share this weakness".
        "static_findings": list(dict.fromkeys(
            f.get("rule_id") for f in (entry.get("static_findings") or [])
            if isinstance(f, dict) and f.get("rule_id")))[:5],
    }
    record["event_id"] = _event_id(record)
    return record


def _from_drift(entry: dict, cluster: str) -> dict:
    """A drift record: a Pod behaving against what it declared.

    Drift is its own detection kind, not a correlation. It is K8sMatrixWarden's own
    comparison of declared securityContext against observed behaviour, so its detector is
    always `kmw` and there is no provider rule behind it.
    """
    record = {
        "kind": "drift",
        "timestamp": entry.get("timestamp") or "",
        "source": "drift",
        "detection_source": "kmw",
        "provider": "k8smatrixwarden",
        "rule": "drift",
        "title": entry.get("verdict") or "configuration drift",
        "provider_rule": None,
        "provider_priority": None,
        "supporting_evidence": None,
        "severity": entry.get("severity") or "CRITICAL",
        "tactic": entry.get("tactic") or "",
        "technique_id": None,
        "technique_name": None,
        "cluster": cluster or None,
        "namespace": entry.get("namespace") or None,
        "pod": entry.get("pod") or None,
        "container": entry.get("container") or None,
        "process": entry.get("proc") or None,
        "workload": None,
        "correlation": "drift",
        "verdict": entry.get("verdict") or "",
        "freshness": entry.get("freshness") or "unknown",
        "age_days": entry.get("age_days"),
        "identity_status": "complete" if entry.get("pod") else "unknown",
        "identity_missing": [] if entry.get("pod") else ["pod"],
        "identity_reason": None,
        "declared": entry.get("declared"),
        "observed": entry.get("observed"),
        "static_findings": [],
    }
    record["event_id"] = _event_id(record)
    return record


def flatten(runtime: Optional[dict], cluster: str = "") -> list:
    """Every runtime record on a scan's runtime block, newest first.

    Ordering is deterministic and total: newest timestamp first, then the event id, which is
    a content hash. Two events written in the same microsecond therefore always come back in
    the same order, so a page or an API response never reshuffles between requests.
    """
    runtime = runtime or {}
    out = []
    correlation = runtime.get("correlation") or {}
    for entry in (correlation.get("correlations") or []):
        if isinstance(entry, dict):
            out.append(_from_correlation(entry, cluster))
    drift = runtime.get("drift") or {}
    for entry in (drift.get("drift") or []):
        if isinstance(entry, dict):
            out.append(_from_drift(entry, cluster))
    out.sort(key=lambda r: (-_epoch(r["timestamp"]), r["event_id"]))
    return out


def apply_filters(records: list, *, source: str = "all", severity: str = "",
                  namespace: str = "", since_seconds: Optional[int] = None,
                  now: Optional[float] = None) -> list:
    """Filter the flattened records. Every filter narrows; none reorders."""
    out = list(records)
    wanted = (source or "all").strip().lower()
    if wanted and wanted != "all":
        if wanted == "audit":
            out = [r for r in out if r["source"] == "audit"]
        elif wanted == "drift":
            out = [r for r in out if r["kind"] == "drift"]
        else:                                  # kmw | falco select by DETECTOR
            out = [r for r in out if r["detection_source"] == wanted]
    if severity:
        levels = {s.strip().upper() for s in str(severity).split(",") if s.strip()}
        if levels:
            out = [r for r in out if str(r["severity"]).upper() in levels]
    if namespace:
        out = [r for r in out if r["namespace"] == namespace]
    if since_seconds:
        import time
        cutoff = (now if now is not None else time.time()) - since_seconds
        # An event with no readable timestamp is kept: dropping it would let a time filter
        # silently hide evidence, which is the failure this whole layer exists to avoid.
        out = [r for r in out
               if _epoch(r["timestamp"]) == 0.0 or _epoch(r["timestamp"]) >= cutoff]
    return out


def summarize(records: list) -> dict:
    """Counts by detector, stream, correlation, severity and identity, for the page header."""
    def tally(key: str) -> dict:
        counts: dict = {}
        for record in records:
            value = str(record.get(key) or "unknown")
            counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items()))

    return {"total": len(records), "by_detector": tally("detection_source"),
            "by_source": tally("source"), "by_correlation": tally("correlation"),
            "by_severity": tally("severity"), "by_identity": tally("identity_status")}
