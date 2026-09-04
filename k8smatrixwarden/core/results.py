"""The aggregate result object produced by a scan and consumed by reporting."""
from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .models import Finding, ScanRequest
from .scoring import RiskResult
from .timeutil import format_ist, ist_date_compact, ist_timestamp, now_ist


def slugify_name(name: str) -> str:
    """Turn a human scan name into a filesystem-/URL-safe slug for use inside a scan id.

    Lowercased, non-alphanumeric runs collapsed to single hyphens, trimmed, and capped so
    the resulting scan id stays short. Always matches the report store's `_SAFE_SCAN_ID`
    charset ([A-Za-z0-9._-]); returns "" when nothing usable remains."""
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug[:40]


def _tool_version() -> str:
    """The package's own version, the single source of truth for what reports claim."""
    try:
        from .. import __version__
        return __version__
    except Exception:                      # pragma: no cover - importable in every path
        return "0.0.0"


#: Width of the trailing subsecond field, in distinct values. 4 hex characters, unchanged
#: from when the field really was a subsecond reading, so the public id format is the same.
_SUBSECOND_SPAN = 0xFFFF
_SUBSECOND_MAX = 0xFFFF

#: The last (stamp, subsecond) this process issued, and the lock protecting it. Uniqueness
#: and ordering live here rather than in the clock because the clock cannot carry them: on
#: Windows `datetime.now()` advances in ~15.6 ms steps, so two thousand consecutive reads
#: return two distinct microsecond values and hundreds of scans land in one bucket. Reports
#: are also saved from the web app's request handlers, so more than one thread can mint at
#: once and two threads reading the same last value would mint the same id.
_LAST_ID: tuple = ("", -1)
_ID_LOCK = threading.Lock()


def _scan_id(name: str = "") -> str:
    """Build a scan id of the form ``<name>-YYYYMMDD-HHMMSS-<subsecond>`` so the id itself
    carries the (optional) scan name, the date, and the time, the report naming format
    surfaced everywhere (files on disk, download filenames, dashboard history). Falls back
    to the ``scan`` prefix when no name is given, preserving the historic ``scan-…`` shape.

    The trailing 4-char field separates scans started in the same second, and it is
    ORDER-PRESERVING rather than a hash. `generated_at` only has second resolution, so the
    report store breaks ties on the scan id; a hashed suffix made that tiebreak deterministic
    but arbitrary, which let the *later* of two same-second scans sort first. Posture then
    compared in the wrong direction and reported new findings as resolved.

    The field is SEEDED from the clock and then advanced by this process, rather than read
    from the clock each time. Reading it was the bug: it assumed roughly microsecond
    resolution, and on a platform whose wall clock ticks every 15.6 ms every scan inside a
    tick got the same id and each report overwrote the last. Seeding keeps the id
    approximately chronological to the outside world; the counter is what makes it unique
    and strictly increasing.

    Two scans minted back to back therefore always differ, and always sort in the order they
    were minted, whatever the clock's resolution. This holds within a process; the report
    store separately refuses to let one report overwrite a different one, which is what
    covers two processes scanning at once.
    """
    global _LAST_ID
    now = now_ist()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    bucket = now.microsecond * _SUBSECOND_SPAN // 1000000
    with _ID_LOCK:
        last_stamp, last_bucket = _LAST_ID
        if stamp < last_stamp:
            # The wall clock moved backwards (an NTP step, an operator setting the time).
            # Chronological order is the property every caller depends on, so the id keeps
            # advancing rather than following the clock back over ids already issued.
            stamp, bucket = last_stamp, last_bucket + 1
        elif stamp == last_stamp and bucket <= last_bucket:
            bucket = last_bucket + 1
        while bucket > _SUBSECOND_MAX:
            # More than 65 536 ids inside one second. Unreachable in practice, a scan costs
            # milliseconds, but the counter must never wrap onto an id already issued, so
            # the mint waits for the second to turn instead of repeating one.
            time.sleep(0.001)
            now = now_ist()
            if now.strftime("%Y%m%d-%H%M%S") > stamp:
                stamp = now.strftime("%Y%m%d-%H%M%S")
                bucket = now.microsecond * _SUBSECOND_SPAN // 1000000
        _LAST_ID = (stamp, bucket)
    base = slugify_name(name) or "scan"
    return f"{base}-{stamp}-{bucket:04x}"


@dataclass
class ScanResult:
    request: ScanRequest
    findings: list[Finding]
    risk: RiskResult
    #: Rules that were selected AND actually completed. A rule that raised is removed here
    #: and listed in `failed_rule_ids` instead, because historical posture uses this set to
    #: decide what a scan was entitled to call `resolved`. Leaving a crashed rule in would
    #: let a broken rule report its own findings as fixed, and the risk score would improve
    #: to match. "Selected" is `request.selector` resolved; this is "evaluated".
    resolved_rule_ids: list[str]
    counts: dict[str, int] = field(default_factory=dict)
    by_tactic: dict[str, int] = field(default_factory=dict)
    by_shard: dict[str, int] = field(default_factory=dict)
    #: Optional human scan name. When set, it seeds the scan_id and the display name so a
    #: report is identifiable as "<name> + date + time" instead of an opaque id.
    name: str = ""
    #: Left empty on construction so __post_init__ can derive it from `name`; an explicit
    #: id (a replayed/stored report, the coverage pseudo-scan) is always respected.
    scan_id: str = ""
    cluster_name: str = "target-cluster"
    generated_at: str = field(default_factory=ist_timestamp)
    #: Stamped on every report. Read from the package rather than written here, so a
    #: release cannot ship reports claiming a version the package does not have: this said
    #: "1.0" while the package was already 1.0.0.
    tool_version: str = field(default_factory=lambda: _tool_version())
    mode: str = "mock"
    #: Non-fatal collection problems (resource types the scanner's RBAC could not read,
    #: API groups absent on this cluster). Carried on the result, not just printed once, 
    #: so every surface can show that coverage was partial.
    warnings: list[str] = field(default_factory=list)
    #: False when the collector could not read the cluster at all. Such a result has zero
    #: findings because nothing was inspected, NOT because the cluster is clean, and every
    #: surface must say so instead of rendering a passing score.
    evidence_ok: bool = True
    #: Rules that were selected but raised, so their result is UNKNOWN for this scan rather
    #: than "nothing found". Kept separate from `resolved_rule_ids` so no surface can mistake
    #: a rule that failed for a rule that came back clean.
    failed_rule_ids: list[str] = field(default_factory=list)
    #: Optional runtime block baked in at scan time from the live Falco feed:
    #: {"correlation": {...}, "drift": {...}, "events_seen": int, "collected_at": str,
    #: "source": "falco-logs"}. None when the scan pulled no runtime feed (mock scans, or a
    #: live scan with --no-runtime / no Falco). Lets the dashboard show the runtime
    #: correlation without a manual paste. See core/correlation.py + agents/runtime.py.
    runtime: Optional[dict] = None
    #: Cluster inventory + per-pod exposure buckets (nodes/namespaces/pods counts and a
    #: worst-wins exposure split) for the dashboard scope bar. Empty for scans saved before
    #: this existed, so the bar simply doesn't render on old reports. See reachability.inventory.
    inventory: dict = field(default_factory=dict)
    #: Evidence coverage + assessment confidence (core/coverage.py): what fraction of the
    #: requested evidence was actually readable, per kind and per domain. Separate from the
    #: risk score on purpose, "how bad is it" and "how much did we see" are different
    #: questions. Empty for scans saved before this existed.
    coverage: dict = field(default_factory=dict)
    #: Workload-level aggregation (core/workload.py). `workload_issues` is one entry per
    #: (rule x owning workload), the remediation units behind the resource-level findings;
    #: `aggregation` carries both counts and how they relate. The findings list is
    #: untouched and remains the evidence. Empty on scans saved before this existed, so an
    #: old report simply shows the resource count on its own.
    workload_issues: list = field(default_factory=list)
    aggregation: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = _scan_id(self.name)

    @property
    def display_name(self) -> str:
        """Report name as shown to humans: the scan name (if any) followed by its date and
        time, e.g. "Prod nightly, 19 Jul 2026, 01:13 IST". Falls back to the scan id when
        the scan was never named."""
        when = format_ist(self.generated_at)
        return f"{self.name}, {when}" if self.name else f"{self.scan_id}, {when}"

    def total(self) -> int:
        return sum(v for k, v in self.counts.items() if k != "INFO")

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "name": self.name,
            "display_name": self.display_name,
            "cluster": self.cluster_name,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "mode": self.mode,
            "warnings": list(self.warnings),
            "evidence_ok": self.evidence_ok,
            "scope": self.request.scope.describe(),
            "selector": self.request.selector.describe(),
            "resolved_rules": self.resolved_rule_ids,
            "risk": {
                "cluster_risk": self.risk.cluster_risk,
                "security_score": self.risk.security_score,
                "rating": self.risk.rating,
                # Why the score is what it is (§7). Additive: every existing consumer of
                # this block reads the three keys above and is unaffected.
                "explanation": self.risk.explanation,
            },
            "counts": self.counts,
            "workload_issues": list(self.workload_issues),
            "aggregation": self.aggregation,
            "by_tactic": self.by_tactic,
            "by_shard": self.by_shard,
            "findings": [f.as_dict() for f in self.findings],
            # Only present when a live scan pulled a Falco feed, kept out of the dict
            # otherwise so existing reports/round-trips are byte-for-byte unchanged.
            **({"runtime": self.runtime} if self.runtime else {}),
            **({"inventory": self.inventory} if self.inventory else {}),
            **({"coverage": self.coverage} if self.coverage else {}),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        """Reconstruct a ScanResult from as_dict(), used by the report store so a stored
        scan can be re-rendered into any format later."""
        rk = d.get("risk", {}) or {}
        rating = rk.get("rating", "Fair")
        risk = RiskResult(
            cluster_risk=float(rk.get("cluster_risk", 0.0)),
            security_score=int(rk.get("security_score", 0)),
            rating=rating,
            rating_emoji=_RATING_EMOJI.get(rating, "🟡"),
            raw=0.0,
            explanation=rk.get("explanation", {}) or {})
        return cls(
            request=_ReplayRequest(_Descr(d.get("scope", "")),
                                   _Descr(d.get("selector", ""))),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            risk=risk,
            resolved_rule_ids=list(d.get("resolved_rules", [])),
            counts=d.get("counts", {}) or {},
            workload_issues=list(d.get("workload_issues", []) or []),
            aggregation=d.get("aggregation", {}) or {},
            by_tactic=d.get("by_tactic", {}) or {},
            by_shard=d.get("by_shard", {}) or {},
            name=d.get("name", ""),
            scan_id=d.get("scan_id", ""),
            cluster_name=d.get("cluster", "target-cluster"),
            generated_at=d.get("generated_at", ""),
            tool_version=str(d.get("tool_version", "1.0")),
            mode=d.get("mode", "mock"),
            warnings=list(d.get("warnings", []) or []),
            evidence_ok=bool(d.get("evidence_ok", True)),
            runtime=d.get("runtime") or None,
            inventory=d.get("inventory", {}) or {},
            coverage=d.get("coverage", {}) or {})


_RATING_EMOJI = {"Excellent": "🟢", "Good": "🟢", "Fair": "🟡", "Poor": "🟠",
                 "Critical": "🔴", "Unknown": "⚠️"}


@dataclass
class _Descr:
    """A stand-in for Scope/Selector when replaying a stored report, reporting only
    ever calls .describe() on them."""
    _text: str

    def describe(self) -> str:
        return self._text


@dataclass
class _ReplayRequest:
    scope: _Descr
    selector: _Descr
