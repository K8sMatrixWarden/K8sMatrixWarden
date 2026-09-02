"""
Report Store (§16.4), persists scan results so they can be listed and re-downloaded
later in any format.

A scan result is saved as `<dir>/<scan_id>.json` (its `as_dict()` form). `download` loads a
stored result and re-renders it via the ReportingEngine into whatever format is asked for, 
so you scan once and can export markdown / json / html / sarif afterwards, to any filename.

Pure stdlib; the store is just a directory of JSON files (default `./k8smatrixwarden-reports`).
"""
from __future__ import annotations

import datetime as _dt
import glob
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .results import ScanResult, _scan_id

# Guards the timeline read-modify-write: the web server is threaded, so two concurrent
# saves could otherwise interleave and lose an update. ponytail: in-process lock; a second
# PROCESS scanning the same store concurrently is out of scope (rare, note the ceiling).
_TIMELINE_LOCK = threading.Lock()


def _open_json(path: str):
    """Open a report for reading, retrying across the brief window of a concurrent write.

    Replacing a file is not instantaneous on Windows: a reader that opens at exactly the
    wrong moment gets PermissionError even though the file is neither missing nor locked by
    anyone for long. Ingestion writes reports while the dashboard and the runtime API read
    them, so without this a perfectly ordinary GET can fail during a falcosidekick push.

    The same bounded budget as the writer, and then the error is raised: a read that cannot
    succeed must fail loudly rather than return an empty report, which would render as a
    clean cluster.
    """
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            return open(path, encoding="utf-8")
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_DELAY)


def _peek_json(path: str) -> Optional[dict]:
    """The JSON at `path`, or None if it is absent or unreadable.

    Used only to see whether a report already occupies a scan id. An unreadable file is
    treated as absent rather than as a blocker: refusing to save a new scan because an old
    one is corrupt would turn one damaged report into a lost one."""
    try:
        with _open_json(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


#: How long to keep retrying the final rename, and how often. Windows refuses to replace a
#: file another handle has open, and every reader of a report holds one for the moment it
#: takes to parse, so a writer that gives up on the first refusal loses the write to a
#: perfectly ordinary concurrent read.
_REPLACE_ATTEMPTS = 25
_REPLACE_DELAY = 0.02


def _replace_with_retry(tmp: str, path: str) -> None:
    """os.replace, retried briefly while the destination is held open elsewhere.

    On POSIX a rename over an open file always succeeds. On Windows it raises
    PermissionError (WinError 5) whenever any handle to the destination is open, and the
    dashboard, the runtime API and the correlator all read reports while ingestion writes
    them. Under concurrent load that surfaced as a runtime event being correlated, answered
    200 with `stored: false`, and then simply not existing, which is the silent loss the
    whole ingestion path is built to prevent.

    Readers open a report only long enough to parse it, so the contention is brief and a
    bounded retry clears it. Half a second of retrying, then the error is raised so the
    caller reports the failure rather than pretending it wrote.
    """
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_DELAY)


def _atomic_write_json(path: str, obj) -> None:
    """Write JSON durably: serialise to a temp file in the same dir, then os.replace(), 
    an atomic rename on POSIX/Windows, so a crash mid-write can never leave a half-written
    (unparseable) report or timeline index behind."""
    # Thread id as well as pid: two threads writing the same report shared one temp file,
    # so each could overwrite the other's half-serialised bytes before either renamed.
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        _replace_with_retry(tmp, path)
    except BaseException:
        # serialise failed mid-write, drop the partial temp so no stray file is left.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise

def default_reports_dir() -> str:
    """The shared report store every surface (CLI, MCP, web) reads/writes by default.

    Resolved independently of the current working directory, so a scan saved from the
    CLI or an MCP/LLM client shows up in the web dashboard's scan history without every
    process having to be launched from the same folder. Resolution order:
      1. $K8SMATRIXWARDEN_REPORTS_DIR, if set (point it at an absolute path)
      2. ~/.k8smatrixwarden/reports , per-user, cwd-independent default

    A relative "k8smatrixwarden-reports" used to be the default; because a relative path
    resolves against each process's cwd, a CLI/MCP scan silently landed in a different
    directory than the web server was reading, so it never appeared in the dashboard.
    """
    env = os.environ.get("K8SMATRIXWARDEN_REPORTS_DIR")
    if env and env.strip():
        return os.path.expanduser(env.strip())
    return os.path.join(os.path.expanduser("~"), ".k8smatrixwarden", "reports")


DEFAULT_DIR = default_reports_dir()
#: Timeline index: finding-identity -> first/last seen + resolved. Lets the tool answer
#: "how long has this been open" (MTTD proxy) and "when was it fixed" (MTTR), which a
#: point-in-time scan alone can't. Granularity == scan cadence.
_TIMELINE_FILE = "_timeline.json"

#: A scan id is `<name>-YYYYMMDD-HHMMSS-xxxx` (or `scan-…` when unnamed, or a synthetic id
#: like `coverage`), see core/results.py::_scan_id. Anything with a
#: path separator, `..`, or other filesystem-significant character is rejected before it is
#: ever joined into a path, otherwise a caller-supplied id (a web route param, an
#: LLM-provided argument) could traverse out of the store dir and read arbitrary `*.json`.
_SAFE_SCAN_ID = re.compile(r"[A-Za-z0-9._-]+")


@dataclass
class StoredReport:
    scan_id: str
    path: str
    generated_at: str
    rating: str
    risk_score: float
    total: int
    scope: str
    name: str = ""
    display_name: str = ""
    cluster: str = "target-cluster"


class ReportStore:
    def __init__(self, directory: str = DEFAULT_DIR):
        self.dir = directory

    # -- save ------------------------------------------------------------- #
    def save(self, result: ScanResult) -> str:
        """Persist a scan, and never over a different one.

        Scan ids are unique by construction within a process (results._scan_id), which is
        what stops a run of rapid scans from overwriting each other. Two SEPARATE processes
        scanning at the same moment share no counter, so the id they mint can coincide. The
        guard below is for that case only: it moves aside for a report this scan did not
        write, and stays out of the way of the ordinary re-save that attaches runtime
        correlation to a scan already on disk.
        """
        os.makedirs(self.dir, exist_ok=True)
        payload = result.as_dict()
        path = os.path.join(self.dir, f"{result.scan_id}.json")
        existing = _peek_json(path)
        if existing and existing.get("generated_at") != result.generated_at:
            # A different scan already owns this id. Losing it would take a whole run of
            # history with it, so this one is filed under a fresh id instead. The caller's
            # result is updated so the id it reports back is the id actually on disk.
            result.scan_id = _scan_id(result.name)
            payload = result.as_dict()
            path = os.path.join(self.dir, f"{result.scan_id}.json")
        _atomic_write_json(path, payload)
        self._update_timeline(result)
        return path

    # -- timeline (MTTD/MTTR) --------------------------------------------- #
    # The index accumulates across scans, and a scan "resolves" whatever it did not
    # re-observe. That is only sound WITHIN one security context: a namespace-scoped scan
    # of `staging` must not mark a cluster-wide finding in `production` as fixed, and a scan
    # of cluster B must not resolve cluster A's history. So every entry is keyed by its
    # scope identity as well as its finding identity, and the resolve sweep only ever
    # touches entries sharing the current scan's scope.
    #
    # Scope identity = cluster + scope description. Both come from the existing model
    # (ScanResult.cluster_name, Scope.describe()); no new concept was introduced. The
    # selector is deliberately NOT part of it: running the same scope with a narrower
    # selector is a partial re-scan of the same context, and posture.py already reports
    # rules that did not re-run as `not_rescanned` rather than resolved.
    @staticmethod
    def scope_key_of(cluster: str, scope: str) -> str:
        """The scope identity string, from its two parts. One place builds it, so a
        `StoredReport` (which carries cluster+scope as plain strings) and a live
        `ScanResult` can never disagree about which history they belong to."""
        return f"{cluster or 'target-cluster'}@{scope or 'cluster-wide'}"

    @classmethod
    def scope_key(cls, result: ScanResult) -> str:
        try:
            scope = result.request.scope.describe()
        except Exception:
            scope = ""
        return cls.scope_key_of(result.cluster_name, scope)

    @classmethod
    def _fkey(cls, rule_id, kind, name, namespace, scope: str = "") -> str:
        """Timeline key. Legacy entries (written before scoping) have four fields and no
        scope prefix; they are still readable and are never resolved by a scoped sweep, so
        an existing store keeps its history instead of being invalidated."""
        finding = "|".join([rule_id or "", kind or "", name or "", namespace or ""])
        return f"{scope}#{finding}" if scope else finding

    @staticmethod
    def _entry_scope(key: str) -> str:
        """The scope a timeline key belongs to. Legacy (unscoped) keys return ''."""
        return key.split("#", 1)[0] if "#" in key else ""

    def _timeline_path(self) -> str:
        return os.path.join(self.dir, _TIMELINE_FILE)

    def _load_timeline(self) -> dict:
        try:
            with _open_json(self._timeline_path()) as fh:
                return json.load(fh)
        except (FileNotFoundError, ValueError):
            return {}

    def _update_timeline(self, result: ScanResult) -> None:
        # Serialised: load → diff → write must be one critical section, or two concurrent
        # saves (threaded web server) race and one update is lost.
        with _TIMELINE_LOCK:
            tl = self._load_timeline()
            ts = result.generated_at
            scope = self.scope_key(result)
            current = {}
            for f in result.findings:
                if f.severity.weight == 0:      # skip INFO/engine-error
                    continue
                r = f.resource
                current[self._fkey(f.rule_id, r.kind, r.name, r.namespace, scope)] = f
            for k, f in current.items():
                e = tl.get(k)
                if e is None:
                    tl[k] = {"rule_id": f.rule_id, "title": f.title,
                             "severity": f.severity.label, "resource": str(f.resource),
                             "scope": scope, "cluster": result.cluster_name,
                             "first_seen": ts, "last_seen": ts, "resolved_at": None}
                else:
                    # A finding that comes back is open again, but the fact that it was
                    # once fixed is the whole evidence for calling it a REGRESSION rather
                    # than a first sighting. Clearing `resolved_at` without keeping that
                    # date destroyed it, so it moves to `last_resolved_at`.
                    if e.get("resolved_at"):
                        e["last_resolved_at"] = e["resolved_at"]
                    e.update(last_seen=ts, resolved_at=None, scope=scope,
                             cluster=result.cluster_name,
                             severity=f.severity.label)   # reappeared / refresh
            # A finding is only "fixed" when a scan that ACTUALLY LOOKED FOR IT did not
            # find it. `posture.compare()` has always applied that rule; the timeline did
            # not, so a narrower scan silently stamped `resolved_at` on everything it never
            # ran, and the finding's next appearance was then reported as a REGRESSION that
            # never happened. Both halves have to hold: same scope, and the rule re-ran.
            rescanned = set(result.resolved_rule_ids or [])
            for k, e in tl.items():
                # Only sweep the scope this scan actually covered. Another cluster's or
                # another namespace's entries were not re-examined, so their absence here
                # says nothing about whether they are fixed. Legacy unscoped entries are
                # likewise left alone rather than being resolved by a scoped scan.
                if self._entry_scope(k) != scope:
                    continue
                if k in current or e.get("resolved_at"):
                    continue
                if rescanned and e.get("rule_id") not in rescanned:
                    continue                            # not looked for, so not fixed
                e["resolved_at"] = ts                   # looked for and gone == fixed
            _atomic_write_json(self._timeline_path(), tl)

    def raw_timeline(self, scope: Optional[str] = None) -> dict:
        """The per-finding first/last-seen index. `timeline()` is the aggregated view; this
        is the raw one, needed to tell a regression from a first-time finding.

        Without `scope` the whole index is returned as stored (scope-prefixed keys). With a
        scope, only that scope's entries come back, re-keyed to the bare finding identity
        `core/posture.py` compares on. Legacy entries written before scoping existed have no
        prefix and are included in every scoped view, so an upgraded store keeps detecting
        regressions against the history it already had instead of starting over.
        """
        tl = self._load_timeline()
        if scope is None:
            return tl
        out: dict = {}
        for key, entry in tl.items():
            entry_scope = self._entry_scope(key)
            if entry_scope and entry_scope != scope:
                continue
            bare = key.split("#", 1)[1] if "#" in key else key
            # A scoped entry is authoritative over a legacy one for the same finding.
            if bare not in out or entry_scope:
                out[bare] = entry
        return out

    def timeline(self, scope: Optional[str] = None) -> dict:
        """Open/resolved finding ages against the latest scan. `age_days` is a
        scan-cadence-granular MTTD proxy; `resolved` with a `resolved_at` gives MTTR.

        `scope` (from `scope_key`/`scope_key_of`) narrows the view to one security context,
        which is what a dashboard showing ONE cluster's scan should pass. Omitted, the view
        spans the whole store, which is correct for a single-context store and is the
        historic behaviour."""
        tl = self.raw_timeline(scope=scope) if scope else self._load_timeline()
        if not tl:
            return {"open": 0, "resolved": 0, "oldest_open_days": 0,
                    "median_open_days": 0, "oldest_critical": None, "entries": []}
        latest = self.list(limit=1)
        now = latest[0].generated_at if latest else max(e["last_seen"] for e in tl.values())
        open_e, resolved = [], 0
        for e in tl.values():
            if e.get("resolved_at"):
                resolved += 1
                continue
            open_e.append({**e, "age_days": _days_between(e["first_seen"], now)})
        open_e.sort(key=lambda x: x["age_days"], reverse=True)
        ages = [e["age_days"] for e in open_e]
        crit = next((e for e in open_e if e["severity"] == "CRITICAL"), None)
        return {"open": len(open_e), "resolved": resolved,
                "oldest_open_days": max(ages) if ages else 0,
                "median_open_days": _median(ages),
                "oldest_critical": crit, "entries": open_e[:100]}

    # -- list ------------------------------------------------------------- #
    def list(self, limit: Optional[int] = None) -> list[StoredReport]:
        out: list[StoredReport] = []
        for p in glob.glob(os.path.join(self.dir, "*.json")):
            if os.path.basename(p).startswith("_"):
                continue        # internal index (e.g. _timeline.json), not a report
            try:
                with _open_json(p) as fh:
                    d = json.load(fh)
            except Exception:
                continue
            risk = d.get("risk", {}) or {}
            counts = d.get("counts", {}) or {}
            total = sum(v for k, v in counts.items() if k != "INFO")
            scan_id = d.get("scan_id", os.path.basename(p)[:-5])
            out.append(StoredReport(
                scan_id=scan_id,
                path=p,
                generated_at=d.get("generated_at", ""),
                rating=risk.get("rating", "?"),
                risk_score=risk.get("cluster_risk", 0.0),
                total=total,
                scope=d.get("scope", ""),
                name=d.get("name", ""),
                display_name=d.get("display_name")
                or _fallback_display_name(d.get("name", ""), scan_id,
                                          d.get("generated_at", "")),
                cluster=d.get("cluster", "target-cluster")))
        # Newest first, with scan_id as the tiebreaker: two scans can share a timestamp
        # (same second), and an unstable order there would make "the previous scan" a
        # coin flip for the posture diff. The id's trailing field encodes the microsecond in
        # an order-preserving way (see results._scan_id), so this tiebreak is chronological
        # and not merely deterministic.
        out.sort(key=lambda r: (r.generated_at, r.scan_id), reverse=True)
        return out[:limit] if limit else out

    # -- load ------------------------------------------------------------- #
    def load(self, scan_id: str) -> ScanResult:
        if not scan_id or not _SAFE_SCAN_ID.fullmatch(scan_id):
            raise FileNotFoundError(f"invalid scan id: {scan_id!r}")
        path = os.path.join(self.dir, f"{scan_id}.json")
        with _open_json(path) as fh:
            return ScanResult.from_dict(json.load(fh))

    def load_latest(self) -> Optional[ScanResult]:
        reports = self.list(limit=1)
        return self.load(reports[0].scan_id) if reports else None

    def resolve(self, scan_id: Optional[str]) -> Optional[ScanResult]:
        """Load an explicit scan id, or the latest if scan_id is None/'latest'."""
        if not scan_id or scan_id == "latest":
            return self.load_latest()
        return self.load(scan_id)


def _fallback_display_name(name: str, scan_id: str, generated_at: str) -> str:
    """Reconstruct a report's display name for reports saved before `display_name` was
    persisted, so old scans still list with a "<name/id>, <date> <time>" label."""
    from .timeutil import format_ist
    head = name or scan_id
    when = format_ist(generated_at)
    return f"{head}, {when}" if when != "N/A" else head


def _parse_ts(s: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _days_between(start: str, end: str) -> float:
    a, b = _parse_ts(start), _parse_ts(end)
    if not a or not b:
        return 0.0
    return round((b - a).total_seconds() / 86400, 1)


def _median(xs: list) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else round((s[mid - 1] + s[mid]) / 2, 1)
