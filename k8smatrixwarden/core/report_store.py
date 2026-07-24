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
from dataclasses import dataclass
from typing import Optional

from .results import ScanResult

# Guards the timeline read-modify-write: the web server is threaded, so two concurrent
# saves could otherwise interleave and lose an update. ponytail: in-process lock; a second
# PROCESS scanning the same store concurrently is out of scope (rare, note the ceiling).
_TIMELINE_LOCK = threading.Lock()


def _atomic_write_json(path: str, obj) -> None:
    """Write JSON durably: serialise to a temp file in the same dir, then os.replace(), 
    an atomic rename on POSIX/Windows, so a crash mid-write can never leave a half-written
    (unparseable) report or timeline index behind."""
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
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
        os.makedirs(self.dir, exist_ok=True)
        path = os.path.join(self.dir, f"{result.scan_id}.json")
        _atomic_write_json(path, result.as_dict())
        self._update_timeline(result)
        return path

    # -- timeline (MTTD/MTTR) --------------------------------------------- #
    # ponytail: diffs each scan against an accumulated index. Meaningful across scans of
    # the SAME scope (e.g. a scheduled cluster-wide scan); mixing scopes/selectors makes
    # findings falsely "resolve" and reappear. Upgrade: key the index per scope if you
    # run mixed scans on one store.
    @staticmethod
    def _fkey(rule_id, kind, name, namespace) -> str:
        return "|".join([rule_id or "", kind or "", name or "", namespace or ""])

    def _timeline_path(self) -> str:
        return os.path.join(self.dir, _TIMELINE_FILE)

    def _load_timeline(self) -> dict:
        try:
            with open(self._timeline_path(), encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, ValueError):
            return {}

    def _update_timeline(self, result: ScanResult) -> None:
        # Serialised: load → diff → write must be one critical section, or two concurrent
        # saves (threaded web server) race and one update is lost.
        with _TIMELINE_LOCK:
            tl = self._load_timeline()
            ts = result.generated_at
            current = {}
            for f in result.findings:
                if f.severity.weight == 0:      # skip INFO/engine-error
                    continue
                r = f.resource
                current[self._fkey(f.rule_id, r.kind, r.name, r.namespace)] = f
            for k, f in current.items():
                e = tl.get(k)
                if e is None:
                    tl[k] = {"rule_id": f.rule_id, "title": f.title,
                             "severity": f.severity.label, "resource": str(f.resource),
                             "first_seen": ts, "last_seen": ts, "resolved_at": None}
                else:
                    e.update(last_seen=ts, resolved_at=None,
                             severity=f.severity.label)   # reappeared / refresh
            for k, e in tl.items():
                if k not in current and not e.get("resolved_at"):
                    e["resolved_at"] = ts               # gone this scan == fixed
            _atomic_write_json(self._timeline_path(), tl)

    def timeline(self) -> dict:
        """Open/resolved finding ages against the latest scan. `age_days` is a
        scan-cadence-granular MTTD proxy; `resolved` with a `resolved_at` gives MTTR."""
        tl = self._load_timeline()
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
                with open(p, encoding="utf-8") as fh:
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
        out.sort(key=lambda r: r.generated_at, reverse=True)
        return out[:limit] if limit else out

    # -- load ------------------------------------------------------------- #
    def load(self, scan_id: str) -> ScanResult:
        if not scan_id or not _SAFE_SCAN_ID.fullmatch(scan_id):
            raise FileNotFoundError(f"invalid scan id: {scan_id!r}")
        path = os.path.join(self.dir, f"{scan_id}.json")
        with open(path, encoding="utf-8") as fh:
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
