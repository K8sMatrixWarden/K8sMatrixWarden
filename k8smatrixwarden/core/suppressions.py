"""Accepted risks, and "only what is new" baselines.

A scanner people keep running is one whose known, accepted findings can be silenced
without being forgotten. A suppression needs a reason and should have an expiry; an expired
one stops applying and is reported, and one that matches nothing is reported as stale, so
the list cannot quietly rot into a permanent blind spot.

    suppressions:
      - rule: workload-run-as-root          # glob, e.g. "net-*" or "*"
        resource: "shop/Deployment/web"     # glob on namespace/Kind/name; default "*"
        reason: "vendor image, ticket SEC-142"
        owner: alice
        expires: 2026-12-31

Suppressed findings are removed before scoring (the score reflects what is still open) and
are kept on the result with their reason, so reports can list them.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import os
from typing import Iterable, Optional

from .posture import finding_key

REPO_FILES = (".k8smatrixwarden-ignore.yaml", ".k8smatrixwarden-ignore.yml",
              ".k8smatrixwarden-ignore.json")


def _read(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith(".json"):
        data = json.loads(text)
    else:
        import yaml
        data = yaml.safe_load(text)
    items = (data or {}).get("suppressions", []) if isinstance(data, dict) else data
    return [dict(i, _source=path) for i in (items or []) if isinstance(i, dict)]


def discover(reports_dir: Optional[str], explicit: Iterable[str] = ()) -> tuple[list, list]:
    """Suppressions from every place a team keeps them: explicit files, the repo file in the
    working directory, and the dashboard-managed store next to the saved reports."""
    paths = list(explicit)
    paths += [f for f in REPO_FILES if os.path.exists(f)]
    if reports_dir:
        store = os.path.join(reports_dir, "suppressions.json")
        if os.path.exists(store):
            paths.append(store)
    out, notes = [], []
    for p in paths:
        try:
            out += _read(p)
        except Exception as exc:
            notes.append(f"suppressions file {p} could not be read: {str(exc).splitlines()[0][:100]}")
    return out, notes


def _day(v) -> Optional[_dt.date]:
    if isinstance(v, _dt.datetime):
        return v.date()
    if isinstance(v, _dt.date):
        return v
    try:
        return _dt.date.fromisoformat(str(v)[:10])
    except (TypeError, ValueError):
        return None


def _ids(f) -> list[str]:
    r = f.resource
    own = f"{r.namespace or ''}/{r.owner_kind or r.kind}/{r.owner_name or r.name}"
    return [own, f"{r.namespace or ''}/{r.kind}/{r.name}"]


def apply(findings: list, suppressions: list, today: Optional[_dt.date] = None):
    """Return (kept, suppressed_rows, notes)."""
    today = today or _dt.date.today()
    notes, live = [], []
    for s in suppressions:
        label = f"{s.get('rule', '?')} on {s.get('resource', '*')}"
        if not s.get("rule") or not str(s.get("reason", "")).strip():
            notes.append(f"suppression ({label}) ignored: it needs a rule and a reason")
            continue
        exp = _day(s.get("expires")) if s.get("expires") else None
        if s.get("expires") and exp is None:
            notes.append(f"suppression ({label}) ignored: expires '{s['expires']}' is not a date")
            continue
        if exp and exp < today:
            notes.append(f"suppression ({label}) expired on {exp}; its findings are reported again")
            continue
        live.append((s, exp))
    kept, rows, used = [], [], set()
    for f in findings:
        hit = next(((i, s, e) for i, (s, e) in enumerate(live)
                    if fnmatch.fnmatchcase(f.rule_id, str(s["rule"]))
                    and any(fnmatch.fnmatchcase(x, str(s.get("resource", "*"))) for x in _ids(f))), None)
        if not hit:
            kept.append(f)
            continue
        i, s, e = hit
        used.add(i)
        rows.append({"rule": f.rule_id, "title": f.title, "severity": f.severity.label,
                     "resource": str(f.resource), "reason": s["reason"],
                     "owner": s.get("owner", ""), "expires": str(e) if e else ""})
    for i, (s, _) in enumerate(live):
        if i not in used:
            notes.append(f"suppression ({s['rule']} on {s.get('resource', '*')}) matches no finding; "
                         "remove it if the problem is fixed")
    return kept, rows, notes


def new_since(findings: list, baseline_findings: list) -> list:
    """Findings whose rule+resource did not exist in the baseline scan."""
    seen = {finding_key(f) for f in baseline_findings}
    return [f for f in findings if finding_key(f) not in seen]
