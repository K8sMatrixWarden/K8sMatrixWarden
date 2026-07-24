"""
IST time helpers, K8sMatrixWarden reports every timestamp in Indian Standard Time
(Asia/Kolkata, UTC+05:30).

Timestamps are emitted as ISO-8601 with the explicit `+05:30` offset so they stay
machine-parseable (``datetime.fromisoformat`` / ``Date(...)`` in the browser) while being
unambiguously IST. ``format_ist`` renders a stored ISO timestamp for human display
(e.g. "19 Jul 2026, 01:13 IST") without depending on the reader's local timezone.
"""
from __future__ import annotations

import datetime as _dt
import re as _re

#: Indian Standard Time, fixed UTC+05:30 (India observes no DST).
IST = _dt.timezone(_dt.timedelta(hours=5, minutes=30), name="IST")

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_ISO_RE = _re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})")


def now_ist() -> _dt.datetime:
    """Timezone-aware 'now' in IST."""
    return _dt.datetime.now(IST)


def ist_timestamp() -> str:
    """ISO-8601 timestamp in IST, e.g. ``2026-07-19T01:13:00+05:30``."""
    return now_ist().strftime("%Y-%m-%dT%H:%M:%S+05:30")


def ist_date_compact() -> str:
    """Compact IST date used inside scan ids, e.g. ``20260719``."""
    return now_ist().strftime("%Y%m%d")


def format_ist(ts: str) -> str:
    """Human-friendly IST rendering of a stored ISO timestamp.

    Reads the stored wall-clock directly (all timestamps are written in IST) rather than
    converting timezones, so it is stable regardless of where the report is opened.
    Returns the input unchanged if it does not look like an ISO timestamp.
    """
    if not ts:
        return "N/A"
    m = _ISO_RE.match(str(ts))
    if not m:
        return str(ts)
    y, mo, d, hh, mm = m.groups()
    return f"{int(d)} {_MONTHS[int(mo) - 1]} {y}, {hh}:{mm} IST"
