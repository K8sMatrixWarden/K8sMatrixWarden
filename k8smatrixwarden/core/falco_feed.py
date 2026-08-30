"""
Falco log feed (§8), turn a Falco pod's stdout into runtime events.

When Falco runs with `json_output=true`, every alert is one JSON object per line on the
container's stdout. This module parses that stream into the raw Falco event dicts the
Runtime Agent already understands (`normalize_falco_event` flattens `output_fields`). It is
the pull counterpart to the falcosidekick push feed (`POST /api/runtime`): instead of
waiting for events to be pushed, a `--live` scan reads the last N minutes of Falco's own
logs and correlates them against the static findings on the spot.

Pure stdlib, pure functions, no cluster access here. The cluster read (listing Falco pods
and reading their logs) lives on the live collector; this module only parses text.
"""
from __future__ import annotations

import json

#: A parsed line is treated as a Falco event when it looks like one: Falco's native JSON
#: carries `output_fields`, or tags its stream in `source` (syscall | k8s_audit), or has the
#: rule/priority pair every alert prints. Anything else (startup banners, health lines,
#: falcoctl chatter) is skipped.
_FALCO_STREAMS = ("syscall", "k8s_audit")


def _looks_like_falco_event(obj: dict) -> bool:
    if "output_fields" in obj:
        return True
    if obj.get("source") in _FALCO_STREAMS:
        return True
    return "rule" in obj and "priority" in obj


def parse_falco_log(text: str) -> list[dict]:
    """Parse a Falco container log (json_output=true) into raw Falco event dicts.

    Accepts the raw multi-line log string. Each non-empty line is JSON-decoded; lines that
    are not JSON (or not Falco-shaped) are skipped rather than raising, so a log that mixes
    startup text with JSON alerts still yields the alerts. A line may carry a leading
    prefix (e.g. a kubectl `--timestamps` stamp) before the JSON, we retry from the first
    '{' in that case.
    """
    out: list[dict] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        obj = _try_json_object(line)
        if obj is not None and _looks_like_falco_event(obj):
            out.append(obj)
    return out


def _try_json_object(line: str):
    """Decode one log line to a dict, tolerating a non-JSON prefix. Returns None if the
    line is not a JSON object."""
    try:
        obj = json.loads(line)
    except ValueError:
        brace = line.find("{")
        if brace <= 0:
            return None
        try:
            obj = json.loads(line[brace:])
        except ValueError:
            return None
    return obj if isinstance(obj, dict) else None


def build_runtime_feed(collector, findings, scope, *, namespace: str = "falco",
                       since_seconds: int = 3600):
    """Pull Falco events from `collector`, correlate them against `findings`, and detect
    drift against the live pods, the one place the runtime block is assembled, shared by
    the CLI (`scan --live`) and the dashboard's Refresh. Returns the runtime dict, or None
    when the collector pulled no events (it records its own warning explaining why)."""
    from ..agents.runtime import RuntimeAgent, normalize_events
    from .correlation import correlate, detect_drift
    from .timeutil import ist_timestamp

    events = normalize_events(collector.collect_runtime_events(
        namespace=namespace, since_seconds=since_seconds))
    if not events:
        return None
    alerts = RuntimeAgent().evaluate_stream(events)
    try:
        pods = collector.collect({"Pod"}, scope).get("Pod")
    except Exception:
        pods = []
    collected_at = ist_timestamp()
    try:
        cluster_label = collector.cluster_label() or ""
    except Exception:
        cluster_label = ""
    return {"source": "falco-logs", "collected_at": collected_at,
            "cluster": cluster_label,
            "falco_namespace": namespace, "since_seconds": since_seconds,
            "events_seen": len(events),
            # The scan's own cluster and timestamp: without them a foreign cluster's
            # event could confirm a finding here, and a week-old alert would read as a
            # current observation.
            "correlation": correlate(findings, alerts, cluster=cluster_label,
                                     now=collected_at),
            "drift": detect_drift(pods or [], events)}


def since_to_seconds(since: str | int | None, default: int = 3600) -> int:
    """Convert a human window ('90s', '15m', '2h', '1d', or a bare number of seconds) to an
    integer number of seconds for the Kubernetes log API's `since_seconds`. Falls back to
    `default` on anything unparseable so a bad flag never aborts a scan."""
    if since is None:
        return default
    if isinstance(since, (int, float)):
        return int(since) if since > 0 else default
    s = str(since).strip().lower()
    if not s:
        return default
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    mult = units.get(s[-1])
    try:
        if mult is not None:
            value = int(float(s[:-1]) * mult)
        else:
            value = int(float(s))
    except ValueError:
        return default
    return value if value > 0 else default
