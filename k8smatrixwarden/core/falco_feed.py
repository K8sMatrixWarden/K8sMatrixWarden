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

import re

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


def _as_text(payload) -> str:
    r"""Coerce a pod-log payload to real text, whatever the Kubernetes client handed back.

    Three shapes occur in the wild and only the first is the documented one:

      * `str`  , the log as written.
      * `bytes`, when the client skips deserialisation.
      * `str` holding the *repr of bytes*, i.e. the six characters ``b'...'`` wrapping a
        body whose line breaks are the two characters backslash-n rather than newlines.
        Several kubernetes-client versions return this from `read_namespaced_pod_log`.

    The third shape is the dangerous one, because it is a perfectly valid `str` that
    `splitlines()` reports as a single line. Every JSON alert is still in there, just
    escaped, so parsing silently yielded zero events on a working Falco install and the
    feed then blamed the operator's configuration for the emptiness.
    """
    if isinstance(payload, (bytes, bytearray)):
        return payload.decode("utf-8", "replace")
    text = payload or ""
    if not isinstance(text, str):
        return str(text)
    stripped = text.strip()
    for prefix in ("b'", 'b"'):
        if stripped.startswith(prefix) and stripped.endswith(prefix[-1]):
            body = stripped[2:-1]
            try:
                # Undo the escaping the repr applied; latin-1 round-trips every byte value.
                return body.encode("latin-1", "backslashreplace").decode(
                    "unicode_escape").encode("latin-1", "replace").decode(
                        "utf-8", "replace")
            except Exception:
                # Worst case, at least restore the line breaks so the alerts are parseable.
                return body.replace("\\n", "\n")
    return text


#: Falco's PLAIN-TEXT alert line, e.g. `17:23:20.946349276: Warning Sensitive file ...`.
#: Recognising it is what separates "Falco is alerting but not in JSON" from "Falco had
#: nothing to alert about" -- two situations that produce an identical empty event list and
#: need opposite advice.
_TEXT_ALERT = re.compile(
    r"^\d{2}:\d{2}:\d{2}\.\d+:\s+"
    r"(Emergency|Alert|Critical|Error|Warning|Notice|Informational|Debug)\s",
    re.MULTILINE)


def counts_text_alerts(text) -> int:
    """How many PLAIN-TEXT Falco alerts the log holds.

    Zero JSON events can mean the operator has json_output off, or simply that nothing
    happened. Only one of those is worth acting on, and telling somebody to enable a
    setting that is already enabled sends them to fix the wrong thing.
    """
    return len(_TEXT_ALERT.findall(_as_text(text)))


def window_text(seconds) -> str:
    """A window an operator reads at a glance: '1 hour', not '3600 seconds'."""
    seconds = int(seconds or 0)
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size and seconds % size == 0:
            n = seconds // size
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return f"{seconds} second{'s' if seconds != 1 else ''}"


#: What the feed found, and how loudly to say it. `severity` is presentation only and
#: never changes a security verdict; it exists because a healthy cluster with nothing to
#: report was being shown in the same voice as a broken one.
QUIET = "quiet"
PLAIN_TEXT = "plain-text"
ACTIVE = "active"

_SEVERITY = {ACTIVE: "ok", QUIET: "info", PLAIN_TEXT: "warning"}


def feed_diagnosis(text_alerts: int, since_seconds: int,
                   namespace: str = "falco") -> dict:
    """Why the feed came back empty, as structured state rather than a sentence.

    An empty event list has two very different causes. Falco writing alerts as plain text
    (json_output off) is a misconfiguration worth acting on. Falco having nothing to alert
    about is a quiet cluster, which is the ordinary case and not a fault at all. The old
    message asserted the first and told everybody to enable json_output -- including
    operators whose json_output was already true, sending them to change a setting that was
    never the problem. `text_alerts` is the discriminator.

    Returning `state` and `severity` alongside the message lets the dashboard show a quiet
    cluster in a neutral voice instead of the same grey blob it uses for a broken feed,
    and lets tests assert on the state rather than on wording.
    """
    window = window_text(since_seconds)
    if text_alerts:
        return {
            "state": PLAIN_TEXT,
            "severity": _SEVERITY[PLAIN_TEXT],
            "message": (f"Falco raised {text_alerts} alert(s) in the last {window} but "
                        f"emitted them as plain text, so none could be read as events."),
            "remediation": (f"helm upgrade falco falcosecurity/falco -n {namespace} "
                            f"--reuse-values --set falco.json_output=true"),
            "window": window,
        }
    return {
        "state": QUIET,
        "severity": _SEVERITY[QUIET],
        "message": (f"No Falco events in the last {window}. Falco is running normally; "
                    f"no alerts were raised during this window."),
        "remediation": None,
        "window": window,
    }


def no_events_reason(text_alerts: int, since_seconds: int,
                     namespace: str = "falco") -> str:
    """The same diagnosis as one line, for the collector's flat `warnings` list."""
    found = feed_diagnosis(text_alerts, since_seconds, namespace)
    tail = f" Enable JSON output: {found['remediation']}" if found["remediation"] else ""
    return f"Falco feed: {found['message']}{tail}"


def parse_falco_log(text) -> list[dict]:
    """Parse a Falco container log (json_output=true) into raw Falco event dicts.

    Accepts the raw multi-line log payload. Each non-empty line is JSON-decoded; lines that
    are not JSON (or not Falco-shaped) are skipped rather than raising, so a log that mixes
    startup text with JSON alerts still yields the alerts. A line may carry a leading
    prefix (e.g. a kubectl `--timestamps` stamp) before the JSON, we retry from the first
    '{' in that case.
    """
    out: list[dict] = []
    for raw_line in _as_text(text).splitlines():
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

    from .runtime_identity import enrich_events

    events = normalize_events(collector.collect_runtime_events(
        namespace=namespace, since_seconds=since_seconds))
    if not events:
        return None
    try:
        pods = collector.collect({"Pod"}, scope).get("Pod")
    except Exception:
        pods = []
    # Recover the Pod behind events Falco could not enrich, before anything reasons about
    # them. Deterministic (container id, exactly one match) or not at all.
    events, identity_coverage = enrich_events(events, pods)
    # evaluate_batch, not evaluate_stream: the accounting is the point. Every event is
    # matched by a curated rule, relayed under Falco's name, or reported unusable with a
    # reason, and the operator can see which.
    alerts, detection_coverage = RuntimeAgent().evaluate_batch(events)
    collected_at = ist_timestamp()
    try:
        cluster_label = collector.cluster_label() or ""
    except Exception:
        cluster_label = ""
    return {"source": "falco-logs", "collected_at": collected_at,
            "cluster": cluster_label,
            "falco_namespace": namespace, "since_seconds": since_seconds,
            "events_seen": len(events),
            # How the provider's events were accounted for. `discarded: 0` is an invariant,
            # not a hope: anything without a detection is listed in `unusable` with a reason.
            "detection_coverage": detection_coverage,
            # Detection coverage and identity coverage answer different questions: "was
            # this event detected?" and "do we know what it happened to?". An event can be
            # detected and still unplaceable.
            "identity_coverage": identity_coverage,
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
