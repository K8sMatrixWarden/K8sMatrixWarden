"""
The runtime window: which timestamp it measures, and where its edges are.

A live validation once found Falco events from 17:23 while looking at 19:30, correctly saw
nothing in the one-hour window, and then reported that as a JSON-output problem. The window
was right; the explanation was wrong. These tests pin both halves down.

Everything here uses a fixed `now` passed into the code under test. Nothing sleeps and
nothing reads the wall clock, so a slow machine cannot make a boundary case flap.

THE CONTRACT, stated once so it cannot drift:

    an event is inside the window when   event_timestamp >= now - window

Inclusive at the far edge. An event whose timestamp cannot be read is KEPT rather than
dropped, because a time filter that silently discards evidence is the failure this whole
layer exists to avoid.
"""
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.falco_feed import (ACTIVE, PLAIN_TEXT, QUIET, counts_text_alerts,
                                             feed_diagnosis, window_text)
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Severity, Tactic)
from k8smatrixwarden.core.runtime_events import apply_filters

#: A fixed instant. Not "now" -- nothing here depends on when the suite runs.
NOW = 1_800_000_000.0
HOUR = 3600


def _at(offset_seconds):
    """An ISO timestamp `offset_seconds` from NOW, as a provider would write it."""
    return dt.datetime.fromtimestamp(
        NOW + offset_seconds, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(offset_seconds, event_id="e1"):
    return {"event_id": event_id, "kind": "correlation", "timestamp": _at(offset_seconds),
            "source": "falco", "detection_source": "falco", "severity": "MEDIUM",
            "namespace": "default", "rule": "rt-shell-in-container",
            "correlation": "confirmed"}


def _in_window(offset_seconds, window=HOUR):
    return len(apply_filters([_event(offset_seconds)],
                             since_seconds=window, now=NOW)) == 1


# --------------------------------------------------------------------------- #
# A. recent, B. old, C. the boundary
# --------------------------------------------------------------------------- #

def test_a_recent_event_is_inside_the_window():
    assert _in_window(-60) and _in_window(-1800) and _in_window(0)


def test_an_event_older_than_the_window_is_excluded():
    """The 17:23-seen-at-19:30 case: outside the window is outside, full stop."""
    assert not _in_window(-2 * HOUR)
    assert not _in_window(-(HOUR + 60))
    assert not _in_window(-86400)


def test_the_boundary_is_inclusive_at_exactly_one_window():
    """The documented contract: `timestamp >= now - window`. Stated as a test so a future
    change to > or >= is a deliberate decision rather than an accident."""
    assert _in_window(-HOUR), "an event exactly one window old must be inside"
    assert _in_window(-(HOUR - 1))
    assert not _in_window(-(HOUR + 1))


def test_the_window_is_configurable_and_the_edge_moves_with_it():
    assert _in_window(-90 * 60, window=2 * HOUR)
    assert not _in_window(-90 * 60, window=HOUR)
    assert _in_window(-2 * HOUR, window=2 * HOUR), "inclusive at the new edge too"


# --------------------------------------------------------------------------- #
# D. clock skew
# --------------------------------------------------------------------------- #

def test_a_future_timestamp_is_kept_and_treated_as_recent():
    """A provider slightly ahead of us is a clock-skew problem, not evidence to discard.
    Keeping it errs toward showing the operator something real; it cannot inflate a claim,
    because the strongest thing a recent event yields is what a genuinely recent event
    would have yielded anyway."""
    assert _in_window(+300)
    assert _in_window(+86400)


def test_a_future_event_is_never_labelled_historical():
    entry = _correlated(days_old=-1)
    assert entry["age_days"] < 0
    assert entry["freshness"] == "recent", "negative age must not read as stale"


# --------------------------------------------------------------------------- #
# Unreadable timestamps are kept, never silently dropped
# --------------------------------------------------------------------------- #

def test_an_unreadable_timestamp_survives_the_filter():
    for bad in ("", "not-a-date", None):
        record = _event(0)
        record["timestamp"] = bad
        assert len(apply_filters([record], since_seconds=HOUR, now=NOW)) == 1, \
            f"a {bad!r} timestamp was dropped; a time filter must not hide evidence"


# --------------------------------------------------------------------------- #
# Section 3: the provider's timestamp, not ours
# --------------------------------------------------------------------------- #

def test_the_window_measures_provider_time_not_ingestion_time():
    """The exact scenario from the spec. Both events are being filtered at NOW, so
    ingestion time is identical for the pair; only the provider timestamps differ, and only
    the recent one survives. If ingestion time were used, both would."""
    old = _event(-2 * HOUR, "provider-17-23")
    recent = _event(-60, "provider-just-now")
    survivors = [r["event_id"] for r in
                 apply_filters([old, recent], since_seconds=HOUR, now=NOW)]
    assert survivors == ["provider-just-now"]


def test_correlation_freshness_also_reads_provider_time():
    assert _correlated(days_old=0.04)["freshness"] == "recent"
    assert _correlated(days_old=8)["freshness"] == "historical"


def _correlated(days_old):
    now_dt = dt.datetime.fromtimestamp(NOW, dt.timezone.utc)
    when = (now_dt - dt.timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    finding = Finding(rule_id="workload-privileged", title="Privileged container",
                      severity=Severity.HIGH,
                      resource=ResourceRef(kind="Pod", name="api", namespace="prod"),
                      message="m", owning_shard="workload_pod_security",
                      mitre=[MitreTag(Tactic.EXECUTION, "T1610", "Deploy Container")])
    alerts = RuntimeAgent().evaluate_stream(normalize_events(
        [{"source": "falco", "proc": "bash", "namespace": "prod",
          "pod": "api-5f8b94447d-blxwg", "time": when}]))
    return correlate([finding], alerts, now=now_dt)["correlations"][0]


# --------------------------------------------------------------------------- #
# Section 4: three states, asserted on structure rather than wording
# --------------------------------------------------------------------------- #

_QUIET_LOG = """Sat Sep 05 17:22:06 2026: Falco initialized with configuration files
Sat Sep 05 17:22:06 2026: Loaded event sources: syscall"""

_TEXT_LOG = """Sat Sep 05 17:22:06 2026: Falco initialized
17:23:17.954850046: Notice Shell spawned by untrusted binary (proc=sh)
17:23:20.946349276: Warning Sensitive file opened for reading (file=/etc/shadow)"""


def test_a_quiet_cluster_is_informational_not_a_warning():
    """A healthy Falco with nothing to report must not be presented as a fault."""
    found = feed_diagnosis(counts_text_alerts(_QUIET_LOG), HOUR)
    assert found["state"] == QUIET
    assert found["severity"] == "info"
    assert found["remediation"] is None, "there is nothing to remediate"


def test_a_quiet_cluster_is_never_told_to_enable_json_output():
    """REGRESSION. The dashboard told an operator whose json_output was already true to
    enable json_output, because the code could not tell "no alerts happened" from "alerts
    happened but not as JSON" and asserted the second."""
    found = feed_diagnosis(counts_text_alerts(_QUIET_LOG), HOUR)
    assert "json_output" not in str(found)


def test_plain_text_alerts_are_a_warning_with_a_fix():
    found = feed_diagnosis(counts_text_alerts(_TEXT_LOG), HOUR)
    assert found["state"] == PLAIN_TEXT
    assert found["severity"] == "warning"
    assert "falco.json_output=true" in found["remediation"]


def test_the_window_is_named_in_the_message_because_it_is_the_reason():
    assert "1 hour" in feed_diagnosis(0, HOUR)["message"]
    assert "2 hours" in feed_diagnosis(0, 2 * HOUR)["message"]


def test_the_quiet_message_avoids_the_old_failure_wording():
    """Presentation is the contract here, so a small number of text assertions earn their
    place: the old string read as a failure on a healthy cluster."""
    message = feed_diagnosis(0, HOUR)["message"]
    assert "no Falco events found" not in message
    assert message.startswith("No Falco events in the last 1 hour.")
    assert "running normally" in message


def test_window_text_reads_like_a_person_wrote_it():
    assert window_text(3600) == "1 hour"
    assert window_text(7200) == "2 hours"
    assert window_text(900) == "15 minutes"
    assert window_text(86400) == "1 day"
    assert window_text(90) == "90 seconds"


# --------------------------------------------------------------------------- #
# The production path, not a stand-in
# --------------------------------------------------------------------------- #

def test_the_collector_uses_the_shared_diagnosis():
    """A stand-in collector that reimplemented this branch would pass even if the real one
    were wrong, so assert the real one calls the shared decision."""
    import inspect

    from k8smatrixwarden.core import evidence
    source = inspect.getsource(evidence.LiveEvidenceCollector.collect_runtime_events)
    assert "feed_diagnosis(" in source and "no_events_reason(" in source
    assert "enable JSON output" not in source, "an inline message is back"


def test_an_active_feed_reports_itself_as_ok():
    from k8smatrixwarden.core.falco_feed import _SEVERITY
    assert _SEVERITY[ACTIVE] == "ok"


def test_the_refresh_endpoint_publishes_state_and_severity():
    import inspect

    from k8smatrixwarden.web.app import WebApp
    source = inspect.getsource(WebApp._api_runtime_refresh)
    assert '"state"' in source and '"severity"' in source
    # The phrase survives in a comment explaining why it went; only its return as a
    # value would be the regression.
    assert '"message": "no Falco events found"' not in source,         "the old failure wording is back"


def test_the_dashboard_renders_severity_from_the_server():
    import tempfile

    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.web.app import WebApp
    page = WebApp(build_platform(),
                  reports_dir=tempfile.mkdtemp()).route("GET", "/").text
    assert "function feedNotice" in page
    # Neutral for ok/info, loud only for warning/error.
    assert "var(--crit)" in page and "var(--muted)" in page
    assert "'No runtime events found')}" not in page, "the old concatenation is back"


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
