"""
Regressions from validating against a REAL Falco sensor.

Everything here was found by deploying Falco 0.44.1 (modern eBPF) to a live cluster and
watching genuine `Read sensitive file untrusted` alerts travel the pipeline. All three
defects were invisible to fixture-based tests, because fixtures hand the code the shape it
expects: a clean log string, an event matching a local rule, and a reader who only looks at
JSON. The live sensor supplied none of those.

The captured event below is a verbatim Falco 0.44.1 alert from that cluster.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent, normalize_events
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.falco_feed import _as_text, parse_falco_log
from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag, ResourceRef,
                                         Severity, Tactic)

#: Verbatim from `kubectl logs -n falco` on the validation cluster.
LIVE_EVENT = {
    "hostname": "desktop-control-plane",
    "output": ("16:40:58.670371591: Warning Sensitive file opened for reading by "
               "non-trusted program | file=/etc/shadow evt_type=open user=root "
               "user_uid=0 process=cat parent=sh command=cat /etc/shadow "
               "container_name=build-code k8s_ns_name=default"),
    "priority": "Warning",
    "rule": "Read sensitive file untrusted",
    "source": "syscall",
    "tags": ["T1555", "container", "filesystem", "host", "maturity_stable",
             "mitre_credential_access"],
    "time": "2026-08-31T16:40:58.670371591Z",
    "output_fields": {
        "container.id": "d2fcde896e65",
        "container.image.repository": "docker.io/madhuakula/k8s-goat-build-code",
        "container.image.tag": "latest",
        "container.name": "build-code",
        "evt.time": 1788194458670371591,
        "evt.type": "open",
        "fd.name": "/etc/shadow",
        "k8s.ns.name": "default",
        "k8s.pod.name": "build-code-deployment-5f9586cd5b-lrw5s",
        "proc.cmdline": "cat /etc/shadow",
        "proc.exepath": "/bin/busybox",
        "proc.name": "cat",
        "proc.pname": "sh",
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0,
    },
}

_NOW = "2026-08-31T22:30:00+05:30"


def _finding(kind="Deployment", name="build-code-deployment", ns="default"):
    f = Finding(rule_id="workload-sa-token-automount", title="SA token automounted",
                severity=Severity.HIGH, resource=ResourceRef(kind, name, ns),
                message="m",
                mitre=[MitreTag(Tactic.CREDENTIAL_ACCESS, "T1552.001", "Creds in files")],
                detection_method=DetectionMethod.STATIC_CONFIG)
    f.exploit_path = [{"kind": "Internet", "name": "external", "detail": ""},
                      {"kind": kind, "name": name, "detail": ns}]
    return f


def _correlate(events, cluster="docker-desktop", now=_NOW, findings=None):
    alerts = RuntimeAgent().evaluate_stream(normalize_events(events))
    return correlate(findings or [_finding()], alerts, cluster=cluster, now=now)


# =========================================================================== #
# 1. Reading the log
# =========================================================================== #
def test_a_pod_log_returned_as_a_bytes_repr_is_still_parsed():
    r"""REGRESSION. The Kubernetes Python client returns `read_namespaced_pod_log` as a
    `str` containing the *repr of bytes*: ``b'line\nline'``, where the line breaks are the
    two characters backslash-n, not newlines. It is a perfectly valid string that
    `splitlines()` reports as ONE line, so every JSON alert was invisible and the feed
    concluded Falco had produced nothing, then told the operator to enable `json_output`,
    which was already enabled. A working sensor, a confident and wrong diagnosis."""
    real = json.dumps(LIVE_EVENT)
    payload = "b'" + ("Mon Aug 31 16:39:51 2026: Falco version: 0.44.1\\n"
                      + real.replace("\\", "\\\\").replace("'", "\\'") + "\\n") + "'"
    assert len(payload.splitlines()) == 1, "the payload really is one line to splitlines()"
    events = parse_falco_log(payload)
    assert len(events) == 1
    assert events[0]["rule"] == "Read sensitive file untrusted"


def test_plain_text_and_bytes_logs_still_parse():
    """The control: the fix must not break the two shapes that already worked."""
    text = "startup banner\n" + json.dumps(LIVE_EVENT) + "\n"
    assert len(parse_falco_log(text)) == 1
    assert len(parse_falco_log(text.encode("utf-8"))) == 1
    assert parse_falco_log("") == []
    assert parse_falco_log(None) == []


def test_as_text_leaves_ordinary_strings_alone():
    assert _as_text("plain\nlines") == "plain\nlines"
    assert _as_text(b"bytes\nlines") == "bytes\nlines"
    # A log that merely BEGINS with b' but is not a repr must not be mangled beyond repair.
    assert "quoted" in _as_text("b'quoted'")


# =========================================================================== #
# 2. Relaying Falco's own verdict
# =========================================================================== #
def test_a_falco_alert_with_no_local_rule_is_relayed_not_discarded():
    """REGRESSION, the live false negative. This agent has 11 rules; Falco's default
    ruleset has around ninety. An event matching none of ours was dropped, so a live sensor
    reporting credential access on three pods produced ZERO runtime alerts. Falco is a
    sensor the operator deliberately deployed; discarding its verdict is discarding
    evidence."""
    alerts = RuntimeAgent().evaluate_stream(normalize_events([LIVE_EVENT]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "falco:Read sensitive file untrusted"
    assert alert.tactic == Tactic.CREDENTIAL_ACCESS.value, "tactic comes from Falco's tag"
    assert alert.severity is Severity.MEDIUM, "from Falco's own Warning priority"
    assert alert.source == "falco" and alert.surface == "runtime"


def test_a_relayed_alert_is_attributed_to_falco_never_adopted():
    """The id must make the provenance unmistakable, so no report can present Falco's
    verdict as one of this tool's own detections."""
    alert = RuntimeAgent().evaluate_stream(normalize_events([LIVE_EVENT]))[0]
    assert alert.rule_id.startswith("falco:")
    assert alert.title.startswith("Falco: ")


def test_an_untagged_falco_rule_is_relayed_with_an_unknown_tactic():
    """A tactic is a claim, and Falco supplies one in its tags. Where it does not (a custom
    rule an operator wrote), the alert is still relayed, with the tactic stated as Unknown
    rather than guessed: dropping it would be the silent discard this relay exists to
    prevent, and inventing a tactic would be the overclaim. An unknown tactic matches no
    static finding, so it surfaces as `runtime-only`, which is precisely what it is."""
    untagged = dict(LIVE_EVENT, tags=["container", "filesystem"])
    alerts = RuntimeAgent().evaluate_stream(normalize_events([untagged]))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "falco:Read sensitive file untrusted"
    assert alerts[0].tactic == "Unknown"

    out = correlate([_finding()], alerts, cluster="docker-desktop", now=_NOW)
    assert out["confirmed_exploitation"] == 0, "an unknown tactic confirms nothing"
    assert out["runtime_only"] == 1


def test_an_event_that_is_not_a_rule_hit_is_not_relayed():
    """No rule name means Falco did not raise an alert at all, just a raw syscall. There is
    no verdict to relay, so nothing is claimed."""
    unnamed = dict(LIVE_EVENT)
    unnamed.pop("rule")
    assert RuntimeAgent().evaluate_stream(normalize_events([unnamed])) == []


def test_a_local_rule_still_wins_over_the_falco_relay():
    """The relay is a fallback, not a replacement: an event this agent recognises must
    still be reported under OUR rule, with our severity and tactic."""
    shell = {"source": "syscall", "rule": "Terminal shell in container",
             "priority": "Notice", "tags": ["mitre_execution"],
             "time": "2026-08-31T16:40:00Z",
             "output_fields": {"proc.name": "bash", "evt.type": "execve",
                               "k8s.ns.name": "default", "k8s.pod.name": "api-9zskz"}}
    alerts = RuntimeAgent().evaluate_stream(normalize_events([shell]))
    assert [a.rule_id for a in alerts] == ["rt-shell-in-container"]


def test_relaying_survives_junk_events():
    """The rule loop tolerates malformed input per-matcher; the relay must too. Found by
    the adversarial suite the moment the relay was added."""
    agent = RuntimeAgent()
    assert agent.evaluate_stream(normalize_events([None])) == []
    assert agent.evaluate_stream([None, {}, {"source": "falco"}]) == []


def test_falco_severity_scale_maps_onto_ours():
    for priority, expected in (("Critical", Severity.CRITICAL), ("Error", Severity.HIGH),
                               ("Warning", Severity.MEDIUM), ("Notice", Severity.LOW)):
        ev = dict(LIVE_EVENT, priority=priority)
        alert = RuntimeAgent().evaluate_stream(normalize_events([ev]))[0]
        assert alert.severity is expected, priority


# =========================================================================== #
# 3. What the live event proves, end to end
# =========================================================================== #
def test_the_live_event_confirms_the_workload_it_names():
    """The whole pipeline on real data: Falco names a Pod with a generated suffix, the
    static finding names the Deployment, and ownership ties them together."""
    out = _correlate([LIVE_EVENT])
    assert out["total_alerts"] == 1
    assert out["confirmed_exploitation"] == 1
    entry = out["correlations"][0]
    assert entry["confidence"] == "confirmed"
    assert entry["tactic"] == Tactic.CREDENTIAL_ACCESS.value
    assert entry["resource"] == "build-code-deployment-5f9586cd5b-lrw5s"
    assert entry["namespace"] == "default"
    assert entry["cluster"] == "docker-desktop"
    assert entry["freshness"] == "recent"


def test_every_falco_field_survives_normalization():
    """Step 5 of the validation: timestamp, source, rule, namespace, pod, container and
    the event body must all still be there after flattening."""
    ev = normalize_events([LIVE_EVENT])[0]
    assert ev["time"] == "2026-08-31T16:40:58.670371591Z"
    assert ev["source"] == "falco"
    assert ev["rule"] == "Read sensitive file untrusted"
    assert ev["namespace"] == "default"
    assert ev["pod"] == "build-code-deployment-5f9586cd5b-lrw5s"
    assert ev["container"] == "build-code"
    assert ev["image"] == "docker.io/madhuakula/k8s-goat-build-code"
    assert ev["proc"] == "cat"
    assert ev["file"] == "/etc/shadow"
    assert ev["uid"] == 0
    assert "mitre_credential_access" in ev["tags"]


def test_a_pod_event_does_not_mark_the_whole_path_observed():
    """Validation step 6, on the real event. Seeing a process inside a Pod is evidence
    about that Pod, not about the Service in front of it or the RBAC behind it."""
    from k8smatrixwarden.core.attack_path import resource_paths
    corr = _correlate([LIVE_EVENT])
    path = resource_paths([_finding()], {"correlation": corr,
                                         "drift": {"drift": []}})[0]
    assert path["confidence"] == "observed"
    assert path["fully_observed"] is False, "the entry hop was never observed"
    assert path["observed_nodes"] == ["build-code-deployment"]
    assert path["evidence_freshness"] == "recent"


def test_a_foreign_cluster_cannot_confirm_the_same_pod_name():
    """Validation step 8, on the real event."""
    ev = normalize_events([LIVE_EVENT])[0]
    ev["cluster"] = "some-other-cluster"
    alerts = RuntimeAgent().evaluate_stream([ev])
    out = correlate([_finding()], alerts, cluster="docker-desktop", now=_NOW)
    assert out["confirmed_exploitation"] == 0
    assert out["correlations"][0]["confidence"] == "corroborated"


def test_the_same_event_ages_out_of_being_current():
    """Validation step 7, on the real event."""
    seen = {label: _correlate([LIVE_EVENT], now=now)["correlations"][0]["freshness"]
            for label, now in (("minutes", "2026-08-31T22:30:00+05:30"),
                               ("2 days", "2026-09-02T22:30:00+05:30"),
                               ("10 days", "2026-09-10T22:30:00+05:30"),
                               ("a year", "2027-08-31T22:30:00+05:30"))}
    assert seen == {"minutes": "recent", "2 days": "recent",
                    "10 days": "historical", "a year": "historical"}


# =========================================================================== #
# 4. Reporting it
# =========================================================================== #
def _result_with_runtime():
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    p = build_platform()
    result = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    corr = _correlate([LIVE_EVENT])
    result.runtime = {"source": "falco-logs", "collected_at": _NOW,
                      "cluster": "docker-desktop", "falco_namespace": "falco",
                      "since_seconds": 7200, "events_seen": 1,
                      "correlation": corr, "drift": {"drift": []}}
    return result


def test_every_rendered_format_reports_the_runtime_correlation():
    """REGRESSION, and the most consequential gap the live run exposed. The runtime feed
    was pulled, correlated and stored, and then appeared in NO rendered report: an operator
    whose sensor said three findings were being actively exploited read a report that never
    mentioned it. Only raw JSON carried it, because JSON serialises the whole result."""
    from k8smatrixwarden.core.reporting import ReportingEngine
    result = _result_with_runtime()
    engine = ReportingEngine()
    for fmt in ("terminal", "text", "markdown", "html"):
        body = engine.render(result, fmt)
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        assert "Runtime" in body, f"{fmt} has no runtime section"
        assert "onfirmed" in body, f"{fmt} does not state the confirmed count"


def test_the_runtime_section_is_absent_when_there_was_no_feed():
    """A mock scan pulls no runtime feed, and a report must not imply one was checked."""
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    from k8smatrixwarden.core.reporting import (ReportingEngine, _runtime_lines,
                                                _runtime_md, _runtime_summary)
    p = build_platform()
    result = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    assert _runtime_summary(result) is None
    assert _runtime_lines(result) == [] and _runtime_md(result) == []
    assert "Runtime feed" not in ReportingEngine().render(result, "text")


def test_the_json_contract_keeps_the_runtime_block_intact():
    from k8smatrixwarden.core.reporting import ReportingEngine
    d = json.loads(ReportingEngine().render(_result_with_runtime(), "json"))
    rt = d["runtime"]
    assert rt["source"] == "falco-logs" and rt["events_seen"] == 1
    entry = rt["correlation"]["correlations"][0]
    assert entry["confidence"] == "confirmed"
    assert entry["runtime"]["rule_id"] == "falco:Read sensitive file untrusted"
    assert entry["freshness"] == "recent"


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_"):
            _fn()
            print("ok", _name)
    print("all passed")


# --------------------------------------------------------------------------- #
# The "no events" diagnostic must name the RIGHT cause
# --------------------------------------------------------------------------- #

_QUIET_LOG = """Sat Sep 05 17:22:06 2026: Falco initialized with configuration files
Sat Sep 05 17:22:06 2026: Loaded event sources: syscall
Sat Sep 05 17:22:06 2026: Opening 'syscall' source with modern BPF probe."""

_TEXT_ALERT_LOG = """Sat Sep 05 17:22:06 2026: Falco initialized
17:23:17.954850046: Notice Shell spawned by untrusted binary (proc=sh)
17:23:20.946349276: Warning Sensitive file opened for reading (file=/etc/shadow)"""


def test_plain_text_alerts_are_recognised():
    """The discriminator. Falco writing alerts as text and Falco writing nothing produce
    an identical empty event list, and the two need opposite advice."""
    from k8smatrixwarden.core.falco_feed import counts_text_alerts
    assert counts_text_alerts(_TEXT_ALERT_LOG) == 2
    assert counts_text_alerts(_QUIET_LOG) == 0


def test_a_json_log_is_never_counted_as_plain_text():
    from k8smatrixwarden.core.falco_feed import counts_text_alerts, parse_falco_log
    line = ('{"rule":"Shell","output":"x","output_fields":{"proc.name":"sh"},'
            '"priority":"Warning","time":"2026-09-05T17:23:17Z"}')
    assert len(parse_falco_log(line)) == 1
    assert counts_text_alerts(line) == 0


def test_a_quiet_cluster_is_not_told_to_enable_json_output():
    """REGRESSION. The dashboard told an operator whose json_output was already true to
    enable json_output, because the code could not tell "no alerts happened" from "alerts
    happened but not as JSON" and asserted the second. That sends somebody to change a
    setting that was never the problem."""
    from k8smatrixwarden.core.falco_feed import counts_text_alerts, no_events_reason
    reason = no_events_reason(counts_text_alerts(_QUIET_LOG), 3600)
    assert "json_output" not in reason, reason
    assert "raised no alerts" in reason
    assert "normal state of a quiet cluster" in reason
    assert "1 hour" in reason, "the window is the actual reason and must be stated"


def test_text_only_alerts_do_advise_enabling_json_output():
    """The other branch: here the advice is right and must still be given."""
    from k8smatrixwarden.core.falco_feed import counts_text_alerts, no_events_reason
    reason = no_events_reason(counts_text_alerts(_TEXT_ALERT_LOG), 3600)
    assert "falco.json_output=true" in reason
    assert "PLAIN TEXT" in reason
    assert "2 alert(s)" in reason


def test_the_window_is_reported_in_human_terms():
    from k8smatrixwarden.core.falco_feed import window_text
    assert window_text(3600) == "1 hour"
    assert window_text(7200) == "2 hours"
    assert window_text(900) == "15 minutes"
    assert window_text(86400) == "1 day"
    assert window_text(90) == "90 seconds"


def test_the_collector_uses_the_shared_message_not_its_own():
    """One implementation: a second copy in the collector would drift from this one."""
    import inspect

    from k8smatrixwarden.core import evidence
    source = inspect.getsource(evidence.LiveEvidenceCollector.collect_runtime_events)
    assert "no_events_reason(" in source
    assert "enable JSON output" not in source, "the old inline message is back"
