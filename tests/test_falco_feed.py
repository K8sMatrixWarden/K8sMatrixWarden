"""Auto Falco feed on --live: log parsing, event-window parsing, runtime persistence on the
scan result, and the cmd_scan wiring that pulls + correlates the feed."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.falco_feed import parse_falco_log, since_to_seconds
from k8smatrixwarden.core.evidence import EvidenceCollector
from k8smatrixwarden.core.results import ScanResult
from k8smatrixwarden.core.models import (Finding, MitreTag, ResourceRef, Scope, ScopeLevel,
                                         Severity, Tactic)
from k8smatrixwarden.cli.main import _attach_runtime_feed


# --------------------------------------------------------------------------- #
# parse_falco_log
# --------------------------------------------------------------------------- #
def test_parse_falco_log_keeps_only_falco_shaped_json_lines():
    log = "\n".join([
        '{"source":"syscall","rule":"Terminal shell","priority":"Notice",'
        '"output_fields":{"proc.name":"bash","k8s.pod.name":"web-abc"}}',
        "Fri Jan 01 12:00:00 2026: Falco initialized with configuration file", # banner
        '{"source":"k8s_audit","output_fields":{"ka.verb":"create",'
        '"ka.target.resource":"clusterrolebindings"}}',
        '{"hello":"world"}',             # valid JSON but not a Falco event
        "   ",                            # blank
    ])
    events = parse_falco_log(log)
    assert len(events) == 2
    assert events[0]["output_fields"]["proc.name"] == "bash"
    assert events[1]["source"] == "k8s_audit"


def test_parse_falco_log_tolerates_leading_prefix_and_bad_lines():
    log = ("2026-01-01T00:00:00Z "  # a kubectl --timestamps style prefix before the JSON
           '{"source":"syscall","output_fields":{"proc.name":"nmap"}}\n'
           "not json at all\n")
    events = parse_falco_log(log)
    assert len(events) == 1 and events[0]["output_fields"]["proc.name"] == "nmap"


def test_parse_falco_log_empty():
    assert parse_falco_log("") == []
    assert parse_falco_log(None) == []


# --------------------------------------------------------------------------- #
# since_to_seconds
# --------------------------------------------------------------------------- #
def test_since_to_seconds_units():
    assert since_to_seconds("45s") == 45
    assert since_to_seconds("30m") == 1800
    assert since_to_seconds("2h") == 7200
    assert since_to_seconds("1d") == 86400
    assert since_to_seconds("90") == 90          # bare number == seconds
    assert since_to_seconds(120) == 120          # numeric passthrough


def test_since_to_seconds_falls_back_on_garbage():
    assert since_to_seconds("") == 3600
    assert since_to_seconds(None) == 3600
    assert since_to_seconds("nonsense") == 3600
    assert since_to_seconds("-5m", default=99) == 99   # non-positive -> default


# --------------------------------------------------------------------------- #
# base collector has no live stream
# --------------------------------------------------------------------------- #
def test_base_collector_pulls_no_runtime_events():
    assert EvidenceCollector().collect_runtime_events() == []


# --------------------------------------------------------------------------- #
# ScanResult.runtime persistence (round-trip through the report store shape)
# --------------------------------------------------------------------------- #
_BASE = {"scan_id": "s-1", "name": "", "scope": "cluster", "selector": "all",
         "risk": {"cluster_risk": 1.0, "security_score": 90, "rating": "Good"},
         "counts": {}, "findings": []}


def test_runtime_survives_as_dict_from_dict_round_trip():
    block = {"source": "falco-logs", "events_seen": 3,
             "correlation": {"confirmed_exploitation": 1, "correlated": 1,
                             "total_alerts": 3, "runtime_only": 1, "correlations": []},
             "drift": {"drift_count": 0, "drift": []}}
    r = ScanResult.from_dict({**_BASE, "runtime": block})
    assert r.runtime == block
    assert r.as_dict()["runtime"] == block


def test_runtime_absent_stays_absent():
    r = ScanResult.from_dict(dict(_BASE))
    assert r.runtime is None
    assert "runtime" not in r.as_dict()   # kept out so old reports are unchanged


# --------------------------------------------------------------------------- #
# _attach_runtime_feed, the cmd_scan wiring, with a fake live collector
# --------------------------------------------------------------------------- #
def _finding(tactic, ns="default", name="health-check-deployment"):
    return Finding(rule_id="workload-shell", title="Shell allowed", severity=Severity.HIGH,
                   resource=ResourceRef(kind="Pod", name=name, namespace=ns),
                   message="x", owning_shard="workload_pod_security",
                   mitre=[MitreTag(tactic, "T1059", "Command and Scripting Interpreter")])


class _FakeCollector:
    """Stands in for LiveEvidenceCollector: hands back raw Falco events + pods for drift."""
    def __init__(self, events, pods=None):
        self._events = events
        self._pods = pods or []
        self.warnings = []

    def collect_runtime_events(self, *, namespace="falco", since_seconds=3600,
                               tail_lines=2000):
        return self._events

    def collect(self, needs, scope):
        return {"Pod": self._pods}


def _args(**over):
    base = dict(mock=False, live=True, no_runtime=False,
                falco_namespace="falco", falco_since="1h")
    base.update(over)
    return types.SimpleNamespace(**base)


def _result():
    return types.SimpleNamespace(findings=[_finding(Tactic.EXECUTION)], runtime=None)


def _request():
    return types.SimpleNamespace(scope=Scope(ScopeLevel.CLUSTER))


def test_attach_runtime_feed_correlates_and_persists():
    # a raw Falco shell event in the same namespace/pod as the finding -> confirmed
    raw = [{"source": "syscall",
            "output_fields": {"proc.name": "bash", "k8s.ns.name": "default",
                              "k8s.pod.name": "health-check-deployment-5f8b94447d-blx"}}]
    result = _result()
    _attach_runtime_feed(result, _FakeCollector(raw), _request(), _args())
    assert result.runtime is not None
    assert result.runtime["source"] == "falco-logs"
    assert result.runtime["events_seen"] == 1
    assert result.runtime["correlation"]["confirmed_exploitation"] == 1
    assert "drift" in result.runtime


def test_attach_runtime_feed_skips_when_not_live_or_opted_out():
    for a in (_args(live=False), _args(mock=True), _args(no_runtime=True)):
        result = _result()
        _attach_runtime_feed(result, _FakeCollector([{"source": "syscall",
                             "output_fields": {"proc.name": "bash"}}]), _request(), a)
        assert result.runtime is None


def test_attach_runtime_feed_no_events_leaves_result_static():
    result = _result()
    _attach_runtime_feed(result, _FakeCollector([]), _request(), _args())
    assert result.runtime is None


def test_attach_runtime_feed_never_raises_on_collector_error():
    class _Boom(_FakeCollector):
        def collect_runtime_events(self, **_):
            raise RuntimeError("pods/log forbidden")
    result = _result()
    _attach_runtime_feed(result, _Boom([]), _request(), _args())  # must not raise
    assert result.runtime is None
