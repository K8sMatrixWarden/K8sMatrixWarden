"""Sample runtime events for the Runtime tab's demo path: synthetic, but land in the
right confidence tier when pushed through the real correlation engine."""
import json

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.correlation import correlate
from k8smatrixwarden.core.models import Finding, MitreTag, ResourceRef, Severity, Tactic
from k8smatrixwarden.core.runtime_demo import sample_events
from k8smatrixwarden.web.app import WebApp


def _finding(tactic, rule_id="r1", name="victim-pod", ns="prod", technique="T1059"):
    return Finding(rule_id=rule_id, title="t", severity=Severity.HIGH,
                   resource=ResourceRef("Pod", name, ns), message="m", owning_shard="s",
                   mitre=[MitreTag(tactic, technique, "n")])


class _Result:
    def __init__(self, findings, cluster_name="c"):
        self.findings = findings
        self.cluster_name = cluster_name


def test_no_findings_means_no_demo_rather_than_a_fabricated_one():
    assert sample_events(_Result([])) == []


def test_three_events_land_in_the_three_documented_tiers():
    f = _finding(Tactic.EXECUTION)
    events = sample_events(_Result([f]))
    assert len(events) == 3
    from k8smatrixwarden.agents.runtime import RuntimeAgent
    alerts = RuntimeAgent().evaluate_batch(events)[0]
    corr = correlate([f], alerts, cluster="c", now="2026-01-01T00:00:00Z")["correlations"]
    got = {c["resource"]: c["confidence"] for c in corr}
    assert got["victim-pod"] == "confirmed"
    assert got["demo-unrecognised-pod-abc123"] == "corroborated"
    assert got["demo-unplaced-pod-xyz789"] == "runtime-only"


def test_credential_access_tactic_reads_the_sensitive_file():
    f = _finding(Tactic.CREDENTIAL_ACCESS, technique="T1552.007")
    confirmed = sample_events(_Result([f]))[0]
    assert confirmed["rule"] == "Read sensitive file untrusted" and confirmed["file"] == "/etc/shadow"


def test_a_non_execution_anchor_still_lands_confirmed_not_silently_reclassified():
    """Regression: the first draft always wrote 'Terminal shell in container' + proc sh,
    which matches agents/runtime.py's CURATED rt-shell-in-container rule -- whose tactic is
    hard-coded to Execution regardless of what tag was attached. An anchor finding tagged
    only Privilege Escalation (no Execution) was silently correlated as Execution instead,
    so it never resource-matched its own finding and landed 'corroborated', not 'confirmed'.
    A single-tactic Execution anchor cannot catch this; it must be a different tactic."""
    from k8smatrixwarden.agents.runtime import RuntimeAgent
    f = _finding(Tactic.PRIVILEGE_ESCALATION, technique="T1611")
    events = sample_events(_Result([f]))
    alerts, _ = RuntimeAgent().evaluate_batch(events)
    corr = correlate([f], alerts, cluster="c", now="2026-01-01T00:00:00Z")["correlations"]
    got = {c["resource"]: c["confidence"] for c in corr}
    assert got["victim-pod"] == "confirmed", got


def test_every_demo_event_is_valid_falco_shape_and_never_fabricates_a_namespace():
    f = _finding(Tactic.DISCOVERY, ns="shop")
    for e in sample_events(_Result([f])):
        assert e["source"] == "falco" and e["rule"] and e["namespace"] == "shop"


def test_http_demo_endpoint_runs_through_real_ingestion_and_labels_itself(tmp_path):
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.core.results import ScanResult
    from k8smatrixwarden.core.scoring import RiskResult

    class _Req:
        class scope:
            @staticmethod
            def describe(): return "cluster-wide"
        class selector:
            @staticmethod
            def describe(): return ""

    result = ScanResult(request=_Req(), findings=[_finding(Tactic.EXECUTION)],
                        resolved_rule_ids=["r1"],
                        risk=RiskResult(cluster_risk=5.0, security_score=50, rating="Fair",
                                       rating_emoji="🟡", raw=0.0),
                        cluster_name="demo-cluster", mode="mock")
    store = ReportStore(str(tmp_path))
    store.save(result)
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    r = app.route("POST", "/api/runtime/demo", body=json.dumps({"scan_id": result.scan_id}).encode())
    assert r.status == 200
    d = json.loads(r.body)
    assert d["demo"] is True and len(d["demo_events"]) == 3
    assert d["correlation"]["confirmed_exploitation"] >= 1

    empty = ScanResult(request=_Req(), findings=[], resolved_rule_ids=[],
                       risk=RiskResult(cluster_risk=0.0, security_score=100, rating="Excellent",
                                      rating_emoji="🟢", raw=0.0), mode="mock")
    store.save(empty)
    bad = app.route("POST", "/api/runtime/demo", body=json.dumps({"scan_id": empty.scan_id}).encode())
    assert bad.status == 400 and "no finding" in json.loads(bad.body)["error"]
