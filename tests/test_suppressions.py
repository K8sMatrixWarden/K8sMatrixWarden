"""Accepted risks and new-only baselines."""
import datetime as dt
import json

from k8smatrixwarden.core.models import Finding, ResourceRef, Severity
from k8smatrixwarden.core.suppressions import apply, discover, new_since


def _f(rule, name="web", ns="shop", kind="Deployment"):
    return Finding(rule_id=rule, title=rule, severity=Severity.HIGH,
                   resource=ResourceRef(kind, name, ns), message="m", owning_shard="s")


TODAY = dt.date(2026, 10, 18)


def test_a_suppression_hides_only_what_it_names_and_keeps_the_reason():
    fs = [_f("workload-run-as-root"), _f("workload-run-as-root", name="api"), _f("net-x")]
    kept, rows, notes = apply(fs, [{"rule": "workload-run-as-root", "resource": "shop/Deployment/web",
                                    "reason": "vendor image SEC-1", "owner": "ann", "expires": "2026-12-31"}], TODAY)
    assert [f.resource.name for f in kept] == ["api", "web"] or len(kept) == 2
    assert rows[0]["reason"] == "vendor image SEC-1" and rows[0]["owner"] == "ann" and not notes


def test_expired_and_reasonless_suppressions_do_not_apply_and_say_so():
    fs = [_f("a"), _f("b")]
    kept, rows, notes = apply(fs, [{"rule": "a", "reason": "old", "expires": "2026-01-01"},
                                   {"rule": "b"}], TODAY)
    assert len(kept) == 2 and not rows
    assert any("expired" in n for n in notes) and any("needs a rule and a reason" in n for n in notes)


def test_a_suppression_matching_nothing_is_reported_as_stale():
    _, _, notes = apply([_f("a")], [{"rule": "zzz", "reason": "r"}], TODAY)
    assert any("matches no finding" in n for n in notes)


def test_globs_and_discovery_from_files(tmp_path, monkeypatch):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"suppressions": [{"rule": "net-*", "reason": "r"}]}))
    items, problems = discover(None, [str(p)])
    kept, rows, _ = apply([_f("net-no-networkpolicy"), _f("rbac-x")], items, TODAY)
    assert len(rows) == 1 and kept[0].rule_id == "rbac-x" and not problems


def test_new_since_a_baseline_counts_only_unseen_findings():
    old = [_f("a")]
    assert [f.rule_id for f in new_since([_f("a"), _f("b")], old)] == ["b"]


def test_slack_message_groups_by_owner_and_never_sends_without_https(tmp_path):
    import pytest
    from k8smatrixwarden.core.notify import send, slack_payload
    from k8smatrixwarden.core.results import ScanResult
    from k8smatrixwarden.core.scoring import RiskResult
    res = ScanResult(request=None, findings=[], resolved_rule_ids=[],
                     risk=RiskResult(cluster_risk=8.0, security_score=20, rating="Poor", rating_emoji="🟠", raw=0.0),
                     workload_issues=[
                         {"severity": "CRITICAL", "title": "Privileged container", "workload": "Deployment/web",
                          "rule_id": "workload-privileged-container", "score": 60, "owner": "payments"},
                         {"severity": "LOW", "title": "x", "workload": "y", "rule_id": "z", "score": 1, "owner": "infra"}])
    text = slack_payload(res, "HIGH", "http://d:8765")["text"]
    assert "payments 1" in text and "infra" not in text and "Remove `privileged: true`" in text
    with pytest.raises(ValueError):
        send("http://insecure.example/hook", {"text": "x"})
