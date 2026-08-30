"""
Evidence coverage and assessment confidence (§5).

The invariant under test: "we could not read it" must never render as "it is fine". A
partly-readable cluster reports lower coverage and lower confidence, while every finding it
DID produce survives untouched.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.coverage import build_coverage, confidence_label
from k8smatrixwarden.core.evidence import EvidenceCollector, default_fixture_path
from k8smatrixwarden.core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector
from k8smatrixwarden.core.results import ScanResult


class _PartialCollector(EvidenceCollector):
    """A collector that can read pods but is forbidden ClusterRoles, the shape of a real
    under-permissioned ServiceAccount. (ClusterRole rather than Secret because no rule
    lists Secret objects, the scanner detects exposed secrets from workload specs and
    control-plane config, so its RBAC never asks for Secret contents at all.)"""

    def __init__(self, forbidden=("ClusterRole",), fatal=False):
        super().__init__()
        import json
        with open(default_fixture_path(), encoding="utf-8") as fh:
            self._data = json.load(fh)
        self._forbidden = set(forbidden)
        self._fatal = fatal

    def _fetch(self, kind, bucket):
        if kind in self._forbidden or self._fatal:
            self.warnings.append(f"{kind}: skipped (HTTP 403 Forbidden)")
            self._record(kind, "skipped", 0, "HTTP 403 Forbidden")
            return []
        self.fetched_ok = True
        items = self._data.get(bucket, [])
        for it in items:
            it.setdefault("kind", kind)
        return list(items)


def _scan(collector):
    platform = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                          mode=ScanMode.SYNC)
    return ScannerAgent(platform).scan(request, collector)


def test_a_fully_readable_scan_reports_full_coverage():
    platform = build_platform()
    result = _scan(platform.make_collector(mock=True))
    assert result.coverage["coverage_pct"] == 100.0
    assert result.coverage["confidence_label"] == "High"
    assert result.coverage["unread_kinds"] == []


def test_partial_access_lowers_coverage_without_hiding_findings():
    full = _scan(build_platform().make_collector(mock=True))
    partial = _scan(_PartialCollector())

    assert partial.coverage["coverage_pct"] < full.coverage["coverage_pct"]
    assert "ClusterRole" in partial.coverage["unread_kinds"]
    assert partial.coverage["kinds"]["ClusterRole"]["status"] == "skipped"
    assert "403" in partial.coverage["kinds"]["ClusterRole"]["reason"]
    # Every finding the scan COULD reach is still reported in full.
    assert partial.findings, "a partial scan still produces findings"
    assert partial.evidence_ok is True                     # degraded != unreadable


def test_unread_evidence_never_becomes_a_passing_score():
    """A collector that could read nothing at all is not a clean cluster."""
    result = _scan(_PartialCollector(fatal=True))
    assert result.evidence_ok is False
    assert result.risk.rating == "Unknown"
    assert result.coverage["confidence_pct"] == 0.0
    assert result.coverage["confidence_label"] == "None"


def test_domain_breakdown_groups_kinds():
    result = _scan(_PartialCollector())
    domains = result.coverage["domains"]
    assert domains["RBAC"]["coverage_pct"] < 100             # ClusterRole unreadable
    assert domains["Workloads"]["coverage_pct"] == 100.0
    assert "ClusterRole" in domains["RBAC"]["kinds"]


def test_partial_reads_count_for_half():
    class _Capped(EvidenceCollector):
        def _fetch(self, kind, bucket):
            self.fetched_ok = True
            self._record(kind, "partial", 1, "hit the pagination cap")
            return [{"kind": kind}]

    collector = _Capped()
    collector.collect({"Pod", "Node"}, Scope(ScopeLevel.CLUSTER))
    assert build_coverage(collector)["coverage_pct"] == 50.0


def test_confidence_labels_are_stable_thresholds():
    assert confidence_label(100.0) == "High"
    assert confidence_label(90.0) == "High"
    assert confidence_label(75.0) == "Moderate"
    assert confidence_label(50.0) == "Low"
    assert confidence_label(10.0) == "Very Low"
    assert confidence_label(100.0, evidence_ok=False) == "None"


def test_coverage_is_absent_not_faked_for_a_scan_without_it():
    """Old stored reports have no coverage block; nothing may invent 100% for them."""
    from k8smatrixwarden.core.scoring import RiskScoringEngine
    result = ScanResult(request=ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                                            selector=Selector()),
                        findings=[], risk=RiskScoringEngine().score([]),
                        resolved_rule_ids=[])
    assert result.coverage == {}
    assert "coverage" not in result.as_dict()


def test_coverage_survives_a_save_load_round_trip():
    result = _scan(_PartialCollector())
    restored = ScanResult.from_dict(result.as_dict())
    assert restored.coverage == result.coverage


def test_coverage_reaches_the_report_and_the_mcp_layer():
    import json
    from k8smatrixwarden.mcp.server import build_tools
    import tempfile

    platform = build_platform()
    result = _scan(platform.make_collector(mock=True))
    doc = json.loads(platform.reporting.json(result))
    assert doc["summary"]["evidence_coverage_pct"] == 100.0
    assert doc["summary"]["assessment_confidence"] == "High"

    reports_dir = tempfile.mkdtemp()
    from k8smatrixwarden.core.report_store import ReportStore
    ReportStore(reports_dir).save(result)
    out = build_tools()["get_cluster_coverage"](reports_dir=reports_dir)
    assert out["coverage"]["coverage_pct"] == 100.0
    assert out["evidence_ok"] is True
