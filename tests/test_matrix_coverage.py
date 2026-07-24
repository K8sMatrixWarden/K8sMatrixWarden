"""Threat-matrix coverage semantics.

Two things made the matrix understate real coverage, both fixed here:

  1. **Id-first cell matching.** The Redguard matrix is finer-grained than
     ATT&CK-for-Containers, "Access the K8s API server", "Access Kubelet API" and
     "Access Kubernetes dashboard" are three distinct Discovery techniques all carrying
     the single id T1613. Matching by id first collapsed them into one cell, so two
     rendered as coverage gaps even though rules for them existed.
  2. **The coverage layer ignored the Runtime Agent.** Techniques that are structurally
     invisible to a config snapshot (a shell being spawned, a miner starting) can only be
     covered at runtime, and were painted as flat gaps.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import RuntimeAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.threat_matrix import build_threat_matrix
from k8smatrixwarden.web.app import _empty_result


def _coverage_matrix(**kw):
    platform = build_platform()
    return build_threat_matrix(_empty_result(platform), platform.registry.rules, **kw)


def _cell(matrix, tactic, technique_name):
    column = next(c for c in matrix.columns if c.tactic == tactic)
    return next(c for c in column.cells if c.technique_name == technique_name)


# --------------------------------------------------------------------------- #
# name-before-id cell resolution
# --------------------------------------------------------------------------- #
def test_redguard_techniques_sharing_one_attack_id_stay_distinct():
    """All three carry T1613. Each must resolve to its own cell, and each must be
    covered by the rules that actually detect it."""
    matrix = _coverage_matrix()
    api = _cell(matrix, "Discovery", "Access the K8s API server")
    kubelet = _cell(matrix, "Discovery", "Access Kubelet API")
    dashboard = _cell(matrix, "Discovery", "Access Kubernetes dashboard")

    assert api.key != kubelet.key != dashboard.key
    assert kubelet.covered and dashboard.covered and api.covered
    # and the right rules landed on the right cells, not all on the T1613 cell
    assert any(r.startswith("kubelet-") for r in kubelet.rule_ids), kubelet.rule_ids
    assert "net-dashboard-exposed" in dashboard.rule_ids
    assert not any(r.startswith("kubelet-") for r in api.rule_ids)


def test_discovery_has_no_remaining_coverage_gaps():
    matrix = _coverage_matrix()
    column = next(c for c in matrix.columns if c.tactic == "Discovery")
    assert [c.technique_name for c in column.cells if c.state == "gap"] == []


def test_canonical_attack_names_still_resolve_by_id():
    """Only a verbatim Redguard name opts into a specific cell; a rule tagged with a
    canonical ATT&CK technique name must keep resolving by id exactly as before."""
    matrix = _coverage_matrix()
    # "Deploy Container"/T1610 is a canonical ATT&CK name, matching no Redguard cell name
    privileged = _cell(matrix, "Privilege Escalation", "Privileged container")
    assert privileged.technique_id == "T1610" and privileged.covered


# --------------------------------------------------------------------------- #
# runtime coverage is a distinct state, never folded into scan coverage
# --------------------------------------------------------------------------- #
def test_runtime_only_techniques_are_marked_runtime_not_gap():
    matrix = _coverage_matrix()
    # a shell spawned inside a container is invisible to a config snapshot by nature
    shell = _cell(matrix, "Execution", "bash/cmd inside container")
    assert shell.state == "runtime"
    assert shell.covered_runtime and not shell.covered
    assert shell.runtime_rule_ids


def test_runtime_coverage_does_not_claim_scan_coverage():
    """`covered` must stay strictly "a scan rule exists", folding runtime detections in
    would claim point-in-time coverage the scanner does not have."""
    matrix = _coverage_matrix()
    for column in matrix.columns:
        for cell in column.cells:
            if cell.covered_runtime and not cell.rule_ids:
                assert cell.covered is False, cell.technique_name
    summary = matrix.summary()
    assert summary["techniques_runtime_only"] > 0
    assert summary["coverage_pct_with_runtime"] > summary["coverage_pct"]


def test_scan_only_matrix_is_still_available():
    """Passing an explicit empty catalog opts out, nothing is silently runtime-covered."""
    matrix = _coverage_matrix(runtime_catalog=[])
    assert matrix.summary()["techniques_runtime_only"] == 0
    assert _cell(matrix, "Execution", "bash/cmd inside container").state == "gap"


def test_runtime_layer_is_loaded_by_default_on_every_surface():
    """The default matters: CLI, report, dashboard and MCP all call build_threat_matrix
    without a catalog, and must not disagree about coverage."""
    default = _coverage_matrix().summary()
    explicit = _coverage_matrix(runtime_catalog=RuntimeAgent().catalog()).summary()
    assert default == explicit


def test_a_hit_always_outranks_runtime_coverage():
    """State precedence: an actual finding is the most specific thing known about a cell."""
    platform = build_platform()
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                          mode=ScanMode.SYNC)
    result = ScannerAgent(platform).scan(request, platform.make_collector(mock=True))
    matrix = build_threat_matrix(result, platform.registry.rules)
    for column in matrix.columns:
        for cell in column.cells:
            if cell.hit:
                assert cell.state == "hit", cell.technique_name


# --------------------------------------------------------------------------- #
# the reported numbers
# --------------------------------------------------------------------------- #
def test_summary_separates_scan_and_runtime_coverage():
    summary = _coverage_matrix().summary()
    scan_and_runtime = summary["techniques_covered"] + summary["techniques_runtime_only"]
    assert scan_and_runtime <= summary["techniques_total"]
    assert summary["coverage_pct_with_runtime"] == round(
        100 * scan_and_runtime / summary["techniques_total"], 1)
