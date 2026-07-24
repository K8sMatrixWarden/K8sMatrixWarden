"""Kubernetes Threat Matrix projection (§12), build, coverage, and rendering."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector, Tactic
from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.core.threat_matrix import (TACTIC_ORDER, build_threat_matrix)
from k8smatrixwarden.core.threat_matrix_render import (render_html_grid, render_markdown,
                                                      render_text)


def _scan(selector=None, scope=None):
    p = build_platform()
    req = ScanRequest(scope=scope or Scope(ScopeLevel.CLUSTER),
                      selector=selector or Selector())
    result = ScannerAgent(p).scan(req, p.make_collector(mock=True))
    return p, result


def test_matrix_has_all_nine_tactics_in_kill_chain_order():
    p, result = _scan()
    tm = build_threat_matrix(result, p.registry.rules)
    assert len(tm.columns) == 9
    assert [c.tactic for c in tm.columns] == [t.value for t in TACTIC_ORDER]
    # every canonical tactic is represented
    assert {c.tactic for c in tm.columns} == {t.value for t in Tactic}


def test_full_scan_lights_up_every_tactic():
    p, result = _scan()
    tm = build_threat_matrix(result, p.registry.rules)
    assert tm.tactics_hit == 9                     # insecure mock cluster hits all 9
    assert tm.techniques_hit > 0
    assert tm.finding_count > 0


def test_coverage_layer_marks_covered_without_findings():
    """With a registry but no findings, cells are covered/gap, never hit."""
    p, result = _scan()
    result.findings = []                           # drop findings, keep the registry
    tm = build_threat_matrix(result, p.registry.rules)
    assert tm.techniques_hit == 0
    assert tm.techniques_covered > 0               # rules still provide coverage
    assert all(not c.hit for col in tm.columns for c in col.cells)


def test_findings_only_matrix_without_registry():
    p, result = _scan()
    tm = build_threat_matrix(result)               # no registry passed
    assert tm.techniques_hit > 0
    assert tm.techniques_covered == 0              # coverage layer absent


def test_cell_state_and_severity_reflect_findings():
    p, result = _scan()
    tm = build_threat_matrix(result, p.registry.rules)
    hit_cells = [c for col in tm.columns for c in col.cells if c.hit]
    assert hit_cells
    for c in hit_cells:
        assert c.state == "hit"
        assert c.max_severity is not None
        assert c.count == len(c.findings)


def test_tactic_slice_hits_that_tactic_and_its_attack_paths():
    """A Persistence scan lights up Persistence, and, correctly, any *other* tactic a
    multi-tactic finding (e.g. a writable hostPath = Persistence + PrivEsc + Lateral) also
    enables. That attack-path spread is the point of the matrix, not a bug."""
    p, result = _scan(selector=Selector(tactics=["Persistence"]))
    tm = build_threat_matrix(result, p.registry.rules)
    persistence = next(c for c in tm.columns if c.tactic == "Persistence")
    assert persistence.hit_count > 0
    # every finding came from a Persistence-tagged rule (the selector's guarantee)
    assert all(any(t.value == "Persistence" for t in f.tactics) for f in result.findings)


def test_as_dict_is_json_serializable_and_complete():
    import json
    p, result = _scan()
    d = build_threat_matrix(result, p.registry.rules).as_dict()
    json.dumps(d)                                  # must not raise
    assert set(d) == {"summary", "columns"}
    s = d["summary"]
    assert s["tactics_total"] == 9
    assert 0 <= s["coverage_pct"] <= 100
    cell = d["columns"][0]["cells"][0]
    assert set(cell) >= {"technique_name", "state", "count", "url"}


def test_summary_finding_count_is_distinct_not_inflated():
    """A multi-tactic finding sits in several columns; the headline count must dedupe it
    and never exceed the scan's real finding total."""
    p, result = _scan()
    tm = build_threat_matrix(result, p.registry.rules)
    assert tm.finding_count <= result.total()
    # per-column counts still legitimately count a finding once per tactic it enables,
    # so their sum is >= the distinct total (that's the attack-path amplification).
    col_sum = sum(col.finding_count for col in tm.columns)
    assert col_sum >= tm.finding_count


def test_renderers_produce_nonempty_output():
    p, result = _scan()
    tm = build_threat_matrix(result, p.registry.rules)
    assert "THREAT MATRIX" in render_text(tm)
    md = render_markdown(tm)
    assert "Kubernetes Threat Matrix" in md and "| Tactic |" in md
    html = render_html_grid(tm)
    assert "tmgrid" in html and "tmcell" in html


def test_duplicate_id_in_tactic_keeps_distinct_cells():
    """Lateral Movement lists T1078.004 and T1552 once each, but ARP/CoreDNS share no id
    with them, verify no reference technique is silently collapsed away."""
    p, result = _scan()
    tm = build_threat_matrix(result, p.registry.rules)
    lm = next(c for c in tm.columns if c.tactic == "Lateral Movement")
    names = [cell.technique_name for cell in lm.cells]
    assert "CoreDNS poisoning" in " ".join(names) or any("CoreDNS" in n for n in names)
    # every Redguard technique for the tactic is present (>= the reference count)
    assert len(lm.cells) >= 7
