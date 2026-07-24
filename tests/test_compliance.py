"""Compliance crosswalk engine, framework mapping onto CIS + OWASP, and its renderers."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import Finding, ResourceRef, Severity
from k8smatrixwarden.frameworks.cis import ControlResult
from k8smatrixwarden.frameworks.cis_catalog import CIS_1_8
from k8smatrixwarden.frameworks.compliance import (
    ComplianceEngine, load_crosswalk, framework_keys, run_audit,
    PASS, FAIL, PARTIAL, MANUAL, NEEDS_REVIEW, NOT_ASSESSED)
from k8smatrixwarden.frameworks import compliance_report as cr
from k8smatrixwarden.taxonomy import __file__ as _tax_init

_CIS_BY_ID = {c.id: c for c in CIS_1_8}


def _cr(cid, status):
    return ControlResult(_CIS_BY_ID[cid], status)


def _finding(rule_id="r", sev=Severity.HIGH, owasp=None, cis=None, ns="default"):
    return Finding(rule_id=rule_id, title=f"finding {rule_id}", severity=sev,
                   resource=ResourceRef("Pod", "x", ns), message="",
                   owasp=owasp, cis=cis or [])


# ---- crosswalk integrity ------------------------------------------------- #
def test_every_crosswalk_cis_id_exists_in_the_catalog():
    valid = {c.id for c in CIS_1_8}
    cw = load_crosswalk()["frameworks"]
    for key, spec in cw.items():
        for req in spec["requirements"]:
            for cid in req.get("cis", []):
                assert cid in valid, f"{key}/{req['id']} references unknown CIS {cid}"


def test_every_crosswalk_owasp_code_exists_in_the_taxonomy():
    owasp_path = os.path.join(os.path.dirname(_tax_init), "owasp_k8s_top10.json")
    codes = set(json.load(open(owasp_path))["categories"].keys())
    cw = load_crosswalk()["frameworks"]
    for key, spec in cw.items():
        for req in spec["requirements"]:
            for code in req.get("owasp", []):
                assert code in codes, f"{key}/{req['id']} references unknown OWASP {code}"


def test_all_four_frameworks_present():
    assert set(framework_keys()) == {
        "PCI-DSS-4.0", "SOC2", "ISO-27001-2022", "NIST-800-53-r5"}


def test_every_requirement_maps_to_at_least_one_control_or_owasp():
    for spec in load_crosswalk()["frameworks"].values():
        for req in spec["requirements"]:
            assert req.get("cis") or req.get("owasp"), \
                f"{req['id']} maps to nothing, it would always be NOT_ASSESSED"


# ---- status precedence --------------------------------------------------- #
def _status(cis_results, findings, req_id, framework="PCI-DSS-4.0"):
    rep = ComplianceEngine().evaluate(cis_results=cis_results, findings=findings,
                                      frameworks=[framework])
    return {r.id: r.status for r in rep.frameworks[0].requirements}[req_id]


def test_pass_when_mapped_cis_passes_and_no_findings():
    # PCI 8.2.1 -> CIS 1.2.1, 4.2.1 (owasp K09)
    assert _status([_cr("1.2.1", "PASS"), _cr("4.2.1", "PASS")], [], "8.2.1") == PASS


def test_fail_when_a_finding_carries_a_mapped_cis_tag():
    # Only a finding tagged with one of the requirement's CIS controls fails it.
    f = _finding(cis=["1.2.1"])
    assert _status([_cr("1.2.1", "PASS"), _cr("4.2.1", "PASS")], [f], "8.2.1") == FAIL


def test_owasp_only_finding_does_not_fail_it_is_needs_review():
    # 8.2.1 maps owasp K09; a K09-tagged finding with NO mapped CIS tag is a lead, not a FAIL.
    f = _finding(owasp="K09")
    assert _status([_cr("1.2.1", "PASS"), _cr("4.2.1", "PASS")], [f], "8.2.1") == PASS  # CIS pass wins
    # with no CIS signal at all, the same finding surfaces the requirement as NEEDS_REVIEW:
    assert _status([], [f], "8.2.1") == NEEDS_REVIEW


def test_fail_when_a_mapped_cis_control_fails():
    assert _status([_cr("1.2.1", "FAIL"), _cr("4.2.1", "PASS")], [], "8.2.1") == FAIL


def test_partial_when_a_mapped_control_needs_node_evidence():
    assert _status([_cr("1.2.1", "NEEDS_NODE"), _cr("4.2.1", "PASS")], [], "8.2.1") == PARTIAL


def test_not_assessed_when_only_owasp_and_no_finding():
    # PCI 6.3.1 maps to OWASP K07 only, no CIS. No finding => honest NOT_ASSESSED, not PASS.
    assert _status([], [], "6.3.1") == NOT_ASSESSED


def test_owasp_only_requirement_with_finding_is_needs_review_not_fail():
    # 6.3.1 (K07 only): a related K07 finding is an indicator to review, never a control FAIL.
    assert _status([], [_finding(owasp="K07")], "6.3.1") == NEEDS_REVIEW


def test_info_findings_do_not_block():
    # weight-0 findings must never flip a requirement to FAIL.
    assert _status([_cr("1.2.1", "PASS"), _cr("4.2.1", "PASS")],
                   [_finding(sev=Severity.INFO, cis=["1.2.1"])], "8.2.1") == PASS


# ---- attestation + blocking count --------------------------------------- #
def test_attestation_counts_distinct_cis_blocking_findings():
    # CC6.1 maps CIS 5.1.1/5.1.3/5.2.1; findings tagged with those are the true blockers.
    f1 = _finding(rule_id="a", cis=["5.1.1"])
    f2 = _finding(rule_id="b", cis=["5.1.3"])
    rep = ComplianceEngine().evaluate(cis_results=[], findings=[f1, f2],
                                      frameworks=["SOC2"])
    fw = rep.frameworks[0]
    assert fw.blocking_findings >= 2
    assert "fail on automated checks" in fw.attestation and "before assessment" in fw.attestation


# ---- end-to-end facade + renderers on the mock cluster ------------------- #
def test_run_audit_on_mock_cluster_produces_all_frameworks():
    rep = run_audit(build_platform(), mock=True, profile="self-managed")
    assert len(rep.frameworks) == 4
    # the deliberately-insecure mock cluster must fail PCI attestation.
    pci = next(f for f in rep.frameworks if f.key == "PCI-DSS-4.0")
    assert pci.counts[FAIL] > 0
    assert pci.blocking_findings > 0


def test_renderers_round_trip():
    rep = run_audit(build_platform(), mock=True, profile="self-managed",
                    frameworks=["PCI-DSS-4.0"])
    md = cr.to_markdown(rep)
    assert "# Compliance Audit" in md and "PCI DSS" in md
    html = cr.to_html(rep)
    assert "<!doctype html>" in html.lower() and "Compliance Audit" in html
    frag = cr.to_html(rep, standalone=False)
    assert "<!doctype" not in frag.lower()  # embeddable fragment, no doc shell


def test_unknown_framework_is_ignored_not_crashed():
    rep = ComplianceEngine().evaluate(cis_results=[], findings=[],
                                      frameworks=["NOT-A-FRAMEWORK"])
    assert rep.frameworks == []
