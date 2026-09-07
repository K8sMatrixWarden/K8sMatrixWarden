"""
Compliance verdicts must rest on evidence, and a partly-examined requirement is not met.

Found by auditing the crosswalk against the engine: 34 of the 54 requirements map to more
than one CIS control, and the status ladder returned PASS as soon as ONE of them passed.
PCI DSS 1.2.5 maps to CIS 5.3.1 and 5.3.2; with 5.3.1 passing and 5.3.2 never evaluated the
requirement reported `status: PASS`. The detail line named only 5.3.1, but `status` is the
machine-readable field an auditor filters on and the one the pass-percentage is computed
from, so a requirement that was half unexamined counted as satisfied.

`NA` is deliberately still allowed to pass. NA means the control does not apply to this
cluster -- a managed control plane the provider owns -- which is an answer. NOT_ASSESSED
means there was no answer, and the two must not be treated alike.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.frameworks.compliance import (FAIL, NOT_ASSESSED, PARTIAL, PASS,
                                                   ComplianceEngine)

CROSSWALK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "k8smatrixwarden", "taxonomy", "compliance_crosswalk.json")

#: PCI DSS 1.2.5, whose two mapped CIS controls made the defect reproducible.
_SPEC = {"id": "1.2.5", "title": "Network security controls",
         "cis": ["5.3.1", "5.3.2"], "owasp": ["K05"]}


def _verdict(cis_status, findings=None):
    engine = ComplianceEngine.__new__(ComplianceEngine)
    return engine._req(_SPEC, cis_status, findings or [])


# --------------------------------------------------------------------------- #
# The defect, and its boundaries
# --------------------------------------------------------------------------- #

def test_a_requirement_with_an_unassessed_control_is_not_pass():
    """REGRESSION. One control passing does not satisfy a requirement built on two."""
    found = _verdict({"5.3.1": PASS})
    assert found.status != PASS, (
        "a requirement reported PASS while one of its mapped controls was never "
        "assessed; UNKNOWN must not be promoted to compliant")
    assert found.status == PARTIAL, found.status
    assert "5.3.2" in found.detail, "the detail must name what was not assessed"
    assert "not verified" in found.detail


def test_a_requirement_passes_only_when_every_mapped_control_was_examined():
    found = _verdict({"5.3.1": PASS, "5.3.2": PASS})
    assert found.status == PASS
    assert "5.3.1" in found.detail and "5.3.2" in found.detail


def test_not_applicable_still_allows_a_pass():
    """NA is an answer: the control does not apply to this cluster. Treating it like
    NOT_ASSESSED would make every managed cluster permanently unverifiable."""
    found = _verdict({"5.3.1": PASS, "5.3.2": "NA"})
    assert found.status == PASS, found.detail


def test_a_failing_control_still_fails_the_requirement():
    """The fix must not have made FAIL reachable only through findings."""
    assert _verdict({"5.3.1": PASS, "5.3.2": FAIL}).status == FAIL


def test_nothing_assessed_is_not_assessed_rather_than_partial():
    assert _verdict({}).status == NOT_ASSESSED


def test_needs_node_remains_partial_with_its_own_reason():
    """PARTIAL has two causes now; each must explain itself."""
    found = _verdict({"5.3.1": "NEEDS_NODE", "5.3.2": PASS})
    assert found.status == PARTIAL
    assert "kube-bench" in found.detail, found.detail


# --------------------------------------------------------------------------- #
# The crosswalk itself
# --------------------------------------------------------------------------- #

def _requirements():
    import json
    with open(CROSSWALK, encoding="utf-8") as handle:
        frameworks = json.load(handle)["frameworks"]
    for name, body in frameworks.items():
        for req in body.get("requirements", []):
            yield name, req


def test_the_defect_was_reachable_for_most_requirements():
    """Context for the fix: this is not an edge case."""
    multi = [r for _, r in _requirements() if len(r.get("cis") or []) > 1]
    assert len(multi) > 20, (
        f"only {len(multi)} multi-control requirements; if the crosswalk changed shape "
        f"this test's premise needs revisiting")


def test_every_mapped_cis_control_exists_in_the_catalog():
    """A requirement mapped to a control id that does not exist can never be assessed,
    and would have silently counted as NOT_ASSESSED forever."""
    from k8smatrixwarden.frameworks.cis_catalog import CIS_1_8
    known = {c.id if hasattr(c, "id") else c["id"] for c in CIS_1_8}
    missing = []
    for framework, req in _requirements():
        for cid in req.get("cis") or []:
            if cid not in known:
                missing.append(f"{framework} {req['id']} -> CIS {cid}")
    assert not missing, f"mapped to non-existent CIS controls: {missing}"


def test_every_requirement_has_some_basis_for_a_verdict():
    """A requirement with neither a CIS control nor an OWASP category can only ever be
    NOT_ASSESSED, which is a mapping gap rather than a result."""
    orphans = [f"{fw} {r['id']}" for fw, r in _requirements()
               if not (r.get("cis") or r.get("owasp"))]
    assert not orphans, f"requirements with no mapping at all: {orphans}"


def test_all_four_frameworks_are_present():
    names = {fw for fw, _ in _requirements()}
    assert len(names) == 4, names


# --------------------------------------------------------------------------- #
# End to end, through the real audit
# --------------------------------------------------------------------------- #

def test_the_audit_never_reports_pass_without_naming_a_passing_control():
    """Whatever the cluster looks like, a PASS must cite the controls that passed."""
    from k8smatrixwarden.mcp.server import build_tools
    report = build_tools()["run_compliance_audit"](mock=True, output_format="json")
    frameworks = report["frameworks"]
    items = list(frameworks.values()) if isinstance(frameworks, dict) else frameworks
    checked = 0
    for framework in items:
        for req in framework.get("requirements") or framework.get("controls") or []:
            checked += 1
            if req["status"] == PASS:
                assert "passing" in req["detail"], (framework.get("name"), req)
                assert not [m for m in req["cis_controls"]
                            if m["status"] == NOT_ASSESSED], (
                    f"{req['id']} passed with an unassessed control")
    assert checked == 54, f"expected 54 requirements, saw {checked}"


if __name__ == "__main__":
    import traceback
    failed = 0
    for key, fn in sorted(globals().items()):
        if key.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {key}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
