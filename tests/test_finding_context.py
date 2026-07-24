"""Finding Context (core/finding_context.py), the shared report-grade content layer
every renderer (markdown/html/json/sarif/pdf) sources Summary/Standards/MITRE/Impact/
Validation from."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.finding_context import (FINDING_CONTEXT, build_finding_context,
                                                   mitre_for, mitre_technique_url,
                                                   standards_for)
from k8smatrixwarden.core.models import (BlastRadius, DetectionMethod, Exploitability,
                                          Finding, MitreTag, ResourceRef, Severity, Tactic)


def test_every_registered_rule_has_kb_content():
    p = build_platform()
    all_ids = set(p.registry.rules.ids())
    kb_ids = set(FINDING_CONTEXT.keys())
    assert all_ids == kb_ids, (all_ids - kb_ids, kb_ids - all_ids)


def test_every_kb_entry_has_summary_impact_and_validation():
    for rule_id, entry in FINDING_CONTEXT.items():
        assert entry.get("summary"), rule_id
        assert entry.get("impact"), rule_id
        assert entry.get("validation"), rule_id


def test_mitre_technique_url_top_level():
    assert mitre_technique_url("T1610") == "https://attack.mitre.org/techniques/T1610/"


def test_mitre_technique_url_subtechnique_uses_slash_not_dot():
    # MITRE's own site uses /T1552/007/, not /T1552.007/
    assert mitre_technique_url("T1552.007") == \
        "https://attack.mitre.org/techniques/T1552/007/"


def _finding(**kw) -> Finding:
    defaults = dict(
        rule_id="workload-privileged-container", title="Privileged container",
        severity=Severity.CRITICAL, resource=ResourceRef("Pod", "x", "ns"),
        message="m", owning_shard="workload_pod_security",
        detection_method=DetectionMethod.STATIC_CONFIG,
        exploitability=Exploitability.LOCAL, blast_radius=BlastRadius.POD,
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_standards_for_uses_real_cis_control_titles_not_generic_placeholder():
    f = _finding(owasp="K01", cis=["5.2.2"])
    refs = standards_for(f)
    cis_ref = next(r for r in refs if r.framework.startswith("CIS"))
    assert "privileged" in cis_ref.title.lower()
    assert cis_ref.control == "5.2.2"
    assert cis_ref.url


def test_standards_for_owasp_uses_real_category_name():
    f = _finding(owasp="K02")
    refs = standards_for(f)
    owasp_ref = next(r for r in refs if "OWASP" in r.framework)
    assert "Authorization" in owasp_ref.title


def test_standards_for_empty_when_no_tags():
    f = _finding(owasp=None, cis=[], nsa_cisa=[])
    assert standards_for(f) == []


def test_mitre_for_dedupes_same_tactic_technique_pair():
    tag = MitreTag(Tactic.PRIVILEGE_ESCALATION, "T1610", "Deploy Container")
    f = _finding(mitre=[tag, tag])
    refs = mitre_for(f)
    assert len(refs) == 1
    assert refs[0].url == "https://attack.mitre.org/techniques/T1610/"


def test_build_finding_context_never_leaves_unsubstituted_templates():
    p = build_platform()
    coll = p.make_collector(mock=True)
    from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector())
    rule_ids = p.mapping.resolve(req.selector)
    findings = p.aggregator.aggregate(p.detection.run(rule_ids, coll, req.scope))
    assert findings
    for f in findings:
        ctx = build_finding_context(f)
        assert ctx.summary and ctx.impact and ctx.validation_steps
        for step in ctx.validation_steps:
            assert "{name}" not in step and "{namespace}" not in step and \
                "{kind}" not in step


def test_build_finding_context_falls_back_for_unknown_rule_id():
    # a rule id genuinely absent from the KB must still produce non-empty content, 
    # never a blank report section.
    f = _finding(rule_id="not-a-real-rule-id", mitre=[
        MitreTag(Tactic.DISCOVERY, "T1613", "Container and Resource Discovery")])
    ctx = build_finding_context(f)
    assert ctx.summary  # falls back to finding.message
    assert ctx.impact
    assert ctx.validation_steps
