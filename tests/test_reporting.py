"""Report quality, structure & correctness across all six formats (§18.2)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.orchestrator import Orchestrator
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector


def _result():
    p = build_platform()
    o = Orchestrator(p)
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector())
    return p, o.run(req, p.make_collector(mock=True))


def test_all_formats_render_nonempty():
    p, res = _result()
    for fmt in ("terminal", "text", "markdown", "json", "sarif", "html"):
        out = p.reporting.render(res, fmt)
        assert isinstance(out, str) and len(out) > 500, fmt


def test_markdown_has_rich_structure():
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    for marker in ("---", "# 🛡️ K8s Security Report", "## 1. 📊 Executive Summary",
                   "## 2. 🗺️ Kubernetes Threat Matrix", "## 3. 🎯 Coverage & Exposure",
                   "OWASP Kubernetes Top 10",
                   "## 4. 🚨 Findings", "## 5. 📎 Appendix", "```bash"):
        assert marker in md, f"missing section: {marker!r}"


def test_markdown_tables_have_balanced_backticks():
    # broken table cells (inner backticks / newlines) would corrupt rendering
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    for ln in md.splitlines():
        if ln.startswith("| "):
            assert ln.count("`") % 2 == 0, f"unbalanced backticks: {ln[:80]}"


def test_json_has_summary_and_finding_context():
    p, res = _result()
    doc = json.loads(p.reporting.render(res, "json"))
    assert "summary" in doc
    assert set(doc["summary"]) >= {"rating", "risk_score", "security_score",
                                   "severity_percent", "owasp", "attack_path_amplified"}
    # per-finding report-grade context is present; remediation was removed by design
    assert all("impact" in f and "validation_steps" in f for f in doc["findings"])
    assert not any("remediation" in f for f in doc["findings"])


def test_sarif_is_valid_and_enriched():
    p, res = _result()
    doc = json.loads(p.reporting.render(res, "sarif"))
    assert doc["version"] == "2.1.0"
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rules, "no SARIF rules emitted"
    r0 = rules[0]
    assert "security-severity" in r0["properties"]
    assert any(t.startswith("mitre/") for t in r0["properties"]["tags"])
    for res_item in doc["runs"][0]["results"]:
        assert "partialFingerprints" in res_item


def test_html_is_self_contained_and_filterable():
    p, res = _result()
    html = p.reporting.render(res, "html")
    assert html.startswith("<!doctype html>")
    low = html.lower()
    assert "card" in low and html.count("card") >= 5   # multiple finding cards
    assert "data-f=" in html                            # interactive severity filters
    assert "gauge" in low                               # risk gauge
    # self-contained: no external stylesheets/scripts/fonts (URLs inside finding text are OK)
    assert "<script src" not in low
    assert "<link" not in low
    assert "url(http" not in low


# ======================================================================= #
# Report-grade per-finding sections: Summary / Standards & Benchmark Mapping
# (with reference links) / MITRE ATT&CK Mapping (with reference links) / Impact /
# Validation (how to reproduce).
# ======================================================================= #
def test_markdown_finding_cards_have_all_required_sections():
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    for marker in ("##### Summary", "##### 📚 Standards & Benchmark Mapping",
                  "##### 🎯 MITRE ATT&CK Mapping", "##### 💥 Impact",
                  "##### ✅ Validation, How to Reproduce / Verify"):
        assert marker in md, f"missing per-finding section: {marker!r}"


def test_markdown_standards_and_mitre_carry_real_reference_links():
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    assert "https://attack.mitre.org/techniques/" in md
    assert "https://www.cisecurity.org/benchmark/kubernetes" in md
    assert "https://owasp.org/www-project-kubernetes-top-ten/" in md


def test_markdown_cis_control_shows_real_title_not_generic_placeholder():
    p, res = _result()
    md = p.reporting.render(res, "markdown")
    # the generic "Control X.Y.Z" placeholder must never appear once real CIS titles
    # are wired in (regression guard for the redundant "5.7.2 -- Control 5.7.2" bug)
    import re
    assert not re.search(r", Control \d+\.\d+", md)


def test_json_findings_carry_full_context_block():
    p, res = _result()
    doc = json.loads(p.reporting.render(res, "json"))
    for fd in doc["findings"]:
        assert "summary" in fd and fd["summary"]
        assert "impact" in fd and fd["impact"]
        assert "validation_steps" in fd and fd["validation_steps"]
        assert "standards" in fd
        assert "mitre_mapping" in fd
        if fd["standards"]:
            assert all(s["url"].startswith("http") for s in fd["standards"])
        if fd["mitre_mapping"]:
            assert all(m["url"].startswith("https://attack.mitre.org")
                      for m in fd["mitre_mapping"])


def test_sarif_help_markdown_and_impact_property_present():
    p, res = _result()
    doc = json.loads(p.reporting.render(res, "sarif"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rules
    for r in rules:
        assert "markdown" in r["help"]
        assert r["properties"].get("impact")


def test_html_cards_have_standards_and_mitre_tables():
    p, res = _result()
    html = p.reporting.render(res, "html")
    assert "Standards &amp; Benchmark Mapping" in html
    assert "MITRE ATT&amp;CK Mapping" in html
    assert "ctx-table" in html
    assert "Validation, how to reproduce" in html


# --------------------------------------------------------------------------- #
# OWASP Kubernetes Top 10, every tag links to its own control page
# --------------------------------------------------------------------------- #
def test_owasp_ids_link_to_their_own_page_not_the_project_landing_page():
    from k8smatrixwarden.core.finding_context import (OWASP_K8S_TOP10_URL,
                                                      _owasp_names, owasp_url)
    codes = _owasp_names()
    assert set(codes) == {f"K{n:02d}" for n in range(1, 11)}
    seen = set()
    for code in codes:
        url = owasp_url(code)
        assert url != OWASP_K8S_TOP10_URL, f"{code} still points at the landing page"
        assert f"/{code}-" in url, url
        assert url.startswith("https://owasp.org/www-project-kubernetes-top-ten/2025/")
        seen.add(url)
    assert len(seen) == 10                      # ten distinct destinations
    # an unknown code degrades to the project page rather than a dead link
    assert owasp_url("K99") == OWASP_K8S_TOP10_URL
    assert owasp_url(None) == OWASP_K8S_TOP10_URL


def test_reports_carry_the_direct_owasp_link():
    p, res = _result()
    tagged = next(f for f in res.findings if f.owasp)
    from k8smatrixwarden.core.finding_context import owasp_url
    expected = owasp_url(tagged.owasp)
    assert expected in p.reporting.render(res, "html")
    assert expected in p.reporting.render(res, "markdown")
