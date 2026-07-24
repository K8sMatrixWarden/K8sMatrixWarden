"""
Agent memory (Phase 2/3/5). SQLite is :memory:, no files, no network.
Covers: finding saved, asset history, service merge, relevant-only injection, keyword search,
tool-quality persistence, asset extraction.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.memory import Memory, extract_asset
from k8smatrixwarden.agents import tool_quality


def _mem():
    return Memory(":memory:")


def test_finding_saved_and_asset_history():
    m = _mem()
    m.save_finding("server01", "weak SSH config", "HIGH", "ssh banner", "fixed")
    h = m.get_asset_history("server01")
    assert h["asset"]["hostname"] == "server01"
    assert h["findings"][0]["finding"] == "weak SSH config"
    assert h["findings"][0]["severity"] == "HIGH"
    assert h["findings"][0]["status"] == "fixed"


def test_services_merge_on_upsert():
    m = _mem()
    m.upsert_asset("server01", services=["ssh"])
    m.upsert_asset("server01", services=["nginx", "postgres"])
    assert set(m.get_asset_history("server01")["services"]) == {"ssh", "nginx", "postgres"}


def test_prelude_injects_relevant_only():
    m = _mem()
    m.upsert_asset("server01", services=["ssh", "nginx"])
    m.save_finding("server01", "weak SSH config", "HIGH", "banner", "fixed")
    m.save_finding("server02", "open dashboard", "CRITICAL", "", "open")
    pre = m.prelude_for("check server01 for privesc")
    assert "server01" in pre and "weak SSH config" in pre
    assert "ssh" in pre and "nginx" in pre
    assert "server02" not in pre  # unrelated asset must not be injected


def test_prelude_empty_when_nothing_relevant():
    assert _mem().prelude_for("scan the cluster") == ""


def test_search_memory_keyword():
    m = _mem()
    m.save_finding("h1", "exposed secret in env", "HIGH", "", "open")
    hits = m.search_memory("any exposed secret?")
    assert any("secret" in f["finding"] for f in hits["findings"])


def test_tool_quality_persists():
    m = _mem()
    q = tool_quality.evaluate("run_scan", {"ports": [22, 80]})
    assert q["quality_score"] < 1.0  # scan result lacks severity/rule_id/resource
    m.save_tool_quality(**{k: q[k] for k in
                           ("tool", "quality_score", "missing_information", "recommended_followup")})
    row = m.db.execute("SELECT * FROM tool_quality").fetchone()
    assert row["tool"] == "run_scan" and row["quality_score"] == q["quality_score"]


def test_tool_quality_error_scores_zero():
    q = tool_quality.evaluate("run_scan", {"error": "boom"})
    assert q["quality_score"] == 0.0


def test_extract_asset():
    assert extract_asset("investigate server01 for privilege escalation") == "server01"
    assert extract_asset("scan 10.0.0.5") == "10.0.0.5"
    assert extract_asset("scan the cluster") is None
