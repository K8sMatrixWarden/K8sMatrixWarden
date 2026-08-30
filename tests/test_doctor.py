"""
`doctor` as a health command (§19) and the read-only safety boundary (§21).

Two things are asserted here that matter more than the rest: an absent OPTIONAL capability
is NOT CONFIGURED and never fails the command, and the read-only invariants are checked by
executing them, not by trusting a comment.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden import doctor as doc
from k8smatrixwarden.bootstrap import build_platform

_LLM_ENV = ("K8SMATRIXWARDEN_LLM_PROVIDER", "K8SMATRIXWARDEN_LLM_MODEL",
            "K8SMATRIXWARDEN_LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")


def _without_llm_env():
    saved = {k: os.environ.pop(k, None) for k in _LLM_ENV}
    return lambda: [os.environ.__setitem__(k, v) for k, v in saved.items()
                    if v is not None]


def _sections(**kw):
    return {s.title: s for s in doc.run_checks(build_platform(), **kw)}


def test_every_section_is_present():
    titles = set(_sections())
    assert {"Shard discovery", "Configuration", "Rules", "Taxonomy", "MCP",
            "Report formats", "Runtime detections", "LLM (optional)",
            "Optional dependencies", "Read-only safety"} <= titles


def test_a_healthy_install_has_no_failures():
    sections = doc.run_checks(build_platform())
    summary = doc.summarize(sections)
    failures = [c for s in sections for c in s.checks if c.status == doc.FAIL]
    assert failures == [], failures
    assert summary["ok"] is True


def test_shards_rules_and_taxonomy_pass():
    sections = _sections()
    assert sections["Shard discovery"].status == doc.PASS
    assert sections["Configuration"].status == doc.PASS
    assert sections["Rules"].status == doc.PASS
    assert sections["Taxonomy"].status == doc.PASS


def test_missing_llm_is_not_configured_and_the_scanner_stays_available():
    restore = _without_llm_env()
    try:
        llm = _sections()["LLM (optional)"]
    finally:
        restore()
    statuses = {c.name: c.status for c in llm.checks}
    assert statuses["provider"] == doc.NOT_CONFIGURED
    assert statuses["scanner functionality"] == doc.PASS
    assert llm.status == doc.NOT_CONFIGURED          # never FAIL
    assert doc.FAIL not in statuses.values()


def test_a_configured_llm_is_reported_without_touching_the_network():
    restore = _without_llm_env()
    os.environ.update({"K8SMATRIXWARDEN_LLM_PROVIDER": "openai",
                       "K8SMATRIXWARDEN_LLM_MODEL": "some-model",
                       "K8SMATRIXWARDEN_LLM_API_KEY": "k"})
    try:
        llm = _sections()["LLM (optional)"]
    finally:
        for k in ("K8SMATRIXWARDEN_LLM_PROVIDER", "K8SMATRIXWARDEN_LLM_MODEL",
                  "K8SMATRIXWARDEN_LLM_API_KEY"):
            os.environ.pop(k, None)
        restore()
    detail = {c.name: c.detail for c in llm.checks}
    assert detail["provider"] == "openai" and detail["model"] == "some-model"
    assert "not probed" in detail["connectivity"]


def test_optional_dependencies_never_fail_the_command():
    deps = _sections()["Optional dependencies"]
    assert all(c.status in (doc.PASS, doc.NOT_CONFIGURED) for c in deps.checks)


def test_every_report_format_renders():
    formats = _sections()["Report formats"]
    text_formats = {c.name: c.status for c in formats.checks}
    for fmt in ("terminal", "text", "markdown", "json", "sarif", "html"):
        assert text_formats[f"format: {fmt}"] == doc.PASS
    # binary formats depend on an optional extra; either state is acceptable, FAIL is not
    for fmt in ("pdf", "xlsx"):
        assert text_formats[f"format: {fmt}"] in (doc.PASS, doc.NOT_CONFIGURED)


def test_readonly_safety_checks_actually_execute():
    safety = _sections()["Read-only safety"]
    statuses = {c.name: c.status for c in safety.checks}
    assert statuses["generated RBAC is read-only"] == doc.PASS
    assert statuses["no mutating MCP tool"] == doc.PASS


def test_generated_rbac_contains_only_read_verbs():
    """The invariant itself, independent of doctor's rendering of it."""
    platform = build_platform()
    for shard, rules in platform.registry.rbac_verbs().items():
        for rule in rules:
            assert set(rule["verbs"]) <= {"get", "list", "watch"}, (shard, rule)
    manifest = platform.loader.deployment_manifest()
    for item in manifest["items"]:
        for rule in item.get("rules", []):
            assert set(rule["verbs"]) <= {"get", "list", "watch"}, item


def test_a_broken_configuration_is_reported_as_a_failure():
    import json
    import tempfile
    path = os.path.join(tempfile.mkdtemp(), "cfg.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"shards": {"not_a_shard": {"enabled": False}}}, fh)
    sections = {s.title: s for s in doc.run_checks(build_platform(path))}
    assert sections["Configuration"].status == doc.FAIL


def test_render_text_is_readable_and_summarize_counts_match():
    sections = doc.run_checks(build_platform())
    text = doc.render_text(sections)
    assert "K8sMatrixWarden, platform health" in text
    assert "Read-only safety" in text
    counts = doc.summarize(sections)["counts"]
    assert counts[doc.PASS] > 0 and counts[doc.FAIL] == 0


def test_doctor_json_output_is_serialisable():
    import json
    payload = doc.summarize(doc.run_checks(build_platform()))
    assert json.loads(json.dumps(payload))["ok"] is True
