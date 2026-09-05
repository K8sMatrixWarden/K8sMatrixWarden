"""
Rule lifecycle (§12/§13), SARIF structure (§15), federation categories (§18) and
documentation/code drift (§20).

The drift tests are the important ones: they read the repository's real numbers and compare
them with what the README claims, so a count can never silently rot again.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform, validate_rules
from k8smatrixwarden.mcp.server import build_tools

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# Rule identity, versioning and metadata.
# --------------------------------------------------------------------------- #
def test_every_rule_passes_validation():
    assert validate_rules(build_platform().registry) == []


def test_rule_ids_are_unique_and_stable_shaped():
    rules = build_platform().registry.rules.all()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for rid in ids:
        assert re.fullmatch(r"[a-z0-9]+([.\-][a-z0-9]+)*", rid), rid


def test_duplicate_rule_ids_are_rejected_at_registration():
    from k8smatrixwarden.core.registry import DuplicateRuleError, RuleRegistry
    platform = build_platform()
    rule = platform.registry.rules.all()[0]
    registry = RuleRegistry()
    registry.register(rule)
    try:
        registry.register(rule)
        assert False, "expected DuplicateRuleError"
    except DuplicateRuleError:
        pass


def test_every_rule_declares_a_version_and_a_confidence():
    for rule in build_platform().registry.rules.all():
        assert isinstance(rule.version, int) and rule.version >= 1, rule.id
        assert rule.confidence in ("high", "medium", "low"), rule.id


def test_rule_metadata_is_machine_readable_and_complete():
    meta = build_platform().registry.rules.all()[0].metadata()
    for key in ("id", "version", "owning_shard", "severity", "detection_method",
                "surface", "mitre", "evidence_needs", "confidence", "references",
                "requires_node_access", "requires_runtime", "false_positive_notes"):
        assert key in meta, key
    json.dumps(meta)                       # must survive serialisation unchanged


def test_get_rule_tool_returns_the_same_metadata():
    platform = build_platform()
    rid = platform.registry.rules.all()[0].id
    assert build_tools()["get_rule"](rid) == platform.registry.rules.get(rid).metadata()


def test_every_rule_belongs_to_a_discovered_shard_with_a_valid_severity():
    platform = build_platform()
    shards = set(platform.registry.shard_names())
    for rule in platform.registry.rules.all():
        assert rule.owning_shard in shards
        assert rule.severity.label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert rule.evidence_needs


# --------------------------------------------------------------------------- #
# SARIF.
# --------------------------------------------------------------------------- #
def _sarif():
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.core.models import (ScanMode, ScanRequest, Scope, ScopeLevel,
                                             Selector)
    platform = build_platform()
    result = ScannerAgent(platform).scan(
        ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                    mode=ScanMode.SYNC), platform.make_collector(mock=True))
    return json.loads(platform.reporting.render(result, "sarif")), result


def test_sarif_document_has_the_required_2_1_structure():
    doc, _ = _sarif()
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith(".json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] and driver["rules"]
    for rule in driver["rules"]:
        assert rule["id"] and rule["shortDescription"]["text"]
        assert rule["help"]["markdown"] and rule["properties"]["tags"]
        assert 0.0 <= float(rule["properties"]["security-severity"]) <= 10.0


def test_sarif_results_reference_declared_rules_and_carry_a_location():
    doc, _ = _sarif()
    run = doc["runs"][0]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert run["results"], "the mock cluster must produce SARIF results"
    for res in run["results"]:
        assert res["ruleId"] in declared
        assert res["level"] in ("error", "warning", "note", "none")
        assert res["message"]["text"]
        # Kubernetes resources are not files, so SARIF `logicalLocations` (not
        # physicalLocation/artifactLocation) is the correct location kind for them.
        location = res["locations"][0]["logicalLocations"][0]
        assert location["name"] and location["fullyQualifiedName"]
        assert res["partialFingerprints"]


def test_sarif_covers_every_finding_and_is_deterministic():
    doc, result = _sarif()
    scoreable = [f for f in result.findings if f.severity.weight > 0]
    assert len(doc["runs"][0]["results"]) == len(scoreable)
    again, _ = _sarif()
    assert ([r["ruleId"] for r in doc["runs"][0]["results"]]
            == [r["ruleId"] for r in again["runs"][0]["results"]])


def test_sarif_carries_framework_mappings():
    doc, _ = _sarif()
    tags = {t for r in doc["runs"][0]["tool"]["driver"]["rules"]
            for t in r["properties"]["tags"]}
    assert any(t.startswith("mitre/") for t in tags)
    assert any(t.startswith("cis/") or t.startswith("owasp/") for t in tags)


# --------------------------------------------------------------------------- #
# Federation.
# --------------------------------------------------------------------------- #
def _cluster_result(cluster, findings, runtime=None):
    from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector
    from k8smatrixwarden.core.results import ScanResult
    from k8smatrixwarden.core.scoring import RiskScoringEngine
    risk = RiskScoringEngine().score(findings)
    return ScanResult(request=ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                                          selector=Selector()),
                      findings=findings, risk=risk, resolved_rule_ids=[],
                      counts={}, cluster_name=cluster, scan_id=f"s-{cluster}",
                      runtime=runtime)


def _identity(kind, name, rule_id="rbac-wildcard-verbs"):
    from k8smatrixwarden.core.models import (DetectionMethod, Finding, MitreTag,
                                             ResourceRef, Severity, Tactic)
    return Finding(rule_id=rule_id, title="t", severity=Severity.CRITICAL,
                   resource=ResourceRef(kind, name), message="m",
                   owning_shard="rbac_identity",
                   mitre=[MitreTag(Tactic.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts")],
                   detection_method=DetectionMethod.RBAC)


def test_shared_custom_identity_is_a_candidate_with_a_relationship():
    from k8smatrixwarden.core.federation import build_federation
    rep = build_federation([
        _cluster_result("prod", [_identity("ClusterRole", "deploy-bot")]),
        _cluster_result("staging", [_identity("ClusterRole", "deploy-bot")])])
    assert len(rep.shared_identities) == 1
    shared = rep.shared_identities[0]
    assert shared.status == "candidate"
    assert shared.relationship == "shared-identity"
    assert "confirm they are the same trust principal" in shared.verification


def test_shared_configmap_is_classified_as_a_shared_resource():
    from k8smatrixwarden.core.federation import build_federation
    rep = build_federation([
        _cluster_result("prod", [_identity("ConfigMap", "app-settings")]),
        _cluster_result("staging", [_identity("ConfigMap", "app-settings")])])
    assert rep.shared_identities[0].relationship == "shared-resource"


def test_builtin_identities_never_create_a_cross_cluster_path():
    from k8smatrixwarden.core.federation import build_federation
    for name in ("cluster-admin", "default", "system:node", "kube-root-ca.crt"):
        rep = build_federation([
            _cluster_result("prod", [_identity("ClusterRole", name)]),
            _cluster_result("staging", [_identity("ClusterRole", name)])])
        assert rep.shared_identities == [], name
        assert "independent blast radii" in rep.summary


def test_an_identity_in_one_cluster_only_is_not_shared():
    from k8smatrixwarden.core.federation import build_federation
    rep = build_federation([
        _cluster_result("prod", [_identity("ClusterRole", "only-here")]),
        _cluster_result("staging", [_identity("ClusterRole", "different")])])
    assert rep.shared_identities == []


def test_runtime_evidence_in_two_clusters_confirms_a_shared_identity():
    from k8smatrixwarden.core.federation import build_federation

    def rt(name):
        return {"correlation": {"correlations": [
            {"confidence": "confirmed", "resource": name, "tactic": "Privilege Escalation",
             "namespace": "default"}]}, "drift": {"drift": []}}

    rep = build_federation([
        _cluster_result("prod", [_identity("ServiceAccount", "deploy-bot")],
                        runtime=rt("deploy-bot")),
        _cluster_result("staging", [_identity("ServiceAccount", "deploy-bot")],
                        runtime=rt("deploy-bot"))])
    shared = rep.shared_identities[0]
    assert shared.status == "confirmed"
    assert "runtime evidence" in shared.verification


def test_a_single_cluster_is_reported_as_such():
    from k8smatrixwarden.core.federation import build_federation
    rep = build_federation([_cluster_result("prod", [_identity("ClusterRole", "x")])])
    assert rep.shared_identities == []
    assert "add more clusters" in rep.summary


# --------------------------------------------------------------------------- #
# Documentation / code drift.
# --------------------------------------------------------------------------- #
def _readme() -> str:
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


def _badge(label: str, text: str):
    """Read a shields.io badge value out of the README, e.g. rules-60-orange -> '60'."""
    m = re.search(rf"badge/{label}-([0-9]+)", text)
    return m.group(1) if m else None


def test_readme_rule_and_shard_counts_match_the_registry():
    platform = build_platform()
    text = _readme()
    assert _badge("rules", text) == str(platform.rule_count())
    assert f"{len(platform.registry.shard_names())} domain shards" in text


def test_readme_mcp_tool_count_matches_the_server():
    text = _readme()
    count = len(build_tools())
    assert _badge("MCP%20tools", text) == str(count)
    assert f"**{count} MCP tools**" in text


def test_readme_test_count_matches_the_suite():
    """Counts the test functions the bundled runner would collect, the same number the
    README badge claims."""
    import importlib
    here = os.path.join(ROOT, "tests")
    total = 0
    for fname in sorted(os.listdir(here)):
        if not (fname.startswith("test_") and fname.endswith(".py")):
            continue
        mod = importlib.import_module(f"tests.{fname[:-3]}")
        total += sum(1 for n in dir(mod)
                     if n.startswith("test_") and callable(getattr(mod, n)))
    assert _badge("tests", _readme()) == str(total), (
        f"README claims {_badge('tests', _readme())} tests, the suite has {total}")


def test_readme_lists_every_shard_by_name():
    text = _readme()
    for shard in build_platform().registry.shard_names():
        assert shard in text, f"{shard} is not documented in the README"


def test_readme_report_formats_match_the_engine():
    from k8smatrixwarden.mcp.server import _VALID_REPORT_FORMATS
    text = _readme()
    for fmt in _VALID_REPORT_FORMATS:
        assert fmt in text, f"report format {fmt} is undocumented"


def test_readme_documents_every_cli_subcommand():
    from k8smatrixwarden.cli.main import build_parser
    text = _readme()
    sub = next(a for a in build_parser()._actions if hasattr(a, "choices") and a.choices
               and "scan" in a.choices)
    for name in sub.choices:
        assert re.search(rf"\b{name}\b", text), f"CLI command '{name}' is undocumented"


# --------------------------------------------------------------------------- #
# Drift detection, extended: the HTML manual and the LLM configuration surface.
#
# These read the repository and derive the expected values. Nothing here asserts on
# formatting or wording, only that every thing the code exposes is documented somewhere.
# --------------------------------------------------------------------------- #
def _html_doc() -> str:
    with open(os.path.join(ROOT, "K8sMatrixWarden-doc.html"), encoding="utf-8") as fh:
        return fh.read()


def test_html_doc_mcp_tool_count_matches_the_server():
    count = len(build_tools())
    text = _html_doc()
    assert f"{count} tools" in text, f"HTML doc does not state the real tool count ({count})"
    assert "36 tools" not in text, "HTML doc still claims a stale tool count"


def _getting_started() -> str:
    with open(os.path.join(ROOT, "GETTING-STARTED.md"), encoding="utf-8") as fh:
        return fh.read()


def test_getting_started_never_names_a_tool_that_does_not_exist():
    """The gap this closes. The onboarding guide had no drift gate at all, so when
    `validate_platform` and `resolve_selector` were removed as duplicates it kept listing
    them, and a reader following it would call tools the server does not have. A stale
    count is a nuisance; a named tool that is gone is a broken instruction.

    Identifiers are matched on the verb prefixes the real tools use, so a field name like
    `response_status` is not mistaken for a tool that vanished."""
    import re as _re
    registered = set(build_tools())
    prefixes = tuple(sorted({name.split("_", 1)[0] + "_" for name in registered}))
    mentioned = {m for m in _re.findall(r"`([a-z][a-z0-9_]{4,})`", _getting_started())
                 if m.startswith(prefixes)}
    ghosts = sorted(mentioned - registered)
    assert ghosts == [], f"GETTING-STARTED.md names tools that do not exist: {ghosts}"


def test_getting_started_tool_count_matches_the_server():
    count = len(build_tools())
    text = _getting_started()
    assert f"{count} tools" in text, \
        f"GETTING-STARTED.md does not state the real tool count ({count})"
    stale = re.findall(r"\b(\d{2}) tools\b", text)
    assert set(stale) <= {str(count)}, \
        f"GETTING-STARTED.md still claims stale tool counts: {sorted(set(stale))}"


def test_getting_started_documents_every_cli_subcommand():
    from k8smatrixwarden.cli.main import build_parser
    text = _getting_started()
    sub = next(a for a in build_parser()._actions if hasattr(a, "choices") and a.choices
               and "scan" in a.choices)
    missing = [n for n in sub.choices if not re.search(rf"\b{n}\b", text)]
    assert missing == [], f"CLI commands missing from GETTING-STARTED.md: {missing}"


def test_html_doc_names_every_mcp_tool():
    text = _html_doc()
    missing = [name for name in build_tools() if f"<code>{name}</code>" not in text]
    assert missing == [], f"MCP tools missing from the HTML manual: {missing}"


def test_html_doc_documents_every_cli_subcommand():
    from k8smatrixwarden.cli.main import build_parser
    text = _html_doc()
    sub = next(a for a in build_parser()._actions if hasattr(a, "choices") and a.choices
               and "scan" in a.choices)
    missing = [n for n in sub.choices if f"<code>{n}</code>" not in text]
    assert missing == [], f"CLI commands missing from the HTML manual: {missing}"


def test_both_docs_document_every_llm_provider_key():
    from k8smatrixwarden.agents.llm_provider import _PROVIDERS
    readme, html = _readme(), _html_doc()
    for provider in _PROVIDERS:
        assert provider in readme, f"provider '{provider}' is undocumented in the README"
        assert provider in html, f"provider '{provider}' is undocumented in the HTML manual"


def test_both_docs_document_every_llm_environment_variable():
    """The env vars the resolver actually reads, discovered from the source rather than
    from a hand-kept list, so a new one cannot ship undocumented."""
    import re as _re
    src = os.path.join(ROOT, "k8smatrixwarden", "agents", "llm_provider.py")
    with open(src, encoding="utf-8") as fh:
        code = fh.read()
    suffixes = set(_re.findall(r'_env\("([A-Z_]+)"\)', code))
    variables = {f"K8SMATRIXWARDEN_LLM_{s}" for s in suffixes}
    # The conventional per-provider credentials the auto-detector looks at.
    variables |= set(_re.findall(r'os\.environ\.get\("([A-Z_]+)"\)', code))
    readme, html = _readme(), _html_doc()
    for var in sorted(variables):
        assert var in readme or var in html, f"{var} is documented nowhere"


def test_html_doc_covers_the_second_pass_analysis_sections():
    """Every analysis surface a user can reach needs a section they can find."""
    text = _html_doc()
    for anchor in ("evidence-coverage", "rbac-graph", "netpol", "attack-layers",
                   "posture-history", "llm"):
        assert f'id="{anchor}"' in text, f"HTML manual has no #{anchor} section"
        assert f'href="#{anchor}"' in text, f"#{anchor} is not linked from the sidebar"


def test_the_report_format_list_is_the_same_everywhere():
    """One list of formats, three consumers (engine, MCP validation, docs). They drift the
    moment one is edited alone."""
    from k8smatrixwarden.core.reporting import ReportingEngine
    from k8smatrixwarden.mcp.server import _VALID_REPORT_FORMATS
    engine = ReportingEngine()
    for fmt in _VALID_REPORT_FORMATS:
        assert hasattr(engine, fmt) or fmt == "terminal", \
            f"MCP advertises format '{fmt}' the engine cannot render"


def test_html_doc_headline_stats_match_the_repository():
    """The manual's Testing & Quality stat row is a claim about this repository. Derive
    both numbers and fail if either has drifted."""
    import importlib
    import re as _re
    here = os.path.join(ROOT, "tests")
    total = 0
    for fname in sorted(os.listdir(here)):
        if fname.startswith("test_") and fname.endswith(".py"):
            mod = importlib.import_module(f"tests.{fname[:-3]}")
            total += sum(1 for n in dir(mod)
                         if n.startswith("test_") and callable(getattr(mod, n)))
    text = _html_doc()
    claimed = _re.search(r'stat-n">(\d+)</div><div class="stat-l">tests passing', text)
    assert claimed and int(claimed.group(1)) == total, (
        f"HTML manual claims {claimed.group(1) if claimed else '?'} tests, "
        f"the suite has {total}")
    shards = len(build_platform().registry.shard_names())
    assert f'stat-n">{shards}/{shards}</div><div class="stat-l">shards loaded clean' in text
