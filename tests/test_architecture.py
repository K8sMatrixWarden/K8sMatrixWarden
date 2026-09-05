"""
The architectural invariant (§2): every entry point resolves through the SAME path.

    Selector -> mapping_engine.resolve() -> rule_id list

CLI, chat/orchestrator, MCP and the web API each build a `Selector` their own way (argparse
flags, natural language, tool arguments, JSON body) and then hand it to one resolver. If any
of them ever grows its own rule-picking logic, an equivalent request would start selecting a
different rule set depending on where it was typed. These tests fail loudly if that happens.

Also pins determinism: resolution order is stable within a process and across fresh
platform builds, so two identical scans are genuinely comparable (which is what the posture
diff in §16 depends on).
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.orchestrator import Orchestrator
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.cli.main import _build_scope, _build_selector
from k8smatrixwarden.core.models import ScopeLevel, Selector
from k8smatrixwarden.mcp.server import build_tools
from k8smatrixwarden.web.app import WebApp


def _cli_args(**over):
    """An argparse-shaped namespace with every selector/scope flag defaulted."""
    base = dict(tactic=[], technique=[], module=[], rule_ids=[], alias=[], framework=[],
                severity_min=None, namespace=None, pod=None, workload=None, node=None,
                image=None, helm_release=None)
    base.update(over)
    return SimpleNamespace(**base)


def test_all_entry_points_resolve_the_same_rule_set():
    """One logical request ('the RBAC module'), four entry points, identical rule ids IN
    IDENTICAL ORDER."""
    platform = build_platform()
    app = WebApp(platform)
    tools = build_tools()

    cli = platform.mapping.resolve(_build_selector(_cli_args(module=["rbac_identity"])))
    web = platform.mapping.resolve(app._selector_from({"modules": ["rbac_identity"]}))
    mcp = tools["preview_scan"](modules=["rbac_identity"])["resolved_rule_ids"]
    chat = platform.mapping.resolve(
        Orchestrator(platform).interpret("scan rbac").request.selector)

    assert cli == web == mcp == chat, {
        "cli": cli, "web": web, "mcp": mcp, "chat": chat}
    assert cli, "the rbac_identity module must resolve to at least one rule"


def test_entry_points_agree_on_a_tactic_selector():
    platform = build_platform()
    app = WebApp(platform)
    tools = build_tools()
    tactic = "Privilege Escalation"

    cli = platform.mapping.resolve(_build_selector(_cli_args(tactic=[tactic])))
    web = platform.mapping.resolve(app._selector_from({"tactics": [tactic]}))
    mcp = tools["preview_scan"](tactics=[tactic])["resolved_rule_ids"]
    assert cli == web == mcp and cli


def test_entry_points_agree_on_an_alias_selector():
    platform = build_platform()
    tools = build_tools()
    cli = platform.mapping.resolve(_build_selector(_cli_args(alias=["Container Escape"])))
    mcp = tools["preview_scan"](aliases=["Container Escape"])["resolved_rule_ids"]
    assert cli == mcp and cli


def test_natural_language_and_explicit_flags_agree():
    """The chat/NL path is a Selector BUILDER, never a second resolver: what it produces
    must resolve exactly like the equivalent explicit flags."""
    platform = build_platform()
    interp = Orchestrator(platform).interpret("scan the cluster for privilege escalation")
    assert interp.request.selector.tactics == ["Privilege Escalation"]
    assert interp.resolved_rule_ids == platform.mapping.resolve(
        _build_selector(_cli_args(tactic=["Privilege Escalation"])))


def test_scope_is_built_identically_by_cli_and_web():
    platform = build_platform()
    app = WebApp(platform)
    cli_scope = _build_scope(_cli_args(namespace="production"))
    web_scope = app._scope_from({"scope_level": "namespace", "namespace": "production"})
    assert cli_scope.level == web_scope.level == ScopeLevel.NAMESPACE
    assert cli_scope.namespace == web_scope.namespace == "production"
    assert cli_scope.describe() == web_scope.describe()


def test_resolution_is_deterministic_within_a_platform():
    platform = build_platform()
    selector = Selector(modules=["workload_pod_security"], tactics=["Persistence"])
    runs = [platform.mapping.resolve(selector) for _ in range(5)]
    assert all(r == runs[0] for r in runs)


def test_resolution_is_deterministic_across_platform_builds():
    """Shard discovery walks the filesystem; if its order leaked into rule order, two
    processes could scan the same request in a different order."""
    a = build_platform().mapping.resolve(Selector())
    b = build_platform().mapping.resolve(Selector())
    assert a == b
    assert len(a) == len(set(a)), "resolve() must not return duplicates"


def test_empty_selector_resolves_to_every_enabled_rule():
    platform = build_platform()
    assert (platform.mapping.resolve(Selector())
            == [r.id for r in platform.registry.rules.enabled()])


def test_a_selector_matching_nothing_raises_rather_than_scanning_everything():
    """A silent empty scan would report a clean cluster it never looked at."""
    from k8smatrixwarden.core.mapping_engine import SelectorResolutionError
    platform = build_platform()
    try:
        platform.mapping.resolve(Selector(modules=["no_such_shard"]))
        assert False, "expected SelectorResolutionError"
    except SelectorResolutionError:
        pass


def test_identical_scans_produce_identical_findings():
    """Determinism end to end, the precondition for the posture diff meaning anything."""
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.core.models import ScanMode, ScanRequest, Scope

    platform = build_platform()
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                          mode=ScanMode.SYNC)
    runs = [ScannerAgent(platform).scan(request, platform.make_collector(mock=True))
            for _ in range(2)]
    keys = [sorted((f.rule_id, str(f.resource)) for f in r.findings) for r in runs]
    assert keys[0] == keys[1]
    assert runs[0].risk.cluster_risk == runs[1].risk.cluster_risk
