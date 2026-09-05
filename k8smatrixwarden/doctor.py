"""
Platform health & consistency checks (§19), the machinery behind `k8smatrixwarden doctor`.

`doctor` used to answer one question (is the taxonomy self-consistent?). It now answers the
question an operator actually has before trusting a scan: *is this installation coherent,
and what is missing?* Every check reports one of four statuses:

    PASS           , verified good
    WARN           , works, but something is off and will bite later
    FAIL           , broken; scans from this install cannot be trusted
    NOT CONFIGURED , an OPTIONAL capability is absent. Never a failure.

The last one matters most for the LLM section: the deterministic scanner has no dependency
on a model being configured, so "no LLM" is a statement of fact, not a fault.

Returns plain data (`run_checks`) so the CLI renders it, tests assert on it, and the MCP
`run_doctor` MCP tool serves the same content without a second implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

PASS, WARN, FAIL, NOT_CONFIGURED = "PASS", "WARN", "FAIL", "NOT CONFIGURED"

#: Verbs that would mean the tool writes to a cluster. Their absence from every generated
#: RBAC rule is the enforceable half of the read-only promise (§21).
_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*",
                "bind", "escalate", "impersonate"}
#: Substrings that would betray a mutating MCP tool. The dedicated test in tests/test_mcp.py
#: is the authority; this check makes the same guarantee visible to an operator.
_MUTATING_TOOL_HINTS = ("apply", "remediate", "delete", "patch", "create_", "write_",
                        "mutate", "fix_", "exec_")

#: Optional extras and what turns on. Absence is reported, never treated as a fault.
_OPTIONAL_DEPS = {
    "kubernetes": "live cluster scanning (--live)",
    "rich": "prettier terminal output",
    "mcp": "the MCP server (`k8smatrixwarden mcp`)",
    "fpdf2": "PDF report export (-o pdf)",
    "openpyxl": "Excel report export",
    "anthropic": "the optional agent path via an Anthropic-hosted model",
    "openai": "the optional agent path via any OpenAI-compatible endpoint",
}
#: import name != distribution name for a couple of these.
_IMPORT_NAME = {"fpdf2": "fpdf", "openpyxl": "openpyxl"}


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    items: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "items": list(self.items)}


@dataclass
class Section:
    title: str
    checks: list = field(default_factory=list)

    @property
    def status(self) -> str:
        """A section is as bad as its worst check."""
        for level in (FAIL, WARN, NOT_CONFIGURED):
            if any(c.status == level for c in self.checks):
                return level
        return PASS

    def as_dict(self) -> dict:
        return {"title": self.title, "status": self.status,
                "checks": [c.as_dict() for c in self.checks]}


def run_checks(platform, *, probe_llm: bool = False) -> list[Section]:
    """Every health check, grouped. Never raises: a check that cannot run reports WARN
    with the reason, because a crashing `doctor` helps nobody."""
    return [
        _shards(platform),
        _configuration(platform),
        _rules(platform),
        _taxonomy(platform),
        _mcp(platform),
        _reporting(platform),
        _runtime(),
        _llm(probe_llm),
        _dependencies(),
        _safety(platform),
    ]


def summarize(sections: list) -> dict:
    counts = {PASS: 0, WARN: 0, FAIL: 0, NOT_CONFIGURED: 0}
    for section in sections:
        for check in section.checks:
            counts[check.status] = counts.get(check.status, 0) + 1
    return {"counts": counts, "ok": counts[FAIL] == 0,
            "sections": [s.as_dict() for s in sections]}


# --------------------------------------------------------------------------- #
def _shards(platform) -> Section:
    names = platform.registry.shard_names()
    status = PASS if names else FAIL
    return Section("Shard discovery", [
        Check("shards discovered", status,
              f"{len(names)} shard(s)" if names else "no shards were discovered",
              sorted(names))])


def _configuration(platform) -> Section:
    problems = list(platform.config_problems)
    # A discovered shard with no config entry still runs (it defaults to enabled), so that
    # is a WARN. A configured shard that does not exist, or a malformed block, is a real
    # inconsistency: the operator believes they changed something that has no effect.
    defaults = [p for p in problems if "has no entry in config" in p]
    real = [p for p in problems if p not in defaults]
    checks = [Check("configuration matches discovered shards",
                    FAIL if real else PASS,
                    f"{len(real)} problem(s)" if real else "no drift", real)]
    if defaults:
        checks.append(Check("shards using default configuration", WARN,
                            f"{len(defaults)} shard(s) have no explicit config entry",
                            defaults))
    return Section("Configuration", checks)


def _rules(platform) -> Section:
    problems = list(platform.rule_problems)
    rules = platform.registry.rules.all()
    disabled = [r.id for r in rules if not r.enabled]
    checks = [
        Check("rule registry loaded", PASS if rules else FAIL,
              f"{len(rules)} rule(s), {len(rules) - len(disabled)} enabled"),
        Check("rule model valid", FAIL if problems else PASS,
              f"{len(problems)} problem(s)" if problems else
              "ids, shards, severities, detection methods, versions and evidence all valid",
              problems),
    ]
    if disabled:
        checks.append(Check("rules disabled by configuration", WARN,
                            f"{len(disabled)} rule(s) will not run", sorted(disabled)))
    return Section("Rules", checks)


def _taxonomy(platform) -> Section:
    problems = list(platform.validation_problems)
    coverage = platform.coverage()
    uncovered = sorted(t for t, n in coverage.items() if n == 0)
    checks = [Check("MITRE mappings and aliases", FAIL if problems else PASS,
                    f"{len(problems)} problem(s)" if problems else
                    "every technique id resolves and every alias targets a real rule",
                    problems)]
    if uncovered:
        checks.append(Check("tactics with no scan rule", WARN,
                            "these tactics can only be covered at runtime", uncovered))
    return Section("Taxonomy", checks)


def _mcp(platform) -> Section:
    checks = []
    try:
        from .mcp.server import build_tools
        tools = build_tools()
        checks.append(Check("MCP tools registered", PASS if tools else FAIL,
                            f"{len(tools)} tool(s)"))
    except Exception as exc:
        return Section("MCP", [Check("MCP tools registered", FAIL,
                                     f"build_tools() failed: {exc}")])
    try:
        import mcp  # noqa: F401
        checks.append(Check("MCP SDK", PASS, "installed, `k8smatrixwarden mcp` can serve"))
    except ImportError:
        checks.append(Check("MCP SDK", NOT_CONFIGURED,
                            'not installed; tools remain callable in-process '
                            '(pip install -e ".[mcp]" to serve them)'))
    return Section("MCP", checks)


def _reporting(platform) -> Section:
    """Render an empty result in every format, so a broken renderer is caught here rather
    than at the end of somebody's scan."""
    from .core.models import ScanRequest, Scope, ScopeLevel, Selector
    from .core.results import ScanResult
    from .core.scoring import RiskScoringEngine

    from .core.models import Severity
    result = ScanResult(request=ScanRequest(scope=Scope(ScopeLevel.CLUSTER),
                                            selector=Selector()),
                        findings=[], risk=RiskScoringEngine().score([]),
                        resolved_rule_ids=[], scan_id="doctor",
                        # Renderers read every severity bucket by name; a real scan always
                        # has all of them (the aggregator fills them in), so a synthetic
                        # result must too.
                        counts={s.label: 0 for s in Severity})
    checks = []
    for fmt in ("terminal", "text", "markdown", "json", "sarif", "html"):
        try:
            platform.reporting.render(result, fmt)
            checks.append(Check(f"format: {fmt}", PASS, "renders"))
        except Exception as exc:
            checks.append(Check(f"format: {fmt}", FAIL, str(exc)))
    for fmt, extra in (("pdf", "pdf"), ("xlsx", "excel")):
        try:
            platform.reporting.render(result, fmt)
            checks.append(Check(f"format: {fmt}", PASS, "renders"))
        except RuntimeError:
            checks.append(Check(f"format: {fmt}", NOT_CONFIGURED,
                                f'optional extra not installed (pip install -e ".[{extra}]")'))
        except Exception as exc:
            checks.append(Check(f"format: {fmt}", FAIL, str(exc)))
    return Section("Report formats", checks)


def _runtime() -> Section:
    try:
        from .agents.runtime import RuntimeAgent
        catalog = RuntimeAgent().catalog()
    except Exception as exc:
        return Section("Runtime detections",
                       [Check("runtime catalog", FAIL, str(exc))])
    sources = sorted({d["source"] for d in catalog})
    return Section("Runtime detections", [
        Check("runtime catalog", PASS if catalog else FAIL,
              f"{len(catalog)} detection(s) across sources: {', '.join(sources)}")])


def _llm(probe: bool) -> Section:
    """The optional agent layer. Absence is NOT CONFIGURED, never FAIL, the deterministic
    scanner does not use it."""
    try:
        from .agents.llm_orchestrator import load_agent_config
        from .agents.llm_provider import status
        info = status(load_agent_config(), probe=probe)
    except Exception as exc:
        return Section("LLM (optional)",
                       [Check("configuration", WARN, f"could not resolve: {exc}")])
    if info["status"] == "NOT CONFIGURED":
        return Section("LLM (optional)", [
            Check("provider", NOT_CONFIGURED,
                  "no provider configured; set K8SMATRIXWARDEN_LLM_PROVIDER/_MODEL or the "
                  "'llm' block of config/agent.json"),
            Check("scanner functionality", PASS,
                  "AVAILABLE, the deterministic scanner does not require an LLM")])
    # How the provider was chosen matters as much as which one: an operator with two API
    # keys set needs to see that the choice was theirs (explicit/environment/config) and
    # not a coin toss.
    detected = info.get("autodetect_candidates") or []
    ambiguous = info["status"] == "AMBIGUOUS"
    # An ambiguity is a configuration the operator has to settle, not a broken tool: the
    # agent path declines until they do, and the scanner is untouched either way. So it
    # WARNs. FAIL is reserved for a configuration that is actually wrong (unknown provider,
    # no model), which would fail whatever the operator intended.
    checks = [
        Check("provider",
              WARN if ambiguous else (FAIL if info["status"] == "INVALID" else PASS),
              f"{info['provider'] or '?'} (source: {info.get('provider_source', '?')})"),
        Check("model", PASS if info["model"] else FAIL, info["model"] or "not set"),
        Check("selection", WARN if ambiguous else PASS,
              (f"ambiguous: credentials present for {', '.join(detected)}; the agent path "
               f"declines until one is named with K8SMATRIXWARDEN_LLM_PROVIDER")
              if ambiguous
              else (f"deterministic; auto-detect candidates: "
                    f"{', '.join(detected) or 'none'}")),
        Check("configuration",
              PASS if not info["problems"] else (WARN if ambiguous else FAIL),
              "; ".join(info["problems"]) or "valid", info["problems"]),
        Check("connectivity",
              PASS if info["connectivity"] == "available"
              else (WARN if info["connectivity"].startswith("unavailable") else NOT_CONFIGURED),
              info["connectivity"] + ("" if probe else " (pass --probe to test)")),
        Check("scanner functionality", PASS,
              "AVAILABLE, unaffected by LLM status"),
    ]
    return Section("LLM (optional)", checks)


def _dependencies() -> Section:
    import importlib
    checks = []
    for dist, purpose in _OPTIONAL_DEPS.items():
        module = _IMPORT_NAME.get(dist, dist)
        try:
            importlib.import_module(module)
            checks.append(Check(dist, PASS, purpose))
        except Exception:
            checks.append(Check(dist, NOT_CONFIGURED, f"not installed, {purpose}"))
    return Section("Optional dependencies", checks)


def _safety(platform) -> Section:
    """The read-only invariants (§21), asserted, not asserted-about-in-a-comment."""
    checks = []
    offending = []
    for shard_name, rules in platform.registry.rbac_verbs().items():
        for rule in rules:
            bad = sorted(set(rule.get("verbs", [])) & _WRITE_VERBS)
            if bad:
                offending.append(f"{shard_name}: {', '.join(bad)} on "
                                 f"{', '.join(rule.get('resources', []))}")
    checks.append(Check("generated RBAC is read-only", FAIL if offending else PASS,
                        "every generated verb is get/list/watch" if not offending
                        else f"{len(offending)} rule(s) request write verbs", offending))
    try:
        from .mcp.server import build_tools
        names = list(build_tools().keys())
        suspicious = sorted(n for n in names
                            if any(h in n.lower() for h in _MUTATING_TOOL_HINTS))
        checks.append(Check("no mutating MCP tool", FAIL if suspicious else PASS,
                            "no tool name implies a write" if not suspicious
                            else "tool names imply mutation", suspicious))
    except Exception as exc:
        checks.append(Check("no mutating MCP tool", WARN, f"could not check: {exc}"))
    return Section("Read-only safety", checks)


# --------------------------------------------------------------------------- #
_EMOJI = {PASS: "✅", WARN: "⚠️ ", FAIL: "❌", NOT_CONFIGURED: "➖"}


def render_text(sections: list, *, verbose: bool = False) -> str:
    lines = ["═" * 74, "  K8sMatrixWarden, platform health", "═" * 74]
    for section in sections:
        lines.append(f"\n{section.title}")
        lines.append("-" * len(section.title))
        for check in section.checks:
            lines.append(f"  {_EMOJI.get(check.status, '?')} {check.status:<14} "
                         f"{check.name}"
                         + (f", {check.detail}" if check.detail else ""))
            if check.items and (verbose or check.status in (FAIL, WARN)):
                for item in check.items[:20]:
                    lines.append(f"        · {item}")
                if len(check.items) > 20:
                    lines.append(f"        · … (+{len(check.items) - 20} more)")
    summary = summarize(sections)["counts"]
    lines += ["", "═" * 74,
              f"  {summary[PASS]} pass · {summary[WARN]} warn · {summary[FAIL]} fail · "
              f"{summary[NOT_CONFIGURED]} not configured",
              "═" * 74]
    return "\n".join(lines)
