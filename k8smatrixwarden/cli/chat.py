"""
Interactive Chat interface (§3.1, §4, §7.4).

A conversational REPL over the Orchestrator. It goes well beyond fixed prompts:

  * understands varied phrasing / synonyms / typos (via the Orchestrator's synonym engine
    plus fuzzy 'did you mean' fallback);
  * has SESSION MEMORY, after a scan you can ask follow-ups ("show criticals",
    "details <rule>", "export markdown");
  * answers informational questions ("what can you do", "list tactics", "explain
    persistence", "what is workload_pod_security");
  * is namespace-aware ("scan production" targets that namespace);
  * handles greetings / thanks / unknown input gracefully.

Per-turn logic lives in `handle_turn()` so it is unit-testable without a live TTY.
"""
from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..agents.orchestrator import Orchestrator
from ..bootstrap import Platform
from ..core.models import ScanMode, Scope, ScopeLevel, Severity

BANNER = r"""
  🛡️  k8smatrixwarden chat, MITRE ATT&CK-aligned Kubernetes security assistant

  Just ask in plain English. For example:
    • scan production for persistence          • any leaked secrets?
    • is my cluster secure?                    • check RBAC and permissions
    • scan only container escape               • run the CIS benchmark
    • show me the critical findings            • details <rule-id>
    • what tactics can you scan for?           • explain lateral movement

  Type 'help' for commands, 'exit' to quit.
"""

HELP = """  Commands & things you can say:

  SCAN
    scan <namespace|pod|image> for <tactic/technique>   run a targeted scan
    is my cluster secure? / scan everything             full-cluster scan
    scan only <container escape|exposed secrets|…>      scan a specific outcome
    run the cis benchmark                               full CIS Kubernetes Benchmark
    map the attack surface                              attack-surface overview

  AFTER A SCAN (follow-ups)
    show criticals / show high / show medium            filter the last results
    summary                                             re-show the last summary
    details <rule-id>                                   deep-dive one finding
    export markdown|json|html|sarif                     save the last report to a file

  LEARN
    what can you do?          list tactics          list modules       list techniques
    explain <tactic>          what is <rule-id / domain>

  coverage · rules [module] · help · exit
"""

TACTIC_DESC = {
    "Initial Access": "How an attacker first gets into the cluster, exposed services, "
                      "compromised images, a stolen kubeconfig, cloud credentials.",
    "Execution": "Running malicious code inside a container, exec-ing in, RCE via an app, "
                 "SSH servers, injected sidecars.",
    "Persistence": "Keeping a foothold across restarts, backdoor containers, CronJobs, "
                   "malicious admission webhooks, writable hostPath mounts.",
    "Privilege Escalation": "Gaining higher privileges, privileged containers, "
                            "cluster-admin bindings, hostPath, container escape to the host.",
    "Defense Evasion": "Avoiding detection, clearing container logs, deleting K8s events, "
                       "impersonating system component names, proxying.",
    "Credential Access": "Stealing secrets and tokens, listing K8s Secrets, service-account "
                         "tokens, mounted cloud credentials, the metadata API.",
    "Discovery": "Mapping the cluster, the API server, kubelet, network scanning, the "
                 "dashboard, the instance metadata API.",
    "Lateral Movement": "Moving between pods / namespaces / cloud, flat networks, reused "
                        "service accounts, CoreDNS poisoning, cloud IAM.",
    "Impact": "Doing damage, data destruction, resource hijacking (cryptomining), denial "
              "of service.",
}


@dataclass
class TurnResult:
    output: str
    quit: bool = False
    needs_confirmation: bool = False
    pending: Optional[object] = None


_AFFIRM = {"y", "yes", "yeah", "yep", "ok", "okay", "sure", "go", "proceed", "do it",
           "run it", "confirm", "yup", "please do"}
_NEGATE = {"n", "no", "nope", "cancel", "stop", "abort", "nah", "don't", "dont"}


class ChatSession:
    """Holds conversation state so confirmations and follow-ups work across turns."""

    def __init__(self, platform: Platform, *, mock: bool = True,
                 fixture: Optional[str] = None, kubeconfig: Optional[str] = None,
                 context: Optional[str] = None):
        self.platform = platform
        self.orch = Orchestrator(platform)
        self.mock = mock
        self.fixture = fixture
        self.kubeconfig = kubeconfig
        self.context = context
        self.mode_label = "mock" if mock else "live"
        self._pending = None            # Interpretation awaiting confirmation
        self.last_result = None         # ScanResult of the most recent scan
        self._ns_cache = None           # cached namespace names

    # ------------------------------------------------------------------ #
    def _collector(self):
        return self.platform.make_collector(mock=self.mock, fixture=self.fixture,
                                            kubeconfig=self.kubeconfig,
                                            context=self.context)

    # ================================================================== #
    # Turn dispatch
    # ================================================================== #
    def handle_turn(self, text: str) -> TurnResult:
        raw = text.strip()
        low = raw.lower()

        # 1) resolve a pending confirmation
        if self._pending is not None:
            return self._resolve_pending(raw, low)

        if not raw:
            return TurnResult("")

        # 2) meta / conversational
        if low in ("exit", "quit", ":q", "q", "bye"):
            return TurnResult("Bye, stay secure. 🛡️", quit=True)
        if low in ("help", "?", "commands", "/help"):
            return TurnResult(HELP)
        if _any(low, r"what can you do|capabilities|what do you do|who are you|"
                     r"what are you"):
            return TurnResult(self._capabilities())
        if _any(low, r"^(hi|hello|hey|yo|hiya|greetings)\b"):
            return TurnResult("Hi! Ask me to scan your cluster, or type 'help'. "
                              "Try: “is my cluster secure?”")
        if _any(low, r"\b(thanks|thank you|cheers|ty|appreciate)\b"):
            return TurnResult("You're welcome! 🛡️ Anything else to scan?")

        # 3) list / learn
        if _any(low, r"list tactics|what tactics|which tactics|show tactics"):
            return TurnResult(self._list_tactics())
        if _any(low, r"list (modules|domains|shards|scanners)|what (modules|domains|"
                     r"scanners)|which (modules|domains)"):
            return TurnResult(self._list_modules())
        if _any(low, r"list (techniques|aliases|outcomes)|what can i scan for|"
                     r"what techniques"):
            return TurnResult(self._list_aliases())
        m = re.match(r"(?:explain|what is|what's|whats|describe|tell me about)\s+(.+)", low)
        if m:
            return TurnResult(self._explain(m.group(1).strip(" ?")))

        if low in ("coverage", "mitre", "show coverage", "show mitre coverage",
                   "mitre coverage"):
            return TurnResult(self._coverage())
        if low == "rules" or low.startswith("rules "):
            parts = raw.split(maxsplit=1)
            return TurnResult(self._rules(parts[1] if len(parts) > 1 else None))

        # 4) follow-ups on the last scan
        fu = self._followup(raw, low)
        if fu is not None:
            return TurnResult(fu)

        # 5) natural-language scan / audit
        #    Multi-step requests go to the optional LLM orchestrator when a key is set;
        #    it chains the same tools MCP exposes. Regex interpretation is the fallback.
        agentic = self._maybe_agentic(raw)
        if agentic is not None:
            return TurnResult(agentic)
        return self._interpret_and_scan(raw, low)

    # ------------------------------------------------------------------ #
    def _maybe_agentic(self, raw: str) -> Optional[str]:
        """LLM-driven tool chaining for likely multi-step requests. Returns None (so the
        caller falls back to the regex interpreter) when no key is set, the request looks
        single-step, or the LLM path is unavailable/fails."""
        if not os.getenv("ANTHROPIC_API_KEY"):
            return None
        from ..agents.llm_orchestrator import LLMUnavailable, _looks_multi_step, investigate
        if not _looks_multi_step(raw):
            return None
        try:
            return investigate(raw, self.platform)
        except LLMUnavailable:
            return None

    # ------------------------------------------------------------------ #
    def _resolve_pending(self, raw: str, low: str) -> TurnResult:
        interp = self._pending
        if low in _AFFIRM or _any(low, r"^(y|yes|yeah|yep|sure|ok|okay|go|proceed|do it|"
                                       r"run it|confirm)\b"):
            self._pending = None
            return TurnResult(self._run(interp))
        if low in _NEGATE or _any(low, r"^(n|no|nope|cancel|stop|abort|nah)\b"):
            self._pending = None
            return TurnResult("Cancelled. What next?")
        # Neither yes nor no → treat as a brand-new request (don't get stuck).
        self._pending = None
        result = self.handle_turn(raw)
        result.output = "(cancelled the previous prompt)\n" + result.output
        return result

    # ------------------------------------------------------------------ #
    def _interpret_and_scan(self, raw: str, low: str) -> TurnResult:
        interp = self.orch.interpret(raw)
        self._apply_namespace_scope(interp, low)

        bad_ns = self._unknown_namespace(interp)
        if bad_ns:
            return TurnResult(bad_ns)

        if "cis" in low or "benchmark" in low or interp.intent == "audit":
            summary = self.orch.confirmation_summary(interp)
            return TurnResult(summary + "\n\n" + self._run_cis())

        # An empty selector resolves to ALL rules (a full scan). Only do that when the user
        # clearly asked to scan everything / a whole scope, otherwise a garbage target
        # ("scan the frobnicator") would silently become a full cluster scan.
        if (interp.request.selector.is_empty()
                and interp.request.scope.level == ScopeLevel.CLUSTER
                and not _full_scan_ok(low)):
            return TurnResult(self._fallback(raw, low))

        if not interp.resolved_rule_ids:
            return TurnResult(self._fallback(raw, low))

        summary = self.orch.confirmation_summary(interp)
        self._pending = interp
        return TurnResult(summary + "\n\nProceed with this scan? [Y/n]",
                          needs_confirmation=True, pending=interp)

    # ================================================================== #
    # Execution
    # ================================================================== #
    def _run(self, interp) -> str:
        interp.request.mode = ScanMode.SYNC
        try:
            collector = self._collector()
        except RuntimeError as exc:
            return f"error: {exc}"
        result = self.orch.run(interp.request, collector, mode_label=self.mode_label)
        self.last_result = result
        tail = ("\n\n💬 Follow-ups: “show criticals” · “details <rule-id>” · "
                "“export markdown” · “summary”")
        return self.platform.reporting.render(result, "terminal") + tail

    def _run_cis(self) -> str:
        from ..frameworks.cis import CISBenchmarkEngine, render_text
        try:
            collector = self._collector()
        except RuntimeError as exc:
            return f"error: {exc}"
        report = CISBenchmarkEngine(self.platform).evaluate(collector)
        return render_text(report, show="fail")

    # ================================================================== #
    # Follow-ups (need a previous scan)
    # ================================================================== #
    def _followup(self, raw: str, low: str) -> Optional[str]:
        # severity filter
        m = re.search(r"\b(critical|high|medium|low)s?\b", low)
        wants_filter = _any(low, r"show|list|filter|only|just|the")
        if m and (wants_filter or low.strip() in (m.group(1), m.group(1) + "s")):
            return self._need_scan() or self._severity_view(m.group(1).upper())

        if _any(low, r"^(summary|recap|overview|score|results?)\b|show (summary|results?)"):
            return self._need_scan() or self._summary_view()

        if _any(low, r"\b(top|worst|most severe|biggest)\b"):
            return self._need_scan() or self._top_view()

        m = re.match(r"(?:details?|show|explain|why)\s+([\w\-]+)", low)
        if m and self.last_result and self._find_by_rule(m.group(1)):
            return self._detail_view(m.group(1))

        if _any(low, r"\b(export|save|download|render|write)\b") and \
                _any(low, r"\b(markdown|md|json|html|sarif|text|pdf|report)\b"):
            fm = re.search(r"\b(markdown|md|json|html|sarif|text|pdf)\b", low)
            fmt = fm.group(1) if fm else "markdown"
            fn = re.search(r"(?:\bto\b|\bas\b|\binto\b)\s+(\S+\.\w+)", raw, re.I)
            return self._need_scan() or self._export(fmt, fn.group(1) if fn else None)

        return None

    def _need_scan(self) -> Optional[str]:
        if self.last_result is None:
            return ("I don't have any results yet. Run a scan first, e.g. "
                    "“scan the cluster” or “is my cluster secure?”")
        return None

    def _severity_view(self, sev_label: str) -> str:
        from ..core.reporting import _display_findings  # ranked, non-info
        try:
            sev = Severity.parse(sev_label)
        except ValueError:
            return "Unknown severity."
        group = [f for f in _display_findings(self.last_result.findings)
                 if f.severity == sev]
        if not group:
            return f"No {sev_label} findings in the last scan. ✅"
        lines = [f"{sev.emoji} {len(group)} {sev_label} finding(s):", ""]
        for i, f in enumerate(group, 1):
            amp = " ⚡" if len(f.tactics) > 1 else ""
            lines.append(f"  {i}. {f.title}, {f.resource}{amp}")
            lines.append(f"     {f.rule_id} · {_mini_mitre(f)} · {f.message}")
        lines.append(f"\n💬 “details {group[0].rule_id}” · “export markdown”")
        return "\n".join(lines)

    def _summary_view(self) -> str:
        return self.platform.reporting.render(self.last_result, "terminal")

    def _top_view(self, n: int = 5) -> str:
        from ..core.reporting import _display_findings
        top = _display_findings(self.last_result.findings)[:n]
        lines = [f"Top {len(top)} findings by risk:", ""]
        for i, f in enumerate(top, 1):
            lines.append(f"  {i}. {f.severity.emoji} {f.title}, {f.resource} "
                         f"(score {round(f.score, 1)})")
        return "\n".join(lines)


    def _detail_view(self, rule_id: str) -> str:
        f = self._find_by_rule(rule_id)
        if not f:
            return f"No finding with rule '{rule_id}' in the last scan."
        lines = [
            f"{f.severity.emoji} {f.title}   [{f.severity.label}]",
            f"  resource      : {f.resource}",
            f"  rule / domain : {f.rule_id}  ·  {f.owning_shard}",
            f"  MITRE         : {_mini_mitre(f)}",
            f"  OWASP / CIS   : {f.owasp or '-'}  ·  {', '.join(f.cis) or '-'}",
            f"  exploitability: {f.exploitability.label}   blast: {f.blast_radius.label}"
            f"   score: {round(f.score, 1)}",
            f"  detail        : {f.message}",
        ]
        if f.evidence:
            import json
            lines.append(f"  evidence      : {json.dumps(f.evidence, default=str)}")
        return "\n".join(lines)

    def _export(self, fmt: str, filename: Optional[str] = None) -> str:
        fmt = {"md": "markdown"}.get(fmt, fmt)
        ext = {"markdown": "md", "json": "json", "html": "html", "sarif": "sarif",
               "text": "txt", "pdf": "pdf"}.get(fmt, "txt")
        try:
            out = self.platform.reporting.render(self.last_result, fmt)
        except RuntimeError as exc:
            return f"Could not generate the report: {exc}"
        path = filename or f"k8smatrixwarden-report-{self.last_result.scan_id}.{ext}"
        try:
            if fmt == "pdf":
                with open(path, "wb") as fh:
                    fh.write(out)
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(out)
            return (f"📄 Saved the {fmt} report to  {path}  ({len(out):,} bytes)."
                    + ("" if filename else "\n   (say “export markdown to <filename>” "
                       "to choose the name)"))
        except Exception as exc:
            return f"Could not write the report: {exc}"

    def _find_by_rule(self, rule_id: str):
        if not self.last_result:
            return None
        rid = rule_id.lower()
        for f in self.last_result.findings:
            if f.rule_id.lower() == rid:
                return f
        return None

    # ================================================================== #
    # Learn / info
    # ================================================================== #
    def _capabilities(self) -> str:
        return (
            "I'm a Kubernetes security assistant. I can:\n"
            "  • scan your cluster, by namespace/pod/image, by MITRE tactic, by technique, "
            "or by domain (RBAC, network, secrets, images, …)\n"
            "  • run the full CIS Kubernetes Benchmark (130 controls)\n"
            "  • map the attack surface\n"
            "  • after a scan, filter findings and explain them in depth\n"
            "  • export reports (markdown / json / html / sarif)\n\n"
            "Try: “scan production for privilege escalation”, “any exposed secrets?”, "
            "“run the cis benchmark”, then “show criticals” and “details <rule-id>”.\n"
            "Type 'help' for the full command list.")

    def _list_tactics(self) -> str:
        cov = self.platform.coverage()
        lines = ["The 9 MITRE ATT&CK tactics I scan for (rules per tactic):", ""]
        for t, desc in TACTIC_DESC.items():
            lines.append(f"  • {t} ({cov.get(t, 0)} rules), {desc}")
        lines.append("\nSay e.g. “scan for persistence”.")
        return "\n".join(lines)

    def _list_modules(self) -> str:
        lines = ["Security domains (shards), say “scan <domain>”:", ""]
        for name in self.platform.registry.shard_names():
            shard = self.platform.registry.get_shard(name)
            n = len(self.platform.registry.rules.by_shard(name))
            lines.append(f"  • {name}  ({n} rules), {getattr(shard, 'title', name)}")
        return "\n".join(lines)

    def _list_aliases(self) -> str:
        aliases = self.platform.mapping.known_terms()["aliases"]
        lines = ["Named techniques / outcomes, say “scan only <name>”:", ""]
        for a in aliases:
            lines.append(f"  • {a}")
        return "\n".join(lines)

    def _explain(self, term: str) -> str:
        # a MITRE tactic?
        for t, desc in TACTIC_DESC.items():
            if term.lower() == t.lower() or term.lower() in t.lower():
                cov = self.platform.coverage().get(t, 0)
                return f"🎯 {t} ({cov} rules)\n  {desc}\n  Say “scan for {t}”."
        # a shard/domain?
        for name in self.platform.registry.shard_names():
            if term.lower() in name or name in term.lower():
                shard = self.platform.registry.get_shard(name)
                rules = self.platform.registry.rules.by_shard(name)
                sample = ", ".join(r.id for r in rules[:5])
                return (f"🧩 {name}, {getattr(shard, 'title', name)} ({len(rules)} rules)\n"
                        f"  e.g. {sample}\n  Say “scan {name}”.")
        # a rule id?
        rule = self.platform.registry.rules.get(term)
        if rule:
            return (f"📏 {rule.id}, {rule.title}  [{rule.severity.label}]\n"
                    f"  domain : {rule.owning_shard}\n"
                    f"  mitre  : "
                    + " · ".join(f"{m.tactic.value}/{m.technique_id}" for m in rule.mitre)
                    + f"\n  owasp  : {rule.owasp or '-'}   cis: {', '.join(rule.cis) or '-'}")
        # an alias?
        for a in self.platform.mapping.known_terms()["aliases"]:
            if term.lower() == a.lower():
                try:
                    from ..core.models import Selector
                    ids = self.platform.mapping.resolve(Selector(techniques=[a]))
                    return (f"🧪 “{a}” expands to {len(ids)} rule(s):\n  "
                            + ", ".join(ids))
                except Exception:
                    break
        sug = self.orch.suggest(term)
        hint = (f" Did you mean: {', '.join(sug)}?" if sug else "")
        return (f"I don't have an explanation for “{term}”.{hint}\n"
                "Try 'list tactics', 'list modules', or 'list techniques'.")

    # ================================================================== #
    # Fallback & namespace awareness
    # ================================================================== #
    def _fallback(self, raw: str, low: str) -> str:
        sug = self.orch.suggest(raw)
        lines = [f"I couldn't turn “{raw}” into a scan."]
        if sug:
            lines.append(f"Did you mean: {', '.join(sug)}?")
        lines.append("You can say things like:")
        lines.append("  • “scan the cluster”  • “scan for privilege escalation”")
        lines.append("  • “any exposed secrets?”  • “run the cis benchmark”")
        lines.append("Type 'help' or 'what can you do?' for more.")
        return "\n".join(lines)

    def _known_namespaces(self) -> list:
        if self._ns_cache is None:
            try:
                ev = self._collector().collect({"Namespace"}, Scope(ScopeLevel.CLUSTER))
                self._ns_cache = [n for n in ev.namespaces() if n]
            except Exception:
                self._ns_cache = []
        return self._ns_cache

    def _apply_namespace_scope(self, interp, low: str) -> None:
        # If no explicit scope was parsed, but the user named a real namespace, use it.
        if interp.request.scope.level != ScopeLevel.CLUSTER:
            return
        for ns in self._known_namespaces():
            if re.search(r"\b" + re.escape(ns.lower()) + r"\b", low):
                interp.request.scope = Scope(ScopeLevel.NAMESPACE, namespace=ns)
                return

    def _unknown_namespace(self, interp) -> Optional[str]:
        """If a namespace scope was parsed that doesn't exist, say so (with suggestions)
        rather than scanning a non-existent namespace."""
        sc = interp.request.scope
        if sc.level != ScopeLevel.NAMESPACE:
            return None
        known = self._known_namespaces()
        if known and sc.namespace not in known:
            close = difflib.get_close_matches(sc.namespace, known, n=3, cutoff=0.5)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            return (f"I don't see a namespace called '{sc.namespace}'.{hint}\n"
                    f"Known namespaces: {', '.join(known)}")
        return None

    # ================================================================== #
    # Static views (coverage / rules)
    # ================================================================== #
    def _coverage(self) -> str:
        lines = ["MITRE tactic coverage (rules per tactic):"]
        for tactic, n in self.platform.coverage().items():
            lines.append(f"  {tactic:<22} {n:>2}  {'█' * n}")
        return "\n".join(lines)

    def _rules(self, module: Optional[str]) -> str:
        rules = self.platform.registry.rules.all()
        if module:
            module = module.strip()
            rules = [r for r in rules if module in r.owning_shard]
        rules = sorted(rules, key=lambda r: (r.owning_shard, r.id))
        head = f"{len(rules)} rule(s)" + (f" in shards matching '{module}'" if module else "")
        return "\n".join([head] + [
            f"  {r.severity.emoji} {r.id:<32} [{r.owning_shard}]" for r in rules[:40]
        ] + (["  …"] if len(rules) > 40 else []))


# ----------------------------------------------------------------------- #
def _any(low: str, pattern: str) -> bool:
    return bool(re.search(pattern, low))


def _full_scan_ok(low: str) -> bool:
    """True if the user clearly wants a full/whole-scope scan (not a garbage target)."""
    if re.search(r"\b(everything|whole|entire|all|posture|overall|secure|security|"
                 r"the cluster|full scan|scan all|audit|thorough|complete)\b", low):
        return True
    # nothing meaningful left after removing scan verbs / stopwords → a bare "scan"
    stripped = re.sub(r"\b(scan|check|run|do|a|an|the|my|please|now|it|of|on|for|cluster|"
                      r"me|us|report)\b", " ", low)
    return not re.search(r"[a-z0-9]", stripped)


def _mini_mitre(f) -> str:
    if not f.mitre:
        return "-"
    return ", ".join(dict.fromkeys(f"{m.tactic.value}/{m.technique_id}" for m in f.mitre))


def run_chat(platform: Platform, *, mock: bool = True, fixture: Optional[str] = None,
             kubeconfig: Optional[str] = None, context: Optional[str] = None,
             input_fn: Callable[[str], str] = input,
             print_fn: Callable[[str], None] = print) -> int:
    """Run the interactive loop. input_fn/print_fn are injectable for testing."""
    session = ChatSession(platform, mock=mock, fixture=fixture, kubeconfig=kubeconfig,
                          context=context)
    print_fn(BANNER)
    while True:
        try:
            text = input_fn("k8smatrixwarden› ")
        except (EOFError, KeyboardInterrupt):
            print_fn("\nBye, stay secure. 🛡️")
            return 0
        turn = session.handle_turn(text)
        if turn.output:
            print_fn(turn.output)
        if turn.quit:
            return 0
