"""
Orchestrator Agent (§4, §7.4).

Single entry point: compiles user intent (natural language OR explicit CLI args) into a
`ScanRequest`, resolves the selector against the registry term index, and produces a
confirmation summary before the Scanner Agent executes.

Intent parsing here is deterministic keyword/fuzzy matching over terms generated FROM the
registry (so it never drifts from what actually exists). An LLM can be layered on top for
ambiguous phrasing, but the resolution target is always the same registry index (§7.4).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..bootstrap import Platform
from ..core.evidence import EvidenceCollector
from ..core.models import (ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity,
                           Tactic)
from ..core.results import ScanResult
from .scanner import ScannerAgent

INTENTS = ["scan", "audit", "map", "monitor", "investigate", "report",
           "download"]

# Synonym maps: regex fragment (word-boundary-wrapped at match time) -> canonical value.
# These let natural variations ("privesc", "leaked secrets", "recon") resolve to the same
# registry terms, without an LLM. Curated (not fuzzy) to avoid wrong scans.
_TACTIC_SYNONYMS = {
    r"privilege escalation|privesc|priv[ -]?esc|escalat\w*": "Privilege Escalation",
    r"persistence|persist\w*|backdoor\w*|foothold": "Persistence",
    r"credential access|credentials?|creds|token theft|steal\w* token": "Credential Access",
    r"lateral movement|lateral|pivot\w*|move sideways": "Lateral Movement",
    r"defense evasion|evasion|evad\w*|cover\w* track": "Defense Evasion",
    r"discovery|recon\w*|enumerat\w*|mapping the": "Discovery",
    r"execution|\brce\b|remote code|run\w* code": "Execution",
    r"initial access|entry point\w*|get\w* in|foothold": "Initial Access",
    r"impact|denial of service|\bdos\b|cryptomin\w*|crypto[- ]?min\w*|"
    r"data destruction|resource hijack\w*": "Impact",
}
_MODULE_SYNONYMS = {
    r"rbac|roles?|permissions?|authoriz\w*|clusterrole\w*|bindings?": "rbac_identity",
    r"network\w*|netpol|networkpolic\w*|ingress|firewall|segmentation": "network_security",
    r"secrets?|vault|credential storage|env var\w*": "secrets",
    r"images?|registry|registries|\bcve\b|cves|supply chain|vulnerabilit\w*|trivy":
        "image_supply_chain",
    r"workloads?|pod security|securitycontext|container security|deployment security":
        "workload_pod_security",
    r"admission|webhooks?|cronjobs?|mutating|validating": "admission_control",
    r"cloud iam|cloud\w*|\biam\b|irsa|workload identity|managed identity|metadata api":
        "cloud_iam",
    r"compliance|\bpsa\b|pod security standard\w*": "compliance",
    r"control[- ]?plane|api[- ]?server|etcd|kubelet|scheduler|controller manager":
        "cluster_control_plane",
    r"attack surface|exposure|entry points?|external exposure": "attack_surface",
}
_ALIAS_SYNONYMS = {
    r"container escape|escape to host|breakout|break out|escaping the container":
        "Container Escape",
    r"exposed secrets?|leaked secrets?|hardcoded secrets?|secrets? in env": "Exposed Secrets",
    r"privileged pods?": "Privileged Pods",
    r"privileged containers?": "Privileged Container",
    r"anonymous api|anonymous auth|anon auth": "Anonymous API Access",
    r"api exposure|exposed api|dashboard exposed": "Kubernetes API Exposure",
}
# tokens that are never a namespace even if they sit in the namespace slot
_RESERVED_WORDS = {"the", "all", "cluster", "everything", "for", "my", "a", "this", "me",
                   "whole", "entire", "some", "any"}


@dataclass
class Interpretation:
    intent: str
    request: ScanRequest
    resolved_rule_ids: list
    notes: list


class Orchestrator:
    def __init__(self, platform: Platform):
        self.p = platform
        self.scanner = ScannerAgent(platform)

    # ------------------------------------------------------------------ #
    # Natural-language interpretation
    # ------------------------------------------------------------------ #
    def interpret(self, text: str) -> Interpretation:
        low = f" {text.lower().strip()} "
        notes: list[str] = []

        intent = next((i for i in INTENTS if f" {i} " in low or low.strip().startswith(i)),
                      "scan")
        scope = self._parse_scope(text, low)
        selector = self._parse_selector(text, low, notes)

        # AUDIT with no explicit framework defaults to a full CIS audit.
        if intent == "audit" and selector.is_empty():
            selector.frameworks.append("CIS")

        request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
        try:
            resolved = self.p.mapping.resolve(selector)
        except Exception as exc:
            notes.append(f"selector did not resolve: {exc}")
            resolved = []
        return Interpretation(intent, request, resolved, notes)

    # words that are never a namespace even if they sit in the namespace slot
    _NON_NS = {"the", "all", "cluster", "everything", "for", "my", "a", "this"}

    def _parse_scope(self, text: str, low: str) -> Scope:
        m = re.search(r"namespace[s]?\s+([a-z0-9][a-z0-9\-]*)", low) or \
            re.search(r"\bns[:=]\s*([a-z0-9][a-z0-9\-]*)", low) or \
            re.search(r"\bin\s+(?:the\s+)?([a-z0-9\-]+)\s+namespace", low)
        if m:
            return Scope(ScopeLevel.NAMESPACE, namespace=m.group(1))
        # "scan <ns> for <tactic>" / "scan the <ns> namespace", bare namespace token.
        m = re.search(r"\bscan\s+(?:the\s+)?([a-z0-9][a-z0-9\-]*)\s+"
                      r"(?:namespace\s+)?for\b", low)
        if m and m.group(1) not in self._NON_NS:
            return Scope(ScopeLevel.NAMESPACE, namespace=m.group(1))
        m = re.search(r"\bpod\s+([a-z0-9][a-z0-9\-]*)", low)
        if m:
            return Scope(ScopeLevel.POD, name=m.group(1))
        m = re.search(r"\b(deployment|daemonset|statefulset)\s+([a-z0-9\-]+)", low)
        if m:
            return Scope(ScopeLevel.WORKLOAD, kind=m.group(1).capitalize(),
                         name=m.group(2))
        m = re.search(r"\bimage\s+(\S+)", low)
        if m:
            return Scope(ScopeLevel.IMAGE, image=m.group(1))
        m = re.search(r"\bnode\s+([a-z0-9\-]+)", low)
        if m:
            return Scope(ScopeLevel.NODE, name=m.group(1))
        return Scope(ScopeLevel.CLUSTER)

    def _parse_selector(self, text: str, low: str, notes: list) -> Selector:
        sel = Selector()
        terms = self.p.mapping.known_terms()

        # Frameworks
        for fw in ("cis", "nsa", "owasp"):
            if re.search(rf"\b{fw}\b", low):
                sel.frameworks.append(fw.upper())

        # Composite aliases by exact display name (e.g. "container escape").
        for alias in terms["aliases"]:
            if alias.lower() in low and alias not in sel.techniques:
                sel.techniques.append(alias)

        # Synonym expansion, tactics, modules, aliases via curated word-boundary patterns.
        self._apply_synonyms(low, sel)

        # Severity floor: "only critical", "critical only", "high and above", etc.
        m = re.search(r"\b(critical|high|medium|low)\b", low)
        if m and re.search(r"\bonly\b|\bjust\b|and above|or higher|\bat least\b", low):
            try:
                sel.severity_min = Severity.parse(m.group(1))
            except ValueError:
                pass
        return sel

    @staticmethod
    def _search(pattern: str, low: str) -> bool:
        return bool(re.search(r"\b(?:" + pattern + r")\b", low))

    def _apply_synonyms(self, low: str, sel: Selector) -> None:
        for pat, tactic in _TACTIC_SYNONYMS.items():
            if self._search(pat, low) and tactic not in sel.tactics:
                sel.tactics.append(tactic)
        for pat, shard in _MODULE_SYNONYMS.items():
            if self._search(pat, low) and shard not in sel.modules:
                sel.modules.append(shard)
        for pat, alias in _ALIAS_SYNONYMS.items():
            if self._search(pat, low) and alias not in sel.techniques:
                sel.techniques.append(alias)

    def suggest(self, text: str) -> list[str]:
        """Best-effort 'did you mean' suggestions when a request resolved to nothing."""
        import difflib
        low = text.lower()
        vocab = [t.value for t in Tactic]
        vocab += self.p.registry.shard_names()
        vocab += self.p.mapping.known_terms()["aliases"]
        words = re.findall(r"[a-z][a-z0-9\- ]{2,}", low)
        hits: list[str] = []
        for w in set(words + [low.strip()]):
            for m in difflib.get_close_matches(w, vocab, n=2, cutoff=0.6):
                if m not in hits:
                    hits.append(m)
        return hits[:4]

    # ------------------------------------------------------------------ #
    # Confirmation + execution
    # ------------------------------------------------------------------ #
    def confirmation_summary(self, interp: Interpretation) -> str:
        n = len(interp.resolved_rule_ids)
        shards = sorted({self.p.registry.rules.get(r).owning_shard
                         for r in interp.resolved_rule_ids
                         if self.p.registry.rules.get(r)})
        head = (f"Intent={interp.intent.upper()}  Scope={interp.request.scope.describe()}  "
                f"Selector={interp.request.selector.describe()}")
        body = (f"→ resolves to {n} rule(s) across {len(shards)} shard(s): "
                f"{', '.join(shards) or 'N/A'}")
        preview = ", ".join(interp.resolved_rule_ids[:8])
        if n > 8:
            preview += f", … (+{n - 8} more)"
        lines = [head, body]
        if preview:
            lines.append(f"  rules: {preview}")
        for note in interp.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)

    def run(self, request: ScanRequest, collector: EvidenceCollector,
            mode_label: str = "mock", name: str = "") -> ScanResult:
        return self.scanner.scan(request, collector, mode_label=mode_label, name=name)
