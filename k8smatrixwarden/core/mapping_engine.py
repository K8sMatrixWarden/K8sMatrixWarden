"""
MITRE Mapping Engine (§6).

The cross-cutting index over the Rule Registry. It is the ONLY component that turns a
Selector into a concrete set of rule ids, so there is exactly one resolution path for
every scan type (§7.2). It also validates each rule's technique ids against a vendored,
versioned ATT&CK-for-Containers taxonomy (§6.2, CI-style guard).

Indexes built once at startup:
    tactic       -> [rule_id]
    technique_id -> [rule_id]     (canonical T-id)
    technique    -> [rule_id]     (fuzzy: id, technique name, or display alias)
    owasp        -> [rule_id]
    cis          -> [rule_id]
    nsa_cisa     -> [rule_id]
    module       -> [rule_id]
    alias        -> [rule_id]     (composite/outcome selectors, e.g. "Container Escape")
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .models import Rule, Selector, Tactic
from .registry import RuleRegistry


class TaxonomyValidationError(ValueError):
    pass


class SelectorResolutionError(ValueError):
    pass


class MITREMappingEngine:
    def __init__(self, registry: RuleRegistry, taxonomy: Optional[dict] = None) -> None:
        self.registry = registry
        self.taxonomy = taxonomy or {}
        self._by_tactic: dict[str, list[str]] = defaultdict(list)
        self._by_technique_id: dict[str, list[str]] = defaultdict(list)
        self._by_technique_term: dict[str, list[str]] = defaultdict(list)
        self._by_owasp: dict[str, list[str]] = defaultdict(list)
        self._by_cis: dict[str, list[str]] = defaultdict(list)
        self._by_nsa: dict[str, list[str]] = defaultdict(list)
        self._by_module: dict[str, list[str]] = defaultdict(list)
        self._aliases: dict[str, list[str]] = {}
        self._alias_display: dict[str, str] = {}   # normalized -> original label
        self._built = False

    # ------------------------------------------------------------------ #
    # Build & validate
    # ------------------------------------------------------------------ #
    def build(self) -> "MITREMappingEngine":
        for rule in self.registry.all():
            self._index_rule(rule)
        self._built = True
        return self

    def _index_rule(self, rule: Rule) -> None:
        self._by_module[_norm(rule.owning_shard)].append(rule.id)
        if rule.owasp:
            self._by_owasp[_norm(rule.owasp)].append(rule.id)
        for c in rule.cis:
            self._by_cis[_norm(c)].append(rule.id)
        for n in rule.nsa_cisa:
            self._by_nsa[_norm(n)].append(rule.id)
        for m in rule.mitre:
            self._by_tactic[_norm(m.tactic.value)].append(rule.id)
            self._by_technique_id[_norm(m.technique_id)].append(rule.id)
            self._by_technique_term[_norm(m.technique_id)].append(rule.id)
            self._by_technique_term[_norm(m.technique_name)].append(rule.id)

    def register_alias(self, name: str, rule_ids: list[str]) -> None:
        """Register a composite/outcome selector (§7.3), e.g. 'Container Escape'."""
        key = _norm(name)
        self._aliases[key] = list(rule_ids)
        self._alias_display[key] = name

    def register_aliases(self, aliases: dict[str, list[str]]) -> None:
        for name, ids in (aliases or {}).items():
            self.register_alias(name, ids)

    def validate(self) -> list[str]:
        """
        CI-style validation (§6.2). Returns a list of human-readable problems; empty = clean.
        Checks: technique ids exist in the vendored taxonomy; alias targets exist.
        """
        problems: list[str] = []
        known_ids = set()
        for tech in self.taxonomy.get("techniques", []):
            known_ids.add(_norm(tech.get("id", "")))
        if known_ids:  # only enforce if a taxonomy was actually loaded
            for rule in self.registry.all():
                for m in rule.mitre:
                    if _norm(m.technique_id) not in known_ids:
                        problems.append(
                            f"rule {rule.id!r} references unknown technique id "
                            f"{m.technique_id!r} (not in vendored taxonomy)"
                        )
        for alias, ids in self._aliases.items():
            for rid in ids:
                if rid not in self.registry:
                    problems.append(
                        f"alias {self._alias_display[alias]!r} targets unknown rule {rid!r}"
                    )
        return problems

    # ------------------------------------------------------------------ #
    # Resolution, the single choke point (§7.2)
    # ------------------------------------------------------------------ #
    def resolve(self, selector: Selector) -> list[str]:
        """
        Selector -> ordered, de-duplicated list of rule ids.
        Empty selector => all enabled rules. Combines axes with OR (union), then applies
        severity_min. Raises if the selector matches nothing (never a silent empty scan).
        """
        if not self._built:
            self.build()

        if selector.is_empty():
            resolved = [r.id for r in self.registry.enabled()]
        else:
            acc: list[str] = []
            for t in selector.tactics:
                acc += self._lookup(self._by_tactic, t, f"tactic {t!r}")
            for tech in selector.techniques:
                # techniques try alias first (outcome labels like "Container Escape"),
                # then the technique term index (id or name).
                if _norm(tech) in self._aliases:
                    acc += self._aliases[_norm(tech)]
                else:
                    acc += self._lookup(self._by_technique_term, tech, f"technique {tech!r}")
            for a in selector.aliases:
                acc += self._lookup(self._aliases, a, f"alias {a!r}")
            for mod in selector.modules:
                acc += self._lookup(self._by_module, mod, f"module {mod!r}")
            for fw in selector.frameworks:
                acc += self._resolve_framework(fw)
            for rid in selector.rule_ids:
                if rid not in self.registry:
                    raise SelectorResolutionError(f"unknown rule id {rid!r}")
                acc.append(rid)
            resolved = acc

        # De-duplicate preserving order.
        seen, ordered = set(), []
        for rid in resolved:
            if rid in seen:
                continue
            rule = self.registry.get(rid)
            if rule is None or not rule.enabled:
                continue
            if selector.severity_min and rule.severity.order < selector.severity_min.order:
                continue
            seen.add(rid)
            ordered.append(rid)

        if not ordered and not selector.is_empty():
            raise SelectorResolutionError(
                f"selector matched no rules: {selector.describe()}"
            )
        return ordered

    def _resolve_framework(self, fw: str) -> list[str]:
        key = _norm(fw)
        if key in ("cis", "cis-benchmark", "cis_kubernetes"):
            ids = [r.id for r in self.registry.all() if r.cis]
        elif key in ("nsa", "nsa-cisa", "nsa_cisa"):
            ids = [r.id for r in self.registry.all() if r.nsa_cisa]
        elif key in ("owasp", "owasp-k8s", "owasp_top10"):
            ids = [r.id for r in self.registry.all() if r.owasp]
        else:
            raise SelectorResolutionError(f"unknown framework {fw!r}")
        return ids

    @staticmethod
    def _lookup(index: dict, key: str, what: str) -> list[str]:
        val = index.get(_norm(key))
        if val is None:
            raise SelectorResolutionError(f"{what} matched nothing")
        return list(val)

    # ------------------------------------------------------------------ #
    # Introspection helpers (used by CLI + AI intent parsing, §7.4)
    # ------------------------------------------------------------------ #
    def known_terms(self) -> dict[str, list[str]]:
        """All selectable terms, for fuzzy matching in the Orchestrator."""
        return {
            "tactics": sorted({t.value for t in Tactic}),
            "modules": sorted(self._by_module.keys()),
            "aliases": sorted(self._alias_display.values()),
            "frameworks": ["CIS", "NSA", "OWASP"],
        }

    def coverage(self) -> dict[str, int]:
        """Rule count per tactic (attack-surface / dashboard helper)."""
        return {t.value: len(self._by_tactic.get(_norm(t.value), [])) for t in Tactic}


def _norm(s: str) -> str:
    return str(s).strip().lower()
