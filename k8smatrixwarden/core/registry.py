"""
Registries (§6.1).

  ScannerRegistry , catalog of domain-shard plugins (name, version, resource types,
                     RBAC verbs). Feeds least-privilege RoleBinding generation.
  RuleRegistry    , catalog of every Rule with its metadata; the single store the
                     MITREMappingEngine indexes and the Detection Engine executes from.

These are deliberately dumb stores; all taxonomy querying lives in the mapping engine.
"""
from __future__ import annotations

from typing import Iterable, Optional

from .models import Rule


class DuplicateRuleError(ValueError):
    pass


class RuleRegistry:
    """Flat catalog of all rules across all shards."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        if rule.id in self._rules:
            raise DuplicateRuleError(f"Duplicate rule id: {rule.id!r}")
        self._rules[rule.id] = rule

    def register_many(self, rules: Iterable[Rule]) -> None:
        for r in rules:
            self.register(r)

    def get(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def all(self) -> list[Rule]:
        return list(self._rules.values())

    def enabled(self) -> list[Rule]:
        return [r for r in self._rules.values() if r.enabled]

    def by_shard(self, shard: str) -> list[Rule]:
        return [r for r in self._rules.values() if r.owning_shard == shard]

    def ids(self) -> list[str]:
        return list(self._rules.keys())

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules


class ScannerRegistry:
    """Catalog of domain-shard plugins and the resources / RBAC verbs they need (§6.1)."""

    def __init__(self, rule_registry: Optional[RuleRegistry] = None) -> None:
        self.rules = rule_registry or RuleRegistry()
        self._shards: dict[str, "object"] = {}

    def register_shard(self, shard) -> None:
        """Register a DomainShard (see shards/base.py) and load its rules."""
        if shard.name in self._shards:
            raise ValueError(f"Duplicate shard: {shard.name!r}")
        self._shards[shard.name] = shard
        self.rules.register_many(shard.rules())

    @property
    def shards(self) -> list:
        return list(self._shards.values())

    def shard_names(self) -> list[str]:
        return list(self._shards.keys())

    def get_shard(self, name: str):
        return self._shards.get(name)

    def resource_types(self) -> set[str]:
        """Union of every resource type any shard needs (for evidence pre-warming)."""
        out: set[str] = set()
        for s in self._shards.values():
            out.update(s.resource_types())
        return out

    def rbac_verbs(self) -> dict[str, list[dict]]:
        """Per-shard RBAC verb declarations, for scoped RoleBinding generation (§20)."""
        return {name: s.rbac_verbs() for name, s in self._shards.items()}
