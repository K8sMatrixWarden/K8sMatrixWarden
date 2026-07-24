"""
Platform bootstrap, wires the whole Scanner Agent together (§3.4, §6).

Builds, once: the Scanner Registry (via the Plugin Loader), the Rule Registry, the MITRE
Mapping Engine (indexed + validated against the vendored taxonomy), the Detection Engine,
Aggregator, Risk Scoring, and Reporting. Applies config-driven rule overrides and aliases.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .core.aggregator import ResultAggregator
from .core.detection import DetectionEngine
from .core.evidence import (EvidenceCollector, LiveEvidenceCollector,
                            MockEvidenceCollector, default_fixture_path)
from .core.mapping_engine import MITREMappingEngine
from .core.models import Severity
from .core.plugin import PluginLoader
from .core.registry import ScannerRegistry
from .core.reporting import ReportingEngine
from .core.scoring import RiskScoringEngine

_ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_taxonomy() -> dict:
    tdir = os.path.join(_ROOT, "taxonomy")
    return {
        "techniques": _load_json(os.path.join(tdir, "attack_for_containers.json"))
        .get("techniques", []),
        "aliases": _load_json(os.path.join(tdir, "redguard_aliases.json")),
        "owasp": _load_json(os.path.join(tdir, "owasp_k8s_top10.json")),
    }


def load_config(path: Optional[str] = None) -> dict:
    base = _load_json(os.path.join(_ROOT, "config", "default_config.json"))
    if path:
        override = _load_json(path)
        base = _deep_merge(base, override)
    return base


def _deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Platform:
    registry: ScannerRegistry
    mapping: MITREMappingEngine
    detection: DetectionEngine
    aggregator: ResultAggregator
    scoring: RiskScoringEngine
    reporting: ReportingEngine
    loader: PluginLoader
    config: dict
    taxonomy: dict
    validation_problems: list = field(default_factory=list)

    # -- collectors ------------------------------------------------------- #
    def make_collector(self, *, mock: bool = True, fixture: Optional[str] = None,
                       kubeconfig: Optional[str] = None,
                       context: Optional[str] = None) -> EvidenceCollector:
        if mock:
            return MockEvidenceCollector(fixture or default_fixture_path())
        return LiveEvidenceCollector(kubeconfig=kubeconfig, context=context)

    # -- introspection ---------------------------------------------------- #
    def coverage(self) -> dict:
        return self.mapping.coverage()

    def rule_count(self) -> int:
        return len(self.registry.rules)


def build_platform(config_path: Optional[str] = None,
                   extra_plugin_packages: Optional[list[str]] = None) -> Platform:
    config = load_config(config_path)
    taxonomy = load_taxonomy()

    registry = ScannerRegistry()
    loader = PluginLoader(registry, extra_packages=extra_plugin_packages)
    loader.load_builtin()
    loader.load_extras()

    _apply_shard_toggles(registry, config)
    _apply_rule_overrides(registry, config)

    mapping = MITREMappingEngine(registry.rules, taxonomy).build()
    mapping.register_aliases(config.get("aliases", {}))
    problems = mapping.validate()

    detection = DetectionEngine(
        registry.rules,
        max_workers=config.get("global", {}).get("parallel_rules", 16))

    return Platform(
        registry=registry, mapping=mapping, detection=detection,
        aggregator=ResultAggregator(), scoring=RiskScoringEngine(),
        reporting=ReportingEngine(registry.rules), loader=loader, config=config,
        taxonomy=taxonomy, validation_problems=problems)


def _apply_shard_toggles(registry: ScannerRegistry, config: dict) -> None:
    toggles = config.get("shards", {})
    for rule in registry.rules.all():
        shard_cfg = toggles.get(rule.owning_shard, {})
        if shard_cfg.get("enabled") is False:
            rule.enabled = False


def _apply_rule_overrides(registry: ScannerRegistry, config: dict) -> None:
    for rid, ov in config.get("rule_overrides", {}).items():
        rule = registry.rules.get(rid)
        if not rule:
            continue
        if "enabled" in ov:
            rule.enabled = bool(ov["enabled"])
        if "severity" in ov:
            try:
                rule.severity = Severity.parse(ov["severity"])
            except ValueError:
                pass
