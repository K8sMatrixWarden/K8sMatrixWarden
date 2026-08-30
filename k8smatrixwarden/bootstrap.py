"""
Platform bootstrap, wires the whole Scanner Agent together (§3.4, §6).

Builds, once: the Scanner Registry (via the Plugin Loader), the Rule Registry, the MITRE
Mapping Engine (indexed + validated against the vendored taxonomy), the Detection Engine,
Aggregator, Risk Scoring, and Reporting. Applies config-driven rule overrides and aliases.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from .core.aggregator import ResultAggregator
from .core.detection import DetectionEngine
from .core.evidence import (EvidenceCollector, LiveEvidenceCollector,
                            MockEvidenceCollector, default_fixture_path)
from .core.mapping_engine import MITREMappingEngine
from .core.models import DetectionMethod, Severity
from .core.plugin import PluginLoader
from .core.registry import ScannerRegistry
from .core.reporting import ReportingEngine
from .core.scoring import RiskScoringEngine

_ROOT = os.path.dirname(os.path.abspath(__file__))


class DuplicateKeyError(ValueError):
    """A JSON object declared the same key twice.

    `json.load` silently keeps the last one, so a config with `"secrets"` written twice
    looks valid while one of the two settings is discarded. Configuration that is silently
    half-applied is the exact drift this module exists to prevent, so it is an error."""


def _no_duplicate_keys(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def _load_json(path: str, *, strict: bool = False) -> dict:
    """Load a JSON file. `strict` rejects duplicate object keys instead of silently
    keeping the last value (used for user configuration, not for vendored taxonomy)."""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        hook = _no_duplicate_keys if strict else None
        return json.load(fh, object_pairs_hook=hook)


def load_taxonomy() -> dict:
    tdir = os.path.join(_ROOT, "taxonomy")
    return {
        "techniques": _load_json(os.path.join(tdir, "attack_for_containers.json"))
        .get("techniques", []),
        "aliases": _load_json(os.path.join(tdir, "redguard_aliases.json")),
        "owasp": _load_json(os.path.join(tdir, "owasp_k8s_top10.json")),
    }


def load_config(path: Optional[str] = None,
                problems: Optional[list] = None) -> dict:
    """Merge the shipped defaults with an optional override file.

    `problems`, when a list is passed, collects human-readable load errors (unreadable or
    malformed JSON, duplicate keys) instead of raising, so one bad override file surfaces
    as a `doctor` FAIL rather than a traceback on every command."""
    base = _read_config(os.path.join(_ROOT, "config", "default_config.json"), problems)
    if path:
        base = _deep_merge(base, _read_config(path, problems))
    return base


def _read_config(path: str, problems: Optional[list]) -> dict:
    try:
        loaded = _load_json(path, strict=True)
    except (DuplicateKeyError, ValueError, OSError) as exc:
        if problems is None:
            raise
        problems.append(f"config {path!r} could not be loaded: {exc}")
        return {}
    if not isinstance(loaded, dict):
        msg = f"config {path!r} must be a JSON object, got {type(loaded).__name__}"
        if problems is None:
            raise ValueError(msg)
        problems.append(msg)
        return {}
    return loaded


#: Every key a shard's config block may carry, and the type it must have. An unknown key is
#: almost always a typo (`"enable"` for `"enabled"`), which would otherwise silently do
#: nothing, so it is reported rather than ignored.
_SHARD_KEYS = {"enabled": bool}


def validate_shard_config(shard_names: list[str], config: dict) -> list[str]:
    """Cross-check the `shards` config block against the shards actually discovered.

    Discovery is authoritative: a shard with no config block defaults to enabled (that is
    what makes a newly dropped-in shard work with no config edit). What is NOT acceptable
    is drift going unnoticed, so every mismatch is reported:

      * configured shard that does not exist   , a stale or misspelled entry doing nothing
      * discovered shard with no config block  , runs on the default, but say so (WARN)
      * malformed block / unknown or wrong-typed key , silently ignored otherwise
    """
    problems: list[str] = []
    block = config.get("shards", {})
    if not isinstance(block, dict):
        return [f"config 'shards' must be an object, got {type(block).__name__}"]
    known = set(shard_names)
    for name, cfg in block.items():
        if name not in known:
            problems.append(
                f"config declares unknown shard {name!r} (discovered shards: "
                f"{', '.join(sorted(known))})")
        if not isinstance(cfg, dict):
            problems.append(f"shard {name!r} config must be an object, got "
                            f"{type(cfg).__name__}")
            continue
        for key, value in cfg.items():
            expected = _SHARD_KEYS.get(key)
            if expected is None:
                problems.append(f"shard {name!r} has unknown config key {key!r} "
                                f"(valid: {', '.join(sorted(_SHARD_KEYS))})")
            elif not isinstance(value, expected):
                problems.append(f"shard {name!r} key {key!r} must be "
                                f"{expected.__name__}, got {type(value).__name__}")
    for name in sorted(known - set(block)):
        problems.append(f"shard {name!r} was discovered but has no entry in config "
                        f"'shards' (defaulting to enabled)")
    return problems


def validate_rule_overrides(registry, config: dict) -> list[str]:
    """Rule overrides that target a rule id no longer in the registry, or set an
    unparseable severity, do nothing at all today. Report them."""
    problems: list[str] = []
    block = config.get("rule_overrides", {})
    if not isinstance(block, dict):
        return [f"config 'rule_overrides' must be an object, got {type(block).__name__}"]
    for rid, override in block.items():
        if registry.rules.get(rid) is None:
            problems.append(f"rule_overrides targets unknown rule id {rid!r}")
            continue
        if not isinstance(override, dict):
            problems.append(f"rule_overrides[{rid!r}] must be an object")
            continue
        if "severity" in override:
            try:
                Severity.parse(override["severity"])
            except ValueError:
                problems.append(f"rule_overrides[{rid!r}] has invalid severity "
                                f"{override['severity']!r}")
    return problems


def _deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


#: A rule id is a stable, machine-readable identity: lowercase words joined by hyphens or
#: dots. It must NOT change when the implementation changes (that is what `version` is
#: for), so it is validated once here rather than left to each shard's discipline.
_RULE_ID = re.compile(r"[a-z0-9]+([.\-][a-z0-9]+)*")


def validate_rules(registry) -> list[str]:
    """Validate every registered rule's identity, taxonomy and evidence declaration.

    Duplicate ids are already impossible (RuleRegistry.register raises), so this covers
    the rest of §13's contract: a stable id, a real shard, a real severity/detection
    method, callable detection logic, a monotonic version, and enough metadata that a
    reader can tell what evidence the rule needs and which framework it answers to.
    """
    problems: list[str] = []
    shards = set(registry.shard_names())
    for rule in registry.rules.all():
        where = f"rule {rule.id!r}"
        if not rule.id or not _RULE_ID.fullmatch(rule.id):
            problems.append(f"{where}: id is not a stable lowercase-hyphenated identifier")
        if rule.owning_shard not in shards:
            problems.append(f"{where}: owning_shard {rule.owning_shard!r} is not a "
                            f"discovered shard")
        if not isinstance(rule.severity, Severity):
            problems.append(f"{where}: severity is not a Severity")
        if not isinstance(rule.detection_method, DetectionMethod):
            problems.append(f"{where}: detection_method is not a DetectionMethod")
        if not callable(rule.check):
            problems.append(f"{where}: check is not callable")
        if not isinstance(rule.version, int) or rule.version < 1:
            problems.append(f"{where}: version must be an integer >= 1, got "
                            f"{rule.version!r}")
        if not rule.evidence_needs:
            problems.append(f"{where}: declares no evidence needs")
        if not rule.mitre and not (rule.cis or rule.nsa_cisa or rule.owasp):
            problems.append(f"{where}: has no MITRE mapping and no framework tag, it "
                            f"cannot be selected by tactic, technique or framework")
    return problems


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
    #: Taxonomy/alias problems from MITREMappingEngine.validate() (unknown technique ids,
    #: aliases pointing at missing rules).
    validation_problems: list = field(default_factory=list)
    #: Configuration-vs-discovery problems (unknown/missing/malformed shard config,
    #: dead rule overrides, unreadable config file). Kept separate from taxonomy problems
    #: so `doctor` can grade them independently.
    config_problems: list = field(default_factory=list)
    #: Rule-model problems (invalid shard/severity/detection method/framework tags).
    rule_problems: list = field(default_factory=list)

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
    config_problems: list[str] = []
    config = load_config(config_path, config_problems)
    taxonomy = load_taxonomy()

    registry = ScannerRegistry()
    loader = PluginLoader(registry, extra_packages=extra_plugin_packages)
    loader.load_builtin()
    loader.load_extras()

    # Discovery first, then validate configuration against what was discovered, then
    # apply it. Configuration can never introduce a shard, only tune a discovered one, so
    # a new shard file is live immediately and a stale config entry is reported, not
    # silently honoured.
    config_problems += validate_shard_config(registry.shard_names(), config)
    config_problems += validate_rule_overrides(registry, config)

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
        taxonomy=taxonomy, validation_problems=problems,
        config_problems=config_problems,
        rule_problems=validate_rules(registry))


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
