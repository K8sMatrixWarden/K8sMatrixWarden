"""
Configuration / shard-discovery consistency (§3).

Discovery is authoritative and configuration only tunes it, so a new shard file works with
no config edit. The failure mode that fix must not reintroduce is silence: an operator who
disables `secrets` and gets no effect (because they typed `secret`, or `enable`, or the
block twice) has to be told, not ignored.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden import bootstrap
from k8smatrixwarden.bootstrap import (DuplicateKeyError, build_platform, load_config,
                                       validate_rule_overrides, validate_shard_config)


def _write(payload: str) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    fh.write(payload)
    fh.close()
    return fh.name


def test_shipped_configuration_is_consistent_with_discovery():
    """The regression this section exists for: `log_analysis` shipped as a shard with no
    config entry, so it could not be toggled and nothing said so."""
    platform = build_platform()
    assert platform.config_problems == []
    configured = set(platform.config["shards"])
    assert configured == set(platform.registry.shard_names())


def test_every_discovered_shard_is_configurable():
    platform = build_platform()
    for name in platform.registry.shard_names():
        assert name in platform.config["shards"], f"{name} has no configuration entry"


def test_unknown_configured_shard_is_reported():
    problems = validate_shard_config(["secrets"], {"shards": {"secrets": {},
                                                             "ghost_shard": {}}})
    assert any("unknown shard 'ghost_shard'" in p for p in problems)


def test_missing_shard_entry_is_reported_but_the_shard_still_runs():
    problems = validate_shard_config(["secrets", "rbac_identity"],
                                     {"shards": {"secrets": {}}})
    assert any("rbac_identity" in p and "no entry in config" in p for p in problems)
    # Defaulting, not failing: the shard is still enabled.
    assert "defaulting to enabled" in " ".join(problems)


def test_unknown_key_in_a_shard_block_is_reported():
    problems = validate_shard_config(["secrets"], {"shards": {"secrets": {"enable": True}}})
    assert any("unknown config key 'enable'" in p for p in problems)


def test_wrong_type_in_a_shard_block_is_reported():
    problems = validate_shard_config(["secrets"],
                                     {"shards": {"secrets": {"enabled": "yes"}}})
    assert any("must be bool" in p for p in problems)


def test_malformed_shard_block_is_reported():
    problems = validate_shard_config(["secrets"], {"shards": {"secrets": ["enabled"]}})
    assert any("must be an object" in p for p in problems)
    assert validate_shard_config(["secrets"], {"shards": "nope"})


def test_duplicate_shard_key_is_rejected_not_silently_last_wins():
    path = _write('{"shards": {"secrets": {"enabled": true}, '
                  '"secrets": {"enabled": false}}}')
    try:
        bootstrap._load_json(path, strict=True)
        assert False, "expected DuplicateKeyError"
    except DuplicateKeyError as exc:
        assert "secrets" in str(exc)
    finally:
        os.unlink(path)


def test_unreadable_override_is_reported_not_raised():
    path = _write("{not json at all")
    problems = []
    try:
        config = load_config(path, problems)
    finally:
        os.unlink(path)
    assert config, "the shipped defaults must still load"
    assert any("could not be loaded" in p for p in problems)


def test_a_bad_override_file_does_not_break_platform_construction():
    path = _write("{oops")
    try:
        platform = build_platform(path)
    finally:
        os.unlink(path)
    assert platform.rule_count() > 0                      # scanning still works
    assert any("could not be loaded" in p for p in platform.config_problems)


def test_dead_rule_override_is_reported():
    platform = build_platform()
    problems = validate_rule_overrides(platform.registry,
                                       {"rule_overrides": {"no-such-rule": {}}})
    assert any("unknown rule id" in p for p in problems)


def test_invalid_severity_in_a_rule_override_is_reported():
    platform = build_platform()
    rid = platform.registry.rules.all()[0].id
    problems = validate_rule_overrides(
        platform.registry, {"rule_overrides": {rid: {"severity": "SPICY"}}})
    assert any("invalid severity" in p for p in problems)


def test_a_newly_discovered_shard_is_enabled_and_flagged_as_unconfigured():
    """Simulates dropping in a new shard file: it runs immediately (no config edit
    needed) and the mismatch is surfaced rather than silently accepted."""
    platform = build_platform()
    names = platform.registry.shard_names() + ["brand_new_shard"]
    problems = validate_shard_config(names, platform.config)
    assert any("brand_new_shard" in p for p in problems)
    assert not any("unknown shard" in p for p in problems)


def test_disabling_a_shard_actually_removes_its_rules():
    path = _write(json.dumps({"shards": {"secrets": {"enabled": False}}}))
    try:
        platform = build_platform(path)
    finally:
        os.unlink(path)
    enabled = {r.id for r in platform.registry.rules.enabled()}
    secrets = {r.id for r in platform.registry.rules.by_shard("secrets")}
    assert secrets and not (secrets & enabled)
