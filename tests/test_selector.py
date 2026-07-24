"""Selector resolution, the single choke point (§7.2, §7.3)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.mapping_engine import SelectorResolutionError
from k8smatrixwarden.core.models import Selector


def _p():
    return build_platform()


def test_empty_selector_resolves_to_all_enabled_rules():
    p = _p()
    ids = p.mapping.resolve(Selector())
    assert len(ids) == len(p.registry.rules.enabled())


def test_tactic_slice_spans_multiple_shards():
    p = _p()
    ids = p.mapping.resolve(Selector(tactics=["Persistence"]))
    shards = {p.registry.rules.get(i).owning_shard for i in ids}
    assert len(shards) >= 2                       # column-slice crosses shards
    assert "workload_pod_security" in shards


def test_module_slice_is_single_shard():
    p = _p()
    ids = p.mapping.resolve(Selector(modules=["rbac_identity"]))
    shards = {p.registry.rules.get(i).owning_shard for i in ids}
    assert shards == {"rbac_identity"}


def test_composite_alias_expands():
    p = _p()
    ids = p.mapping.resolve(Selector(techniques=["Container Escape"]))
    assert "workload-privileged-container" in ids
    assert "workload-docker-socket" in ids


def test_single_rule_id():
    p = _p()
    ids = p.mapping.resolve(Selector(rule_ids=["workload-privileged-container"]))
    assert ids == ["workload-privileged-container"]


def test_framework_slice():
    p = _p()
    ids = p.mapping.resolve(Selector(frameworks=["CIS"]))
    assert all(p.registry.rules.get(i).cis for i in ids)
    assert len(ids) > 0


def test_union_semantics_dedup():
    p = _p()
    # secrets module ∪ Credential Access tactic, overlapping, must dedupe.
    ids = p.mapping.resolve(Selector(modules=["secrets"],
                                     tactics=["Credential Access"]))
    assert len(ids) == len(set(ids))


def test_unknown_selector_raises_not_silent_empty():
    p = _p()
    with pytest.raises(SelectorResolutionError):
        p.mapping.resolve(Selector(tactics=["Nonsense Tactic"]))


def test_severity_min_filters():
    p = _p()
    from k8smatrixwarden.core.models import Severity
    ids = p.mapping.resolve(Selector(severity_min=Severity.CRITICAL))
    assert all(p.registry.rules.get(i).severity == Severity.CRITICAL for i in ids)
