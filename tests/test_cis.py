"""CIS Kubernetes Benchmark v1.8 engine, full 130-control coverage (§5.9) + mitigation."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.evidence import build_component_config
from k8smatrixwarden.frameworks.cis import FAIL, NA, NEEDS_NODE, PASS, CISBenchmarkEngine
from k8smatrixwarden.frameworks.cis_catalog import CIS_1_8, catalog_summary
from k8smatrixwarden.frameworks.kube_bench_adapter import parse_kube_bench_json


def _report(kb=None, profile="self-managed"):
    p = build_platform()
    return CISBenchmarkEngine(p).evaluate(p.make_collector(mock=True),
                                          kube_bench_results=kb, profile=profile)


def test_catalog_has_exactly_130_controls():
    assert len(CIS_1_8) == 130
    s = catalog_summary()
    assert s["by_section"] == {"1": 60, "2": 7, "3": 5, "4": 23, "5": 35}


def test_eval_split_after_mitigation():
    # 25 native + 2 builtin + 38 component = 65 API-evaluated; 31 file; 34 manual.
    ev = catalog_summary()["by_eval"]
    assert ev["native"] == 25
    assert ev["builtin"] == 2
    assert ev["component"] == 38
    assert ev["kube-bench"] == 31
    assert ev["manual"] == 34


def test_no_duplicate_control_ids():
    ids = [c.id for c in CIS_1_8]
    assert len(ids) == len(set(ids))


def test_every_control_gets_a_status():
    report = _report()
    assert len(report.results) == 130
    assert all(r.status in {PASS, FAIL, "MANUAL", NA, NEEDS_NODE} for r in report.results)
    assert sum(report.counts.values()) == 130


def test_mitigation_shrinks_needs_node_to_file_controls_only():
    # After Layer 1/2, only the 31 file-permission controls remain NEEDS_NODE.
    report = _report()
    assert report.counts[NEEDS_NODE] == 31
    for r in report.results:
        if r.status == NEEDS_NODE:
            assert r.control.ev == "kube-bench"       # never a flag control


def test_component_controls_evaluated_from_flags():
    report = _report()
    st = {r.control.id: r.status for r in report.results}
    # mock apiServer has profiling=true -> 1.2.16 FAIL; service-account-lookup=true -> 1.2.22 PASS
    assert st["1.2.16"] == FAIL
    assert st["1.2.22"] == PASS
    # etcd auto-tls=true -> 2.3 FAIL ; scheduler bind-address=127.0.0.1 -> 1.4.2 PASS
    assert st["2.3"] == FAIL
    assert st["1.4.2"] == PASS


def test_native_controls_flag_planted_issues():
    failed = {r.control.id for r in _report().results if r.status == FAIL}
    assert {"5.2.2", "5.1.3", "5.1.1", "5.3.2"} <= failed


def test_managed_profile_marks_control_plane_na():
    report = _report(profile="eks")
    for r in report.results:
        if r.control.section in {"1", "2", "3"}:
            assert r.status == NA
        # worker + policy sections still graded
    assert report.counts[NA] == 72          # 60 + 7 + 5
    assert report.by_section["5"][NA] == 0


def test_kube_bench_json_resolves_file_controls():
    before = {r.control.id: r.status for r in _report().results}
    assert before["1.1.1"] == NEEDS_NODE       # file control, node-only
    assert before["4.1.1"] == NEEDS_NODE

    kb_doc = {"Controls": [{"tests": [{"results": [
        {"test_number": "1.1.1", "status": "PASS"},
        {"test_number": "4.1.1", "status": "FAIL"},
    ]}]}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(kb_doc, fh)
        path = fh.name
    kb = parse_kube_bench_json(path)
    os.unlink(path)
    assert kb == {"1.1.1": "PASS", "4.1.1": "FAIL"}

    after = {r.control.id: r.status for r in _report(kb=kb).results}
    assert after["1.1.1"] == PASS
    assert after["4.1.1"] == FAIL


def test_live_component_config_parses_static_pod_flags():
    # Layer 1: control-plane flags recovered from kube-system static-pod specs.
    pods = [{
        "metadata": {"name": "kube-apiserver-master", "namespace": "kube-system"},
        "spec": {"containers": [{"name": "kube-apiserver", "command": [
            "kube-apiserver", "--anonymous-auth=false", "--profiling=false",
            "--authorization-mode=Node,RBAC"]}]},
    }]
    cc = build_component_config(pods)
    flags = cc["spec"]["apiServer"]["flags"]
    assert flags["anonymous-auth"] == "false"
    assert flags["profiling"] == "false"
    assert flags["authorization-mode"] == "Node,RBAC"
    assert cc["spec"]["apiServer"]["anonymousAuth"] is False


def test_cis_tags_align_with_catalog():
    p = build_platform()
    for c in CIS_1_8:
        if c.ev != "native":
            continue
        for rid in c.rules:
            rule = p.registry.rules.get(rid)
            assert rule is not None, f"{c.id} refs missing rule {rid}"
            assert c.id in rule.cis, f"rule {rid} missing cis tag {c.id} (has {rule.cis})"
