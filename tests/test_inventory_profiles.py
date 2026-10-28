"""The cluster inventory carries what the dashboard's drill-down profiles need."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector


def _inv():
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                                         mode=ScanMode.SYNC), p.make_collector(mock=True))
    return r.cluster_inventory["sections"]


def test_every_pod_links_to_its_workload_and_carries_container_security_facts():
    s = _inv()
    wl_ids = {w["id"] for w in s["workloads"]}
    assert s["pods"]
    for pod in s["pods"]:
        assert pod["workload"] in wl_ids
        for c in pod["containers"]:
            assert {"privileged", "root", "read_only_fs", "caps_add", "limits"} <= set(c)
        assert pod["ingress_policy"] and pod["egress_policy"]


def test_privileged_pod_is_flagged_and_its_workload_reports_egress_posture():
    s = _inv()
    assert any(p["containers"] and p["containers"][0]["privileged"] for p in s["pods"])
    for w in s["workloads"]:
        assert "egress_policy" in w and "services" in w and "ingresses" in w


def test_namespace_rows_roll_up_exposure_and_policy_gaps():
    for n in _inv()["namespaces"]:
        assert {"exposed", "open_ingress", "open_egress", "unhealthy", "privileged"} <= set(n)
