"""Network topology graph: exposure paths and NetworkPolicy-mediated pod-to-pod edges."""
import os

from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.models import Scope, ScopeLevel
from k8smatrixwarden.core.topology import build_topology


def _pod(name, ns, **labels):
    return {"kind": "Pod", "metadata": {"name": name, "namespace": ns, "labels": labels}}


def _svc(name, ns, selector, stype="ClusterIP"):
    return {"kind": "Service", "metadata": {"name": name, "namespace": ns},
            "spec": {"type": stype, "selector": selector}}


def _topo(**buckets):
    return build_topology(Evidence(buckets, Scope(ScopeLevel.CLUSTER)))


def _edges(t, kind):
    return {(e["from"], e["to"]) for e in t["edges"] if e["kind"] == kind}


def _cluster(**extra):
    base = dict(
        namespaces=[{"metadata": {"name": "prod"}}],
        pods=[_pod("web-1", "prod", app="web"), _pod("db-1", "prod", app="db"),
              _pod("evil-1", "prod", app="evil")],
        services=[_svc("web", "prod", {"app": "web"}, "LoadBalancer"),
                  _svc("db", "prod", {"app": "db"})])
    base.update(extra)
    return base


def test_loadbalancer_service_exposes_its_backing_workload_to_the_internet():
    t = _topo(**_cluster())
    assert ("internet", "prod/Service/web") in _edges(t, "exposes")
    assert ("prod/Service/web", "prod/Pod/web-1") in _edges(t, "routes-to")
    assert t["summary"]["internet_exposed"] == ["prod/Pod/web-1"]


def test_a_clusterip_service_is_not_internet_exposed():
    t = _topo(**_cluster())
    assert "prod/Pod/db-1" not in t["summary"]["internet_exposed"]


def test_endpointslice_evidence_overrides_the_selector():
    sl = {"metadata": {"name": "db-x", "namespace": "prod",
                       "labels": {"kubernetes.io/service-name": "db"}},
          "endpoints": [{"targetRef": {"kind": "Pod", "name": "evil-1"}}]}
    t = _topo(**_cluster(endpointslices=[sl]))
    routes = [e for e in t["edges"] if e["from"] == "prod/Service/db"]
    assert [(e["to"], e["evidence"]) for e in routes] == [("prod/Pod/evil-1", "endpointslice")]


def test_ingress_routes_to_a_service():
    ing = {"metadata": {"name": "i", "namespace": "prod"},
           "spec": {"rules": [{"http": {"paths": [
               {"backend": {"service": {"name": "db"}}}]}}]}}
    t = _topo(**_cluster(ingresses=[ing]))
    assert ("prod/Ingress/i", "prod/Service/db") in _edges(t, "routes-to")
    assert "prod/Pod/db-1" in t["summary"]["internet_exposed"]


def test_a_policy_admits_only_the_named_peer():
    pol = {"metadata": {"name": "db-from-web", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "db"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}]}}
    t = _topo(**_cluster(networkpolicies=[pol]))
    allowed = _edges(t, "allowed")
    assert ("prod/Pod/web-1", "prod/Pod/db-1") in allowed
    assert ("prod/Pod/evil-1", "prod/Pod/db-1") not in allowed
    assert "prod/Pod/db-1" in t["summary"]["isolated_workloads"]
    assert "prod/Pod/evil-1" in t["summary"]["open_workloads"]


def test_source_egress_deny_removes_the_edge():
    ing = {"metadata": {"name": "db-from-web", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}]}}
    egr = {"metadata": {"name": "web-no-egress", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Egress"]}}
    t = _topo(**_cluster(networkpolicies=[ing, egr]))
    assert ("prod/Pod/web-1", "prod/Pod/db-1") not in _edges(t, "allowed")


def test_unevaluable_policy_yields_no_edge_and_unknown_status():
    pol = {"metadata": {"name": "weird", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {"matchExpressions": [
                        {"key": "app", "operator": "Weird", "values": ["web"]}]}}]}]}}
    t = _topo(**_cluster(networkpolicies=[pol]))
    assert not _edges(t, "allowed")
    assert "prod/Pod/db-1" in t["summary"]["unknown_workloads"]


def test_replicaset_pods_collapse_into_their_deployment():
    pods = [{"metadata": {"name": f"api-abc-{i}", "namespace": "prod", "labels": {"app": "api"},
                          "ownerReferences": [{"kind": "ReplicaSet", "name": "api-abc",
                                               "controller": True}]}} for i in range(2)]
    rs = [{"metadata": {"name": "api-abc", "namespace": "prod",
                        "ownerReferences": [{"kind": "Deployment", "name": "api"}]}}]
    t = _topo(namespaces=[], pods=pods, replicasets=rs)
    w = [n for n in t["nodes"] if n["type"] == "workload"]
    assert [(n["id"], n["pods"]) for n in w] == [("prod/Deployment/api", 2)]


def test_a_scan_carries_the_topology_and_survives_a_round_trip():
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    from k8smatrixwarden.core.results import ScanResult
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    assert r.topology["summary"]["workloads"] == 5
    assert ScanResult.from_dict(r.as_dict()).topology == r.topology


def _ip_pod(name, ip, **labels):
    p = _pod(name, "prod", **labels)
    p["status"] = {"podIP": ip}
    return p


def test_an_ipblock_peer_admits_a_pod_by_its_ip_unless_excepted():
    pol = {"metadata": {"name": "db-from-cidr", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/24",
                                                       "except": ["10.0.0.9/32"]}}]}]}}
    t = _topo(namespaces=[], networkpolicies=[pol], pods=[
        _ip_pod("db-1", "10.1.0.1", app="db"), _ip_pod("web-1", "10.0.0.5", app="web"),
        _ip_pod("evil-1", "10.0.0.9", app="evil"), _ip_pod("far-1", "192.168.0.1", app="far")])
    allowed = _edges(t, "allowed")
    assert ("prod/Pod/web-1", "prod/Pod/db-1") in allowed
    assert ("prod/Pod/evil-1", "prod/Pod/db-1") not in allowed
    assert ("prod/Pod/far-1", "prod/Pod/db-1") not in allowed
    assert t["nodes"][1:] and "10.1.0.1" in next(
        n for n in t["nodes"] if n["id"] == "prod/Pod/db-1")["ips"]


def test_a_pod_without_an_ip_is_unknown_to_an_ipblock_not_denied():
    pol = {"metadata": {"name": "p", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/24"}}]}]}}
    t = _topo(namespaces=[], networkpolicies=[pol],
              pods=[_pod("db-1", "prod", app="db"), _pod("web-1", "prod", app="web")])
    assert not _edges(t, "allowed")


def test_a_large_cluster_is_still_scanned_and_the_count_is_exact(monkeypatch):
    import k8smatrixwarden.core.topology as topo
    monkeypatch.setattr(topo, "MAX_EDGES_LISTED", 3)
    pol = {"metadata": {"name": "p", "namespace": "prod"},
           "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {}}]}]}}
    pods = [_pod("db-1", "prod", app="db")] + [_pod(f"c-{i}", "prod", app=f"c{i}")
                                                 for i in range(10)]
    t = _topo(namespaces=[], networkpolicies=[pol], pods=pods)
    assert t["summary"]["allowed_edges_total"] == 10
    assert len(_edges(t, "allowed")) == 3 and t["notes"]


def test_the_topology_page_and_api_render():
    import tempfile
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.web.app import WebApp
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    d = tempfile.mkdtemp()
    ReportStore(d).save(r)
    app = WebApp(p, reports_dir=d)
    page = app.route("GET", "/graph", query=f"scan_id={r.scan_id}")
    assert page.status == 200 and b"/vendor/cytoscape.min.js" in page.body
    assert app.route("GET", f"/api/report/{r.scan_id}/topology").status == 200


def test_the_security_graph_data_dedupes_issues_and_carries_attack_paths():
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    from k8smatrixwarden.web.graph_page import build_graph
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(), p.make_collector(
        mock=True, fixture=os.path.join(os.path.dirname(__file__), "..", "eval", "dvka",
                                        "cluster_fixture.json")))
    g = build_graph(r)
    frontend = g["issues"]["dvka-vuln/Deployment/ap-frontend"]
    assert len({i["r"] for i in frontend}) == len(frontend), "one row per rule"
    assert any(p["internet"] and "dvka-vuln/Deployment/ap-frontend" in p["nodes"]
               for p in g["paths"])
    assert "internet-exposed" in next(n for n in g["nodes"]
                                      if n["id"] == "dvka-vuln/Deployment/ap-frontend")["factors"]


def test_the_cluster_inventory_answers_engineer_questions_without_secret_data():
    import json
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.core.models import ScanRequest
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(), p.make_collector(
        mock=True, fixture=os.path.join(os.path.dirname(__file__), "..", "eval", "dvka",
                                        "cluster_fixture.json")))
    inv = r.cluster_inventory
    assert set(inv["sections"]) >= {"nodes", "namespaces", "workloads", "services", "bindings", "config"}
    wl = {w["name"]: w for w in inv["sections"]["workloads"]}
    assert wl["wl-privileged"]["flags"] and "privileged" in wl["wl-privileged"]["flags"]
    assert wl["ap-frontend"]["internet"] and wl["ap-frontend"]["issues"]["n"] >= 2
    assert any(b["grants"] for b in inv["sections"]["bindings"]), "wide grants are flagged"
    assert any("NetworkPolicy" in a["title"] for a in inv["attention"])
    blob = json.dumps(inv)
    assert "S3cr3t-Passw0rd" not in blob and "hunter2" not in blob, "no secret or config values"
    # survives a store round trip
    from k8smatrixwarden.core.results import ScanResult
    assert ScanResult.from_dict(r.as_dict()).cluster_inventory == inv
