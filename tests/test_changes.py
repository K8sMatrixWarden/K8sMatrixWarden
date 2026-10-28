"""What changed since the last scan, and which changes make the cluster easier to attack."""
from k8smatrixwarden.core.changes import diff


def _wl(name, **kw):
    return {"namespace": "shop", "kind": "Deployment", "name": name, "images": ["app:1.0"], "flags": [],
            "internet": False, "desired": 2, "sa": "default", **kw}


def _inv(workloads=(), services=(), bindings=(), namespaces=()):
    return {"sections": {"workloads": list(workloads), "services": list(services),
                         "bindings": list(bindings), "namespaces": list(namespaces)}}


def test_new_privileged_internet_workload_and_image_change_are_reported_and_risky():
    before = _inv([_wl("web"), _wl("old")])
    after = _inv([_wl("web", images=["app:latest"]), _wl("api", flags=["privileged"], internet=True)])
    items = diff(before, after)
    by = {(i["name"], i["kind"]): i for i in items}
    assert by[("api", "added")]["risky"] and "privileged" in by[("api", "added")]["summary"]
    assert by[("web", "changed")]["risky"] and "app:latest" in by[("web", "changed")]["summary"]
    assert ("old", "removed") in by and not by[("old", "removed")]["risky"]
    assert items[0]["risky"], "risky changes sort first"


def test_exposure_access_and_policy_regressions():
    before = _inv([_wl("web")], [{"namespace": "shop", "name": "web", "type": "ClusterIP", "external": False}],
                  [], [{"name": "shop", "policies": 2, "psa": "restricted", "system": False}])
    after = _inv([_wl("web", internet=True)], [{"namespace": "shop", "name": "web", "type": "LoadBalancer", "external": True}],
                 [{"kind": "ClusterRoleBinding", "name": "x", "namespace": None, "role": "cluster-admin",
                   "subjects": ["User bob"], "grants": ["everything"], "builtin": False}],
                 [{"name": "shop", "policies": 0, "psa": "baseline", "system": False}])
    text = " | ".join(i["summary"] for i in diff(before, after) if i["risky"])
    for needle in ("became reachable from the Internet", "open to the outside", "cluster-admin", "lost all its network rules", "restricted Pod Security"):
        assert needle in text, needle


def test_no_previous_or_old_scan_means_no_changes_not_an_error():
    assert diff({}, _inv([_wl("a")])) == [] and diff(_inv([_wl("a")]), {}) == []
