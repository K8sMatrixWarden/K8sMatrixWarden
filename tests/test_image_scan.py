"""Grype image-vulnerability evidence: scanned by the digest that runs, never by the tag."""
import json
import types

from k8smatrixwarden.core.evidence import Evidence
from k8smatrixwarden.core.image_scan import GrypeRunner, build_image_evidence, parse_grype, running_images
from k8smatrixwarden.core.models import Scope, ScopeLevel
from k8smatrixwarden.bootstrap import build_platform

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


def _pod(name, digest, image="registry.example/app:1.0"):
    return {"kind": "Pod", "metadata": {"name": name, "namespace": "prod"},
            "spec": {"containers": [{"name": "app", "image": image}]},
            "status": {"containerStatuses": [{"name": "app", "image": image,
                                              "imageID": f"registry.example/app@{digest}"}]}}


def _grype(*matches):
    return {"descriptor": {"db": {"status": {"built": "2099-01-01T00:00:00Z"}}},
            "matches": [{"vulnerability": {"id": i, "severity": s, "fix": {"state": f, "versions": []},
                                           "knownExploited": [{"cveID": i}] if kev else [],
                                           "epss": [{"epss": 0.4}]},
                         "artifact": {"name": "openssl", "version": "1.0", "type": "deb"}}
                        for i, s, f, kev in matches]}


def _ev(items, pods):
    return Evidence({"imagevulnerability": items, "pods": pods}, Scope(ScopeLevel.CLUSTER))


def _item(digest, doc):
    return {"kind": "ImageVulnerability", "metadata": {"name": digest},
            "spec": {"image": "registry.example/app:1.0", "digest": digest, **parse_grype(doc)}}


def _run(ev):
    rule = build_platform().registry.rules.get("workload-image-vulnerabilities")
    return list(rule.check(rule, ev, None))


def test_same_tag_two_digests_are_scanned_separately():
    imgs = running_images([_pod("old", OLD), _pod("new", NEW)])
    assert set(imgs) == {OLD, NEW}
    assert imgs[OLD]["target"].endswith("@" + OLD)


def test_local_import_digest_falls_back_to_the_tag():
    # Docker Desktop / kind report an unrelated local-import ref; its digest is not in the
    # image's own registry, so the target must be the pullable tag, not repo@local-digest.
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "kube-system"},
           "spec": {"containers": [{"name": "app", "image": "registry.k8s.io/kube-apiserver:v1.36.1"}]},
           "status": {"containerStatuses": [{"name": "app", "image": "registry.k8s.io/kube-apiserver:v1.36.1",
                                             "imageID": f"docker.io/library/import-2026-06-02@{OLD}"}]}}
    img = next(iter(running_images([pod]).values()))
    assert img["pinned"] is False
    assert img["target"] == "registry.k8s.io/kube-apiserver:v1.36.1"


def test_patched_rebuild_is_clear_and_stale_copy_is_flagged():
    items = [_item(OLD, _grype(("CVE-1", "Critical", "fixed", False))), _item(NEW, _grype())]
    found = _run(_ev(items, [_pod("old", OLD), _pod("new", NEW)]))
    assert [f.resource.name for f in found] == ["old"]
    assert found[0].severity.label == "CRITICAL"


def test_known_exploited_outranks_and_unfixable_low_noise_is_ignored():
    kev = _item(OLD, _grype(("CVE-2", "Medium", "not-fixed", True)))
    assert _run(_ev([kev], [_pod("p", OLD)]))[0].severity.label == "CRITICAL"
    quiet = _item(OLD, _grype(("CVE-3", "High", "not-fixed", False), ("CVE-4", "Low", "fixed", False)))
    assert _run(_ev([quiet], [_pod("p", OLD)])) == []


def test_unscanned_image_is_not_reported_as_clean_or_vulnerable():
    err = {"kind": "ImageVulnerability", "metadata": {"name": OLD},
           "spec": {"image": "x", "digest": OLD, "error": "registry unreachable"}}
    assert _run(_ev([err], [_pod("p", OLD)])) == []


def test_runner_failure_is_a_warning_and_caching_is_by_digest(tmp_path):
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(_grype(("C", "High", "fixed", False))), stderr="")
    runner = GrypeRunner(cache_dir=str(tmp_path), run=fake)
    items, warns = build_image_evidence([_pod("p", OLD)], runner)
    build_image_evidence([_pod("p", OLD)], runner)
    assert len(calls) == 1 and not warns and items[0]["spec"]["matches"][0]["id"] == "C"
    bad = GrypeRunner(cache_dir=str(tmp_path), run=lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr="boom"))
    _, warns = build_image_evidence([_pod("q", NEW)], bad)
    assert "could not scan" in warns[0]


def test_inventory_lists_images_with_counts_and_says_nothing_when_unscanned():
    from collections import defaultdict
    from k8smatrixwarden.core.cluster_inventory import _image_rows
    items = [_item(OLD, _grype(("CVE-1", "Critical", "fixed", True), ("CVE-2", "High", "not-fixed", False)))]
    groups = defaultdict(list, {("prod", "Deployment", "app"): [_pod("p", OLD)]})
    row = _image_rows(_ev(items, [_pod("p", OLD)]), groups)[0]
    assert (row["kev"], row["fixable"], row["counts"]["Critical"]) == (1, 1, 1)
    assert row["workloads"] == ["prod/Deployment/app"] and row["top"][0]["id"] == "CVE-1"
    assert _image_rows(_ev([], [_pod("p", OLD)]), groups) == []


def _scenario(exposed):
    from tests import fixtures_scenarios as fx
    c = fx.scenario_a()
    c["pods"][0]["spec"]["containers"][0]["securityContext"] = {}      # only the CVE finding
    c["pods"][0]["status"] = {"containerStatuses": [{"name": "app", "image": "app:1.0",
                                                     "imageID": f"reg/app@{OLD}"}]}
    c["imagevulnerability"] = [_item(OLD, _grype(("CVE-9", "Critical", "fixed", False)))]
    if not exposed:
        c["ingresses"] = []
    return c


def _cve_finding(exposed):
    from tests.test_integration_pipeline import _scan, _finding
    result, platform = _scan(_scenario(exposed))
    return result, platform, _finding(result, "workload-image-vulnerabilities", "payment-api")


def test_a_cve_on_an_exposed_pod_outranks_the_same_cve_on_an_isolated_one_and_joins_its_path():
    from k8smatrixwarden.core.threat_matrix import attack_paths, build_threat_matrix
    result, platform, hot = _cve_finding(True)
    _, _, cold = _cve_finding(False)
    assert "ingress" in hot.exploitable_by and hot.score > cold.score
    ap = attack_paths(build_threat_matrix(result, platform.registry.rules), result.runtime,
                      cluster=result.cluster_name)
    assert any(f.rule_id == "workload-image-vulnerabilities"
               for p in ap["resource_paths"] for f in p.get("findings", []) if hasattr(f, "rule_id")) \
        or "workload-image-vulnerabilities" in json.dumps(ap["resource_paths"], default=str)


def test_exploitability_follows_kev_and_epss():
    from k8smatrixwarden.shards.workload_pod_security import _vuln_exploitability as ex
    labels = [ex([1], 0).label, ex([], 0.6).label, ex([], 0.1).label, ex([], 0.0).label]
    assert labels == ["Remote", "Remote", "Adjacent", "Local"]
