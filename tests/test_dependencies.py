"""Dependency manager: SBOM normalising, direct/indirect, runtime use, and the store's caching."""
import json
import subprocess

from k8smatrixwarden.core import dependencies as D
from k8smatrixwarden.core.image_scan import parse_grype

SYFT = {
    "distro": {"prettyName": "Alpine Linux v3.8"},
    "artifacts": [
        {"id": "a", "name": "libverto", "version": "1", "type": "apk", "locations": [{"path": "/lib/apk/db/installed"}],
         "metadata": {"files": [{"path": "/usr/lib/libverto.so.1"}]}},
        {"id": "b", "name": "krb5-libs", "version": "2", "type": "apk", "locations": [{"path": "/lib/apk/db/installed"}],
         "metadata": {"files": [{"path": "/usr/lib/libkrb5.so"}]}},
        {"id": "c", "name": "log4j-core", "version": "2.14.1", "type": "java-archive",
         "locations": [{"path": "/app/app.jar", "accessPath": "/app/app.jar:BOOT-INF/lib/log4j-core-2.14.1.jar"}], "metadata": {}},
        {"id": "d", "name": "flask", "version": "3", "type": "python", "locations": [{"path": "/usr/lib/python3/site-packages/flask"}],
         "metadata": {}},
    ],
    "artifactRelationships": [{"parent": "a", "child": "b", "type": "dependency-of"}],
}
GRYPE = {"matches": [{"vulnerability": {"id": "CVE-2021-44228", "severity": "Critical", "fix": {"state": "fixed", "versions": ["2.15.0"]}},
                      "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"}}]}


def test_direct_and_indirect_come_from_the_relationships_and_unknown_is_not_guessed():
    kinds = {p["name"]: p["kind"] for p in D.normalize(SYFT)["packages"]}
    assert kinds["libverto"] == "indirect" and kinds["krb5-libs"] == "direct"      # libverto is needed by krb5-libs
    assert kinds["log4j-core"] == "unknown" and kinds["flask"] == "unknown"        # no relationships recorded for them


def test_a_jar_inside_a_jar_is_marked_nested():
    pk = {p["name"]: p for p in D.normalize(SYFT)["packages"]}
    assert pk["log4j-core"]["nested"] and not pk["libverto"]["nested"]


def test_usage_never_claims_unused_for_what_it_cannot_see():
    pk = {p["name"]: p for p in D.normalize(SYFT)["packages"]}
    assert D.usage_of(pk["libverto"], None) == "not-observed"
    assert D.usage_of(pk["libverto"], {"/usr/lib/libverto.so.1"}) == "in-use"
    assert D.usage_of(pk["libverto"], {"/other"}) == "not-seen"
    assert D.usage_of(pk["log4j-core"], {"/app/app.jar"}) == "in-running-archive"
    assert D.usage_of(pk["flask"], {"/other"}) == "cannot-tell"                    # Python modules are not visible in /proc


def test_report_puts_vulnerable_and_loaded_first_and_counts_fix_first():
    vulns = parse_grype(GRYPE)
    rep = D.report(D.normalize(SYFT), vulns, {"/app/app.jar"})
    assert rep["packages"][0]["name"] == "log4j-core" and rep["packages"][0]["worst"] == "Critical"
    assert rep["summary"]["fixFirst"] == 1 and rep["summary"]["observed"]
    assert D.report(D.normalize(SYFT), vulns, None)["summary"]["observed"] is False


def test_parse_observation_keeps_only_files_and_commands():
    out = D.parse_observation("C java -jar /app/app.jar\nF /app/app.jar\nF /lib/ld-musl.so\nnoise\n")
    assert out["files"] == ["/app/app.jar", "/lib/ld-musl.so"] and out["commands"] == ["java -jar /app/app.jar"]


def test_search_finds_a_package_across_images():
    stores = {"k1": {"image": "a:1", "workloads": [{"namespace": "x", "kind": "Deployment", "name": "w"}],
                     "packages": D.normalize(SYFT)["packages"]}}
    hits = D.search(stores, "log4j")
    assert len(hits) == 1 and hits[0]["workloads"][0]["name"] == "w" and D.search(stores, "") == []


def test_store_caches_by_digest_and_refuses_bad_output(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/bin/" + b)
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(SYFT), stderr="")
    store = D.SbomStore(cache_dir=str(tmp_path), run=run)
    img = {"digest": "sha256:" + "a" * 64, "target": "repo@sha256:" + "a" * 64}
    assert store.generate(img)["cached"] is False and store.generate(img)["cached"] is True
    assert len(calls) == 1 and store.load(img["digest"])["packages"]
    bad = D.SbomStore(cache_dir=str(tmp_path / "b"), run=lambda c, **k: subprocess.CompletedProcess(c, 0, stdout="not json", stderr=""))
    assert "error" in bad.generate({"digest": "d", "target": "t"}) and not bad.has("d")


def test_inventory_groups_pods_by_image_and_names_the_deployment():
    pod = {"metadata": {"namespace": "x", "name": "web-5f8b7c9d6-abcde",
                        "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5f8b7c9d6"}]},
           "status": {"containerStatuses": [{"name": "c", "image": "nginx:1", "imageID": "docker-pullable://nginx@sha256:" + "b" * 64,
                                             "state": {"running": {}}}]}}
    inv = D.inventory([pod])
    assert len(inv) == 1 and inv[0]["workloads"] == [{"namespace": "x", "kind": "Deployment", "name": "web"}]
