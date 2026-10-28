"""Scanning YAML before deploy: same rules, scores and exposure analysis, no cluster."""
import os
import textwrap

import pytest

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.manifests import MANIFEST_MODULES, ManifestEvidenceCollector
from k8smatrixwarden.core.models import ScanRequest, Selector

APP = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - {name: app, image: "nginx:latest", securityContext: {privileged: true}}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80}]}
"""


def _scan(path, **kw):
    p = build_platform()
    col = ManifestEvidenceCollector([str(path)], **kw)
    req = ScanRequest(selector=Selector(modules=list(MANIFEST_MODULES)))
    return ScannerAgent(p).scan(req, col, mode_label="manifests"), col


def test_a_privileged_deployment_behind_a_load_balancer_is_found_and_marked_exposed(tmp_path):
    (tmp_path / "app.yaml").write_text(APP)
    result, col = _scan(tmp_path)
    f = next(f for f in result.findings if f.rule_id == "workload-privileged-container")
    assert f.resource.name == "web" and f.resource.namespace == "shop"
    assert "ingress" in f.exploitable_by, "the Service selector must reach the Deployment's pods"
    assert col.cluster_label().startswith("manifests:")


def test_objects_without_a_namespace_land_in_default_and_lists_are_unrolled(tmp_path):
    (tmp_path / "l.yaml").write_text(textwrap.dedent("""
        apiVersion: v1
        kind: List
        items:
        - {apiVersion: v1, kind: Pod, metadata: {name: p}, spec: {containers: [{name: c, image: x:1}]}}
    """))
    _, col = _scan(tmp_path)
    pod = col._data["pods"][0]
    assert pod["metadata"]["namespace"] == "default"


def test_bad_files_are_noted_and_an_empty_folder_is_an_error(tmp_path):
    (tmp_path / "bad.yaml").write_text("a: [unclosed")
    (tmp_path / "ok.yaml").write_text(APP)
    col = ManifestEvidenceCollector([str(tmp_path)])
    assert any("bad.yaml" in s for s in col.skipped)
    with pytest.raises(RuntimeError, match="no Kubernetes manifests"):
        ManifestEvidenceCollector([str(tmp_path / "bad.yaml")])


def test_helm_chart_without_helm_is_skipped_with_a_note(tmp_path, monkeypatch):
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: c\nversion: 1\n")
    (chart / "templates" / "d.yaml").write_text("kind: Deployment\nmetadata: {name: {{ .Release.Name }}}\n")
    (tmp_path / "plain.yaml").write_text(APP)
    monkeypatch.setattr("shutil.which", lambda *_: None)
    col = ManifestEvidenceCollector([str(tmp_path)])
    assert any("helm" in s for s in col.skipped) and col._data.get("deployments")


def test_check_is_scan_with_sensible_defaults_and_gates_ci(tmp_path, capsys):
    from k8smatrixwarden.cli.main import _check_to_scan, main
    a = _check_to_scan([str(tmp_path), "--fail-on", "HIGH"])
    assert a[:4] == ["scan", "-y", "-o", "brief"] and "--manifests" in a and "--no-save" in a
    assert "--live" in _check_to_scan([]) and "--live" not in a
    (tmp_path / "app.yaml").write_text(APP)
    assert main(["check", str(tmp_path), "--fail-on", "HIGH"]) == 1
    assert "Fix these first" in capsys.readouterr().out
    (tmp_path / ".ignore.json").write_text("{}")                       # a non-manifest file is harmless
    assert main(["check", str(tmp_path), "--fail-on", "HIGH", "--baseline", "zzz-missing"]) == 2


def test_pr_comment_lists_only_new_findings_with_fixes(tmp_path, capsys):
    from k8smatrixwarden.cli.main import main
    (tmp_path / "base").mkdir()
    (tmp_path / "base" / "a.yaml").write_text(APP.replace("privileged: true", "privileged: false"))
    main(["check", str(tmp_path / "base"), "-o", "json", "--output-file", str(tmp_path / "base.json")])
    (tmp_path / "head").mkdir()
    (tmp_path / "head" / "a.yaml").write_text(APP)
    code = main(["check", str(tmp_path / "head"), "--baseline", str(tmp_path / "base.json"),
                 "--fail-on", "HIGH", "--comment-file", str(tmp_path / "c.md")])
    md = (tmp_path / "c.md").read_text()
    assert code == 1 and "new finding(s) in this change" in md and "Privileged container" in md
    assert "Blocking" in md and "Remove `privileged: true`" in md
