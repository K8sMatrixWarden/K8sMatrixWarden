"""Scan Kubernetes YAML before it is deployed.

The rules read an `Evidence` snapshot and do not care where it came from, so a folder of
manifests (or a rendered Helm chart) is just another collector. That gives CI the same
findings, scores and attack paths as a live cluster, with no cluster access.

What a manifest scan cannot know is stated, not guessed: there are no pod IPs, no live
ServiceAccount tokens, no control-plane flags and no running image digests. Rules about
those need a cluster and are left out of manifest scans (see `MANIFEST_MODULES`).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Optional

from .evidence import KIND_ALIASES, EvidenceCollector

#: Shards whose evidence lives in the manifests themselves.
MANIFEST_MODULES = ["workload_pod_security", "rbac_identity", "network_security", "secrets"]

_EXT = (".yaml", ".yml", ".json")
#: Kinds that are cluster-scoped; every other kind without a namespace lands in "default".
_CLUSTER_KINDS = {"Namespace", "Node", "ClusterRole", "ClusterRoleBinding", "PersistentVolume",
                  "StorageClass", "CustomResourceDefinition", "APIService",
                  "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"}


def _load_docs(text: str, name: str) -> list:
    if name.endswith(".json"):
        return [json.loads(text)]
    try:
        import yaml
    except ImportError as exc:                                  # pragma: no cover
        raise RuntimeError("Scanning manifests needs PyYAML: pip install pyyaml") from exc
    return [d for d in yaml.safe_load_all(text) if d]


class ManifestEvidenceCollector(EvidenceCollector):
    def __init__(self, paths: list[str], helm: bool = True, helm_set: Optional[list] = None):
        super().__init__()
        self.paths = [os.path.abspath(p) for p in paths]
        self.sources = 0
        self.skipped: list[str] = []
        self._data: dict[str, list] = {}
        for p in self.paths:
            if not os.path.exists(p):
                raise RuntimeError(f"manifest path not found: {p}")
            self._walk(p, helm, helm_set or [])
        if not self.sources:
            raise RuntimeError("no Kubernetes manifests (.yaml, .yml, .json) found in: "
                               + ", ".join(paths))
        self.fetched_ok = True

    @classmethod
    def from_docs(cls, docs: list, label: str = "inline") -> "ManifestEvidenceCollector":
        """Evidence from objects already in memory (the dashboard's builder, tests)."""
        self = cls.__new__(cls)
        EvidenceCollector.__init__(self)
        self.paths, self.sources, self.skipped, self._data, self._label = [], 1, [], {}, label
        self._add(list(docs), label)
        self.fetched_ok = True
        return self

    def cluster_label(self) -> str:
        if getattr(self, "_label", None):
            return "manifests:" + self._label
        return "manifests:" + ",".join(os.path.basename(p.rstrip("/")) or p for p in self.paths)

    # -- loading ---------------------------------------------------------------------------
    def _walk(self, path: str, helm: bool, helm_set: list) -> None:
        if os.path.isfile(path):
            self._read_file(path)
            return
        if os.path.exists(os.path.join(path, "Chart.yaml")):
            if helm:
                self._render_chart(path, helm_set)
            else:
                self.skipped.append(f"{path}: Helm chart skipped (helm rendering turned off)")
            return
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            if root != path and os.path.exists(os.path.join(root, "Chart.yaml")):
                dirs[:] = []
                if helm:
                    self._render_chart(root, helm_set)
                continue
            for f in sorted(files):
                if f.endswith(_EXT):
                    self._read_file(os.path.join(root, f))

    def _read_file(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            docs = _load_docs(text, path)
        except RuntimeError:
            raise
        except Exception as exc:
            self.skipped.append(f"{path}: not valid YAML/JSON ({str(exc).splitlines()[0][:80]})")
            return
        self.sources += 1
        self._add(docs, path)

    def _render_chart(self, chart: str, helm_set: list) -> None:
        if not shutil.which("helm"):
            self.skipped.append(f"{chart}: Helm chart skipped, `helm` is not installed")
            return
        cmd = ["helm", "template", os.path.basename(chart.rstrip("/")), chart]
        for s in helm_set:
            cmd += ["--set", s]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if proc.returncode != 0:
            self.skipped.append(f"{chart}: helm template failed: {proc.stderr.strip()[:120]}")
            return
        self.sources += 1
        self._add(_load_docs(proc.stdout, "chart.yaml"), chart)

    def _add(self, docs: list, source: str) -> None:
        for d in docs:
            if not isinstance(d, dict):
                continue
            if d.get("kind", "").endswith("List") and isinstance(d.get("items"), list):
                self._add(d["items"], source)
                continue
            kind = d.get("kind")
            bucket = KIND_ALIASES.get(kind)
            if not bucket:
                continue
            meta = d.setdefault("metadata", {})
            if kind not in _CLUSTER_KINDS:
                meta.setdefault("namespace", "default")
            meta.setdefault("annotations", {})
            self._data.setdefault(bucket, []).append(d)

    def _fetch(self, kind: str, bucket: str) -> list[dict]:
        return list(self._data.get(bucket, []))
