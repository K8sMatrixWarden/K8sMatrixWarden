"""Shard ⑤, Image & Supply Chain (§5.7).

CVE scanning is delegated to an external adapter (Trivy) when available; the native rules
here cover config/provenance signals that don't require pulling the image.
"""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (DetectionMethod as DM, MitreTag as M, Rule, Severity as S,
                           Tactic as T)
from .base import DomainShard, ref
from .workload_pod_security import WORKLOAD_KINDS

NAME = "image_supply_chain"

# A small illustrative registry allow-list; empty means "all allowed".
_POPULAR = {"nginx", "redis", "postgres", "mysql", "busybox", "alpine", "ubuntu",
            "node", "python", "golang", "httpd"}


def _iter_images(ev):
    for kind in WORKLOAD_KINDS:
        for res in ev.get(kind):
            for c in ev.containers(res):
                yield res, c, c.get("image", "")


def _image_pull_policy(rule, ev, scope):
    for res, c, image in _iter_images(ev):
        if c.get("imagePullPolicy") == "IfNotPresent" and image.endswith(":latest"):
            yield rule.finding(ref(res), f"container '{c.get('name')}' may run a stale "
                               f"cached image (IfNotPresent + :latest)",
                               evidence={"image": image})


def _unsigned(rule, ev, scope):
    for res, c, image in _iter_images(ev):
        annos = Evidence.dig(res, "metadata.annotations", {}) or {}
        if not any("cosign" in k or "signature" in k for k in annos):
            yield rule.finding(ref(res), f"image '{image}' has no cosign/notary signature "
                               f"annotation", evidence={"image": image})
            break


def _typosquat(rule, ev, scope):
    for res, c, image in _iter_images(ev):
        repo = image.split("/")[-1].split(":")[0].split("@")[0]
        for pop in _POPULAR:
            if repo != pop and _levenshtein(repo, pop) == 1:
                yield rule.finding(ref(res), f"image name '{repo}' is one edit away from "
                                   f"popular image '{pop}' (typosquatting risk)",
                                   evidence={"image": image, "similar_to": pop})


def _kubeconfig_embedded(rule, ev, scope):
    for res, c, image in _iter_images(ev):
        for e in c.get("env", []) or []:
            if "kubeconfig" in (e.get("name", "").lower()) and e.get("value"):
                yield rule.finding(ref(res), f"container '{c.get('name')}' embeds a "
                                   f"kubeconfig via env '{e.get('name')}'",
                                   severity=S.CRITICAL, evidence={"env": e.get("name")})


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class ImageSupplyChainShard(DomainShard):
    name = NAME
    title = "Image & Supply Chain"
    index = "⑤"

    def rules(self):
        return [
            Rule("img-pull-policy", "Stale-image pull policy", self.name, ["Pod"],
                 S.LOW, DM.IMAGE, _image_pull_policy,
                 mitre=[M(T.INITIAL_ACCESS, "T1525", "Implant Internal Image")],
                 owasp="K07", evidence_needs=WORKLOAD_KINDS),
            Rule("img-not-signed", "Image not signed", self.name, ["Pod"], S.MEDIUM,
                 DM.IMAGE, _unsigned,
                 mitre=[M(T.INITIAL_ACCESS, "T1525", "Implant Internal Image")],
                 owasp="K07", evidence_needs=WORKLOAD_KINDS),
            Rule("img-typosquat", "Typosquatted image name", self.name, ["Pod"], S.HIGH,
                 DM.IMAGE, _typosquat,
                 mitre=[M(T.INITIAL_ACCESS, "T1525", "Implant Internal Image")],
                 owasp="K07", evidence_needs=WORKLOAD_KINDS),
            Rule("img-kubeconfig-embedded", "Kubeconfig embedded in image", self.name,
                 ["Pod"], S.CRITICAL, DM.IMAGE, _kubeconfig_embedded,
                 mitre=[M(T.INITIAL_ACCESS, "T1552", "Unsecured Credentials")],
                 owasp="K03", evidence_needs=WORKLOAD_KINDS),
        ]


SHARD = ImageSupplyChainShard
