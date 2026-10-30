"""Known-vulnerability evidence for the images a cluster is actually running, via Grype.

The scanner stays read-only against the cluster. Grype is a separate, optional program that
reads an image from a registry (or the local container store) and matches the packages it
finds against vulnerability feeds. Nothing here writes to the cluster.

Two decisions answer "was this image patched?":

* **Scan the digest that runs, not the tag that was asked for.** A pod's
  `status.containerStatuses[].imageID` is the content hash the node really started. If an image
  was rebuilt and re-pushed under the same tag, the new pods carry a new digest and are scanned
  as a different image; a node still holding the old cached copy keeps the old digest and keeps
  being reported. The tag in the pod spec is never used to decide either.
* **Grype judges packages inside the image, not the version in its name.** A patched rebuild
  that really contains the fixed package stops matching; a distro back-port is matched against
  the distro's own advisory feed, so it clears even though the upstream version number looks old.

What it cannot see is noted in the finding, not hidden: an image Grype could not read is
reported as unscanned, never as clean.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Optional

KIND = "ImageVulnerability"
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _digest_of(image_id: str) -> str:
    m = _DIGEST.search(image_id or "")
    return m.group(0) if m else ""


def running_images(pods: list[dict]) -> dict[str, dict]:
    """Unique images the pods are running, keyed by digest (or by reference when the runtime
    reported none). Each value: {image, digest, target, pinned}.

    `pinned` is True when the digest came from a repository reference
    (`repo@sha256:...`), which Grype can pull exactly. A bare image id (typical for an image
    loaded straight into a local node) cannot be pulled by digest, so the reference is used
    and the result is only as good as that reference."""
    out: dict[str, dict] = {}
    for pod in pods:
        status = pod.get("status", {}) or {}
        for cs in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
            image, image_id = cs.get("image") or "", cs.get("imageID") or ""
            if not image:
                continue
            digest = _digest_of(image_id)
            pinned = "@" in image_id and bool(digest)
            key = digest or image
            target = f"{image.split('@')[0]}@{digest}" if pinned else image
            out.setdefault(key, {"image": image, "digest": digest, "target": target,
                                 "pinned": pinned})
    return out


def parse_grype(doc: dict) -> dict:
    """Reduce a Grype JSON report to what the rules need. Tolerates missing fields, since
    Grype adds them across versions (EPSS and KEV are recent)."""
    matches = []
    for m in doc.get("matches", []) or []:
        v, art = m.get("vulnerability", {}) or {}, m.get("artifact", {}) or {}
        fix = v.get("fix", {}) or {}
        epss = max([e.get("epss", 0) or 0 for e in v.get("epss", []) or []] or [0])
        matches.append({
            "id": v.get("id", ""),
            "severity": v.get("severity") if v.get("severity") in _SEVERITIES else "Unknown",
            "package": art.get("name", ""), "version": art.get("version", ""),
            "type": art.get("type", ""),
            "fixState": fix.get("state", "unknown"), "fixedIn": fix.get("versions", []) or [],
            "knownExploited": bool(v.get("knownExploited")), "epss": epss,
        })
    db = ((doc.get("descriptor", {}) or {}).get("db", {}) or {})
    built = (db.get("status", {}) or {}).get("built") or db.get("built") or ""
    return {"matches": matches, "dbBuilt": built}


class GrypeRunner:
    """Runs the `grype` binary and caches by digest. A digest is immutable, so a cached
    result for one never goes stale on its own; the feed does, which is why every result
    carries `dbBuilt` and a scan warns when it is old."""

    def __init__(self, binary: str = "grype", cache_dir: Optional[str] = None,
                 timeout: int = 300, run: Callable = subprocess.run):
        self.binary = binary
        self.timeout = timeout
        self._run = run
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser("~"), ".cache",
                                                   "k8smatrixwarden", "grype")

    def available(self) -> bool:
        from .tool_install import resolve
        return resolve(self.binary) is not None

    def _cache_path(self, digest: str) -> str:
        return os.path.join(self.cache_dir, hashlib.sha256(digest.encode()).hexdigest() + ".json")

    def scan(self, img: dict) -> dict:
        """Return {matches, dbBuilt} or {error}. Never raises: one unreadable image must not
        fail the scan of the rest."""
        path = self._cache_path(img["digest"]) if img["pinned"] else None
        if path and os.path.exists(path):
            try:
                with open(path) as fh:
                    return json.load(fh)
            except (OSError, ValueError):
                pass
        from .tool_install import resolve
        try:
            proc = self._run([resolve(self.binary) or self.binary, img["target"], "-o", "json", "--quiet"],
                             capture_output=True, text=True, timeout=self.timeout)
            if proc.returncode != 0:
                return {"error": (proc.stderr or "grype failed").strip()[-300:]}
            result = parse_grype(json.loads(proc.stdout))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)[:300]}
        if path:
            try:
                os.makedirs(self.cache_dir, exist_ok=True)
                with open(path, "w") as fh:
                    json.dump(result, fh)
            except OSError:
                pass
        return result


def build_image_evidence(pods: list[dict], runner: GrypeRunner,
                         workers: int = 4) -> tuple[list[dict], list[str]]:
    """ImageVulnerability evidence items plus human-readable warnings."""
    images = running_images(pods)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(runner.scan, images.values()))
    items, warnings = [], []
    for img, res in zip(images.values(), results):
        if "error" in res:
            warnings.append(f"ImageVulnerability: could not scan {img['image']}: {res['error']}")
        items.append({"kind": KIND, "metadata": {"name": img["digest"] or img["image"]},
                      "spec": {"image": img["image"], "digest": img["digest"],
                               "pinned": img["pinned"], **res}})
    ages = [_age_days(i["spec"].get("dbBuilt")) for i in items]
    ages = [a for a in ages if a is not None]
    if ages and max(ages) > 7:
        warnings.append(f"ImageVulnerability: the Grype vulnerability database is {max(ages)} "
                        "days old; run `grype db update` so recent CVEs are matched")
    return items, warnings


def _age_days(built: Optional[str]) -> Optional[int]:
    if not built:
        return None
    try:
        dt = datetime.fromisoformat(built.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None
