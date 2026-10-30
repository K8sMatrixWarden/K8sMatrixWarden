"""What every running image is made of, which of it is vulnerable, and which of it is really in use.

Three questions, three honest answers:

* **What is inside?** Syft builds a software bill of materials (SBOM) for each image that is
  running, keyed by the digest the node started. It is cached, so asking again is free and
  "which workloads contain package X?" never needs another pull.
* **Is any of it vulnerable?** Grype matches that same SBOM, so the two never disagree about
  what the image contains.
* **Is it used?** Presence is not use. A read-only look at each container's processes
  (`/proc/<pid>/maps`, `/fd`) shows which files are really loaded. A package whose files are
  loaded is *in use*. A package that is not seen is *not seen*, never "unused": the method sees
  executables, shared libraries and open jars, but not Python or Node modules after import.

Direct and indirect: Syft records which package depends on which for ecosystems that publish it
(OS packages, lockfiles). A package nothing depends on is *direct*; one something else pulls in
is *indirect*. Where the ecosystem records no relationships the answer is "unknown", not a guess.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from typing import Callable, Optional

from .image_scan import parse_grype, running_images
from .tool_install import resolve as _resolve_tool

# Types whose files appear in /proc/<pid>/maps or /fd while the program runs.
OBSERVABLE = {"apk", "deb", "rpm", "java-archive", "binary", "go-module", "alpm", "portage", "nix"}
_FILES_CAP = 600          # owned-file paths kept per OS package; enough to recognise it, bounded for big images
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Negligible": 0, "Unknown": 0}

# Reads only. Lists the files each process has mapped or open and its command line.
OBSERVE_SCRIPT = (
    "for p in /proc/[0-9]*; do "
    "echo \"C $(tr '\\0' ' ' < $p/cmdline 2>/dev/null)\"; "
    "awk '$6 ~ /^\\// {print \"F \" $6}' $p/maps 2>/dev/null; "
    "for f in $p/fd/*; do l=$(readlink \"$f\" 2>/dev/null); case \"$l\" in /*) echo \"F $l\";; esac; done; "
    "l=$(readlink $p/exe 2>/dev/null); [ -n \"$l\" ] && echo \"F $l\"; "
    "done"
)


def sbom_key(img: dict) -> str:
    return img.get("digest") or img.get("image") or ""


# --------------------------------------------------------------------------- SBOM

def normalize(doc: dict) -> dict:
    """Reduce a Syft JSON document to packages with direct/indirect and the paths they live at."""
    arts = doc.get("artifacts") or []
    by_id = {a.get("id"): a for a in arts}
    dependents: dict[str, set] = {}
    depends_on: dict[str, set] = {}
    typed_with_rels: set[str] = set()
    for r in doc.get("artifactRelationships") or []:
        if r.get("type") != "dependency-of":
            continue
        dep, parent = r.get("parent"), r.get("child")          # `parent` is the dependency, `child` the package needing it
        if dep in by_id and parent in by_id:
            dependents.setdefault(dep, set()).add(parent)
            depends_on.setdefault(parent, set()).add(dep)
            typed_with_rels.update((by_id[dep].get("type"), by_id[parent].get("type")))
    out = []
    for a in arts:
        meta = a.get("metadata") or {}
        loc = a.get("locations") or []
        paths = sorted({l.get("path") for l in loc if l.get("path")})
        nested = any((l.get("accessPath") or "").startswith((l.get("path") or "\0") + ":") for l in loc)   # a jar inside a jar
        files = [f.get("path") for f in (meta.get("files") or []) if isinstance(f, dict) and f.get("path")]
        typ = a.get("type") or ""
        pid = a.get("id")
        if typ not in typed_with_rels:
            kind = "unknown"
        else:
            kind = "indirect" if dependents.get(pid) else "direct"
        out.append({"id": pid, "name": a.get("name") or "", "version": a.get("version") or "", "type": typ,
                    "purl": a.get("purl") or "", "paths": paths, "nested": nested, "files": files[:_FILES_CAP],
                    "kind": kind, "neededBy": sorted(by_id[d].get("name", "") for d in dependents.get(pid, ()))[:8],
                    "needs": sorted(by_id[d].get("name", "") for d in depends_on.get(pid, ()))[:8]})
    return {"packages": out, "distro": ((doc.get("distro") or {}).get("prettyName") or "")}


class SbomStore:
    """Runs Syft and keeps each image's SBOM on disk by digest. A digest never changes, so a stored
    SBOM never goes stale; only the vulnerability feed does, which is why that is matched fresh."""

    def __init__(self, syft: str = "syft", grype: str = "grype", cache_dir: Optional[str] = None,
                 timeout: int = 900, run: Callable = subprocess.run):
        self.syft, self.grype, self.timeout, self._run = syft, grype, timeout, run
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser("~"), ".cache", "k8smatrixwarden", "sbom")

    def tools(self) -> dict:
        return {"syft": _resolve_tool(self.syft) is not None, "grype": _resolve_tool(self.grype) is not None}

    def path(self, key: str) -> str:
        return os.path.join(self.cache_dir, hashlib.sha256(key.encode()).hexdigest() + ".syft.json")

    def has(self, key: str) -> bool:
        return os.path.exists(self.path(key))

    def generate(self, img: dict) -> dict:
        """Return {ok, path} or {error}. Never raises: one unreadable image must not stop the rest."""
        key, dest = sbom_key(img), self.path(sbom_key(img))
        if os.path.exists(dest):
            return {"ok": True, "path": dest, "cached": True}
        syft = _resolve_tool(self.syft)
        if syft is None:
            return {"error": "syft is not installed, so no SBOM can be built. Install it from the Dependencies tab."}
        try:
            proc = self._run([syft, img["target"], "-o", "syft-json", "-q"], capture_output=True, text=True,
                             timeout=self.timeout)
            if proc.returncode != 0:
                return {"error": (proc.stderr or "syft failed").strip()[-300:]}
            json.loads(proc.stdout)                                                 # refuse to cache a half-written file
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(dest, "w") as fh:
                fh.write(proc.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)[:300]}
        return {"ok": True, "path": dest, "cached": False}

    def load(self, key: str) -> Optional[dict]:
        try:
            with open(self.path(key)) as fh:
                return normalize(json.load(fh))
        except (OSError, ValueError):
            return None

    def vulnerabilities(self, key: str) -> dict:
        """Grype over the stored SBOM: {matches, dbBuilt} or {error}."""
        grype = _resolve_tool(self.grype)
        if grype is None:
            return {"error": "grype is not installed. Install it from the Dependencies tab."}
        try:
            proc = self._run([grype, "sbom:" + self.path(key), "-o", "json", "--quiet"], capture_output=True,
                             text=True, timeout=self.timeout)
            if proc.returncode != 0:
                return {"error": (proc.stderr or "grype failed").strip()[-300:]}
            return parse_grype(json.loads(proc.stdout))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)[:300]}

    def export(self, key: str, fmt: str = "cyclonedx-json") -> Optional[str]:
        """The SBOM in a standard format (CycloneDX or SPDX), converted by Syft from the stored one."""
        if fmt not in ("cyclonedx-json", "spdx-json", "syft-json") or not self.has(key):
            return None
        if fmt == "syft-json":
            with open(self.path(key)) as fh:
                return fh.read()
        syft = _resolve_tool(self.syft)
        if syft is None:
            return None
        try:
            proc = self._run([syft, "convert", self.path(key), "-o", fmt, "-q"], capture_output=True,
                             text=True, timeout=120)
            return proc.stdout if proc.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None


# --------------------------------------------------------------------------- inventory

def _workload(pod: dict) -> dict:
    md = pod.get("metadata") or {}
    owner = next(iter(md.get("ownerReferences") or []), {}) or {}
    kind, name = owner.get("kind") or "Pod", owner.get("name") or md.get("name", "")
    if kind == "ReplicaSet":
        kind, name = "Deployment", re.sub(r"-[a-z0-9]{6,10}$", "", name)
    return {"namespace": md.get("namespace", ""), "kind": kind, "name": name}


def inventory(pods: list[dict]) -> list[dict]:
    """Every distinct running image, with the workloads and pods that run it."""
    imgs = running_images(pods)
    for img in imgs.values():
        img["workloads"], img["pods"] = [], []
    for pod in pods:
        wl, md = _workload(pod), pod.get("metadata") or {}
        for cs in ((pod.get("status") or {}).get("containerStatuses") or []):
            m = re.search(r"sha256:[0-9a-f]{64}", cs.get("imageID") or "")
            key = m.group(0) if m else cs.get("image")
            img = imgs.get(key)
            if not img:
                continue
            if wl not in img["workloads"]:
                img["workloads"].append(wl)
            img["pods"].append({"namespace": md.get("namespace", ""), "name": md.get("name", ""),
                                "container": cs.get("name", ""), "running": "running" in (cs.get("state") or {})})
    return [{"key": sbom_key(i), **i} for i in imgs.values()]


# --------------------------------------------------------------------------- runtime

def parse_observation(text: str) -> dict:
    """The output of OBSERVE_SCRIPT: files that processes have mapped or open, and their commands."""
    files, cmds = set(), set()
    for line in (text or "").splitlines():
        if line.startswith("F /"):
            files.add(line[2:].strip())
        elif line.startswith("C ") and line[2:].strip():
            cmds.add(line[2:].strip()[:200])
    return {"files": sorted(files), "commands": sorted(cmds)}


def _under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def usage_of(pkg: dict, observed: Optional[set]) -> str:
    """in-use | in-running-archive | not-seen | cannot-tell | not-observed."""
    if observed is None:
        return "not-observed"
    if pkg["type"] not in OBSERVABLE:
        return "cannot-tell"
    if pkg["files"] and any(f in observed for f in pkg["files"]):
        return "in-use"
    if any(p in observed for p in pkg["paths"]):
        return "in-running-archive" if pkg["nested"] else "in-use"
    if any(_under(o, p) for p in pkg["paths"] if not p.endswith(".jar") for o in observed):
        return "in-use"
    return "not-seen"


def report(sbom: dict, vulns: dict, observed: Optional[set]) -> dict:
    """Packages with their worst vulnerability and usage, plus a summary that puts the fix-first set on top."""
    by_pkg: dict[tuple, list] = {}
    for m in (vulns or {}).get("matches", []):
        by_pkg.setdefault((m["package"], m["version"]), []).append(m)
    rows = []
    for p in sbom["packages"]:
        ms = by_pkg.get((p["name"], p["version"]), [])
        worst = max((m["severity"] for m in ms), key=lambda s: _SEV_RANK.get(s, 0), default="")
        use = usage_of(p, observed)
        rows.append({**{k: p[k] for k in ("id", "name", "version", "type", "purl", "kind", "neededBy", "needs", "paths")},
                     "usage": use, "worst": worst, "vulns": [{"id": m["id"], "severity": m["severity"], "fixedIn": m["fixedIn"],
                                                              "fixState": m["fixState"], "kev": m["knownExploited"],
                                                              "epss": m["epss"]} for m in
                                                             sorted(ms, key=lambda m: -_SEV_RANK.get(m["severity"], 0))][:25]})
    rows.sort(key=lambda r: (-bool(r["worst"]) * (1 + _SEV_RANK.get(r["worst"], 0)), r["usage"] != "in-use", r["name"]))
    vul = [r for r in rows if r["worst"]]
    summary = {"packages": len(rows), "direct": sum(r["kind"] == "direct" for r in rows),
               "indirect": sum(r["kind"] == "indirect" for r in rows), "unknownKind": sum(r["kind"] == "unknown" for r in rows),
               "vulnerable": len(vul), "critical": sum(r["worst"] == "Critical" for r in rows),
               "inUse": sum(r["usage"] in ("in-use", "in-running-archive") for r in rows),
               "fixFirst": sum(1 for r in vul if r["usage"] in ("in-use", "in-running-archive")),
               "observed": observed is not None, "distro": sbom.get("distro", ""),
               "dbBuilt": (vulns or {}).get("dbBuilt", ""), "vulnError": (vulns or {}).get("error", "")}
    return {"summary": summary, "packages": rows}


def search(stores: dict[str, dict], q: str) -> list[dict]:
    """Where does a package run? `stores` maps image key -> {image, workloads, packages}."""
    q = (q or "").strip().lower()
    if not q:
        return []
    hits: dict[tuple, dict] = {}
    for key, s in stores.items():
        for p in s["packages"]:
            if q in p["name"].lower() or q in (p["purl"] or "").lower():
                h = hits.setdefault((p["name"], p["version"]), {"name": p["name"], "version": p["version"],
                                                                "type": p["type"], "images": [], "workloads": []})
                h["images"].append(s["image"])
                h["workloads"].extend(w for w in s["workloads"] if w not in h["workloads"])
    return sorted(hits.values(), key=lambda h: (h["name"], h["version"]))[:200]
