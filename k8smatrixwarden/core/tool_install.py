"""Provision the optional scan tools (syft, grype) into a tool-local bin, with no new deps.

The core stays stdlib-only and offline. This module is the one place that reaches the
network, and only when the Dependencies feature asks it to: it downloads the official
Anchore release binary for this OS/arch from GitHub, checks it against the published
SHA-256 checksums, and drops it in ``~/.cache/k8smatrixwarden/bin``. Everything that runs
syft or grype resolves through :func:`resolve`, which prefers that bin and falls back to
whatever is already on PATH, so a user who installed them by hand still works.

ponytail: SHA-256 is the integrity floor. The releases are also cosign-signed; add cosign
verification here if supply-chain hardening becomes a requirement.
"""
from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile
from typing import Optional

REPO = {"syft": "anchore/syft", "grype": "anchore/grype"}
BIN_DIR = os.path.join(os.path.expanduser("~"), ".cache", "k8smatrixwarden", "bin")
_TIMEOUT = 300


def _plat() -> tuple[str, str, str]:
    """(os, arch, ext) in Anchore's release naming, e.g. ('windows', 'amd64', 'zip')."""
    sysname = {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(
        platform.system().lower(), platform.system().lower())
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower())
    return sysname, arch, ("zip" if sysname == "windows" else "tar.gz")


def _exe(name: str) -> str:
    return name + (".exe" if platform.system().lower() == "windows" else "")


def resolve(name: str) -> Optional[str]:
    """Absolute path to the tool: the bundled copy first, else PATH. None if neither."""
    local = os.path.join(BIN_DIR, _exe(name))
    if os.path.isfile(local) and os.access(local, os.X_OK if os.name != "nt" else os.F_OK):
        return local
    return shutil.which(name)


def _get(url: str, binary: bool = True):
    # The GitHub API needs a UA or it 403s; releases download is a plain redirect-followed GET.
    req = urllib.request.Request(url, headers={"User-Agent": "k8smatrixwarden"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # nosec - fixed Anchore/GitHub hosts
        data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def _pick_asset(assets: list[dict], name: str) -> tuple[Optional[dict], Optional[dict]]:
    """(binary asset, checksums asset) for this OS/arch, matched by the release's own names."""
    osn, arch, ext = _plat()
    suffix = f"_{osn}_{arch}.{ext}"
    art = next((a for a in assets if a["name"].startswith(name + "_") and a["name"].endswith(suffix)), None)
    sums = next((a for a in assets if a["name"].endswith("_checksums.txt")), None)
    return art, sums


def _verify(blob: bytes, sums_text: str, filename: str) -> bool:
    want = next((ln.split()[0] for ln in sums_text.splitlines()
                 if ln.strip().endswith(filename)), None)
    return bool(want) and hashlib.sha256(blob).hexdigest() == want


def _extract(blob: bytes, name: str, ext: str, dest_dir: str) -> str:
    """Write the single binary out of the downloaded archive; return its path."""
    want = _exe(name)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, want)
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            member = next(m for m in z.namelist() if os.path.basename(m) == want)
            with z.open(member) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            member = next(m for m in t.getmembers() if os.path.basename(m.name) == want)
            with t.extractfile(member) as src, open(dest, "wb") as out:  # type: ignore[arg-type]
                shutil.copyfileobj(src, out)
    if os.name != "nt":
        os.chmod(dest, 0o755)
    return dest


def install(name: str) -> dict:
    """Download, verify and place one tool. Returns {ok, path} or {error}. Never raises."""
    if name not in REPO:
        return {"error": f"unknown tool '{name}'"}
    if resolve(name) and os.path.isfile(os.path.join(BIN_DIR, _exe(name))):
        return {"ok": True, "path": os.path.join(BIN_DIR, _exe(name)), "cached": True}
    osn, arch, ext = _plat()
    try:
        import json
        rel = json.loads(_get(f"https://api.github.com/repos/{REPO[name]}/releases/latest", binary=False))
        art, sums = _pick_asset(rel.get("assets") or [], name)
        if not art:
            return {"error": f"no {name} release asset for {osn}/{arch}"}
        blob = _get(art["browser_download_url"])
        if sums and not _verify(blob, _get(sums["browser_download_url"], binary=False), art["name"]):
            return {"error": f"checksum mismatch for {art['name']}"}
        path = _extract(blob, name, ext, BIN_DIR)
        return {"ok": True, "path": path, "version": rel.get("tag_name", "")}
    except Exception as exc:  # network / archive / fs: a failed install is a state, not a crash
        return {"error": str(exc)[:300]}


def install_all(names) -> dict:
    return {n: install(n) for n in names}


def _parse_db_status(text: str, rc: int) -> dict:
    def field(name):
        return next((l.split(":", 1)[1].strip() for l in text.splitlines()
                     if l.strip().lower().startswith(name)), "")
    valid = rc == 0 and field("status:").lower() == "valid"
    return {"state": "valid" if valid else "missing", "built": field("built:") if valid else ""}


def grype_db_status() -> dict:
    """Is grype's vulnerability DB present? {state: valid|missing|no-grype|error, built}."""
    grype = resolve("grype")
    if not grype:
        return {"state": "no-grype", "built": ""}
    try:
        proc = subprocess.run([grype, "db", "status"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30)
        return _parse_db_status(proc.stdout + proc.stderr, proc.returncode)
    except Exception as exc:
        return {"state": "error", "built": "", "error": str(exc)[:150]}


def warm_grype_db() -> dict:
    """Pre-download grype's vulnerability DB so the first report doesn't stall on it.
    `grype db update` is idempotent and quick when the DB is already current."""
    grype = resolve("grype")
    if not grype:
        return {"error": "grype not installed"}
    try:
        proc = subprocess.run([grype, "db", "update"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=600)
        return {"ok": True} if proc.returncode == 0 else {"error": (proc.stderr or "db update failed")[-200:]}
    except Exception as exc:
        return {"error": str(exc)[:200]}


def _demo() -> None:
    """Self-check for the pure logic that needs no network."""
    osn, arch, ext = _plat()
    assert osn in ("windows", "darwin", "linux") or osn, osn
    assert arch in ("amd64", "arm64") or arch, arch
    # asset picking matches by the release's own naming
    assets = [{"name": f"syft_1.0.0_{osn}_{arch}.{ext}", "browser_download_url": "u"},
              {"name": "syft_1.0.0_checksums.txt", "browser_download_url": "c"},
              {"name": f"syft_1.0.0_other_arch.{ext}", "browser_download_url": "x"}]
    art, sums = _pick_asset(assets, "syft")
    assert art and art["name"].endswith(f"_{osn}_{arch}.{ext}"), art
    assert sums and sums["name"].endswith("_checksums.txt"), sums
    # checksum verify
    blob = b"hello"
    good = hashlib.sha256(blob).hexdigest() + "  syft_1.0.0_x.tar.gz"
    assert _verify(blob, good, "syft_1.0.0_x.tar.gz")
    assert not _verify(blob, good, "other.tar.gz")
    assert not _verify(b"tampered", good, "syft_1.0.0_x.tar.gz")
    # db status parsing
    ok = _parse_db_status("Schema: v6\nBuilt:     2026-10-30T06:23:28Z\nStatus:    valid\n", 0)
    assert ok == {"state": "valid", "built": "2026-10-30T06:23:28Z"}, ok
    bad = _parse_db_status("Built: 0001-01-01T00:00:00Z\nStatus: invalid\n", 1)
    assert bad == {"state": "missing", "built": ""}, bad
    print("tool_install self-check OK", osn, arch, ext)


if __name__ == "__main__":
    _demo()
