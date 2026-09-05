"""
Helm lifecycle: find it, install it, remove it — without ever running a shell.

The Falco lifecycle needs helm. When helm is missing, Falco status honestly reports
`unknown`, which is correct and completely unhelpful: the operator is told something is
wrong and given no way to fix it from the product. This module closes that, narrowly.

It is a host-side write path, so it is fenced the same way the Falco one is, and then some.

WHAT MAKES THIS SAFE

  Pinned version.      One supported Helm release, named in this file. Not a parameter: a
                       caller who could choose the version could choose a URL, and a caller
                       who can choose a URL can install anything.

  Pinned checksums.    The SHA-256 of every supported artifact is written below, in source.
                       They are NOT fetched at install time. Fetching a checksum from the
                       same server as the binary proves only that the server is
                       self-consistent, which is exactly what an attacker who controls the
                       server would arrange. A pinned digest means a swapped artifact fails
                       here, on this machine, with no network involved in the decision.

  Verify then extract. The archive is hashed before anything is unpacked, and nothing
                       downloaded is ever executed before that check passes. A mismatch
                       deletes the download and returns an error.

  KMW-owned directory. Installs land in the per-user KMW bin directory and nowhere else.
                       The system PATH is not modified, no system helm is touched, and no
                       package manager is invoked.

  Removal by ownership. `remove` deletes only a binary inside the KMW directory. A helm
                       from Homebrew, Chocolatey, Scoop, a distro package or a hand-placed
                       /usr/local/bin is reported as externally managed and left alone. The
                       check is the file's LOCATION, which cannot be spoofed by an argument
                       because there is no path argument.

  The same write gate. K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE governs install and remove, the
                       one mechanism the Falco lifecycle already uses. No second permission
                       system.

HONEST STATES

`not-installed` means both the KMW directory and PATH were checked and helm is in neither.
`unknown` means the question could not be answered — the binary exists but will not report
its version, a lookup raised, a download could not be verified. The two are never merged:
"we looked and it is absent" is a fact, "we could not look" is not.
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

#: The one Helm release this project installs. Bump deliberately, with its checksums.
HELM_VERSION = "v3.16.3"

#: Where the artifacts come from. A constant, never an argument.
_BASE_URL = "https://get.helm.sh"

#: SHA-256 of each supported artifact, taken from the Helm project's published sums and
#: pinned here so verification needs no network and trusts no server. The windows-amd64
#: digest was additionally confirmed against an independently downloaded copy.
CHECKSUMS = {
    "windows-amd64": ("helm-{v}-windows-amd64.zip",
                      "1a52aa56e55168c3d3d2e45fa833a32290e4e3790559851dce1e707eb7728b81"),
    "linux-amd64": ("helm-{v}-linux-amd64.tar.gz",
                    "f5355c79190951eed23c5432a3b920e071f4c00a64f75e077de0dd4cb7b294ea"),
    "linux-arm64": ("helm-{v}-linux-arm64.tar.gz",
                    "5bd34ed774df6914b323ff84a0a156ea6ff2ba1eaf0113962fa773f3f9def798"),
    "darwin-amd64": ("helm-{v}-darwin-amd64.tar.gz",
                     "495d75b404a96fb664f1ca3f8cb01db2210aacc62dbfa1bbab30916abbb20a57"),
    "darwin-arm64": ("helm-{v}-darwin-arm64.tar.gz",
                     "3a39f690173086e6eea17674751eb3c8b970c02697e49cecd4093eaa3cf89dcd"),
}

#: Reuses the Falco gate rather than inventing a second one.
from .falco_lifecycle import WRITE_GATE, writes_allowed  # noqa: E402  (single gate)

#: Status values. `unknown` is never a synonym for `not-installed`.
INSTALLED = "installed"
NOT_INSTALLED = "not-installed"
UNKNOWN = "unknown"

#: Where a KMW-managed helm lives. Under the same per-user directory as the report store,
#: so one place holds everything this project owns on the host.
def managed_dir() -> str:
    override = os.environ.get("K8SMATRIXWARDEN_HOME")
    base = override or os.path.join(os.path.expanduser("~"), ".k8smatrixwarden")
    return os.path.join(base, "bin")


def _exe_name() -> str:
    return "helm.exe" if sys.platform == "win32" else "helm"


def managed_path() -> str:
    """The only path this module will ever install to or delete from."""
    return os.path.join(managed_dir(), _exe_name())


def platform_key() -> Optional[str]:
    """`os-arch` for this machine, or None when it is not a platform we ship."""
    machine = platform.machine().lower()
    arch = {"amd64": "amd64", "x86_64": "amd64", "x64": "amd64",
            "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    system = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform)
    if not arch or not system:
        return None
    key = f"{system}-{arch}"
    return key if key in CHECKSUMS else None


def find_helm() -> tuple:
    """(path, source) for the helm this process should use, preferring the KMW-managed one.

    `source` is `kmw-managed`, `system`, or None when there is none. The KMW copy wins so
    that a freshly installed helm is usable immediately, without the PATH of an
    already-running MCP or web process being touched — a process cannot see PATH edits made
    after it started, and asking an operator to restart the machine is not a fix.
    """
    mine = managed_path()
    if os.path.isfile(mine) and os.access(mine, os.X_OK):
        return mine, "kmw-managed"
    found = shutil.which("helm")
    if found:
        return found, "system"
    return None, None


def helm_version(path: str) -> tuple:
    """(version string, error). Never raises."""
    try:
        done = subprocess.run([path, "version", "--short"], capture_output=True,
                              text=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, f"{type(exc).__name__} running helm: {exc}"
    if done.returncode != 0:
        return None, (done.stderr or done.stdout or "helm exited non-zero").strip()[:200]
    return (done.stdout or "").strip().splitlines()[0] if done.stdout else "", None


def status() -> dict:
    """Where helm is, who owns it, and whether it works. Read-only; needs no write gate."""
    path, source = find_helm()
    if not path:
        return {"status": NOT_INSTALLED, "source": None, "path": None,
                "path_available": shutil.which("helm") is not None,
                "managed_path": managed_path(),
                "lifecycle_supported": platform_key() is not None,
                "platform": platform_key() or f"{sys.platform}/{platform.machine()}",
                "writes_allowed": writes_allowed(),
                "reason": ("helm is not in the K8sMatrixWarden bin directory and not on "
                           "PATH; install_helm can place a pinned, checksum-verified copy "
                           "in the KMW directory")}
    version, error = helm_version(path)
    if error:
        # The binary is there and will not answer. That is not the same as absent.
        return {"status": UNKNOWN, "source": source, "path": path,
                "path_available": shutil.which("helm") is not None,
                "managed_path": managed_path(),
                "lifecycle_supported": platform_key() is not None,
                "writes_allowed": writes_allowed(),
                "reason": f"helm was found at {path} but did not report a version: {error}"}
    return {"status": INSTALLED, "source": source, "version": version, "path": path,
            "path_available": shutil.which("helm") is not None,
            "managed_path": managed_path(),
            "lifecycle_supported": platform_key() is not None,
            "pinned_version": HELM_VERSION,
            "writes_allowed": writes_allowed(),
            "removable_by_kmw": source == "kmw-managed"}


def _refused() -> dict:
    return {"status": "refused", "reason": "writes_not_allowed", "write_gate": WRITE_GATE,
            "writes_allowed": False,
            "note": (f"installing or removing helm writes to this machine. Set "
                     f"{WRITE_GATE}=1 in the environment of the process running "
                     f"K8sMatrixWarden to allow it. Cluster scanning stays read-only "
                     f"either way.")}


def _download(url: str, into: str) -> Optional[str]:
    """Fetch `url` to `into` over HTTPS. Returns an error string, or None on success."""
    if not url.startswith("https://"):            # belt and braces; the URL is a constant
        return f"refusing a non-HTTPS download: {url}"
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            with open(into, "wb") as handle:
                shutil.copyfileobj(response, handle)
    except urllib.error.HTTPError as exc:
        return f"download failed: HTTP {exc.code} for {url}"
    except Exception as exc:
        return f"download failed: {type(exc).__name__}: {exc}"
    return None


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_helm(archive: str, workdir: str) -> Optional[str]:
    """Pull just the helm binary out of a verified archive. Returns its path, or None.

    Members are matched by BASENAME and written to a flat directory, so a crafted archive
    containing `../../something` cannot escape — even though the archive was already
    checksum-verified, an extraction that trusts member paths is a habit worth not having.
    """
    wanted = _exe_name()
    out = os.path.join(workdir, wanted)
    if archive.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(archive) as zf:
            member = next((m for m in zf.namelist()
                           if os.path.basename(m) == wanted), None)
            if not member:
                return None
            with zf.open(member) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
    else:
        import tarfile
        with tarfile.open(archive) as tf:
            member = next((m for m in tf.getmembers()
                           if m.isfile() and os.path.basename(m.name) == wanted), None)
            if not member:
                return None
            src = tf.extractfile(member)
            if src is None:
                return None
            with src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return out


def install() -> dict:
    """Place a pinned, checksum-verified helm in the KMW bin directory.

    Idempotent: an existing helm — KMW-managed or system — is reported and left alone
    rather than replaced. Upgrading is not what "install" was asked to do, and silently
    swapping a working system binary would be worse than doing nothing.
    """
    if not writes_allowed():
        return _refused()
    key = platform_key()
    if not key:
        return {"status": "error",
                "error": (f"unsupported platform {sys.platform}/{platform.machine()}; "
                          f"supported: {', '.join(sorted(CHECKSUMS))}"),
                "lifecycle_supported": False}

    current = status()
    if current["status"] == INSTALLED:
        return {**current, "status": "already-installed",
                "message": (f"helm {current.get('version')} is already available "
                            f"({current.get('source')} at {current.get('path')}); "
                            f"nothing was changed")}

    template, expected = CHECKSUMS[key]
    filename = template.format(v=HELM_VERSION)
    url = f"{_BASE_URL}/{filename}"
    workdir = tempfile.mkdtemp(prefix="kmw-helm-")
    archive = os.path.join(workdir, filename)
    try:
        error = _download(url, archive)
        if error:
            return {"status": "error", "error": error, "url": url}

        actual = _sha256(archive)
        if actual != expected:
            os.remove(archive)
            return {"status": "error", "error": (
                "checksum mismatch: the downloaded archive is not the pinned Helm "
                f"{HELM_VERSION} release and was deleted without being unpacked"),
                "expected_sha256": expected, "actual_sha256": actual, "url": url}

        binary = _extract_helm(archive, workdir)
        if not binary or not os.path.isfile(binary):
            return {"status": "error",
                    "error": f"no {_exe_name()} found inside the verified archive"}

        os.makedirs(managed_dir(), exist_ok=True)
        target = managed_path()
        shutil.copy2(binary, target)
        if sys.platform != "win32":
            os.chmod(target, 0o755)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    after = status()
    if after["status"] != INSTALLED:
        return {"status": "error",
                "error": "helm was written but will not report a version",
                "helm": after}
    return {"status": "installed", "source": "kmw-managed", "version": after.get("version"),
            "path": target, "pinned_version": HELM_VERSION,
            "verified_sha256": expected,
            "note": ("installed into the K8sMatrixWarden directory only; the system PATH "
                     "was not modified. K8sMatrixWarden finds this copy directly, so no "
                     "shell restart is needed."),
            "helm": after}


def remove() -> dict:
    """Delete the KMW-managed helm, and only that.

    A system helm is reported as externally managed and left in place. This project put it
    nowhere, so removing it is not this project's business — and a security tool that
    deletes binaries it did not install is a worse problem than a missing dependency.
    """
    if not writes_allowed():
        return _refused()
    target = managed_path()
    if not os.path.isfile(target):
        path, source = find_helm()
        if source == "system":
            return {"status": "not_removed", "reason": "Helm is externally managed",
                    "source": "system", "path": path,
                    "note": ("K8sMatrixWarden did not install this helm and will not "
                             "delete it. Remove it with whatever installed it.")}
        return {"status": NOT_INSTALLED, "source": None,
                "message": "there is no K8sMatrixWarden-managed helm to remove"}
    try:
        os.remove(target)
    except OSError as exc:
        return {"status": "error", "error": f"could not remove {target}: {exc}"}
    return {"status": "removed", "source": "kmw-managed", "path": target,
            "note": ("only the K8sMatrixWarden copy was deleted; the directory and any "
                     "system helm are untouched"),
            "helm": status()}
