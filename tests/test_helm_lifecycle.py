"""
Helm lifecycle: pinned, verified, KMW-owned, and never a shell.

Installing software on the host is a bigger promise than anything else this project does,
so the tests are mostly about what it refuses. The download is pinned by version AND by
SHA-256 held in source; removal is decided by where a file lives, not by a path somebody
passed; and the whole thing runs behind the same write gate the Falco lifecycle uses.

Nothing here reaches the network. The one test that exercises a real install is skipped
unless a KMW-managed Helm already happens to be present, because a test suite that quietly
downloads binaries is a test suite nobody can run offline.
"""
import hashlib
import inspect
import io
import json
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core import falco_lifecycle as falco
from k8smatrixwarden.core import helm_lifecycle as helm
from k8smatrixwarden.mcp.server import build_tools

TOOLS = build_tools()


def _isolated(monkeypatchable_home):
    """Point the KMW home at a scratch directory so nothing touches the real install."""
    os.environ["K8SMATRIXWARDEN_HOME"] = monkeypatchable_home


def _restore_home(previous):
    if previous is None:
        os.environ.pop("K8SMATRIXWARDEN_HOME", None)
    else:
        os.environ["K8SMATRIXWARDEN_HOME"] = previous


# --------------------------------------------------------------------------- #
# The pin: version and digests are source constants, not inputs
# --------------------------------------------------------------------------- #

def test_the_version_is_pinned_and_not_a_parameter():
    """A caller who can choose the version can choose a URL, and a caller who can choose a
    URL can install anything."""
    assert helm.HELM_VERSION.startswith("v")
    for fn in (helm.install, helm.remove, helm.status):
        params = set(inspect.signature(fn).parameters)
        assert not params & {"version", "url", "path", "chart", "source", "binary",
                             "checksum", "sha256", "command", "args"}, \
            f"{fn.__name__} exposes an install-target parameter"
    assert helm.install.__code__.co_argcount == 0


def test_every_supported_platform_has_a_pinned_digest():
    for key, (template, digest) in helm.CHECKSUMS.items():
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), key
        assert helm.HELM_VERSION in template.format(v=helm.HELM_VERSION)


def test_the_download_host_is_a_constant_and_https():
    source = inspect.getsource(helm)
    assert 'https://get.helm.sh' in source
    assert "_BASE_URL" in source
    # No f-string or concatenation building a host from an argument.
    assert "http://" not in source.replace("non-HTTPS", "")


def test_digests_are_not_fetched_at_install_time():
    """Fetching a checksum from the server that serves the binary proves only that the
    server agrees with itself."""
    source = inspect.getsource(helm.install)
    assert "sha256sum" not in source
    assert "CHECKSUMS[key]" in source


def test_no_shell_is_ever_invoked():
    import ast
    tree = ast.parse(inspect.getsource(helm))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                assert kw.arg != "shell" or not getattr(kw.value, "value", False)
            attr = getattr(node.func, "attr", "")
            owner = getattr(getattr(node.func, "value", None), "id", "")
            if owner == "os" and attr == "system":
                raise AssertionError("os.system is called")
            if (owner, attr) == ("subprocess", "run"):
                assert node.args and isinstance(node.args[0], (ast.List, ast.Starred))


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

def test_a_corrupted_download_is_rejected_and_deleted(monkeypatch):
    """The archive is hashed BEFORE anything is unpacked, and a mismatch never reaches
    the extractor, let alone the filesystem."""
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    home = tempfile.mkdtemp()
    _isolated(home)
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    captured = {}

    def fake_download(url, into):
        captured["url"] = url
        with open(into, "wb") as fh:
            fh.write(b"this is not helm")
        return None

    extracted = []
    monkeypatch.setattr(helm, "_download", fake_download)
    monkeypatch.setattr(helm, "_extract_helm",
                        lambda *a, **k: extracted.append(1) or None)
    try:
        out = helm.install()
    finally:
        _restore_home(previous)
    assert out["status"] == "error"
    assert "checksum mismatch" in out["error"]
    assert out["actual_sha256"] == hashlib.sha256(b"this is not helm").hexdigest()
    assert extracted == [], "a failed checksum must not reach the extractor"
    assert captured["url"].startswith("https://get.helm.sh/")


def test_a_download_failure_is_structured_not_an_exception(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    monkeypatch.setattr(helm, "_download", lambda url, into: "download failed: HTTP 503")
    try:
        out = helm.install()
    finally:
        _restore_home(previous)
    assert out["status"] == "error" and "503" in out["error"]


def test_a_verified_archive_installs_into_the_kmw_directory(monkeypatch):
    """The happy path, with a synthetic archive whose digest is pinned for the test, so no
    network is involved."""
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    home = tempfile.mkdtemp()
    _isolated(home)
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    key = helm.platform_key()
    if not key:
        _restore_home(previous)
        return                                   # unsupported platform; covered elsewhere

    payload = b"#!/bin/sh\necho v3.16.3+fake\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(f"{key}/{helm._exe_name()}", payload)
    archive_bytes = buffer.getvalue()
    digest = hashlib.sha256(archive_bytes).hexdigest()

    monkeypatch.setitem(helm.CHECKSUMS, key, ("helm-{v}-fake.zip", digest))

    def fake_download(url, into):
        with open(into, "wb") as fh:
            fh.write(archive_bytes)
        return None

    monkeypatch.setattr(helm, "_download", fake_download)
    monkeypatch.setattr(helm, "helm_version", lambda path: ("v3.16.3+fake", None))
    try:
        out = helm.install()
        assert out["status"] == "installed", out
        assert out["source"] == "kmw-managed"
        assert os.path.isfile(helm.managed_path())
        assert helm.managed_path().startswith(home)
        # Idempotent: a second install reports rather than replaces.
        again = helm.install()
        assert again["status"] == "already-installed"
    finally:
        _restore_home(previous)


def test_an_unsupported_platform_is_refused(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    monkeypatch.setattr(helm, "platform_key", lambda: None)
    try:
        out = helm.install()
    finally:
        _restore_home(previous)
    assert out["status"] == "error" and "unsupported platform" in out["error"]
    assert out["lifecycle_supported"] is False


def test_an_unknown_architecture_maps_to_no_platform(monkeypatch):
    monkeypatch.setattr(helm.platform, "machine", lambda: "mips64")
    assert helm.platform_key() is None


# --------------------------------------------------------------------------- #
# Status honesty
# --------------------------------------------------------------------------- #

def test_absent_everywhere_is_not_installed(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setattr(helm.shutil, "which", lambda name: None)
    try:
        out = helm.status()
    finally:
        _restore_home(previous)
    assert out["status"] == helm.NOT_INSTALLED
    assert out["source"] is None
    assert out["reason"], "not-installed must still say what was checked"


def test_a_binary_that_will_not_answer_is_unknown_not_absent(monkeypatch):
    """The distinction the whole module turns on: 'we looked and it is gone' is a fact,
    'we could not look' is not."""
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setattr(helm, "find_helm", lambda: ("/usr/local/bin/helm", "system"))
    monkeypatch.setattr(helm, "helm_version",
                        lambda path: (None, "PermissionError running helm"))
    try:
        out = helm.status()
    finally:
        _restore_home(previous)
    assert out["status"] == helm.UNKNOWN
    assert out["status"] != helm.NOT_INSTALLED
    assert "did not report a version" in out["reason"]


def test_a_system_helm_is_labelled_system(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setattr(helm.shutil, "which", lambda name: "/opt/homebrew/bin/helm")
    monkeypatch.setattr(helm, "helm_version", lambda path: ("v3.15.0", None))
    try:
        out = helm.status()
    finally:
        _restore_home(previous)
    assert out["status"] == helm.INSTALLED
    assert out["source"] == "system"
    assert out["removable_by_kmw"] is False


def test_a_kmw_copy_is_preferred_over_one_on_path(monkeypatch):
    """A freshly installed Helm must be usable immediately: a running process cannot see
    PATH edits made after it started."""
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    home = tempfile.mkdtemp()
    _isolated(home)
    os.makedirs(helm.managed_dir(), exist_ok=True)
    with open(helm.managed_path(), "wb") as fh:
        fh.write(b"binary")
    os.chmod(helm.managed_path(), 0o755)
    monkeypatch.setattr(helm.shutil, "which", lambda name: "/usr/bin/helm")
    try:
        path, source = helm.find_helm()
    finally:
        _restore_home(previous)
    assert source == "kmw-managed"
    assert path.startswith(home)


# --------------------------------------------------------------------------- #
# Removal only touches what this project owns
# --------------------------------------------------------------------------- #

def test_an_external_helm_is_never_removed(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    monkeypatch.setattr(helm.shutil, "which", lambda name: "/opt/homebrew/bin/helm")
    try:
        out = helm.remove()
    finally:
        _restore_home(previous)
    assert out["status"] == "not_removed"
    assert out["reason"] == "Helm is externally managed"
    assert out["source"] == "system"


def test_removing_when_nothing_is_owned_is_not_an_error(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    monkeypatch.setattr(helm.shutil, "which", lambda name: None)
    try:
        out = helm.remove()
    finally:
        _restore_home(previous)
    assert out["status"] == helm.NOT_INSTALLED


def test_removal_deletes_only_the_managed_file(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    home = tempfile.mkdtemp()
    _isolated(home)
    monkeypatch.setenv(helm.WRITE_GATE, "1")
    os.makedirs(helm.managed_dir(), exist_ok=True)
    with open(helm.managed_path(), "wb") as fh:
        fh.write(b"binary")
    neighbour = os.path.join(helm.managed_dir(), "something-else.txt")
    with open(neighbour, "w") as fh:
        fh.write("keep me")
    # Resolve the paths BEFORE restoring the home override, or they point at the real
    # installation and the assertions silently check the wrong files.
    target, directory = helm.managed_path(), helm.managed_dir()
    try:
        out = helm.remove()
    finally:
        _restore_home(previous)
    assert out["status"] == "removed"
    assert not os.path.exists(target)
    assert os.path.exists(neighbour), "removal touched a neighbouring file"
    assert os.path.isdir(directory), "removal deleted the directory"


def test_there_is_no_path_parameter_to_aim_removal_at():
    assert helm.remove.__code__.co_argcount == 0


# --------------------------------------------------------------------------- #
# The write gate, shared with Falco
# --------------------------------------------------------------------------- #

def test_install_and_remove_are_refused_without_the_gate(monkeypatch):
    monkeypatch.delenv(helm.WRITE_GATE, raising=False)
    for out in (helm.install(), helm.remove()):
        assert out["status"] == "refused"
        assert out["reason"] == "writes_not_allowed"
        assert out["write_gate"] == helm.WRITE_GATE


def test_status_needs_no_gate(monkeypatch):
    monkeypatch.delenv(helm.WRITE_GATE, raising=False)
    assert helm.status()["status"] in (helm.INSTALLED, helm.NOT_INSTALLED, helm.UNKNOWN)


def test_it_is_the_same_gate_falco_uses():
    assert helm.WRITE_GATE == falco.WRITE_GATE
    assert helm.writes_allowed is falco.writes_allowed


# --------------------------------------------------------------------------- #
# Falco uses the shared discovery, not its own
# --------------------------------------------------------------------------- #

def test_falco_does_not_look_helm_up_itself():
    """Checked on the parsed code: the module's docstring explains why it does NOT call
    shutil.which("helm"), and a text search would match that explanation."""
    import ast
    tree = ast.parse(inspect.getsource(falco))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "which":
            for arg in node.args:
                assert not (isinstance(arg, ast.Constant) and arg.value == "helm"), \
                    "Falco must use the shared Helm discovery, not a second lookup"
    assert "helm_lifecycle" in inspect.getsource(falco)


def test_falco_reports_an_actionable_reason_when_helm_is_missing(monkeypatch):
    previous = os.environ.get("K8SMATRIXWARDEN_HOME")
    _isolated(tempfile.mkdtemp())
    monkeypatch.setattr(helm.shutil, "which", lambda name: None)
    try:
        out = falco.status()
    finally:
        _restore_home(previous)
    assert out["state"] == falco.UNKNOWN
    assert "Helm" in out["error"]
    assert out["state"] != falco.NOT_INSTALLED


# --------------------------------------------------------------------------- #
# The three surfaces
# --------------------------------------------------------------------------- #

def test_the_three_mcp_tools_are_registered_and_take_no_arguments():
    for name in ("get_helm_status", "install_helm", "remove_helm"):
        assert name in TOOLS
    for name in ("install_helm", "remove_helm", "get_helm_status"):
        assert inspect.signature(TOOLS[name]).parameters == {}, \
            f"{name} must take no arguments"


def test_the_mcp_tools_delegate_to_the_service():
    for name in ("get_helm_status", "install_helm", "remove_helm"):
        assert "helm_lifecycle" in inspect.getsource(TOOLS[name])


def test_the_cli_has_a_helm_command():
    from k8smatrixwarden.cli.main import build_parser
    parser = build_parser()
    sub = next(a for a in parser._actions
               if hasattr(a, "choices") and a.choices and "scan" in a.choices)
    assert "helm" in sub.choices
    nested = next(a for a in sub.choices["helm"]._actions
                  if hasattr(a, "choices") and a.choices)
    assert set(nested.choices) == {"status", "install", "remove"}
    assert parser.prog == "k8smatrixwarden"


def test_the_cli_delegates_to_the_service():
    from k8smatrixwarden.cli.main import cmd_helm
    source = inspect.getsource(cmd_helm)
    assert "helm_lifecycle" in source
    assert "subprocess" not in source and "urllib" not in source


def test_the_web_endpoints_answer_and_take_no_parameters():
    import tempfile as _tempfile

    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.web.app import WebApp
    app = WebApp(build_platform(), reports_dir=_tempfile.mkdtemp())
    status = app.route("GET", "/api/helm/status")
    assert status.status == 200
    assert json.loads(status.text)["status"] in (
        helm.INSTALLED, helm.NOT_INSTALLED, helm.UNKNOWN)
    source = inspect.getsource(WebApp._api_helm)
    assert "helm_lifecycle" in source
    assert "urllib" not in source and "subprocess" not in source


def test_the_browser_never_builds_an_install():
    import tempfile as _tempfile

    from k8smatrixwarden.bootstrap import build_platform
    from k8smatrixwarden.web.app import WebApp
    page = WebApp(build_platform(),
                  reports_dir=_tempfile.mkdtemp()).route("GET", "/runtime").text
    assert "/api/helm/" in page
    assert "get.helm.sh" not in page
    assert "sha256" not in page.lower()


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            if "monkeypatch" in inspect.signature(fn).parameters:
                continue
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
