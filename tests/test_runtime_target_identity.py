"""
A status page must name the cluster it looked at.

An operator validating an EKS cluster opened Runtime Management and read:

    Falco: Unknown
    helm could not list releases: Kubernetes cluster unreachable:
    Get "https://127.0.0.1:51103/version": connect: actively refused

Falco was running perfectly on that EKS cluster -- 2/2 pods, chart falco-9.1.0. Nothing
was broken. The Falco and Helm lifecycles run bare `helm` and `kubectl` with no
`--kubeconfig` and no `--context`, so they act on whatever the SERVER PROCESS's environment
selects, and that dashboard had been started in a shell pointing at Docker Desktop. Scans
choose their cluster per call, through an explicit `kubeconfig=` argument; these two
mechanisms are different and the page named neither.

The model is not the defect -- a lifecycle that took a cluster argument would let a caller
aim an install at a cluster they were not looking at. The defect was that the answer was
invisible. So `status()` now reports the target it inspected, and both runtime pages say
which cluster they are about.

The same reasoning covers Runtime Events, which shows the latest saved scan: with two
clusters in one report store, "latest" is not self-evident.
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core import falco_lifecycle as falco
from k8smatrixwarden.web.app import WebApp


# --------------------------------------------------------------------------- #
# The lifecycle reports its target
# --------------------------------------------------------------------------- #

def test_current_target_never_returns_credentials():
    """It exists to identify a cluster, not to describe how to reach one."""
    found = falco.current_target()
    blob = repr(found).lower()
    for secret in ("token", "client-key", "certificate-authority", "client-certificate",
                   "password", "bearer", "-----begin"):
        assert secret not in blob, f"{secret!r} appeared in the target metadata"
    # A full server URL can carry a path/query; only the host is reported.
    assert "://" not in str(found.get("api_server_host") or "")


def test_current_target_says_where_the_answer_came_from():
    found = falco.current_target()
    assert "process environment" in found["source"]
    assert "context" in found, "the context key is always present, even when None"


def test_the_target_follows_the_process_environment():
    """The mechanism itself: change KUBECONFIG, get a different answer. Uses a kubeconfig
    written for this test, so it needs no real cluster and reaches none."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "kubeconfig")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "apiVersion: v1\nkind: Config\ncurrent-context: pretend-cluster\n"
                "clusters:\n- name: c\n  cluster:\n    server: https://kmw.example:6443\n"
                "contexts:\n- name: pretend-cluster\n  context:\n    cluster: c\n"
                "    user: u\nusers:\n- name: u\n  user: {}\n")
        saved = os.environ.get("KUBECONFIG")
        os.environ["KUBECONFIG"] = path
        try:
            found = falco.current_target()
        finally:
            if saved is None:
                os.environ.pop("KUBECONFIG", None)
            else:
                os.environ["KUBECONFIG"] = saved
    if _kubectl_missing():
        return                                  # nothing to read the file with
    assert found.get("context") == "pretend-cluster", found
    assert found.get("api_server_host") == "kmw.example", found
    assert found.get("kubeconfig") == "KUBECONFIG environment variable"


def _kubectl_missing() -> bool:
    try:
        subprocess.run(["kubectl", "version", "--client"], capture_output=True,
                       timeout=20)
        return False
    except (OSError, subprocess.TimeoutExpired):
        return True


def test_every_falco_status_answer_carries_a_target():
    """Including the ones that fail. An `unknown` with no subject is the original bug."""
    import inspect
    source = inspect.getsource(falco.status)
    returns = [line for line in source.splitlines()
               if "return {" in line or line.strip().startswith("return {")]
    assert returns, "status() no longer returns dict literals; re-check this guard"
    assert source.count("current_target()") >= 3, (
        "a status branch answers about a cluster without naming it")


# --------------------------------------------------------------------------- #
# The pages say which cluster
# --------------------------------------------------------------------------- #

def _page(path):
    return WebApp(build_platform(), reports_dir=tempfile.mkdtemp()).route("GET", path).text


def test_runtime_management_renders_its_target():
    page = _page("/runtime-management")
    assert "id='fa-target'" in page, "no element to render the target into"
    assert "function faTarget" in page
    assert "scans choose their own cluster separately" in page, (
        "the page must distinguish the lifecycle target from the scan target")


def test_the_target_renderer_uses_textcontent_not_innerhtml():
    """This page defines no `esc`, because it never interpolates. An earlier draft of
    faTarget used innerHTML with esc(), threw ReferenceError, and left the whole Falco
    panel stuck on 'Checking...' -- a runtime failure a parse check cannot see."""
    page = _page("/runtime-management")
    start = page.index("function faTarget")
    body = page[start:page.index("function faRender", start)]
    # The word survives in the comment explaining why it is not used; only actual code
    # counts, the same trap a previous guard fell into.
    code = " ".join(line for line in body.splitlines()
                    if not line.strip().startswith("//"))
    assert "innerHTML" not in code, (
        "faTarget interpolates into innerHTML; this page has no escaping helper")
    assert "textContent" in code


def test_runtime_events_names_its_cluster_and_scan():
    page = _page("/runtime-events")
    assert "Cluster: ${esc(d.cluster" in page, (
        "the events feed shows the latest scan without saying which cluster it is from")
    assert "scan ${esc(d.scan_id" in page


def test_the_runtime_api_returns_the_cluster_it_read():
    """The page can only show it because the API supplies it."""
    import inspect

    from k8smatrixwarden.core import runtime_events
    source = inspect.getsource(runtime_events.query_runtime)
    assert '"cluster"' in source
    assert '"scan_id"' in source


if __name__ == "__main__":
    import traceback
    failed = 0
    for key, fn in sorted(globals().items()):
        if key.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {key}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
