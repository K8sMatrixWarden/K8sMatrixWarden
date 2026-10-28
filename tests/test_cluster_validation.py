"""Does the generated design behave on a real cluster the way the page claims?

Skipped unless K8SMW_E2E_CONTEXT names a throwaway kubectl context whose network plugin enforces
NetworkPolicy (for example `minikube start -p kmw-test --cni=calico`). It creates one uniquely named
namespace plus a cluster-scoped admission policy, and removes both afterwards.
"""
import json
import os
import subprocess
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core import builder

CTX = os.environ.get("K8SMW_E2E_CONTEXT", "")
pytestmark = pytest.mark.skipif(not CTX, reason="set K8SMW_E2E_CONTEXT to a throwaway cluster to run")


def _k(*args, ns=None, stdin=None, timeout=120):
    cmd = ["kubectl", "--context", CTX] + (["-n", ns] if ns else []) + list(args)
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)


def _spec(ns):
    c = lambda **k: k                                                              # noqa: E731
    return {"app": "shop", "namespace": ns, "guardrails": "deny", "transport": {"mode": "none", "reason": "e2e"},
            "components": [
                c(type="namespace", name=ns),
                c(type="networkpolicy", name="default-deny", mode="default-deny"),
                c(type="networkpolicy", name="allow-dns", mode="allow-dns"),
                c(type="workload", name="web"), c(type="service", name="web", target="web"),
                c(type="workload", name="api"), c(type="service", name="api", target="api"),
                c(type="networkpolicy", name="api-from-web", mode="allow-from", target="api", port="8080", **{"from": "web"}),
                c(type="networkpolicy", name="web-to-api", mode="allow-to", target="web", to="api", port="8080")]}


@pytest.fixture(scope="module")
def deployed():
    ns = "kmw-e2e-" + uuid.uuid4().hex[:6]
    spec = _spec(ns)
    yaml_text = builder.manifests_yaml(spec)
    r = _k("apply", "-f", "-", stdin=yaml_text)
    assert r.returncode == 0, r.stderr                      # file order alone must be enough
    for d in ("web", "api"):
        w = _k("rollout", "status", f"deploy/{d}", "--timeout=180s", ns=ns, timeout=200)
        assert w.returncode == 0, "the generated pods did not start: " + w.stdout + w.stderr
    yield ns
    _k("delete", "namespace", ns, "--wait=false")
    _k("delete", "validatingadmissionpolicybinding", f"{ns}-guardrails")
    _k("delete", "validatingadmissionpolicy", f"{ns}-guardrails")


def _pod(ns, app):
    return _k("get", "pod", "-l", f"app.kubernetes.io/name={app}", "-o", "name", ns=ns).stdout.split()[0]


def _wget(ns, src, url):
    t = time.time()
    r = _k("exec", _pod(ns, src), "--", "wget", "-q", "-O", "/dev/null", "-T", "4", url, ns=ns)
    return r.returncode, time.time() - t


def test_the_declared_call_works_and_name_lookup_works(deployed):
    rc, _ = _wget(deployed, "web", "http://api:80")
    assert rc == 0


def test_undeclared_calls_are_blocked_not_refused(deployed):
    rc, secs = _wget(deployed, "api", "http://web:80")
    assert rc != 0 and secs >= 3, "api->web is not declared, it must time out"
    rc, secs = _wget(deployed, "web", "http://1.1.1.1")
    assert rc != 0 and secs >= 3, "outbound to the internet is not declared, it must time out"


def _bad_pod(ns, name, patch):
    base = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns},
            "spec": {"serviceAccountName": "web", "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "app", "image": "nginxinc/nginx-unprivileged:1.27.2-alpine",
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}}}]}}
    patch(base["spec"])
    return json.dumps(base)


@pytest.mark.parametrize("name,patch,message", [
    ("latest", lambda s: s["containers"][0].update(image="nginxinc/nginx-unprivileged:latest"), "never latest"),
    ("writable", lambda s: s["containers"][0]["securityContext"].update(readOnlyRootFilesystem=False), "read-only"),
    ("hostnet", lambda s: s.update(hostNetwork=True), "Host network"),
    ("initpriv", lambda s: s.update(initContainers=[{"name": "i", "image": "nginxinc/nginx-unprivileged:1.27.2-alpine",
                                                      "securityContext": {"privileged": True}, "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}}}]),
     "Privileged"),
])
def test_the_cluster_itself_refuses_a_pod_that_drops_a_promised_control(deployed, name, patch, message):
    # Pod Security would also refuse these, so take it out of the way: this tests OUR policy.
    _k("label", "namespace", deployed, "pod-security.kubernetes.io/enforce=privileged", "--overwrite")
    r = _k("apply", "--dry-run=server", "-f", "-", ns=deployed, stdin=_bad_pod(deployed, "bad-" + name, patch))
    assert r.returncode != 0 and message in (r.stderr + r.stdout), r.stderr


def test_a_compliant_pod_is_admitted(deployed):
    _k("label", "namespace", deployed, "pod-security.kubernetes.io/enforce=privileged", "--overwrite")
    r = _k("apply", "--dry-run=server", "-f", "-", ns=deployed, stdin=_bad_pod(deployed, "good", lambda s: None))
    assert r.returncode == 0, r.stderr
