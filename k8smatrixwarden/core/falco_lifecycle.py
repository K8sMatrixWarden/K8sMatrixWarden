"""
Falco lifecycle: deploy, status, remove — one implementation, three front doors.

K8sMatrixWarden reads clusters. This module is the single exception, and it is deliberately
small and deliberately fenced. Getting a runtime feed at all means Falco has to exist in the
cluster, and telling an operator to go and run three helm commands by hand is a poor answer
from a tool that is otherwise able to do the work. So the work is done here, once, and the
MCP tools, the CLI `falco` command and the dashboard's Runtime tab all call it. There is no
second copy of this logic anywhere; a divergence between "deploy from the UI" and "deploy
from an assistant" would be a security bug, not a cosmetic one.

WHAT MAKES THIS SAFE

  A write gate.        Deploying and removing mutate the cluster, so they do nothing unless
                       K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1 is set in the server's own
                       environment. Off, `deploy` returns the exact commands for a human to
                       run and changes nothing. The gate is read from the environment, never
                       from a tool argument, so no caller can turn it on.

  No shell, ever.      Every helm invocation is a fixed argv list. `shell=True` appears
                       nowhere. A namespace of `falco; rm -rf /` is one argument to helm,
                       not two commands to a shell.

  Validated inputs.    Namespace and release must look like Kubernetes names. The chart and
                       repository are CONSTANTS, not parameters: a caller that could choose
                       the chart could install anything at all, which is the same capability
                       as arbitrary execution wearing a hat.

  Narrow removal.      Removal is `helm uninstall <release> -n <namespace>`, and only for a
                       release helm reports as installed. The namespace is never deleted:
                       operators put other things in it, and `kubectl delete namespace` is
                       exactly the broad destructive move this module refuses to make.

  Honest outcomes.     A partial install is reported as `degraded` or `failed` with what was
                       actually observed. Nothing here claims success it did not verify.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Optional

#: The chart this project supports, fixed. Not a parameter: choosing the chart is choosing
#: what code runs in the cluster, which is a capability no caller should have through a
#: security scanner.
CHART = "falcosecurity/falco"
REPO_NAME = "falcosecurity"
REPO_URL = "https://falcosecurity.github.io/charts"
DEFAULT_RELEASE = "falco"
DEFAULT_NAMESPACE = "falco"

#: Kubernetes object-name syntax (RFC 1123 label). Anything else is refused before it can
#: reach an argv list, so the validation is a contract rather than a last line of defence.
_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_MAX_NAME = 63

#: The environment variable that must be set for anything here to change a cluster.
WRITE_GATE = "K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE"

#: Lifecycle states. Reported, never guessed.
NOT_INSTALLED = "not-installed"
RUNNING = "running"
DEGRADED = "degraded"
FAILED = "failed"
UNKNOWN = "unknown"


def writes_allowed() -> bool:
    """Is this process permitted to change the cluster? Read from the environment only."""
    return os.environ.get(WRITE_GATE) == "1"


def _validate(namespace: str, release: str) -> Optional[str]:
    """The reason these names are unusable, or None. Checked before any argv is built."""
    for label, value in (("namespace", namespace), ("release", release)):
        if not value or len(value) > _MAX_NAME or not _NAME.match(value):
            return (f"invalid {label} {value!r}: expected a Kubernetes name "
                    f"(lowercase letters, digits and '-', up to {_MAX_NAME} characters)")
    return None


def _helm(*args, timeout: int = 120):
    """Run helm with a fixed argument list. Never a shell, never a caller-built string."""
    return subprocess.run(["helm", *args], capture_output=True, text=True,
                          timeout=timeout)


def _kubectl(*args, timeout: int = 30):
    return subprocess.run(["kubectl", *args], capture_output=True, text=True,
                          timeout=timeout)


def _tooling(need_kubectl: bool = True) -> Optional[dict]:
    """A structured error when the binaries this needs are absent, or None."""
    if shutil.which("helm") is None:
        return {"error": "helm not found on PATH; install helm (https://helm.sh) or "
                         "deploy Falco yourself with the commands from deploy(dry-run)"}
    if need_kubectl and shutil.which("kubectl") is None:
        return {"error": "kubectl not found on PATH; install kubectl or check status "
                         "with your own tooling"}
    return None


def _blocked() -> dict:
    """The refusal returned when the write gate is closed."""
    return {
        "error": f"cluster writes are disabled; set {WRITE_GATE}=1 in the environment of "
                 f"the process running K8sMatrixWarden to allow it",
        "write_gate": WRITE_GATE,
        "writes_allowed": False,
        "note": ("K8sMatrixWarden is read-only by default. Deploying or removing Falco "
                 "changes the cluster, so it is refused rather than performed quietly."),
    }


def plan(webhook_url: str, namespace: str = DEFAULT_NAMESPACE,
         release: str = DEFAULT_RELEASE) -> list:
    """The exact commands a deploy would run. Also what `deploy` returns when gated.

    `json_output=true` makes Falco print one JSON alert per line, which is what the pull
    feed reads from the pod logs; falcosidekick covers the push feed to `/api/runtime`.
    Setting both means either ingestion route works without a second install.
    """
    values = (f"falco.json_output=true,"
              f"falcosidekick.enabled=true,"
              f"falcosidekick.config.webhook.address={webhook_url}")
    return [
        f"helm repo add {REPO_NAME} {REPO_URL}",
        "helm repo update",
        f"helm install {release} {CHART} -n {namespace} --create-namespace "
        f"--set {values}",
    ]


def status(namespace: str = DEFAULT_NAMESPACE,
           release: str = DEFAULT_RELEASE) -> dict:
    """What Falco is actually doing in this cluster. Read-only; needs no write gate.

    Reads the helm release and the DaemonSet, and reports what both say. When they
    disagree — a release exists but no pod is ready — that is `degraded`, which is the
    answer an operator needs and the one a naive "is the release there?" check would miss.
    """
    problem = _validate(namespace, release)
    if problem:
        return {"state": UNKNOWN, "error": problem}
    missing = _tooling()
    if missing:
        return {"state": UNKNOWN, **missing}

    out: dict = {"namespace": namespace, "release": release,
                 "install_method": "helm", "writes_allowed": writes_allowed()}
    try:
        listed = _helm("list", "-n", namespace, "-o", "json", timeout=30)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {**out, "state": UNKNOWN,
                "error": f"could not reach the cluster: {type(exc).__name__}"}
    if listed.returncode != 0:
        return {**out, "state": UNKNOWN,
                "error": f"helm could not list releases: {_trim(listed.stderr)}"}
    try:
        releases = json.loads(listed.stdout or "[]")
    except json.JSONDecodeError:
        releases = []
    mine = next((r for r in releases if r.get("name") == release), None)
    if not mine:
        return {**out, "state": NOT_INSTALLED,
                "message": f"no helm release {release!r} in namespace {namespace!r}"}

    out["chart"] = mine.get("chart")
    out["app_version"] = mine.get("app_version")
    out["revision"] = mine.get("revision")
    out["helm_status"] = mine.get("status")

    ready = desired = None
    try:
        got = _kubectl("get", "daemonset", "-n", namespace,
                       "-l", "app.kubernetes.io/name=falco", "-o", "json")
        if got.returncode == 0:
            items = (json.loads(got.stdout or "{}") or {}).get("items") or []
            if items:
                st = items[0].get("status") or {}
                ready = st.get("numberReady", 0)
                desired = st.get("desiredNumberScheduled", 0)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        ready = desired = None          # reported as unknown, never invented
    out["pods_ready"] = ready
    out["pods_desired"] = desired

    if mine.get("status") not in ("deployed", "superseded"):
        out["state"] = FAILED
        out["message"] = f"helm reports the release as {mine.get('status')!r}"
    elif ready is None or desired is None:
        out["state"] = UNKNOWN
        out["message"] = ("the helm release exists but the DaemonSet could not be read, "
                          "so readiness is unknown rather than assumed healthy")
    elif desired and ready >= desired:
        out["state"] = RUNNING
        out["message"] = f"{ready}/{desired} Falco pods ready"
    else:
        out["state"] = DEGRADED
        out["message"] = (f"the release is installed but only {ready}/{desired} Falco "
                          f"pods are ready")
    return out


def deploy(webhook_url: str, namespace: str = DEFAULT_NAMESPACE,
           release: str = DEFAULT_RELEASE, timeout: int = 300) -> dict:
    """Install Falco + falcosidekick, wired to `webhook_url`.

    Gated: with writes disabled this changes nothing and returns the commands to run by
    hand. Idempotent in the direction that matters — an existing release is reported, not
    reinstalled over, because a second `helm install` of the same name fails anyway and a
    surprise upgrade is not what "deploy" was asked for.

    Every step is verified. A helm install that returns zero but leaves no ready pod is
    reported as `degraded`, not as success. That is the ordinary outcome of a first
    install, not a fault: the chart's default driver pulls a `falco-driver-loader` init
    image, and `helm --wait` returns before the DaemonSet finishes it. Observed on a live
    cluster at ~24 s for helm and ~4 minutes to `running`. The caller polls `status`; this
    function does not sit on the connection waiting, and it does not call a pod that is
    still pulling an image a success.
    """
    problem = _validate(namespace, release)
    if problem:
        return {"status": "error", "error": problem}
    if not isinstance(webhook_url, str) or not webhook_url.startswith(("http://",
                                                                       "https://")):
        return {"status": "error",
                "error": f"invalid webhook_url {webhook_url!r}: expected an http(s) URL "
                         f"K8sMatrixWarden can be reached on, e.g. "
                         f"http://host.docker.internal:8080/api/runtime"}
    commands = plan(webhook_url, namespace, release)
    next_steps = [
        f"Check pod status: kubectl get pods -n {namespace}",
        f"Tail logs: kubectl logs -n {namespace} -l app.kubernetes.io/name=falco -f",
        "Then: refresh_runtime_feed, then get_runtime_events",
    ]
    if not writes_allowed():
        return {"status": "dry-run", "webhook": webhook_url, "namespace": namespace,
                "release": release, "commands": commands, "next_steps": next_steps,
                **_blocked()}

    missing = _tooling(need_kubectl=False)
    if missing:
        return {"status": "error", "commands": commands, **missing}

    already = status(namespace, release)
    if already.get("state") in (RUNNING, DEGRADED):
        return {"status": "already-installed", "namespace": namespace,
                "release": release, "falco": already,
                "message": (f"helm release {release!r} already exists in {namespace!r}; "
                            f"remove it first to reinstall")}

    steps: list = []
    values = (f"falco.json_output=true,falcosidekick.enabled=true,"
              f"falcosidekick.config.webhook.address={webhook_url}")
    try:
        for label, args in (
            (f"add the {REPO_NAME} helm repo", ("repo", "add", REPO_NAME, REPO_URL)),
            ("update helm repos", ("repo", "update",)),
            ("install the chart", ("install", release, CHART, "-n", namespace,
                                   "--create-namespace", "--set", values,
                                   "--wait", "--timeout", f"{max(30, int(timeout))}s")),
        ):
            done = _helm(*args, timeout=max(60, int(timeout) + 30))
            if done.returncode != 0:
                return {"status": "failed", "failed_step": label,
                        "error": _trim(done.stderr) or _trim(done.stdout),
                        "steps": steps, "commands": commands,
                        "note": ("the cluster may hold a partial install; run "
                                 "get_falco_status, and remove_falco to clean up"),
                        "falco": status(namespace, release)}
            steps.append(f"ok: {label}")
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": f"helm timed out after {timeout}s",
                "steps": steps, "commands": commands,
                "note": ("the install may still be in progress; run get_falco_status "
                         "before retrying"),
                "falco": status(namespace, release)}
    except OSError as exc:
        return {"status": "failed", "error": f"could not run helm: {exc}",
                "steps": steps, "commands": commands}

    final = status(namespace, release)
    return {"status": "installed" if final.get("state") == RUNNING else "degraded",
            "namespace": namespace, "release": release, "webhook": webhook_url,
            "steps": steps, "next_steps": next_steps, "falco": final}


def remove(namespace: str = DEFAULT_NAMESPACE, release: str = DEFAULT_RELEASE,
           timeout: int = 180) -> dict:
    """Uninstall the Falco helm release. Gated, and narrow by construction.

    `helm uninstall` removes what that release created and nothing else. The namespace is
    left in place: operators keep other things there, and deleting it to be thorough is how
    a cleanup becomes an outage.
    """
    problem = _validate(namespace, release)
    if problem:
        return {"status": "error", "error": problem}
    if not writes_allowed():
        return {"status": "dry-run", "namespace": namespace, "release": release,
                "commands": [f"helm uninstall {release} -n {namespace}"],
                **_blocked()}
    missing = _tooling(need_kubectl=False)
    if missing:
        return {"status": "error", **missing}

    before = status(namespace, release)
    if before.get("state") == NOT_INSTALLED:
        return {"status": "not-installed", "namespace": namespace, "release": release,
                "message": f"no helm release {release!r} in namespace {namespace!r}, "
                           f"nothing to remove"}
    if before.get("state") == UNKNOWN and before.get("error"):
        return {"status": "error", "falco": before,
                "error": f"refusing to uninstall without knowing what is there: "
                         f"{before['error']}"}
    try:
        done = _helm("uninstall", release, "-n", namespace, "--wait",
                     timeout=max(60, int(timeout)))
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": f"helm uninstall timed out after {timeout}s",
                "falco": status(namespace, release)}
    except OSError as exc:
        return {"status": "failed", "error": f"could not run helm: {exc}"}
    if done.returncode != 0:
        return {"status": "failed", "error": _trim(done.stderr) or _trim(done.stdout),
                "falco": status(namespace, release)}
    after = status(namespace, release)
    return {"status": "removed" if after.get("state") == NOT_INSTALLED else "partial",
            "namespace": namespace, "release": release,
            "namespace_kept": True,
            "note": ("the namespace was left in place; only the helm release was "
                     "uninstalled"),
            "falco": after}


def _trim(text: Optional[str], limit: int = 400) -> str:
    """Tool output, shortened. Helm prints its own errors; we pass them through rather
    than paraphrasing, but never a whole log."""
    text = (text or "").strip()
    return text[:limit] + ("…" if len(text) > limit else "")
