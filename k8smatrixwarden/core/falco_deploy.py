"""Is Falco running, and how do we put it there without disturbing the cluster?

Everything here is read-only except `deploy` and `remove`, and those do nothing unless the person who
started the dashboard opted in with K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE=1 and the request names what it
is about to do. They run the user's own `helm` and `kubectl` with the user's own credentials, as plain
argument lists (no shell), in a dedicated namespace, with resource limits, and `--atomic` so a failed
install rolls itself back. Remove only touches a release this tool installed (it checks the release
description), never one somebody else deployed.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from typing import Callable, Optional

MARK = "installed by K8sMatrixWarden"
REPO = ("falcosecurity", "https://falcosecurity.github.io/charts")
_NS = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_CTX = re.compile(r"^[A-Za-z0-9._:/@-]{1,120}$")
GATE = "K8SMATRIXWARDEN_ALLOW_CLUSTER_WRITE"


def writes_enabled(env=None) -> bool:
    return (os.environ if env is None else env).get(GATE) == "1"


# ---- status: read-only ---------------------------------------------------------------------------
def _kernel_ok(version: str) -> Optional[bool]:
    m = re.match(r"^(\d+)\.(\d+)", version or "")
    return None if not m else (int(m.group(1)), int(m.group(2))) >= (5, 8)


def status(evidence) -> dict:
    """What the last cluster read says about Falco: where it runs, how healthy, how much of the cluster it covers."""
    dss = [d for d in evidence.get("DaemonSet", all_scopes=True)
           if "falco" in ((d.get("metadata") or {}).get("name") or "").lower() and "sidekick" not in ((d.get("metadata") or {}).get("name") or "").lower()]
    nodes = evidence.get("Node", all_scopes=True)
    node_info = [{"name": (n.get("metadata") or {}).get("name"), "kernel": ((n.get("status") or {}).get("nodeInfo") or {}).get("kernelVersion", ""),
                  "os": ((n.get("status") or {}).get("nodeInfo") or {}).get("osImage", ""),
                  "arch": ((n.get("status") or {}).get("nodeInfo") or {}).get("architecture", "")} for n in nodes]
    base = {"nodes": node_info, "node_count": len(nodes)}
    if not dss:
        return dict(base, state="not-installed", message="Falco is not running in this cluster.", namespace="", name="", version="",
                    ready=0, desired=0, coverage=0.0, problems=[], sidekick=False)
    d = dss[0]
    md, st = d.get("metadata") or {}, d.get("status") or {}
    ns = md.get("namespace", "")
    ready, desired = int(st.get("numberReady") or 0), int(st.get("desiredNumberScheduled") or 0)
    img = next(iter((((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or [{}]), {}).get("image", "")
    version = img.rsplit(":", 1)[-1] if ":" in img.rsplit("/", 1)[-1] else ""
    problems = []
    for p in evidence.get("Pod", all_scopes=True):
        pm = p.get("metadata") or {}
        if pm.get("namespace") == ns and "falco" in (pm.get("name") or "") and "sidekick" not in (pm.get("name") or ""):
            for c in ((p.get("status") or {}).get("containerStatuses") or []):
                w = (c.get("state") or {}).get("waiting") or {}
                if w.get("reason") in ("CrashLoopBackOff", "Error", "ImagePullBackOff", "CreateContainerConfigError"):
                    problems.append(f"{pm.get('name')}: {w['reason']}")
    sidekick = any("sidekick" in ((x.get("metadata") or {}).get("name") or "") for x in evidence.get("Deployment", all_scopes=True)
                   if (x.get("metadata") or {}).get("namespace") == ns)
    release = any(((s.get("metadata") or {}).get("name") or "").startswith("sh.helm.release.v1.falco.")
                  for s in evidence.get("Secret", all_scopes=True) if (s.get("metadata") or {}).get("namespace") == ns)
    cov = round(ready / len(nodes), 2) if nodes else 0.0
    state = "unhealthy" if problems or (desired and not ready) else ("partial" if desired and ready < max(desired, len(nodes)) else "healthy")
    msg = {"healthy": f"Falco is running on {ready} of {len(nodes)} node(s).",
           "partial": f"Falco is running on {ready} of {len(nodes)} node(s). The others are not covered.",
           "unhealthy": "Falco is installed but not working: " + ("; ".join(problems[:2]) or "no pod is ready") + "."}[state]
    return dict(base, state=state, message=msg, namespace=ns, name=md.get("name", ""), version=version, ready=ready, desired=desired,
                coverage=cov, problems=problems, sidekick=sidekick, helm_release=release)


# ---- the plan --------------------------------------------------------------------------------------
SECRET_NAME = "kmw-falcosidekick"
_PRIORITIES = ("debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency")


def clean_alerts(alerts: Optional[dict]) -> Optional[dict]:
    """Slack destination for alerts. The URL is a credential: it is checked here, goes only into a Secret
    applied on stdin, and is never put in command arguments, in the Helm values, or in a response."""
    if not alerts or not str(alerts.get("slack_webhook") or "").strip():
        return None
    url = str(alerts["slack_webhook"]).strip()
    if not re.match(r"^https://[A-Za-z0-9.-]+/\S{4,380}$", url):
        raise ValueError("The Slack webhook must be an https:// address with no spaces.")
    pr = str(alerts.get("min_priority") or "warning").lower()
    if pr not in _PRIORITIES:
        raise ValueError("The minimum priority must be one of " + ", ".join(_PRIORITIES) + ".")
    return {"slack_webhook": url, "min_priority": pr}


def _secret_yaml(namespace: str, url: str) -> str:
    import yaml
    return yaml.safe_dump({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET_NAME, "namespace": namespace, "labels": {"app.kubernetes.io/managed-by": "K8sMatrixWarden"}},
                           "type": "Opaque", "stringData": {"SLACK_WEBHOOKURL": url}})


def values(custom_rules_yaml: str = "", node_selector: Optional[dict] = None, alerts: Optional[dict] = None) -> dict:
    v = {"driver": {"kind": "modern_ebpf"},
         "falco": {"json_output": True, "json_include_output_property": True},
         "resources": {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}},
         "tolerations": []}
    if node_selector:
        v["nodeSelector"] = node_selector
    a = clean_alerts(alerts)
    if a:
        v["falcosidekick"] = {"enabled": True, "config": {"existingSecret": SECRET_NAME, "slack": {"minimumpriority": a["min_priority"]}}}
    if custom_rules_yaml.strip():
        v["customRules"] = {"kmw-rules.yaml": custom_rules_yaml}
    return v


def _ns_yaml(ns: str) -> str:
    return ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    app.kubernetes.io/managed-by: K8sMatrixWarden\n"
            "    pod-security.kubernetes.io/enforce: privileged\n    pod-security.kubernetes.io/audit: privileged\n"
            "    pod-security.kubernetes.io/warn: privileged\n" % ns)


def preflight(st: dict, have: Optional[Callable[[str], Optional[str]]] = None, namespace: str = "falco") -> list[dict]:
    """Checks a careful operator would run before installing a privileged DaemonSet."""
    have = have or shutil.which
    out = []
    add = lambda i, t, s, d: out.append({"id": i, "title": t, "status": s, "detail": d})              # noqa: E731
    add("helm", "Helm is installed on this machine", "ok" if have("helm") else "bad", "" if have("helm") else "Install Helm (brew install helm); the deploy runs it for you.")
    add("kubectl", "kubectl is installed on this machine", "ok" if have("kubectl") else "bad", "" if have("kubectl") else "Install kubectl; the deploy runs it for you.")
    if st["state"] != "not-installed":
        add("existing", "Falco is not already installed", "warn", f"Falco is already in namespace {st['namespace']}; a deploy would upgrade it.")
    nodes = st.get("nodes") or []
    if nodes:
        bad = [n["name"] for n in nodes if _kernel_ok(n["kernel"]) is False]
        add("kernel", "Node kernels support Falco's eBPF probe (5.8 or newer)", "bad" if bad else "ok",
            f"Too old: {', '.join(bad[:3])}." if bad else f"{len(nodes)} node(s) checked.")
        vm = [n["name"] for n in nodes if re.search(r"docker desktop|minikube|kind|colima|lima", (n["os"] + " " + n["name"]).lower())]
        if vm:
            add("virtual", "Nodes are real machines or full VMs", "warn",
                "This looks like a local dev cluster (Docker Desktop, minikube or kind). Falco may start fine but capture no events there; "
                "we saw exactly that. Use a cloud or bare-metal node for real coverage.")
        else:
            add("virtual", "Nodes are real machines or full VMs", "ok", "")
    else:
        add("kernel", "Node kernels support Falco's eBPF probe (5.8 or newer)", "warn", "Run a cluster scan first so the nodes can be checked.")
    add("namespace", f"Own namespace '{namespace}' with a privileged Pod Security label", "ok",
        "Created for Falco only; nothing else in your cluster is touched. Falco needs host access, so only this namespace is relaxed.")
    add("limits", "Resource limits so Falco cannot starve your apps", "ok", "100m CPU / 256Mi requested, 1 CPU / 1Gi at most, per node.")
    add("atomic", "A failed install rolls itself back", "ok", "Helm runs with --atomic --wait: if Falco does not come up, the install is undone.")
    add("tolerations", "Control-plane nodes are left alone", "ok", "No tolerations are added, so Falco runs on worker nodes only.")
    return out


def commands(release: str = "falco", namespace: str = "falco", context: str = "", values_file: str = "falco-values.yaml", alerts: bool = False) -> list[dict]:
    kc = ["--kube-context", context] if context else []
    kctx = ["--context", context] if context else []
    secret = [{"title": "Store the Slack alert address in a Secret (never in the Helm values)", "writes": True, "argv": ["kubectl", *kctx, "apply", "-f", "-"], "stdin": "secret"}] if alerts else []
    return [
        {"title": f"Create the '{namespace}' namespace (privileged Pod Security, Falco only)", "writes": True, "argv": ["kubectl", *kctx, "apply", "-f", "-"], "stdin": "ns"},
        *secret,
        {"title": "Add the Falco chart repository (local Helm config only)", "writes": False, "argv": ["helm", "repo", "add", REPO[0], REPO[1], "--force-update"]},
        {"title": "Refresh the chart list (local only)", "writes": False, "argv": ["helm", "repo", "update", REPO[0]]},
        {"title": "Install Falco", "writes": True,
         "argv": ["helm", *kc, "upgrade", "--install", release, "falcosecurity/falco", "-n", namespace, "-f", values_file,
                  "--atomic", "--wait", "--timeout", "300s", "--description", MARK]},
    ]


def validate_args(namespace: str, context: str) -> None:
    if not _NS.match(namespace or ""):
        raise ValueError("The namespace must be lowercase letters, numbers and dashes.")
    if context and not _CTX.match(context):
        raise ValueError("The kube context name has characters that are not allowed.")


def plan(st: dict, custom_rules_yaml: str = "", namespace: str = "falco", context: str = "", node_selector: Optional[dict] = None,
         have=None, runner=None, alerts: Optional[dict] = None) -> dict:
    """What a deploy would do, with the exact commands, the generated values, and (when Helm is available) what the chart renders."""
    import yaml
    validate_args(namespace, context)
    vals = values(custom_rules_yaml, node_selector, alerts)
    pre = preflight(st, have, namespace)
    if clean_alerts(alerts):
        pre.append({"id": "alerts", "title": "Alerts go to Slack", "status": "ok",
                    "detail": f"Falco's alert forwarder (falcosidekick) is added, at priority {clean_alerts(alerts)['min_priority']} and above. The address is stored in a Secret, not in the Helm values."})
    out = {"namespace": namespace, "preflight": pre, "values": yaml.safe_dump(vals, sort_keys=False), "commands": commands(namespace=namespace, context=context, alerts=bool(clean_alerts(alerts))),
           "writes_enabled": writes_enabled(), "blocked": any(c["status"] == "bad" for c in pre), "renders": None}
    have = have or shutil.which
    runner = runner or subprocess.run
    if have("helm"):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            vf = os.path.join(d, "v.yaml")
            with open(vf, "w", encoding="utf-8") as fh:
                fh.write(out["values"])
            try:
                runner(["helm", "repo", "add", REPO[0], REPO[1], "--force-update"], capture_output=True, text=True, timeout=60)
                r = runner(["helm", "template", "falco", "falcosecurity/falco", "-n", namespace, "-f", vf], capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    kinds: dict = {}
                    for m in re.finditer(r"^kind: (\w+)", r.stdout, re.M):
                        kinds[m.group(1)] = kinds.get(m.group(1), 0) + 1
                    out["renders"] = {"ok": True, "kinds": kinds}
                else:
                    out["renders"] = {"ok": False, "error": (r.stderr or r.stdout).strip()[-400:]}
                    out["blocked"] = True
            except (OSError, subprocess.SubprocessError) as exc:
                out["renders"] = {"ok": False, "error": str(exc)[:200]}
    return out


# ---- run (gated) -----------------------------------------------------------------------------------
class Deployer:
    """Runs the plan in a background thread and keeps the progress where the page can poll it."""

    def __init__(self):
        self.runs: dict = {}
        self._lock = threading.Lock()

    def start(self, kind: str, steps: list, stdin_map: dict, runner=None) -> str:
        rid = uuid.uuid4().hex[:8]
        run = {"id": rid, "kind": kind, "state": "running", "started": time.time(), "steps": [{"title": s["title"], "status": "pending", "output": ""} for s in steps]}
        with self._lock:
            self.runs[rid] = run
        threading.Thread(target=self._go, args=(run, steps, stdin_map, runner or subprocess.run), daemon=True).start()
        return rid

    def _go(self, run, steps, stdin_map, runner):
        for i, s in enumerate(steps):
            run["steps"][i]["status"] = "running"
            try:
                p = runner(s["argv"], input=stdin_map.get(s.get("stdin")) if s.get("stdin") else None, capture_output=True, text=True, timeout=420)
                run["steps"][i]["output"] = ((p.stdout or "") + (p.stderr or "")).strip()[-600:]
                ok = p.returncode == 0
            except (OSError, subprocess.SubprocessError) as exc:
                run["steps"][i]["output"], ok = str(exc)[:300], False
            run["steps"][i]["status"] = "done" if ok else "failed"
            if not ok:
                run["state"] = "failed"
                return
        run["state"] = "done"

    def get(self, rid: str) -> Optional[dict]:
        return self.runs.get(rid)


def deploy_steps(st: dict, custom_rules_yaml: str, namespace: str, context: str, tmpdir: str, node_selector=None, alerts=None) -> tuple[list, dict]:
    import yaml
    validate_args(namespace, context)
    a = clean_alerts(alerts)
    vf = os.path.join(tmpdir, "falco-values.yaml")
    with open(vf, "w", encoding="utf-8") as fh:
        yaml.safe_dump(values(custom_rules_yaml, node_selector, alerts), fh, sort_keys=False)
    stdin = {"ns": _ns_yaml(namespace)}
    if a:
        stdin["secret"] = _secret_yaml(namespace, a["slack_webhook"])
    return commands(namespace=namespace, context=context, values_file=vf, alerts=bool(a)), stdin


def remove_steps(namespace: str, context: str, status_runner=None) -> list:
    """Uninstall only a release this tool installed. Anything else is refused with a reason."""
    validate_args(namespace, context)
    runner = status_runner or subprocess.run
    kc = ["--kube-context", context] if context else []
    try:
        p = runner(["helm", *kc, "status", "falco", "-n", namespace, "-o", "json"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Could not ask Helm about the release: " + str(exc)[:120])
    if p.returncode != 0:
        raise ValueError("There is no Helm release named 'falco' in that namespace.")
    import json
    desc = ((json.loads(p.stdout or "{}").get("info") or {}).get("description") or "")
    if MARK not in desc:
        raise ValueError("This Falco was not installed by K8sMatrixWarden, so it will not remove it. Remove it with the tool that installed it.")
    return [{"title": "Uninstall Falco (the release this tool installed)", "writes": True, "argv": ["helm", *kc, "uninstall", "falco", "-n", namespace]}]
