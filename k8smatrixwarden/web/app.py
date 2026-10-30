"""
WebApp, the dashboard's routing + logic, deliberately socket-free so it is unit-testable.

`WebApp.route(method, path, query, body)` returns a `Response`; `server.py` is a thin
`http.server` shell that just calls it. Every HTML surface reuses the same ReportingEngine,
ReportStore, and threat-matrix builder the CLI/MCP use, the dashboard is a *view* over the
one engine, it never re-implements scanning or reporting.

Read-mostly by design: the only state-changing route is `POST /api/scan`, which runs a
read-only scan and saves the result. The tool detects and reports only, it never mutates
the cluster from any surface.
"""
from __future__ import annotations

import json
import threading
import os
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs

from ..core.models import (ScanMode, ScanRequest, Scope, ScopeLevel, Selector, Severity)
from ..core.report_store import DEFAULT_DIR, ReportStore
from ..core.finding_context import _owasp_taxonomy
from ..core.reporting import scan_warning_lines, _esc
from ..core.results import ScanResult
from ..core.threat_matrix import build_threat_matrix
from . import pages

_VALID_FORMATS = {"json", "markdown", "md", "sarif", "html", "text", "terminal", "brief"}
_VENDOR_ASSETS = {"cytoscape.min.js"}  # allow-list, no arbitrary file reads via /vendor/<name>


@dataclass
class Response:
    status: int = 200
    content_type: str = "text/html; charset=utf-8"
    body: bytes = b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _html(body: str, status: int = 200) -> Response:
    return Response(status, "text/html; charset=utf-8", body.encode("utf-8"))


def _json(obj, status: int = 200) -> Response:
    return Response(status, "application/json; charset=utf-8",
                    json.dumps(obj, indent=2, default=str).encode("utf-8"))


def _text(s: str, status: int = 200) -> Response:
    return Response(status, "text/plain; charset=utf-8", s.encode("utf-8"))


#: Serialises the read-modify-write that persists a runtime batch. See _api_runtime.
_RUNTIME_PERSIST_LOCK = threading.Lock()


def _slim(d: dict) -> dict:
    """A finding as the list views need it. The route lists and the full last-applied manifest
    each object carries were most of the payload and nothing in a list reads them."""
    out = {k: v for k, v in d.items() if k != "rbac_paths"}
    res = dict(out.get("resource") or {})
    ann = dict(res.get("annotations") or {})
    ann.pop("kubectl.kubernetes.io/last-applied-configuration", None)
    res["annotations"] = ann
    out["resource"] = res
    return out


def _workload_summary(result) -> dict:
    """Resource-finding and workload-issue counts for the dashboard, recomputed for reports
    saved before workload aggregation existed so an old scan still shows both."""
    from ..core.reporting import workload_summary
    return workload_summary(result)


class WebApp:
    def __init__(self, platform, reports_dir: str = DEFAULT_DIR,
                 allow_scan: bool = True, allow_client_kubeconfig: bool = True):
        self.p = platform
        self.reports_dir = reports_dir
        self.allow_scan = allow_scan
        #: Whether `POST /api/scan` may accept a kubeconfig from the request body.
        #:
        #: Loading a kubeconfig EXECUTES its credential plugin (`aws eks get-token`,
        #: `gke-gcloud-auth-plugin`, `kubelogin`, …), that is how cloud auth works, and
        #: the `kubernetes` client does it too. So a caller who can supply a kubeconfig
        #: can run an arbitrary command as the server's user. That is fine when the only
        #: possible caller is the operator on loopback, and it is remote code execution
        #: the moment the server binds a routable address. `server.serve()` therefore sets
        #: this False for a non-loopback bind unless the operator opts back in
        #: (`--allow-remote-kubeconfig`) after putting their own authentication in front.
        self.allow_client_kubeconfig = allow_client_kubeconfig

    @property
    def tasks(self):
        if getattr(self, "_tasks", None) is None:
            from .tasks import TaskManager
            self._tasks = TaskManager(self.reports_dir)
        return self._tasks

    # ------------------------------------------------------------------ #
    # Tasks (background scans) and accepted risks
    def _api_tasks(self, method: str, parts: list, q: dict, body: bytes) -> Response:
        from .tasks import KINDS, TaskError
        if method == "GET":
            if len(parts) == 3:
                t = self.tasks.get(parts[2])
                return _json(t, 200) if t else _json({"error": "No such task."}, 404)
            return _json({"tasks": self.tasks.list(), "kinds": KINDS,
                          "can_run": self.allow_scan, "can_use_paths": self.allow_client_kubeconfig})
        if not self.allow_scan:
            return _json({"error": "Starting scans is disabled on this server."}, 403)
        try:
            data = json.loads(body or b"{}")
        except ValueError as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        if method == "POST" and parts[2:] == ["cancel"]:
            return _json({"cancelled": self.tasks.cancel(str(data.get("id", "")))})
        if method == "POST" and len(parts) == 2:
            if data.get("kind") == "scan-manifests" and not self.allow_client_kubeconfig:
                return _json({"error": "Scanning server-side paths is only allowed when the "
                                       "dashboard is bound to loopback."}, 403)
            cleanup = None
            if data.get("kind") == "scan-live":
                try:
                    kc_path, cleanup = self._resolve_kubeconfig(data)
                except PermissionError as exc:
                    return _json({"error": str(exc)}, 403)
                if kc_path:
                    data["kubeconfig"] = kc_path
            try:
                return _json(self.tasks.submit(str(data.get("kind", "")), data, cleanup), 202)
            except TaskError as exc:
                if cleanup:
                    try:
                        os.unlink(cleanup)
                    except OSError:
                        pass
                return _json({"error": str(exc)}, 400)
        return _json({"error": "Unsupported request."}, 405)

    def _api_build(self, method: str, action: str, body: bytes) -> Response:
        """The builder: components in, manifests / Helm chart / security check out. Pure
        generation, never applied to a cluster."""
        from ..core import builder
        if method != "POST":
            return _json({"error": "Use POST."}, 405)
        try:
            spec = json.loads(body or b"{}")
        except ValueError as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        try:
            if action == "designs":
                op = spec.get("op", "list")
                if op != "list" and not self.allow_scan:
                    return _json({"error": "Saving designs is disabled on this server."}, 403)
                if op == "save":
                    builder.blueprint_save(self.reports_dir, spec.get("name"), spec.get("spec") or {})
                elif op == "load":
                    return _json({"spec": builder.blueprint_load(self.reports_dir, spec.get("name"))})
                elif op == "delete":
                    builder.blueprint_delete(self.reports_dir, spec.get("name"))
                return _json({"designs": builder.blueprint_list(self.reports_dir)})
            if action == "exceptions":
                return _json({"exceptions": builder.exceptions(spec)})
            if action == "drift":
                sid = spec.pop("scan_id", None)
                if sid:
                    result = self.store.resolve(sid)
                else:
                    recent = self.store.list(limit=1)
                    result = self.store.resolve(recent[0].scan_id) if recent else None
                if result is None:
                    return _json({"error": "There is no saved scan to compare with. Run a scan first."}, 404)
                return _json(dict(builder.drift(spec, result.cluster_inventory), scan=result.display_name))
            if action == "digest":
                if not self.allow_scan:
                    return _json({"error": "Looking up images is disabled on this server."}, 403)
                return _json(builder.resolve_digest(spec.get("image")))
            if action == "imagescan":
                if not self.allow_scan:
                    return _json({"error": "Scanning images is disabled on this server."}, 403)
                return _json(builder.scan_image(spec.get("image")))
            if action == "preview":
                analysis = builder.analyze(spec, self.p)
                lay = builder.layers(spec, self._build_env())
                return _json({"yaml": builder.manifests_yaml(spec), "install": builder.install_command(spec),
                              "check": builder.check(spec, self.p, analysis), "layers": lay,
                              "threat_model": builder.threat_model(spec, lay, analysis),
                              "attack_paths": self._design_paths(analysis),
                              "presets": builder.ROLE_PRESETS, "env": self._build_env()})
            if action == "chart":
                return Response(200, "application/gzip", builder.chart_tgz(spec))
            if action == "files":
                return _json({"files": builder.chart_files(spec)})
        except builder.BuildError as exc:
            body = {"error": str(exc), "component": getattr(exc, "component", "")}
            if action == "preview":
                try:                                  # the layers need no resolved targets, so a half-built design still gets them
                    body["layers"] = builder.layers(spec, self._build_env())
                    body["presets"] = builder.ROLE_PRESETS
                    body["env"] = self._build_env()
                except builder.BuildError:
                    pass
            return _json(body, 422)
        return _json({"error": f"Unknown builder action '{action}'."}, 404)

    def _deps_state(self) -> dict:
        if getattr(self, "_deps", None) is None:
            from ..core.dependencies import SbomStore
            self._deps = {"store": SbomStore(), "observed": {}, "jobs": {}, "install": None,
                          "lock": threading.Lock()}
        return self._deps

    def _api_deps(self, method: str, action: str, body: bytes) -> Response:
        """Dependency manager: SBOM per running image, vulnerabilities on it, and what is really loaded.
        Building SBOMs pulls images and observing runs read-only commands inside pods, both only when asked."""
        import subprocess
        import time
        from concurrent.futures import ThreadPoolExecutor
        from ..core import dependencies as dp
        from ..core import tool_install as ti
        if method != "POST":
            return _json({"error": "Use POST."}, 405)
        try:
            data = json.loads(body or b"{}")
        except ValueError as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        st = self._deps_state()
        store = st["store"]
        if action == "install":
            # Bundles the official syft/grype into a tool-local bin. No cluster needed, so this
            # runs before the pod read below. Background, like generate: the download is slow.
            names = [n for n in ("syft", "grype") if not ti.resolve(n)]
            need_db = bool(ti.resolve("grype")) and ti.grype_db_status().get("state") != "valid"
            if (names or need_db) and (st.get("install") or {}).get("state") != "running":
                st["install"] = {"state": "running", "names": names or (["grype-db"] if need_db else [])}

                def do_install():
                    res = ti.install_all(names)
                    ok = all(v.get("ok") for v in res.values())          # True when names is empty
                    if ok and ti.resolve("grype"):          # warm grype's DB so the first report doesn't stall
                        res["grype-db"] = ti.warm_grype_db()
                    st["install"] = {"state": "done" if ok else "error", "result": res}
                threading.Thread(target=do_install, daemon=True).start()
            return _json({"started": names, "install": st.get("install"), "tools": store.tools(),
                          "db": ti.grype_db_status()})
        try:
            pods = self.p.make_collector(mock=False).collect({"Pod"}, Scope(ScopeLevel.CLUSTER)).get("Pod")
        except Exception as exc:                                    # no cluster is a state, not a crash
            msg = "Could not read the cluster: " + str(exc).splitlines()[0][:160]
            # `images` still reports tool status (cluster-independent) so the tab renders and
            # the install state is visible even with no cluster; the rest genuinely need pods.
            if action == "images":
                return _json({"tools": store.tools(), "images": [], "install": st.get("install"),
                              "db": ti.grype_db_status(), "error": msg})
            return _json({"error": msg}, 502)
        imgs = {i["key"]: i for i in dp.inventory(pods)}
        key = data.get("key", "")
        if action == "images":
            rows = []
            for i in imgs.values():
                obs = st["observed"].get(i["key"])
                rows.append({"key": i["key"], "image": i["image"], "pinned": i["pinned"], "workloads": i["workloads"],
                             "pods": len(i["pods"]), "sbom": store.has(i["key"]), "job": st["jobs"].get(i["key"]),
                             "observed": bool(obs), "observedAt": obs["at"] if obs else None})
            return _json({"tools": store.tools(), "images": rows, "install": st.get("install"),
                          "db": ti.grype_db_status()})
        if action == "generate":
            keys = list(imgs) if data.get("all") else [k for k in (data.get("keys") or [key]) if k in imgs]
            todo = [k for k in keys if not store.has(k) and (st["jobs"].get(k) or {}).get("state") != "running"]
            for k in todo:
                st["jobs"][k] = {"state": "running"}

            def work(k):
                r = store.generate(imgs[k])
                st["jobs"][k] = {"state": "error", "error": r["error"]} if "error" in r else {"state": "done"}
            if todo:
                def run_all():
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        list(pool.map(work, todo))
                threading.Thread(target=run_all, daemon=True).start()
            return _json({"started": len(todo)})
        if action == "report":
            img = imgs.get(key)
            sb = store.load(key) if img else None
            if not sb:
                return _json({"error": "No SBOM for this image yet. Build it first."}, 404)
            obs = st["observed"].get(key)
            rep = dp.report(sb, store.vulnerabilities(key), set(obs["files"]) if obs else None)
            rep["image"] = {k: img[k] for k in ("key", "image", "workloads", "pinned")}
            rep["observation"] = {"at": obs["at"], "pods": obs["pods"]} if obs else None
            return _json(rep)
        if action == "search":
            stores = {}
            for k, i in imgs.items():
                sb = store.load(k) if store.has(k) else None
                if sb:
                    stores[k] = {"image": i["image"], "workloads": i["workloads"], "packages": sb["packages"]}
            return _json({"results": dp.search(stores, data.get("q", "")), "searched": len(stores), "images": len(imgs)})
        if action == "export":
            out = store.export(key, data.get("format", "cyclonedx-json"))
            return _json({"error": "No SBOM to export."}, 404) if out is None else Response(200, "application/json", out.encode())
        if action == "observe":
            img = imgs.get(key)
            if not img:
                return _json({"error": "That image is not running."}, 404)
            if data.get("confirm") != "observe":
                return _json({"error": "Observing runs read-only commands inside the pods. Send confirm=observe."}, 400)
            running, seen = [], set()
            for pd in img["pods"]:                                    # one pod per workload, three at most
                wl = pd["name"].rsplit("-", 2)[0]
                if pd["running"] and wl not in seen and len(running) < 3:
                    seen.add(wl)
                    running.append(pd)
            files, results = set(), []
            for pd in running:
                try:
                    r = subprocess.run(["kubectl", "exec", "-n", pd["namespace"], pd["name"], "-c", pd["container"], "--",
                                        "sh", "-c", dp.OBSERVE_SCRIPT], capture_output=True, text=True, timeout=30)
                    ok = r.returncode == 0 and "F /" in r.stdout
                    files |= set(dp.parse_observation(r.stdout)["files"]) if ok else set()
                    results.append({"pod": pd["name"], "ok": ok, "error": "" if ok else (r.stderr.strip().splitlines() or ["no output"])[-1][:200]})
                except (OSError, subprocess.SubprocessError) as exc:
                    results.append({"pod": pd["name"], "ok": False, "error": str(exc)[:200]})
            if files:
                st["observed"][key] = {"files": sorted(files), "at": time.strftime("%Y-%m-%d %H:%M:%S"), "pods": results}
            return _json({"observed": bool(files), "pods": results})
        return _json({"error": f"Unknown dependency action '{action}'."}, 404)

    def _falco_status(self) -> dict:
        """Falco's state from a live, read-only cluster read (cached briefly: the page asks often)."""
        import time
        from ..core import falco_deploy
        cached = getattr(self, "_falco_cache", None)
        if cached and time.time() - cached[0] < 15:
            return cached[1]
        try:
            collector = self.p.make_collector(mock=False)
            ev = collector.collect({"DaemonSet", "Pod", "Node", "Deployment", "Secret"}, Scope(ScopeLevel.CLUSTER))
            st = falco_deploy.status(ev)
        except Exception as exc:                                    # no cluster access is a state, not a crash
            why = str(exc).splitlines()[0][:160]
            if "Service host/port" in why or "Connection refused" in why or "Max retries" in why:
                why = "no cluster answered. Start your cluster, or check the kubeconfig and context the dashboard was started with."
            st = {"state": "unreachable", "message": "Could not read the cluster: " + why, "nodes": [], "node_count": 0,
                  "namespace": "", "name": "", "version": "", "ready": 0, "desired": 0, "coverage": 0.0, "problems": [], "sidekick": False}
        self._falco_cache = (time.time(), st)
        return st

    def _api_rules(self, method: str, action: str, body: bytes) -> Response:
        """The Runtime tab's rule workbench: what is deployed, guided rule creation, tests, and a gated Falco deploy."""
        import tempfile
        from ..core import falco_deploy, runtime_rules as rr
        if method != "POST":
            return _json({"error": "Use POST."}, 405)
        try:
            data = json.loads(body or b"{}")
        except ValueError as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        spec = data.get("spec") or {}
        try:
            if action == "behaviors":
                return _json({"behaviors": {k: {kk: vv for kk, vv in v.items()} for k, v in rr.BEHAVIORS.items()}, "tactics": rr.TACTICS,
                              "priorities": rr.PRIORITIES, "exception_fields": rr._EXC_FIELDS, "examples": rr.EXAMPLES})
            if action == "catalog":
                cache = os.path.join(os.path.expanduser("~"), ".cache", "k8smatrixwarden")
                dflt = rr.default_rules(cache) if data.get("defaults") else {"rules": [], "error": ""}
                return _json({"curated": rr.curated_rules(), "default": dflt["rules"], "default_error": dflt["error"],
                              "custom": rr.list_saved(self.reports_dir)})
            if action == "generate":
                y = rr.to_yaml(spec)
                return _json({"yaml": y, "condition": rr.condition(spec), "lint": rr.lint(y), "explain": [] if rr.normalize(spec)["advanced"] else rr.explain(spec)})
            if action == "test":
                custom = [{"label": c.get("label"), "event": rr.parse_event_lines(c.get("lines", "")) if "lines" in c else c.get("event"),
                           "expected": c.get("expected")} for c in data.get("events") or []]
                return _json(rr.run_tests(spec, custom))
            if action == "validate":
                y = rr.to_yaml(spec)
                return _json({"lint": rr.lint(y), "engine": rr.validate_with_falco(y) if data.get("engine") else None})
            if action in ("save", "delete"):
                if not self.allow_scan:
                    return _json({"error": "Saving rules is disabled on this server."}, 403)
                if action == "save":
                    rr.save_rule(self.reports_dir, spec)
                else:
                    rr.delete_rule(self.reports_dir, data.get("name"))
                return _json({"custom": rr.list_saved(self.reports_dir)})
            if action == "falco-status":
                return _json(self._falco_status())
            if action in ("rule-stats", "health"):
                from ..core import runtime_ops as ops
                ns = data.get("namespace") or "falco"
                hours = max(1, min(168, int(data.get("hours") or 24)))
                try:
                    collector = self.p.make_collector(mock=False)
                except Exception as exc:
                    return _json({"error": "Could not reach the cluster: " + str(exc).splitlines()[0][:140]}, 400)
                if action == "health":
                    return _json(ops.health(collector.falco_logs(ns, hours * 3600)  if hasattr(collector, "falco_logs") else {}, hours))
                events = collector.collect_runtime_events(namespace=ns, since_seconds=hours * 3600, tail_lines=4000)
                stats = ops.rule_stats(events, hours)
                extra = {}
                for r in rr.list_saved(self.reports_dir):
                    st = stats.get(r["name"])
                    extra[r["name"]] = {"advice": ops.advice(st, r["stage"]), "suggestions": ops.suggest_exceptions(st, r["spec"])}
                return _json({"stats": stats, "tuning": extra, "events_read": len(events), "hours": hours})
            if action == "coverage":
                from ..core import runtime_ops as ops
                cache = os.path.join(os.path.expanduser("~"), ".cache", "k8smatrixwarden")
                rules = rr.curated_rules() + rr.list_saved(self.reports_dir) + rr.default_rules(cache)["rules"]
                return _json(ops.mitre_coverage(rules, self._falco_status().get("state", "")))
            if action in ("agents", "agents-save"):
                from ..core import agent_coverage as ac
                if action == "agents-save":
                    if not self.allow_scan:
                        return _json({"error": "Changing the agent list is disabled on this server."}, 403)
                    ac.save_config(self.reports_dir, data.get("tracked") or [], data.get("min_versions") or {}, data.get("custom") or [])
                agents = ac.load_agents(self.reports_dir)
                try:
                    collector = self.p.make_collector(mock=False)
                    ev = collector.collect({"Node", "Pod", "DaemonSet"}, Scope(ScopeLevel.CLUSTER))
                except Exception as exc:
                    return _json({"error": "Could not read the cluster: " + str(exc).splitlines()[0][:140], "config": agents}, 400)
                rep = ac.report(ev, agents)
                rep["config"] = [{k: a[k] for k in ("id", "name", "vendor", "kind", "tracked", "min_version", "custom", "what")} for a in agents]
                return _json(rep)
            if action == "history":
                return _json({"history": rr.history(self.reports_dir, data.get("name"))})
            if action == "restore":
                if not self.allow_scan:
                    return _json({"error": "Changing rules is disabled on this server."}, 403)
                rr.restore(self.reports_dir, data.get("name"), data.get("index"))
                return _json({"custom": rr.list_saved(self.reports_dir)})
            if action == "export":
                from ..core import runtime_rules as _r
                return _json({"pack": rr.export_pack(self.reports_dir), "yaml": _r.to_yaml([x["spec"] for x in rr.list_saved(self.reports_dir)]) if rr.list_saved(self.reports_dir) else ""})
            if action == "import":
                if not self.allow_scan:
                    return _json({"error": "Importing rules is disabled on this server."}, 403)
                res = rr.import_pack(self.reports_dir, data.get("pack"), bool(data.get("overwrite")))
                return _json(dict(res, custom=rr.list_saved(self.reports_dir)))
            if action == "simulate":
                from ..core import runtime_ops as ops
                return _json(ops.simulation_plan(spec))
            if action == "falco-plan":
                saved = [x["spec"] for x in rr.list_saved(self.reports_dir)] if data.get("include_rules", True) else []
                return _json(falco_deploy.plan(self._falco_status(), rr.to_yaml(saved) if saved else "", data.get("namespace") or "falco",
                                               data.get("context") or "", data.get("node_selector") or None, alerts=data.get("alerts")))
            if action in ("falco-deploy", "falco-remove"):
                want = "deploy-falco" if action == "falco-deploy" else "remove-falco"
                if not self.allow_scan:
                    return _json({"error": "Changing the cluster is disabled on this server (--no-scan)."}, 403)
                if not falco_deploy.writes_enabled():
                    return _json({"error": "This dashboard is read-only. To allow it to deploy Falco, restart it with "
                                           f"{falco_deploy.GATE}=1. Nothing was changed.", "gated": True}, 403)
                if data.get("confirm") != want:
                    return _json({"error": f"Confirmation missing: send confirm='{want}'."}, 400)
                ns, ctx = data.get("namespace") or "falco", data.get("context") or ""
                if not hasattr(self, "_deployer"):
                    self._deployer = falco_deploy.Deployer()
                if action == "falco-deploy":
                    st = self._falco_status()
                    if any(c["status"] == "bad" for c in falco_deploy.preflight(st, namespace=ns)):
                        return _json({"error": "A pre-flight check failed; fix it first (see the checks)."}, 409)
                    saved = [x["spec"] for x in rr.list_saved(self.reports_dir)] if data.get("include_rules", True) else []
                    tmp = tempfile.mkdtemp(prefix="kmw-falco-")
                    steps, stdin_map = falco_deploy.deploy_steps(st, rr.to_yaml(saved) if saved else "", ns, ctx, tmp, data.get("node_selector") or None, data.get("alerts"))
                else:
                    steps, stdin_map = falco_deploy.remove_steps(ns, ctx), {}
                rid = self._deployer.start(action, steps, stdin_map)
                self._falco_cache = None
                return _json({"run": rid}, 202)
            if action == "falco-run":
                run = getattr(self, "_deployer", None) and self._deployer.get(str(data.get("run")))
                if not run:
                    return _json({"error": "Unknown run."}, 404)
                if run["state"] in ("done", "failed"):
                    self._falco_cache = None
                    if run["state"] == "done" and run["kind"] == "falco-deploy" and not run.get("marked"):
                        run["marked"] = True
                        rr.mark_deployed(self.reports_dir, [x["name"] for x in rr.list_saved(self.reports_dir)])
                return _json(run)
        except (rr.RuleError, ValueError) as exc:
            return _json({"error": str(exc)}, 422)
        return _json({"error": f"Unknown action '{action}'."}, 404)

    @staticmethod
    def _design_paths(analysis) -> list:
        """Attack paths our own graph analysis finds in what the builder generated."""
        try:
            from .graph_page import build_graph
            return [{"summary": p["summary"], "severity": p["severity"], "entry": p["entry"], "target": p["target"],
                     "internet": p["internet"]} for p in build_graph(analysis)["paths"][:5]]
        except Exception:
            return []

    def _build_env(self) -> dict:
        """What the builder can learn about the real cluster from the latest saved scan: today, the
        network plugin, because a NetworkPolicy on a plugin that ignores it protects nothing."""
        import time
        cached = getattr(self, "_env_cache", None)
        if cached and time.time() - cached[0] < 60:
            return cached[1]
        env = {}
        try:
            recent = self.store.list(limit=1)
            result = self.store.resolve(recent[0].scan_id) if recent else None
            inv = (result.cluster_inventory if result else {}) or {}
            sec = inv.get("sections") or {}
            if sec:
                env["scanned"] = True
                names = " ".join(w.get("name", "") + " " + " ".join(w.get("images", []))
                                 for w in sec.get("workloads", [])
                                 if w.get("namespace") in ("kube-system", "calico-system", "tigera-operator", "cilium", "linkerd", "istio-system"))
                low = names.lower()
                for plugin in ("calico", "cilium", "antrea", "weave", "kube-router", "flannel", "kindnet"):
                    if plugin in low:
                        env["cni"] = plugin
                        break
                crds = " ".join((e.get("name") or "") + " " + (e.get("group") or "") for e in sec.get("extensions", []))
                nss = {n.get("name") for n in sec.get("namespaces", [])}
                if "linkerd.io" in crds or "linkerd" in nss:
                    env["mesh"] = "linkerd"
                elif "istio.io" in crds or "istio-system" in nss:
                    env["mesh"] = "istio"
                env["certmanager"] = "cert-manager.io" in crds or "cert-manager" in nss
                env["kyverno"] = "kyverno.io" in crds or "kyverno" in nss
        except Exception:
            env = {}
        self._env_cache = (time.time(), env)
        return env

    def _supp_file(self) -> str:
        return os.path.join(self.reports_dir, "suppressions.json")

    def _supp_read(self) -> list:
        try:
            with open(self._supp_file(), encoding="utf-8") as fh:
                return list((json.load(fh) or {}).get("suppressions", []))
        except (OSError, ValueError):
            return []

    def _supp_write(self, items: list) -> None:
        os.makedirs(self.reports_dir, exist_ok=True)
        with open(self._supp_file(), "w", encoding="utf-8") as fh:
            json.dump({"suppressions": items}, fh, indent=2)

    def _api_suppressions(self, method: str, parts: list, body: bytes) -> Response:
        import datetime as dt
        import uuid
        items = self._supp_read()
        if method == "GET":
            today = dt.date.today().isoformat()
            return _json({"suppressions": [dict(i, expired=bool(i.get("expires")) and i["expires"] < today)
                                           for i in items]})
        if not self.allow_scan:
            return _json({"error": "Changing accepted risks is disabled on this server."}, 403)
        try:
            data = json.loads(body or b"{}")
        except ValueError as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        if method == "POST" and parts[2:] == ["delete"]:
            keep = [i for i in items if i.get("id") != data.get("id")]
            self._supp_write(keep)
            return _json({"deleted": len(items) - len(keep)})
        if method == "POST" and len(parts) == 2:
            rule, reason = str(data.get("rule", "")).strip(), str(data.get("reason", "")).strip()
            if not rule or not reason:
                return _json({"error": "An accepted risk needs a rule and a reason."}, 400)
            exp = str(data.get("expires", "")).strip()
            if exp:
                try:
                    dt.date.fromisoformat(exp)
                except ValueError:
                    return _json({"error": "Expiry must be a date like 2026-12-31."}, 400)
            items.append({"id": uuid.uuid4().hex[:8], "rule": rule,
                          "resource": str(data.get("resource", "")).strip() or "*", "reason": reason,
                          "owner": str(data.get("owner", "")).strip(), "expires": exp,
                          "created": dt.date.today().isoformat()})
            self._supp_write(items)
            return _json({"ok": True, "suppressions": items}, 201)
        return _json({"error": "Unsupported request."}, 405)

    @property
    def store(self) -> ReportStore:
        return ReportStore(self.reports_dir)

    # ------------------------------------------------------------------ #
    # Router
    # ------------------------------------------------------------------ #
    def route(self, method: str, path: str, query: str = "",
              body: bytes = b"") -> Response:
        method = method.upper()
        path = "/" + path.strip("/") if path != "/" else "/"
        q = {k: v[0] for k, v in parse_qs(query or "").items()}
        parts = [p for p in path.split("/") if p]

        try:
            if method == "GET" and path == "/":
                return self._dashboard()
            if method == "GET" and path == "/health":
                return _json({"status": "ok", "rules": self.p.rule_count(),
                              "shards": len(self.p.registry.shard_names())})
            if method == "GET" and path == "/graph":
                return _html(pages.topology_page(self._load(q.get("scan_id"))))
            if method == "GET" and parts[:1] == ["vendor"] and len(parts) == 2:
                return self._vendor_asset(parts[1])
            if method == "GET" and path == "/api/reports":
                return self._api_reports(q)
            if method == "GET" and path == "/api/dashboard":
                return self._cached_dashboard(q.get("scan_id"))
            if method == "GET" and path == "/api/timeline":
                return _json(self._api_timeline(q))
            if method == "GET" and path == "/api/finding":
                return self._api_finding(q)
            if method == "POST" and path == "/api/scan":
                return self._api_scan(body)
            if parts[:2] == ["api", "build"] and len(parts) == 3:
                return self._api_build(method, parts[2], body)
            if parts[:2] == ["api", "runtime-rules"] and len(parts) == 3:
                return self._api_rules(method, parts[2], body)
            if parts[:2] == ["api", "deps"] and len(parts) == 3:
                return self._api_deps(method, parts[2], body)
            if path == "/api/tasks" or parts[:2] == ["api", "tasks"]:
                return self._api_tasks(method, parts, q, body)
            if path == "/api/suppressions" or parts[:2] == ["api", "suppressions"]:
                return self._api_suppressions(method, parts, body)
            if method == "POST" and path == "/api/runtime/refresh":
                return self._api_runtime_refresh(body)
            if method == "POST" and path == "/api/runtime/demo":
                return self._api_runtime_demo(body)
            if method == "POST" and path == "/api/runtime":
                return self._api_runtime(body)
            # Read side of the same path. Method dispatch keeps ingestion untouched: a
            # falcosidekick POST and an operator GET never meet.
            if method == "GET" and path == "/api/runtime":
                return self._api_runtime_events(q)
            if method == "GET" and path in ("/runtime-events", "/runtime/events",
                                            "/runtime-management", "/runtime"):
                return self._runtime_page()
            # /api/report/<id>  and  /api/report/<id>/matrix
            if method == "GET" and len(parts) >= 3 and parts[:2] == ["api", "report"]:
                if len(parts) == 3:
                    return self._api_report(parts[2], q)
                if len(parts) == 4 and parts[3] == "matrix":
                    return self._api_report_matrix(parts[2])
                if len(parts) == 4 and parts[3] == "topology":
                    return _json(self._load(parts[2]).topology)
        except _NotFound as exc:
            return self._not_found(str(exc), q)
        except Exception as exc:  # never leak a stack trace to the browser
            if _wants_json(path, q):
                return _json({"error": str(exc)}, 500)
            return _html(pages.error_page(500, f"Internal error: {exc}"), 500)

        return self._not_found(f"No route for {method} {path}", q)

    # ------------------------------------------------------------------ #
    # HTML pages
    # ------------------------------------------------------------------ #
    def _dashboard(self) -> Response:
        # The dashboard is now a client-side app that fetches /api/dashboard, this
        # just serves the shell. All rendering (KPIs, findings table, matrix heatmap,
        # attack path, runtime) happens in the browser from that one JSON payload.
        return _html(pages.dashboard_page(has_scan=bool(self.store.list())))

    def _vendor_asset(self, name: str) -> Response:
        # Third-party browser JS the dashboard needs (e.g. the Attack Path graph),
        # vendored and served locally, no CDN, so the dashboard stays self-contained.
        if name not in _VENDOR_ASSETS or "/" in name or "\\" in name:
            raise _NotFound(f"No such asset: {name}")
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", name)
        with open(path, "rb") as fh:
            return Response(200, "application/javascript; charset=utf-8", fh.read())

    def _api_timeline(self, q: dict) -> dict:
        """Finding ages for ONE cluster. `scan_id` picks it; otherwise the newest scan's
        cluster is used. Unscoped, this blended every cluster in the store into a single
        MTTD/MTTR figure that described none of them."""
        reports = self.store.list()
        if not reports:
            return self.store.timeline()
        wanted = q.get("scan_id")
        chosen = next((r for r in reports if r.scan_id == wanted), reports[0])
        return self.store.timeline(
            scope=self.store.scope_key_of(chosen.cluster, chosen.scope))

    def _cached_dashboard(self, scan_id: Optional[str]) -> Response:
        """The dashboard payload is expensive (it loads and compares saved scans) and changes
        only when a report is written, so it is cached against the report folder's contents."""
        try:
            sig = tuple(sorted((e.name, e.stat().st_mtime_ns) for e in os.scandir(self.reports_dir)
                               if e.name.endswith(".json") and e.name != "tasks.json"))
        except OSError:
            sig = ()
        cache = self.__dict__.setdefault("_dash_cache", {})
        key = (scan_id or "", sig)
        hit = cache.get(key)
        if hit is None:
            hit = json.dumps(self._dashboard_data(scan_id), indent=None, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
            if len(cache) > 6:
                cache.clear()
            cache[key] = hit
        return Response(200, "application/json; charset=utf-8", hit)

    def _dashboard_data(self, scan_id: Optional[str] = None) -> dict:
        """Everything the dashboard needs, in one payload: the selected (or latest) scan +
        findings + threat matrix + attack path + runtime readiness + risk trend + history.

        `scan_id` lets the dashboard render any saved report, not just the newest one, the
        report selector posts the chosen id here. Falls back to the latest scan when the id
        is missing/unknown so a stale selection never 404s the whole dashboard."""
        reports = self.store.list()
        if not reports:
            return {"has_scan": False, "history": [],
                    "allow_client_kubeconfig": self.allow_client_kubeconfig,
                    "selectors": self._selector_vocab()}
        known = {r.scan_id for r in reports}
        selected = scan_id if scan_id in known else reports[0].scan_id
        latest = self._load(selected)
        # One report store can hold several clusters. The trend line, the history list and
        # the age timeline are all statements ABOUT the selected cluster, so they are
        # narrowed to its scope: a risk trend that interleaves two clusters' scans is not a
        # trend, and an age timeline that blends them mis-ages both.
        chosen = next(r for r in reports if r.scan_id == selected)
        scope = self.store.scope_key_of(chosen.cluster, chosen.scope)
        reports = [r for r in reports
                   if self.store.scope_key_of(r.cluster, r.scope) == scope]
        matrix = build_threat_matrix(latest, self.p.registry.rules)
        from ..core.threat_matrix import attack_paths
        from ..agents.runtime import RuntimeAgent

        catalog = RuntimeAgent().catalog()
        runtime_by_tactic: dict[str, list] = {}
        for r in catalog:
            runtime_by_tactic.setdefault(r["tactic"], []).append(r["title"])
        exposed = [c.tactic for c in matrix.columns if c.hit_count]

        return {
            "has_scan": True,
            "selected_scan_id": selected,
            # Lets the Scan form hide the kubeconfig inputs when this server would refuse
            # them, instead of offering a control that always 403s.
            "allow_client_kubeconfig": self.allow_client_kubeconfig,
            # K01…K10 -> their direct owasp.org page, so a finding's OWASP tag links to
            # the control itself rather than the project landing page.
            "owasp_urls": _owasp_taxonomy().get("urls", {}),
            "selectors": self._selector_vocab(),
            "scan": {"scan_id": latest.scan_id, "name": latest.name,
                     "display_name": latest.display_name,
                     "generated_at": latest.generated_at,
                     "mode": latest.mode, "scope": latest.request.scope.describe(),
                     "rating": latest.risk.rating,
                     "cluster_risk": latest.risk.cluster_risk,
                     "security_score": latest.risk.security_score,
                     "counts": latest.counts, "total": latest.total(),
                     # Scan health, every dashboard view that shows a score or a finding
                     # count reads these so an unread cluster is never painted as clean.
                     "evidence_ok": latest.evidence_ok,
                     "warnings": scan_warning_lines(latest),
                     "suppressed": list(latest.suppressed),
                     "suppression_notes": list(latest.suppression_notes)},
            # Evidence coverage / assessment confidence (§5) and the score's own
            # contributor breakdown (§7). Both are computed server-side; the dashboard
            # renders them and never recomputes security logic in JavaScript.
            "coverage": latest.coverage,
            "risk_explanation": latest.risk.explanation,
            # What changed since the previous scan of this cluster (§16).
            "posture": self._posture(selected),
            "changes": self._changes(selected, latest),
            "inventory": latest.inventory,
            "routes": self._routes(latest),
            "cluster_inventory": latest.cluster_inventory,
            # Both counts, and the remediation units behind the evidence. The findings list
            # below is unchanged and remains the resource-level record; this is the same
            # information grouped by the object an operator would edit.
            "aggregation": _workload_summary(latest),
            "workload_issues": list(latest.workload_issues or []),
            # rbac_paths repeats the same escalation routes on every finding of a pod and was
            # most of the payload (28 MB on the DVKA cluster); the drawer fetches the routes
            # per finding from /api/finding, so the list view does not need them.
            "findings": [_slim(f.as_dict()) for f in latest.findings],
            "threat_matrix": matrix.as_dict(),
            "attack_path": attack_paths(matrix, latest.runtime,
                                        cluster=latest.cluster_name),
            "runtime": {"armed": len(catalog), "by_tactic": runtime_by_tactic,
                        "exposed_tactics": exposed},
            # Runtime correlation baked into the scan at --live time from the Falco feed
            # (correlation + drift). None for mock scans or a live scan with no Falco, the
            # Runtime tab then shows the manual paste box instead. See cmd_scan.
            "runtime_correlation": latest.runtime,
            "trend": [[r.generated_at, r.risk_score] for r in reversed(reports)],
            "timeline": self.store.timeline(scope=scope),
            "history": [{"scan_id": r.scan_id, "name": r.name,
                         "display_name": r.display_name,
                         "generated_at": r.generated_at,
                         "rating": r.rating, "risk_score": r.risk_score,
                         "total": r.total, "scope": r.scope} for r in reports],
        }

    def _changes(self, scan_id: str, current) -> dict:
        """Object-level changes since the previous scan of the same cluster and scope. Isolated:
        no previous scan, or one saved before the inventory existed, simply yields nothing."""
        from ..core.changes import diff
        try:
            reports = self.store.list()
            i = next(n for n, r in enumerate(reports) if r.scan_id == scan_id)
            scope = self.store.scope_key_of(reports[i].cluster, reports[i].scope)
            earlier = next((r for r in reports[i + 1:]
                            if self.store.scope_key_of(r.cluster, r.scope) == scope), None)
            if not earlier:
                return {"since": None, "items": []}
            prev = self.store.load(earlier.scan_id)
            return {"since": {"scan_id": prev.scan_id, "name": prev.display_name,
                              "generated_at": prev.generated_at},
                    "items": diff(prev.cluster_inventory, current.cluster_inventory)}
        except Exception:
            return {"since": None, "items": []}

    def _posture(self, scan_id: str) -> dict:
        """Posture change vs the previous scan of the same cluster. Isolated: a store with
        one scan (or an unreadable older report) must not take the dashboard down."""
        from ..core.posture import latest_change
        try:
            return latest_change(self.store, scan_id)
        except Exception:
            return {}

    def _api_runtime(self, body: bytes) -> Response:
        """Ingest a batch of runtime events (Falco/audit JSON) and return both the
        scan-correlation and the config-drift analysis against the latest saved scan.
        Point falcosidekick (or `falco -o json_output`) at this endpoint, or POST a
        batch by hand. Body: {"events": [...], "scan_id"?: "...", "namespace"?: "..."}."""
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        raw = data.get("events") if (isinstance(data, dict) and "events" in data) else data
        out = self._ingest_runtime(scan_id, raw)
        return _json(out, 400 if list(out) == ["error"] else 200)

    def _api_runtime_demo(self, body: bytes) -> Response:
        """Push three synthetic, clearly-labelled events through the SAME ingestion path a
        real sensor uses, built from this scan's own findings (core/runtime_demo.py). Lets
        the Runtime tab be tried with no Falco deployed. Never invents a resource the scan
        did not already find."""
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        result = self.store.resolve(scan_id)
        if result is None:
            return _json({"error": "No saved scan to correlate against. Run a scan first."}, 400)
        from ..core.runtime_demo import sample_events
        events = sample_events(result)
        if not events:
            return _json({"error": "This scan has no finding with a MITRE tactic to "
                                   "build a demo from."}, 400)
        out = self._ingest_runtime(result.scan_id, events)
        if "error" not in out:
            out["demo"] = True
            out["demo_events"] = events
        return _json(out, 400 if "error" in out else 200)

    def _ingest_runtime(self, scan_id: Optional[str], raw) -> dict:
        """Normalize, detect, correlate, persist. Shared by the real push path and the
        in-dashboard demo, so a demo event is judged by the exact same code a falcosidekick
        POST is."""
        from ..agents.runtime import RuntimeAgent, normalize_batch
        from ..core.correlation import correlate, detect_drift

        events, rejected = normalize_batch(raw)
        result = self.store.resolve(scan_id)
        if result is None:
            return {"error": "No saved scan to correlate against. Run a scan first."}
        # drift needs live pod specs; reuse the scan's mode (mock/live) via a fresh fetch
        mock = result.mode != "live"
        try:
            collector = self.p.make_collector(mock=mock)
            pods = collector.collect({"Pod"}, Scope(ScopeLevel.CLUSTER)).get("Pod")
        except RuntimeError:
            pods = []
        # The push path gets exactly the same identity recovery and accounting as the pull
        # path. A falcosidekick POST and a log pull of the same event must mean the same
        # thing, or the two ingestion routes disagree about the cluster.
        from ..core.runtime_identity import enrich_events
        events, identity_coverage = enrich_events(events, pods)
        alerts, detection_coverage = RuntimeAgent().evaluate_batch(events)
        # Entries that never became events still count as arrived.
        if rejected:
            detection_coverage["events_received"] += len(rejected)
            detection_coverage["unusable_events"] += len(rejected)
            detection_coverage["unusable"] = (detection_coverage["unusable"]
                                              + rejected)[:25]
        from ..core.timeutil import ist_timestamp
        collected_at = ist_timestamp()
        correlation = correlate(result.findings, alerts,
                                cluster=result.cluster_name, now=collected_at)
        drift = detect_drift(pods, events)

        # Persist into the SAME block the pull feed writes, so an ingested event is
        # actually readable afterwards. Without this the push path wrote to nowhere: an
        # event delivered by falcosidekick was correlated, answered, and forgotten, so
        # `GET /api/runtime` and the Runtime page never showed it. Merging (rather than
        # replacing) keeps the pulled history, and re-delivering the same alert does not
        # count twice. Isolated: ingestion must still answer even if the store is
        # read-only or full.
        from ..core.runtime_events import merge_runtime
        incoming = {"source": "runtime-push", "collected_at": collected_at,
                    "cluster": result.cluster_name, "correlation": correlation,
                    "drift": drift, "detection_coverage": detection_coverage,
                    "identity_coverage": identity_coverage}
        stored = False
        try:
            # Serialised, and re-read INSIDE the lock. Persisting a runtime batch is a
            # read-modify-write of one stored scan, and falcosidekick pushes concurrently:
            # without this, forty simultaneous POSTs each merged into the copy they had
            # loaded before the others saved, and thirty-nine events vanished while every
            # request answered 200. Silently losing an event the operator was told was
            # received is the worst failure this endpoint has.
            #
            # ponytail: one process-wide lock, not one per scan. Ingestion is a merge and a
            # write, not a scan; per-scan locks only matter if several clusters push into
            # one endpoint hard enough to contend. Two SEPARATE processes serving the same
            # report directory are still racy, which is what the store's own
            # overwrite guard is there to bound.
            with _RUNTIME_PERSIST_LOCK:
                current = self.store.resolve(result.scan_id) or result
                current.runtime = merge_runtime(current.runtime, incoming)
                self.store.save(current)
            stored = True
        except Exception:                      # pragma: no cover - defensive
            stored = False

        # Response shape is unchanged for existing clients; `stored` is additive.
        return {"correlation": correlation,
                "detection_coverage": detection_coverage,
                "identity_coverage": identity_coverage,
                "events_received": len(events) + len(rejected),
                "stored": stored,
                "scan_id": result.scan_id,
                "drift": drift}

    def _api_finding(self, q: dict) -> Response:
        """Full report-grade context for one finding (summary, impact, verification
        steps), so the dashboard's inline detail can show the same depth as the report
        without loading the whole page. Identifies the finding by its stable anchor, the
        same slug the report cards and the dashboard JS already share."""
        from ..core.reporting import finding_anchor
        from ..core.explain import explain_finding
        from ..core.threat_matrix import attack_paths
        result = self.store.resolve(q.get("scan_id"))
        if result is None:
            return _json({"error": "No such scan."}, 404)
        anchor = q.get("anchor") or ""
        f = next((x for x in result.findings
                  if finding_anchor(x.rule_id, x.resource.kind, x.resource.name,
                                    x.resource.namespace) == anchor), None)
        if f is None:
            return _json({"error": "Finding not found in this scan."}, 404)
        path = attack_paths(build_threat_matrix(result, self.p.registry.rules),
                            result.runtime, cluster=result.cluster_name)
        explanation = explain_finding(f, rule=self.p.registry.rules.get(f.rule_id),
                                      runtime=result.runtime, attack_path=path,
                                      cluster=result.cluster_name)
        # `summary`/`impact`/`validation` are kept at the top level: the dashboard's inline
        # detail pane already reads those three keys, and the richer structure is additive.
        return _json({"summary": explanation["what"],
                      "impact": explanation["why_it_matters"],
                      "validation": explanation["validation_steps"],
                      "fix": explanation["fix"],
                      "explanation": explanation})

    def _api_runtime_events(self, q: dict) -> Response:
        """GET /api/runtime, the recent runtime events already stored on a scan.

        Read-only and additive: POST on this path still ingests. The filtering, validation
        and shaping live in core/runtime_events.query_runtime, which the MCP
        `get_runtime_events` tool calls too, so the two surfaces answer the same question
        with the same code and cannot disagree about what was observed.

        Query: `limit` (default 50), `source` (all|kmw|falco|audit|drift), `severity`
        (comma-separated), `namespace`, `since` (90s|15m|2h|7d|1w or seconds), `scan_id`.
        """
        from ..core.runtime_events import query_runtime
        result = self.store.resolve(q.get("scan_id"))
        if result is None:
            return _json({"error": "No saved scan yet. Run a scan first."}, 400)
        return _json(query_runtime(
            result,
            limit=(q.get("limit") or "").strip(),
            source=(q.get("source") or "all"),
            severity=(q.get("severity") or ""),
            namespace=(q.get("namespace") or ""),
            since=(q.get("since") or "")))

    def _runtime_page(self) -> Response:
        return _html(pages.runtime_page())

    def _api_runtime_refresh(self, body: bytes) -> Response:
        """Live-pull Falco events from the cluster, re-correlate against the current scan,
        persist and return the fresh runtime block. Needs the dashboard to have cluster
        access (in-cluster config or a kubeconfig). The streaming POST /api/runtime path
        (falcosidekick push) is unaffected."""
        from ..core.falco_feed import build_runtime_feed
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)
        result = self.store.resolve(data.get("scan_id") if isinstance(data, dict) else None)
        if result is None:
            return _json({"error": "No saved scan to correlate against. Run a scan first."}, 400)
        ns = (result.runtime or {}).get("falco_namespace") or "falco"
        try:
            collector = self.p.make_collector(mock=False)
            feed = build_runtime_feed(collector, result.findings,
                                      Scope(ScopeLevel.CLUSTER), namespace=ns)
        except RuntimeError as exc:
            return _json({"state": "unavailable", "severity": "error",
                          "error": f"Live Falco pull requires cluster access: {exc}"}, 400)
        if feed is None:
            # The state, not just a sentence. "no Falco events found" followed by advice
            # read as a failure on a perfectly healthy cluster; the caller now gets the
            # condition and can present a quiet feed differently from a broken one.
            found = getattr(collector, "runtime_feed_state", None) or {
                "state": "unknown", "severity": "warning",
                "message": "The Falco feed could not be read.", "remediation": None}
            return _json({"runtime": None,
                          "state": found.get("state"),
                          "severity": found.get("severity"),
                          "message": found.get("message"),
                          "remediation": found.get("remediation"),
                          "warnings": getattr(collector, "warnings", [])})
        result.runtime = feed
        self.store.save(result)
        return _json({"runtime": feed})

    # ------------------------------------------------------------------ #
    # JSON API
    # ------------------------------------------------------------------ #
    def _api_reports(self, q: dict) -> Response:
        limit = _int(q.get("limit"))
        return _json([{"scan_id": r.scan_id, "name": r.name,
                       "display_name": r.display_name,
                       "generated_at": r.generated_at,
                       "rating": r.rating, "risk_score": r.risk_score,
                       "total_findings": r.total, "scope": r.scope}
                      for r in self.store.list(limit=limit)])

    def _api_report(self, scan_id: str, q: dict) -> Response:
        result = self._load(scan_id)
        fmt = (q.get("format") or "json").lower()
        if fmt not in _VALID_FORMATS:
            valid = sorted(_VALID_FORMATS)
            return _json({"error": f"Unknown format {fmt!r}. Valid formats: {', '.join(valid)}"}, 400)
        content = self.p.reporting.render(result, fmt)
        if fmt == "json":
            return Response(200, "application/json; charset=utf-8",
                            content.encode("utf-8"))
        if fmt == "html":
            return _html(content)
        return _text(content)

    @staticmethod
    def _routes(result) -> dict:
        """The attack-path summary the Overview shows, from the same builder as the Attack paths
        page so the two can never disagree about how many routes there are."""
        from .graph_page import build_graph
        paths = build_graph(result)["paths"]
        return {"total": len(paths), "internet": sum(1 for p in paths if p["internet"]),
                "top": [{"severity": p["severity"], "internet": p["internet"], "issues": p["issues"],
                         "title": p["title"], "target": p["target"],
                         "steps": [s for s in p["steps"] if s["t"] not in ("ClusterRoleBinding", "RoleBinding")]}
                        for p in paths[:6]]}

    def _api_report_matrix(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        return _json(build_threat_matrix(result, self.p.registry.rules).as_dict())

    def _api_scan(self, body: bytes) -> Response:
        if not self.allow_scan:
            return _json({"error": "Scanning is disabled on this server "
                          "(started with --no-scan)."}, 403)
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"Invalid JSON body: {exc}"}, 400)

        scope = self._scope_from(data)
        selector = self._selector_from(data)
        mock = bool(data.get("mock", True))
        scan_name = (data.get("scan_name") or "").strip()

        # kubeconfig may arrive as a server-side path (`kubeconfig`) OR as the file's
        # contents uploaded from the browser file-picker (`kubeconfig_content`), the
        # browser can't reveal a real filesystem path, so a picked file is sent by value
        # and materialised into a short-lived temp file here.
        try:
            kubeconfig, tmp_kubeconfig = self._resolve_kubeconfig(data)
        except PermissionError as exc:
            return _json({"error": str(exc)}, 403)
        try:
            try:
                collector = self.p.make_collector(
                    mock=mock, fixture=data.get("fixture"),
                    kubeconfig=kubeconfig, context=data.get("context"),
                    **({"grype": True} if data.get("grype") and not mock else {}))
            except RuntimeError as exc:
                return _json({"error": str(exc)}, 400)

            from ..agents.scanner import ScannerAgent
            request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
            try:
                result = ScannerAgent(self.p).scan(
                    request, collector, mode_label="mock" if mock else "live",
                    name=scan_name)
            except Exception as exc:
                return _json({"error": f"Scan failed: {exc}"}, 400)
        finally:
            if tmp_kubeconfig:
                try:
                    os.unlink(tmp_kubeconfig)
                except OSError:
                    pass

        self.store.save(result)
        return _json({"scan_id": result.scan_id, "name": result.name,
                      "display_name": result.display_name,
                      "rating": result.risk.rating,
                      "risk": result.risk.cluster_risk,
                      "security_score": result.risk.security_score,
                      "total_findings": result.total(),
                      "scope": result.request.scope.describe(),
                      "evidence_ok": result.evidence_ok,
                      "warnings": scan_warning_lines(result),
                      })

    def _resolve_kubeconfig(self, data: dict) -> tuple[Optional[str], Optional[str]]:
        """Return (kubeconfig_path, temp_path_to_clean_up).

        Prefers an explicit server-side `kubeconfig` path; otherwise, if the browser
        uploaded the file's `kubeconfig_content`, writes it to a temp file and returns that
        path plus the same path as the second element so the caller unlinks it afterward.

        Raises PermissionError when the request supplies either form and this server is
        not configured to accept one, see `allow_client_kubeconfig`. Both forms are gated,
        not just the uploaded content: a `kubeconfig` *path* names a file whose credential
        plugin the server would then execute just the same."""
        path = data.get("kubeconfig")
        content = data.get("kubeconfig_content")
        supplied = ((isinstance(path, str) and path.strip())
                    or (isinstance(content, str) and content.strip()))
        if supplied and not self.allow_client_kubeconfig:
            raise PermissionError(
                "this server does not accept a kubeconfig from the request because it is "
                "not bound to localhost. Loading a kubeconfig executes its credential "
                "plugin (aws/gcloud/kubelogin), so accepting one from the network would "
                "let any caller run commands as the server's user. Either run the "
                "dashboard on 127.0.0.1, or scan from the CLI on the server "
                "(`k8smatrixwarden scan --live --kubeconfig …`), or, only behind your own "
                "authentication, restart with --allow-remote-kubeconfig.")
        if isinstance(path, str) and path.strip():
            return path.strip(), None
        if isinstance(content, str) and content.strip():
            import tempfile
            fd, tmp = tempfile.mkstemp(prefix="k8smw-kubeconfig-", suffix=".yaml")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            return tmp, tmp
        return None, None

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _selector_vocab(self) -> dict:
        """Every selectable term the dashboard's Scan-form selector dropdown offers, grouped
        by axis (the same vocabulary the CLI/chat resolve against, from the mapping engine's
        registry-derived index, so it never drifts from what actually exists). Techniques
        and rule ids are intentionally omitted: there are too many to be a usable dropdown,
        and tactics/modules/frameworks/aliases cover the user-facing selectors."""
        terms = self.p.mapping.known_terms()
        return {"tactics": terms.get("tactics", []),
                "modules": terms.get("modules", []),
                "frameworks": terms.get("frameworks", []),
                "aliases": terms.get("aliases", [])}

    def _scope_from(self, data: dict) -> Scope:
        key = str(data.get("scope_level") or "cluster").lower().replace("-", "_")
        try:
            level = ScopeLevel(key)
        except ValueError:
            level = ScopeLevel.CLUSTER
        return Scope(level=level, namespace=data.get("namespace"),
                     name=data.get("name"), kind=data.get("kind"),
                     image=data.get("image"))

    def _selector_from(self, data: dict) -> Selector:
        """Accept either a structured selector or a single free-text `selector` string
        (parsed with the same Orchestrator logic the CLI/chat use)."""
        text = data.get("selector")
        if isinstance(text, str) and text.strip():
            from ..agents.orchestrator import Orchestrator
            interp = Orchestrator(self.p).interpret(f"scan for {text.strip()}")
            return interp.request.selector
        sev = data.get("severity_min")
        return Selector(
            tactics=list(data.get("tactics", []) or []),
            techniques=list(data.get("techniques", []) or []),
            modules=list(data.get("modules", []) or []),
            rule_ids=list(data.get("rule_ids", []) or []),
            aliases=list(data.get("aliases", []) or []),
            frameworks=list(data.get("frameworks", []) or []),
            severity_min=Severity.parse(sev) if sev else None)

    def _load(self, scan_id: str) -> ScanResult:
        try:
            result = self.store.resolve(scan_id)
        except FileNotFoundError:
            raise _NotFound(f"No stored report with scan id {scan_id!r}.")
        if result is None:
            raise _NotFound("No stored reports yet. Run a scan first.")
        return result

    def _not_found(self, message: str, q: dict) -> Response:
        return _json({"error": message}, 404) if q.get("format") \
            else _html(pages.error_page(404, message), 404)


class _NotFound(Exception):
    pass


def _wants_json(path: str, q: dict) -> bool:
    return path.startswith("/api/") or (q.get("format") == "json")


def _aggregate(reports: list) -> dict:
    order = {"Critical": 5, "Poor": 4, "Fair": 3, "Good": 2, "Excellent": 1}
    worst = "N/A"
    worst_rank = 0
    for r in reports:
        rk = order.get(r.rating, 0)
        if rk > worst_rank:
            worst_rank, worst = rk, r.rating
    return {
        "total_reports": len(reports),
        "total_findings": sum(r.total for r in reports),
        "worst_rating": worst,
        "latest_risk": reports[0].risk_score if reports else 0,
    }


def _empty_result(platform) -> ScanResult:
    from ..core.scoring import RiskScoringEngine
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector())
    risk = RiskScoringEngine().score([])
    return ScanResult(request=req, findings=[], risk=risk, resolved_rule_ids=[],
                      counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                      scan_id="coverage", cluster_name="(coverage)")


def _int(v) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except (ValueError, TypeError):
        return None
