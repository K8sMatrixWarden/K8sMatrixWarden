"""The task controller behind the dashboard's Tasks view.

Every task runs the SAME command-line scan an engineer would type, as a child process.
That keeps the dashboard and the CLI identical by construction (one code path to trust),
isolates a crash or a slow Grype run from the web server, makes Cancel a real kill, and
gives the log for free (the process's own progress lines).

The server never builds a shell string: arguments are a validated list. Free text (scan
name, namespace, context) is checked against a strict pattern first.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from typing import Optional

KINDS = {"scan-live": "Scan live cluster", "scan-manifests": "Scan manifests",
         "scan-sample": "Scan sample cluster"}
_NAME = re.compile(r"^[A-Za-z0-9 ._:/@+-]{1,80}$")
_NS = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_SAVED = re.compile(r"(\S+-\d{8}-\d{6}-[0-9a-f]{4})\s+→")
_MAX_LOG = 400
_KEEP = 40


class TaskError(ValueError):
    pass


def build_args(kind: str, p: dict, reports_dir: str) -> list[str]:
    """Validated CLI arguments for a task. Raises TaskError for anything unusual."""
    if kind not in KINDS:
        raise TaskError(f"unknown task kind '{kind}'")
    args = ["scan", "-y", "-o", "json", "--output-file", os.devnull]
    name = (p.get("name") or "").strip()
    if name:
        if not _NAME.match(name):
            raise TaskError("scan name may use letters, numbers, spaces and . _ : / @ + - only")
        args += ["--name", name]
    ns = (p.get("namespace") or "").strip()
    if ns:
        if not _NS.match(ns):
            raise TaskError(f"'{ns}' is not a valid namespace name")
        args += ["--namespace", ns]
    if kind == "scan-live":
        ctx = (p.get("context") or "").strip()
        if ctx and not _NAME.match(ctx):
            raise TaskError("context name has characters a kubeconfig context cannot have")
        args += ["--live"] + (["--context", ctx] if ctx else [])
        if p.get("grype"):
            args += ["--grype"]
    elif kind == "scan-manifests":
        paths = [x.strip() for x in (p.get("paths") or []) if str(x).strip()]
        if not paths:
            raise TaskError("give at least one file or folder to scan")
        for x in paths:
            if not os.path.exists(x):
                raise TaskError(f"'{x}' does not exist on the machine running the dashboard")
        args += ["--manifests"] + paths
    else:
        args += ["--mock"]
    return args + ["--reports-dir", reports_dir]


class TaskManager:
    def __init__(self, reports_dir: str, max_parallel: int = 2):
        self.reports_dir = reports_dir
        self.max_parallel = max_parallel
        self._lock = threading.Lock()
        self._tasks: dict[str, dict] = {}
        self._procs: dict[str, subprocess.Popen] = {}
        self._file = os.path.join(reports_dir, "tasks.json")
        self._load()

    # -- persistence -----------------------------------------------------------------------
    def _load(self) -> None:
        try:
            with open(self._file, encoding="utf-8") as fh:
                for t in json.load(fh):
                    if t.get("status") in ("queued", "running"):
                        t.update(status="failed", error="the dashboard restarted while this ran",
                                 finished=time.time())
                    self._tasks[t["id"]] = t
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        try:
            os.makedirs(self.reports_dir, exist_ok=True)
            keep = sorted(self._tasks.values(), key=lambda t: t["created"], reverse=True)[:_KEEP]
            with open(self._file, "w", encoding="utf-8") as fh:
                json.dump(keep, fh)
        except OSError:
            pass

    # -- api -------------------------------------------------------------------------------
    def submit(self, kind: str, params: dict) -> dict:
        args = build_args(kind, params, self.reports_dir)
        task = {"id": uuid.uuid4().hex[:10], "kind": kind, "title": KINDS[kind],
                "detail": self._detail(kind, params), "status": "queued", "created": time.time(),
                "started": None, "finished": None, "log": [], "scan_id": None, "error": "",
                "exit_code": None, "command": "k8smatrixwarden scan " + " ".join(args[6:-2])}
        with self._lock:
            self._tasks[task["id"]] = task
            self._save()
        threading.Thread(target=self._run, args=(task["id"], args), daemon=True).start()
        return self._public(task)

    def list(self) -> list[dict]:
        with self._lock:
            return [self._public(t, tail=3) for t in
                    sorted(self._tasks.values(), key=lambda t: t["created"], reverse=True)]

    def get(self, tid: str) -> Optional[dict]:
        with self._lock:
            t = self._tasks.get(tid)
            return self._public(t) if t else None

    def cancel(self, tid: str) -> bool:
        with self._lock:
            t, proc = self._tasks.get(tid), self._procs.get(tid)
            if not t or t["status"] not in ("queued", "running"):
                return False
            t["status"] = "cancelled"
            t["finished"] = time.time()
        if proc and proc.poll() is None:
            proc.terminate()
        with self._lock:
            self._save()
        return True

    # -- internals -------------------------------------------------------------------------
    @staticmethod
    def _detail(kind: str, p: dict) -> str:
        if kind == "scan-live":
            return ((p.get("context") or "current context") + (", with image CVEs" if p.get("grype") else ""))
        if kind == "scan-manifests":
            return ", ".join(p.get("paths") or [])
        return "bundled demo cluster"

    @staticmethod
    def _public(t: dict, tail: Optional[int] = None) -> dict:
        out = dict(t)
        out["log"] = list(t["log"][-tail:] if tail else t["log"])
        return out

    def _wait_for_slot(self, tid: str) -> bool:
        while True:
            with self._lock:
                t = self._tasks[tid]
                if t["status"] == "cancelled":
                    return False
                running = sum(1 for x in self._tasks.values() if x["status"] == "running")
                if running < self.max_parallel:
                    t["status"], t["started"] = "running", time.time()
                    return True
            time.sleep(0.5)

    def _run(self, tid: str, args: list[str]) -> None:
        if not self._wait_for_slot(tid):
            return
        try:
            proc = subprocess.Popen([sys.executable, "-m", "k8smatrixwarden"] + args,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
        except OSError as exc:
            self._finish(tid, None, f"could not start the scan: {exc}")
            return
        with self._lock:
            self._procs[tid] = proc
        for line in proc.stderr:
            line = line.rstrip()
            if not line or line.startswith("[written]"):
                continue
            with self._lock:
                t = self._tasks[tid]
                t["log"].append(line)
                del t["log"][:-_MAX_LOG]
                m = _SAVED.search(line)
                if m:
                    t["scan_id"] = m.group(1)
        proc.wait()
        self._finish(tid, proc.returncode, "")

    def _finish(self, tid: str, code: Optional[int], error: str) -> None:
        with self._lock:
            t = self._tasks[tid]
            self._procs.pop(tid, None)
            t["exit_code"] = code
            if t["status"] == "cancelled":
                return
            t["finished"] = time.time()
            # exit 1 is `--fail-on`; a scan that saved a report succeeded as a scan.
            ok = bool(t["scan_id"]) and code in (0, 1)
            t["status"] = "done" if ok else "failed"
            if not ok:
                last = next((l for l in reversed(t["log"]) if l.startswith("error")), "")
                t["error"] = error or last.replace("error: ", "") or f"exited with code {code}"
            self._save()
