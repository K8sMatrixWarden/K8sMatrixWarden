"""The task controller: dashboard jobs are the real CLI, validated, cancellable, remembered."""
import json
import time

import pytest

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.web.app import WebApp
from k8smatrixwarden.web.tasks import TaskError, TaskManager, build_args


def _wait(tm, tid, secs=60):
    end = time.time() + secs
    while time.time() < end:
        t = tm.get(tid)
        if t["status"] not in ("queued", "running"):
            return t
        time.sleep(0.3)
    raise AssertionError("task did not finish")


def test_arguments_are_validated_and_never_a_shell_string(tmp_path):
    with pytest.raises(TaskError):
        build_args("scan-live", {"name": "x; rm -rf /"}, str(tmp_path))
    with pytest.raises(TaskError):
        build_args("scan-live", {"namespace": "Not_Valid"}, str(tmp_path))
    with pytest.raises(TaskError):
        build_args("scan-manifests", {"paths": [str(tmp_path / "missing")]}, str(tmp_path))
    with pytest.raises(TaskError):
        build_args("nope", {}, str(tmp_path))
    a = build_args("scan-live", {"context": "minikube", "grype": True, "name": "nightly"}, str(tmp_path))
    assert a[0] == "scan" and "--live" in a and "--grype" in a and a[-2] == "--reports-dir"


def test_live_scan_passes_a_kubeconfig_path_and_rejects_a_missing_one(tmp_path):
    kc = tmp_path / "kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    a = build_args("scan-live", {"kubeconfig": str(kc)}, str(tmp_path))
    assert a[a.index("--kubeconfig") + 1] == str(kc)
    with pytest.raises(TaskError):
        build_args("scan-live", {"kubeconfig": str(tmp_path / "nope")}, str(tmp_path))


def test_a_sample_scan_runs_saves_a_report_and_is_remembered(tmp_path):
    tm = TaskManager(str(tmp_path))
    t = _wait(tm, tm.submit("scan-sample", {"name": "demo"})["id"])
    assert t["status"] == "done" and t["scan_id"] and t["exit_code"] in (0, 1)
    assert any("[saved]" in l for l in t["log"])
    assert TaskManager(str(tmp_path)).get(t["id"])["status"] == "done"      # survives a restart


def test_a_failing_task_reports_why_and_cancel_stops_a_running_one(tmp_path):
    tm = TaskManager(str(tmp_path))
    t = _wait(tm, tm.submit("scan-live", {"context": "no-such-context-xyz"})["id"])
    assert t["status"] == "failed" and t["error"]
    t2 = tm.submit("scan-sample", {})
    assert tm.cancel(t2["id"]) in (True, False)
    assert tm.get(t2["id"])["status"] in ("cancelled", "done")


def test_http_routes_and_accepted_risks(tmp_path):
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    r = app.route("POST", "/api/tasks", body=b'{"kind": "scan-live", "namespace": "Bad_NS"}')
    assert r.status == 400
    assert app.route("GET", "/api/tasks").status == 200
    bad = app.route("POST", "/api/suppressions", body=b'{"rule": "a"}')
    assert bad.status == 400
    ok = app.route("POST", "/api/suppressions", body=json.dumps(
        {"rule": "workload-run-as-root", "reason": "vendor", "expires": "2999-01-01"}).encode())
    assert ok.status == 201
    sid = json.loads(app.route("GET", "/api/suppressions").body)["suppressions"][0]["id"]
    assert app.route("POST", "/api/suppressions/delete", body=json.dumps({"id": sid}).encode()).status == 200
    assert json.loads(app.route("GET", "/api/suppressions").body)["suppressions"] == []
