"""Guided runtime rules and the gated Falco deploy."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core import falco_deploy as fd
from k8smatrixwarden.core import runtime_rules as rr

SPECS = {
    "process": {"name": "Shell in prod", "behavior": "process", "values": {"names": "bash, sh", "cmdline_contains": "-i"},
                "scope": {"namespaces": "production"}, "exceptions": [{"field": "container.image.repository", "values": "debug-tools"}]},
    "file_read": {"name": "Shadow read", "behavior": "file_read", "values": {"paths": "/etc/shadow, /root/.aws/"}},
    "file_write": {"name": "Binary write", "behavior": "file_write", "values": {"paths": "/usr/bin", "process_names": "sh"}},
    "network_out": {"name": "Metadata call", "behavior": "network_out", "values": {"destinations": "169.254.169.254, 203.0.113.0/24", "ports": "80"}},
    "k8s_api": {"name": "Secret listing", "behavior": "k8s_api", "values": {"verbs": "list", "resources": "secrets"}},
}


@pytest.mark.parametrize("kind", sorted(SPECS))
def test_every_guided_behaviour_generates_a_clean_rule_that_passes_its_own_tests(kind):
    y = rr.to_yaml(SPECS[kind])
    out = rr.lint(y)
    assert out["errors"] == [] and (out["warnings"] == [] or (kind == "k8s_api" and "k8saudit plugin" in out["warnings"][0]))
    res = rr.run_tests(SPECS[kind])
    assert res["ok"] and res["passed"] >= 3, [c for c in res["cases"] if not c["pass"]]
    assert any(c["expected"] for c in res["cases"]) and any(not c["expected"] for c in res["cases"])


def test_the_condition_names_every_field_the_analyst_filled_in():
    cond = rr.condition(SPECS["process"])
    for part in ('proc.name in ("bash", "sh")', 'proc.cmdline contains "-i"', 'k8s.ns.name in ("production")',
                 'not container.image.repository in ("debug-tools")', "container.id != host"):
        assert part in cond


def test_a_value_that_could_break_out_of_the_condition_is_refused():
    bad = {**SPECS["process"], "values": {"names": 'bash" or 1=1 or proc.name in ("x'}}
    with pytest.raises(rr.RuleError, match="quote"):
        rr.to_yaml(bad)


@pytest.mark.parametrize("spec,msg", [
    ({"name": "x"}, "name of 3"), ({"name": "Okay name", "behavior": "nope"}, "Pick what"),
    ({"name": "Okay name", "behavior": "process"}, "at least one program"),
    ({"name": "Okay name", "behavior": "file_read", "values": {"paths": "etc/shadow"}}, "start it with a slash"),
    ({"name": "Okay name", "behavior": "network_out", "values": {}}, "destination, a port"),
    ({"name": "Okay name", "behavior": "network_out", "values": {"destinations": "999.1.1.1"}}, "not an IP"),
    ({"name": "Okay name", "behavior": "network_out", "values": {"ports": "70000"}}, "not a port"),
    ({"name": "Okay name", "behavior": "k8s_api", "values": {"verbs": "list"}}, "one action and one resource"),
    ({**SPECS["process"], "priority": "LOUD"}, "Priority"), ({**SPECS["process"], "technique": "ABC"}, "technique"),
])
def test_mistakes_get_a_sentence_an_analyst_can_act_on(spec, msg):
    with pytest.raises(rr.RuleError, match=msg):
        rr.normalize(spec)


def test_the_simulator_says_which_condition_stopped_a_quiet_event():
    r = rr.evaluate(SPECS["process"], {"evt.type": "execve", "container.id": "x", "proc.name": "sleep", "k8s.ns.name": "production"})
    assert r["fires"] is False and "the program is one of" in r["stopped_by"]


def test_a_rule_that_is_too_broad_fails_its_own_quiet_cases():
    broad = {"name": "Everything", "behavior": "network_out", "values": {"ports": "443"}}
    res = rr.run_tests(broad, [{"label": "Normal web call from a container", "event": {"evt.type": "connect", "container.id": "x", "fd.sport": "443", "fd.sip": "1.2.3.4"}, "expected": False}])
    assert res["failed"] == 1 and res["cases"][-1]["fires"] is True


def test_stage_audit_lowers_priority_and_tags_the_rule():
    r = rr.to_rule({**SPECS["process"], "stage": "audit", "priority": "CRITICAL"})
    assert r["priority"] == "INFORMATIONAL" and "kmw_stage_audit" in r["tags"]
    assert rr.to_rule(SPECS["k8s_api"])["source"] == "k8s_audit"


def test_lint_catches_broken_conditions_and_priorities():
    out = rr.lint("- rule: a\n  desc: d\n  condition: (proc.name = x\n  output: o\n  priority: LOUD")
    assert any("brackets" in e for e in out["errors"]) and any("priority" in e for e in out["errors"])
    assert rr.lint("not yaml: [")["errors"]


def test_falco_own_check_reports_plainly_when_docker_is_missing_and_uses_a_pinned_argv_when_present():
    assert rr.validate_with_falco("- rule: a", which=lambda x: None)["available"] is False
    seen = {}

    class P:
        returncode, stdout, stderr = 0, "Ok", ""

    def run(argv, **k):
        seen["argv"] = argv
        return P()

    out = rr.validate_with_falco("- rule: a", runner=run, which=lambda x: "/usr/bin/docker")
    assert out["ok"] and seen["argv"][:3] == ["docker", "run", "--rm"] and "falco" in seen["argv"] and "-V" in seen["argv"]


def test_saved_rules_round_trip_and_the_catalog_lists_curated_default_and_custom(tmp_path):
    rr.save_rule(str(tmp_path), SPECS["file_read"])
    assert [x["name"] for x in rr.list_saved(str(tmp_path))] == ["Shadow read"] and rr.list_saved(str(tmp_path))[0]["editable"]
    cur = rr.curated_rules()
    assert len(cur) == 11 and all(c["watches"] and c["why"] for c in cur)
    text = "- rule: Terminal shell in container\n  desc: A shell was used\n  condition: spawned_process\n  priority: NOTICE\n  tags: [mitre_execution, T1059]\n"
    d = rr.default_rules(str(tmp_path / "cache"), fetcher=lambda url: text)
    assert d["rules"][0]["name"] == "Terminal shell in container" and d["rules"][0]["tactic"] == "Execution"
    assert rr.default_rules(str(tmp_path / "cache"), fetcher=lambda url: 1 / 0)["rules"]          # served from the cache
    assert rr.delete_rule(str(tmp_path), "Shadow read") and not rr.list_saved(str(tmp_path))


# ---- Falco status and the gated deploy ---------------------------------------------------------------
class _Ev:
    def __init__(self, **kinds):
        self.k = kinds

    def get(self, kind, all_scopes=False):
        return self.k.get(kind, [])


def _ds(ready, desired, name="falco", ns="falco"):
    return {"metadata": {"name": name, "namespace": ns}, "status": {"numberReady": ready, "desiredNumberScheduled": desired},
            "spec": {"template": {"spec": {"containers": [{"image": "falcosecurity/falco:0.40.0"}]}}}}


def _node(name="n1", kernel="6.1.0", os_="Ubuntu"):
    return {"metadata": {"name": name}, "status": {"nodeInfo": {"kernelVersion": kernel, "osImage": os_, "architecture": "amd64"}}}


def test_status_distinguishes_not_installed_healthy_partial_and_unhealthy():
    assert fd.status(_Ev(Node=[_node()]))["state"] == "not-installed"
    assert fd.status(_Ev(Node=[_node()], DaemonSet=[_ds(1, 1)]))["state"] == "healthy"
    assert fd.status(_Ev(Node=[_node("a"), _node("b")], DaemonSet=[_ds(1, 2)]))["state"] == "partial"
    crash = {"metadata": {"name": "falco-x", "namespace": "falco"}, "status": {"containerStatuses": [{"state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}}
    st = fd.status(_Ev(Node=[_node()], DaemonSet=[_ds(0, 1)], Pod=[crash]))
    assert st["state"] == "unhealthy" and "CrashLoopBackOff" in st["message"] and st["version"] == "0.40.0"


def test_preflight_flags_old_kernels_and_local_dev_clusters_and_missing_tools():
    st = fd.status(_Ev(Node=[_node("minikube", "4.19.0", "Buildroot")]))
    pre = {c["id"]: c for c in fd.preflight(st, have=lambda x: None)}
    assert pre["kernel"]["status"] == "bad" and pre["virtual"]["status"] == "warn" and pre["helm"]["status"] == "bad"


def test_the_plan_lists_exact_commands_limits_and_never_adds_control_plane_tolerations():
    st = fd.status(_Ev(Node=[_node()]))
    p = fd.plan(st, "- rule: a", have=lambda x: None)
    assert "limits" in p["values"] and "tolerations: []" in p["values"] and "kmw-rules.yaml" in p["values"]
    install = next(c for c in p["commands"] if c["title"] == "Install Falco")
    assert "--atomic" in install["argv"] and "--wait" in install["argv"] and install["argv"][0] == "helm"
    with pytest.raises(ValueError):
        fd.plan(st, namespace="Bad Name!")


def test_deploy_is_refused_unless_the_operator_opted_in_and_confirmed(tmp_path, monkeypatch):
    from k8smatrixwarden.web.app import WebApp
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    monkeypatch.delenv(fd.GATE, raising=False)
    r = app.route("POST", "/api/runtime-rules/falco-deploy", body=b'{"confirm": "deploy-falco"}')
    assert r.status == 403 and json.loads(r.body)["gated"] is True
    monkeypatch.setenv(fd.GATE, "1")
    assert app.route("POST", "/api/runtime-rules/falco-deploy", body=b"{}").status == 400
    ro = WebApp(build_platform(), reports_dir=str(tmp_path), allow_scan=False)
    assert ro.route("POST", "/api/runtime-rules/falco-deploy", body=b'{"confirm": "deploy-falco"}').status == 403


def test_remove_only_touches_a_release_this_tool_installed():
    def status_for(desc):
        class P:
            returncode, stdout, stderr = 0, json.dumps({"info": {"description": desc}}), ""
        return lambda argv, **k: P()
    assert fd.remove_steps("falco", "", status_for(fd.MARK))[0]["argv"][:3] == ["helm", "uninstall", "falco"]
    with pytest.raises(ValueError, match="not installed by"):
        fd.remove_steps("falco", "", status_for("Install complete"))


def test_the_deployer_runs_steps_in_order_stops_at_the_first_failure_and_never_uses_a_shell():
    calls = []

    class P:
        def __init__(self, rc):
            self.returncode, self.stdout, self.stderr = rc, "out", ""

    def runner(argv, **k):
        calls.append(argv)
        return P(1 if argv[0] == "second" else 0)

    d = fd.Deployer()
    rid = d.start("falco-deploy", [{"title": "a", "argv": ["first"]}, {"title": "b", "argv": ["second"]}, {"title": "c", "argv": ["third"]}], {}, runner)
    import time
    for _ in range(50):
        if d.get(rid)["state"] != "running":
            break
        time.sleep(0.05)
    run = d.get(rid)
    assert run["state"] == "failed" and [s["status"] for s in run["steps"]] == ["done", "failed", "pending"] and calls == [["first"], ["second"]]


def test_the_rules_api_generates_tests_and_saves(tmp_path):
    from k8smatrixwarden.web.app import WebApp
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    post = lambda a, **b: app.route("POST", f"/api/runtime-rules/{a}", body=json.dumps(b).encode())            # noqa: E731
    g = json.loads(post("generate", spec=SPECS["process"]).body)
    assert g["lint"]["errors"] == [] and "- rule: Shell in prod" in g["yaml"]
    t = json.loads(post("test", spec=SPECS["process"], events=[{"label": "mine", "lines": "evt.type=execve\ncontainer.id=x\nproc.name=bash\nproc.cmdline=bash -i\nk8s.ns.name=production\ncontainer.image.repository=app", "expected": True}]).body)
    assert t["ok"] and t["cases"][-1]["custom"] and t["cases"][-1]["fires"]
    assert post("generate", spec={"name": "x"}).status == 422
    assert json.loads(post("save", spec=SPECS["process"]).body)["custom"][0]["name"] == "Shell in prod"
    cat = json.loads(post("catalog").body)
    assert len(cat["curated"]) == 11 and cat["custom"] and cat["default"] == []


# ---- agent coverage -------------------------------------------------------------------------------------
from k8smatrixwarden.core import agent_coverage as ac       # noqa: E402
from k8smatrixwarden.core import runtime_ops as ops        # noqa: E402


def _agent_ds(name="falcon-sensor", ns="sec", image="crowdstrike/falcon-sensor:7.10.0", tol=None):
    return {"metadata": {"name": name, "namespace": ns}, "status": {"numberReady": 2, "desiredNumberScheduled": 2},
            "spec": {"template": {"spec": {"containers": [{"image": image}], "tolerations": tol or []}}}}


def _apod(name, node, ds="falcon-sensor", ns="sec", image="crowdstrike/falcon-sensor:7.10.0", ready=True, waiting=""):
    st = {"phase": "Running", "conditions": [{"type": "Ready", "status": "True" if ready else "False"}], "containerStatuses": [{"restartCount": 0, "state": {"waiting": {"reason": waiting}} if waiting else {}}]}
    return {"metadata": {"name": name, "namespace": ns, "ownerReferences": [{"kind": "DaemonSet", "name": ds}]}, "spec": {"nodeName": node, "containers": [{"image": image}]}, "status": st}


def _node2(name, taints=None):
    return {"metadata": {"name": name}, "spec": {"taints": taints or []}}


def _agent(agent_id, **extra):
    return dict(next(a for a in ac.CATALOG if a["id"] == agent_id), tracked=True, **extra)


def test_node_agent_coverage_names_missing_nodes_with_the_reason_and_flags_unhealthy_pods():
    ev = _Ev(Node=[_node2("a"), _node2("b"), _node2("gpu", [{"key": "nvidia.com/gpu", "effect": "NoSchedule"}])],
             DaemonSet=[_agent_ds()], Pod=[_apod("s-1", "a"), _apod("s-2", "b", ready=False, waiting="CrashLoopBackOff")])
    r = ac.evaluate(_agent("crowdstrike"), ev)
    assert r["expected"] == 3 and r["covered"] == 1 and r["status"] == "degraded" and r["coverage"] == 0.333
    assert any("gpu" in m and "tainted" in m for m in r["missing"]) and any("CrashLoopBackOff" in u for u in r["unhealthy"])


def test_agent_versions_drift_and_minimum_version_are_reported():
    ev = _Ev(Node=[_node2("a"), _node2("b")], DaemonSet=[_agent_ds()],
             Pod=[_apod("s-1", "a"), _apod("s-2", "b", image="crowdstrike/falcon-sensor:7.2.0")])
    r = ac.evaluate(_agent("crowdstrike", min_version="7.5.0"), ev)
    assert r["status"] == "degraded" and r["below_min"] == ["7.2.0"] and any("More than one version" in n for n in r["notes"])
    full = ac.evaluate(_agent("crowdstrike"), _Ev(Node=[_node2("a")], DaemonSet=[_agent_ds()], Pod=[_apod("s-1", "a")]))
    assert full["status"] == "healthy" and full["coverage"] == 1.0


def test_an_agent_that_is_not_in_the_cluster_says_so_and_a_sidecar_is_checked_per_pod():
    assert ac.evaluate(_agent("wiz"), _Ev(Node=[_node2("a")]))["status"] == "not-found"
    def pod(n, side):
        cs = [{"name": "app", "image": "x"}] + ([{"name": "linkerd-proxy", "image": "cr.l5d.io/linkerd/proxy:stable-2.14.1"}] if side else [])
        return {"metadata": {"name": n, "namespace": "shop"}, "spec": {"containers": cs}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}}
    r = ac.evaluate(_agent("linkerd"), _Ev(Pod=[pod("a", True), pod("b", False)]))
    assert r["expected"] == 2 and r["covered"] == 1 and r["missing"] == ["shop/b"] and r["status"] == "degraded"


def test_unknown_daemonsets_are_offered_and_the_tracked_list_round_trips(tmp_path):
    ev = _Ev(DaemonSet=[_agent_ds(), _agent_ds("kube-proxy", "kube-system", "k8s/kube-proxy:1"), _agent_ds("mystery-agent", "ops", "acme/mystery:1")], Node=[])
    assert [u["name"] for u in ac.unknown_daemonsets(ev, ac.CATALOG)] == ["mystery-agent"]
    ac.save_config(str(tmp_path), ["falco", "linkerd"], {"falco": "0.40.0"}, [{"name": "Acme EDR", "kind": "daemonset", "names": ["acme-edr"]}])
    got = {a["id"]: a for a in ac.load_agents(str(tmp_path))}
    assert got["falco"]["tracked"] and got["falco"]["min_version"] == "0.40.0" and not got["wiz"]["tracked"] and got["custom-acme-edr"]["tracked"]
    with pytest.raises(ValueError):
        ac.save_config(str(tmp_path), [], {}, [{"name": "", "kind": "daemonset", "names": []}])


# ---- tuning, health, coverage, simulation, history ------------------------------------------------------
def _ev(rule, proc="sh", ns="monitoring", t="2026-10-21T10:00:00Z"):
    return {"rule": rule, "priority": "Warning", "time": t, "output_fields": {"proc.name": proc, "k8s.ns.name": ns}}


def test_rule_stats_count_fires_and_suggest_an_exception_when_one_source_dominates():
    st = ops.rule_stats([_ev("Shell in prod")] * 9 + [_ev("Shell in prod", "bash", "prod")] + [_ev("Falco internal: syscall event drop")])
    assert st["Shell in prod"]["fires"] == 10 and "Falco internal: syscall event drop" not in st
    sug = ops.suggest_exceptions(st["Shell in prod"], {})
    assert {s["field"] for s in sug} >= {"proc.name", "k8s.ns.name"} and sug[0]["share"] == 0.9
    assert ops.advice(st["Shell in prod"], "audit")["state"] == "noisy" and ops.advice(None, "audit")["state"] == "quiet"


def test_health_reports_dropped_events_and_rule_errors_from_the_logs():
    drop = json.dumps({"rule": "Falco internal: syscall event drop", "priority": "Debug", "time": "t", "output_fields": {"n_drops": 40}})
    alert = json.dumps({"rule": "x", "priority": "Warning", "time": "2026-10-21T10:00:00Z", "output_fields": {}})
    h = ops.health({"falco-a": drop + "\n" + alert, "falco-b": "Error: rule 'bad': unknown field foo.bar\n"})
    assert h["state"] == "errors" and h["dropped_events"] == 40 and h["pods"][1]["errors"]
    assert ops.health({"p": alert})["state"] == "healthy" and ops.health({})["state"] == "no-data"


def test_mitre_coverage_counts_only_rules_that_are_really_watching():
    rules = [{"kind": "curated", "name": "a", "tactic": "Execution"}, {"kind": "custom", "name": "mine", "tactic": "Impact", "deployed": ""},
             {"kind": "default", "name": "d", "tactic": "Persistence", "enabled": True}]
    rows = {r["tactic"]: r for r in ops.mitre_coverage(rules, "not-installed")["rows"]}
    assert rows["Execution"]["active"] == 1 and rows["Impact"]["active"] == 0 and rows["Impact"]["saved"] == 1 and rows["Persistence"]["gap"]
    assert not {r["tactic"]: r for r in ops.mitre_coverage(rules, "healthy")["rows"]}["Persistence"]["gap"]


def test_simulation_plan_gives_throwaway_pod_commands_and_never_runs_anything():
    p = ops.simulation_plan(SPECS["file_read"])
    assert p["setup"].startswith("kubectl run kmw-sim") and "cat /etc/shadow" in p["commands"][0] and p["event_generator"] == "syscall.ReadSensitiveFileUntrusted"
    assert "throwaway" in p["warning"] and p["cleanup"].startswith("kubectl delete pod kmw-sim")
    assert "wget" in ops.simulation_plan(SPECS["network_out"])["commands"][0]


def test_rule_history_restore_export_and_import(tmp_path):
    base = str(tmp_path)
    rr.save_rule(base, SPECS["file_read"])
    v2 = {**SPECS["file_read"], "values": {"paths": "/etc/shadow"}, "priority": "CRITICAL"}
    rr.save_rule(base, v2)
    assert [h["priority"] for h in rr.history(base, "Shadow read")] == ["WARNING"]
    rr.restore(base, "Shadow read", 0)
    assert rr.list_saved(base)[0]["priority"] == "WARNING" and len(rr.history(base, "Shadow read")) == 2
    pack = rr.export_pack(base)
    other = str(tmp_path / "other")
    res = rr.import_pack(other, pack)
    assert res["imported"] == ["Shadow read"] and rr.import_pack(other, pack)["skipped"] == ["Shadow read"]
    assert rr.import_pack(other, [{"name": "x"}])["errors"] and rr.import_pack(other, pack, overwrite=True)["imported"]
    with pytest.raises(rr.RuleError):
        rr.import_pack(other, {"rules": []})


def test_alert_destination_is_validated_kept_out_of_values_and_args_and_only_in_a_secret():
    url = "https://hooks.slack.com/services/T0/B0/secretsecret"
    al = {"slack_webhook": url, "min_priority": "error"}
    v = json.dumps(fd.values("", None, al))
    assert "falcosidekick" in v and "secretsecret" not in v and fd.SECRET_NAME in v
    st = fd.status(_Ev(Node=[_node()]))
    plan = fd.plan(st, alerts=al, have=lambda x: None)
    assert "secretsecret" not in json.dumps(plan)
    steps, stdin = fd.deploy_steps(st, "", "falco", "", "/tmp", None, al)
    assert url in stdin["secret"] and all(url not in " ".join(s["argv"]) for s in steps)
    for bad in ({"slack_webhook": "http://x/y"}, {"slack_webhook": "https://hooks.slack.com/a b"}, {"slack_webhook": url, "min_priority": "loud"}):
        with pytest.raises(ValueError):
            fd.clean_alerts(bad)


def test_the_extra_runtime_routes_answer(tmp_path):
    from k8smatrixwarden.web.app import WebApp
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    post = lambda a, **b: app.route("POST", f"/api/runtime-rules/{a}", body=json.dumps(b).encode())            # noqa: E731
    assert json.loads(post("simulate", spec=SPECS["process"]).body)["commands"]
    post("save", spec=SPECS["file_read"])
    assert json.loads(post("export").body)["pack"]["rules"]
    assert json.loads(post("import", pack=json.loads(post("export").body)["pack"]).body)["skipped"] == ["Shadow read"]
    assert json.loads(post("history", name="Shadow read").body)["history"] == []
    cov = json.loads(post("coverage").body)
    assert cov["rows"] and "Execution" in {r["tactic"] for r in cov["rows"] if r["active"]}
