"""The builder: components in, safe manifests and a working Helm chart out."""
import io
import tarfile

import pytest

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core import builder as B

SPEC = {"app": "shop", "namespace": "shop", "components": [
    {"type": "serviceaccount", "name": "web"},
    {"type": "workload", "name": "web", "serviceAccount": "web"},
    {"type": "service", "name": "web", "target": "web"},
    {"type": "ingress", "name": "web", "host": "shop.example.com", "target": "web"},
    {"type": "networkpolicy", "name": "deny", "mode": "default-deny"},
    {"type": "networkpolicy", "name": "allow-ingress", "mode": "allow-from", "target": "web", "from": "ingress-nginx"},
    {"type": "pdb", "name": "web", "target": "web"},
]}


def _kinds(docs):
    return [(d["kind"], d["metadata"]["name"]) for d in docs]


def test_defaults_are_the_hardened_ones():
    docs = B.manifests(SPEC)
    dep = next(d for d in docs if d["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert pod["securityContext"]["runAsNonRoot"] is True and pod["automountServiceAccountToken"] is False
    assert c["securityContext"]["readOnlyRootFilesystem"] is True and c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert c["resources"]["limits"] and ("Service", "web") in _kinds(docs)


def test_a_secure_build_checks_clean_and_loosening_a_default_is_called_out():
    p = build_platform()
    ok = B.check(SPEC, p)
    assert ok["ok"], ok["issues"]
    loose = {**SPEC, "components": [dict(c, runAsRoot=True) if c["type"] == "workload" else c for c in SPEC["components"]]}
    bad = B.check(loose, p)
    assert any(i["rule"] == "workload-run-as-root" and i["component"] == "web" for i in bad["issues"])
    assert all(i["fix"] for i in bad["issues"] if i["rule"] == "workload-run-as-root")


def test_chart_has_values_and_templates_that_read_them():
    files = B.chart_files(SPEC)
    assert {"Chart.yaml", "values.yaml", "templates/deployment-web.yaml", "templates/service-web.yaml"} <= set(files)
    assert "image: nginxinc" in files["values.yaml"] and "replicas: 2" in files["values.yaml"]
    dep = files["templates/deployment-web.yaml"]
    assert "{{ .Values.web.image | quote }}" in dep and "replicas: {{ .Values.web.replicas }}" in dep
    assert "namespace: {{ .Release.Namespace }}" in dep and "@@" not in "".join(files.values())
    with tarfile.open(fileobj=io.BytesIO(B.chart_tgz(SPEC))) as t:
        assert "shop/Chart.yaml" in t.getnames() and "shop/templates/ingress-web.yaml" in t.getnames()
    assert "helm install shop ./shop" in B.install_command(SPEC)


@pytest.mark.parametrize("bad,msg", [
    ({"app": "Bad_Name"}, "lowercase"),
    ({"components": [{"type": "service", "name": "s"}]}, "needs to point at"),
    ({"components": [{"type": "workload", "name": "w", "image": "nginx; rm"}]}, "valid image"),
    ({"components": [{"type": "workload", "name": "w", "port": 99999}]}, "between"),
    ({"components": [{"type": "workload", "name": "w", "serviceAccount": "ghost"}]}, "not on the canvas"),
    ({"components": [{"type": "networkpolicy", "name": "p", "mode": "allow-from"}]}, "needs to point at"),
    ({"components": [{"type": "workload", "name": "w"}, {"type": "workload", "name": "w"}]}, "two workload"),
])
def test_mistakes_get_a_plain_sentence_not_a_traceback(bad, msg):
    with pytest.raises(B.BuildError, match=msg):
        B.manifests({"app": "x", **bad})


def test_http_preview_chart_and_friendly_errors(tmp_path):
    import json
    from k8smatrixwarden.web.app import WebApp
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    body = json.dumps(SPEC).encode()
    r = app.route("POST", "/api/build/preview", body=body)
    d = json.loads(r.body)
    assert r.status == 200 and "kind: Deployment" in d["yaml"] and d["check"]["ok"] and "helm install" in d["install"]
    c = app.route("POST", "/api/build/chart", body=body)
    assert c.status == 200 and c.content_type == "application/gzip" and c.body[:2] == b"\x1f\x8b"
    bad = app.route("POST", "/api/build/preview", body=json.dumps({"app": "x", "components": [{"type": "service"}]}).encode())
    assert bad.status == 422 and "needs to point at" in json.loads(bad.body)["error"]


# ---- security layers, DNS/ingress allow rules, saved designs ---------------------------------
def _base():
    return {"app": "shop", "namespace": "shop", "components": [
        {"type": "networkpolicy", "name": "default-deny", "mode": "default-deny"},
        {"type": "workload", "name": "shop"}, {"type": "service", "name": "shop", "target": "shop"},
        {"type": "ingress", "name": "shop", "host": "shop.example.com", "target": "shop"}]}


def test_default_deny_without_dns_or_ingress_allow_is_reported_as_missing_layers():
    from k8smatrixwarden.core import builder
    ly = {x["id"]: x for x in builder.layers(_base())["layers"]}
    assert ly["dns-egress"]["status"] == "off" and ly["dns-egress"]["add"]["mode"] == "allow-dns"
    assert ly["ingress-path"]["status"] == "off" and ly["ingress-path"]["add"]["from"] == "ingress-nginx"


def test_adding_the_suggested_layers_closes_them_and_the_chart_still_builds():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["transport"] = {"mode": "mesh", "mesh": "linkerd"}          # a choice, not an addable component
    for _ in range(3):
        for x in builder.layers(spec)["layers"]:
            if x["status"] == "off" and x["add"] and not x["optional"]:
                spec["components"].append(dict(x["add"]))
    r = builder.layers(spec)
    assert r["off"] == 0, [x["id"] for x in r["layers"] if x["status"] == "off" and not x["optional"]]
    assert "allow-dns" in str(builder.manifests(spec)) or "kube-dns" in str(builder.manifests(spec))
    assert builder.chart_files(spec)["Chart.yaml"]


def test_a_secret_typed_into_plain_env_is_flagged_loosened():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"][1]["env"] = [{"name": "DB_PASSWORD", "value": "x"}]
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}
    assert ly["secrets"]["status"] == "loosened" and "DB_PASSWORD" in ly["secrets"]["detail"]


def test_secret_env_becomes_a_secret_key_ref_never_a_value():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"][1]["secretEnv"] = [{"name": "DB_PASSWORD", "secret": "shop-db", "key": "password"}]
    dep = next(d for d in builder.manifests(spec) if d["kind"] == "Deployment")
    env = dep["spec"]["template"]["spec"]["containers"][0]["env"][0]
    assert env["valueFrom"]["secretKeyRef"] == {"name": "shop-db", "key": "password"} and "value" not in env


def test_workload_gets_probes_by_default_and_namespace_name_follows_the_app_namespace():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"].append({"type": "namespace", "name": "something-else"})
    docs = builder.manifests(spec)
    c = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert "readinessProbe" in c and "livenessProbe" in c
    assert next(d for d in docs if d["kind"] == "Namespace")["metadata"]["name"] == "shop"


def test_saved_designs_round_trip_and_refuse_bad_names(tmp_path):
    from k8smatrixwarden.core import builder
    base = str(tmp_path)
    builder.blueprint_save(base, "secure api", _base())
    assert [d["name"] for d in builder.blueprint_list(base)] == ["secure api"]
    assert builder.blueprint_load(base, "secure api")["app"] == "shop"
    for bad in ("../x", "", "a/b"):
        try:
            builder.blueprint_save(base, bad, _base())
            assert False, bad
        except builder.BuildError:
            pass
        try:
            builder.blueprint_load(base, bad)
            assert False, bad
        except builder.BuildError:
            pass
    assert builder.blueprint_delete(base, "secure api") and not builder.blueprint_list(base)


# ---- loosening a default needs a reason and compensating controls ----------------------------
def _root_spec(reason=""):
    spec = _base()
    spec["components"][1].update({"runAsRoot": True, "reason": reason})
    return spec


def test_loosened_default_without_a_reason_is_not_accepted():
    from k8smatrixwarden.core import builder
    lay = {x["id"]: x for x in builder.layers(_root_spec())["layers"]}["non-root"]
    assert lay["status"] == "loosened" and "business reason" in lay["detail"]
    assert {c["id"] for c in lay["compensating"]} == {"read-only-fs", "default-deny", "no-token"}


def test_loosened_default_with_reason_and_cover_is_covered_and_annotated():
    from k8smatrixwarden.core import builder
    spec = _root_spec("vendor image cannot drop root, SEC-123")
    lay = {x["id"]: x for x in builder.layers(spec)["layers"]}["non-root"]
    assert lay["status"] == "covered" and "SEC-123" in lay["reason"]
    dep = next(d for d in builder.manifests(spec) if d["kind"] == "Deployment")
    assert dep["metadata"]["annotations"]["k8smatrixwarden.io/exception"].startswith("vendor image")


def test_loosened_default_is_not_covered_when_a_compensating_control_is_missing():
    from k8smatrixwarden.core import builder
    spec = _root_spec("legacy")
    spec["components"][1]["writableRoot"] = True            # now the read-only filesystem cover is gone too
    lay = {x["id"]: x for x in builder.layers(spec)["layers"]}["non-root"]
    assert lay["status"] == "loosened" and "still needs" in lay["detail"]


def test_public_load_balancer_needs_source_ranges_and_they_reach_the_manifest():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"][2].update({"kind": "LoadBalancer", "reason": "partner API", "sourceRanges": ["203.0.113.0/24"]})
    svc = next(d for d in builder.manifests(spec) if d["kind"] == "Service")
    assert svc["spec"]["loadBalancerSourceRanges"] == ["203.0.113.0/24"]
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}
    assert {c["id"]: c["status"] for c in ly["no-public-service"]["compensating"]}["source-ranges"] == "on"


def test_preview_error_still_returns_layers_and_names_the_component(tmp_path):
    import json
    from k8smatrixwarden.web.app import WebApp
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    spec = {"app": "a", "namespace": "a", "components": [
        {"type": "networkpolicy", "name": "d", "mode": "default-deny"}, {"type": "hpa", "name": "h"}]}
    r = app.route("POST", "/api/build/preview", body=json.dumps(spec).encode())
    d = json.loads(r.body)
    assert r.status == 422 and d["component"] == "h" and d["layers"]["layers"]


def test_loosened_pod_security_and_api_token_need_a_reason_even_with_no_app_yet():
    from k8smatrixwarden.core import builder
    spec = {"app": "a", "namespace": "a", "components": [
        {"type": "namespace", "psa": "privileged"}, {"type": "serviceaccount", "name": "s", "readsApi": True}]}
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}
    assert ly["ns-fence"]["status"] == "loosened" and "business reason" in ly["ns-fence"]["detail"]
    assert ly["no-token"]["status"] == "loosened"
    assert any(c["add"] == {"type": "workload"} for c in ly["ns-fence"]["compensating"])


# ---- 1. permissions, 2. outbound, 3. supply chain, 4. guardrails and drift, 5. locks ----------
def _sa_spec(**role):
    spec = _base()
    spec["components"] += [{"type": "serviceaccount", "name": "app", "readsApi": True, "reason": "operator"}]
    spec["components"][1]["serviceAccount"] = "app"
    if role is not None:
        spec["components"].append({"type": "role", "name": "app-role", "serviceAccount": "app", **role})
    return spec


def test_api_token_without_a_role_asks_for_one_and_wildcards_are_refused():
    from k8smatrixwarden.core import builder
    spec = _sa_spec()
    spec["components"].pop()                                           # drop the role
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}
    assert ly["api-role"]["status"] == "off" and ly["api-role"]["add"]["type"] == "role"
    spec["components"].append({"type": "role", "name": "r", "serviceAccount": "app",
                               "rules": [{"resources": ["*"], "verbs": ["get"]}]})
    with pytest.raises(builder.BuildError, match="Wildcards"):
        builder.manifests(spec)


def test_role_becomes_namespaced_role_and_binding_and_secret_access_needs_a_reason():
    from k8smatrixwarden.core import builder
    spec = _sa_spec(rules=[{"resources": ["secrets"], "verbs": ["get"]}])
    docs = builder.manifests(spec)
    assert {"Role", "RoleBinding"} <= {d["kind"] for d in docs} and "ClusterRole" not in {d["kind"] for d in docs}
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}["least-privilege-rbac"]
    assert ly["status"] == "loosened" and "secrets" in ly["detail"]


def test_egress_cidr_refuses_the_whole_internet_and_ports_reach_the_policy():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"].append({"type": "networkpolicy", "name": "ext", "mode": "allow-egress-cidr", "target": "shop", "cidr": "0.0.0.0/0"})
    with pytest.raises(builder.BuildError, match="whole internet"):
        builder.manifests(spec)
    spec["components"][-1].update({"cidr": "203.0.113.0/24", "port": "443"})
    pol = [d for d in builder.manifests(spec) if d["metadata"]["name"] == "ext"][0]
    assert pol["spec"]["egress"][0]["ports"] == [{"protocol": "TCP", "port": 443}]


def test_floating_image_tag_and_untrusted_registry_are_flagged():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"][1]["image"] = "nginx:latest"
    spec["registries"] = "registry.example.com/team"
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}
    assert ly["image-tag"]["status"] == "off" and ly["trusted-registry"]["status"] == "off"


def test_image_scan_refuses_option_like_references_and_reports_missing_grype():
    from k8smatrixwarden.core import builder

    class Gone:
        def available(self):
            return False

    with pytest.raises(builder.BuildError):
        builder.scan_image("--output=/etc/passwd")
    assert builder.scan_image("nginx:1.27", Gone())["available"] is False


def test_guardrail_policy_is_built_from_the_design_and_leaves_out_loosened_controls():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["guardrails"] = "deny"
    docs = builder.manifests(spec)
    vap = next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicy")
    msgs = [v["message"] for v in vap["spec"]["validations"]]
    assert "Containers must run as a non-root user." in msgs
    assert next(d for d in docs if d["kind"] == "ValidatingAdmissionPolicyBinding")["spec"]["validationActions"] == ["Deny"]
    spec["components"][1].update({"runAsRoot": True, "reason": "vendor"})
    vap = next(d for d in builder.manifests(spec) if d["kind"] == "ValidatingAdmissionPolicy")
    assert "Containers must run as a non-root user." not in [v["message"] for v in vap["spec"]["validations"]]
    spec["guardrails"] = "off"
    assert not [d for d in builder.manifests(spec) if d["kind"].startswith("ValidatingAdmission")]


def test_drift_names_where_the_cluster_moved_away_from_the_design():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"].insert(0, {"type": "namespace", "name": "shop"})
    inv = {"sections": {
        "namespaces": [{"name": "shop", "psa": "baseline"}], "services": [], "ingresses": [], "policies": [],
        "workloads": [{"id": "shop/Deployment/shop", "name": "shop", "namespace": "shop", "desired": 5,
                       "images": ["nginxinc/nginx-unprivileged:1.27.2-alpine"]},
                      {"id": "shop/Deployment/rogue", "name": "rogue", "namespace": "shop", "desired": 1, "images": []}],
        "pods": [{"namespace": "shop", "workload": "shop/Deployment/shop", "flags": [],
                  "containers": [{"privileged": True, "root": True, "read_only_fs": False, "limits": False}]}]}}
    items = {(i["object"], i["aspect"]) for i in builder.drift(spec, inv)["items"]}
    assert ("Namespace shop", "Pod Security level") in items and ("Workload shop", "privileged") in items
    assert ("Workload shop", "replicas") in items and ("Workload rogue", "in the design") in items


def test_locked_layer_is_blocked_until_a_named_approver_and_expiry_returns_it():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"][1].update({"runAsRoot": True, "reason": "vendor"})
    spec["locks"] = ["non-root"]
    assert {x["id"]: x for x in builder.layers(spec)["layers"]}["non-root"]["status"] == "blocked"
    spec["approvals"] = {"non-root": {"by": "alice", "ticket": "SEC-1", "expires": "2099-01-01"}}
    assert {x["id"]: x for x in builder.layers(spec)["layers"]}["non-root"]["status"] == "covered"
    spec["approvals"]["non-root"]["expires"] = "2020-01-01"
    assert {x["id"]: x for x in builder.layers(spec)["layers"]}["non-root"]["status"] == "loosened"


def test_only_fully_covered_exceptions_are_exported_and_each_one_expires():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"][1].update({"runAsRoot": True, "reason": ""})
    assert builder.exceptions(spec) == []
    spec["components"][1]["reason"] = "vendor image"
    out = builder.exceptions(spec)
    assert out and out[0]["rule"] == "workload-run-as-root" and out[0]["resource"] == "shop/Deployment/shop" and out[0]["expires"]


def test_drift_endpoint_compares_with_the_latest_saved_scan(tmp_path):
    import json
    from k8smatrixwarden.agents.scanner import ScannerAgent
    from k8smatrixwarden.core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector
    from k8smatrixwarden.core.report_store import ReportStore
    from k8smatrixwarden.web.app import WebApp
    p = build_platform()
    res = ScannerAgent(p).scan(ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(), mode=ScanMode.SYNC),
                               p.make_collector(mock=True))
    ReportStore(str(tmp_path)).save(res)
    app = WebApp(p, reports_dir=str(tmp_path))
    r = app.route("POST", "/api/build/drift", body=json.dumps(SPEC).encode())
    d = json.loads(r.body)
    assert r.status == 200 and d["checked"] and "items" in d
    empty = WebApp(p, reports_dir=str(tmp_path / "none"))
    assert empty.route("POST", "/api/build/drift", body=json.dumps(SPEC).encode()).status == 404


# ---- workload kinds -----------------------------------------------------------------------------
@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet", "CronJob", "Job"])
def test_every_workload_kind_builds_a_hardened_pod_and_checks_clean(kind):
    from k8smatrixwarden.core import builder
    spec = {"app": "a", "namespace": "a", "components": [
        {"type": "networkpolicy", "name": "d", "mode": "default-deny"}, {"type": "workload", "name": "w", "kind": kind}]}
    docs = builder.manifests(spec)
    wl = next(d for d in docs if d["kind"] == kind)
    tmpl = wl["spec"]["template"] if kind in ("Deployment", "StatefulSet", "Job") else wl["spec"]["jobTemplate"]["spec"]["template"]
    sc = tmpl["spec"]["containers"][0]["securityContext"]
    assert sc["allowPrivilegeEscalation"] is False and sc["readOnlyRootFilesystem"] is True
    assert builder.check(spec, build_platform())["ok"]
    assert builder.chart_files(spec)["values.yaml"]


def test_statefulset_gets_storage_and_a_headless_service_and_jobs_get_no_probes_or_pdb():
    from k8smatrixwarden.core import builder
    spec = {"app": "a", "namespace": "a", "components": [{"type": "workload", "name": "db", "kind": "StatefulSet", "storage": "20Gi"}]}
    docs = builder.manifests(spec)
    ss = next(d for d in docs if d["kind"] == "StatefulSet")
    assert ss["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] == "20Gi"
    assert any(d["kind"] == "Service" and d["spec"]["clusterIP"] == "None" for d in docs)
    job = {"app": "a", "namespace": "a", "components": [{"type": "workload", "name": "j", "kind": "Job", "replicas": 3}]}
    ids = {x["id"] for x in builder.layers(job)["layers"]}
    assert not ids & {"probes", "pdb", "hpa"}


def test_service_cannot_point_at_a_job_and_cron_schedule_is_validated():
    from k8smatrixwarden.core import builder
    spec = {"app": "a", "namespace": "a", "components": [
        {"type": "workload", "name": "j", "kind": "Job"}, {"type": "service", "name": "s", "target": "j"}]}
    with pytest.raises(builder.BuildError, match="keeps running"):
        builder.manifests(spec)
    with pytest.raises(builder.BuildError, match="five parts"):
        builder.manifests({"app": "a", "namespace": "a", "components": [{"type": "workload", "name": "c", "kind": "CronJob", "schedule": "daily"}]})


# ---- more components: disk, certificate, node agent, limits, spread ------------------------------
def test_storage_certificate_daemonset_limitrange_and_spread_are_built():
    from k8smatrixwarden.core import builder
    spec = {"app": "a", "namespace": "a", "components": [
        {"type": "namespace", "name": "a"}, {"type": "workload", "name": "w", "replicas": 2},
        {"type": "workload", "name": "agent", "kind": "DaemonSet"},
        {"type": "storage", "name": "w-data", "target": "w", "size": "20Gi", "path": "/var/data"},
        {"type": "service", "name": "s", "target": "w"}, {"type": "ingress", "name": "i", "target": "s"},
        {"type": "certificate", "name": "c", "target": "i", "issuer": "corp-ca"}]}
    docs = builder.manifests(spec)
    kinds = {d["kind"] for d in docs}
    assert {"LimitRange", "PersistentVolumeClaim", "Certificate", "DaemonSet"} <= kinds
    pod = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]
    assert {"name": "w-data", "persistentVolumeClaim": {"claimName": "w-data"}} in pod["volumes"]
    assert pod["topologySpreadConstraints"][0]["topologyKey"] == "kubernetes.io/hostname"
    cert = next(d for d in docs if d["kind"] == "Certificate")
    assert cert["spec"]["secretName"] == "i-tls" and cert["spec"]["issuerRef"]["name"] == "corp-ca"


def test_storage_refuses_a_statefulset_target_and_bad_paths():
    from k8smatrixwarden.core import builder
    base = [{"type": "workload", "name": "db", "kind": "StatefulSet"}]
    with pytest.raises(builder.BuildError, match="own disk"):
        builder.manifests({"app": "a", "namespace": "a", "components": base + [{"type": "storage", "name": "d", "target": "db"}]})
    with pytest.raises(builder.BuildError, match="mount path"):
        builder.manifests({"app": "a", "namespace": "a", "components": [{"type": "workload", "name": "w"},
                           {"type": "storage", "name": "d", "target": "w", "path": "/../etc"}]})


def test_ingress_with_tls_suggests_a_certificate_layer():
    from k8smatrixwarden.core import builder
    ly = {x["id"]: x for x in builder.layers(_base())["layers"]}
    assert ly["certificate"]["status"] == "off" and ly["certificate"]["add"]["type"] == "certificate"


# ---- threat-model hardening ----------------------------------------------------------------------
def test_namespace_and_fences_come_before_workloads_and_the_guardrail_binding_comes_last():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"].append({"type": "namespace", "name": "shop"})
    kinds = [d["kind"] for d in builder.manifests(spec)]
    assert kinds[0] == "Namespace" and kinds.index("Namespace") < kinds.index("Deployment")
    assert kinds[-1] == "ValidatingAdmissionPolicyBinding"


def test_yaml_has_no_aliases_even_where_a_dict_is_shared():
    from k8smatrixwarden.core import builder
    text = builder.manifests_yaml(_base())
    assert "&id" not in text and "*id" not in text
    assert "livenessProbe" in text and text.count("tcpSocket") == 2


def test_guardrail_checks_init_and_ephemeral_containers_too():
    from k8smatrixwarden.core import builder
    vap = next(d for d in builder.manifests(_base()) if d["kind"] == "ValidatingAdmissionPolicy")
    exprs = " ".join(v["expression"] for v in vap["spec"]["validations"])
    assert "initContainers.all" in exprs and "ephemeralContainers.all" in exprs
    assert "pods/ephemeralcontainers" in vap["spec"]["matchConstraints"]["resourceRules"][0]["resources"]


def test_an_app_with_no_identity_gets_its_own_tokenless_service_account():
    from k8smatrixwarden.core import builder
    docs = builder.manifests(_base())
    sa = next(d for d in docs if d["kind"] == "ServiceAccount")
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert sa["metadata"]["name"] == "shop" and sa["automountServiceAccountToken"] is False
    assert dep["spec"]["template"]["spec"]["serviceAccountName"] == "shop"


def test_namespace_peers_can_be_narrowed_to_one_pod_and_wide_ones_are_called_out():
    from k8smatrixwarden.core import builder
    spec = _base()
    spec["components"].append({"type": "networkpolicy", "name": "in", "mode": "allow-from", "target": "shop", "from": "ingress-nginx", "port": "8080"})
    assert {x["id"]: x for x in builder.layers(spec)["layers"]}["narrow-peers"]["status"] == "off"
    spec["components"][-1]["fromPod"] = "ingress-nginx"
    pol = next(d for d in builder.manifests(spec) if d["metadata"]["name"] == "in")
    peer = pol["spec"]["ingress"][0]["from"][0]
    assert peer["podSelector"]["matchLabels"]["app.kubernetes.io/name"] == "ingress-nginx" and "namespaceSelector" in peer
    assert {x["id"]: x for x in builder.layers(spec)["layers"]}["narrow-peers"]["status"] == "on"


def test_network_rules_are_flagged_when_the_cluster_plugin_does_not_enforce_them():
    from k8smatrixwarden.core import builder
    ly = {x["id"]: x for x in builder.layers(_base(), {"cni": "flannel"})["layers"]}
    assert ly["netpol-enforced"]["status"] == "off" and "does not enforce" in ly["netpol-enforced"]["detail"]
    ly = {x["id"]: x for x in builder.layers(_base(), {"cni": "calico"})["layers"]}
    assert ly["netpol-enforced"]["status"] == "on"


def test_every_layer_maps_to_an_attacker_goal_and_residual_risk_is_stated():
    from k8smatrixwarden.core import builder
    out = builder.layers(_base())
    assert all(x["tactic"] in builder.TACTICS and x["threat"] for x in out["layers"])
    assert out["threats"] and out["residual"] and any("runtime" in r.lower() for r in out["residual"])


# ---- encryption between services ------------------------------------------------------------------
def _two_tier(transport=None):
    return {"app": "a", "namespace": "a", "transport": transport or {}, "components": [
        {"type": "namespace", "name": "a"}, {"type": "networkpolicy", "name": "d", "mode": "default-deny"},
        {"type": "workload", "name": "web"}, {"type": "service", "name": "web", "target": "web"},
        {"type": "workload", "name": "api"}, {"type": "service", "name": "api", "target": "api"},
        {"type": "networkpolicy", "name": "api-from-web", "mode": "allow-from", "target": "api", "from": "web", "port": "8080"}]}


def test_encryption_between_services_is_required_until_a_choice_is_made():
    from k8smatrixwarden.core import builder
    x = {y["id"]: y for y in builder.layers(_two_tier())["layers"]}["service-encryption"]
    assert x["status"] == "off" and len(x["choices"]) == 4 and any(c["recommended"] for c in x["choices"])


def test_recommendation_follows_what_the_cluster_already_runs():
    from k8smatrixwarden.core import builder
    pick = lambda env: [c["set"] for c in {y["id"]: y for y in builder.layers(_two_tier(), env)["layers"]}["service-encryption"]["choices"] if c["recommended"]]  # noqa: E731
    assert pick({"scanned": True, "mesh": "istio"}) == [{"mode": "mesh", "mesh": "istio"}]
    assert pick({"scanned": True, "certmanager": True}) == [{"mode": "certs"}]
    assert pick({"scanned": True}) == [{"mode": "mesh", "mesh": "linkerd"}]


def test_linkerd_mode_annotates_the_namespace_and_gives_the_proxy_limits():
    from k8smatrixwarden.core import builder
    docs = builder.manifests(_two_tier({"mode": "mesh", "mesh": "linkerd"}))
    ns = next(d for d in docs if d["kind"] == "Namespace")
    assert ns["metadata"]["annotations"]["linkerd.io/inject"] == "enabled"
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert "config.linkerd.io/proxy-cpu-limit" in dep["spec"]["template"]["metadata"]["annotations"]


def test_istio_ambient_mode_is_strict_mtls_and_allow_rules_become_identity_rules():
    from k8smatrixwarden.core import builder
    docs = builder.manifests(_two_tier({"mode": "mesh", "mesh": "istio"}))
    assert next(d for d in docs if d["kind"] == "Namespace")["metadata"]["labels"]["istio.io/dataplane-mode"] == "ambient"
    assert next(d for d in docs if d["kind"] == "PeerAuthentication")["spec"]["mtls"]["mode"] == "STRICT"
    pol = next(d for d in docs if d["kind"] == "AuthorizationPolicy")
    assert pol["spec"]["rules"][0]["from"][0]["source"]["principals"] == ["cluster.local/ns/a/sa/web"]


def test_certificate_mode_gives_each_serving_app_a_certificate_mounted_read_only():
    from k8smatrixwarden.core import builder
    docs = builder.manifests(_two_tier({"mode": "certs", "issuer": "corp-ca"}))
    certs = [d for d in docs if d["kind"] == "Certificate"]
    assert {c["metadata"]["name"] for c in certs} == {"web-internal", "api-internal"}
    assert certs[0]["spec"]["issuerRef"]["name"] == "corp-ca" and "web.a.svc" in next(c for c in certs if c["metadata"]["name"] == "web-internal")["spec"]["dnsNames"]
    pod = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "web")["spec"]["template"]["spec"]
    assert any(m["name"] == "tls" and m["readOnly"] for m in pod["containers"][0]["volumeMounts"])


def test_skipping_encryption_needs_a_reason_and_mesh_without_the_cluster_having_it_is_flagged():
    from k8smatrixwarden.core import builder
    lay = lambda t, env=None: {y["id"]: y for y in builder.layers(_two_tier(t), env)["layers"]}["service-encryption"]  # noqa: E731
    assert lay({"mode": "none"})["status"] == "loosened"
    assert lay({"mode": "none", "reason": "single service"})["status"] == "covered"
    assert lay({"mode": "mesh", "mesh": "istio"}, {"scanned": True, "mesh": "linkerd"})["status"] == "off"
    assert lay({"mode": "mesh", "mesh": "linkerd"}, {"scanned": True, "mesh": "linkerd"})["status"] == "on"


# ---- per-component threat model, attack paths, private registry ----------------------------------
def _three(**extra):
    c = lambda **k: k                                                              # noqa: E731
    return {"app": "a", "namespace": "a", "transport": {"mode": "none", "reason": "t"}, **extra, "components": [
        c(type="namespace", name="a"), c(type="networkpolicy", name="d", mode="default-deny"), c(type="networkpolicy", name="dns", mode="allow-dns"),
        c(type="workload", name="web"), c(type="service", name="web", target="web"),
        c(type="workload", name="api"), c(type="service", name="api", target="api"),
        c(type="networkpolicy", name="api-from-web", mode="allow-from", target="api", port="8080", **{"from": "web"}),
        c(type="networkpolicy", name="web-to-api", mode="allow-to", target="web", to="api", port="8080")]}


def test_threat_model_lists_stride_threats_for_each_flow_and_app_and_verifies_flows():
    from k8smatrixwarden.core import builder
    spec = _three()
    tm = builder.threat_model(spec, builder.layers(spec, {"scanned": True, "cni": "calico"}), builder.analyze(spec, build_platform()))
    assert tm["verified"] and [f["verified"] for f in tm["flows"] if f["id"] == "web>api"] == [True]
    cats = {t["stride"] for t in tm["threats"]}
    assert cats == set("STRIDE")
    assert all(t["status"] in ("mitigated", "partial", "open", "residual") for t in tm["threats"]) and tm["boundaries"]
    assert any(t["status"] == "residual" and t["residual"] for t in tm["threats"])          # honest about what is not covered


def test_a_rule_that_blocks_its_own_call_is_reported_as_a_design_defect():
    from k8smatrixwarden.core import builder
    spec = _three()
    spec["components"] = [c for c in spec["components"] if c["name"] != "web-to-api"]
    tm = builder.threat_model(spec, builder.layers(spec), builder.analyze(spec, build_platform()))
    assert [f["verified"] for f in tm["flows"] if f["id"] == "web>api"] == [False]
    assert any(t["category"] == "Design defect" and "outbound rule" in t["abuse"] for t in tm["threats"])


def test_the_scanners_own_topology_sees_the_design_so_exposure_is_evaluated():
    from k8smatrixwarden.core import builder
    spec = _three()
    spec["components"] += [{"type": "ingress", "name": "web", "target": "web"}]
    topo = builder.analyze(spec, build_platform()).topology
    assert "a/Deployment/web" in topo["summary"]["internet_exposed"] and topo["summary"]["workloads"] == 2


def test_attack_path_found_in_a_risky_design(tmp_path):
    import json
    from k8smatrixwarden.web.app import WebApp
    spec = _three()
    spec["components"] += [{"type": "serviceaccount", "name": "web", "readsApi": True, "reason": "x"},
                           {"type": "role", "name": "r", "serviceAccount": "web", "rules": [{"resources": ["secrets"], "verbs": ["get"]}], "reason": "x"}]
    spec["components"][3]["serviceAccount"] = "web"
    app = WebApp(build_platform(), reports_dir=str(tmp_path))
    d = json.loads(app.route("POST", "/api/build/preview", body=json.dumps(spec).encode()).body)
    assert d["threat_model"]["threats"] and any("read-secrets" in p["target"] or "secrets" in p["target"] for p in d["attack_paths"])


def test_pull_secret_signing_policy_and_trusted_registry_reach_the_manifests():
    from k8smatrixwarden.core import builder
    key = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----"
    spec = {"app": "a", "namespace": "a", "registries": "artifactory.corp.com/docker-local", "pullSecret": "art-pull", "signing": {"publicKey": key},
            "components": [{"type": "workload", "name": "w", "image": "artifactory.corp.com/docker-local/w:1.0"}]}
    docs = builder.manifests(spec)
    assert next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["imagePullSecrets"] == [{"name": "art-pull"}]
    pol = next(d for d in docs if d["kind"] == "ClusterPolicy")
    assert pol["spec"]["rules"][0]["verifyImages"][0]["imageReferences"] == ["artifactory.corp.com/docker-local/*"]
    ly = {x["id"]: x for x in builder.layers(spec)["layers"]}
    assert ly["image-signed"]["status"] == "on" and ly["private-registry-auth"]["status"] == "on"
    with pytest.raises(builder.BuildError, match="PEM"):
        builder.manifests({**spec, "signing": {"publicKey": "not a key"}})


def test_digest_resolver_pins_a_tag_from_the_registry_and_refuses_bad_input():
    from k8smatrixwarden.core import builder

    class Resp:
        headers = {"Docker-Content-Digest": "sha256:" + "c" * 64}

    seen = {}

    def opener(req, timeout=0):
        seen["url"], seen["auth"] = req.full_url, req.headers.get("Authorization")
        return Resp()

    out = builder.resolve_digest("artifactory.corp.com/docker-local/shop/web:1.2", opener, {"K8SMW_REGISTRY_TOKEN": "tok"})
    assert out["pinned"].endswith("@sha256:" + "c" * 64) and out["pinned"].startswith("artifactory.corp.com/docker-local/shop/web:1.2@")
    assert seen["url"] == "https://artifactory.corp.com/v2/docker-local/shop/web/manifests/1.2" and seen["auth"] == "Bearer tok"
    assert builder.resolve_digest("a/b@sha256:" + "d" * 64)["already"] is True
    with pytest.raises(builder.BuildError):
        builder.resolve_digest("--evil")


def test_layers_work_on_a_half_built_design():
    # A bad name and a broken component must not hide the protections the user is designing for.
    out = B.layers({"app": "Alibaba", "namespace": "", "components": [
        {"type": "workload", "name": "web"}, {"type": "service", "name": "x", "target": "missing"}]})
    assert out["layers"] and out["problems"]
    assert any("workload" in x["types"] for x in out["layers"])


def test_layers_of_nothing_never_raise():
    for spec in (None, {}, {"components": [None, "x", 3]}):
        assert B.layers(spec)["layers"]
