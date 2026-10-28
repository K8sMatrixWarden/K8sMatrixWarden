"""Web dashboard routing (socket-free), WebApp.route covers every surface (§3.1, §19)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.web.app import WebApp


def _app():
    return WebApp(build_platform(), reports_dir=tempfile.mkdtemp())


def _scan(app, body=None):
    r = app.route("POST", "/api/scan", body=json.dumps(body or {"mock": True}).encode())
    return r, json.loads(r.text)


def test_health_reports_platform_stats():
    r = _app().route("GET", "/health")
    assert r.status == 200
    d = json.loads(r.text)
    assert d["status"] == "ok" and d["rules"] > 0 and d["shards"] >= 7


def test_dashboard_is_spa_shell_and_api_reflects_scans():
    # The dashboard is now a client-side app; the shell always serves 200 and the data
    # comes from /api/dashboard. Assert the data contract, not scraped HTML.
    app = _app()
    assert app.route("GET", "/").status == 200
    empty = json.loads(app.route("GET", "/api/dashboard").text)
    assert empty["has_scan"] is False
    _, d = _scan(app)
    data = json.loads(app.route("GET", "/api/dashboard").text)
    assert data["has_scan"] is True
    assert data["scan"]["scan_id"] == d["scan_id"]
    assert "threat_matrix" in data and "attack_path" in data and "runtime" in data
    assert len(data["findings"]) > 0
    # The persisted-runtime slot is always present in the contract; None for a mock scan
    # (which pulls no Falco feed) and populated when a --live scan baked one in.
    assert "runtime_correlation" in data and data["runtime_correlation"] is None


def test_runtime_endpoint_correlates_and_detects_drift():
    app = _app()
    _scan(app)
    events = [{"source": "audit", "verb": "create",
               "resource": "clusterrolebindings", "namespace": "production"}]
    r = app.route("POST", "/api/runtime",
                  body=json.dumps({"events": events}).encode())
    assert r.status == 200
    out = json.loads(r.text)
    assert "correlation" in out and "drift" in out
    assert out["correlation"]["total_alerts"] >= 1


def test_runtime_refresh_needs_scan_then_degrades_without_cluster():
    app = _app()
    # No scan yet -> clear 400, not a crash.
    r = app.route("POST", "/api/runtime/refresh", body=b"{}")
    assert r.status == 400 and "no saved scan" in json.loads(r.text)["error"].lower()
    # With a (mock) scan, the live pull behaves correctly whatever the machine offers.
    # Which outcome you get is a property of the machine, not of the code, and all three
    # are right:
    #   * no cluster reachable       -> 400 naming the missing cluster access
    #   * cluster but no Falco       -> 200 with runtime: null and a warning saying why
    #   * cluster WITH a live Falco  -> 200 with a populated runtime block
    # The third case only became reachable once a real Falco was deployed against this
    # suite; asserting degradation unconditionally would have turned a working live feed
    # into a test failure.
    _scan(app)
    r = app.route("POST", "/api/runtime/refresh", body=b"{}")
    out = json.loads(r.text)
    if r.status == 400:
        assert "cluster access" in out["error"]
    elif out["runtime"] is None:
        assert r.status == 200 and out["warnings"]
    else:
        rt = out["runtime"]
        assert r.status == 200 and rt["source"] and rt["events_seen"] >= 0
        assert "correlation" in rt and "drift" in rt


def test_finding_context_endpoint_returns_report_grade_detail():
    from k8smatrixwarden.core.reporting import finding_anchor
    app = _app()
    _, d = _scan(app)
    data = json.loads(app.route("GET", "/api/dashboard").text)
    f = data["findings"][0]; r = f["resource"]
    anchor = finding_anchor(f["rule_id"], r["kind"], r["name"], r.get("namespace"))
    res = app.route("GET", "/api/finding",
                    query=f"scan_id={data['scan']['scan_id']}&anchor={anchor}")
    assert res.status == 200
    ctx = json.loads(res.text)
    assert ctx["summary"] and ctx["impact"] and isinstance(ctx["validation"], list)
    # unknown anchor is a clean 404, not a crash
    bad = app.route("GET", "/api/finding",
                    query=f"scan_id={data['scan']['scan_id']}&anchor=f-nope")
    assert bad.status == 404




def test_scan_runs_saves_and_is_downloadable():
    app = _app()
    r, d = _scan(app)
    assert r.status == 200
    assert d["scan_id"] and d["total_findings"] > 0 and d["rating"]
    # the HTML report page is gone from the dashboard; the data is still downloadable
    # API JSON carries the threat_matrix block
    api = app.route("GET", f"/api/report/{d['scan_id']}", query="format=json")
    assert api.status == 200 and "threat_matrix" in api.text


def test_scan_by_free_text_selector():
    app = _app()
    _, d = _scan(app, {"scope_level": "cluster", "selector": "Persistence", "mock": True})
    assert d["total_findings"] > 0
    # the scan's matrix must implicate Persistence (multi-tactic findings may add others)
    m = json.loads(app.route("GET", f"/api/report/{d['scan_id']}/matrix").text)
    persistence = next(c for c in m["columns"] if c["tactic"] == "Persistence")
    assert persistence["techniques_hit"] > 0


def test_scan_forwards_context_and_kubeconfig_to_collector():
    # The Scan tab's live cluster selection (context + kubeconfig) must reach the
    # collector. Spy on make_collector: record what the route requested, but hand back a
    # working mock collector so the scan still runs without the kubernetes package.
    app = _app()
    captured = {}
    orig = app.p.make_collector

    def spy(**kwargs):
        captured.update(kwargs)
        return orig(mock=True, fixture=None)

    app.p.make_collector = spy
    r, d = _scan(app, {"scope_level": "cluster", "mock": False,
                       "context": "kind-kind", "kubeconfig": "/tmp/kc"})
    assert r.status == 200 and d["scan_id"]
    assert captured.get("mock") is False
    assert captured.get("context") == "kind-kind"
    assert captured.get("kubeconfig") == "/tmp/kc"






def test_api_reports_lists_saved():
    app = _app()
    _, d = _scan(app)
    rows = json.loads(app.route("GET", "/api/reports").text)
    assert any(row["scan_id"] == d["scan_id"] for row in rows)


def test_missing_report_returns_404():
    app = _app()
    assert app.route("GET", "/report/nope").status == 404
    assert app.route("GET", "/api/report/nope", query="format=json").status == 404


def test_unknown_route_is_404_not_500():
    app = _app()
    assert app.route("GET", "/totally/unknown").status == 404


def test_bad_format_is_rejected():
    app = _app()
    _, d = _scan(app)
    r = app.route("GET", f"/api/report/{d['scan_id']}", query="format=exe")
    assert r.status == 400 and "unknown format" in r.text.lower()


def test_scan_can_be_disabled():
    app = WebApp(build_platform(), reports_dir=tempfile.mkdtemp(), allow_scan=False)
    r = app.route("POST", "/api/scan", body=b"{}")
    assert r.status == 403


def test_invalid_json_body_is_400_not_crash():
    app = _app()
    r = app.route("POST", "/api/scan", body=b"{not json")
    assert r.status == 400 and "error" in r.text


def test_path_traversal_scan_id_is_rejected():
    # a report route param must never escape the store dir (defence in depth even though
    # the server binds localhost by default).
    app = _app()
    for evil in ("../../../../etc/passwd", "..%2f..%2fsecret", "foo/bar"):
        r = app.route("GET", f"/report/{evil}")
        assert r.status == 404
        j = app.route("GET", f"/api/report/{evil}", query="format=json")
        assert j.status == 404




def test_dashboard_pages_offer_a_theme_toggle():
    app = _app()
    for path in ("/", "/runtime-events"):
        html = app.route("GET", path).text
        assert "themebtn" in html and "toggleTheme" in html, path
        assert "data-theme=dark" in html and "data-theme=light" in html, path


def test_dashboard_payload_carries_scan_health_and_owasp_links():
    app = _app()
    app.route("POST", "/api/scan", body=b'{"mock": true}')
    import json as _json
    d = _json.loads(app.route("GET", "/api/dashboard").text)
    assert d["scan"]["evidence_ok"] is True
    assert d["scan"]["warnings"] == []
    assert d["owasp_urls"]["K01"].endswith("K01-Insecure-Workload-Configurations.html")


# --------------------------------------------------------------------------- #
# Client-supplied kubeconfig is code execution, gate it on the bind address
#
# Loading a kubeconfig runs its credential plugin (aws/gcloud/kubelogin) as the server's
# user. On loopback the only caller is the operator. On a routable bind it is RCE, so the
# request-body kubeconfig is refused unless explicitly re-enabled.
# --------------------------------------------------------------------------- #
def _remote_app():
    return WebApp(build_platform(), reports_dir=tempfile.mkdtemp(),
                  allow_client_kubeconfig=False)


def test_is_loopback_is_conservative_about_bind_addresses():
    from k8smatrixwarden.web.server import is_loopback
    for local in ("127.0.0.1", "localhost", "::1", "127.0.0.53", "[::1]"):
        assert is_loopback(local), local
    # "" and 0.0.0.0 bind every interface; a hostname is unknowable here, all remote.
    for remote in ("0.0.0.0", "", "::", "10.0.0.5", "192.168.1.20", "example.com", None):
        assert not is_loopback(remote), remote


def test_remote_bind_refuses_a_kubeconfig_from_the_request_body():
    app = _remote_app()
    for payload in (b'{"mock": false, "kubeconfig": "/etc/passwd"}',
                    b'{"mock": false, "kubeconfig_content": "apiVersion: v1"}'):
        r = app.route("POST", "/api/scan", body=payload)
        assert r.status == 403, payload
        assert "credential plugin" in r.text
        assert "--allow-remote-kubeconfig" in r.text


def test_remote_bind_still_allows_scans_without_a_kubeconfig():
    # the gate is on the kubeconfig, not on scanning, a mock scan still works
    app = _remote_app()
    r = app.route("POST", "/api/scan", body=b'{"mock": true}')
    assert r.status == 200 and "scan_id" in r.text


def test_loopback_bind_still_accepts_a_kubeconfig():
    app = _app()                      # allow_client_kubeconfig defaults True
    seen = {}

    def fake_collector(mock=True, fixture=None, kubeconfig=None, context=None):
        seen["kubeconfig"] = kubeconfig
        raise RuntimeError("stop here, we only care that it got through the gate")

    app.p.make_collector = fake_collector
    r = app.route("POST", "/api/scan", body=b'{"mock": false, "kubeconfig": "/tmp/kc"}')
    assert r.status == 400                      # the RuntimeError above, not the gate
    assert seen["kubeconfig"] == "/tmp/kc"


def test_dashboard_payload_tells_the_form_whether_kubeconfigs_are_accepted():
    import json as _json
    assert _json.loads(_remote_app().route("GET", "/api/dashboard").text)[
        "allow_client_kubeconfig"] is False
    assert _json.loads(_app().route("GET", "/api/dashboard").text)[
        "allow_client_kubeconfig"] is True






def test_compliance_unknown_framework_is_404():
    assert _app().route("GET", "/api/compliance", "frameworks=NOPE").status == 404






def test_every_page_shares_one_sidebar_and_marks_its_own_item():
    from k8smatrixwarden.web import pages
    for page, key in (("home", None), ("graph", "graph"), ("matrix", "matrix"),
                      ("runtime-events", "runtime")):
        nav = pages._topbar(page)
        for item in ("overview", "issues", "graph", "matrix", "cluster", "runtime", "scans"):
            assert f"data-nav='{item}'" in nav
        on = [i for i in ("graph", "matrix", "runtime") if
              f"data-nav='{i}' href=" in nav and "aria-current='page'" in
              nav.split(f"data-nav='{i}'")[1].split(">")[0]]
        assert on == ([key] if key else []), (page, on)
