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
    assert d["status"] == "ok" and d["rules"] > 0 and d["shards"] >= 11


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
    assert r.status == 400 and "no saved scan" in json.loads(r.text)["error"]
    # With a (mock) scan but no live cluster access, the live pull degrades gracefully.
    _scan(app)
    r = app.route("POST", "/api/runtime/refresh", body=b"{}")
    assert r.status == 400 and "cluster access" in json.loads(r.text)["error"]


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


def test_report_export_pdf_and_excel():
    app = _app()
    _scan(app)
    sid = json.loads(app.route("GET", "/api/reports").text)[0]["scan_id"]
    # PDF: 200 + %PDF magic when fpdf2 is present, else a clean 400 naming the dependency.
    pdf = app.route("GET", "/api/report/" + sid, query="format=pdf")
    if pdf.status == 200:
        assert pdf.content_type == "application/pdf" and pdf.body[:4] == b"%PDF"
    else:
        assert pdf.status == 400 and "fpdf" in pdf.text.lower()
    # XLSX (and the 'excel' alias): 200 + PK zip magic when openpyxl is present, else 400.
    for fmt in ("xlsx", "excel"):
        xl = app.route("GET", "/api/report/" + sid, query="format=" + fmt)
        if xl.status == 200:
            assert "spreadsheet" in xl.content_type and xl.body[:2] == b"PK"
        else:
            assert xl.status == 400 and "openpyxl" in xl.text.lower()
    # unknown format still errors clearly, and now lists pdf/xlsx as valid
    bad = app.route("GET", "/api/report/" + sid, query="format=doc")
    assert bad.status == 400 and "xlsx" in bad.text


def test_scan_runs_saves_and_is_downloadable():
    app = _app()
    r, d = _scan(app)
    assert r.status == 200
    assert d["scan_id"] and d["total_findings"] > 0 and d["rating"]
    # report HTML carries the matrix heatmap
    rep = app.route("GET", f"/report/{d['scan_id']}")
    assert rep.status == 200 and "tmgrid" in rep.text
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


def test_coverage_matrix_route():
    r = _app().route("GET", "/matrix")
    assert r.status == 200 and "tmgrid" in r.text and "Threat Matrix" in r.text


def test_report_matrix_page():
    app = _app()
    _, d = _scan(app)
    r = app.route("GET", f"/report/{d['scan_id']}/matrix")
    assert r.status == 200 and "tmgrid" in r.text and d["scan_id"] in r.text


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
    assert r.status == 400 and "unknown format" in r.text


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


def test_coverage_matrix_reports_coverage_not_zeroed_hit_counts():
    """The standalone /matrix page has no scan overlaid, so hit-derived numbers are
    structurally 0. It must report the coverage axis instead of showing "0/9 tactics
    implicated · 0 findings mapped", which reads as a broken counter."""
    app = _app()
    html = app.route("GET", "/matrix").text
    assert "techniques with a detection rule" in html
    assert "tactics with coverage" in html
    assert "rules mapped to the matrix" in html
    assert "with a rule" in html                    # per-column counter
    for hit_stat in ("tactics implicated", "techniques triggered", "findings mapped"):
        assert hit_stat not in html, hit_stat
    # a scan's own matrix keeps the hit axis
    app.route("POST", "/api/scan", body=b'{"mock": true}')
    scan_id = app.store.list()[0].scan_id
    scan_html = app.route("GET", f"/report/{scan_id}/matrix").text
    assert "tactics implicated" in scan_html and "findings mapped" in scan_html


def test_dashboard_pages_offer_a_theme_toggle():
    app = _app()
    for path in ("/", "/matrix"):
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


def test_compliance_html_page_renders():
    r = _app().route("GET", "/compliance")
    assert r.status == 200 and "text/html" in r.content_type
    assert b"Compliance Audit" in r.body


def test_compliance_api_json_and_framework_filter():
    r = _app().route("GET", "/api/compliance", "frameworks=SOC2")
    assert r.status == 200
    d = json.loads(r.text)
    assert [f["short"] for f in d["frameworks"]] == ["SOC 2"]


def test_compliance_unknown_framework_is_404():
    assert _app().route("GET", "/api/compliance", "frameworks=NOPE").status == 404


def test_compliance_pdf_is_binary_or_clean_error():
    r = _app().route("GET", "/compliance", "format=pdf")
    # fpdf2 is optional: either a real PDF, or a clean 400 telling you to install it.
    if r.status == 200:
        assert r.content_type == "application/pdf" and r.body[:5] == b"%PDF-"
    else:
        assert r.status == 400 and b"fpdf2" in r.body


def test_federation_html_and_api_routes():
    app = _app()
    _scan(app, {"mock": True})               # one saved scan -> one cluster
    rh = app.route("GET", "/federation")
    assert rh.status == 200 and b"Federation Blast Radius" in rh.body
    rj = app.route("GET", "/api/federation")
    assert rj.status == 200
    d = json.loads(rj.text)
    assert "clusters" in d and "shared_identities" in d and "summary" in d
