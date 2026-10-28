"""Every rule says how to fix it, and the dashboard's finding API carries that."""
import json
import tempfile

from k8smatrixwarden.agents.scanner import ScannerAgent
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest
from k8smatrixwarden.core.remediation import FIXES
from k8smatrixwarden.core.report_store import ReportStore
from k8smatrixwarden.core.reporting import finding_anchor
from k8smatrixwarden.web.app import WebApp


def test_every_registered_rule_has_a_fix():
    ids = set(build_platform().registry.rules.ids())
    assert ids == set(FIXES), (ids - set(FIXES), set(FIXES) - ids)
    assert all(f["how"] for f in FIXES.values())


def test_the_finding_api_returns_the_fix():
    p = build_platform()
    r = ScannerAgent(p).scan(ScanRequest(), p.make_collector(mock=True))
    d = tempfile.mkdtemp()
    ReportStore(d).save(r)
    f = next(x for x in r.findings if x.rule_id == "workload-privileged-container")
    anchor = finding_anchor(f.rule_id, f.resource.kind, f.resource.name, f.resource.namespace)
    body = json.loads(WebApp(p, reports_dir=d).route(
        "GET", "/api/finding", query=f"scan_id={r.scan_id}&anchor={anchor}").text)
    assert body["fix"]["how"] and "privileged: false" in body["fix"]["change"]
