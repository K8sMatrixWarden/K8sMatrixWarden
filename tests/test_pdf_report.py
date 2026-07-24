"""PDF report generation (core/pdf_report.py), requires the optional `pdf` extra
(fpdf2). Tests degrade gracefully (no-op pass) when it isn't installed, consistent with
the project's zero-required-dependency philosophy, the same way nothing here hard-fails
if `rich`/`kubernetes`/`mcp` aren't installed either."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanRequest, Scope, ScopeLevel, Selector

try:
    import fpdf  # noqa: F401
    _FPDF = True
except ImportError:
    _FPDF = False


def _result(selector=None):
    p = build_platform()
    coll = p.make_collector(mock=True)
    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=selector or Selector())
    rule_ids = p.mapping.resolve(req.selector)
    from k8smatrixwarden.agents.scanner import ScannerAgent
    return p, ScannerAgent(p).scan(req, coll)


def test_render_pdf_produces_a_valid_pdf():
    if not _FPDF:
        return
    from k8smatrixwarden.core.pdf_report import render_pdf
    p, result = _result()
    data = render_pdf(result)
    assert isinstance(data, bytes)
    assert data.startswith(b"%PDF-")
    assert b"%%EOF" in data[-64:]
    assert len(data) > 1000


def test_render_pdf_handles_zero_findings():
    if not _FPDF:
        return
    from k8smatrixwarden.core.pdf_report import render_pdf
    # a namespace with no matching findings in the mock fixture
    p, empty_result = _result(selector=Selector(rule_ids=["workload-privileged-container"]))
    req = ScanRequest(scope=Scope(ScopeLevel.NAMESPACE, namespace="monitoring"),
                      selector=Selector(rule_ids=["workload-privileged-container"]))
    coll = p.make_collector(mock=True)
    from k8smatrixwarden.agents.scanner import ScannerAgent
    empty_result = ScannerAgent(p).scan(req, coll)
    assert empty_result.total() == 0
    data = render_pdf(empty_result)
    assert data.startswith(b"%PDF-")


def test_render_pdf_all_56_rules_no_exceptions():
    """Every finding a full mock scan can produce must render without error, the
    strongest guard against a KB entry containing something the PDF core fonts choke on
    (Unicode, unbalanced markup, etc.)."""
    if not _FPDF:
        return
    from k8smatrixwarden.core.pdf_report import render_pdf
    p, result = _result()
    assert result.total() > 0
    data = render_pdf(result)
    assert data.startswith(b"%PDF-")


def test_reporting_engine_dispatches_pdf_format():
    if not _FPDF:
        return
    p, result = _result()
    out = p.reporting.render(result, "pdf")
    assert isinstance(out, bytes)
    assert out.startswith(b"%PDF-")


def test_reporting_engine_other_formats_still_return_str():
    # a regression guard: adding pdf's bytes-return path must not affect the other six
    p, result = _result()
    for fmt in ("terminal", "text", "markdown", "json", "sarif", "html"):
        out = p.reporting.render(result, fmt)
        assert isinstance(out, str), fmt


def test_render_pdf_without_fpdf2_raises_clear_runtime_error():
    """Simulates the extra not being installed (the standard `sys.modules[name] = None`
    trick forces the next `import fpdf` to raise ImportError), must surface an
    actionable RuntimeError, not a raw traceback, matching the same graceful-degradation
    contract as the `live`/`mcp` extras elsewhere in the codebase."""
    import k8smatrixwarden.core.pdf_report as pdf_report_mod

    p, result = _result()
    had_fpdf = "fpdf" in sys.modules
    saved = sys.modules.get("fpdf")
    sys.modules["fpdf"] = None
    try:
        try:
            pdf_report_mod.render_pdf(result)
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert "pdf" in str(exc).lower()
    finally:
        if had_fpdf:
            sys.modules["fpdf"] = saved
        else:
            del sys.modules["fpdf"]
