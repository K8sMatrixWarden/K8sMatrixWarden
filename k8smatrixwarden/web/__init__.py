"""
Web interface (§3.1, §19), the Security Dashboard from the architecture doc.

A dependency-free (stdlib `http.server`) web app where a security engineer can browse every
saved scan, open the full rich HTML report, view the per-scan **Kubernetes Threat Matrix**
heatmap, launch a new scan, and pull any report as JSON/markdown/SARIF over a small HTTP API.

Split so the routing is unit-testable without a socket:
    app.py    , WebApp.route(method, path, query, body) -> Response  (pure)
    pages.py  , HTML chrome (dashboard, matrix page, layout) reusing the report CSS
    server.py , the thin http.server wrapper + `k8smatrixwarden web` entry point
"""
from .app import Response, WebApp

__all__ = ["WebApp", "Response"]
