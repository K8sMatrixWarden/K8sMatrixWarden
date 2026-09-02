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

_VALID_FORMATS = {"json", "markdown", "md", "sarif", "html", "text", "terminal"}
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
            if method == "GET" and path == "/matrix":
                return self._coverage_matrix()
            if method == "GET" and path == "/compliance":
                return self._compliance(q)
            if method == "GET" and path == "/api/compliance":
                return self._api_compliance(q)
            if method == "GET" and path == "/federation":
                return self._federation()
            if method == "GET" and path == "/api/federation":
                return self._api_federation()
            if method == "GET" and parts[:1] == ["vendor"] and len(parts) == 2:
                return self._vendor_asset(parts[1])
            if method == "GET" and path == "/api/reports":
                return self._api_reports(q)
            if method == "GET" and path == "/api/dashboard":
                return _json(self._dashboard_data(q.get("scan_id")))
            if method == "GET" and path == "/api/timeline":
                return _json(self.store.timeline())
            if method == "GET" and path == "/api/finding":
                return self._api_finding(q)
            if method == "POST" and path == "/api/scan":
                return self._api_scan(body)
            if method == "POST" and path == "/api/runtime/refresh":
                return self._api_runtime_refresh(body)
            if method == "POST" and path == "/api/runtime":
                return self._api_runtime(body)
            # Read side of the same path. Method dispatch keeps ingestion untouched: a
            # falcosidekick POST and an operator GET never meet.
            if method == "GET" and path == "/api/runtime":
                return self._api_runtime_events(q)
            if method == "GET" and path == "/runtime":
                return self._runtime_page()
            # /report/<id>  and  /report/<id>/matrix
            if method == "GET" and len(parts) >= 2 and parts[0] == "report":
                if len(parts) == 2:
                    return self._report_html(parts[1])
                if len(parts) == 3 and parts[2] == "matrix":
                    return self._report_matrix_html(parts[1])
            # /api/report/<id>  and  /api/report/<id>/matrix
            if method == "GET" and len(parts) >= 3 and parts[:2] == ["api", "report"]:
                if len(parts) == 3:
                    return self._api_report(parts[2], q)
                if len(parts) == 4 and parts[3] == "matrix":
                    return self._api_report_matrix(parts[2])
        except _NotFound as exc:
            return self._not_found(str(exc), q)
        except Exception as exc:  # never leak a stack trace to the browser
            if _wants_json(path, q):
                return _json({"error": str(exc)}, 500)
            return _html(pages.error_page(500, f"Internal error: {exc}"), 500)

        return self._not_found(f"no route for {method} {path}", q)

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
            raise _NotFound(f"no such asset: {name}")
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", name)
        with open(path, "rb") as fh:
            return Response(200, "application/javascript; charset=utf-8", fh.read())

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
                     "warnings": scan_warning_lines(latest)},
            # Evidence coverage / assessment confidence (§5) and the score's own
            # contributor breakdown (§7). Both are computed server-side; the dashboard
            # renders them and never recomputes security logic in JavaScript.
            "coverage": latest.coverage,
            "risk_explanation": latest.risk.explanation,
            # What changed since the previous scan of this cluster (§16).
            "posture": self._posture(selected),
            "inventory": latest.inventory,
            "findings": [f.as_dict() for f in latest.findings],
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
            "timeline": self.store.timeline(),
            "history": [{"scan_id": r.scan_id, "name": r.name,
                         "display_name": r.display_name,
                         "generated_at": r.generated_at,
                         "rating": r.rating, "risk_score": r.risk_score,
                         "total": r.total, "scope": r.scope} for r in reports],
        }

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
            return _json({"error": f"invalid JSON body: {exc}"}, 400)
        from ..agents.runtime import RuntimeAgent, normalize_batch
        from ..core.correlation import correlate, detect_drift

        # Body can be {"events":[...], "scan_id"?} (our batch), OR a bare Falco event
        # posted by falcosidekick (one event per request). Normalize either into the
        # flat internal shape the matchers use.
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        raw = data.get("events") if (isinstance(data, dict) and "events" in data) else data
        events, rejected = normalize_batch(raw)
        result = self.store.resolve(scan_id)
        if result is None:
            return _json({"error": "no saved scan to correlate against, scan first"}, 400)
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
        return _json({"correlation": correlate(result.findings, alerts,
                                               cluster=result.cluster_name,
                                               now=ist_timestamp()),
                      "detection_coverage": detection_coverage,
                      "identity_coverage": identity_coverage,
                      "events_received": len(events) + len(rejected),
                      "drift": detect_drift(pods, events)})

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
            return _json({"error": "no such scan"}, 404)
        anchor = q.get("anchor") or ""
        f = next((x for x in result.findings
                  if finding_anchor(x.rule_id, x.resource.kind, x.resource.name,
                                    x.resource.namespace) == anchor), None)
        if f is None:
            return _json({"error": "finding not found"}, 404)
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
                      "explanation": explanation})

    def _api_runtime_events(self, q: dict) -> Response:
        """GET /api/runtime, the recent runtime events already stored on a scan.

        Read-only and additive: POST on this path still ingests. Nothing new is stored, the
        records are reshaped from the scan's own runtime block, so this view can never
        disagree with the report about what was observed.

        Query: `limit` (default 50), `source` (all|kmw|falco|audit|drift), `severity`
        (comma-separated), `namespace`, `since` (90s|15m|2h|7d|1w or seconds), `scan_id`.
        A malformed value is ignored and named in `warnings` rather than silently applied,
        because a filter that quietly does nothing hides events.
        """
        from ..core.runtime_events import (apply_filters, flatten, parse_since, summarize,
                                           SOURCES)
        result = self.store.resolve(q.get("scan_id"))
        if result is None:
            return _json({"error": "no saved scan yet, scan first"}, 400)

        warnings = []
        limit, raw_limit = 50, (q.get("limit") or "").strip()
        if raw_limit:
            if raw_limit.isdigit() and int(raw_limit) > 0:
                limit = min(int(raw_limit), 1000)
            else:
                warnings.append(f"ignored limit={raw_limit!r}, expected a positive integer")
        source = (q.get("source") or "all").strip().lower() or "all"
        if source not in SOURCES:
            warnings.append(f"ignored source={source!r}, expected one of "
                            f"{', '.join(SOURCES)}")
            source = "all"
        since_raw = (q.get("since") or "").strip()
        since_seconds = parse_since(since_raw)
        if since_raw and since_seconds is None:
            warnings.append(f"ignored since={since_raw!r}, expected e.g. 15m, 2h, 7d or "
                            f"a number of seconds")

        runtime = result.runtime or {}
        every = flatten(runtime, result.cluster_name)
        matched = apply_filters(every, source=source,
                                severity=(q.get("severity") or "").strip(),
                                namespace=(q.get("namespace") or "").strip(),
                                since_seconds=since_seconds)
        return _json({
            "scan_id": result.scan_id,
            "cluster": result.cluster_name,
            "collected_at": runtime.get("collected_at"),
            "feed_source": runtime.get("source"),
            # Totals before the limit, so a truncated page still says how much exists.
            "total": len(every),
            "matched": len(matched),
            "returned": min(limit, len(matched)),
            "limit": limit,
            "filters": {"source": source, "severity": (q.get("severity") or "").strip(),
                        "namespace": (q.get("namespace") or "").strip(),
                        "since": since_raw or None},
            "warnings": warnings,
            "summary": summarize(matched),
            "detection_coverage": runtime.get("detection_coverage"),
            "identity_coverage": runtime.get("identity_coverage"),
            "events": matched[:limit],
        })

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
            return _json({"error": f"invalid JSON body: {exc}"}, 400)
        result = self.store.resolve(data.get("scan_id") if isinstance(data, dict) else None)
        if result is None:
            return _json({"error": "no saved scan to correlate against, scan first"}, 400)
        ns = (result.runtime or {}).get("falco_namespace") or "falco"
        try:
            collector = self.p.make_collector(mock=False)
            feed = build_runtime_feed(collector, result.findings,
                                      Scope(ScopeLevel.CLUSTER), namespace=ns)
        except RuntimeError as exc:
            return _json({"error": f"live Falco pull needs cluster access: {exc}"}, 400)
        if feed is None:
            return _json({"runtime": None, "message": "no Falco events found",
                          "warnings": getattr(collector, "warnings", [])})
        result.runtime = feed
        self.store.save(result)
        return _json({"runtime": feed})

    def _report_html(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        return _html(self.p.reporting.render(result, "html"))

    def _report_matrix_html(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        tm = build_threat_matrix(result, self.p.registry.rules)
        return _html(pages.matrix_page(tm, result=result))

    def _coverage_matrix(self) -> Response:
        """The global 'what can the tool detect' matrix, every registered rule's coverage,
        no findings. Distinct from a scan matrix, which overlays this scan's hits."""
        empty = _empty_result(self.p)
        tm = build_threat_matrix(empty, self.p.registry.rules)
        note = (f"Detection coverage across all {self.p.rule_count()} registered rules")
        return _html(pages.matrix_page(tm, result=None, title_note=note))

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

    #: Binary export formats and their MIME types. These render to bytes (not str) and
    #: need the optional extra (`fpdf2` for pdf, `openpyxl` for xlsx); a missing dependency
    #: surfaces as a clean 400 rather than a 500.
    _BINARY_FORMATS = {
        "pdf": "application/pdf",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }

    def _api_report(self, scan_id: str, q: dict) -> Response:
        result = self._load(scan_id)
        fmt = (q.get("format") or "json").lower()
        if fmt == "excel":
            fmt = "xlsx"
        if fmt in self._BINARY_FORMATS:
            try:
                data = self.p.reporting.render(result, fmt)
            except RuntimeError as exc:      # optional dependency not installed
                return _json({"error": str(exc)}, 400)
            return Response(200, self._BINARY_FORMATS[fmt], data)
        if fmt not in _VALID_FORMATS:
            valid = sorted(_VALID_FORMATS | set(self._BINARY_FORMATS))
            return _json({"error": f"unknown format {fmt!r}, valid: {', '.join(valid)}"}, 400)
        content = self.p.reporting.render(result, fmt)
        if fmt == "json":
            return Response(200, "application/json; charset=utf-8",
                            content.encode("utf-8"))
        if fmt == "html":
            return _html(content)
        return _text(content)

    def _api_report_matrix(self, scan_id: str) -> Response:
        result = self._load(scan_id)
        return _json(build_threat_matrix(result, self.p.registry.rules).as_dict())

    # ------------------------------------------------------------------ #
    # Compliance audit, a standalone page like /matrix. Audits the mock target by
    # default; a live audit needs a kubeconfig context, so it runs from the CLI/MCP where
    # the target is explicit (the web live-scan path is separately kubeconfig-gated).
    # ------------------------------------------------------------------ #
    # Compliance audit tied to the scan the user is actually viewing. A saved scan carries
    # findings but not a CIS run, so this is a FINDINGS-DERIVED audit: a requirement fails
    # when a finding tagged with one of its CIS controls exists. It cannot show CIS PASS
    # states (nothing affirmatively ran the benchmark), so those requirements read
    # NOT_ASSESSED and the page says to run `k8smatrixwarden compliance` for the full audit.
    # Only when the store is empty do we fall back to a live/mock run for the demo.
    # ------------------------------------------------------------------ #
    def _run_compliance(self, q: dict):
        from ..frameworks.compliance import ComplianceEngine, run_audit, framework_keys
        fw = q.get("frameworks")
        frameworks = [f for f in fw.split(",") if f] if fw else None
        if frameworks:
            bad = [f for f in frameworks if f not in set(framework_keys())]
            if bad:
                raise _NotFound(f"unknown framework(s): {bad}")

        store = self.store
        if not store.list():
            # empty store, nothing scanned yet; run a mock audit so the page is not blank.
            return run_audit(self.p, mock=True, profile="auto", frameworks=frameworks), True
        result = self._load(q.get("scan_id"))       # selected scan, else latest
        rep = ComplianceEngine().evaluate(
            cis_results=[], findings=result.findings, frameworks=frameworks,
            scan_id=result.scan_id, cluster=result.cluster_name,
            generated_at=result.generated_at, profile=result.mode)
        return rep, False

    _CIS_NOTE = ("<div class='cf-note' style='border-left-color:var(--high)'>Derived from "
                 "the findings of scan <b>{sid}</b>. A requirement fails when a finding maps "
                 "to one of its CIS controls. CIS <b>pass</b> states are not shown here "
                 "(nothing re-ran the 130-control benchmark against this saved scan); run "
                 "<code>k8smatrixwarden compliance</code> for the full CIS-backed audit.</div>")

    def _compliance(self, q: dict) -> Response:
        from ..frameworks import compliance_report as cr
        report, is_mock = self._run_compliance(q)
        fmt = (q.get("format") or "html").lower()
        if fmt == "json":
            return _json(report.as_dict())
        if fmt == "pdf":
            try:
                return Response(200, "application/pdf", cr.to_pdf(report))
            except RuntimeError as exc:
                return _json({"error": str(exc)}, 400)
        note = "" if is_mock else self._CIS_NOTE.format(sid=_esc(report.scan_id or "N/A"))
        body = (pages._topbar("compliance")
                + cr.to_html(report, standalone=False).replace("</h1>", "</h1>" + note, 1))
        return _html(pages.layout("K8sMatrixWarden · Compliance Audit", body))

    def _api_compliance(self, q: dict) -> Response:
        return _json(self._run_compliance(q)[0].as_dict())

    # ------------------------------------------------------------------ #
    # Federation blast radius, correlates the newest saved scan of each cluster in the
    # store. Populate it by scanning each cluster (its own context) via /api/scan.
    # ------------------------------------------------------------------ #
    def _build_federation(self):
        from ..core.federation import build_federation, latest_per_cluster
        return build_federation(latest_per_cluster(self.store))

    def _federation(self) -> Response:
        from ..core import federation_report as fr
        body = pages._topbar("federation") + fr.to_html(self._build_federation(),
                                                         standalone=False)
        return _html(pages.layout("K8sMatrixWarden · Federation Blast Radius", body))

    def _api_federation(self) -> Response:
        return _json(self._build_federation().as_dict())

    def _api_scan(self, body: bytes) -> Response:
        if not self.allow_scan:
            return _json({"error": "scanning is disabled on this server "
                          "(started with --no-scan)"}, 403)
        try:
            data = json.loads(body or b"{}")
        except Exception as exc:
            return _json({"error": f"invalid JSON body: {exc}"}, 400)

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
                    kubeconfig=kubeconfig, context=data.get("context"))
            except RuntimeError as exc:
                return _json({"error": str(exc)}, 400)

            from ..agents.scanner import ScannerAgent
            request = ScanRequest(scope=scope, selector=selector, mode=ScanMode.SYNC)
            try:
                result = ScannerAgent(self.p).scan(
                    request, collector, mode_label="mock" if mock else "live",
                    name=scan_name)
            except Exception as exc:
                return _json({"error": f"scan failed: {exc}"}, 400)
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
                      "report_url": f"/report/{result.scan_id}",
                      "matrix_url": f"/report/{result.scan_id}/matrix"})

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
            raise _NotFound(f"no stored report with scan-id {scan_id!r}")
        if result is None:
            raise _NotFound("no stored reports yet, run a scan first")
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
