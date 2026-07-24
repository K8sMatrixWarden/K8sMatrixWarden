"""
Compliance crosswalk engine, maps K8sMatrixWarden's existing checks onto governance
frameworks (PCI DSS, SOC 2, ISO 27001, NIST 800-53) so a security engineer can hand an
auditor a per-requirement pass/fail/evidence report instead of a technical finding dump.

Design: it invents no new detections. Each framework requirement is crosswalked (in
taxonomy/compliance_crosswalk.json) to CIS Kubernetes Benchmark v1.8 control ids, which
the CIS engine already grades, and/or OWASP Kubernetes Top 10 codes, which every finding
already self-declares. This engine joins those two sources and, crucially, NEVER reports a
requirement as passing when it has no affirmative evidence: a requirement whose only signal
is an OWASP code with no matching finding is `NOT_ASSESSED`, not PASS, because the scanner
did not actively verify it (an absent finding only means "no violation seen", not "checked").
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from ..core.models import Finding
from ..frameworks.cis_catalog import CIS_1_8

# Per-requirement status. Only a failing CIS control (or a finding tagged with a mapped CIS
# control) FAILs a requirement, a loose OWASP-category match is a related INDICATOR, never a
# formal control failure. PARTIAL = an assessable CIS control still needs node evidence
# (kube-bench); MANUAL = mapped controls are human-judgement only; NEEDS_REVIEW = a related
# finding exists (by OWASP category) but this requirement has no formal automated control
# here, a lead to review, not a pass or a fail; NOT_ASSESSED = no signal at all (honest gap,
# never a silent pass).
PASS, FAIL, PARTIAL, MANUAL, NEEDS_REVIEW, NOT_ASSESSED = (
    "PASS", "FAIL", "PARTIAL", "MANUAL", "NEEDS_REVIEW", "NOT_ASSESSED")
_ALL_STATUSES = (PASS, FAIL, PARTIAL, MANUAL, NEEDS_REVIEW, NOT_ASSESSED)

_CIS_TITLES = {c.id: c.title for c in CIS_1_8}


def _crosswalk_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "taxonomy", "compliance_crosswalk.json")


_CROSSWALK: Optional[dict] = None


def load_crosswalk() -> dict:
    global _CROSSWALK
    if _CROSSWALK is None:
        with open(_crosswalk_path(), encoding="utf-8") as fh:
            _CROSSWALK = json.load(fh)
    return _CROSSWALK


def framework_keys() -> list[str]:
    return list(load_crosswalk()["frameworks"].keys())


@dataclass
class RequirementResult:
    id: str
    title: str
    status: str
    cis_controls: list                    # [{id, title, status}]
    owasp: list                           # [K03, ...]
    blocking_findings: list               # list[Finding]
    detail: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "status": self.status,
                "cis_controls": self.cis_controls, "owasp": self.owasp,
                "detail": self.detail,
                "blocking_findings": [
                    {"rule_id": f.rule_id, "title": f.title,
                     "severity": f.severity.label, "resource": str(f.resource),
                     "owasp": f.owasp, "cis": f.cis}
                    for f in self.blocking_findings]}


@dataclass
class FrameworkResult:
    key: str
    name: str
    short: str
    url: str
    scope_note: str
    requirements: list                    # list[RequirementResult]
    counts: dict = field(default_factory=dict)
    pass_pct: int = 0
    blocking_findings: int = 0            # distinct findings blocking any FAIL
    attestation: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "short": self.short,
                "url": self.url, "scope_note": self.scope_note,
                "counts": self.counts, "pass_pct": self.pass_pct,
                "total_requirements": len(self.requirements),
                "blocking_findings": self.blocking_findings,
                "attestation": self.attestation,
                "requirements": [r.as_dict() for r in self.requirements]}


@dataclass
class ComplianceReport:
    frameworks: list                      # list[FrameworkResult]
    scan_id: str = ""
    cluster: str = ""
    generated_at: str = ""
    profile: str = ""

    def as_dict(self) -> dict:
        return {"scan_id": self.scan_id, "cluster": self.cluster,
                "generated_at": self.generated_at, "profile": self.profile,
                "frameworks": [f.as_dict() for f in self.frameworks]}


class ComplianceEngine:
    """Join a CIS report (per-control status) + a scan's findings to framework requirements.

    Pure and side-effect free: the caller runs the CIS benchmark and the scan, then hands
    both in. That keeps the engine unit-testable without a cluster.
    """

    def evaluate(self, *, cis_results: list, findings: list,
                 frameworks: Optional[list] = None,
                 scan_id: str = "", cluster: str = "",
                 generated_at: str = "", profile: str = "") -> ComplianceReport:
        cw = load_crosswalk()["frameworks"]
        keys = frameworks or list(cw.keys())
        # index CIS status by control id; only weight-bearing findings can block.
        cis_status = {r.control.id: r.status for r in cis_results}
        live = [f for f in findings if f.severity.weight > 0]

        out = []
        for key in keys:
            spec = cw.get(key)
            if not spec:
                continue
            reqs = [self._req(r, cis_status, live) for r in spec["requirements"]]
            counts = {s: 0 for s in _ALL_STATUSES}
            for r in reqs:
                counts[r.status] += 1
            assessed = counts[PASS] + counts[FAIL] + counts[PARTIAL]
            pass_pct = round(100 * counts[PASS] / assessed) if assessed else 0
            blockers = {(f.rule_id, str(f.resource))
                        for r in reqs if r.status == FAIL for f in r.blocking_findings}
            out.append(FrameworkResult(
                key=key, name=spec["name"], short=spec.get("short", key),
                url=spec.get("url", ""), scope_note=spec.get("scope_note", ""),
                requirements=reqs, counts=counts, pass_pct=pass_pct,
                blocking_findings=len(blockers),
                attestation=self._attestation(spec.get("short", key), counts, len(blockers))))
        return ComplianceReport(frameworks=out, scan_id=scan_id, cluster=cluster,
                                generated_at=generated_at, profile=profile)

    # ------------------------------------------------------------------ #
    def _req(self, spec: dict, cis_status: dict, live: list) -> RequirementResult:
        cis_ids = spec.get("cis", [])
        owasp = spec.get("owasp", [])
        # CIS controls mapped to this requirement, with the status they got this run.
        mapped = [{"id": cid, "title": _CIS_TITLES.get(cid, cid),
                   "status": cis_status.get(cid, NOT_ASSESSED)} for cid in cis_ids]
        statuses = {m["status"] for m in mapped}
        # Only a finding tagged with a MAPPED CIS control fails the requirement. A finding
        # that merely shares the OWASP category is a related indicator, not a control failure
        #, counting it as FAIL produced a 0%-pass-everywhere readout an auditor dismisses.
        blocking = [f for f in live if set(f.cis) & set(cis_ids)]
        indicators = [f for f in live
                      if f.owasp and f.owasp in owasp and not (set(f.cis) & set(cis_ids))]

        if blocking or FAIL in statuses:
            status = FAIL
        elif "NEEDS_NODE" in statuses:
            status = PARTIAL
        elif PASS in statuses:
            status = PASS
        elif statuses and statuses <= {"MANUAL", "NA"}:
            status = MANUAL
        elif indicators:
            # A related finding exists but no formal control here, a lead to review, not a
            # pass and not a formal fail.
            status = NEEDS_REVIEW
        else:
            status = NOT_ASSESSED

        shown = blocking if status == FAIL else (indicators if status == NEEDS_REVIEW else [])
        detail = self._detail(status, mapped, shown, owasp)
        return RequirementResult(id=spec["id"], title=spec["title"], status=status,
                                 cis_controls=mapped, owasp=owasp,
                                 blocking_findings=sorted(shown,
                                     key=lambda f: -f.severity.weight),
                                 detail=detail)

    @staticmethod
    def _detail(status, mapped, blocking, owasp) -> str:
        if status == FAIL:
            n = len(blocking)
            if n:
                worst = max((f.severity.label for f in blocking),
                            key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2,
                                           "LOW": 1}.get(s, 0))
                return f"{n} live finding(s) violate this control (worst: {worst})."
            fails = [m["id"] for m in mapped if m["status"] == FAIL]
            return f"CIS control(s) failing: {', '.join(fails)}."
        if status == PARTIAL:
            nn = [m["id"] for m in mapped if m["status"] == "NEEDS_NODE"]
            return f"Needs on-node evidence (kube-bench) for CIS {', '.join(nn)}."
        if status == PASS:
            ok = [m["id"] for m in mapped if m["status"] == PASS]
            return f"CIS control(s) passing: {', '.join(ok)}; no violating findings."
        if status == MANUAL:
            return "Mapped CIS control(s) require manual review, no automated verdict."
        if status == NEEDS_REVIEW:
            n = len(blocking)   # here `blocking` is the indicator list passed in by _req
            return (f"{n} related finding(s) (OWASP {', '.join(owasp)}), no formal automated "
                    f"control for this requirement here; review as a lead before assessment.")
        return (f"No automated check for this requirement (mapped to OWASP "
                f"{', '.join(owasp)} only). Requires manual attestation.")

    @staticmethod
    def _attestation(short: str, counts: dict, blockers: int) -> str:
        # This is automated posture evidence for the assessed subset, NOT a pass/fail
        # attestation (formal attestation needs a qualified assessor + out-of-scope controls).
        if counts[FAIL]:
            return (f"{counts[FAIL]} {short} requirement(s) fail on automated checks, "
                    f"{blockers} finding(s) to remediate before assessment.")
        pend = counts[PARTIAL] + counts[MANUAL] + counts[NEEDS_REVIEW] + counts[NOT_ASSESSED]
        if pend:
            return (f"No assessed {short} control fails on automated checks; {pend} "
                    f"requirement(s) still need manual review or node evidence.")
        return f"All assessed {short} requirements pass."


def run_audit(platform, *, mock: bool = True, fixture=None, kubeconfig=None,
              context=None, profile: str = "auto", frameworks: Optional[list] = None,
              kube_bench_json=None) -> ComplianceReport:
    """One-call facade: run a cluster scan + the CIS benchmark once, then map both onto the
    requested frameworks. Shared by the MCP tool, the web route and the CLI so the
    scan→CIS→crosswalk pipeline is defined in exactly one place."""
    from ..agents.scanner import ScannerAgent
    from ..core.models import ScanRequest, ScanMode, Scope, ScopeLevel, Selector
    from ..core.evidence import detect_provider
    from .cis import CISBenchmarkEngine
    from .kube_bench_adapter import maybe_load

    collector = platform.make_collector(mock=mock, fixture=fixture,
                                        kubeconfig=kubeconfig, context=context)
    if profile == "auto":
        ev = collector.collect({"Node"}, Scope(ScopeLevel.CLUSTER))
        profile = detect_provider(ev.get("Node", all_scopes=True))["profile"]

    req = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                      mode=ScanMode.SYNC)
    result = ScannerAgent(platform).scan(req, collector,
                                         mode_label="mock" if mock else "live")
    cis = CISBenchmarkEngine(platform).evaluate(
        collector, kube_bench_results=maybe_load(kube_bench_json), profile=profile)
    return ComplianceEngine().evaluate(
        cis_results=cis.results, findings=result.findings, frameworks=frameworks,
        scan_id=result.scan_id, cluster=result.cluster_name,
        generated_at=result.generated_at, profile=profile)
