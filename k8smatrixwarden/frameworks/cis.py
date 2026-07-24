"""
CIS Benchmark Engine (§5.9), full 130-control coverage with API-side mitigation.

Gives EVERY control a status so nothing is missed:

  PASS      , evaluated and compliant
  FAIL      , evaluated and non-compliant (offending resources attached)
  MANUAL    , CIS marks it Manual; needs human review
  NA        , not applicable on this provider profile (managed control plane)
  NEEDS_NODE, requires on-node file read; supply kube-bench JSON to resolve

Evaluation methods (see cis_catalog):
  native   , run the mapped domain-shard rules once over cluster evidence (rule fired ⇒ FAIL)
  builtin  , purpose-built evaluator here
  component, read a control-plane / kubelet PROCESS FLAG from ComponentConfig evidence
              (Mitigation Layer 1/2: parsed from kube-system static-pod specs + kubelet config)
  kube-bench, node FILE permission read; resolved from kube-bench JSON, else NEEDS_NODE
  manual   , surfaced for human review

Provider profiles (Mitigation Layer 4): on eks/gke/aks the managed control plane (sections
1–3) cannot and should not be graded → those controls are marked NA rather than NEEDS_NODE.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from ..core.evidence import Evidence, EvidenceCollector
from ..core.models import Scope, ScopeLevel
from .cis_catalog import (BENCHMARK_TITLE, BENCHMARK_VERSION, CIS_1_8,
                          CONTROL_PLANE_SECTIONS, SECTION_NAMES, CisControl)

PASS, FAIL, MANUAL, NA, NEEDS_NODE = "PASS", "FAIL", "MANUAL", "NA", "NEEDS_NODE"
_ALL_STATUSES = (PASS, FAIL, MANUAL, NA, NEEDS_NODE)
MANAGED_PROFILES = {"eks", "gke", "aks"}


@dataclass
class ControlResult:
    control: CisControl
    status: str
    detail: str = ""
    resources: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"id": self.control.id, "title": self.control.title,
                "section": self.control.section, "type": self.control.type,
                "evaluation": self.control.ev, "status": self.status,
                "detail": self.detail, "resources": self.resources}


@dataclass
class CISReport:
    version: str
    title: str
    profile: str
    results: list
    counts: dict
    by_section: dict
    pass_pct: int
    auto_coverage_pct: int

    def as_dict(self) -> dict:
        return {"benchmark": self.title, "version": self.version, "profile": self.profile,
                "total_controls": len(self.results), "counts": self.counts,
                "pass_pct": self.pass_pct, "auto_coverage_pct": self.auto_coverage_pct,
                "by_section": self.by_section,
                "controls": [r.as_dict() for r in self.results]}


class CISBenchmarkEngine:
    def __init__(self, platform):
        self.p = platform

    def evaluate(self, collector: EvidenceCollector,
                 kube_bench_results: Optional[dict] = None,
                 profile: str = "self-managed") -> CISReport:
        kb = kube_bench_results or {}
        profile = (profile or "self-managed").lower()

        # 1) Run every referenced native rule ONCE over cluster-wide evidence.
        native_rule_ids = sorted({rid for c in CIS_1_8 for rid in c.rules})
        findings = self.p.detection.run(native_rule_ids, collector,
                                        Scope(ScopeLevel.CLUSTER))
        fired: dict[str, list] = {}
        for f in findings:
            if f.severity.weight > 0:
                fired.setdefault(f.rule_id, []).append(str(f.resource))

        # 2) Shared evidence for builtin + component evaluators.
        ev = collector.collect(
            {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ComponentConfig"},
            Scope(ScopeLevel.CLUSTER))
        cfg_flags = _component_flags(ev)

        # 3) Evaluate every control.
        results = [self._evaluate(c, fired, ev, cfg_flags, kb, profile) for c in CIS_1_8]
        return self._summarize(results, profile)

    # ------------------------------------------------------------------ #
    def _evaluate(self, c: CisControl, fired, ev, cfg_flags, kb, profile) -> ControlResult:
        # Layer 4, managed provider: control-plane sections are provider-owned → N/A.
        if profile in MANAGED_PROFILES and c.section in CONTROL_PLANE_SECTIONS:
            return ControlResult(c, NA, f"provider-managed control plane ({profile})")

        if c.ev == "native":
            hits = [r for rid in c.rules for r in fired.get(rid, [])]
            if hits:
                return ControlResult(c, FAIL, f"{len(hits)} non-compliant resource(s)",
                                     sorted(set(hits))[:10])
            return ControlResult(c, PASS, "no violations detected")

        if c.ev == "builtin":
            return self._builtin(c, ev)

        if c.ev == "component":
            return self._component(c, cfg_flags)

        if c.ev == "kube-bench":
            if c.id in kb:
                return ControlResult(c, _map_kb(kb[c.id]), f"kube-bench: {kb[c.id]}")
            return ControlResult(c, NEEDS_NODE,
                                 "requires node file inspection (supply kube-bench JSON)")

        return ControlResult(c, MANUAL, "requires manual review")

    # -- component flag evaluation (Mitigation Layer 1/2) ----------------- #
    def _component(self, c: CisControl, cfg_flags: dict) -> ControlResult:
        component, flag, op, value = c.check
        flags = cfg_flags.get(component)
        if flags is None:
            # We could not read this component's config (e.g. no static-pod access).
            return ControlResult(c, NEEDS_NODE,
                                 f"{component} config not readable from the API")
        val = flags.get(flag)
        ok = _eval_flag(op, val, value)
        if ok:
            return ControlResult(c, PASS, f"{flag}={_show(val)}")
        return ControlResult(c, FAIL, f"{component} --{flag}={_show(val)} (op {op} "
                             f"{value})".rstrip())

    def _builtin(self, c: CisControl, ev: Evidence) -> ControlResult:
        if c.id == "5.2.13":       # HostPorts
            off = [str(_ref(r)) for r in _workloads(ev)
                   for cont in Evidence.containers(r)
                   for port in (cont.get("ports", []) or []) if port.get("hostPort")]
            return (ControlResult(c, FAIL, "containers use hostPort", sorted(set(off))[:10])
                    if off else ControlResult(c, PASS, "no hostPort usage"))
        if c.id == "5.7.4":        # default namespace should not be used
            off = [str(_ref(r)) for r in _workloads(ev)
                   if (r.get("metadata", {}) or {}).get("namespace") == "default"]
            return (ControlResult(c, FAIL, "workloads in default namespace",
                                  sorted(set(off))[:10])
                    if off else ControlResult(c, PASS, "default namespace unused"))
        return ControlResult(c, MANUAL, "no builtin evaluator")

    # ------------------------------------------------------------------ #
    def _summarize(self, results, profile) -> CISReport:
        counts = Counter(r.status for r in results)
        counts = {s: counts.get(s, 0) for s in _ALL_STATUSES}
        evaluated = counts[PASS] + counts[FAIL]
        applicable = len(results) - counts[NA]
        pass_pct = round(100 * counts[PASS] / evaluated) if evaluated else 0
        auto_cov = round(100 * evaluated / applicable) if applicable else 0

        by_section: dict[str, dict] = {}
        for r in results:
            d = by_section.setdefault(r.control.section,
                                      {"name": SECTION_NAMES.get(r.control.section),
                                       **{s: 0 for s in _ALL_STATUSES}, "total": 0})
            d[r.status] += 1
            d["total"] += 1
        return CISReport(BENCHMARK_VERSION, BENCHMARK_TITLE, profile, results, counts,
                         by_section, pass_pct, auto_cov)


# ----------------------------------------------------------------------- #
def _component_flags(ev: Evidence) -> dict:
    """Extract per-component flag dicts from the ComponentConfig evidence."""
    items = ev.get("ComponentConfig", all_scopes=True)
    if not items:
        return {}
    spec = items[0].get("spec", {}) or {}
    out = {}
    for comp in ("apiServer", "controllerManager", "scheduler", "etcd", "kubelet"):
        c = spec.get(comp)
        if isinstance(c, dict) and isinstance(c.get("flags"), dict):
            out[comp] = c["flags"]
    return out


def _eval_flag(op: str, val, value: str) -> bool:
    present = val is not None and val != ""
    lst = _split(val)
    if op == "set":
        return present
    if op == "unset":
        return not present
    if op == "eq":
        return present and str(val).lower() == str(value).lower()
    if op == "contains":
        return value in lst
    if op == "not_contains":
        return present and value not in lst
    if op == "admission_has":
        return value in lst
    if op == "admission_not":
        return value not in lst        # absent list ⇒ compliant (default state)
    if op == "not_true":
        return str(val).lower() != "true"
    if op == "not_false":
        return str(val).lower() != "false"
    if op == "not_zero":
        return str(val) != "0"
    if op == "feature_true":
        return (val is None) or (f"{value}=true" in str(val))
    return False


def _split(val) -> list:
    if not val:
        return []
    return [x.strip() for x in str(val).split(",") if x.strip()]


def _show(val) -> str:
    return "<unset>" if (val is None or val == "") else str(val)


def _workloads(ev: Evidence):
    for kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet"):
        yield from ev.get(kind)


def _ref(res):
    from ..core.models import ResourceRef
    meta = res.get("metadata", {}) or {}
    return ResourceRef(res.get("kind", "Pod"), meta.get("name", ""), meta.get("namespace"))


def _map_kb(kb_status: str) -> str:
    s = str(kb_status).upper()
    return {"PASS": PASS, "FAIL": FAIL, "WARN": MANUAL, "INFO": MANUAL}.get(s, NEEDS_NODE)


# ----------------------------------------------------------------------- #
_EMOJI = {PASS: "✅", FAIL: "❌", MANUAL: "🔶", NA: "➖", NEEDS_NODE: "⚙️"}


def render_text(report: CISReport, show: str = "fail") -> str:
    c = report.counts
    lines = [
        "═" * 78,
        f"  {report.title}  ({report.version})   profile: {report.profile}",
        "═" * 78,
        f"  Total controls : {len(report.results)}",
        f"  ✅ PASS {c[PASS]:<4}❌ FAIL {c[FAIL]:<4}🔶 MANUAL {c[MANUAL]:<4}"
        f"➖ NA {c[NA]:<4}⚙️  NEEDS_NODE {c[NEEDS_NODE]:<4}",
        f"  Automated pass rate : {report.pass_pct}%   "
        f"(auto-evaluated coverage of applicable controls: {report.auto_coverage_pct}%)",
        "-" * 78,
        "  Per section:",
    ]
    for sec in sorted(report.by_section):
        d = report.by_section[sec]
        lines.append(f"    §{sec} {d['name']:<30} ✅{d[PASS]:<3}❌{d[FAIL]:<3}"
                     f"🔶{d[MANUAL]:<3}➖{d[NA]:<3}⚙️{d[NEEDS_NODE]:<3}")
    if show in ("fail", "all"):
        lines += ["-" * 78, "  Failed controls:"]
        fails = [r for r in report.results if r.status == FAIL]
        if not fails:
            lines.append("    (none) ✅")
        for r in fails:
            lines.append(f"    ❌ [{r.control.id}] {r.control.title}")
            if r.resources:
                lines.append(f"         → {', '.join(r.resources[:5])}"
                             + (" …" if len(r.resources) > 5 else ""))
            elif r.detail:
                lines.append(f"         → {r.detail}")
    if show == "all":
        lines += ["-" * 78, "  Manual / node-dependent controls:"]
        for r in report.results:
            if r.status in (MANUAL, NEEDS_NODE, NA):
                lines.append(f"    {_EMOJI[r.status]} [{r.control.id}] {r.control.title}")
    lines.append("═" * 78)
    return "\n".join(lines)


def render_markdown(report: CISReport) -> str:
    c = report.counts
    out = [f"# 📋 {report.title}, Compliance Report",
           "",
           f"**Profile:** {report.profile}  |  **Controls:** {len(report.results)}  |  "
           f"**Automated pass rate:** {report.pass_pct}%  |  "
           f"**Auto-evaluated coverage:** {report.auto_coverage_pct}%",
           "",
           "| Status | Count |", "|---|---|",
           f"| ✅ PASS | {c[PASS]} |", f"| ❌ FAIL | {c[FAIL]} |",
           f"| 🔶 MANUAL | {c[MANUAL]} |", f"| ➖ NA (provider-managed) | {c[NA]} |",
           f"| ⚙️ NEEDS_NODE (kube-bench) | {c[NEEDS_NODE]} |",
           "", "## Per section", "",
           "| § | Section | ✅ | ❌ | 🔶 | ➖ | ⚙️ | Total |",
           "|---|---|---|---|---|---|---|---|"]
    for sec in sorted(report.by_section):
        d = report.by_section[sec]
        out.append(f"| {sec} | {d['name']} | {d[PASS]} | {d[FAIL]} | {d[MANUAL]} "
                   f"| {d[NA]} | {d[NEEDS_NODE]} | {d['total']} |")
    out += ["", "## Failed controls", ""]
    fails = [r for r in report.results if r.status == FAIL]
    if not fails:
        out.append("_None_ ✅")
    for r in fails:
        tail = (f", {', '.join(r.resources[:5])}" if r.resources
                else (f", {r.detail}" if r.detail else ""))
        out.append(f"- ❌ **[{r.control.id}]** {r.control.title}{tail}")
    return "\n".join(out)
