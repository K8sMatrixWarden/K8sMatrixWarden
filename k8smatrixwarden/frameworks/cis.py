"""
CIS Benchmark Engine (§5.9), full 130-control coverage with API-side mitigation.

Gives EVERY control a status so nothing is missed:

  PASS      , evaluated and compliant
  FAIL      , evaluated and non-compliant (offending resources attached)
  MANUAL    , CIS marks it Manual; needs human review
  NA        , not applicable on this provider profile (managed control plane)
  NEEDS_NODE, requires on-node file read; supply kube-bench JSON to resolve
  NOT_ASSESSED, the evidence this control needs could not be read, so there is no
              verdict. Never collapsed into PASS: an unreadable cluster produces the
              same empty finding set as a clean one, and only this status tells them
              apart for the frameworks built on top.

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
#: The evidence this control needs could not be read, so the control has NO verdict. This is
#: distinct from every other status and must never be folded into one of them: NA means the
#: control does not apply, MANUAL means no automated check exists, NEEDS_NODE means the
#: check exists but needs on-node data, and PASS means we looked and found compliance.
#: Without this status a forbidden or unreachable cluster produced "no violations detected"
#: for every rule-backed control, which propagated to SOC 2 / ISO / NIST / PCI as a 100%
#: pass rate on a cluster nothing had been read from.
NOT_ASSESSED = "NOT_ASSESSED"
_ALL_STATUSES = (PASS, FAIL, MANUAL, NA, NEEDS_NODE, NOT_ASSESSED)
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

        # 3) Evaluate every control. `unreadable` is what separates "we looked and found
        # nothing wrong" from "we could not look", which are the same empty result set.
        unreadable = _unreadable_kinds(collector)
        results = [self._evaluate(c, fired, ev, cfg_flags, kb, profile, unreadable)
                   for c in CIS_1_8]
        return self._summarize(results, profile)

    # ------------------------------------------------------------------ #
    def _evaluate(self, c: CisControl, fired, ev, cfg_flags, kb, profile,
                  unreadable: Optional[set] = None) -> ControlResult:
        # Layer 4, managed provider: control-plane sections are provider-owned → N/A.
        if profile in MANAGED_PROFILES and c.section in CONTROL_PLANE_SECTIONS:
            return ControlResult(c, NA, f"provider-managed control plane ({profile})")

        if c.ev == "native":
            hits = [r for rid in c.rules for r in fired.get(rid, [])]
            if hits:
                return ControlResult(c, FAIL, f"{len(hits)} non-compliant resource(s)",
                                     sorted(set(hits))[:10])
            # No rule fired. That means compliance only if the rules could actually see the
            # resources they judge; if every kind they need was unreadable, the empty result
            # is an artefact of the failed read, not a clean cluster.
            missing = self._unverifiable(c, unreadable)
            if missing:
                return ControlResult(c, NOT_ASSESSED,
                                     f"evidence unavailable: could not read "
                                     f"{', '.join(sorted(missing))}")
            return ControlResult(c, PASS, "no violations detected")

        if c.ev == "builtin":
            missing = self._unverifiable(c, unreadable, _BUILTIN_KINDS)
            if missing:
                return ControlResult(c, NOT_ASSESSED,
                                     f"evidence unavailable: could not read "
                                     f"{', '.join(sorted(missing))}")
            return self._builtin(c, ev)

        if c.ev == "component":
            return self._component(c, cfg_flags)

        if c.ev == "kube-bench":
            if c.id in kb:
                return ControlResult(c, _map_kb(kb[c.id]), f"kube-bench: {kb[c.id]}")
            return ControlResult(c, NEEDS_NODE,
                                 "requires node file inspection (supply kube-bench JSON)")

        return ControlResult(c, MANUAL, "requires manual review")

    def _unverifiable(self, c: CisControl, unreadable, fallback_kinds=None) -> set:
        """Which kinds this control depends on could not be read.

        ANY unreadable kind is enough to withhold a PASS. A control asserting "no privileged
        containers" cannot be satisfied by inspecting Pods when Deployments were forbidden,
        the violation could be sitting in the half that was never fetched. Requiring every
        kind to fail before withholding the pass would let a single readable kind vouch for
        all the others.

        FAIL is decided before this runs, so partial evidence still reports the violations it
        did find; only the clean verdict needs full sight. Returns empty when the needed kinds
        cannot be determined, since inventing NOT_ASSESSED would be its own false claim."""
        if not unreadable:
            return set()
        needed = set(fallback_kinds or ())
        for rid in c.rules:
            rule = self.p.registry.rules.get(rid)
            if rule:
                needed.update(rule.evidence_needs or rule.resource_scope or ())
        return needed & set(unreadable)

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
#: Kinds the two builtin evaluators (hostPort, default-namespace usage) reason about. They
#: read workloads directly rather than through a rule, so they have no rule to inherit
#: evidence needs from.
_BUILTIN_KINDS = frozenset({"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job",
                            "CronJob", "ReplicaSet"})


def _unreadable_kinds(collector) -> set:
    """Resource kinds the collector could not read at all this run.

    `skipped` is the collector's own word for a read that failed (RBAC forbidden, API group
    absent, cluster unreachable). A kind that read successfully but returned zero items is
    `ok`, and an empty cluster is a real answer, so the two must not be confused."""
    cov = getattr(collector, "coverage", {}) or {}
    return {k for k, i in cov.items() if (i or {}).get("status") == "skipped"}


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
_EMOJI = {PASS: "✅", FAIL: "❌", MANUAL: "🔶", NA: "➖", NEEDS_NODE: "⚙️",
          NOT_ASSESSED: "❔"}


def render_text(report: CISReport, show: str = "fail") -> str:
    c = report.counts
    lines = [
        "═" * 78,
        f"  {report.title}  ({report.version})   profile: {report.profile}",
        "═" * 78,
        f"  Total controls : {len(report.results)}",
        f"  ✅ PASS {c[PASS]:<4}❌ FAIL {c[FAIL]:<4}🔶 MANUAL {c[MANUAL]:<4}"
        f"➖ NA {c[NA]:<4}⚙️  NEEDS_NODE {c[NEEDS_NODE]:<4}"
        f"❔ NOT_ASSESSED {c[NOT_ASSESSED]:<4}",
        f"  Automated pass rate : {report.pass_pct}%   "
        f"(auto-evaluated coverage of applicable controls: {report.auto_coverage_pct}%)",
        "-" * 78,
        "  Per section:",
    ]
    for sec in sorted(report.by_section):
        d = report.by_section[sec]
        lines.append(f"    §{sec} {d['name']:<30} ✅{d[PASS]:<3}❌{d[FAIL]:<3}"
                     f"🔶{d[MANUAL]:<3}➖{d[NA]:<3}⚙️{d[NEEDS_NODE]:<3}"
                     f"❔{d[NOT_ASSESSED]:<3}")
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
           f"| ❔ NOT_ASSESSED (evidence unavailable) | {c[NOT_ASSESSED]} |",
           "", "## Per section", "",
           "| § | Section | ✅ | ❌ | 🔶 | ➖ | ⚙️ | ❔ | Total |",
           "|---|---|---|---|---|---|---|---|---|"]
    for sec in sorted(report.by_section):
        d = report.by_section[sec]
        out.append(f"| {sec} | {d['name']} | {d[PASS]} | {d[FAIL]} | {d[MANUAL]} "
                   f"| {d[NA]} | {d[NEEDS_NODE]} | {d[NOT_ASSESSED]} | {d['total']} |")
    out += ["", "## Failed controls", ""]
    fails = [r for r in report.results if r.status == FAIL]
    if not fails:
        out.append("_None_ ✅")
    for r in fails:
        tail = (f", {', '.join(r.resources[:5])}" if r.resources
                else (f", {r.detail}" if r.detail else ""))
        out.append(f"- ❌ **[{r.control.id}]** {r.control.title}{tail}")
    return "\n".join(out)
