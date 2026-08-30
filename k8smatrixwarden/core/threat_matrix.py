"""
Threat Matrix (§3.3, §12), projects a scan's findings onto the Kubernetes Threat Matrix.

This is the "one matrix per scan" view: the 9 tactics of the Microsoft/Redguard Kubernetes
Threat Matrix (https://kubernetes-threat-matrix.redguard.ch/) laid out as columns, each with
its techniques as cells, and every cell painted by orthogonal states that already live in
the platform:

    reference, the technique exists in the Redguard matrix (the full attacker playbook)
    covered  , a scan Rule can detect it (from the registry)
    runtime  , no scan rule, but a Runtime Agent detection covers it (Falco/audit/drift)
    hit      , this scan actually produced a finding on it (from the ScanResult)

`runtime` is a distinct state, not folded into `covered`, because the two answer different
questions: a scan rule says "the configuration allows this", a runtime detection says "this
is happening right now". Several Redguard techniques (a shell spawned in a container, a
miner starting) are structurally invisible to a config snapshot and can ONLY be covered at
runtime, showing them as flat gaps understated real coverage.

Keying prefers an exact Redguard technique NAME, then falls back to the canonical
ATT&CK-for-Containers id (the mapping contract, §6.2). Name-first matters because the
Redguard matrix is finer-grained than ATT&CK: "Access the K8s API server", "Access Kubelet
API" and "Access Kubernetes dashboard" are three distinct techniques all carrying the
single id T1613, so id-first matching collapsed them into one cell and painted the other
two as gaps even where rules existed. Redguard techniques with no stable id, or whose id
already appears in the same tactic, are name-keyed cells, so a technique with no rule
renders as an un-covered cell rather than being silently dropped. Nothing here re-derives
severity or scoring; it reads the Findings the Scanner already produced.

The output is a plain, JSON-serialisable structure (`ThreatMatrix.as_dict()`), so it is
equally consumable by the markdown/HTML reporters, the web dashboard heatmap, and the MCP
`build_threat_matrix` tool, one matrix, many surfaces.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .finding_context import mitre_technique_url
from .models import Finding, Severity, Tactic
from .registry import RuleRegistry
from .results import ScanResult

REDGUARD_MATRIX_URL = "https://kubernetes-threat-matrix.redguard.ch/"

# The 9 tactics, in kill-chain order (§12.1). This is the column order of every rendered
# matrix; `Tactic` (core.models) is the enum, this list just pins presentation order.
TACTIC_ORDER: list[Tactic] = [
    Tactic.INITIAL_ACCESS, Tactic.EXECUTION, Tactic.PERSISTENCE,
    Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION, Tactic.CREDENTIAL_ACCESS,
    Tactic.DISCOVERY, Tactic.LATERAL_MOVEMENT, Tactic.IMPACT,
]

# The Redguard/Microsoft Kubernetes Threat Matrix techniques per tactic (§12.1), as
# (display_name, attack_for_containers_id_or_None). The id is filled only where the
# canonical ATT&CK-for-Containers technique is unambiguous AND not already used earlier in
# the same tactic (a duplicate id in one column is dropped to None so the two distinct
# Redguard techniques stay as separate cells). Techniques with no stable ATT&CK id keep
# None, they are real attacker behaviours the matrix must still show, just not id-keyed.
REDGUARD_TECHNIQUES: dict[str, list[tuple[str, Optional[str]]]] = {
    "Initial Access": [
        ("Using cloud credentials", "T1078.004"),
        ("Compromised images in registry", "T1525"),
        ("Kubeconfig file", "T1552"),
        ("Application vulnerability", None),
        ("Exposed sensitive interfaces", "T1133"),
    ],
    "Execution": [
        ("Exec into container", "T1609"),
        ("bash/cmd inside container", "T1059"),
        ("New container", "T1610"),
        ("Application exploit (RCE)", None),
        ("SSH server running inside container", None),
        ("Sidecar injection", None),
    ],
    "Persistence": [
        ("Backdoor container", "T1525"),
        ("Writable hostPath mount", None),
        ("Kubernetes CronJob", "T1053.003"),
        ("Malicious admission controller", "T1554"),
    ],
    "Privilege Escalation": [
        ("Privileged container", "T1610"),
        ("Cluster-admin binding", "T1078"),
        ("hostPath mount", None),
        ("Access cloud resources", "T1078.004"),
        ("Disable namespacing (host PID/IPC/net)", None),
    ],
    "Defense Evasion": [
        ("Clear container logs", "T1070"),
        ("Delete K8s events", None),
        ("Pod / container name similarity", None),
        ("Connect from proxy server", None),
    ],
    "Credential Access": [
        ("List K8s secrets", "T1552.007"),
        ("Mount service principal", None),
        ("Access container service account", None),
        ("Application credentials in config files", "T1552"),
        ("Access managed identity credential", "T1552.005"),
        ("Malicious admission controller", "T1554"),
    ],
    "Discovery": [
        ("Access the K8s API server", "T1613"),
        ("Access Kubelet API", None),
        ("Network mapping", "T1046"),
        ("Access Kubernetes dashboard", None),
        ("Instance Metadata API", "T1552.005"),
    ],
    "Lateral Movement": [
        ("Access cloud resources", "T1078.004"),
        ("Container service account", "T1552.007"),
        ("Cluster internal networking", None),
        ("Applications credentials in config files", "T1552"),
        ("Writable volume mounts on host", None),
        ("CoreDNS poisoning", "T1557"),
        ("ARP poisoning / IP spoofing", None),
    ],
    "Impact": [
        ("Data destruction", "T1485"),
        ("Resource hijacking", "T1496"),
        ("Denial of service", "T1499"),
    ],
}


def _norm(s: str) -> str:
    return str(s).strip().lower()


@dataclass
class MatrixCell:
    """One technique in one tactic column."""
    tactic: str
    technique_name: str
    technique_id: Optional[str] = None
    #: Redguard display alias, when the covered/canonical name differs from the matrix's own
    reference_name: Optional[str] = None
    covered: bool = False                      # a scan Rule exists that can detect this
    rule_ids: list[str] = field(default_factory=list)
    #: Runtime Agent detections (Falco/audit/drift) that cover this technique. Kept
    #: separate from `rule_ids` on purpose: a runtime detection tells you when something
    #: IS happening, a scan rule tells you the configuration allows it. Collapsing them
    #: into one "covered" flag would claim point-in-time coverage the scanner doesn't have.
    runtime_rule_ids: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    #: cell identity within its tactic column (id, or "name:<...>")
    key: str = ""

    @property
    def hit(self) -> bool:
        return bool(self.findings)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> Optional[Severity]:
        real = [f.severity for f in self.findings if f.severity.weight > 0]
        return max(real, key=lambda s: s.order) if real else None

    @property
    def covered_runtime(self) -> bool:
        return bool(self.runtime_rule_ids)

    @property
    def state(self) -> str:
        """The single word a heatmap paints the cell with.

        Ordered by how much this scan actually knows: a finding beats a scan rule that
        found nothing, which beats runtime-only coverage (nothing to see in a config
        snapshot, it is caught live), which beats no coverage at all."""
        if self.hit:
            return "hit"
        if self.covered:
            return "covered"
        if self.covered_runtime:
            return "runtime"
        return "gap"

    def url(self) -> str:
        return mitre_technique_url(self.technique_id) if self.technique_id else REDGUARD_MATRIX_URL

    def as_dict(self) -> dict:
        sev = self.max_severity
        return {
            "technique_name": self.technique_name,
            "technique_id": self.technique_id,
            "reference_name": self.reference_name,
            "covered": self.covered,
            "covered_runtime": self.covered_runtime,
            "hit": self.hit,
            "state": self.state,
            "count": self.count,
            "max_severity": sev.label if sev else None,
            "max_severity_emoji": sev.emoji if sev else "",
            "rule_ids": sorted(set(self.rule_ids)),
            "runtime_rule_ids": sorted(set(self.runtime_rule_ids)),
            "finding_rule_ids": sorted({f.rule_id for f in self.findings}),
            "resources": sorted({str(f.resource) for f in self.findings})[:20],
            "url": self.url(),
        }


@dataclass
class TacticColumn:
    tactic: str
    cells: list[MatrixCell] = field(default_factory=list)

    @property
    def hit_count(self) -> int:
        return sum(1 for c in self.cells if c.hit)

    @property
    def finding_count(self) -> int:
        return sum(c.count for c in self.cells)

    @property
    def max_severity(self) -> Optional[Severity]:
        sevs = [c.max_severity for c in self.cells if c.max_severity]
        return max(sevs, key=lambda s: s.order) if sevs else None

    def as_dict(self) -> dict:
        sev = self.max_severity
        return {
            "tactic": self.tactic,
            "techniques_total": len(self.cells),
            "techniques_covered": sum(1 for c in self.cells if c.covered),
            "techniques_runtime_only": sum(
                1 for c in self.cells if c.covered_runtime and not c.covered),
            "techniques_hit": self.hit_count,
            "finding_count": self.finding_count,
            "max_severity": sev.label if sev else None,
            "max_severity_emoji": sev.emoji if sev else "",
            "cells": [c.as_dict() for c in self.cells],
        }


@dataclass
class ThreatMatrix:
    scan_id: str
    generated_at: str
    scope: str
    columns: list[TacticColumn] = field(default_factory=list)

    # -- aggregate stats -------------------------------------------------- #
    @property
    def techniques_total(self) -> int:
        return sum(len(col.cells) for col in self.columns)

    @property
    def techniques_covered(self) -> int:
        return sum(1 for col in self.columns for c in col.cells if c.covered)

    @property
    def techniques_hit(self) -> int:
        return sum(col.hit_count for col in self.columns)

    @property
    def tactics_hit(self) -> int:
        return sum(1 for col in self.columns if col.hit_count)

    @property
    def techniques_runtime_only(self) -> int:
        """Techniques with NO scan rule but a Runtime Agent detection, real coverage the
        scanner cannot provide, which would otherwise render as a flat coverage gap."""
        return sum(1 for col in self.columns for c in col.cells
                   if c.covered_runtime and not c.covered)

    @property
    def tactics_covered(self) -> int:
        """Tactics with at least one technique the platform has a rule for. Independent of
        any scan, this is what the standalone /matrix coverage page reports on."""
        return sum(1 for col in self.columns
                   if any(c.covered for c in col.cells))

    @property
    def rule_count(self) -> int:
        """Distinct rules contributing coverage anywhere on the matrix."""
        return len({rid for col in self.columns for c in col.cells for rid in c.rule_ids})

    @property
    def finding_count(self) -> int:
        """DISTINCT findings mapped onto the matrix. A multi-tactic finding appears in one
        cell per tactic it enables, so summing column counts would over-count it, dedupe
        by finding identity here so the headline number matches reality (it is ≤ the
        scan's total, since findings with no MITRE tag don't appear on the matrix)."""
        seen = set()
        for col in self.columns:
            for cell in col.cells:
                for f in cell.findings:
                    seen.add(f.dedup_key())
        return len(seen)

    def summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "scope": self.scope,
            "reference": REDGUARD_MATRIX_URL,
            "tactics_total": len(self.columns),
            "tactics_hit": self.tactics_hit,
            "tactics_covered": self.tactics_covered,
            "rule_count": self.rule_count,
            "techniques_total": self.techniques_total,
            "techniques_covered": self.techniques_covered,
            "techniques_runtime_only": self.techniques_runtime_only,
            "techniques_hit": self.techniques_hit,
            "coverage_pct": _pct(self.techniques_covered, self.techniques_total),
            "coverage_pct_with_runtime": _pct(
                self.techniques_covered + self.techniques_runtime_only,
                self.techniques_total),
            "exposure_pct": _pct(self.techniques_hit, self.techniques_total),
            "finding_count": self.finding_count,
        }

    def as_dict(self) -> dict:
        return {"summary": self.summary(),
                "columns": [col.as_dict() for col in self.columns]}


def _pct(n: int, total: int) -> float:
    return round(100 * n / total, 1) if total else 0.0


def _default_runtime_catalog() -> list[dict]:
    """The Runtime Agent's detection catalog, loaded by default so every surface, CLI,
    report, dashboard, MCP, reports the same coverage. A caller that genuinely wants a
    scan-only matrix passes an explicit empty list rather than relying on the default.

    Imported lazily: the Runtime Agent is a peer subsystem, and a matrix should still
    build if it is unavailable for any reason."""
    try:
        from ..agents.runtime import RuntimeAgent
        return RuntimeAgent().catalog()
    except Exception:
        return []


def attack_paths(matrix: ThreatMatrix, runtime: Optional[dict] = None) -> dict:
    """Chain the matrix's HIT cells into a kill-chain exploit path.

    The columns are already in kill-chain order (TACTIC_ORDER: Initial Access -> Impact).
    An attacker's realistic path through THIS cluster is, per tactic they have a foothold
    in (a hit cell), the technique(s) actually available and the resources exposing them.

    Every step is backed by findings this scan actually produced: a tactic with no hit cell
    contributes no step, so the chain never invents a link between unrelated findings.
    `runtime` (a scan's runtime block, when one exists) attaches the live evidence that
    lands on the same tactic, which is what lifts a step's confidence from "possible" to
    "observed".

    ponytail: kill-chain-order chaining, the ATT&CK-navigator convention, not a per-finding
    causal graph. It answers "which tactics can an attacker actually string together here,
    and does the chain reach Impact". Upgrade to true edge inference (this pod's
    ServiceAccount can reach that binding) when a single-target path matters more than the
    tactic-level overview.
    """
    by_tactic = _runtime_by_tactic(runtime)
    steps = []
    for col in matrix.columns:                       # already kill-chain ordered
        hits = [c for c in col.cells if c.hit]
        if not hits:
            continue
        sev = col.max_severity
        evidence = by_tactic.get(col.tactic, [])
        supporting = _supporting(hits)
        steps.append({
            "tactic": col.tactic,
            "worst_severity": sev.label if sev else None,
            "techniques": [{
                "technique_name": c.technique_name,
                "technique_id": c.technique_id,
                "max_severity": c.max_severity.label if c.max_severity else None,
                "resources": sorted({str(f.resource) for f in c.findings})[:20],
                "finding_rule_ids": sorted({f.rule_id for f in c.findings}),
                "url": c.url(),
            } for c in hits],
            # The individual findings that put this step on the chain, so a reader can go
            # step -> finding -> evidence without re-deriving anything.
            "supporting_findings": supporting,
            "runtime_evidence": evidence,
            "confidence": _step_confidence(evidence),
            "internet_reachable": any(f["internet_reachable"] for f in supporting),
        })
    reaches_impact = any(s["tactic"] == "Impact" for s in steps)
    return {
        "scan_id": matrix.scan_id,
        "scope": matrix.scope,
        "chain": " -> ".join(s["tactic"] for s in steps),
        "steps": steps,
        "entry_points": steps[0]["techniques"] if steps else [],
        "reaches_impact": reaches_impact,
        "tactic_count": len(steps),
        "confidence": _path_confidence(steps),
        "reference": REDGUARD_MATRIX_URL,
    }


def _supporting(cells: list) -> list[dict]:
    """Distinct findings behind a step, worst first, with the reachability context already
    computed for them (never recomputed here)."""
    seen: dict = {}
    for cell in cells:
        for f in cell.findings:
            seen.setdefault(f.dedup_key(), f)
    out = sorted(seen.values(), key=lambda f: (f.severity.order, f.score), reverse=True)
    return [{"rule_id": f.rule_id, "title": f.title, "severity": f.severity.label,
             "resource": str(f.resource), "namespace": f.resource.namespace,
             "exploitable_by": list(f.exploitable_by),
             "internet_reachable": "ingress" in f.exploitable_by,
             "exploit_path": list(f.exploit_path)}
            for f in out[:20]]


def _runtime_by_tactic(runtime: Optional[dict]) -> dict:
    """Live evidence grouped by tactic, from a scan's runtime block. Only `confirmed` and
    `corroborated` correlations count as evidence for a step; a `runtime-only` alert by
    definition has no static finding to support."""
    out: dict = {}
    for c in ((runtime or {}).get("correlation") or {}).get("correlations", []):
        if c.get("confidence") == "runtime-only":
            continue
        out.setdefault(c.get("tactic", ""), []).append({
            "level": c.get("confidence"), "timestamp": c.get("timestamp", ""),
            "rule_id": (c.get("runtime") or {}).get("rule_id"),
            "title": (c.get("runtime") or {}).get("title"),
            "resource": c.get("resource", ""), "namespace": c.get("namespace", "")})
    for drift in ((runtime or {}).get("drift") or {}).get("drift", []):
        out.setdefault(drift.get("tactic", ""), []).append({
            "level": "drift", "timestamp": drift.get("timestamp", ""),
            "rule_id": "drift", "title": drift.get("verdict", ""),
            "resource": drift.get("pod", ""), "namespace": drift.get("namespace", "")})
    return out


def _step_confidence(evidence: list) -> str:
    """How strongly this step is evidenced. `observed` requires runtime proof on the same
    tactic; without it a step is exactly what the scan can honestly claim, a configuration
    that makes the tactic available."""
    levels = {e.get("level") for e in evidence}
    if "confirmed" in levels or "drift" in levels:
        return "observed"
    if "corroborated" in levels:
        return "corroborated"
    return "configuration-only"


_PATH_RANK = {"configuration-only": 0, "corroborated": 1, "observed": 2}


def _path_confidence(steps: list) -> str:
    """The chain is only as strong as its strongest evidenced step, and a chain with no
    steps has no confidence to report."""
    if not steps:
        return "none"
    best = max(steps, key=lambda s: _PATH_RANK.get(s["confidence"], 0))
    return best["confidence"]


# ----------------------------------------------------------------------- #
# Builder
# ----------------------------------------------------------------------- #
def build_threat_matrix(result: ScanResult,
                        registry: Optional[RuleRegistry] = None,
                        runtime_catalog: Optional[list[dict]] = None) -> ThreatMatrix:
    """Project a ScanResult onto the Kubernetes Threat Matrix.

    `registry` (optional) supplies the *coverage* layer, which techniques the platform
    has any rule for, independent of whether this scan hit them. Pass
    `platform.registry.rules` for the full three-state (gap/covered/hit) matrix; omit it
    to render a findings-only matrix (every non-empty cell is simply `hit`).
    """
    if runtime_catalog is None:
        runtime_catalog = _default_runtime_catalog()

    # 1) Seed reference cells from the Redguard matrix, one column per tactic.
    columns: list[TacticColumn] = []
    # per-tactic lookups so rules/findings can find the cell to light up
    by_id: dict[str, dict[str, MatrixCell]] = {}      # tactic -> {tech_id -> cell}
    by_name: dict[str, dict[str, MatrixCell]] = {}     # tactic -> {norm(name) -> cell}

    for tactic in TACTIC_ORDER:
        tval = tactic.value
        col = TacticColumn(tactic=tval)
        id_index: dict[str, MatrixCell] = {}
        name_index: dict[str, MatrixCell] = {}
        for name, tid in REDGUARD_TECHNIQUES.get(tval, []):
            # a duplicate id inside one tactic keeps only the first id-keyed; the rest
            # become name-keyed so both distinct Redguard techniques still show.
            use_id = tid if (tid and tid not in id_index) else None
            key = use_id or f"name:{_norm(name)}"
            cell = MatrixCell(tactic=tval, technique_name=name, technique_id=tid,
                              reference_name=name, key=key)
            col.cells.append(cell)
            if use_id:
                id_index[use_id] = cell
            name_index[_norm(name)] = cell
        columns.append(col)
        by_id[tval] = id_index
        by_name[tval] = name_index

    col_by_tactic = {col.tactic: col for col in columns}

    def _locate(tactic_val: str, tech_id: str, tech_name: str,
                create: bool) -> Optional[MatrixCell]:
        """Find (or, for coverage, create) the cell a (tactic, technique) maps to."""
        col = col_by_tactic.get(tactic_val)
        if col is None:                       # tactic not in the 9 (shouldn't happen)
            return None
        # NAME BEFORE ID, deliberately. The Redguard matrix is finer-grained than
        # ATT&CK-for-Containers: "Access the K8s API server", "Access Kubelet API" and
        # "Access Kubernetes dashboard" are three distinct Discovery techniques that all
        # carry the single ATT&CK id T1613. Matching by id first collapsed all three into
        # one cell, so the other two rendered as coverage gaps even though rules for them
        # existed. Naming a Redguard technique verbatim is therefore how a rule opts into
        # that exact cell; anything using a canonical ATT&CK name (which never matches a
        # Redguard cell name) still resolves by id exactly as before.
        nidx = by_name[tactic_val]
        if _norm(tech_name) in nidx:
            return nidx[_norm(tech_name)]
        idx = by_id[tactic_val]
        if tech_id and tech_id in idx:
            return idx[tech_id]
        if not create:
            return None
        # A covered/hit technique the Redguard reference list didn't enumerate, add it so
        # the platform's real coverage is never hidden behind an incomplete reference list.
        key = tech_id or f"name:{_norm(tech_name)}"
        cell = MatrixCell(tactic=tactic_val, technique_name=tech_name,
                          technique_id=tech_id or None, key=key)
        col.cells.append(cell)
        if tech_id:
            idx[tech_id] = cell
        nidx[_norm(tech_name)] = cell
        return cell

    # 2) Coverage layer, every registered rule marks its technique cells "covered".
    if registry is not None:
        for rule in registry.all():
            for m in rule.mitre:
                cell = _locate(m.tactic.value, m.technique_id, m.technique_name, create=True)
                if cell is None:
                    continue
                cell.covered = True
                cell.rule_ids.append(rule.id)
                # Keep the Redguard display name for a reference cell (this IS the
                # Kubernetes Threat Matrix the user asked for, "CoreDNS poisoning" reads
                # better than the raw ATT&CK "Adversary-in-the-Middle"); the canonical
                # ATT&CK technique is still reachable via technique_id / its URL.
                cell.technique_id = cell.technique_id or m.technique_id

    # 3) Runtime layer, Runtime Agent detections (Falco/audit/drift). A technique the
    #    scanner structurally cannot see in a config snapshot (a shell being spawned, a
    #    miner starting) is still covered by the platform, just on the other surface.
    #    Pass `RuntimeAgent().catalog()`; omit it for a scan-only view.
    for det in (runtime_catalog or []):
        cell = _locate(det.get("tactic", ""), det.get("technique_id", ""),
                       det.get("technique_name", ""), create=True)
        if cell is not None:
            cell.runtime_rule_ids.append(det.get("id", ""))

    # 4) Hit layer, this scan's findings light up their cells.
    for f in result.findings:
        if f.severity.weight == 0:            # skip INFO / engine-error findings
            continue
        for m in f.mitre:
            cell = _locate(m.tactic.value, m.technique_id, m.technique_name, create=True)
            if cell is not None:
                cell.findings.append(f)

    return ThreatMatrix(
        scan_id=result.scan_id,
        generated_at=result.generated_at,
        scope=result.request.scope.describe(),
        columns=columns,
    )
