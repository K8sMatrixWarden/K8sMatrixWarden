"""
Core domain model for the K8sMatrixWarden (v1.0).

Everything in the platform is expressed in terms of the types defined here:

    Rule      , the atomic technique-level check, self-declaring its taxonomy tags (§5.1)
    Finding   , one detected issue against one resource, carrying the rule's tags (§6.1)
    Scope     , WHAT resources a scan touches       (cluster→pod→image)            (§4.3)
    Selector  , WHICH rules a scan runs             (tactic/technique/module/…)    (§4.3)
    ScanRequest, the single object every entry point compiles to                     (§4.3)
    Evidence  , the shared, scope-constrained snapshot fed to rules                 (§6.1)

Only the standard library is used so the engine runs with zero third-party installs.
"""
from __future__ import annotations

import dataclasses
import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional


# --------------------------------------------------------------------------- #
# Severity / method / risk enumerations
# --------------------------------------------------------------------------- #
class Severity(Enum):
    """Finding severity with numeric weight (§18.1)."""
    CRITICAL = ("CRITICAL", 10, "🔴")
    HIGH = ("HIGH", 7, "🟠")
    MEDIUM = ("MEDIUM", 4, "🟡")
    LOW = ("LOW", 1, "🟢")
    INFO = ("INFO", 0, "⚪")

    def __init__(self, label: str, weight: int, emoji: str):
        self.label = label
        self.weight = weight
        self.emoji = emoji

    @property
    def order(self) -> int:
        # Higher = more severe, for sorting/threshold comparisons.
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.label]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        key = str(value).strip().upper()
        for m in cls:
            if m.label == key:
                return m
        raise ValueError(f"Unknown severity: {value!r}")


class DetectionMethod(Enum):
    """How a rule gathers evidence, and therefore WHEN it can fire (§1, §8).

    Two detection *surfaces*:
      • scan   , point-in-time analysis of a config/RBAC/image/network/cloud snapshot
                  (the Scanner Agent; a finding is true "as of this scan")
      • runtime, continuous observation of a live event stream, i.e. audit events or
                  syscall/behavioural telemetry (the Runtime Agent DaemonSet; a finding
                  means "this is happening / just happened")
    """
    STATIC_CONFIG = "static_config"
    RBAC = "rbac"
    IMAGE = "image"
    NETWORK = "network"
    AUDIT_LOG = "audit_log"
    RUNTIME_BEHAVIORAL = "runtime_behavioral"
    CLOUD_IAM = "cloud_iam"

    @property
    def is_runtime(self) -> bool:
        """True if this method observes a live stream (Runtime Agent) rather than a
        point-in-time snapshot (Scanner Agent)."""
        return self in (DetectionMethod.AUDIT_LOG, DetectionMethod.RUNTIME_BEHAVIORAL)

    @property
    def surface(self) -> str:
        return "runtime" if self.is_runtime else "scan"


class Exploitability(Enum):
    REMOTE = ("Remote", 3)
    ADJACENT = ("Adjacent", 2)
    LOCAL = ("Local", 1)

    def __init__(self, label: str, weight: int):
        self.label = label
        self.weight = weight

    @classmethod
    def parse(cls, label: str) -> "Exploitability":
        for m in cls:
            if m.label.lower() == str(label).lower():
                return m
        return cls.LOCAL


class BlastRadius(Enum):
    CLUSTER = ("Cluster-wide", 3)
    NAMESPACE = ("Namespace", 2)
    POD = ("Pod", 1)

    def __init__(self, label: str, weight: int):
        self.label = label
        self.weight = weight

    @classmethod
    def parse(cls, label: str) -> "BlastRadius":
        for m in cls:
            if m.label.lower() == str(label).lower():
                return m
        return cls.POD


class Tactic(Enum):
    """The 9 tactics of the Kubernetes Threat Matrix (§12.1). No 'Collection'."""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    IMPACT = "Impact"

    @classmethod
    def parse(cls, value: str) -> "Tactic":
        key = str(value).strip().lower()
        for t in cls:
            if t.value.lower() == key or t.name.lower() == key.replace(" ", "_"):
                return t
        raise ValueError(f"Unknown tactic: {value!r}")


@dataclass(frozen=True)
class MitreTag:
    """A single MITRE ATT&CK for Containers mapping on a rule (§6.2)."""
    tactic: Tactic
    technique_id: str          # canonical ATT&CK-for-Containers id, e.g. "T1610"
    technique_name: str

    def as_dict(self) -> dict:
        return {
            "tactic": self.tactic.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
        }


# --------------------------------------------------------------------------- #
# Scope, WHAT to scan
# --------------------------------------------------------------------------- #
class ScopeLevel(Enum):
    CLUSTER = "cluster"
    NAMESPACE = "namespace"
    WORKLOAD = "workload"
    NODE = "node"
    POD = "pod"
    IMAGE = "image"
    HELM_RELEASE = "helm_release"


@dataclass
class Scope:
    """The resource scope of a scan (§4.3)."""
    level: ScopeLevel = ScopeLevel.CLUSTER
    namespace: Optional[str] = None
    name: Optional[str] = None
    kind: Optional[str] = None          # for workload scope, e.g. "Deployment"
    image: Optional[str] = None

    def describe(self) -> str:
        if self.level == ScopeLevel.CLUSTER:
            return "cluster-wide"
        if self.level == ScopeLevel.NAMESPACE:
            return f"namespace/{self.namespace}"
        if self.level == ScopeLevel.IMAGE:
            return f"image/{self.image}"
        if self.level == ScopeLevel.NODE:
            return f"node/{self.name}"
        if self.level == ScopeLevel.WORKLOAD:
            return f"{self.kind or 'workload'}/{self.name}@{self.namespace}"
        return f"{self.level.value}/{self.name}@{self.namespace}"

    def matches(self, resource: dict) -> bool:
        """True if a fetched resource is in scope (used to filter evidence)."""
        if self.level == ScopeLevel.CLUSTER:
            return True
        meta = resource.get("metadata", {}) or {}
        rns = meta.get("namespace")
        rname = meta.get("name")
        kind = resource.get("kind", "")
        if self.level == ScopeLevel.NAMESPACE:
            # Cluster-scoped objects (no namespace) still pass so RBAC/webhooks are visible.
            return rns is None or rns == self.namespace
        if self.level == ScopeLevel.POD:
            return kind == "Pod" and rname == self.name and (self.namespace in (None, rns))
        if self.level == ScopeLevel.WORKLOAD:
            if self.kind and kind and kind != self.kind:
                return False
            return rname == self.name and (self.namespace in (None, rns))
        if self.level == ScopeLevel.NODE:
            if kind == "Node":
                return rname == self.name
            return (resource.get("spec", {}) or {}).get("nodeName") == self.name
        if self.level == ScopeLevel.IMAGE:
            for c in _all_containers(resource):
                if self.image and self.image in (c.get("image") or ""):
                    return True
            return False
        if self.level == ScopeLevel.HELM_RELEASE:
            labels = meta.get("labels", {}) or {}
            return labels.get("app.kubernetes.io/instance") == self.name
        return True


def _all_containers(resource: dict) -> list[dict]:
    spec = resource.get("spec", {}) or {}
    pod_spec = spec.get("template", {}).get("spec", spec) if "template" in spec else spec
    out = []
    out.extend(pod_spec.get("containers", []) or [])
    out.extend(pod_spec.get("initContainers", []) or [])
    out.extend(pod_spec.get("ephemeralContainers", []) or [])
    return out


# --------------------------------------------------------------------------- #
# Selector, WHICH rules to run
# --------------------------------------------------------------------------- #
@dataclass
class Selector:
    """
    Chooses which rules run (§4.3). All axes combine with OR (union) semantics,
    then the union is intersected with scope. An empty selector means "all rules".
    """
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    severity_min: Optional[Severity] = None

    def is_empty(self) -> bool:
        return not any([self.tactics, self.techniques, self.modules,
                        self.rule_ids, self.aliases, self.frameworks])

    def describe(self) -> str:
        parts = []
        for label, vals in [("tactic", self.tactics), ("technique", self.techniques),
                            ("module", self.modules), ("rule", self.rule_ids),
                            ("alias", self.aliases), ("framework", self.frameworks)]:
            if vals:
                parts.append(f"{label}={','.join(vals)}")
        if self.severity_min:
            parts.append(f"severity>={self.severity_min.label}")
        return " ".join(parts) if parts else "all-rules"


class ScanMode(Enum):
    SYNC = "sync"
    ASYNC = "async"


@dataclass
class ScanRequest:
    """The single internal object every entry point compiles to (§4.3)."""
    scope: Scope = field(default_factory=Scope)
    selector: Selector = field(default_factory=Selector)
    mode: ScanMode = ScanMode.SYNC
    output: str = "terminal"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class ResourceRef:
    kind: str = ""
    name: str = ""
    namespace: Optional[str] = None
    #: Direct/resolved owning controller (a Pod's controller, resolved past
    #: ReplicaSet->Deployment and Job->CronJob where evidence allows). None means no
    #: controller was found (a standalone resource). Purely descriptive context.
    owner_kind: Optional[str] = None
    owner_name: Optional[str] = None
    #: Labels/annotations of the resolved owner (or the resource's own), descriptive
    #: context, e.g. surfacing Helm/ArgoCD/Flux management in a report.
    labels: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)

    def __str__(self) -> str:
        if self.namespace:
            return f"{self.kind}/{self.name} ({self.namespace})"
        return f"{self.kind}/{self.name}" if self.name else self.kind


@dataclass
class Finding:
    """One detected issue. Taxonomy tags are copied from the owning Rule (§6.1)."""
    rule_id: str
    title: str
    severity: Severity
    resource: ResourceRef
    message: str
    owning_shard: str = ""
    mitre: list[MitreTag] = field(default_factory=list)
    owasp: Optional[str] = None
    cis: list[str] = field(default_factory=list)
    nsa_cisa: list[str] = field(default_factory=list)
    detection_method: Optional[DetectionMethod] = None
    exploitability: Exploitability = Exploitability.LOCAL
    blast_radius: BlastRadius = BlastRadius.POD
    evidence: dict = field(default_factory=dict)
    score: float = 0.0                      # filled in by RiskScoringEngine

    # -- convenience views ------------------------------------------------- #
    @property
    def tactics(self) -> list[Tactic]:
        seen, out = set(), []
        for m in self.mitre:
            if m.tactic not in seen:
                seen.add(m.tactic)
                out.append(m.tactic)
        return out

    @property
    def surface(self) -> str:
        """'scan' or 'runtime', whether this finding came from point-in-time config
        analysis or live event/behaviour observation (§8). Falls back to 'scan' when the
        detection method is unknown (a bare/hand-built Finding)."""
        return self.detection_method.surface if self.detection_method else "scan"

    def dedup_key(self) -> tuple:
        return (self.rule_id, self.resource.kind, self.resource.name,
                self.resource.namespace)

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "resource": {"kind": self.resource.kind, "name": self.resource.name,
                         "namespace": self.resource.namespace,
                         "owner_kind": self.resource.owner_kind,
                         "owner_name": self.resource.owner_name,
                         "labels": self.resource.labels,
                         "annotations": self.resource.annotations},
            "message": self.message,
            "owning_shard": self.owning_shard,
            "mitre": [m.as_dict() for m in self.mitre],
            "owasp": self.owasp,
            "cis": self.cis,
            "nsa_cisa": self.nsa_cisa,
            "detection_method": self.detection_method.value if self.detection_method else None,
            "surface": self.surface,
            "exploitability": self.exploitability.label,
            "blast_radius": self.blast_radius.label,
            "evidence": self.evidence,
            "score": round(self.score, 3),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Reconstruct a Finding from its as_dict() form (for the report store)."""
        res = d.get("resource", {}) or {}
        dm = d.get("detection_method")
        f = cls(
            rule_id=d.get("rule_id", ""),
            title=d.get("title", ""),
            severity=Severity.parse(d.get("severity", "INFO")),
            resource=ResourceRef(res.get("kind", ""), res.get("name", ""),
                                 res.get("namespace"), res.get("owner_kind"),
                                 res.get("owner_name"), res.get("labels", {}) or {},
                                 res.get("annotations", {}) or {}),
            message=d.get("message", ""),
            owning_shard=d.get("owning_shard", ""),
            mitre=[MitreTag(Tactic.parse(m["tactic"]), m["technique_id"],
                            m["technique_name"]) for m in d.get("mitre", [])],
            owasp=d.get("owasp"),
            cis=list(d.get("cis", [])),
            nsa_cisa=list(d.get("nsa_cisa", [])),
            detection_method=DetectionMethod(dm) if dm else None,
            exploitability=Exploitability.parse(d.get("exploitability", "Local")),
            blast_radius=BlastRadius.parse(d.get("blast_radius", "Pod")),
            evidence=d.get("evidence", {}) or {},
        )
        f.score = float(d.get("score", 0.0))
        return f


# --------------------------------------------------------------------------- #
# Rule, the atomic check
# --------------------------------------------------------------------------- #
# A check function receives (rule, evidence, scope) and returns Findings.
CheckFn = Callable[["Rule", "Evidence", Scope], Iterable[Finding]]


@dataclass
class Rule:
    """
    A single technique-level check (§5.1). Taxonomy is authored here, once, and
    indexed centrally at startup by the MITREMappingEngine (§6.2 anti-drift).
    """
    id: str
    title: str
    owning_shard: str
    resource_scope: list[str]                 # kinds this rule reasons about
    severity: Severity
    detection_method: DetectionMethod
    check: CheckFn
    mitre: list[MitreTag] = field(default_factory=list)
    owasp: Optional[str] = None
    cis: list[str] = field(default_factory=list)
    nsa_cisa: list[str] = field(default_factory=list)
    evidence_needs: list[str] = field(default_factory=list)
    default_exploitability: Exploitability = Exploitability.LOCAL
    default_blast_radius: BlastRadius = BlastRadius.POD
    enabled: bool = True

    def __post_init__(self):
        if not self.evidence_needs:
            self.evidence_needs = list(self.resource_scope)

    @property
    def tactics(self) -> list[Tactic]:
        seen, out = set(), []
        for m in self.mitre:
            if m.tactic not in seen:
                seen.add(m.tactic)
                out.append(m.tactic)
        return out

    @property
    def surface(self) -> str:
        """'scan' (point-in-time, Scanner Agent) or 'runtime' (live stream, Runtime
        Agent), derived from the rule's detection_method (§8)."""
        return self.detection_method.surface

    def finding(self, resource: ResourceRef, message: str, *,
                severity: Optional[Severity] = None,
                exploitability: Optional[Exploitability] = None,
                blast_radius: Optional[BlastRadius] = None,
                evidence: Optional[dict] = None) -> Finding:
        """Build a Finding pre-populated with this rule's taxonomy tags."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            resource=resource,
            message=message,
            owning_shard=self.owning_shard,
            mitre=list(self.mitre),
            owasp=self.owasp,
            cis=list(self.cis),
            nsa_cisa=list(self.nsa_cisa),
            detection_method=self.detection_method,
            exploitability=exploitability or self.default_exploitability,
            blast_radius=blast_radius or self.default_blast_radius,
            evidence=evidence or {},
        )

    def metadata(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "owning_shard": self.owning_shard,
            "resource_scope": self.resource_scope,
            "severity": self.severity.label,
            "detection_method": self.detection_method.value,
            "surface": self.surface,
            "mitre": [m.as_dict() for m in self.mitre],
            "owasp": self.owasp,
            "cis": self.cis,
            "nsa_cisa": self.nsa_cisa,
            "evidence_needs": self.evidence_needs,
            "enabled": self.enabled,
        }
