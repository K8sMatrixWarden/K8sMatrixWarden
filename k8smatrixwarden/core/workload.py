"""
Workload-level aggregation: how many things are actually wrong, as opposed to how many
Kubernetes objects carry the evidence.

A live scan of an eight-namespace cluster produced 517 resource-level findings from 32
rules. Every one of them was true, and none of them was counted twice: the scanner had
found a real flaw on a real object each time. The headline number was still misleading,
because Kubernetes represents one workload as a chain of objects:

    Deployment/foo  ->  ReplicaSet/foo-abc123  ->  Pod/foo-abc123-xyz

A Deployment whose pod template runs as root produces that finding on the Deployment, on
every ReplicaSet it has ever created, and on every Pod those ReplicaSets are running. Three
findings, one misconfiguration, one edit to fix it. On that scan 353 of 517 findings sat on
derived Pod and ReplicaSet objects, and `workload-run-as-root` alone reported 62 findings
across 18 workloads.

So this module adds a second, coarser count beside the first. It does not replace it:

    resource-level findings   the evidence, unchanged, every object that carries the flaw
    workload-level issues     the remediation units, one per (rule x owning workload)

Both are published everywhere, under names that cannot be confused for each other. The
resource findings remain the record of what was observed; the workload issues answer "how
many separate things must someone go and fix", which is the question a headline count is
read as answering.

WHAT IS NEVER DONE HERE

Aggregation follows Kubernetes' own ownership metadata and nothing else. It never matches on
name prefixes, name similarity, or a pod-name convention, because those are guesses and this
is the layer whose whole purpose is to be exact about identity. `Deployment/api` and
`Deployment/api-server` are two workloads. A Pod whose controller is not in the evidence
keeps its own identity rather than being attached to a plausible-looking parent.

The grouping key is (rule, workload), never workload alone. A Deployment that is privileged
AND mounts a hostPath AND runs as root is three issues, because those are three separate
things to fix. Two Deployments with the same flaw are two issues, because they are two
places to fix it.

Namespace and cluster are part of workload identity, so `Deployment/api` in `staging` never
merges with `Deployment/api` in `production`, and neither merges with the same name in
another cluster.

Runtime evidence is not aggregated here at all. Five shell executions in one workload are
five runtime events; collapsing them with a static-workload key would destroy the event
semantics the runtime pipeline is built on. See core/correlation.py.
"""
from __future__ import annotations

import hashlib
from typing import Optional

#: Kinds Kubernetes generates from a controller rather than from an operator's manifest.
#: A finding on one of these, WHEN it has a resolved controller, is evidence about the
#: controller's configuration rather than an independently authored object. A standalone
#: Pod (no controller) is not derived: somebody wrote it, and it is fixed on its own.
DERIVED_KINDS = frozenset({"Pod", "ReplicaSet", "Job"})

#: Separator between the parts of a workload id. Chosen because Kubernetes names cannot
#: contain it, so the id parses back unambiguously.
_SEP = "|"


def workload_ref(resource) -> tuple:
    """(kind, name) of the workload a resource belongs to.

    The owner if Kubernetes recorded one, otherwise the resource itself. `owner_kind` /
    `owner_name` are already resolved past the intermediate controller by
    shards/base.py::resolve_owner (ReplicaSet -> Deployment, Job -> CronJob) wherever the
    evidence allowed it, so this reads that single authoritative answer rather than
    re-deriving a second one that could disagree with it.
    """
    owner_kind = getattr(resource, "owner_kind", None)
    owner_name = getattr(resource, "owner_name", None)
    if owner_kind and owner_name:
        return owner_kind, owner_name
    return getattr(resource, "kind", "") or "", getattr(resource, "name", "") or ""


def workload_id(resource, cluster: str = "") -> str:
    """Stable identity of the owning workload: ``Kind/name|namespace|cluster``.

    Namespace and cluster are always present, empty when the resource is cluster-scoped or
    the scan did not name a cluster. They are part of the identity rather than decoration:
    without them the same workload name in two namespaces, or in two clusters whose reports
    share a store, would silently become one workload.
    """
    kind, name = workload_ref(resource)
    namespace = getattr(resource, "namespace", None) or ""
    return f"{kind}/{name}{_SEP}{namespace}{_SEP}{cluster or ''}"


def is_derived_resource(resource) -> bool:
    """Is this object one Kubernetes generated from a controller we can actually see?

    True only when BOTH hold: the kind is one Kubernetes generates, and a controller was
    resolved for it. A standalone Pod is somebody's manifest and is fixed on its own. A Pod
    whose ReplicaSet is missing from the evidence is also not treated as derived, because we
    cannot point at the thing that would be edited instead.
    """
    kind = getattr(resource, "kind", "") or ""
    if kind not in DERIVED_KINDS:
        return False
    return bool(getattr(resource, "owner_kind", None)
                and getattr(resource, "owner_name", None))


def resource_finding_id(finding, cluster: str = "") -> str:
    """Stable id for ONE resource-level finding: rule + the exact object it fired on.

    Derived from identity rather than from position in a list, so the same finding keeps the
    same id across scans, report formats and re-reads. This is what a reader follows from a
    workload issue back to the evidence underneath it.
    """
    resource = finding.resource
    seed = _SEP.join([finding.rule_id or "", resource.kind or "", resource.name or "",
                      resource.namespace or "", cluster or ""])
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]


def aggregation_group(finding, cluster: str = "") -> str:
    """The (rule, workload) group this finding is evidence for.

    Deliberately NOT the workload alone. One Deployment that is privileged, mounts a
    hostPath and runs as root has three things wrong with it and three fixes to make; one
    group per workload would report that as a single issue and hide two of them.
    """
    return f"{finding.rule_id}@{workload_id(finding.resource, cluster)}"


def annotate(findings: list, cluster: str = "") -> list:
    """Stamp every finding with its aggregation identity, in place, and return the list.

    Nothing is removed, reordered, merged or hidden. The findings are exactly what they
    were; they now also carry the four fields that let any surface group them the same way
    as any other surface.
    """
    for finding in findings or []:
        finding.resource_finding_id = resource_finding_id(finding, cluster)
        finding.owning_workload_id = workload_id(finding.resource, cluster)
        finding.is_derived_resource = is_derived_resource(finding.resource)
        finding.aggregation_group = aggregation_group(finding, cluster)
    return findings


def _representative(group: list):
    """The finding that best speaks for a group: the one on the object an operator edits.

    A non-derived object first (the Deployment rather than its Pods), then worst severity,
    then the highest-scoring, then the id, so the choice is deterministic and never depends
    on which order the rules happened to finish in. Ties broken by id rather than left to
    dict ordering, because a report that names a different Pod each run reads as churn.
    """
    return sorted(group, key=lambda f: (
        f.is_derived_resource,
        -f.severity.order,
        -(getattr(f, "score", 0.0) or 0.0),
        getattr(f, "resource_finding_id", "") or "",
    ))[0]


class WorkloadIssue:
    """One (rule x owning workload) remediation unit, and the evidence behind it."""

    __slots__ = ("group", "rule_id", "title", "severity", "workload_id", "workload_kind",
                 "workload_name", "namespace", "cluster", "owning_shard", "tactics",
                 "resources", "resource_finding_ids", "derived_count", "score",
                 "score_breakdown", "representative")

    def __init__(self, group, findings, cluster):
        lead = _representative(findings)
        kind, name = workload_ref(lead.resource)
        self.group = group
        self.rule_id = lead.rule_id
        self.title = lead.title
        # Worst severity across the evidence. A group's severity cannot be lower than any
        # single piece of evidence in it, or aggregating would quietly downgrade a finding.
        self.severity = max((f.severity for f in findings), key=lambda s: s.order)
        self.workload_id = workload_id(lead.resource, cluster)
        self.workload_kind = kind
        self.workload_name = name
        self.namespace = lead.resource.namespace
        self.cluster = cluster or ""
        self.owning_shard = lead.owning_shard
        self.tactics = sorted({t.value for f in findings for t in f.tactics})
        self.resources = sorted({str(f.resource) for f in findings})
        self.resource_finding_ids = sorted(
            getattr(f, "resource_finding_id", "") or "" for f in findings)
        self.derived_count = sum(1 for f in findings if f.is_derived_resource)
        # The representative's score, NOT the sum. Summing would reintroduce exactly the
        # layer multiplication this module exists to remove: three copies of one
        # misconfiguration would score three times as much as one copy of it.
        self.score = round(float(getattr(lead, "score", 0.0) or 0.0), 3)
        # The four factors whose product IS `score`, carried from the representative so an
        # analyst can still reproduce an issue's contribution by hand (§7). Aggregation
        # changed WHICH finding is counted, not whether the arithmetic is checkable.
        self.score_breakdown = dict(getattr(lead, "score_breakdown", {}) or {})
        self.representative = str(lead.resource)

    def as_dict(self) -> dict:
        return {
            "aggregation_group": self.group,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "owning_workload_id": self.workload_id,
            "workload": f"{self.workload_kind}/{self.workload_name}",
            "workload_kind": self.workload_kind,
            "workload_name": self.workload_name,
            "namespace": self.namespace,
            "cluster": self.cluster or None,
            "owning_shard": self.owning_shard,
            "tactics": list(self.tactics),
            "resource_count": len(self.resources),
            "derived_resource_count": self.derived_count,
            "resources": list(self.resources),
            "resource_finding_ids": list(self.resource_finding_ids),
            "score": self.score,
            "scored_resource": self.representative,
            "score_breakdown": self.score_breakdown,
        }


def workload_issues(findings: list, cluster: str = "") -> list:
    """Group resource-level findings into (rule x owning workload) issues.

    The findings themselves are untouched and remain the evidence. Order is deterministic:
    worst severity first, then rule, then workload, so two runs of the same scan produce the
    same list and two reports of it can be diffed.
    """
    annotate(findings, cluster)
    grouped: dict = {}
    for finding in findings or []:
        grouped.setdefault(finding.aggregation_group, []).append(finding)
    issues = [WorkloadIssue(group, members, cluster)
              for group, members in grouped.items()]
    return sorted(issues, key=lambda i: (-i.severity.order, i.rule_id, i.workload_id))


def counts_by_severity(issues: list) -> dict:
    """{severity label -> number of workload issues}, in the same shape as the resource
    counts so the two can be shown side by side without a second vocabulary."""
    from .models import Severity
    tally: dict = {}
    for issue in issues or []:
        tally[issue.severity.label] = tally.get(issue.severity.label, 0) + 1
    return {s.label: tally.get(s.label, 0) for s in Severity}


def summarize(findings: list, issues: list) -> dict:
    """The two counts and how they relate, for any surface that reports both.

    `duplication_factor` is descriptive, never applied to anything: it says how much of the
    resource count is the ownership chain repeating itself, which is the thing that made the
    raw number hard to read in the first place.
    """
    from .aggregator import ResultAggregator
    findings = findings or []
    issues = issues or []
    derived = sum(1 for f in findings if getattr(f, "is_derived_resource", False))
    return {
        "resource_findings": len(findings),
        "workload_issues": len(issues),
        "derived_resource_findings": derived,
        "duplication_factor": (round(len(findings) / len(issues), 2)
                               if issues else 1.0),
        "resource_counts": ResultAggregator.counts(findings),
        "workload_counts": counts_by_severity(issues),
        "distinct_workloads": len({i.workload_id for i in issues}),
    }
