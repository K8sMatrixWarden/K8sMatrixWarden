"""
Scan × Runtime correlation (§8), the "is this static weakness being exploited RIGHT NOW"
layer that no plain scanner has.

A Scanner finding says "this config is weak" (point-in-time). A Runtime alert says "this
behaviour just happened" (live stream). Alone, each is half the picture. Correlated, they
answer the question a responder actually has: *of everything the scan flagged, which ones
is an attacker acting on?*

Join key is the MITRE tactic both sides already carry (the mapping contract, §6.2): a
runtime alert tagged Privilege Escalation lines up with the scan findings tagged Privilege
Escalation. Confidence is tiered by how tightly the two sides actually match, because
"confirmed exploitation" is a strong claim it is reserved for a RESOURCE-level match:

  confirmed   , the runtime event names a pod that IS (or belongs to) the exact resource a
                 static finding is on, same namespace. This is the only tier that says
                 "this specific weakness is being acted on".
  corroborated, same tactic (and often same namespace) but no resource-level link. The
                 behaviour aligns with a known weakness class here, but we cannot prove it
                 is THIS finding, do not report it as exploited.
  runtime-only, a runtime alert with NO matching static finding (novel behaviour the scan
                 never predicted, often the most interesting).

A tactic+namespace coincidence is NOT proof of exploitation, so it is corroborated, never
confirmed.

Pure function of (findings, alerts): no cluster access, no scan re-run. Reuses the tactics
already on each Finding and RuntimeAlert.
"""
from __future__ import annotations

from typing import Optional

from .evidence import Evidence
from .models import Finding, Severity


def _event_ns(event: dict) -> str:
    """Namespace the runtime event happened in, if it carries one. Falco enriches with
    k8s.ns.name; audit events carry `namespace` directly. Empty when unknown."""
    return str(event.get("namespace") or event.get("k8s.ns.name") or "").strip()


def _event_pod(event: dict) -> str:
    return str(event.get("pod") or event.get("k8s.pod.name") or "").strip()


#: Kubernetes' generated pod-name suffix alphabet: base-32 with vowels and easily-confused
#: digits removed, exactly 5 characters (k8s.io/apimachinery/pkg/util/rand). A segment
#: drawn from it is a generated suffix; an English word is not.
_RAND_ALPHABET = set("bcdfghjklmnpqrstvwxz2456789")


def _looks_generated(segment: str) -> bool:
    """Is this pod-name segment a Kubernetes-generated suffix rather than part of a name?

    Three shapes occur in practice:
      * `9zskz`      , the 5-char rand suffix every generated pod carries
      * `5f9586cd5b` , a ReplicaSet's pod-template hash
      * `0`, `12`    , a StatefulSet's ordinal
    A human-authored word such as `server` matches none of them.
    """
    if not segment:
        return False
    if segment.isdigit():                                   # StatefulSet ordinal
        return True
    # Kubernetes emits exactly 5; 3-5 is accepted so a shortened or synthetic name is not
    # a false negative. The alphabet is the discriminator, not the length: it excludes
    # every vowel, so an English word such as `server` can never match.
    if 3 <= len(segment) <= 5 and set(segment) <= _RAND_ALPHABET:  # generated pod suffix
        return True
    # ReplicaSet template hash: alphanumeric, of hash length, and containing a digit,
    # which is what separates `5f9586cd5b` from `deployment`.
    return (5 <= len(segment) <= 11 and segment.isalnum() and segment.islower()
            and any(c.isdigit() for c in segment))


def belongs_to(pod: str, workload: str) -> bool:
    """Is `pod` an instance of the workload named `workload`?

    Kubernetes names generated pods `<workload>-<suffix>` (Job, DaemonSet, StatefulSet) or
    `<workload>-<template-hash>-<suffix>` (Deployment, via its ReplicaSet). A bare prefix
    test gets this dangerously wrong: `api-server-7d9f-xk2` starts with `api-`, so a
    finding on workload `api` was reported as CONFIRMED EXPLOITATION on the strength of an
    event about the unrelated workload `api-server`. Confirmed exploitation is the
    strongest claim this tool makes, so the suffix must actually look generated.
    """
    if pod == workload:
        return True
    if not workload or not pod.startswith(workload + "-"):
        return False
    suffix = pod[len(workload) + 1:]
    segments = suffix.split("-")
    if not 1 <= len(segments) <= 2:      # deeper nesting means a different workload name
        return False
    return all(_looks_generated(seg) for seg in segments)


def _event_cluster(event: dict) -> str:
    """Cluster the runtime event came from, if the feed labelled it.

    Falco does not emit this natively, but a multi-cluster falcosidekick deployment
    routinely adds it (`customfields`, or a `cluster` output field), and one endpoint
    receiving several clusters' alerts is a normal topology. When the label IS present and
    names a different cluster than the scan, the event is about a different cluster's pod
    that merely shares a name, so it cannot confirm anything here.
    """
    return str(event.get("cluster") or event.get("k8s.cluster.name") or "").strip()


def _cluster_conflicts(event: dict, cluster: str) -> bool:
    """True only when both sides name a cluster AND they disagree. An unlabelled event is
    not evidence of a mismatch, so it is not treated as one."""
    seen = _event_cluster(event)
    return bool(seen and cluster and seen != cluster)


def _resource_matched(pod: str, ns: str, statics: list) -> list:
    """Static findings whose resource IS the pod the runtime event names, or the workload
    that pod belongs to. This is the resource-level link that alone justifies 'confirmed
    exploitation', so both halves of the identity must hold:

      name      , the pod is that resource, or a generated instance of it (`_belongs_to`)
      namespace , the event names the SAME namespace the finding is in

    An event that carries no namespace cannot establish the second half. Two clusters, or
    two namespaces, routinely run identically named workloads, so confirming without a
    namespace is a guess. Such an event still correlates, as `corroborated`.
    """
    if not pod or not ns:
        return []
    out = []
    for f in statics:
        if f.resource.namespace and f.resource.namespace != ns:
            continue
        if belongs_to(pod, f.resource.name or ""):
            out.append(f)
    return out


def _event_time(event: dict) -> str:
    """When the runtime event happened, as the source reported it ('' when it didn't).
    Kept verbatim rather than reformatted, so it stays comparable to the source's own
    logs during an investigation."""
    return str(event.get("time") or event.get("evt.time") or "").strip()


def _alert_view(a) -> dict:
    return {"rule_id": a.rule_id, "title": a.title, "severity": a.severity.label,
            "source": a.source, "surface": getattr(a, "surface", "runtime"),
            "timestamp": _event_time(a.event), "event": a.event}


def _finding_view(f: Finding) -> dict:
    return {"rule_id": f.rule_id, "title": f.title, "severity": f.severity.label,
            "resource": str(f.resource), "shard": f.owning_shard}


#: How old a runtime event may be before it stops counting as a CURRENT observation.
#: An event that genuinely happened is never discarded, it is relabelled: `historical`
#: evidence tells a responder the behaviour was seen, without asserting it is happening
#: now. Seven days is a deliberate, documented choice, not a Kubernetes constant.
RUNTIME_FRESHNESS_DAYS = 7


def _age_days(timestamp: str, now: str) -> Optional[float]:
    """Age of an event in days, or None when either side cannot be parsed. Unparseable
    means unknown, and unknown must not be treated as fresh OR as stale."""
    import datetime as _dt

    def _parse(value):
        try:
            return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    a, b = _parse(timestamp), _parse(now)
    if a is None or b is None:
        return None
    if a.tzinfo is None:
        a = a.replace(tzinfo=_dt.timezone.utc)
    if b.tzinfo is None:
        b = b.replace(tzinfo=_dt.timezone.utc)
    return (b - a).total_seconds() / 86400.0


def correlate(findings: list[Finding], alerts: list, cluster: str = "",
              now: str = "") -> dict:
    """Cross-reference static scan findings with live runtime alerts. Returns the
    correlations worst-first plus the headline counts a responder/leader reads first."""
    by_tactic: dict[str, list[Finding]] = {}
    for f in findings:
        for t in f.tactics:
            by_tactic.setdefault(t.value, []).append(f)

    correlations = []
    for a in alerts:
        statics = by_tactic.get(a.tactic, [])
        ns, pod = _event_ns(a.event), _event_pod(a.event)
        # A feed aggregating several clusters can deliver an event about a pod that merely
        # shares a name with one here. When the event names a cluster and it is not this
        # one, resource identity does not hold, so it cannot confirm.
        foreign = _cluster_conflicts(a.event, cluster)
        stamp = _event_time(a.event)
        age = _age_days(stamp, now) if now else None
        stale = age is not None and age > RUNTIME_FRESHNESS_DAYS
        resource_hit = [] if foreign else _resource_matched(pod, ns, statics)
        ns_scoped = [f for f in statics if ns and f.resource.namespace == ns]
        if not statics:
            conf, verdict, matched = ("runtime-only",
                "unexpected runtime behaviour, no matching static weakness", [])
        elif resource_hit:
            conf, verdict, matched = ("confirmed",
                "static weakness on this resource is being actively exploited", resource_hit)
        elif foreign:
            conf, verdict, matched = ("corroborated",
                f"event is labelled cluster {_event_cluster(a.event)!r}, not "
                f"{cluster!r}; a same-named pod in another cluster cannot confirm this "
                f"finding", ns_scoped or statics)
        else:
            # same tactic (± namespace) but no resource-level link, aligns, not proven.
            conf, verdict, matched = ("corroborated",
                "runtime behaviour aligns with a known static weakness (no resource-level "
                "link, not proof this finding is exploited)", ns_scoped or statics)
        sev = max([a.severity] + [f.severity for f in matched],
                  key=lambda s: s.order)
        correlations.append({
            "tactic": a.tactic,
            # `confidence` is the historic key; `correlation_level` is the same value under
            # the name §8 asks for. Both are emitted so nothing downstream breaks.
            "confidence": conf,
            "correlation_level": conf,
            "verdict": verdict,
            "reason": _reason(conf, pod, ns, matched),
            "severity": sev.label,
            "timestamp": stamp,
            # Freshness is reported, never used to silently discard evidence: an event that
            # happened, happened. `historical` says the behaviour WAS seen without
            # asserting it is happening now, which is what "observed" would imply.
            "age_days": None if age is None else round(age, 2),
            "freshness": ("unknown" if age is None
                          else ("historical" if stale else "recent")),
            "source": a.source,
            "cluster": _event_cluster(a.event) or (cluster or None),
            "resource": pod,
            "namespace": ns,
            "runtime": _alert_view(a),
            "static_findings": [_finding_view(f) for f in matched[:5]],
            "related_finding": _finding_view(matched[0]) if matched else None,
        })

    correlations.sort(key=lambda c: Severity.parse(c["severity"]).order, reverse=True)

    # Alert VOLUME and evidence STRENGTH are different quantities and are reported
    # separately. A shell held open in one container emits the same Falco alert repeatedly;
    # counting each copy turned one observation into "50 confirmed exploitations", which
    # overstates the incident to exactly the audience least able to check it. Strength is
    # therefore counted over distinct (weakness, resource) pairs, while `total_alerts`
    # keeps reporting the raw volume.
    def _distinct(predicate) -> int:
        return len({((c.get("runtime") or {}).get("rule_id"), c["tactic"],
                     c["namespace"], c["resource"])
                    for c in correlations if predicate(c)})

    return {
        "total_alerts": len(alerts),
        "correlated": _distinct(lambda c: c["static_findings"]),
        "confirmed_exploitation": _distinct(lambda c: c["confidence"] == "confirmed"),
        "runtime_only": _distinct(lambda c: c["confidence"] == "runtime-only"),
        "correlations": correlations,
        # The same correlations in the order they HAPPENED, which is how an incident is
        # read. Events with no timestamp sort last rather than being dropped.
        "timeline": sorted(correlations,
                           key=lambda c: (c["timestamp"] == "", c["timestamp"])),
    }


def _reason(level: str, pod: str, ns: str, matched: list) -> str:
    """Why this correlation got the confidence it did, in one line an analyst can audit."""
    where = f"pod {pod!r}" + (f" in ns/{ns}" if ns else "")
    if level == "confirmed":
        return (f"runtime event names {where}, which is (or belongs to) the resource "
                f"{matched[0].resource} the static finding is on")
    if level == "corroborated":
        if not pod:
            return ("runtime event shares the tactic with static findings but names no "
                    "resource, so no resource-level link can be established")
        return (f"runtime event names {where}, which does not match any static finding's "
                f"resource; shared tactic only")
    return "no static finding carries this tactic, nothing to link the behaviour to"


# --------------------------------------------------------------------------- #
# Drift detection, declared config vs observed runtime behaviour
# --------------------------------------------------------------------------- #
#: Paths a readOnlyRootFilesystem pod is still allowed to write (mounted rw by design).
_WRITABLE_PREFIXES = ("/tmp", "/var/tmp", "/dev", "/proc", "/run", "/var/run")
_WRITE_OPS = {"write", "openwrite", "open_write", "truncate", "rename", "unlink"}
#: Ops/binaries only a privileged (or extra-capability) container can perform.
_PRIV_PROCS = {"nsenter", "mount", "insmod", "modprobe", "umount"}


def _declared_posture(pod: dict) -> dict:
    """What the Pod spec *promises* about its security posture. A promise the runtime can
    then contradict. Pod-level securityContext applies to all containers; a container-level
    setting overrides it, so a promise holds only when EVERY container keeps it."""
    pod_sc = Evidence.dig(pod, "spec.securityContext") or {}
    containers = Evidence.containers(pod)

    def _all(field: str) -> bool:
        # true only if pod-level sets it OR every container sets it (no gap to exploit)
        if pod_sc.get(field) is True:
            return True
        return bool(containers) and all(
            (c.get("securityContext", {}) or {}).get(field) is True for c in containers)

    non_root = _all("runAsNonRoot") or (pod_sc.get("runAsUser") not in (None, 0)
                                        and pod_sc.get("runAsUser") != 0)
    # never privileged: no container asks for it (the common, promised case)
    non_privileged = all(not (c.get("securityContext", {}) or {}).get("privileged")
                         for c in containers) if containers else True
    return {"non_root": bool(non_root),
            "read_only_fs": _all("readOnlyRootFilesystem"),
            "non_privileged": non_privileged}


def detect_drift(pods: list[dict], events: list[dict]) -> dict:
    """Flag runtime behaviour that contradicts a Pod's declared security posture, the
    strongest signal there is, because it means a control the operator THINKS is in place
    is not (either a container escape, or the policy never actually applied). Needs events
    that name their pod (Falco k8s.pod.name enrichment); un-attributable events are skipped.
    """
    by_pod: dict[tuple, dict] = {}
    for p in pods:
        meta = p.get("metadata", {}) or {}
        by_pod[(meta.get("namespace") or "", meta.get("name") or "")] = _declared_posture(p)

    findings = []
    for e in events:
        name, ns = _event_pod(e), _event_ns(e)
        posture = by_pod.get((ns, name))
        if posture is None:
            continue  # ponytail: can't attribute event to a scanned pod, skip (no guessing)
        uid, op = str(e.get("uid", "")), str(e.get("op", "")).lower()
        f = str(e.get("file", ""))
        proc = str(e.get("proc", ""))
        drift = None
        if posture["non_root"] and (uid == "0" or e.get("user") == "root"):
            drift = ("runAsNonRoot", "runAsNonRoot: true", "process running as uid 0",
                     "Privilege Escalation")
        elif posture["read_only_fs"] and op in _WRITE_OPS and f and \
                not f.startswith(_WRITABLE_PREFIXES):
            drift = ("readOnlyRootFilesystem", "readOnlyRootFilesystem: true",
                     f"write to {f}", "Defense Evasion")
        elif posture["non_privileged"] and (proc in _PRIV_PROCS or "release_agent" in f):
            drift = ("privileged", "not privileged",
                     f"privileged operation ({proc or f})", "Privilege Escalation")
        if drift:
            policy, declared, observed, tactic = drift
            findings.append({
                "pod": name, "namespace": ns, "policy": policy,
                "declared": declared, "observed": observed, "tactic": tactic,
                "severity": "CRITICAL", "timestamp": _event_time(e),
                "source": str(e.get("source", "")),
                "verdict": f"policy bypass, pod declares {declared!r} but runtime shows "
                           f"{observed}", "event": e})
    findings.sort(key=lambda d: (d["timestamp"] == "", d["timestamp"]))
    return {"pods_checked": len(by_pod), "events_seen": len(events),
            "drift_count": len(findings), "drift": findings}
