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


def correlate(findings: list[Finding], alerts: list) -> dict:
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
        resource_hit = _resource_matched(pod, ns, statics)
        ns_scoped = [f for f in statics if ns and f.resource.namespace == ns]
        if not statics:
            conf, verdict, matched = ("runtime-only",
                "unexpected runtime behaviour, no matching static weakness", [])
        elif resource_hit:
            conf, verdict, matched = ("confirmed",
                "static weakness on this resource is being actively exploited", resource_hit)
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
            "timestamp": _event_time(a.event),
            "source": a.source,
            "resource": pod,
            "namespace": ns,
            "runtime": _alert_view(a),
            "static_findings": [_finding_view(f) for f in matched[:5]],
            "related_finding": _finding_view(matched[0]) if matched else None,
        })

    correlations.sort(key=lambda c: Severity.parse(c["severity"]).order, reverse=True)
    return {
        "total_alerts": len(alerts),
        "correlated": sum(1 for c in correlations if c["static_findings"]),
        "confirmed_exploitation": sum(1 for c in correlations
                                      if c["confidence"] == "confirmed"),
        "runtime_only": sum(1 for c in correlations
                            if c["confidence"] == "runtime-only"),
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
