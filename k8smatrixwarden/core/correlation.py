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


def _resource_matched(pod: str, ns: str, statics: list) -> list:
    """Static findings whose resource IS the pod the runtime event names, or the workload
    that pod belongs to (pods are <workload>-<rs>-<hash>). Same-namespace required. This is
    the resource-level link that alone justifies 'confirmed exploitation'."""
    if not pod:
        return []
    out = []
    for f in statics:
        if ns and f.resource.namespace and f.resource.namespace != ns:
            continue
        rn = f.resource.name or ""
        if rn and (pod == rn or pod.startswith(rn + "-")):
            out.append(f)
    return out


def _alert_view(a) -> dict:
    return {"rule_id": a.rule_id, "title": a.title, "severity": a.severity.label,
            "source": a.source, "event": a.event}


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
            "confidence": conf,
            "verdict": verdict,
            "severity": sev.label,
            "runtime": _alert_view(a),
            "static_findings": [_finding_view(f) for f in matched[:5]],
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
    }


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
                "severity": "CRITICAL",
                "verdict": f"policy bypass, pod declares {declared!r} but runtime shows "
                           f"{observed}", "event": e})
    return {"pods_checked": len(by_pod), "events_seen": len(events),
            "drift_count": len(findings), "drift": findings}
