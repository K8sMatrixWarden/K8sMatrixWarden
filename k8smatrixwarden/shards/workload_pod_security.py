"""Shard ②, Workload & Pod Security (§5.4)."""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius, DetectionMethod as DM, Exploitability as EX,
                           MitreTag, Rule, Severity as S, Tactic as T)
from .base import DomainShard, ref as _base_ref, resolve_owner

SHARD_NAME = "workload_pod_security"
#: Every kind that carries a PodSpec of its own, and is therefore a scan target.
#:
#: CronJob belongs here. It was previously owner-lookup-only, on the reasoning that the
#: Jobs it spawns get scanned anyway. That leaves a real blind spot: a CronJob that has not
#: fired yet, or whose Jobs have been garbage-collected, has no Job to inherit the finding,
#: while its template still defines the privileged container that will run on the next
#: tick. "Kubernetes CronJob" is a Persistence technique in the threat matrix precisely
#: because the schedule outlives the pods.
WORKLOAD_KINDS = ["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job",
                  "CronJob"]
#: Kinds looked up by name to resolve a Pod's owner chain one hop further than
#: shards/base.py's generic single-hop ref() can (ReplicaSet->Deployment, Job->CronJob).
OWNER_LOOKUP_KINDS = list(WORKLOAD_KINDS)


def _iter(ev: Evidence):
    """Yield (resource, pod_spec, containers) for every workload in scope."""
    for kind in WORKLOAD_KINDS:
        for res in ev.get(kind):
            yield res, ev.pod_spec(res), ev.containers(res)


def ref(ev: Evidence, res: dict):
    """Pod/workload ResourceRef with the owner chain resolved past the intermediate
    controller (ReplicaSet->Deployment, Job->CronJob).

    Delegates to the shared `resolve_owner`, which is also applied centrally to every
    finding once rules have run. Kept here because these rules read the resolved owner's
    labels during evaluation (Helm/ArgoCD/Flux stamp their markers on the controller), and
    it is the same implementation either way rather than a second copy of it."""
    return resolve_owner(_base_ref(res), ev)


def _priv(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            if Evidence.dig(c, "securityContext.privileged") is True:
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' runs privileged "
                    f"(full host access)",
                    blast_radius=BlastRadius.CLUSTER, exploitability=EX.LOCAL,
                    evidence={"container": c.get("name"), "privileged": True})


def _run_as_root(rule, ev, scope):
    for res, spec, containers in _iter(ev):
        pod_nonroot = Evidence.dig(spec, "securityContext.runAsNonRoot")
        for c in containers:
            nonroot = Evidence.dig(c, "securityContext.runAsNonRoot")
            uid = Evidence.dig(c, "securityContext.runAsUser")
            effective_nonroot = nonroot if nonroot is not None else pod_nonroot
            if uid == 0 or (effective_nonroot is not True and uid in (None, 0)):
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' may run as root "
                    f"(runAsNonRoot not enforced)",
                    evidence={"container": c.get("name"), "runAsUser": uid})


def _allow_priv_esc(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            ape = Evidence.dig(c, "securityContext.allowPrivilegeEscalation")
            if ape is True or ape is None:
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' allows privilege escalation "
                    f"(allowPrivilegeEscalation not false)",
                    evidence={"container": c.get("name")})


def _writable_root_fs(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            if Evidence.dig(c, "securityContext.readOnlyRootFilesystem") is not True:
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' has a writable root "
                    f"filesystem (readOnlyRootFilesystem not true)",
                    evidence={"container": c.get("name")})


_DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "NET_RAW", "DAC_OVERRIDE", "NET_ADMIN",
                   "SYS_MODULE", "BPF"}


def _dangerous_caps(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            added = set(Evidence.dig(c, "securityContext.capabilities.add", []) or [])
            hit = added & _DANGEROUS_CAPS
            if hit:
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' adds dangerous "
                    f"capabilities: {', '.join(sorted(hit))}",
                    evidence={"container": c.get("name"), "capabilities": sorted(hit)})


def _caps_not_dropped(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            dropped = set(Evidence.dig(c, "securityContext.capabilities.drop", []) or [])
            if "ALL" not in dropped:
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' does not drop ALL "
                    f"capabilities",
                    evidence={"container": c.get("name"), "dropped": sorted(dropped)})


def _host_ns(field, tactic_name):
    def _check(rule, ev, scope):
        for res, spec, _c in _iter(ev):
            if spec.get(field) is True:
                yield rule.finding(
                    ref(ev, res), f"workload shares host {field} namespace",
                    blast_radius=BlastRadius.NAMESPACE,
                    evidence={field: True})
    return _check


def _docker_socket(rule, ev, scope):
    for res, spec, _c in _iter(ev):
        for vol in spec.get("volumes", []) or []:
            path = Evidence.dig(vol, "hostPath.path") or ""
            if "docker.sock" in path:
                yield rule.finding(
                    ref(ev, res), f"mounts the Docker socket ({path}), container escape",
                    blast_radius=BlastRadius.CLUSTER,
                    evidence={"volume": vol.get("name"), "path": path})


def _hostpath_root(rule, ev, scope):
    for res, spec, _c in _iter(ev):
        for vol in spec.get("volumes", []) or []:
            path = Evidence.dig(vol, "hostPath.path")
            if path == "/" or path in ("/etc", "/var/run", "/etc/kubernetes/manifests"):
                yield rule.finding(
                    ref(ev, res), f"mounts sensitive hostPath '{path}', full/host-critical "
                    f"filesystem access",
                    blast_radius=BlastRadius.CLUSTER,
                    evidence={"volume": vol.get("name"), "path": path})


def _hostpath_writable(rule, ev, scope):
    for res, spec, _c in _iter(ev):
        for vol in spec.get("volumes", []) or []:
            hp = vol.get("hostPath")
            path = (hp or {}).get("path")
            if hp and path not in (None, "/") and path not in (
                    "/etc", "/var/run", "/etc/kubernetes/manifests"):
                yield rule.finding(
                    ref(ev, res), f"mounts a writable hostPath '{path}' (persistence / "
                    f"lateral movement vector)",
                    blast_radius=BlastRadius.NAMESPACE,
                    evidence={"volume": vol.get("name"), "path": path})


def _missing_limits(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            limits = Evidence.dig(c, "resources.limits")
            if not limits:
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' has no resource limits "
                    f"(DoS amplification)",
                    evidence={"container": c.get("name")})


def _no_seccomp(rule, ev, scope):
    for res, spec, containers in _iter(ev):
        pod_seccomp = Evidence.dig(spec, "securityContext.seccompProfile.type")
        for c in containers:
            c_seccomp = Evidence.dig(c, "securityContext.seccompProfile.type")
            if not (c_seccomp or pod_seccomp):
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' has no seccomp profile",
                    evidence={"container": c.get("name")})
            break  # one finding per workload is enough for seccomp


def _sa_automount(rule, ev, scope):
    for res, spec, _c in _iter(ev):
        if spec.get("automountServiceAccountToken") is not False:
            yield rule.finding(
                ref(ev, res), "service-account token is auto-mounted "
                "(automountServiceAccountToken not false)",
                evidence={"automount": spec.get("automountServiceAccountToken")})


def _latest_tag(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            image = c.get("image", "")
            if image.endswith(":latest") or (":" not in image.split("/")[-1]
                                             and "@" not in image):
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' uses a mutable/unpinned "
                    f"image tag: {image}",
                    evidence={"container": c.get("name"), "image": image})


def _sshd(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            cmd = " ".join(c.get("command", []) or []) + " " + \
                  " ".join(c.get("args", []) or [])
            if "sshd" in cmd or "sshd" in (c.get("image", "")):
                yield rule.finding(
                    ref(ev, res), f"container '{c.get('name')}' appears to run an SSH server",
                    evidence={"container": c.get("name")})


def _host_port(rule, ev, scope):
    for res, _spec, containers in _iter(ev):
        for c in containers:
            for port in c.get("ports", []) or []:
                if port.get("hostPort"):
                    yield rule.finding(
                        ref(ev, res), f"container '{c.get('name')}' binds hostPort "
                        f"{port['hostPort']} on the node",
                        evidence={"container": c.get("name"), "hostPort": port["hostPort"]})


def _share_process_ns(rule, ev, scope):
    for res, spec, _c in _iter(ev):
        if spec.get("shareProcessNamespace") is True:
            yield rule.finding(ref(ev, res), "containers share one process namespace, so each "
                               "can see and signal the others' processes")


def _no_security_context(rule, ev, scope):
    for res, spec, containers in _iter(ev):
        if not spec.get("securityContext") and not any(c.get("securityContext")
                                                       for c in containers):
            yield rule.finding(ref(ev, res), "no securityContext on the pod or any container")


def _host_process(rule, ev, scope):
    for res, spec, containers in _iter(ev):
        flags = [Evidence.dig(spec, "securityContext.windowsOptions.hostProcess")] + \
                [Evidence.dig(c, "securityContext.windowsOptions.hostProcess") for c in containers]
        if any(f is True for f in flags):
            yield rule.finding(ref(ev, res), "Windows HostProcess container runs directly "
                               "on the node", blast_radius=BlastRadius.CLUSTER)


def _default_namespace(rule, ev, scope):
    for res, _spec, _c in _iter(ev):
        if (res.get("metadata", {}) or {}).get("namespace") == "default":
            yield rule.finding(ref(ev, res), "workload runs in the default namespace")


_VULN_SEV = {"Critical": S.CRITICAL, "High": S.HIGH, "Medium": S.MEDIUM}


def _vuln_exploitability(kev: list, epss: float):
    """How likely a CVE is to be used, from outside evidence rather than a guess.

    Known-exploited (CISA KEV) or an EPSS score of 0.5+ is treated like a remotely usable
    flaw (3). EPSS 0.05+ is adjacent (2). Everything else is local (1): a theoretical CVE
    adds little on its own, and the reachability multiplier still raises it when the pod
    is Internet-facing. EPSS is Grype's own field; when absent it counts as 0."""
    if kev or epss >= 0.5:
        return EX.REMOTE
    return EX.ADJACENT if epss >= 0.05 else EX.LOCAL


def _image_vulns(rule, ev, scope):
    """One finding per running pod image whose Grype result has a fixable or known-exploited
    Medium-or-worse vulnerability. Looks the image up by the digest the pod is running, so a
    rebuilt (patched) image under the same tag is judged on its own contents."""
    by_digest, by_ref = {}, {}
    for it in ev.get("ImageVulnerability", all_scopes=True):
        spec = it.get("spec", {}) or {}
        if "error" in spec:
            continue
        if spec.get("digest"):
            by_digest[spec["digest"]] = spec
        by_ref.setdefault(spec.get("image"), spec)
    for pod in ev.get("Pod"):
        statuses = ((pod.get("status", {}) or {}).get("containerStatuses") or []) + \
                   ((pod.get("status", {}) or {}).get("initContainerStatuses") or [])
        for cs in statuses:
            digest = (cs.get("imageID") or "").rpartition("@")[2] or cs.get("imageID") or ""
            spec = by_digest.get(digest) or (by_ref.get(cs.get("image")) if not digest.startswith("sha256:") else None)
            if not spec:
                continue
            matches = [m for m in spec.get("matches", []) if m["severity"] in _VULN_SEV
                       or m["knownExploited"]]
            kev = [m for m in matches if m["knownExploited"]]
            fixable = [m for m in matches if m["fixState"] == "fixed"]
            pool = kev or fixable
            if not pool:
                continue          # nothing to patch and nothing actively exploited
            worst_epss = max((m["epss"] for m in matches), default=0)
            sev = S.CRITICAL if kev else max((_VULN_SEV.get(m["severity"], S.MEDIUM) for m in pool),
                                             key=lambda s: s.value)
            if worst_epss >= 0.5 and sev is not S.CRITICAL:
                sev = S.HIGH if sev is S.MEDIUM else S.CRITICAL      # likely to be exploited soon
            counts = {}
            for m in matches:
                counts[m["severity"]] = counts.get(m["severity"], 0) + 1
            top = sorted(matches, key=lambda m: (not m["knownExploited"], m["severity"] != "Critical",
                                                 -m["epss"]))[:10]
            yield rule.finding(
                ref(ev, pod), f"image {spec.get('image')} has {len(matches)} vulnerabilities "
                f"({len(fixable)} with a fix available, {len(kev)} known to be exploited)",
                severity=sev, exploitability=_vuln_exploitability(kev, worst_epss),
                evidence={"container": cs.get("name"), "image": spec.get("image"),
                          "digest": spec.get("digest"), "counts": counts, "top": top,
                          "scanner": "grype", "dbBuilt": spec.get("dbBuilt")})


class WorkloadPodSecurityShard(DomainShard):
    name = SHARD_NAME
    title = "Workload & Pod Security"
    index = "②"

    def rules(self):
        M = MitreTag
        return [
            Rule("workload-privileged-container", "Privileged container", self.name,
                 ["Pod"], S.CRITICAL, DM.STATIC_CONFIG, _priv,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Deploy Container"),
                        M(T.EXECUTION, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.2.2"], nsa_cisa=["Pod Security"],
                 evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-run-as-root", "Container runs as root", self.name,
                 ["Pod"], S.HIGH, DM.STATIC_CONFIG, _run_as_root,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.2.7"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-allow-priv-escalation", "Privilege escalation allowed",
                 self.name, ["Pod"], S.HIGH, DM.STATIC_CONFIG, _allow_priv_esc,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1548", "Abuse Elevation Control")],
                 owasp="K01", cis=["5.2.6"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-writable-root-fs", "Writable root filesystem", self.name,
                 ["Pod"], S.MEDIUM, DM.STATIC_CONFIG, _writable_root_fs,
                 mitre=[M(T.PERSISTENCE, "T1610", "Deploy Container")],
                 owasp="K01", evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-dangerous-caps", "Dangerous capabilities added", self.name,
                 ["Pod"], S.HIGH, DM.STATIC_CONFIG, _dangerous_caps,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Deploy Container"),
                        M(T.LATERAL_MOVEMENT, "T1610", "ARP poisoning / IP spoofing")],
                 owasp="K01", cis=["5.2.8", "5.2.9"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-caps-not-dropped", "Capabilities not dropped (ALL)", self.name,
                 ["Pod"], S.HIGH, DM.STATIC_CONFIG, _caps_not_dropped,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.2.9", "5.2.10"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-host-pid", "Host PID namespace shared", self.name, ["Pod"],
                 S.CRITICAL, DM.STATIC_CONFIG, _host_ns("hostPID", "Disable Namespacing"),
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Disable namespacing (host PID/IPC/net)")],
                 owasp="K01", cis=["5.2.3"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-host-network", "Host network shared", self.name, ["Pod"],
                 S.HIGH, DM.STATIC_CONFIG, _host_ns("hostNetwork", "Disable Namespacing"),
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Disable namespacing (host PID/IPC/net)"),
                        M(T.DISCOVERY, "T1046", "Network Service Discovery")],
                 owasp="K01", cis=["5.2.5"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-host-ipc", "Host IPC namespace shared", self.name, ["Pod"],
                 S.HIGH, DM.STATIC_CONFIG, _host_ns("hostIPC", "Disable Namespacing"),
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Disable namespacing (host PID/IPC/net)")],
                 owasp="K01", cis=["5.2.4"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-docker-socket", "Docker socket mounted", self.name, ["Pod"],
                 S.CRITICAL, DM.STATIC_CONFIG, _docker_socket,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1611", "Escape to Host")],
                 owasp="K01", nsa_cisa=["Pod Security"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-hostpath-root", "Sensitive hostPath mount", self.name, ["Pod"],
                 S.CRITICAL, DM.STATIC_CONFIG, _hostpath_root,
                 mitre=[M(T.PERSISTENCE, "T1610", "Deploy Container"),
                        M(T.PRIVILEGE_ESCALATION, "T1611", "hostPath mount"),
                        M(T.LATERAL_MOVEMENT, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.2.12"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-hostpath-writable", "Writable hostPath mount", self.name,
                 ["Pod"], S.HIGH, DM.STATIC_CONFIG, _hostpath_writable,
                 mitre=[M(T.PERSISTENCE, "T1610", "Writable hostPath mount"),
                        M(T.LATERAL_MOVEMENT, "T1610", "Writable volume mounts on host")],
                 owasp="K01", cis=["5.2.12"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-missing-limits", "Missing resource limits", self.name, ["Pod"],
                 S.MEDIUM, DM.STATIC_CONFIG, _missing_limits,
                 mitre=[M(T.IMPACT, "T1499", "Endpoint Denial of Service")],
                 owasp="K01", evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-no-seccomp", "No seccomp profile", self.name, ["Pod"],
                 S.MEDIUM, DM.STATIC_CONFIG, _no_seccomp,
                 mitre=[M(T.DEFENSE_EVASION, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.7.2"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-sa-token-automount", "SA token auto-mounted", self.name,
                 ["Pod"], S.MEDIUM, DM.STATIC_CONFIG, _sa_automount,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1528", "Access container service account")],
                 owasp="K03", cis=["5.1.6"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-latest-tag", "Mutable :latest image tag", self.name, ["Pod"],
                 S.MEDIUM, DM.IMAGE, _latest_tag,
                 mitre=[M(T.INITIAL_ACCESS, "T1525", "Implant Internal Image")],
                 owasp="K07", evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-sshd-present", "SSH server inside container", self.name,
                 ["Pod"], S.HIGH, DM.IMAGE, _sshd,
                 mitre=[M(T.EXECUTION, "T1610", "SSH server running inside container")],
                 owasp="K01", evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-host-port", "Container uses hostPort", self.name, ["Pod"],
                 S.MEDIUM, DM.STATIC_CONFIG, _host_port,
                 mitre=[M(T.LATERAL_MOVEMENT, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.2.13"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-share-process-ns", "Shared process namespace", self.name, ["Pod"],
                 S.MEDIUM, DM.STATIC_CONFIG, _share_process_ns,
                 mitre=[M(T.LATERAL_MOVEMENT, "T1610", "Deploy Container")],
                 owasp="K01", evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-no-security-context", "No securityContext", self.name, ["Pod"],
                 S.MEDIUM, DM.STATIC_CONFIG, _no_security_context,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.7.3"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-windows-hostprocess", "Windows HostProcess container", self.name,
                 ["Pod"], S.CRITICAL, DM.STATIC_CONFIG, _host_process,
                 mitre=[M(T.PRIVILEGE_ESCALATION, "T1611", "Escape to Host")],
                 owasp="K01", cis=["5.2.11"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-default-namespace", "Workload in the default namespace", self.name,
                 ["Pod"], S.LOW, DM.STATIC_CONFIG, _default_namespace,
                 mitre=[M(T.DEFENSE_EVASION, "T1610", "Deploy Container")],
                 owasp="K01", cis=["5.7.4"], evidence_needs=OWNER_LOOKUP_KINDS),
            Rule("workload-image-vulnerabilities", "Running image has known vulnerabilities",
                 self.name, ["Pod", "ImageVulnerability"], S.HIGH, DM.IMAGE, _image_vulns,
                 mitre=[M(T.INITIAL_ACCESS, "T1190", "Exploit Public-Facing Application")],
                 owasp="K07", evidence_needs=["Pod", "ImageVulnerability"] + OWNER_LOOKUP_KINDS),
        ]


SHARD = WorkloadPodSecurityShard
