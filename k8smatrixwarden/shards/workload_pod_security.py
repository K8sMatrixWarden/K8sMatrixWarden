"""Shard ②, Workload & Pod Security (§5.4)."""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius, DetectionMethod as DM, Exploitability as EX,
                           MitreTag, Rule, Severity as S, Tactic as T)
from .base import DomainShard, ref as _base_ref

SHARD_NAME = "workload_pod_security"
WORKLOAD_KINDS = ["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"]
#: extra kinds only needed to resolve a Pod's owner chain one hop further than
#: shards/base.py's generic single-hop ref() can (ReplicaSet->Deployment, Job->CronJob), 
#: not iterated as scan targets themselves (see _iter), only looked up by name.
OWNER_LOOKUP_KINDS = WORKLOAD_KINDS + ["CronJob"]


def _iter(ev: Evidence):
    """Yield (resource, pod_spec, containers) for every workload in scope."""
    for kind in WORKLOAD_KINDS:
        for res in ev.get(kind):
            yield res, ev.pod_spec(res), ev.containers(res)


def _find(ev: Evidence, kind: str, name: str):
    if not kind or not name:
        return None
    return next((o for o in ev.get(kind, all_scopes=True)
                if (o.get("metadata") or {}).get("name") == name), None)


def ref(ev: Evidence, res: dict):
    """Pod/workload ResourceRef with the owner chain resolved as far as scan evidence
    allows: a Deployment-owned Pod's direct owner is a ReplicaSet, and a CronJob-owned
    Pod's direct owner is a Job, neither is the top-level controller a report should
    attribute the finding to. So resolve one hop further when the intermediate object is
    present in the evidence already fetched for this scan, and prefer the resolved
    *owner's* own labels/annotations over the Pod's own for Helm/ArgoCD/Flux detection
    (that's where those tools actually stamp their markers). If the hop can't be confirmed
    from evidence, the direct (unresolved) owner is kept as-is (no guessing)."""
    r = _base_ref(res)
    if res.get("kind") != "Pod" or not r.owner_kind:
        return r

    top_kind, top_name = r.owner_kind, r.owner_name
    if r.owner_kind == "ReplicaSet":
        rs = _find(ev, "ReplicaSet", r.owner_name)
        if rs:
            rs_kind, rs_name = _base_ref(rs).owner_kind, _base_ref(rs).owner_name
            if rs_kind == "Deployment":
                top_kind, top_name = rs_kind, rs_name
    elif r.owner_kind == "Job":
        job = _find(ev, "Job", r.owner_name)
        if job:
            job_kind, job_name = _base_ref(job).owner_kind, _base_ref(job).owner_name
            if job_kind == "CronJob":
                top_kind, top_name = job_kind, job_name

    labels, annotations = r.labels, r.annotations
    owner_obj = _find(ev, top_kind, top_name)
    if owner_obj:
        meta = owner_obj.get("metadata", {}) or {}
        labels = meta.get("labels", {}) or {}
        annotations = meta.get("annotations", {}) or {}

    import dataclasses
    return dataclasses.replace(r, owner_kind=top_kind, owner_name=top_name,
                               labels=labels, annotations=annotations)


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
                 owasp="K01", cis=["5.2.9"], evidence_needs=OWNER_LOOKUP_KINDS),
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
        ]


SHARD = WorkloadPodSecurityShard
