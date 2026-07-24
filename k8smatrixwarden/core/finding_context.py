"""
Finding Context, the single source of "report-grade" content for a finding.

Every professional scanner report (Nessus, Qualys, Prisma Cloud, Trivy...) presents a
finding as more than a one-line message: a plain-English summary, which named standard or
benchmark it's drawn from (with a reference link), the MITRE ATT&CK mapping (with a
reference link), the real-world impact if left unaddressed, and how to independently
verify/reproduce it. This module is where all of that content is authored ONCE and shared
by every report renderer (markdown, html, json, sarif, pdf, terminal), so no format can
drift from another about what a finding means.

`FINDING_CONTEXT` holds hand-written summary/impact/validation content for every rule in
the registry (56, at the time of writing). A rule that somehow isn't in the KB yet (e.g. a
newly added one) still gets a sensible, non-empty fallback generated from its own tags, 
never a blank section in a report.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .models import Finding

# --------------------------------------------------------------------------------- #
# Reference links, real, stable URLs. No per-control deep link exists for CIS (the
# benchmark PDF requires free registration, with no addressable per-control anchor), so
# CIS/NSA-CISA link to the source document itself; the control/section number is carried
# alongside the link so a reader can locate it there. MITRE technique links ARE
# individually addressable and are computed exactly, including the sub-technique
# slash-notation MITRE's own site uses (T1552.007 -> .../T1552/007/).
# --------------------------------------------------------------------------------- #
CIS_BENCHMARK_URL = "https://www.cisecurity.org/benchmark/kubernetes"
NSA_CISA_URL = ("https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/"
               "CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF")
OWASP_K8S_TOP10_URL = "https://owasp.org/www-project-kubernetes-top-ten/"
POD_SECURITY_STANDARDS_URL = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
MITRE_ATTACK_CONTAINERS_URL = "https://attack.mitre.org/matrices/enterprise/containers/"


def mitre_technique_url(technique_id: str) -> str:
    """T1610 -> .../techniques/T1610/ ; T1552.007 -> .../techniques/T1552/007/ (MITRE's
    own site uses a slash, not a dot, for the sub-technique segment)."""
    tid = (technique_id or "").strip()
    if "." in tid:
        main, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{main}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


_OWASP: Optional[dict] = None


def _owasp_taxonomy() -> dict:
    global _OWASP
    if _OWASP is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "taxonomy", "owasp_k8s_top10.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _OWASP = json.load(fh)
        except Exception:
            _OWASP = {}
    return _OWASP


def _owasp_names() -> dict:
    return _owasp_taxonomy().get("categories", {}) or {}


def owasp_url(code: Optional[str]) -> str:
    """The direct owasp.org page for one Top-10 category (K01 … K10), e.g. K03 ->
    .../2025/en/src/K03-Secrets-Management-Failures.html. Falls back to the project
    landing page for an unknown code, so a link is never dead."""
    urls = _owasp_taxonomy().get("urls", {}) or {}
    return urls.get((code or "").strip().upper()) or OWASP_K8S_TOP10_URL


# --------------------------------------------------------------------------------- #
@dataclass(frozen=True)
class StandardRef:
    """One named standard/benchmark/policy a finding is drawn from."""
    framework: str          # e.g. "CIS Kubernetes Benchmark v1.8"
    control: str            # e.g. "5.2.2", "K01", "Pod Security"
    title: str               # human-readable label for the control
    url: str


@dataclass(frozen=True)
class MitreRef:
    """One MITRE ATT&CK for Containers mapping a finding is tagged with."""
    tactic: str
    technique_id: str
    technique_name: str
    url: str


@dataclass
class FindingContext:
    """Everything a report renderer needs to write a full, professional finding
    section, beyond what's already on the Finding object."""
    summary: str
    impact: str
    validation_steps: list = field(default_factory=list)
    standards: list = field(default_factory=list)     # list[StandardRef]
    mitre: list = field(default_factory=list)          # list[MitreRef]


_CIS_TITLES: Optional[dict] = None


def _cis_titles() -> dict:
    """The real, official CIS control titles (e.g. "Minimize the admission of privileged
    containers" for 5.2.2), sourced from the same vendored catalog the CIS Benchmark
    Engine itself evaluates against (frameworks/cis_catalog.py), never a generic
    "Control X.Y.Z" placeholder."""
    global _CIS_TITLES
    if _CIS_TITLES is None:
        try:
            from ..frameworks.cis_catalog import CIS_1_8
            _CIS_TITLES = {c.id: c.title for c in CIS_1_8}
        except Exception:
            _CIS_TITLES = {}
    return _CIS_TITLES


def standards_for(finding: Finding) -> list[StandardRef]:
    """Every named standard/benchmark/policy this finding maps to, each with a
    reference link, derived from the rule's own owasp/cis/nsa_cisa tags, so it can
    never drift from what the rule actually declares."""
    out: list[StandardRef] = []
    if finding.owasp:
        name = _owasp_names().get(finding.owasp, finding.owasp)
        out.append(StandardRef("OWASP Kubernetes Top 10 (2025)", finding.owasp, name,
                               owasp_url(finding.owasp)))
    for c in finding.cis:
        title = _cis_titles().get(c, f"Control {c}")
        out.append(StandardRef("CIS Kubernetes Benchmark v1.8", c, title, CIS_BENCHMARK_URL))
    for n in finding.nsa_cisa:
        out.append(StandardRef("NSA/CISA Kubernetes Hardening Guide", n, n, NSA_CISA_URL))
    return out


def mitre_for(finding: Finding) -> list[MitreRef]:
    """Every distinct MITRE ATT&CK tactic/technique this finding is tagged with, each
    with its real, individually-addressable attack.mitre.org URL."""
    seen: set = set()
    out: list[MitreRef] = []
    for m in finding.mitre:
        key = (m.tactic.value, m.technique_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(MitreRef(m.tactic.value, m.technique_id, m.technique_name,
                            mitre_technique_url(m.technique_id)))
    return out


def _format_all(templates: list, finding: Finding) -> list[str]:
    res = finding.resource
    ns = res.namespace or "default"
    kind = (res.kind or "pod").lower()
    out = []
    for t in templates:
        try:
            out.append(t.format(name=res.name, namespace=ns, kind=kind))
        except Exception:
            out.append(t)
    return out


def _fallback_impact(finding: Finding) -> str:
    tactics = ", ".join(t.value for t in finding.tactics) or "cluster security"
    return (f"Scored {finding.severity.label} with {finding.exploitability.label.lower()} "
           f"exploitability and a {finding.blast_radius.label.lower()}-level blast radius. "
           f"Left unaddressed it contributes to: {tactics}.")


def _fallback_validation(finding: Finding) -> list[str]:
    res = finding.resource
    ns = f" -n {res.namespace}" if res.namespace else ""
    return [f"kubectl get {(res.kind or 'pod').lower()} {res.name}{ns} -o yaml"]


def build_finding_context(finding: Finding) -> FindingContext:
    """The single entry point every report renderer calls for a finding's full context."""
    kb = FINDING_CONTEXT.get(finding.rule_id, {})
    summary = kb.get("summary") or finding.message
    impact = kb.get("impact") or _fallback_impact(finding)
    validation = (_format_all(kb["validation"], finding) if kb.get("validation")
                 else _fallback_validation(finding))
    return FindingContext(
        summary=summary, impact=impact, validation_steps=validation,
        standards=standards_for(finding), mitre=mitre_for(finding),
    )


# =================================================================================== #
# The knowledge base, summary / impact / validation for every rule.
#
# `validation` entries are templates: {name}/{namespace}/{kind} are filled in from the
# actual finding's resource at render time.
# =================================================================================== #
FINDING_CONTEXT: dict[str, dict] = {

    # ---------------------------------------------------------------- shard ① control plane
    "apiserver-anonymous-auth": {
        "summary": "The API server accepts unauthenticated requests under the "
                   "`system:anonymous` identity, so anyone who can reach it can act as a "
                   "cluster user without presenting any credential.",
        "impact": "An attacker who can route a request to the API server, from inside the "
                 "network, a misconfigured LoadBalancer, or a leaked endpoint, gets "
                 "whatever access the `system:unauthenticated` group's bindings grant, "
                 "often enough to enumerate cluster state or, if that group is ever bound "
                 "to anything permissive, escalate outright.",
        "validation": [
            "kubectl get --raw /api -v=6 2>&1 | head -20  "
            "# an unauthenticated 200 instead of 401/403 confirms anonymous auth is on",
        ],
    },
    "apiserver-insecure-port": {
        "summary": "The API server's deprecated `--insecure-port` is enabled, serving the "
                   "API with no authentication or encryption on a plaintext HTTP port.",
        "impact": "Any request reaching that port bypasses authentication, authorization, "
                 "and TLS entirely, a direct, unauthenticated path to full API access, "
                 "including secrets, from anywhere with network reachability.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\\n' | grep insecure-port",
        ],
    },
    "etcd-client-cert-auth": {
        "summary": "etcd, the cluster's entire state store, including every Secret in "
                   "plaintext unless encryption-at-rest is separately enabled, does not "
                   "require client certificate authentication.",
        "impact": "Anyone who can reach etcd's client port (2379) can read or write the "
                 "raw cluster datastore directly, completely bypassing the Kubernetes API, "
                 "RBAC, and admission control. This is a full cluster compromise path.",
        "validation": [
            "kubectl -n kube-system get pod -l component=etcd -o "
            "jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\\n' | grep client-cert-auth",
        ],
    },
    "kubelet-anonymous-auth": {
        "summary": "A node's kubelet API accepts unauthenticated requests on port "
                   "10250. Anyone who can reach it can read pod specs, pull logs, and exec "
                   "into containers on the node with no credential, a well-known path to "
                   "node and workload compromise.",
        "impact": "The kubelet API can list every pod's spec (including env-var secrets), "
                 "exec into containers, and fetch logs. Anonymous access to it is a "
                 "well-known, actively exploited path to full node and workload compromise.",
        "validation": [
            "curl -sk https://<node-ip>:10250/pods  "
            "# a 200 with pod data instead of 401 confirms anonymous kubelet access",
        ],
    },
    "kubelet-authz-always-allow": {
        "summary": "The kubelet's authorization mode is `AlwaysAllow`, so even an "
                   "authenticated caller's identity is never actually checked against "
                   "RBAC before the kubelet honors the request.",
        "impact": "Any credential that can merely authenticate to the kubelet, not "
                 "necessarily one with any RBAC grant, gets full kubelet API access: "
                 "pod exec, log retrieval, and container lifecycle control on that node.",
        "validation": [
            "kubectl get --raw /api/v1/nodes/<node>/proxy/configz 2>/dev/null | "
            "jq '.kubeletconfig.authorization.mode'",
        ],
    },
    "apiserver-audit-logging": {
        "summary": "The API server has no `--audit-log-path` configured, so no record of "
                   "who did what against the cluster is being kept.",
        "impact": "Without an audit trail, a compromise, a privilege-escalation attempt, or "
                 "even ordinary operator error is unrecoverable after the fact, there is "
                 "nothing to investigate, correlate, or use as evidence.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\\n' | grep audit-log-path",
        ],
    },
    "etcd-encryption-missing": {
        "summary": "No `--encryption-provider-config` is set on the API server, so "
                   "Secrets are stored in etcd as plaintext, not encrypted at rest.",
        "impact": "Anyone with read access to etcd's data directory or its backups, a "
                 "stolen disk snapshot, an exposed backup bucket, a compromised etcd node "
                 ", can read every Secret in the cluster directly, with no additional key "
                 "required.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\\n' | "
            "grep encryption-provider-config",
        ],
    },
    "kubelet-read-only-port": {
        "summary": "The kubelet's deprecated read-only port 10255 is open, an "
                   "unauthenticated HTTP endpoint exposing pod and node state.",
        "impact": "Anyone with network access to the node can enumerate every pod's "
                 "spec, resource usage, and metadata on it with zero authentication, a "
                 "reconnaissance foothold for planning further attacks.",
        "validation": ["curl -s http://<node-ip>:10255/pods | head -5"],
    },
    "deprecated-k8s-version": {
        "summary": "The cluster is running an end-of-life or otherwise outdated "
                   "Kubernetes version with known, patched CVEs in supported releases.",
        "impact": "Every disclosed CVE affecting that version, including any with public "
                 "exploit code, remains exploitable indefinitely, since no further "
                 "security patches are being backported to an EOL release.",
        "validation": ["kubectl version --short 2>/dev/null || kubectl version"],
    },

    # ---------------------------------------------------------- shard ② workload/pod security
    "workload-privileged-container": {
        "summary": "A container runs with `securityContext.privileged: true`, giving it "
                   "essentially the same access to the host as a root process running "
                   "directly on the node.",
        "impact": "A privileged container can load kernel modules, access every device on "
                 "the host, and trivially break out to the underlying node, from there, "
                 "an attacker controls every other workload scheduled on that node and can "
                 "pivot across the cluster.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].securityContext.privileged}}'",
        ],
    },
    "workload-host-pid": {
        "summary": "The pod shares the host's PID namespace (`hostPID: true`), so its "
                   "containers can see and interact with every process running on the node.",
        "impact": "A container in this pod can see other containers' process environments "
                 "(often containing secrets), send signals to host processes, and, "
                 "combined with `/proc/<pid>/root`, reachable in this namespace, read "
                 "another container's filesystem, a well-documented container-escape "
                 "primitive.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o jsonpath='{{.spec.hostPID}}'",
        ],
    },
    "workload-docker-socket": {
        "summary": "The container mounts the Docker (or containerd) socket from the host, "
                   "handing it direct control over the node's container runtime.",
        "impact": "Access to the runtime socket is equivalent to root on the node: an "
                 "attacker can launch a new privileged container, bind-mount the host "
                 "filesystem into it, and read/write anything on the node, a textbook, "
                 "one-command container escape.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.volumes[*].hostPath.path}}' | grep -o '[^ ]*docker.sock'",
        ],
    },
    "workload-hostpath-root": {
        "summary": "The pod mounts a sensitive host path (`/`, `/etc`, `/var/run`, or "
                   "`/etc/kubernetes/manifests`) from the node's filesystem.",
        "impact": "Mounting `/etc/kubernetes/manifests` lets an attacker drop a new static "
                 "pod manifest that the kubelet will run automatically, surviving pod "
                 "restarts and even node reboots, a durable, host-level persistence and "
                 "privilege-escalation mechanism. A root mount grants effectively "
                 "unrestricted host filesystem access.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.volumes[*].hostPath.path}}'",
        ],
    },
    "workload-run-as-root": {
        "summary": "The container has no enforced non-root user, it may run as UID 0 "
                   "inside the container.",
        "impact": "Running as root inside the container removes a key defense-in-depth "
                 "layer: if any other misconfiguration (a writable filesystem, a capability, "
                 "a kernel vulnerability) is also present, root privileges inside the "
                 "container make exploiting it materially easier, and any container-escape "
                 "primitive lands the attacker as root on the host too.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].securityContext.runAsUser}} "
            "{{.spec.securityContext.runAsNonRoot}}'",
        ],
    },
    "workload-allow-priv-escalation": {
        "summary": "`allowPrivilegeEscalation` is not explicitly set to `false`, so a "
                   "process in the container can gain more privileges than its parent "
                   "(e.g. via a setuid binary) at runtime.",
        "impact": "Combined with any writable, attacker-influenced binary in the image, "
                 "this allows in-container privilege escalation even when the container "
                 "itself doesn't start as root, widening the blast radius of an "
                 "application-level compromise.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].securityContext.allowPrivilegeEscalation}}'",
        ],
    },
    "workload-dangerous-caps": {
        "summary": "The container adds a Linux capability from a high-risk set "
                   "(`SYS_ADMIN`, `SYS_PTRACE`, `NET_RAW`, `NET_ADMIN`, `SYS_MODULE`, "
                   "`BPF`, `DAC_OVERRIDE`) beyond the container-runtime default.",
        "impact": "Each of these capabilities maps to a documented container-escape or "
                 "lateral-movement technique, `SYS_ADMIN` alone is close to full root, "
                 "`NET_RAW` enables ARP/IP spoofing for on-path attacks against other pods "
                 "on the same node, and `SYS_PTRACE` allows inspecting/injecting into other "
                 "processes' memory.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].securityContext.capabilities.add}}'",
        ],
    },
    "workload-caps-not-dropped": {
        "summary": "The container does not drop the full Linux capability set "
                   "(`capabilities.drop: [ALL]`) before adding back only what it needs.",
        "impact": "Leaving the container-runtime default capability set intact (which "
                 "already includes things like `NET_RAW` and `CHOWN`) means the container "
                 "carries more ambient privilege than most application workloads ever "
                 "legitimately need, unnecessary attack surface with no functional benefit.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].securityContext.capabilities.drop}}'",
        ],
    },
    "workload-host-network": {
        "summary": "The pod shares the host's network namespace (`hostNetwork: true`), "
                   "binding directly to the node's own network interfaces.",
        "impact": "The pod can see and bind to every port on the node, sniff traffic on the "
                 "host's interfaces, and reach any service the node itself can reach "
                 "(including cloud metadata endpoints that may otherwise be firewalled from "
                 "pod IPs), a significant discovery and lateral-movement advantage.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o jsonpath='{{.spec.hostNetwork}}'",
        ],
    },
    "workload-host-ipc": {
        "summary": "The pod shares the host's IPC namespace (`hostIPC: true`), exposing "
                   "shared memory segments and semaphores used by host processes.",
        "impact": "A container in this pod can read or write shared memory used by other "
                 "processes on the node, including, in some configurations, information "
                 "leaked by unrelated host services, an information-disclosure and "
                 "cross-process-influence vector.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o jsonpath='{{.spec.hostIPC}}'",
        ],
    },
    "workload-hostpath-writable": {
        "summary": "The pod mounts a writable hostPath volume outside the small set of "
                   "already-flagged critical system paths.",
        "impact": "A writable path on the node's filesystem that survives the pod's own "
                 "lifecycle is a persistence mechanism, an attacker who compromises this "
                 "pod can drop a payload on the node that a different, later workload (or "
                 "the node itself) may execute, and it can be used to move data between "
                 "pods that shouldn't otherwise be able to communicate.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.volumes[*].hostPath.path}}'",
        ],
    },
    "workload-sshd-present": {
        "summary": "The container appears to run an SSH server, a second, "
                   "Kubernetes-invisible entry point into the container alongside "
                   "`kubectl exec`.",
        "impact": "An SSH daemon inside a container is almost always unnecessary and gives "
                 "an attacker who obtains or brute-forces credentials a persistent access "
                 "path that bypasses Kubernetes RBAC and audit logging entirely, "
                 "`kubectl exec` is logged and authorized by the API server; a direct SSH "
                 "session to the pod IP is neither.",
        "validation": [
            "kubectl exec -n {namespace} {name} -- sh -c "
            "\"ps aux 2>/dev/null | grep sshd; cat /etc/ssh/sshd_config 2>/dev/null | head -1\"",
        ],
    },
    "workload-writable-root-fs": {
        "summary": "The container's root filesystem is writable (`readOnlyRootFilesystem` "
                   "is not `true`). An attacker who runs code in it can drop a backdoor or "
                   "modify application files in place until the pod restarts, an avoidable "
                   "persistence window for a stateless workload.",
        "impact": "A writable root filesystem lets an attacker who achieves code execution "
                 "in the container persist a backdoor binary or modify application code in "
                 "place, surviving until the pod is next restarted, an unnecessary window "
                 "for most stateless application workloads.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].securityContext.readOnlyRootFilesystem}}'",
        ],
    },
    "workload-missing-limits": {
        "summary": "The container sets no CPU or memory `resources.limits`. One "
                   "misbehaving or compromised container can then exhaust a node's "
                   "resources and starve every other workload on it, with no per-container "
                   "blast-radius boundary.",
        "impact": "A single misbehaving or compromised container without limits can "
                 "consume all available CPU/memory on its node, starving every other "
                 "workload scheduled there, a self-inflicted or attacker-triggered "
                 "denial-of-service that has no per-container blast-radius boundary.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.containers[*].resources.limits}}'",
        ],
    },
    "workload-no-seccomp": {
        "summary": "The container has no seccomp profile applied, every syscall the "
                   "kernel exposes is available to it by default.",
        "impact": "Seccomp is one of the cheapest, highest-value hardening layers "
                 "available: applying `RuntimeDefault` alone blocks dozens of syscalls "
                 "with no legitimate use in a typical application container, meaningfully "
                 "shrinking what a post-exploitation payload can actually do even after "
                 "achieving code execution.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.securityContext.seccompProfile.type}} "
            "{{.spec.containers[*].securityContext.seccompProfile.type}}'",
        ],
    },
    "workload-sa-token-automount": {
        "summary": "This workload's ServiceAccount token is automatically mounted into "
                   "the pod, even though most application containers never call the "
                   "Kubernetes API.",
        "impact": "If the container is compromised, the mounted token is immediately "
                 "usable by the attacker to call the Kubernetes API as that ServiceAccount "
                 ", credential theft that requires no further exploitation step, and one of "
                 "the most common real-world Kubernetes attack-chain pivots.",
        "validation": [
            "kubectl get {kind} {name} -n {namespace} -o "
            "jsonpath='{{.spec.automountServiceAccountToken}}'",
        ],
    },
    "workload-latest-tag": {
        "summary": "The container references a mutable image tag (`:latest`, or no tag/"
                   "digest at all) instead of an immutable content digest.",
        "impact": "The exact code running in production can silently change on the next "
                 "pod restart or node reschedule without any deployment event, breaking "
                 "reproducibility, complicating incident response ('which image was "
                 "actually running?'), and opening a supply-chain window if the tag is ever "
                 "repointed to a malicious image at the registry.",
        "validation": ["kubectl get {kind} {name} -n {namespace} -o "
                      "jsonpath='{{.spec.containers[*].image}}'"],
    },

    # --------------------------------------------------------------------- shard ③ RBAC
    "rbac-wildcard-verbs": {
        "summary": "A Role/ClusterRole grants `verbs: [\"*\"]`, every possible action on "
                   "the matched resources, present and future.",
        "impact": "A wildcard verb silently grants any verb the Kubernetes API ever adds "
                 "in a future version too, not just today's. Combined with almost any "
                 "resource grant, it typically includes `create`/`update`/`patch`/`delete` "
                 ", full read-write control, not the narrow access the role was likely "
                 "intended to provide.",
        "validation": ["kubectl get clusterrole,role -A -o json | "
                      "jq '.items[] | select(.rules[]?.verbs[]?==\"*\") | .metadata.name'"],
    },
    "rbac-wildcard-resources": {
        "summary": "A Role/ClusterRole grants `resources: [\"*\"]`, access to every "
                   "resource type in every API group the rule's apiGroups cover.",
        "impact": "This silently includes `secrets`, `pods/exec`, and RBAC objects "
                 "themselves unless verbs are also tightly scoped, a wildcard resource "
                 "grant is one of the most common accidental routes to a full "
                 "privilege-escalation chain.",
        "validation": ["kubectl get clusterrole,role -A -o json | "
                      "jq '.items[] | select(.rules[]?.resources[]?==\"*\") | .metadata.name'"],
    },
    "rbac-cluster-admin-default-sa": {
        "summary": "The `cluster-admin` ClusterRole is bound to a namespace's `default` "
                   "ServiceAccount, the identity every pod in that namespace gets "
                   "automatically unless it explicitly requests a different one.",
        "impact": "Every pod in that namespace, whether or not it was ever intended to have "
                 "cluster-wide access, can act as `cluster-admin` simply by using its "
                 "auto-mounted token, a single compromised pod anywhere in the namespace "
                 "becomes full, unrestricted cluster compromise.",
        "validation": ["kubectl get clusterrolebinding -o json | "
                      "jq '.items[] | select(.roleRef.name==\"cluster-admin\") | "
                      "select(.subjects[]?.name==\"default\")'"],
    },
    "rbac-bind-escalate-verbs": {
        "summary": "A Role/ClusterRole grants the `bind`, `escalate`, or `impersonate` "
                   "verb, RBAC's own built-in privilege-escalation primitives.",
        "impact": "`escalate` lets the holder grant themselves permissions they don't "
                 "already have; `bind` lets them attach any Role/ClusterRole (including "
                 "`cluster-admin`) to a subject; `impersonate` lets them act as any other "
                 "user or ServiceAccount. Any of the three is a direct, intended-by-Kubernetes "
                 "escalation path, not a side effect, holding one of these verbs on a "
                 "broad scope is equivalent to holding whatever it can grant.",
        "validation": ["kubectl get clusterrole,role -A -o json | "
                      "jq '.items[] | select(.rules[]?.verbs[]? | IN(\"bind\",\"escalate\",\"impersonate\"))"
                      " | .metadata.name'"],
    },
    "rbac-secret-read-broad": {
        "summary": "A ClusterRole grants `get`/`list` on `secrets` cluster-wide rather than "
                   "scoped to a namespace or specific secret names.",
        "impact": "Any subject bound to this role can read every Secret in every "
                 "namespace, database credentials, TLS keys, cloud IAM tokens, other "
                 "teams' application secrets, a single overly broad grant that "
                 "effectively flattens Kubernetes' namespace isolation for credential "
                 "material.",
        "validation": ["kubectl get clusterrole -o json | jq '.items[] | "
                      "select(.rules[]? | select(.resources[]?==\"secrets\") | "
                      ".verbs[]? | IN(\"get\",\"list\")) | .metadata.name'"],
    },
    "rbac-can-delete-events": {
        "summary": "A Role/ClusterRole grants `delete` on `events`. Since events are "
                   "where responders look first, a subject with this grant can erase "
                   "evidence of its own activity, pod creation, exec, and image pulls, as "
                   "it happens.",
        "impact": "Kubernetes events are one of the first places an operator looks during "
                 "incident response. A subject that can delete them can erase evidence of "
                 "its own suspicious activity (pod creation, exec, image pulls) as it "
                 "happens, a defense-evasion primitive specifically flagged in the "
                 "Kubernetes threat matrix.",
        "validation": ["kubectl get clusterrole,role -A -o json | "
                      "jq '.items[] | select(.rules[]? | select(.resources[]?==\"events\") | "
                      ".verbs[]?==\"delete\") | .metadata.name'"],
    },
    "rbac-coredns-configmap-write": {
        "summary": "A Role/ClusterRole grants `update`/`patch` on `configmaps` broadly "
                   "enough to include (or not clearly exclude) the `kube-system/coredns` "
                   "ConfigMap that drives cluster-internal DNS resolution.",
        "impact": "Whoever can rewrite CoreDNS's Corefile controls DNS resolution for the "
                 "entire cluster, a classic adversary-in-the-middle position, capable of "
                 "redirecting any pod's traffic (including to internal services or the "
                 "cloud metadata API) to an attacker-controlled endpoint.",
        "validation": ["kubectl get role,rolebinding -n kube-system -o json | "
                      "jq '.items[] | select(.rules[]?.resources[]?==\"configmaps\")'"],
    },

    # ---------------------------------------------------------------- shard ④ network
    "net-dashboard-exposed": {
        "summary": "The Kubernetes Dashboard is reachable from outside the cluster. It is "
                   "a frequently targeted entry point; an under-authenticated public "
                   "Dashboard has led to real breaches by letting attackers schedule their "
                   "own pods.",
        "impact": "The Dashboard is a well-documented, frequently targeted attack surface "
                 ", multiple real-world breaches (including a widely reported Tesla "
                 "cryptomining incident) started from an internet-reachable, "
                 "under-authenticated Dashboard used to schedule an attacker-controlled pod.",
        "validation": ["kubectl -n kubernetes-dashboard get svc kubernetes-dashboard -o "
                      "jsonpath='{{.spec.type}} {{.status.loadBalancer.ingress}}'"],
    },
    "net-lb-no-source-range": {
        "summary": "A public-facing LoadBalancer Service has no `loadBalancerSourceRanges` "
                   "set, so it accepts traffic from any source IP.",
        "impact": "Without a source-IP allowlist, the service is reachable by anyone on "
                 "the internet, not just intended clients, removing a cheap, effective "
                 "layer of network-level access control for a service that may not need "
                 "to be globally reachable at all.",
        "validation": ["kubectl get svc {name} -n {namespace} -o "
                      "jsonpath='{{.spec.type}} {{.spec.loadBalancerSourceRanges}}'"],
    },
    "net-ingress-no-tls": {
        "summary": "An Ingress resource serves traffic over plain HTTP with no TLS "
                   "configuration.",
        "impact": "Any credential, session token, or sensitive payload sent to this "
                 "endpoint travels in cleartext and can be intercepted by anyone with "
                 "network visibility along the path, a straightforward, passive "
                 "eavesdropping exposure.",
        "validation": ["kubectl get ingress {name} -n {namespace} -o jsonpath='{{.spec.tls}}'"],
    },
    "net-no-networkpolicy": {
        "summary": "The namespace has zero NetworkPolicies applied, so every pod in it "
                   "can send and receive traffic from every other pod in the cluster by "
                   "default.",
        "impact": "A flat, unsegmented pod network means a single compromised pod, "
                 "anywhere in the cluster, can immediately probe and reach every other "
                 "workload with no additional lateral-movement step required. NetworkPolicy "
                 "is Kubernetes' primary built-in segmentation control, and it is opt-in.",
        "validation": ["kubectl get networkpolicy -n {namespace}"],
    },
    "net-metadata-api-open": {
        "summary": "Pods in this environment can reach the cloud provider's instance "
                   "metadata endpoint (`169.254.169.254`) with no egress restriction.",
        "impact": "The metadata API commonly serves the node's IAM role credentials. An "
                 "attacker who achieves code execution in any pod on this node can request "
                 "those credentials directly over HTTP and pivot from a container "
                 "compromise straight into the cloud account, one of the most common "
                 "real-world Kubernetes-to-cloud escalation chains (see the Capital One "
                 "breach).",
        "validation": ["kubectl exec -n {namespace} {name} -- "
                      "curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null"],
    },
    "net-nodeport-service": {
        "summary": "A Service of type `NodePort` opens a port in the 30000–32767 range "
                   "directly on every node in the cluster.",
        "impact": "NodePort exposure bypasses any Ingress-level access control and is "
                 "reachable on every node's IP, widening the effective attack surface well "
                 "beyond what a ClusterIP + Ingress topology would expose, especially if "
                 "nodes themselves have public IPs.",
        "validation": ["kubectl get svc {name} -n {namespace} -o "
                      "jsonpath='{{.spec.type}} {{.spec.ports[*].nodePort}}'"],
    },

    # ---------------------------------------------------------- shard ⑤ image/supply-chain
    "img-kubeconfig-embedded": {
        "summary": "A container image has a kubeconfig file baked into one of its "
                   "layers. Anyone who can pull the image gets a working set of cluster "
                   "credentials, possibly for a higher-privilege cluster than the one it "
                   "runs in.",
        "impact": "Anyone who can pull the image, including from a public registry, or "
                 "via a leaked/typosquatted mirror, gets a working set of cluster "
                 "credentials, potentially for a completely different, higher-privilege "
                 "cluster than the one the image is actually deployed to.",
        "validation": ["docker history --no-trunc {name} 2>/dev/null | grep -i kubeconfig "
                      "|| echo 'inspect layers manually: docker save {name} | tar -tv | grep kube'"],
    },
    "img-typosquat": {
        "summary": "The image name closely resembles a popular, legitimate image "
                   "(e.g. `nignx` instead of `nginx`), a classic supply-chain typosquat "
                   "pattern.",
        "impact": "A typosquatted image pulled by mistake (a copy-paste error, a "
                 "misconfigured base-image reference) can run arbitrary attacker code with "
                 "whatever privileges the pod spec grants it, supply-chain compromise "
                 "with no exploit required, just a plausible-looking name.",
        "validation": ["kubectl get {kind} {name} -n {namespace} -o "
                      "jsonpath='{{.spec.containers[*].image}}'  "
                      "# compare against the intended, correctly-spelled image name"],
    },
    "img-not-signed": {
        "summary": "The image carries no cosign/notary signature to verify its "
                   "provenance. Without verification, the cluster cannot tell the image the "
                   "team built from one swapped in at the registry or through a compromised "
                   "CI pipeline.",
        "impact": "Without signature verification, the cluster cannot distinguish between "
                 "the image the team actually built and one substituted at the registry "
                 "(via a compromised CI pipeline, a registry-level compromise, or a "
                 "man-in-the-middle), image signing is the control that closes that gap.",
        "validation": ["cosign verify {name} 2>&1 | head -5"],
    },
    "img-pull-policy": {
        "summary": "The container uses `imagePullPolicy: IfNotPresent` on a tag that "
                   "isn't pinned to a digest. Nodes with a stale cached copy keep running "
                   "it after a fix is pushed under the same tag, so a patched vulnerability "
                   "can linger on some nodes.",
        "impact": "A node that already has a stale cached copy of the tag will keep "
                 "running it even after a fix has been pushed to the registry under the "
                 "same tag, a patched vulnerability can remain exploitable on some nodes "
                 "well after the image was 'fixed'.",
        "validation": ["kubectl get {kind} {name} -n {namespace} -o "
                      "jsonpath='{{.spec.containers[*].imagePullPolicy}}'"],
    },

    # -------------------------------------------------------------------- shard ⑥ secrets
    "sec-etcd-not-encrypted": {
        "summary": "Secrets are stored in etcd without encryption at rest, the same "
                   "underlying gap as `etcd-encryption-missing`, surfaced from the "
                   "Secrets domain's perspective.",
        "impact": "Every Secret in the cluster is recoverable in plaintext by anyone with "
                 "read access to etcd's storage or backups, with no additional key or "
                 "credential required.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{{.spec.containers[0].command}}' | tr ',' '\\n' | "
            "grep encryption-provider-config",
        ],
    },
    "sec-env-var-secrets": {
        "summary": "A container injects a Secret's value via an environment variable "
                   "(`env[].valueFrom.secretKeyRef`) rather than a mounted file.",
        "impact": "Environment variables are captured whole in `kubectl describe pod`, "
                 "crash dumps, core dumps, child-process environments, and many APM/logging "
                 "agents that snapshot process environment by default, each an independent "
                 "way the secret value can leak outside the one process that actually needs it.",
        "validation": ["kubectl get {kind} {name} -n {namespace} -o "
                      "jsonpath='{{.spec.containers[*].env[?(@.valueFrom.secretKeyRef)].name}}'"],
    },
    "sec-configmap-credentials": {
        "summary": "A ConfigMap key or value looks like a hardcoded credential "
                   "(password, token, API key, private key).",
        "impact": "Unlike Secrets, ConfigMaps are not treated as sensitive by Kubernetes, "
                 "they're readable by any identity with generic `get`/`list` on ConfigMaps "
                 "(a far more common grant than secret access), and their contents are "
                 "shown in plaintext by `kubectl get configmap -o yaml` with no redaction.",
        "validation": ["kubectl get configmap {name} -n {namespace} -o yaml"],
    },
    "sec-mounted-cloud-creds": {
        "summary": "A volume mount path matches a well-known cloud credential file "
                   "location (`.aws/credentials`, `azure.json`, a GCP service-account "
                   "JSON, or a `.kube/config`).",
        "impact": "These files typically grant standing, long-lived cloud or cluster "
                 "credentials with whatever scope was provisioned for them, often far "
                 "broader than the single pod needs, turning a container compromise "
                 "directly into a cloud-account or cross-cluster compromise.",
        "validation": ["kubectl get {kind} {name} -n {namespace} -o "
                      "jsonpath='{{.spec.containers[*].volumeMounts[*].mountPath}}'"],
    },

    # --------------------------------------------------------------- shard ⑨ admission control
    "admission-malicious-webhook": {
        "summary": "A Mutating or Validating webhook is configured with a suspiciously "
                   "broad scope and/or an external endpoint outside the cluster.",
        "impact": "A mutating webhook can silently rewrite every matching object the API "
                 "server processes, inject a sidecar, add a hostPath mount, alter "
                 "securityContext, on every create/update, cluster-wide, invisibly to "
                 "whoever submitted the original manifest. It's one of the stealthiest "
                 "persistence mechanisms in Kubernetes.",
        "validation": ["kubectl get mutatingwebhookconfigurations,"
                      "validatingwebhookconfigurations -o json | "
                      "jq '.items[] | {{name: .metadata.name, webhooks: [.webhooks[] | "
                      "{{name, clientConfig, failurePolicy}}]}}'"],
    },
    "admission-webhook-failurepolicy": {
        "summary": "A security-relevant admission webhook is set to `failurePolicy: "
                   "Ignore`. If it ever goes unreachable, from a crash or a deliberate "
                   "attacker, every object it should gate is admitted anyway, so the policy "
                   "can be bypassed rather than defeated.",
        "impact": "If the webhook is ever unreachable, network issue, the webhook pod "
                 "itself crashing, or an attacker deliberately taking it offline, every "
                 "object it was supposed to validate or mutate is admitted anyway, "
                 "silently. An attacker who can make a policy webhook unavailable can "
                 "bypass it entirely rather than needing to defeat its logic.",
        "validation": ["kubectl get mutatingwebhookconfigurations,"
                      "validatingwebhookconfigurations -o json | "
                      "jq '.items[].webhooks[] | select(.failurePolicy==\"Ignore\") | .name'"],
    },
    "admission-sidecar-injection": {
        "summary": "A mutating webhook injects a sidecar container into the pods it "
                   "processes. This is normal for service meshes, but it is also a way to "
                   "smuggle an attacker-controlled container into every pod cluster-wide, "
                   "so what gets injected and by whom needs review.",
        "impact": "Sidecar injection is legitimate for service meshes and observability "
                 "agents, but it is also a documented technique for smuggling an "
                 "attacker-controlled container into every pod cluster-wide via a single "
                 "webhook compromise, reviewing exactly what gets injected and by whom is "
                 "necessary to distinguish the two.",
        "validation": ["kubectl get mutatingwebhookconfigurations -o json | "
                      "jq '.items[].webhooks[] | {{name, rules}}'"],
    },
    "cronjob-suspicious": {
        "summary": "A CronJob has a suspicious schedule, image, or command, the pattern "
                   "used by backdoors that need to survive pod restarts and even node "
                   "reboots.",
        "impact": "A CronJob is a durable, self-reinstating persistence mechanism: even if "
                 "the malicious pod it spawns is found and killed, the CronJob simply "
                 "creates another one on its next scheduled tick, with no further attacker "
                 "action required.",
        "validation": ["kubectl get cronjob {name} -n {namespace} -o "
                      "jsonpath='{{.spec.schedule}} {{.spec.jobTemplate.spec.template.spec.containers[*].image}} "
                      "{{.spec.jobTemplate.spec.template.spec.containers[*].command}}'"],
    },

    # ------------------------------------------------------------------ shard ⑩ cloud IAM
    "iam-overpermissive": {
        "summary": "The AWS IAM role (IRSA) attached to this ServiceAccount grants "
                   "permissions well beyond what the workload actually uses.",
        "impact": "Any pod using this ServiceAccount inherits the role's full permission "
                 "set for the lifetime of its token, a container compromise translates "
                 "directly into whatever that over-broad IAM policy allows in the cloud "
                 "account, not just what the application itself needed.",
        "validation": ["kubectl get sa {name} -n {namespace} -o "
                      "jsonpath='{{.metadata.annotations.eks\\.amazonaws\\.com/role-arn}}'  "
                      "# then: aws iam list-attached-role-policies --role-name <role>"],
    },
    "iam-node-role-broad": {
        "summary": "The EC2/node instance role is broader than any pod actually scheduled "
                   "on that node needs.",
        "impact": "Before IRSA/Workload Identity was adopted (or for pods that don't use "
                 "it), every pod on the node can reach the node's own instance role via the "
                 "metadata API, an overly broad node role means every workload on that "
                 "node, trusted or not, effectively holds that role's full permissions.",
        "validation": ["aws ec2 describe-instances --instance-ids <id> --query "
                      "'Reservations[].Instances[].IamInstanceProfile'"],
    },
    "iam-managed-identity-reachable": {
        "summary": "A managed cloud identity's credentials are reachable from a pod on "
                   "this node. Paired with an open metadata path, a container compromise "
                   "becomes a cloud-account compromise; the credential is one "
                   "unauthenticated HTTP request away.",
        "impact": "Combined with an open path to the metadata API (see "
                 "`net-metadata-api-open`), this is the concrete mechanism by which a "
                 "container compromise becomes a cloud-account compromise, the credential "
                 "is sitting one unauthenticated HTTP request away.",
        "validation": ["kubectl exec -n {namespace} {name} -- "
                      "curl -s -m 2 -H 'Metadata: true' "
                      "'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01' "
                      "2>/dev/null"],
    },

    # --------------------------------------------------------------------- shard ⑦ compliance
    "compliance-psa-not-restricted": {
        "summary": "The namespace does not enforce the `restricted` Pod Security Standard "
                   ", Kubernetes' own built-in, opt-in baseline for hardened pod specs.",
        "impact": "Without PSA enforcement, nothing prevents any future pod deployed into "
                 "this namespace from being privileged, root, or host-namespace-sharing, "
                 "regardless of how well-intentioned today's workloads are, it's a "
                 "namespace-wide guardrail, not a one-time check.",
        "validation": ["kubectl get ns {name} -o "
                      "jsonpath='{{.metadata.labels.pod-security\\.kubernetes\\.io/enforce}}'"],
    },

    # ---------------------------------------------------------------- shard ⑧ attack surface
    "as-sa-fanout": {
        "summary": "The same ServiceAccount is mounted into many workloads across "
                   "multiple namespaces. A compromise of any one of them can act as that "
                   "identity everywhere it is used, so its blast radius spans every "
                   "namespace it appears in.",
        "impact": "A single compromised pod anywhere this ServiceAccount is used can act "
                 "as it everywhere else it's used too, the SA's effective blast radius is "
                 "the union of every namespace it appears in, not just the one where the "
                 "compromise happened. This is exactly how a low-value workload becomes an "
                 "unintended pivot point into higher-value ones sharing the same identity.",
        "validation": ["kubectl get pods -A -o json | "
                      "jq -r '.items[] | select(.spec.serviceAccountName==\"{name}\") | "
                      "\"\\(.metadata.namespace)/\\(.metadata.name)\"'"],
    },

    # ---------------------------------------------------------------- shard ⑪ log analysis
    "log-audit-policy-missing": {
        "summary": "The API server has no `--audit-policy-file`. The audit policy is what "
                   "decides which requests get recorded and at what level; with no policy "
                   "the API server records nothing, so an audit log file can exist and "
                   "still be empty.",
        "impact": "There is no record of who did what in the cluster. Every incident "
                 "question that matters after a breach, which identity created that "
                 "ClusterRoleBinding, when the Secret was first read, whether the "
                 "attacker is still active, becomes unanswerable. It also removes the "
                 "evidence an attacker would otherwise have to tamper with, so intrusions "
                 "leave no trace at all rather than a suspicious gap.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{{.items[0].spec.containers[0].command}}' | tr ',' '\\n' | grep audit-",
            "# a policy file must be present AND non-empty; an empty policy logs nothing",
        ],
    },
    "log-audit-retention-short": {
        "summary": "Audit logs are kept for fewer than 30 days (or the retention window is "
                   "undefined). CIS sets 30 days as the floor, which is also roughly the "
                   "median time an intruder goes unnoticed.",
        "impact": "The audit trail can expire before anyone knows to look at it. An "
                 "attacker who established access last month leaves a log window that has "
                 "already rolled over, so the initial access and privilege escalation, "
                 "the parts that explain how they got in and what else they touched, are "
                 "gone even though the compromise is ongoing.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{{.items[0].spec.containers[0].command}}' | tr ',' '\\n' | "
            "grep audit-log-maxage",
        ],
    },
    "log-audit-rotation-weak": {
        "summary": "Audit-log rotation keeps too few files, or files too small, so history "
                   "is discarded by volume regardless of the configured retention in days.",
        "impact": "A burst of activity silently rolls older entries out of retention, and "
                 "a burst of activity is exactly what an attack looks like. The noisiest, "
                 "most interesting hour is the one most likely to push the preceding "
                 "reconnaissance out of the logs, and an attacker can trigger that "
                 "deliberately to flush evidence without touching a single log file.",
        "validation": [
            "kubectl -n kube-system get pod -l component=kube-apiserver -o "
            "jsonpath='{{.items[0].spec.containers[0].command}}' | tr ',' '\\n' | "
            "grep -E 'audit-log-(maxbackup|maxsize)'",
        ],
    },
    "log-no-collector": {
        "summary": "No workload in the cluster looks like a log-shipping agent, so "
                   "container and audit logs exist only on the node that produced them.",
        "impact": "Logs on the node are logs an attacker can reach. Clearing a container "
                 "log or deleting Kubernetes events (MITRE T1070) destroys the only copy, "
                 "and a node that is drained, autoscaled away, or simply crashes takes its "
                 "logs with it. Shipping logs off-node is what turns them from a "
                 "convenience into evidence.",
        "validation": [
            "kubectl get daemonsets,deployments -A -o json | jq -r "
            "'.items[].spec.template.spec.containers[].image' | sort -u",
            "# look for fluent-bit / fluentd / vector / otel-collector / a vendor agent",
        ],
    },
}
