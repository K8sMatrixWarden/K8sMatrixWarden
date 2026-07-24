"""
Complete CIS Kubernetes Benchmark v1.8 control catalog (130 controls).

Sourced verbatim from kube-bench's `cfg/cis-1.8/*.yaml`. Section totals:
  §1 Control Plane 60 · §2 etcd 7 · §3 Config 5 · §4 Worker Nodes 23 · §5 Policies 35 = 130

Evaluation method per control (`ev`), chosen so whatever the K8s API can prove is proven
from the API, and only genuinely node-local reads are delegated:

  native    , mapped domain-shard rule(s): rule fired ⇒ FAIL, else PASS.
  builtin   , purpose-built evaluator in cis.py.
  component , control-plane / kubelet PROCESS FLAG, read from the ComponentConfig evidence
               (built live by parsing kube-system static-pod specs + kubelet config, §mitigation
               Layer 1/2). Each carries a `check = (component, flag, op, value)` predicate.
  kube-bench, node FILE permission/ownership read; requires on-node access → kube-bench JSON.
  manual    , CIS-designated manual review.

Mitigation split (see §5.9.2): 25 native + 2 builtin + 38 component = 65 evaluated from the
API; 31 kube-bench (true node-file reads); 34 manual.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class CisControl:
    id: str
    title: str
    type: str                 # Automated | Manual (from CIS)
    ev: str                   # native | builtin | component | kube-bench | manual
    rules: tuple = ()         # native rule ids (ev == native)
    check: Optional[Tuple] = None   # (component, flag, op, value) for ev == component

    @property
    def section(self) -> str:
        return self.id.split(".")[0]


SECTION_NAMES = {
    "1": "Control Plane Components", "2": "etcd", "3": "Control Plane Configuration",
    "4": "Worker Nodes", "5": "Policies",
}
# Sections that live on the (possibly managed) control plane, marked N/A on managed profiles.
CONTROL_PLANE_SECTIONS = {"1", "2", "3"}


def _c(id, title, typ, ev, *rules, check=None):
    return CisControl(id, title, typ, ev, tuple(rules), check)


def _comp(id, title, typ, component, flag, op, value=""):
    return CisControl(id, title, typ, "component", (), (component, flag, op, value))


CIS_1_8: list[CisControl] = [
    # ── 1.1 Control Plane Node Configuration Files (file perms/ownership → node) ──
    _c("1.1.1", "API server pod spec file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.2", "API server pod spec file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.3", "Controller manager pod spec file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.4", "Controller manager pod spec file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.5", "Scheduler pod spec file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.6", "Scheduler pod spec file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.7", "etcd pod spec file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.8", "etcd pod spec file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.9", "CNI file permissions 600 or more restrictive", "Manual", "kube-bench"),
    _c("1.1.10", "CNI file ownership root:root", "Manual", "kube-bench"),
    _c("1.1.11", "etcd data directory permissions 700 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.12", "etcd data directory ownership etcd:etcd", "Automated", "kube-bench"),
    _c("1.1.13", "admin.conf file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.14", "admin.conf file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.15", "scheduler.conf file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.16", "scheduler.conf file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.17", "controller-manager.conf file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("1.1.18", "controller-manager.conf file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.19", "Kubernetes PKI directory and file ownership root:root", "Automated", "kube-bench"),
    _c("1.1.20", "Kubernetes PKI certificate file permissions 600 or more restrictive", "Manual", "kube-bench"),
    _c("1.1.21", "Kubernetes PKI key file permissions 600", "Manual", "kube-bench"),
    # ── 1.2 API Server ──
    _c("1.2.1", "--anonymous-auth argument is set to false", "Manual", "native", "apiserver-anonymous-auth"),
    _comp("1.2.2", "--token-auth-file parameter is not set", "Automated", "apiServer", "token-auth-file", "unset"),
    _comp("1.2.3", "--DenyServiceExternalIPs is set", "Manual", "apiServer", "enable-admission-plugins", "admission_has", "DenyServiceExternalIPs"),
    _comp("1.2.4", "--kubelet-client-certificate and --kubelet-client-key set", "Automated", "apiServer", "kubelet-client-certificate", "set"),
    _comp("1.2.5", "--kubelet-certificate-authority argument set", "Automated", "apiServer", "kubelet-certificate-authority", "set"),
    _comp("1.2.6", "--authorization-mode is not set to AlwaysAllow", "Automated", "apiServer", "authorization-mode", "not_contains", "AlwaysAllow"),
    _comp("1.2.7", "--authorization-mode includes Node", "Automated", "apiServer", "authorization-mode", "contains", "Node"),
    _comp("1.2.8", "--authorization-mode includes RBAC", "Automated", "apiServer", "authorization-mode", "contains", "RBAC"),
    _c("1.2.9", "Admission plugin EventRateLimit is set", "Manual", "manual"),
    _comp("1.2.10", "Admission plugin AlwaysAdmit is not set", "Automated", "apiServer", "enable-admission-plugins", "admission_not", "AlwaysAdmit"),
    _c("1.2.11", "Admission plugin AlwaysPullImages is set", "Manual", "manual"),
    _c("1.2.12", "Admission plugin SecurityContextDeny set (if PSP not used)", "Manual", "manual"),
    _comp("1.2.13", "Admission plugin ServiceAccount is set", "Automated", "apiServer", "disable-admission-plugins", "admission_not", "ServiceAccount"),
    _comp("1.2.14", "Admission plugin NamespaceLifecycle is set", "Automated", "apiServer", "disable-admission-plugins", "admission_not", "NamespaceLifecycle"),
    _comp("1.2.15", "Admission plugin NodeRestriction is set", "Automated", "apiServer", "enable-admission-plugins", "admission_has", "NodeRestriction"),
    _comp("1.2.16", "--profiling argument is set to false", "Automated", "apiServer", "profiling", "eq", "false"),
    _c("1.2.17", "--audit-log-path argument is set", "Automated", "native", "apiserver-audit-logging"),
    _comp("1.2.18", "--audit-log-maxage set to 30 or as appropriate", "Automated", "apiServer", "audit-log-maxage", "set"),
    _comp("1.2.19", "--audit-log-maxbackup set to 10 or as appropriate", "Automated", "apiServer", "audit-log-maxbackup", "set"),
    _comp("1.2.20", "--audit-log-maxsize set to 100 or as appropriate", "Automated", "apiServer", "audit-log-maxsize", "set"),
    _c("1.2.21", "--request-timeout argument set as appropriate", "Manual", "manual"),
    _comp("1.2.22", "--service-account-lookup argument set to true", "Automated", "apiServer", "service-account-lookup", "eq", "true"),
    _comp("1.2.23", "--service-account-key-file argument set", "Automated", "apiServer", "service-account-key-file", "set"),
    _comp("1.2.24", "--etcd-certfile and --etcd-keyfile set", "Automated", "apiServer", "etcd-certfile", "set"),
    _comp("1.2.25", "--tls-cert-file and --tls-private-key-file set", "Automated", "apiServer", "tls-cert-file", "set"),
    _comp("1.2.26", "--client-ca-file argument set", "Automated", "apiServer", "client-ca-file", "set"),
    _comp("1.2.27", "--etcd-cafile argument set", "Automated", "apiServer", "etcd-cafile", "set"),
    _c("1.2.28", "--encryption-provider-config argument set", "Manual", "native", "etcd-encryption-missing"),
    _c("1.2.29", "Encryption providers appropriately configured", "Manual", "manual"),
    _c("1.2.30", "API Server uses only strong cryptographic ciphers", "Manual", "manual"),
    # ── 1.3 Controller Manager ──
    _c("1.3.1", "--terminated-pod-gc-threshold set as appropriate", "Manual", "manual"),
    _comp("1.3.2", "--profiling argument is set to false", "Automated", "controllerManager", "profiling", "eq", "false"),
    _comp("1.3.3", "--use-service-account-credentials set to true", "Automated", "controllerManager", "use-service-account-credentials", "eq", "true"),
    _comp("1.3.4", "--service-account-private-key-file set", "Automated", "controllerManager", "service-account-private-key-file", "set"),
    _comp("1.3.5", "--root-ca-file argument set", "Automated", "controllerManager", "root-ca-file", "set"),
    _comp("1.3.6", "RotateKubeletServerCertificate set to true", "Automated", "controllerManager", "feature-gates", "feature_true", "RotateKubeletServerCertificate"),
    _comp("1.3.7", "--bind-address argument set to 127.0.0.1", "Automated", "controllerManager", "bind-address", "eq", "127.0.0.1"),
    # ── 1.4 Scheduler ──
    _comp("1.4.1", "--profiling argument is set to false", "Automated", "scheduler", "profiling", "eq", "false"),
    _comp("1.4.2", "--bind-address argument set to 127.0.0.1", "Automated", "scheduler", "bind-address", "eq", "127.0.0.1"),
    # ── 2 etcd ──
    _comp("2.1", "--cert-file and --key-file arguments set", "Automated", "etcd", "cert-file", "set"),
    _c("2.2", "--client-cert-auth argument set to true", "Automated", "native", "etcd-client-cert-auth"),
    _comp("2.3", "--auto-tls argument is not set to true", "Automated", "etcd", "auto-tls", "not_true"),
    _comp("2.4", "--peer-cert-file and --peer-key-file set", "Automated", "etcd", "peer-cert-file", "set"),
    _comp("2.5", "--peer-client-cert-auth argument set to true", "Automated", "etcd", "peer-client-cert-auth", "eq", "true"),
    _comp("2.6", "--peer-auto-tls argument is not set to true", "Automated", "etcd", "peer-auto-tls", "not_true"),
    _c("2.7", "Unique Certificate Authority used for etcd", "Manual", "manual"),
    # ── 3.1 Authentication and Authorization ──
    _c("3.1.1", "Client certificate authentication not used for users", "Manual", "manual"),
    _c("3.1.2", "Service account token authentication not used for users", "Manual", "manual"),
    _c("3.1.3", "Bootstrap token authentication not used for users", "Manual", "manual"),
    # ── 3.2 Logging ──
    _c("3.2.1", "A minimal audit policy is created", "Manual", "manual"),
    _c("3.2.2", "Audit policy covers key security concerns", "Manual", "manual"),
    # ── 4.1 Worker Node Configuration Files (file perms/ownership → node) ──
    _c("4.1.1", "kubelet service file permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("4.1.2", "kubelet service file ownership root:root", "Automated", "kube-bench"),
    _c("4.1.3", "proxy kubeconfig file permissions 600 or more restrictive", "Manual", "kube-bench"),
    _c("4.1.4", "proxy kubeconfig file ownership root:root", "Manual", "kube-bench"),
    _c("4.1.5", "--kubeconfig kubelet.conf permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("4.1.6", "--kubeconfig kubelet.conf ownership root:root", "Automated", "kube-bench"),
    _c("4.1.7", "Certificate authorities file permissions 600 or more restrictive", "Manual", "kube-bench"),
    _c("4.1.8", "Client certificate authorities file ownership root:root", "Manual", "kube-bench"),
    _c("4.1.9", "kubelet config.yaml permissions 600 or more restrictive", "Automated", "kube-bench"),
    _c("4.1.10", "kubelet config.yaml file ownership root:root", "Automated", "kube-bench"),
    # ── 4.2 Kubelet ──
    _c("4.2.1", "--anonymous-auth argument set to false", "Automated", "native", "kubelet-anonymous-auth"),
    _c("4.2.2", "--authorization-mode not set to AlwaysAllow", "Automated", "native", "kubelet-authz-always-allow"),
    _comp("4.2.3", "--client-ca-file argument set", "Automated", "kubelet", "client-ca-file", "set"),
    _c("4.2.4", "--read-only-port argument set to 0", "Manual", "native", "kubelet-read-only-port"),
    _comp("4.2.5", "--streaming-connection-idle-timeout not set to 0", "Manual", "kubelet", "streaming-connection-idle-timeout", "not_zero"),
    _comp("4.2.6", "--make-iptables-util-chains set to true", "Automated", "kubelet", "make-iptables-util-chains", "eq", "true"),
    _c("4.2.7", "--hostname-override argument is not set", "Manual", "manual"),
    _c("4.2.8", "eventRecordQPS set to ensure appropriate event capture", "Manual", "manual"),
    _c("4.2.9", "--tls-cert-file and --tls-private-key-file set", "Manual", "manual"),
    _comp("4.2.10", "--rotate-certificates argument is not set to false", "Automated", "kubelet", "rotate-certificates", "not_false"),
    _c("4.2.11", "RotateKubeletServerCertificate set to true", "Manual", "manual"),
    _c("4.2.12", "Kubelet uses only strong cryptographic ciphers", "Manual", "manual"),
    _c("4.2.13", "A limit is set on pod PIDs", "Manual", "manual"),
    # ── 5.1 RBAC and Service Accounts ──
    _c("5.1.1", "cluster-admin role only used where required", "Manual", "native", "rbac-cluster-admin-default-sa"),
    _c("5.1.2", "Minimize access to secrets", "Manual", "native", "rbac-secret-read-broad"),
    _c("5.1.3", "Minimize wildcard use in Roles and ClusterRoles", "Manual", "native",
       "rbac-wildcard-verbs", "rbac-wildcard-resources"),
    _c("5.1.4", "Minimize access to create pods", "Manual", "manual"),
    _c("5.1.5", "Default service accounts are not actively used", "Manual", "manual"),
    _c("5.1.6", "Service Account Tokens only mounted where necessary", "Manual", "native",
       "workload-sa-token-automount"),
    _c("5.1.7", "Avoid use of system:masters group", "Manual", "manual"),
    _c("5.1.8", "Limit use of Bind, Impersonate and Escalate permissions", "Manual", "native",
       "rbac-bind-escalate-verbs"),
    _c("5.1.9", "Minimize access to create persistent volumes", "Manual", "manual"),
    _c("5.1.10", "Minimize access to the proxy sub-resource of nodes", "Manual", "manual"),
    _c("5.1.11", "Minimize access to the approval sub-resource of CSRs", "Manual", "manual"),
    _c("5.1.12", "Minimize access to webhook configuration objects", "Manual", "manual"),
    _c("5.1.13", "Minimize access to the service account token creation", "Manual", "manual"),
    # ── 5.2 Pod Security Standards ──
    _c("5.2.1", "Cluster has at least one active policy control mechanism", "Manual", "native",
       "compliance-psa-not-restricted"),
    _c("5.2.2", "Minimize the admission of privileged containers", "Manual", "native",
       "workload-privileged-container"),
    _c("5.2.3", "Minimize admission of containers sharing host PID namespace", "Manual", "native",
       "workload-host-pid"),
    _c("5.2.4", "Minimize admission of containers sharing host IPC namespace", "Manual", "native",
       "workload-host-ipc"),
    _c("5.2.5", "Minimize admission of containers sharing host network namespace", "Manual", "native",
       "workload-host-network"),
    _c("5.2.6", "Minimize admission of containers with allowPrivilegeEscalation", "Manual", "native",
       "workload-allow-priv-escalation"),
    _c("5.2.7", "Minimize the admission of root containers", "Manual", "native", "workload-run-as-root"),
    _c("5.2.8", "Minimize the admission of containers with NET_RAW capability", "Manual", "native",
       "workload-dangerous-caps"),
    _c("5.2.9", "Minimize the admission of containers with added capabilities", "Manual", "native",
       "workload-caps-not-dropped", "workload-dangerous-caps"),
    _c("5.2.10", "Minimize the admission of containers with capabilities assigned", "Manual", "manual"),
    _c("5.2.11", "Minimize the admission of Windows HostProcess containers", "Manual", "manual"),
    _c("5.2.12", "Minimize the admission of HostPath volumes", "Manual", "native",
       "workload-hostpath-root", "workload-hostpath-writable"),
    _c("5.2.13", "Minimize the admission of containers which use HostPorts", "Manual", "builtin"),
    # ── 5.3 Network Policies and CNI ──
    _c("5.3.1", "CNI in use supports NetworkPolicies", "Manual", "manual"),
    _c("5.3.2", "All Namespaces have NetworkPolicies defined", "Manual", "native", "net-no-networkpolicy"),
    # ── 5.4 Secrets Management ──
    _c("5.4.1", "Prefer Secrets as files over Secrets as environment variables", "Manual", "native",
       "sec-env-var-secrets"),
    _c("5.4.2", "Consider external secret storage", "Manual", "manual"),
    # ── 5.5 Extensible Admission Control ──
    _c("5.5.1", "Configure Image Provenance using ImagePolicyWebhook", "Manual", "manual"),
    # ── 5.7 General Policies ──
    _c("5.7.1", "Create administrative boundaries between resources using namespaces", "Manual", "manual"),
    _c("5.7.2", "Ensure seccomp profile is set to docker/default in Pod definitions", "Manual", "native",
       "workload-no-seccomp"),
    _c("5.7.3", "Apply SecurityContext to your Pods and Containers", "Manual", "manual"),
    _c("5.7.4", "The default namespace should not be used", "Manual", "builtin"),
]

BENCHMARK_VERSION = "cis-1.8"
BENCHMARK_TITLE = "CIS Kubernetes Benchmark v1.8"


def catalog_summary() -> dict:
    from collections import Counter
    return {
        "total": len(CIS_1_8),
        "by_section": dict(sorted(Counter(c.section for c in CIS_1_8).items())),
        "by_eval": dict(Counter(c.ev for c in CIS_1_8)),
    }
