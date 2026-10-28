"""
How to fix each rule's finding: one sentence of intent and the smallest change that does it.

Kept beside (not inside) the knowledge base in finding_context.py: that file says what a
weakness IS and how to VERIFY it; this one says what to CHANGE. `how` is plain prose, `change`
is a snippet an engineer can paste, `check` is the command that proves the fix landed.
Every registered rule must have an entry (tests/test_remediation.py).
"""
from __future__ import annotations


def _r(how, change="", check=""):
    return {"how": how, "change": change, "check": check}


_SC = "securityContext"

FIXES: dict[str, dict] = {
    # ---- workloads ---------------------------------------------------------------------------
    "workload-privileged-container": _r(
        "Remove `privileged: true`. Grant only the specific capability the container needs.",
        f"{_SC}:\n  privileged: false\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop: [\"ALL\"]",
        "kubectl get <kind> <name> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.privileged}'"),
    "workload-allow-priv-escalation": _r(
        "Set `allowPrivilegeEscalation: false` so no child process can gain more privilege than its parent.",
        f"{_SC}:\n  allowPrivilegeEscalation: false"),
    "workload-run-as-root": _r(
        "Run as a non-root user and enforce it, so a compromised process is not UID 0.",
        f"{_SC}:\n  runAsNonRoot: true\n  runAsUser: 10001"),
    "workload-writable-root-fs": _r(
        "Make the root filesystem read-only and mount an `emptyDir` where the app must write.",
        f"{_SC}:\n  readOnlyRootFilesystem: true\nvolumeMounts:\n- {{name: tmp, mountPath: /tmp}}\n# volumes:\n# - {{name: tmp, emptyDir: {{}}}}"),
    "workload-dangerous-caps": _r(
        "Drop all capabilities and add back only what is required. SYS_ADMIN, NET_ADMIN, SYS_PTRACE and the like are near-root.",
        "capabilities:\n  drop: [\"ALL\"]\n  # add: [\"NET_BIND_SERVICE\"]   # only if truly needed"),
    "workload-caps-not-dropped": _r(
        "Drop every Linux capability by default.",
        "capabilities:\n  drop: [\"ALL\"]"),
    "workload-host-pid": _r(
        "Remove `hostPID: true`. A pod that shares the node's process namespace can see and signal every host process.",
        "spec:\n  hostPID: false"),
    "workload-host-network": _r(
        "Remove `hostNetwork: true` and expose the port through a Service instead.",
        "spec:\n  hostNetwork: false"),
    "workload-host-ipc": _r(
        "Remove `hostIPC: true` so the pod cannot read the host's shared memory.",
        "spec:\n  hostIPC: false"),
    "workload-docker-socket": _r(
        "Stop mounting the container runtime socket. Build images with a daemonless builder (Kaniko, BuildKit rootless) instead.",
        "# delete the hostPath volume for /var/run/docker.sock and its volumeMount"),
    "workload-hostpath-root": _r(
        "Remove the hostPath mount of `/` or another sensitive host directory. Use a PersistentVolumeClaim or emptyDir.",
        "# replace\n#   hostPath: {path: /}\n# with\n#   persistentVolumeClaim: {claimName: app-data}"),
    "workload-hostpath-writable": _r(
        "Prefer a PersistentVolumeClaim. If a hostPath is unavoidable, make it read-only and as narrow as possible.",
        "volumeMounts:\n- {name: logs, mountPath: /logs, readOnly: true}"),
    "workload-missing-limits": _r(
        "Set CPU and memory requests and limits so one container cannot starve the node.",
        "resources:\n  requests: {cpu: 50m, memory: 64Mi}\n  limits:   {cpu: 250m, memory: 128Mi}"),
    "workload-no-seccomp": _r(
        "Apply the runtime's default seccomp profile to filter dangerous syscalls.",
        "spec:\n  securityContext:\n    seccompProfile:\n      type: RuntimeDefault"),
    "workload-sa-token-automount": _r(
        "Do not mount the ServiceAccount token into pods that never call the Kubernetes API.",
        "spec:\n  automountServiceAccountToken: false"),
    "workload-latest-tag": _r(
        "Pin the image to an immutable version, ideally a digest, so a re-pull cannot silently change what runs.",
        "image: registry.example.com/app:1.4.2   # or app@sha256:<digest>"),
    "workload-image-vulnerabilities": _r(
        "Rebuild or update the image to a version that contains the fixed packages, redeploy, and re-scan. The result follows the image digest, so a patched rebuild clears it and a node still holding the old copy does not.",
        "image: registry.example.com/app:<patched-tag>@sha256:<new-digest>",
        "grype <image> --only-fixed"),
    "workload-sshd-present": _r(
        "Remove the SSH server from the image. Use `kubectl exec` / `kubectl debug` for access.",
        "# rebuild the image without openssh-server and drop the sshd command"),
    "rbac-create-pods": _r(
        "Remove `create` on `pods`; let a controller (Deployment, Job) create them.",
        "# delete `pods` from the role's create rule"),
    "rbac-system-masters": _r(
        "Remove the subject; bind a named, narrow role instead.",
        "kubectl delete clusterrolebinding <name>"),
    "rbac-create-pv": _r(
        "Remove `create` on `persistentvolumes`; provision storage through StorageClasses.",
        "# delete `persistentvolumes` from the role's create rule"),
    "rbac-node-proxy": _r(
        "Remove `nodes/proxy`; use the metrics APIs for monitoring.",
        "# delete `nodes/proxy` from the role's resources"),
    "rbac-csr-approve": _r(
        "Remove update/patch on `certificatesigningrequests/approval`.",
        "# delete `certificatesigningrequests/approval` from the role"),
    "rbac-webhook-config-write": _r(
        "Remove write access to the webhook configuration resources.",
        "# delete webhookconfigurations from the role's write rule"),
    "rbac-sa-token-create": _r(
        "Remove `create` on `serviceaccounts/token` or restrict it with `resourceNames`.",
        "resources: [\"serviceaccounts/token\"]\nresourceNames: [\"my-app\"]\nverbs: [\"create\"]"),
    "workload-host-port": _r(
        "Remove `hostPort`; expose the app through a Service.",
        "ports:\n- containerPort: 8080   # no hostPort"),
    "workload-share-process-ns": _r(
        "Remove `shareProcessNamespace: true` unless a debug sidecar truly needs it.",
        "spec:\n  shareProcessNamespace: false"),
    "workload-no-security-context": _r(
        "Set a pod and container securityContext.",
        "securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false\n  capabilities: {drop: [\"ALL\"]}"),
    "workload-windows-hostprocess": _r(
        "Remove `windowsOptions.hostProcess: true`.",
        "# delete securityContext.windowsOptions.hostProcess"),
    "workload-default-namespace": _r(
        "Move the workload to a dedicated namespace.",
        "kubectl create namespace my-app   # then redeploy with -n my-app"),
    # ---- RBAC ---------------------------------------------------------------------------------
    "rbac-wildcard-verbs": _r(
        "Replace `verbs: [\"*\"]` with the exact verbs needed.",
        "rules:\n- apiGroups: [\"\"]\n  resources: [\"pods\"]\n  verbs: [\"get\", \"list\", \"watch\"]"),
    "rbac-wildcard-resources": _r(
        "Replace `resources: [\"*\"]` with the exact resources needed.",
        "rules:\n- apiGroups: [\"\"]\n  resources: [\"pods\", \"services\"]\n  verbs: [\"get\", \"list\"]"),
    "rbac-secret-read-broad": _r(
        "Do not let a ClusterRole read Secrets cluster-wide. Use a namespaced Role limited to the Secret names that are needed.",
        "kind: Role   # not ClusterRole\nrules:\n- apiGroups: [\"\"]\n  resources: [\"secrets\"]\n  resourceNames: [\"app-config\"]\n  verbs: [\"get\"]"),
    "rbac-bind-escalate-verbs": _r(
        "Remove `bind`, `escalate` and `impersonate`. They let the holder grant themselves any permission.",
        "# delete those verbs from the role's rules"),
    "rbac-can-delete-events": _r(
        "Remove `delete` on `events`. Anyone who can delete events can erase the trail of what they did.",
        "# delete `events` from the role's delete rule"),
    "rbac-coredns-configmap-write": _r(
        "Restrict ConfigMap write access to named ConfigMaps and never to kube-system's CoreDNS.",
        "resources: [\"configmaps\"]\nresourceNames: [\"my-app-config\"]\nverbs: [\"get\", \"update\"]"),
    "rbac-cluster-admin-default-sa": _r(
        "Remove the binding that makes the default ServiceAccount cluster-admin. Create a dedicated ServiceAccount with a narrow role.",
        "kubectl delete clusterrolebinding <name>",
        "kubectl auth can-i '*' '*' --as=system:serviceaccount:<ns>:default"),
    "rbac-cluster-admin-user-binding": _r(
        "Confirm this person still needs unrestricted access. Prefer a time-boxed, audited grant or a narrower role.",
        "kubectl delete clusterrolebinding <name>   # or bind a narrower ClusterRole"),
    "rbac-broad-subject-admin": _r(
        "Never bind admin to `system:authenticated`, `system:unauthenticated` or `system:anonymous`. Remove the binding.",
        "kubectl delete clusterrolebinding <name>",
        "kubectl auth can-i '*' '*' --as=system:anonymous"),
    # ---- network ----------------------------------------------------------------------------------
    "net-no-networkpolicy": _r(
        "Add a default-deny NetworkPolicy to the namespace, then allow only the flows the app needs.",
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: default-deny-all}\nspec:\n  podSelector: {}\n  policyTypes: [Ingress, Egress]"),
    "net-metadata-api-open": _r(
        "Add an egress policy that blocks the cloud metadata address, 169.254.169.254.",
        "egress:\n- to:\n  - ipBlock: {cidr: 0.0.0.0/0, except: [169.254.169.254/32]}"),
    "net-nodeport-service": _r(
        "Use ClusterIP behind an Ingress or a LoadBalancer with source ranges. A NodePort opens a port on every node.",
        "spec:\n  type: ClusterIP"),
    "net-lb-no-source-range": _r(
        "Restrict who may reach the LoadBalancer.",
        "spec:\n  loadBalancerSourceRanges: [\"203.0.113.0/24\"]"),
    "net-dashboard-exposed": _r(
        "Do not expose the Kubernetes dashboard. Reach it through `kubectl proxy` or an authenticating gateway.",
        "spec:\n  type: ClusterIP"),
    "net-ingress-no-tls": _r(
        "Terminate TLS at the Ingress.",
        "spec:\n  tls:\n  - hosts: [app.example.com]\n    secretName: app-tls"),
    # ---- secrets -----------------------------------------------------------------------------------
    "sec-env-var-secrets": _r(
        "Mount the Secret as a read-only file instead of an environment variable, which leaks into logs, crash dumps and child processes.",
        "volumes:\n- {name: creds, secret: {secretName: db-credentials}}\nvolumeMounts:\n- {name: creds, mountPath: /etc/creds, readOnly: true}"),
    "sec-configmap-credentials": _r(
        "Move the credential out of the ConfigMap into a Secret (or an external secret store), and rotate it, since it has been readable.",
        "kubectl create secret generic app-creds --from-literal=password=<new>"),
    "sec-mounted-cloud-creds": _r(
        "Replace mounted cloud credential files with workload identity (IRSA, GKE Workload Identity, Azure Workload Identity).",
        "# annotate the ServiceAccount with the cloud role and remove the credentials mount"),
    "sec-etcd-not-encrypted": _r(
        "Enable encryption at rest for Secrets in the API server.",
        "--encryption-provider-config=/etc/kubernetes/enc.yaml",
        "kubectl -n kube-system get pod -l component=kube-apiserver -o yaml | grep encryption-provider-config"),
    # ---- compliance, attack surface, logging -----------------------------------------------------------
    "compliance-psa-not-restricted": _r(
        "Enforce the `restricted` Pod Security Standard on the namespace.",
        "kubectl label ns <ns> pod-security.kubernetes.io/enforce=restricted --overwrite"),
    "as-sa-fanout": _r(
        "Give each workload its own ServiceAccount so a compromise of one does not inherit the others' access.",
        "kubectl create serviceaccount <workload>-sa -n <ns>   # then set serviceAccountName"),
    "log-audit-policy-missing": _r(
        "Configure an audit policy file on the API server.",
        "--audit-policy-file=/etc/kubernetes/audit-policy.yaml"),
    "log-audit-retention-short": _r(
        "Keep audit logs at least 30 days.",
        "--audit-log-maxage=30"),
    "log-audit-rotation-weak": _r(
        "Keep more, larger audit-log files so a busy hour cannot discard the entries that matter.",
        "--audit-log-maxbackup=10\n--audit-log-maxsize=100"),
    "log-no-collector": _r(
        "Run a log collector (Fluent Bit, Vector, the OpenTelemetry Collector) that ships logs off the node.",
        "helm install fluent-bit fluent/fluent-bit -n logging --create-namespace"),
}


def fix_for(rule_id: str) -> dict:
    return FIXES.get(rule_id, {})
