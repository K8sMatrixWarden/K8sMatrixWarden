"""
K8s Security MCP Server, the 5 knowledge datasets (§10).

  1. kubectl Security Commands
  2. Scanning Tool Commands
  3. CVE Knowledge Base
  4. Compliance Rule Sets
  5. Taxonomy Files  (loaded from k8smatrixwarden/taxonomy via bootstrap)

These are plain Python/JSON so the agents and CLI can query them with or without the MCP
protocol layer. `mcp/server.py` exposes them over MCP when the SDK is installed.
"""
from __future__ import annotations

# --- Dataset 1: kubectl Security Commands -------------------------------- #
KUBECTL_COMMANDS = {
    "list-privileged-pods":
        "kubectl get pods -A -o json | jq '.items[] | "
        "select(.spec.containers[].securityContext.privileged==true) | .metadata.name'",
    "list-hostnetwork-pods":
        "kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true) | "
        ".metadata.namespace + \"/\" + .metadata.name'",
    "cluster-admin-bindings":
        "kubectl get clusterrolebindings -o json | jq '.items[] | "
        "select(.roleRef.name==\"cluster-admin\") | .subjects'",
    "wildcard-clusterroles":
        "kubectl get clusterroles -o json | jq '.items[] | select(.rules[].verbs[]==\"*\")'",
    "can-i-list":
        "kubectl auth can-i --list --as=system:serviceaccount:{namespace}:{sa}",
    "networkpolicies":
        "kubectl get networkpolicies -A",
    "nodeport-services":
        "kubectl get svc -A -o json | jq '.items[] | select(.spec.type==\"NodePort\")'",
    "mutating-webhooks":
        "kubectl get mutatingwebhookconfigurations -o json | jq '.items[].webhooks[] | "
        "{name, clientConfig, failurePolicy}'",
    "cronjobs":
        "kubectl get cronjobs -A -o wide",
}

# --- Dataset 2: Scanning Tool Commands ----------------------------------- #
TOOL_COMMANDS = {
    "trivy": [
        "trivy image --severity CRITICAL,HIGH {image}",
        "trivy k8s --report summary cluster",
    ],
    "kube-bench": ["kube-bench run --targets master,node,etcd,policies --json"],
    "kubeaudit": ["kubeaudit all"],
    "kubesec": ["kubesec scan {manifest}"],
    "kubescape": ["kubescape scan framework nsa,mitre,cis-v1.23"],
    "popeye": ["popeye -A --out json"],
    "trufflehog": ["trufflehog docker --image {image}"],
    "cosign": ["cosign verify {image}", "cosign verify-attestation {image}"],
}

# --- Dataset 3: CVE Knowledge Base (subset, §15.1) ----------------------- #
CVE_KB = {
    "CVE-2018-1002105": {"severity": "CRITICAL", "affects": "<1.10.11",
                         "desc": "API server websocket upgrade -> unauth cluster-admin"},
    "CVE-2020-8554": {"severity": "MEDIUM", "affects": "all",
                      "desc": "MitM via LoadBalancer/ExternalIP"},
    "CVE-2021-25741": {"severity": "HIGH", "affects": "<1.22.1",
                       "desc": "Symlink -> hostPath escape via subPath"},
    "CVE-2024-3177": {"severity": "HIGH", "affects": "<1.30",
                      "desc": "Bypass mountable secrets via ephemeral containers"},
    "CVE-2024-9486": {"severity": "CRITICAL", "affects": "image-builder",
                      "desc": "K8s Image Builder VMs with default credentials"},
}

# --- Dataset 4: Compliance Rule Sets (pointers) -------------------------- #
COMPLIANCE_RULES = {
    "CIS": {"version": "1.8", "tool": "kube-bench", "pass_threshold": 80},
    "PSS": {"levels": ["Privileged", "Baseline", "Restricted"], "enforce": "restricted"},
    "NSA_CISA": {"tool": "kubescape", "sections": ["Pod Security", "Network Policy",
                                                   "Authentication", "Audit Logging",
                                                   "Upgrading"]},
}
