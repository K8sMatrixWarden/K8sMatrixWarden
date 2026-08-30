"""
Realistic cluster fixtures for the end-to-end integration tests.

The bundled mock cluster is a broad "lots of things are wrong" sample. It is good for
breadth and useless for proving that one specific attack chain is represented coherently
from evidence to report, because too much else is firing at the same time.

Each fixture here is a small, purpose-built cluster that isolates ONE scenario, so a test
can assert the whole pipeline's behaviour on it without the assertion being an accident of
some unrelated finding. They are plain dicts in the same shape the mock collector loads,
which is the same camelCase shape the live collector produces.
"""
from __future__ import annotations

import copy


def _pod(name, ns, labels, *, sa=None, privileged=False, run_as_non_root=None,
         read_only_fs=None, host_path=False):
    container = {"name": "app", "image": "app:1.0", "securityContext": {}}
    if privileged:
        container["securityContext"]["privileged"] = True
    if read_only_fs is not None:
        container["securityContext"]["readOnlyRootFilesystem"] = read_only_fs
    spec = {"containers": [container]}
    if sa:
        spec["serviceAccountName"] = sa
    if run_as_non_root is not None:
        spec["securityContext"] = {"runAsNonRoot": run_as_non_root}
    if host_path:
        spec["volumes"] = [{"name": "host", "hostPath": {"path": "/"}}]
        container["volumeMounts"] = [{"name": "host", "mountPath": "/host"}]
    return {"kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": spec}


def _svc(name, ns, selector, svc_type="ClusterIP"):
    return {"kind": "Service",
            "metadata": {"name": name, "namespace": ns},
            "spec": {"type": svc_type, "selector": selector,
                     "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}]}}


def _ingress(name, ns, service):
    return {"kind": "Ingress", "metadata": {"name": name, "namespace": ns},
            "spec": {"rules": [{"host": "app.example.com", "http": {"paths": [
                {"path": "/", "backend": {"service": {"name": service,
                                                      "port": {"number": 80}}}}]}}]}}


def _sa(name, ns):
    return {"kind": "ServiceAccount", "metadata": {"name": name, "namespace": ns}}


def _role(name, ns, rules):
    return {"kind": "Role", "metadata": {"name": name, "namespace": ns}, "rules": rules}


def _crole(name, rules):
    return {"kind": "ClusterRole", "metadata": {"name": name}, "rules": rules}


def _rolebinding(name, ns, role, sa, sa_ns, role_kind="Role"):
    return {"kind": "RoleBinding", "metadata": {"name": name, "namespace": ns},
            "roleRef": {"kind": role_kind, "name": role},
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": sa_ns}]}


def _namespace(name, labels=None):
    return {"kind": "Namespace", "metadata": {"name": name, "labels": labels or {}}}


def _empty() -> dict:
    """Every bucket the collector may ask for, so an unlisted kind reads as an empty
    cluster rather than a missing key."""
    return {"namespaces": [], "pods": [], "deployments": [], "daemonsets": [],
            "statefulsets": [], "replicasets": [], "jobs": [], "cronjobs": [],
            "services": [], "ingresses": [], "networkpolicies": [], "serviceaccounts": [],
            "secrets": [], "configmaps": [], "roles": [], "rolebindings": [],
            "clusterroles": [], "clusterrolebindings": [],
            "mutatingwebhookconfigurations": [], "validatingwebhookconfigurations": [],
            "componentconfig": [], "cloudiam": []}


# --------------------------------------------------------------------------- #
# Scenario A, Internet -> Ingress -> Service -> Pod -> SA -> RoleBinding -> Role
#             -> secrets/get
# --------------------------------------------------------------------------- #
def scenario_a() -> dict:
    """The full chain, every hop backed by a real object.

    payment-api is fronted by an Ingress, runs as a ServiceAccount that a RoleBinding ties
    to a Role granting `get` on secrets, and the pod itself is privileged so the scanner
    has a finding to hang the chain on.
    """
    c = _empty()
    c["namespaces"] = [_namespace("production", {"env": "prod"})]
    c["pods"] = [_pod("payment-api", "production", {"app": "payment"},
                      sa="payment-api", privileged=True)]
    c["services"] = [_svc("payment", "production", {"app": "payment"})]
    c["ingresses"] = [_ingress("payment-ingress", "production", "payment")]
    c["serviceaccounts"] = [_sa("payment-api", "production")]
    c["roles"] = [_role("payment-reader", "production",
                        [{"apiGroups": [""], "resources": ["secrets"],
                          "verbs": ["get", "list"]}])]
    c["rolebindings"] = [_rolebinding("payment-api-binding", "production",
                                      "payment-reader", "payment-api", "production")]
    c["secrets"] = [{"kind": "Secret", "metadata": {"name": "stripe-key",
                                                    "namespace": "production"},
                     "type": "Opaque", "data": {"key": "c2VjcmV0"}}]
    return c


# --------------------------------------------------------------------------- #
# Scenario B, the same exposure, but a NetworkPolicy blocks the ingress path
# --------------------------------------------------------------------------- #
def scenario_b() -> dict:
    """Identical to A plus a default-deny ingress NetworkPolicy selecting the pod.

    The vulnerability is unchanged and must keep its severity; only the reachability
    context may change.
    """
    c = scenario_a()
    c["networkpolicies"] = [{
        "kind": "NetworkPolicy",
        "metadata": {"name": "deny-ingress", "namespace": "production"},
        "spec": {"podSelector": {"matchLabels": {"app": "payment"}},
                 "policyTypes": ["Ingress"]}}]
    return c


def scenario_b_expression_selector() -> dict:
    """Scenario B with the policy selecting by matchExpressions instead of matchLabels.
    Semantically identical; a selector engine that only understands matchLabels would
    wrongly report the pod as exposed."""
    c = scenario_a()
    c["pods"][0]["metadata"]["labels"]["tier"] = "frontend"
    c["networkpolicies"] = [{
        "kind": "NetworkPolicy",
        "metadata": {"name": "deny-ingress-expr", "namespace": "production"},
        "spec": {"podSelector": {"matchExpressions": [
            {"key": "tier", "operator": "In", "values": ["frontend"]}]},
            "policyTypes": ["Ingress"]}}]
    return c


def scenario_b_unevaluable_policy() -> dict:
    """A policy this build cannot evaluate (an operator Kubernetes does not define).
    Must resolve to `partial`, which is neither isolation nor open."""
    c = scenario_a()
    c["networkpolicies"] = [{
        "kind": "NetworkPolicy",
        "metadata": {"name": "weird", "namespace": "production"},
        "spec": {"podSelector": {"matchExpressions": [
            {"key": "app", "operator": "Regex", "values": ["pay.*"]}]},
            "policyTypes": ["Ingress"]}}]
    return c


# --------------------------------------------------------------------------- #
# Scenario F, two namespaces, same workload names and labels
# --------------------------------------------------------------------------- #
def scenario_f() -> dict:
    """`api` exists in both `alpha` and `beta` with identical labels and an identically
    named ServiceAccount. Only alpha's SA is bound to anything privileged, and only
    alpha's pod is exposed. Nothing about beta may inherit alpha's conclusions."""
    c = _empty()
    c["namespaces"] = [_namespace("alpha"), _namespace("beta")]
    c["pods"] = [_pod("api", "alpha", {"app": "api"}, sa="api-sa", privileged=True),
                 _pod("api", "beta", {"app": "api"}, sa="api-sa", privileged=True)]
    c["services"] = [_svc("api", "alpha", {"app": "api"}, svc_type="LoadBalancer"),
                     _svc("api", "beta", {"app": "api"})]
    c["serviceaccounts"] = [_sa("api-sa", "alpha"), _sa("api-sa", "beta")]
    c["clusterroles"] = [_crole("secret-reader",
                                [{"apiGroups": [""], "resources": ["secrets"],
                                  "verbs": ["get"]}])]
    c["rolebindings"] = [_rolebinding("api-binding", "alpha", "secret-reader",
                                      "api-sa", "alpha", role_kind="ClusterRole")]
    return c


# --------------------------------------------------------------------------- #
# Runtime event batches (scenarios C and D)
# --------------------------------------------------------------------------- #
def runtime_shell_in_payment_api() -> list[dict]:
    """Scenario C: a shell spawned, then a sensitive file read, both naming the pod a
    static finding is on. Flat internal shape, i.e. post-normalisation."""
    return [
        {"source": "falco", "proc": "bash", "pod": "payment-api",
         "namespace": "production", "time": "2026-08-30T10:00:00Z",
         "rule": "Terminal shell in container"},
        {"source": "falco", "proc": "cat", "file": "/var/run/secrets/kubernetes.io/token",
         "pod": "payment-api", "namespace": "production",
         "time": "2026-08-30T10:00:05Z", "rule": "Read sensitive file"},
        {"source": "audit", "verb": "list", "resource": "secrets",
         "namespace": "production", "pod": "payment-api",
         "time": "2026-08-30T10:00:09Z"},
    ]


def runtime_unrelated_namespace() -> list[dict]:
    """A shell in a completely different namespace. Must not touch production's findings."""
    return [{"source": "falco", "proc": "bash", "pod": "other-pod",
             "namespace": "sandbox", "time": "2026-08-30T10:00:00Z"}]


def scenario_d() -> dict:
    """A pod that DECLARES runAsNonRoot and readOnlyRootFilesystem, for the drift test."""
    c = _empty()
    c["namespaces"] = [_namespace("production")]
    c["pods"] = [_pod("hardened", "production", {"app": "hardened"},
                      sa="hardened", run_as_non_root=True, read_only_fs=True)]
    c["serviceaccounts"] = [_sa("hardened", "production")]
    return c


def runtime_contradicting_posture() -> list[dict]:
    """Runtime behaviour that contradicts scenario D's declared posture."""
    return [
        {"source": "falco", "proc": "sh", "uid": "0", "pod": "hardened",
         "namespace": "production", "time": "2026-08-30T11:00:00Z"},
        {"source": "falco", "proc": "tee", "op": "write", "file": "/etc/passwd",
         "pod": "hardened", "namespace": "production",
         "time": "2026-08-30T11:00:02Z"},
    ]


def write_fixture(data: dict, directory: str, name: str = "cluster.json") -> str:
    """Persist a fixture where the collector (and the CLI's --fixture flag) can load it."""
    import json
    import os
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(copy.deepcopy(data), fh, indent=2)
    return path
