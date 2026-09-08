"""
Exec needs `create` OR `get`, and the second one is easy to talk yourself out of.

This file exists because a live EKS audit nearly removed a real detection.

`system:controller:generic-garbage-collector` holds
`apiGroups:[*] resources:[*] verbs:[delete,get,list,patch,update,watch]` -- everything
except `create`. KMW reported it as able to exec into a pod and take that pod's
ServiceAccount token. The obvious check disagreed:

    kubectl auth can-i create pods/exec --as=system:serviceaccount:kube-system:generic-garbage-collector
    no

which looks conclusive, and is not. Exec has two transports. SPDY is a POST and authorizes
as `create`; WebSocket is a GET and authorizes as `get`, and WebSocket has been kubectl's
default since 1.30. Running it settled it:

    kubectl auth can-i get pods/exec --as=...:generic-garbage-collector      -> yes
    kubectl exec --as=...:generic-garbage-collector -- echo EXEC_SUCCEEDED   -> EXEC_SUCCEEDED
    KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false kubectl exec --as=... -- echo    -> forbidden

So the capability really is `{create, get}`, the finding was a true positive, and
`auth can-i create pods/exec` returning "no" is not evidence that a principal cannot exec.
These tests keep both verbs, and keep the reason next to them, so the next person who
notices the "no" does not remove `get` again.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core.rbac_graph import ESCALATION_PRIMITIVES, _rule_grants

#: Verbatim from the live EKS cluster.
GC_RULE = {"apiGroups": ["*"], "resources": ["*"],
           "verbs": ["delete", "get", "list", "patch", "update", "watch"]}
NS_CONTROLLER_RULE = {"apiGroups": ["*"], "resources": ["*"],
                      "verbs": ["delete", "deletecollection", "get", "list", "watch"]}
CLUSTER_ADMIN_RULE = {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}


def _capability(name):
    for entry in ESCALATION_PRIMITIVES:
        if entry[0] == name:
            return entry
    raise AssertionError(f"no capability named {name!r}")


def _grants(rule, capability):
    _name, verbs, resources, groups, _desc = _capability(capability)
    return _rule_grants(rule, verbs, resources, groups)


# --------------------------------------------------------------------------- #
# Both exec transports
# --------------------------------------------------------------------------- #

def test_get_on_the_exec_subresource_grants_exec():
    """REGRESSION. WebSocket exec is a GET, and it is kubectl's default. Proven live:
    impersonating a get-only principal and running `kubectl exec` succeeded."""
    assert _grants({"apiGroups": [""], "resources": ["pods/exec"],
                    "verbs": ["get"]}, "exec-pods") is True, (
        "dropping `get` here is a false negative on WebSocket exec, which is how kubectl "
        "1.30+ execs by default")


def test_create_on_the_exec_subresource_grants_exec():
    """SPDY exec is a POST."""
    assert _grants({"apiGroups": [""], "resources": ["pods/exec"],
                    "verbs": ["create"]}, "exec-pods") is True


def test_a_read_only_wildcard_role_can_still_exec():
    """The live case. `auth can-i create pods/exec` said no; the exec succeeded anyway."""
    assert _grants(GC_RULE, "exec-pods") is True
    assert _grants(NS_CONTROLLER_RULE, "exec-pods") is True


def test_cluster_admin_grants_exec():
    assert _grants(CLUSTER_ADMIN_RULE, "exec-pods") is True


def test_a_role_with_neither_verb_does_not_grant_exec():
    """The capability still has to mean something."""
    assert _grants({"apiGroups": [""], "resources": ["pods/exec"],
                    "verbs": ["delete", "watch"]}, "exec-pods") is False
    assert _grants({"apiGroups": [""], "resources": ["pods"],
                    "verbs": ["get", "create"]}, "exec-pods") is False, (
        "`pods` is not `pods/exec`; only the subresource grants execution")


# --------------------------------------------------------------------------- #
# The other capabilities the same wildcard role does and does not have
# --------------------------------------------------------------------------- #

def test_the_read_only_wildcard_reads_secrets():
    assert _grants(GC_RULE, "read-secrets") is True


def test_the_read_only_wildcard_cannot_create_a_workload():
    """`create deployments` and `create pods` both answered no on the live cluster."""
    assert _grants(GC_RULE, "create-workload") is False


def test_reading_secrets_needs_only_one_of_get_or_list():
    for verb in ("get", "list"):
        assert _grants({"apiGroups": [""], "resources": ["secrets"],
                        "verbs": [verb]}, "read-secrets") is True, verb


def test_writing_bindings_needs_only_one_of_create_update_patch():
    for verb in ("create", "update", "patch"):
        assert _grants({"apiGroups": ["rbac.authorization.k8s.io"],
                        "resources": ["clusterrolebindings"],
                        "verbs": [verb]}, "modify-bindings") is True, verb


def test_every_multi_verb_capability_is_a_genuine_disjunction():
    """`_rule_grants` matches on ANY declared verb, so a capability listing several must
    mean that any one of them confers it. Each entry below is a claim that it does."""
    interchangeable = {
        # Either transport execs: create is SPDY/POST, get is WebSocket/GET.
        "exec-pods": {"create", "get"},
        "read-secrets": {"get", "list"},                     # either reads the object
        "modify-bindings": {"create", "update", "patch"},    # any one writes it
        # escalate writes a role you do not hold; bind binds one. Either grants a role
        # you were not entitled to.
        "bind-roles": {"bind", "escalate"},
    }
    for name, verbs, _resources, _groups, _desc in ESCALATION_PRIMITIVES:
        if len(verbs) == 1:
            continue
        assert name in interchangeable, (
            f"capability {name!r} declares several verbs {sorted(verbs)}; the matcher "
            f"accepts ANY of them, so each must independently confer it")
        assert verbs == interchangeable[name], (name, sorted(verbs))


if __name__ == "__main__":
    import traceback
    failed = 0
    for key, fn in sorted(globals().items()):
        if key.startswith("test_") and callable(fn):
            try:
                fn()
            except Exception:
                failed += 1
                print(f"FAIL {key}")
                traceback.print_exc()
    print("ok" if not failed else f"{failed} failed")
