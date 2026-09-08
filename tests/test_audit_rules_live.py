"""
Kubernetes Audit detection, from records a real API server wrote.

Every event below was fetched from CloudWatch on a live EKS cluster
(`/aws/eks/k8s-goat-cluster/cluster`, stream `kube-apiserver-audit-*`) after generating the
matching action by hand, then trimmed of anything identifying. They are the shapes the API
server actually emits, which is the point: two of the five curated audit rules missed the
behaviour they are named after, and both misses were invisible against hand-written events.

  rt-exec-kube-system matched `verb: create` on `pods/exec`. Exec has two transports --
  SPDY is a POST and audits as `create`, WebSocket is a GET and audits as `get` -- and
  WebSocket is kubectl's default from 1.30. The live cluster produced 32 exec records, all
  of them `verb: get`, and the rule detected none.

  rt-new-rolebinding is titled "New (Cluster)RoleBinding created" and matched only
  `clusterrolebindings`. A namespaced RoleBinding pointing at a powerful ClusterRole is the
  same escalation with a smaller blast radius; creating one produced a record the rule
  ignored.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents.runtime import (RuntimeAgent, is_kubernetes_audit_event,
                                            normalize_audit_event, normalize_events)

#: Real EKS record: `kubectl exec` into kube-system over the default WebSocket transport.
EXEC_WEBSOCKET = {
    "kind": "Event", "apiVersion": "audit.k8s.io/v1",
    "level": "RequestResponse", "auditID": "93bd6ecf-55d8-430b-b32d-772c84cbb470",
    "stage": "ResponseComplete", "verb": "get",
    "requestURI": "/api/v1/namespaces/kube-system/pods/aws-node-62mjt/exec"
                  "?command=sh&command=-c&container=aws-node&stdout=true",
    "user": {"username": "kubernetes-admin", "groups": ["system:authenticated"]},
    "sourceIPs": ["203.0.113.7"], "userAgent": "kubectl/v1.36.1",
    "objectRef": {"resource": "pods", "subresource": "exec",
                  "namespace": "kube-system", "name": "aws-node-62mjt",
                  "apiVersion": "v1"},
    "responseStatus": {"metadata": {}, "code": 101},
    "requestReceivedTimestamp": "2026-09-08T18:55:35.428000Z",
    "stageTimestamp": "2026-09-08T18:55:35.433270Z"}

#: The same action over SPDY, which is what the rule used to require.
EXEC_SPDY = dict(EXEC_WEBSOCKET, verb="create",
                 auditID="11111111-2222-3333-4444-555555555555")

#: Real EKS record: a namespaced RoleBinding created.
ROLEBINDING = {
    "kind": "Event", "apiVersion": "audit.k8s.io/v1",
    "level": "RequestResponse", "auditID": "0753ac81-9d5e-4e1a-8d39-836293255f5a",
    "stage": "ResponseComplete", "verb": "create",
    "requestURI": "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings",
    "user": {"username": "kubernetes-admin"},
    "objectRef": {"resource": "rolebindings", "namespace": "kube-system",
                  "name": "kmw-probe-binding",
                  "apiGroup": "rbac.authorization.k8s.io", "apiVersion": "v1"},
    "responseStatus": {"metadata": {}, "code": 201},
    "stageTimestamp": "2026-09-08T17:47:38.449238Z"}

CLUSTERROLEBINDING = dict(
    ROLEBINDING, auditID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    objectRef={"resource": "clusterrolebindings", "name": "superadmin",
               "apiGroup": "rbac.authorization.k8s.io", "apiVersion": "v1"})

#: Real EKS record: cluster-wide secret enumeration.
SECRET_LIST = {
    "kind": "Event", "apiVersion": "audit.k8s.io/v1",
    "level": "Metadata", "auditID": "c973f271-c708-4982-95c2-5861447905c6",
    "stage": "ResponseComplete", "verb": "list",
    "requestURI": "/api/v1/secrets?limit=500",
    "user": {"username": "kubernetes-admin"},
    "objectRef": {"resource": "secrets", "apiVersion": "v1"},
    "responseStatus": {"metadata": {}, "code": 200},
    "stageTimestamp": "2026-09-08T17:47:35.849210Z"}


def _detect(*records):
    alerts, coverage = RuntimeAgent().evaluate_batch(normalize_events(list(records)))
    return {a.rule_id for a in alerts}, alerts, coverage


# --------------------------------------------------------------------------- #
# The records are recognised and read faithfully
# --------------------------------------------------------------------------- #

def test_a_real_audit_record_is_recognised_as_one():
    for record in (EXEC_WEBSOCKET, ROLEBINDING, SECRET_LIST):
        assert is_kubernetes_audit_event(record), record["auditID"]


def test_the_fields_an_analyst_needs_survive_normalization():
    """Who did this, to what, from where, and did it succeed."""
    found = normalize_audit_event(EXEC_WEBSOCKET)
    assert found["source"] == "audit"
    assert found["provider"] == "kubernetes-audit"
    assert found["verb"] == "get"
    assert found["resource"] == "pods/exec", "subresource must join its parent"
    assert found["namespace"] == "kube-system"
    assert found["resource_name"] == "aws-node-62mjt"
    assert found["pod"] == "aws-node-62mjt"
    assert found["username"] == "kubernetes-admin"
    assert found["source_ip"] == "203.0.113.7"
    assert found["audit_id"] == "93bd6ecf-55d8-430b-b32d-772c84cbb470"
    assert found["response_status"] == 101
    assert found["time"] == "2026-09-08T18:55:35.433270Z", "provider time, as given"


def test_absent_fields_are_omitted_rather_than_defaulted():
    """A record with no namespace is a cluster-scoped action, not one in namespace ''."""
    found = normalize_audit_event(SECRET_LIST)
    assert "namespace" not in found
    assert "pod" not in found


# --------------------------------------------------------------------------- #
# rt-exec-kube-system: both transports
# --------------------------------------------------------------------------- #

def test_websocket_exec_into_kube_system_is_detected():
    """REGRESSION. 32 real records, all `verb: get`, previously all missed."""
    rules, alerts, _ = _detect(EXEC_WEBSOCKET)
    assert "rt-exec-kube-system" in rules, rules
    alert = next(a for a in alerts if a.rule_id == "rt-exec-kube-system")
    assert alert.severity.label == "CRITICAL"
    assert alert.detection_source == "kmw"
    assert alert.event["audit_id"] == EXEC_WEBSOCKET["auditID"]


def test_spdy_exec_into_kube_system_is_still_detected():
    """The transport the rule already handled must keep working."""
    rules, _alerts, _ = _detect(EXEC_SPDY)
    assert "rt-exec-kube-system" in rules, rules


def test_exec_outside_kube_system_is_not_this_rule():
    """The rule is about kube-system specifically; widening it would be a different claim."""
    elsewhere = dict(EXEC_WEBSOCKET, objectRef=dict(EXEC_WEBSOCKET["objectRef"],
                                                    namespace="default"))
    rules, _alerts, _ = _detect(elsewhere)
    assert "rt-exec-kube-system" not in rules, rules


# --------------------------------------------------------------------------- #
# rt-new-rolebinding: both scopes
# --------------------------------------------------------------------------- #

def test_a_namespaced_rolebinding_is_detected():
    """REGRESSION. The rule is titled "(Cluster)RoleBinding" and covered only half."""
    rules, alerts, _ = _detect(ROLEBINDING)
    assert "rt-new-rolebinding" in rules, rules
    alert = next(a for a in alerts if a.rule_id == "rt-new-rolebinding")
    assert alert.severity.label == "CRITICAL"
    assert alert.event["namespace"] == "kube-system"


def test_a_clusterrolebinding_is_still_detected():
    rules, _alerts, _ = _detect(CLUSTERROLEBINDING)
    assert "rt-new-rolebinding" in rules, rules


def test_reading_a_rolebinding_is_not_creating_one():
    """`create` is the verb that matters; a `get` is not an escalation."""
    read = dict(ROLEBINDING, verb="get")
    rules, _alerts, _ = _detect(read)
    assert "rt-new-rolebinding" not in rules, rules


# --------------------------------------------------------------------------- #
# The rules that were already right
# --------------------------------------------------------------------------- #

def test_secret_enumeration_is_detected():
    rules, alerts, _ = _detect(SECRET_LIST)
    assert "rt-secret-enum" in rules, rules
    alert = next(a for a in alerts if a.rule_id == "rt-secret-enum")
    assert alert.severity.label == "HIGH"
    assert alert.tactic == "Credential Access"


def test_every_real_record_is_accounted_for():
    """The accounting invariant, against real records rather than invented ones."""
    _rules, _alerts, coverage = _detect(EXEC_WEBSOCKET, ROLEBINDING, SECRET_LIST)
    assert coverage["discarded"] == 0, coverage
    assert coverage["events_received"] == 3
    assert (coverage["kmw_matches"] + coverage["falco_relays"]
            + coverage["unusable_events"]) == 3, coverage


def test_no_tactic_or_severity_is_invented_for_an_unmatched_record():
    """An audit action nobody wrote a rule for must be reported as unusable with a reason,
    not quietly given a verdict."""
    boring = dict(SECRET_LIST, verb="get",
                  objectRef={"resource": "configmaps", "namespace": "default",
                             "name": "kube-root-ca.crt", "apiVersion": "v1"})
    rules, _alerts, coverage = _detect(boring)
    assert rules == set(), rules
    assert coverage["discarded"] == 0
    for entry in coverage.get("unusable") or []:
        assert entry.get("reason"), entry


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
