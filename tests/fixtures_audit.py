"""
Native Kubernetes audit Events, in the shape the API server actually writes them.

Each fixture is a complete `audit.k8s.io/v1` record for one of the five curated audit
detections, with the fields an operator would need to act on it: who made the request, from
where, with what client, and whether it succeeded.

Shapes follow the Kubernetes audit schema: `objectRef` names the target, `user` the
requester, `sourceIPs` the origin, `responseStatus.code` the outcome, and `stageTimestamp`
the moment the request completed. Only `ResponseComplete` records describe an outcome.
"""

_BASE_USER = {"username": "kubernetes-admin",
              "groups": ["kubeadm:cluster-admins", "system:authenticated"]}
_AGENT = "kubectl/v1.36.1 (windows/amd64) kubernetes/f2c1e0a"


def audit_event(*, verb, resource, name=None, namespace=None, subresource=None,
                api_group=None, code=200, user=None, groups=None,
                source_ip="192.168.65.3", user_agent=_AGENT,
                request_uri=None, stage="ResponseComplete",
                timestamp="2026-09-02T06:10:00.250000Z",
                audit_id="00000000-0000-4000-8000-000000000000"):
    """One native Kubernetes audit Event."""
    obj = {"resource": resource}
    if name:
        obj["name"] = name
    if namespace:
        obj["namespace"] = namespace
    if subresource:
        obj["subresource"] = subresource
    if api_group:
        obj["apiGroup"] = api_group
    who = dict(_BASE_USER)
    if user:
        who["username"] = user
    if groups is not None:
        who["groups"] = list(groups)
    return {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse", "auditID": audit_id, "stage": stage,
        "requestURI": request_uri or f"/api/v1/{resource}",
        "verb": verb, "user": who, "sourceIPs": [source_ip], "userAgent": user_agent,
        "objectRef": obj, "responseStatus": {"metadata": {}, "code": code},
        "requestReceivedTimestamp": "2026-09-02T06:10:00.100000Z",
        "stageTimestamp": timestamp,
    }


#: The five curated audit detections, each with the audit record that should trigger it.
AUDIT_CASES = {
    "rt-new-rolebinding": audit_event(
        verb="create", resource="clusterrolebindings", name="attacker-binding",
        api_group="rbac.authorization.k8s.io", code=201,
        request_uri="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        audit_id="11111111-1111-4111-8111-111111111111"),

    "rt-exec-kube-system": audit_event(
        verb="create", resource="pods", subresource="exec", name="etcd-control-plane",
        namespace="kube-system", code=101,
        request_uri="/api/v1/namespaces/kube-system/pods/etcd-control-plane/exec"
                    "?command=sh&stdin=true&tty=true",
        audit_id="22222222-2222-4222-8222-222222222222"),

    "rt-secret-enum": audit_event(
        verb="list", resource="secrets", namespace="default", code=200,
        request_uri="/api/v1/namespaces/default/secrets?limit=500",
        audit_id="33333333-3333-4333-8333-333333333333"),

    "rt-delete-events": audit_event(
        verb="delete", resource="events", name="pod-crash-123", namespace="default",
        code=200, request_uri="/api/v1/namespaces/default/events/pod-crash-123",
        audit_id="44444444-4444-4444-8444-444444444444"),
}


def mass_delete_events(count=25):
    """The mass-delete case, as the API server actually records it: one record per object.

    A single audit Event cannot express "twenty-five deletions" — the API server writes one
    record per deleted object, and the spike only exists across them. The runtime agent
    recovers the rate by grouping the batch, so this returns the burst rather than a
    synthetic event carrying a pre-computed tally.
    """
    return [audit_event(verb="delete", resource="pods", namespace="production",
                        name=f"api-{i:04d}", code=200,
                        request_uri=f"/api/v1/namespaces/production/pods/api-{i:04d}",
                        timestamp=f"2026-09-02T06:11:{i % 60:02d}.000000Z",
                        audit_id=f"55555555-5555-4555-8555-{i:012d}")
            for i in range(count)]
