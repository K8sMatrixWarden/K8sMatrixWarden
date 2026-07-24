"""Shard ④, Network Security (§5.6)."""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, Exploitability as EX,
                           MitreTag as M, ResourceRef, Rule, Severity as S, Tactic as T)
from .base import DomainShard, ref

NAME = "network_security"


def _nodeport(rule, ev, scope):
    for svc in ev.get("Service"):
        if Evidence.dig(svc, "spec.type") == "NodePort":
            ports = [p.get("nodePort") for p in Evidence.dig(svc, "spec.ports", []) or []]
            yield rule.finding(ref(svc), f"NodePort service exposes ports {ports}",
                               exploitability=EX.REMOTE,
                               evidence={"nodePorts": ports})


def _lb_no_source(rule, ev, scope):
    for svc in ev.get("Service"):
        if Evidence.dig(svc, "spec.type") == "LoadBalancer" and \
                not Evidence.dig(svc, "spec.loadBalancerSourceRanges"):
            yield rule.finding(ref(svc), "LoadBalancer has no loadBalancerSourceRanges "
                               "(open to the internet)",
                               exploitability=EX.REMOTE, blast_radius=BR.NAMESPACE,
                               evidence={"type": "LoadBalancer"})


def _dashboard(rule, ev, scope):
    for svc in ev.get("Service"):
        name = Evidence.dig(svc, "metadata.name", "")
        if "kubernetes-dashboard" in name:
            if Evidence.dig(svc, "spec.type") in ("NodePort", "LoadBalancer"):
                yield rule.finding(ref(svc), "Kubernetes dashboard is externally exposed",
                                   severity=S.CRITICAL, exploitability=EX.REMOTE,
                                   blast_radius=BR.CLUSTER)


def _ingress_no_tls(rule, ev, scope):
    for ing in ev.get("Ingress"):
        if not Evidence.dig(ing, "spec.tls"):
            yield rule.finding(ref(ing), "Ingress serves traffic without TLS",
                               exploitability=EX.REMOTE)


def _no_networkpolicy(rule, ev, scope):
    policies = ev.get("NetworkPolicy", all_scopes=True)
    ns_with_policy = {Evidence.dig(p, "metadata.namespace") for p in policies}
    for ns in ev.get("Namespace", all_scopes=True):
        name = Evidence.dig(ns, "metadata.name")
        if name in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        if scope.namespace and name != scope.namespace:
            continue
        if name not in ns_with_policy:
            yield rule.finding(ResourceRef("Namespace", name),
                               f"namespace '{name}' has no NetworkPolicy (flat network)",
                               blast_radius=BR.NAMESPACE,
                               evidence={"namespace": name})


def _metadata_open(rule, ev, scope):
    """Flag namespaces whose egress isn't restricted from the metadata API."""
    policies = ev.get("NetworkPolicy", all_scopes=True)
    blocked_ns = set()
    for p in policies:
        types = Evidence.dig(p, "spec.policyTypes", []) or []
        if "Egress" in types:
            blocked_ns.add(Evidence.dig(p, "metadata.namespace"))
    for ns in ev.get("Namespace", all_scopes=True):
        name = Evidence.dig(ns, "metadata.name")
        if name in ("kube-system", "kube-public", "kube-node-lease"):
            continue
        if scope.namespace and name != scope.namespace:
            continue
        if name not in blocked_ns:
            yield rule.finding(ResourceRef("Namespace", name),
                               f"namespace '{name}' has no egress policy blocking the "
                               f"cloud metadata API (169.254.169.254)",
                               blast_radius=BR.NAMESPACE, exploitability=EX.ADJACENT,
                               evidence={"namespace": name})


class NetworkSecurityShard(DomainShard):
    name = NAME
    title = "Network Security"
    index = "④"

    def rules(self):
        return [
            Rule("net-nodeport-service", "NodePort service exposed", self.name,
                 ["Service"], S.MEDIUM, DM.NETWORK, _nodeport,
                 mitre=[M(T.INITIAL_ACCESS, "T1133", "External Remote Services")],
                 owasp="K06", evidence_needs=["Service"]),
            Rule("net-lb-no-source-range", "LoadBalancer without source range", self.name,
                 ["Service"], S.HIGH, DM.NETWORK, _lb_no_source,
                 mitre=[M(T.INITIAL_ACCESS, "T1133", "External Remote Services")],
                 owasp="K06", evidence_needs=["Service"]),
            Rule("net-dashboard-exposed", "Kubernetes dashboard exposed", self.name,
                 ["Service"], S.CRITICAL, DM.NETWORK, _dashboard,
                 mitre=[M(T.DISCOVERY, "T1613", "Access Kubernetes dashboard")],
                 owasp="K06", evidence_needs=["Service"]),
            Rule("net-ingress-no-tls", "Ingress without TLS", self.name, ["Ingress"],
                 S.HIGH, DM.NETWORK, _ingress_no_tls,
                 mitre=[M(T.INITIAL_ACCESS, "T1133", "External Remote Services")],
                 owasp="K06", evidence_needs=["Ingress"]),
            Rule("net-no-networkpolicy", "Namespace without NetworkPolicy", self.name,
                 ["NetworkPolicy", "Namespace"], S.HIGH, DM.NETWORK, _no_networkpolicy,
                 mitre=[M(T.LATERAL_MOVEMENT, "T1610", "Cluster internal networking")],
                 owasp="K05", cis=["5.3.2"], nsa_cisa=["Network Policy"],
                 evidence_needs=["NetworkPolicy", "Namespace"]),
            Rule("net-metadata-api-open", "Metadata API not blocked", self.name,
                 ["NetworkPolicy", "Namespace"], S.HIGH, DM.NETWORK, _metadata_open,
                 mitre=[M(T.CREDENTIAL_ACCESS, "T1552.005",
                          "Cloud Instance Metadata API"),
                        M(T.LATERAL_MOVEMENT, "T1552.005",
                          "Cloud Instance Metadata API"),
                        # reachable metadata is also how an attacker enumerates the
                        # cloud environment from inside a pod -- the Redguard matrix
                        # lists it under Discovery too
                        M(T.DISCOVERY, "T1552.005", "Instance Metadata API")],
                 owasp="K08", evidence_needs=["NetworkPolicy", "Namespace"]),
        ]


SHARD = NetworkSecurityShard
