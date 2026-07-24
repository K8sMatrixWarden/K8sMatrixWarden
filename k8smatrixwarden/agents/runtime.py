"""
Runtime Agent (§8).

Uses the SAME rule/registry pattern as the Scanner (§8 intro): Falco/Tetragon syscall
rules, K8s audit-event rules, and drift rules are all tagged with MITRE tactics. In a live
deployment this runs as a DaemonSet tailing Falco/Tetragon and the audit stream; here it
provides the rule catalog and an event-matching engine that can be driven by a simulated
or real event feed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.models import (BlastRadius as BR, Exploitability as EX, MitreTag as M,
                           ResourceRef, Severity as S, Tactic as T)


@dataclass
class RuntimeRule:
    id: str
    title: str
    severity: S
    tactic: M
    matcher: Callable[[dict], bool]
    source: str = "falco"          # falco | audit | drift
    #: Every rule in this agent observes a LIVE stream, so its detection surface is always
    #: "runtime" (as opposed to the Scanner Agent's point-in-time "scan" surface, §8). This
    #: is the explicit runtime-vs-scan tag the two detection systems are separated by.
    surface: str = "runtime"

    def metadata(self) -> dict:
        return {"id": self.id, "title": self.title, "severity": self.severity.label,
                "surface": self.surface, "source": self.source,
                "tactic": self.tactic.tactic.value,
                "technique_id": self.tactic.technique_id,
                "technique_name": self.tactic.technique_name}


@dataclass
class RuntimeAlert:
    rule_id: str
    title: str
    severity: S
    tactic: str
    event: dict
    source: str = "falco"
    surface: str = "runtime"


def _proc(name):        # process-name matcher for Falco-style events
    return lambda e: e.get("source") == "falco" and name in (e.get("proc") or "")


def _audit(verb=None, resource=None, ns=None):
    def _m(e):
        if e.get("source") != "audit":
            return False
        if verb and e.get("verb") != verb:
            return False
        if resource and e.get("resource") != resource:
            return False
        if ns and e.get("namespace") != ns:
            return False
        return True
    return _m


def normalize_falco_event(raw: dict) -> dict:
    """Map ONE Falco/falcosidekick native event to the flat internal shape the rule
    matchers expect. Falco nests everything under `output_fields` with dotted keys
    (proc.name, k8s.pod.name, ka.verb, …) and tags its stream in `source`
    ('syscall' | 'k8s_audit'). We flatten to {source: falco|audit, proc, connect, file,
    op, uid, pod, namespace, verb, resource}."""
    of = raw.get("output_fields") or {}
    if raw.get("source") == "k8s_audit" or "ka.verb" in of:
        ev = {"source": "audit", "verb": of.get("ka.verb"),
              "resource": of.get("ka.target.resource"),
              "namespace": of.get("ka.target.namespace"),
              "pod": of.get("ka.target.name")}
        return {k: v for k, v in ev.items() if v not in (None, "")}
    fd = of.get("fd.name") or ""
    # network fd if Falco gave a sip/rip, or the fd looks like host:port (not a path)
    is_net = bool(of.get("fd.sip") or of.get("fd.rip")) or (":" in fd and "/" not in fd)
    ev = {"source": "falco", "proc": of.get("proc.name"),
          "op": of.get("evt.type"), "namespace": of.get("k8s.ns.name"),
          "pod": of.get("k8s.pod.name"), "uid": of.get("user.uid")}
    if is_net:
        ev["connect"] = fd or f"{of.get('fd.sip', '')}:{of.get('fd.sport', '')}"
    elif fd:
        ev["file"] = fd
    return {k: v for k, v in ev.items() if v not in (None, "")}


def normalize_events(raw) -> list[dict]:
    """Accept a single event or a batch, in either Falco-native or already-flat shape,
    and return a list of flat internal events. Lets `/api/runtime` take falcosidekick's
    one-event-per-POST as well as a hand-built batch."""
    if isinstance(raw, dict):
        raw = [raw]
    out = []
    for e in raw or []:
        if not isinstance(e, dict):
            continue
        if "output_fields" in e or e.get("source") in ("syscall", "k8s_audit"):
            out.append(normalize_falco_event(e))
        else:
            out.append(e)  # already flat internal shape
    return out


class RuntimeAgent:
    def __init__(self):
        self.rules = self._build_rules()

    def _build_rules(self) -> list[RuntimeRule]:
        return [
            RuntimeRule("rt-shell-in-container", "Shell spawned in container", S.HIGH,
                        M(T.EXECUTION, "T1059", "Command and Scripting Interpreter"),
                        lambda e: e.get("source") == "falco" and
                        (e.get("proc") or "") in ("bash", "sh", "zsh")),
            RuntimeRule("rt-metadata-api", "Metadata API access from container", S.CRITICAL,
                        M(T.CREDENTIAL_ACCESS, "T1552.005", "Cloud Instance Metadata API"),
                        lambda e: "169.254.169.254" in str(e.get("connect", ""))),
            RuntimeRule("rt-network-recon", "Network recon tool executed", S.HIGH,
                        M(T.DISCOVERY, "T1046", "Network Service Discovery"),
                        lambda e: (e.get("proc") or "") in ("nmap", "masscan", "nc",
                                                            "netcat")),
            RuntimeRule("rt-crypto-miner", "Crypto-miner signature", S.HIGH,
                        M(T.IMPACT, "T1496", "Resource Hijacking"),
                        lambda e: (e.get("proc") or "") in ("xmrig", "minerd", "cpuminer")),
            RuntimeRule("rt-container-escape", "Container escape indicator", S.CRITICAL,
                        M(T.PRIVILEGE_ESCALATION, "T1611", "Escape to Host"),
                        lambda e: any(x in str(e.get("file", "")) for x in
                                      ("release_agent", "/proc/1/root")) or
                        (e.get("proc") or "") in ("nsenter", "chroot")),
            RuntimeRule("rt-log-clear", "Container log cleared/truncated", S.HIGH,
                        M(T.DEFENSE_EVASION, "T1070", "Indicator Removal"),
                        lambda e: e.get("op") == "truncate" and
                        "/var/log" in str(e.get("file", "")), source="falco"),
            RuntimeRule("rt-new-rolebinding", "New (Cluster)RoleBinding created", S.CRITICAL,
                        M(T.PRIVILEGE_ESCALATION, "T1078", "Valid Accounts"),
                        _audit(verb="create", resource="clusterrolebindings"),
                        source="audit"),
            RuntimeRule("rt-exec-kube-system", "kubectl exec into kube-system", S.CRITICAL,
                        M(T.EXECUTION, "T1609", "Container Administration Command"),
                        _audit(verb="create", resource="pods/exec", ns="kube-system"),
                        source="audit"),
            RuntimeRule("rt-secret-enum", "Secret enumeration via API", S.HIGH,
                        M(T.CREDENTIAL_ACCESS, "T1552.007", "Container API Credentials"),
                        _audit(verb="list", resource="secrets"), source="audit"),
            RuntimeRule("rt-delete-events", "K8s events deleted", S.HIGH,
                        # named as the Redguard matrix names it, so the threat matrix
                        # lights the "Delete K8s events" cell rather than collapsing onto
                        # "Clear container logs" (both carry ATT&CK T1070)
                        M(T.DEFENSE_EVASION, "T1070", "Delete K8s events"),
                        _audit(verb="delete", resource="events"), source="audit"),
            RuntimeRule("rt-mass-delete", "Mass deletion spike", S.CRITICAL,
                        M(T.IMPACT, "T1485", "Data Destruction"),
                        lambda e: e.get("source") == "audit" and
                        e.get("verb") == "delete" and e.get("count", 0) >= 10,
                        source="audit"),
        ]

    def catalog(self) -> list[dict]:
        """The runtime detection catalog, every rule tagged surface='runtime', with its
        source (falco | audit | drift) and MITRE mapping. The counterpart to the Scanner
        registry's scan-surface rules; lets a caller enumerate 'what is detected at
        runtime vs. at scan time' (§8)."""
        return [r.metadata() for r in self.rules]

    def evaluate(self, event: dict) -> list[RuntimeAlert]:
        alerts = []
        for r in self.rules:
            try:
                if r.matcher(event):
                    alerts.append(RuntimeAlert(r.id, r.title, r.severity,
                                               r.tactic.tactic.value, event,
                                               source=r.source, surface=r.surface))
            except Exception:
                continue
        return alerts

    def evaluate_stream(self, events: list[dict]) -> list[RuntimeAlert]:
        out = []
        for e in events:
            out.extend(self.evaluate(e))
        return out
