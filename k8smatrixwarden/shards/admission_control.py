"""Shard ⑨, Admission Control (NEW, §5.11).

Closes the Persistence / Credential Access 'malicious admission controller' and Execution
'sidecar injection' gaps, plus CronJob persistence.
"""
from __future__ import annotations

from ..core.evidence import Evidence
from ..core.models import (BlastRadius as BR, DetectionMethod as DM, MitreTag as M,
                           Rule, Severity as S, Tactic as T)
from .base import DomainShard, ref

NAME = "admission_control"
_SUSPICIOUS_CRON_IMG = ("curl", "wget", "nc", "netcat", "miner", "xmrig", "busybox")
_SUSPICIOUS_SCHEDULES = ("* * * * *", "*/1 * * * *", "*/2 * * * *")


def _malicious_webhook(rule, ev, scope):
    for wh in ev.get("MutatingWebhookConfiguration", all_scopes=True):
        for w in wh.get("webhooks", []) or []:
            url = Evidence.dig(w, "clientConfig.url")
            selector = w.get("namespaceSelector")
            external = bool(url) and not url.startswith("https://kubernetes.default")
            broad = selector in (None, {}, {"matchLabels": {}})
            if external and broad:
                yield rule.finding(
                    ref(wh), f"mutating webhook '{w.get('name')}' targets an external URL "
                    f"({url}) with cluster-wide scope",
                    blast_radius=BR.CLUSTER, evidence={"url": url})


def _webhook_failurepolicy(rule, ev, scope):
    for kind in ("MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"):
        for wh in ev.get(kind, all_scopes=True):
            for w in wh.get("webhooks", []) or []:
                if w.get("failurePolicy") == "Ignore":
                    yield rule.finding(
                        ref(wh), f"webhook '{w.get('name')}' has failurePolicy=Ignore "
                        f"(security control can be bypassed by breaking it)",
                        evidence={"webhook": w.get("name")})


def _sidecar_injection(rule, ev, scope):
    for wh in ev.get("MutatingWebhookConfiguration", all_scopes=True):
        for w in wh.get("webhooks", []) or []:
            name = (w.get("name", "") + str(wh.get("metadata", {}).get("name", ""))).lower()
            if "inject" in name or "sidecar" in name:
                if not _is_known_mesh(name):
                    yield rule.finding(
                        ref(wh), f"mutating webhook '{w.get('name')}' injects sidecars "
                        f"(verify it is a trusted mesh/agent)",
                        evidence={"webhook": w.get("name")})


def _cronjob_suspicious(rule, ev, scope):
    for cj in ev.get("CronJob"):
        schedule = Evidence.dig(cj, "spec.schedule", "")
        spec = ev.pod_spec(Evidence.dig(cj, "spec.jobTemplate", {}))
        images = [c.get("image", "") for c in spec.get("containers", []) or []]
        cmds = " ".join(" ".join(c.get("command", []) or []) + " " +
                        " ".join(c.get("args", []) or [])
                        for c in spec.get("containers", []) or [])
        bad_img = any(tok in (img + cmds).lower()
                      for img in images for tok in _SUSPICIOUS_CRON_IMG)
        if bad_img or schedule in _SUSPICIOUS_SCHEDULES:
            yield rule.finding(
                ref(cj), f"CronJob '{Evidence.dig(cj,'metadata.name')}' looks suspicious "
                f"(schedule={schedule!r}, images={images})",
                blast_radius=BR.NAMESPACE, evidence={"schedule": schedule,
                                                     "images": images})


def _is_known_mesh(name: str) -> bool:
    return any(m in name for m in ("istio", "linkerd", "vault-agent", "istiod"))


class AdmissionControlShard(DomainShard):
    name = NAME
    title = "Admission Control"
    index = "⑨"

    def rules(self):
        wneed = ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"]
        return [
            Rule("admission-malicious-webhook", "Suspicious mutating webhook", self.name,
                 ["MutatingWebhookConfiguration"], S.CRITICAL, DM.STATIC_CONFIG,
                 _malicious_webhook,
                 mitre=[M(T.PERSISTENCE, "T1554", "Compromise Host Software Binary"),
                        M(T.CREDENTIAL_ACCESS, "T1554", "Malicious admission controller")],
                 owasp="K04", evidence_needs=["MutatingWebhookConfiguration"]),
            Rule("admission-webhook-failurepolicy", "Webhook failurePolicy=Ignore",
                 self.name, wneed, S.HIGH, DM.STATIC_CONFIG, _webhook_failurepolicy,
                 mitre=[M(T.DEFENSE_EVASION, "T1562", "Impair Defenses")],
                 owasp="K04", evidence_needs=wneed),
            Rule("admission-sidecar-injection", "Unrecognized sidecar injection", self.name,
                 ["MutatingWebhookConfiguration"], S.HIGH, DM.STATIC_CONFIG,
                 _sidecar_injection,
                 mitre=[M(T.EXECUTION, "T1610", "Sidecar injection")],
                 owasp="K04", evidence_needs=["MutatingWebhookConfiguration"]),
            Rule("cronjob-suspicious", "Suspicious CronJob", self.name, ["CronJob"],
                 S.HIGH, DM.STATIC_CONFIG, _cronjob_suspicious,
                 mitre=[M(T.PERSISTENCE, "T1053.003", "Scheduled Task/Job: Cron")],
                 owasp="K01", evidence_needs=["CronJob"]),
        ]


SHARD = AdmissionControlShard
