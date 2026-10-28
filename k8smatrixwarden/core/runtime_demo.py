"""Sample runtime events, so the Runtime tab is demonstrable without a live Falco feed.

Deploying Falco and generating real syscall activity is infrastructure work outside this
tool's reach (and on some hosts, such as nested-VM laptops, its eBPF probe cannot attach to
the kernel at all). What the tool CAN do is show, truthfully, how correlation behaves once
events do arrive: three synthetic, clearly-labelled Falco-shaped events built from THIS
scan's own real findings, pushed through the exact same `/api/runtime` ingestion path a real
sensor uses. Nothing here invents a resource that is not already in the scan.

The three events are built to land in the three confidence tiers `correlate()` defines:

  confirmed      , names the exact resource of a real finding
  corroborated   , same namespace, a resource the scan never saw
  runtime-only   , a rule Falco raised with no MITRE tag, so it cannot be placed on any
                   finding at all (the documented `_falco_native_alert` "Unknown tactic" path)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

_DEMO_CONTAINER_ID = "d3m0eca11ab1e0"


def _base(rule: str, **fields) -> dict:
    return {"source": "falco", "priority": "Warning",
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "container_id": _DEMO_CONTAINER_ID, "rule": rule, **fields}


def sample_events(result) -> list[dict]:
    """Up to three demo events built from `result.findings`. Empty when the scan has no
    finding with a tactic to build from (nothing truthful to demonstrate)."""
    findings = [f for f in (result.findings or []) if f.tactics]
    if not findings:
        return []
    anchor = max(findings, key=lambda f: f.severity.order)
    tactic = anchor.tactics[0]
    technique = next((m.technique_id for m in anchor.mitre if m.tactic == tactic), "")
    tag = _TAG_FOR_TACTIC.get(tactic.value, "mitre_execution")
    ns = anchor.resource.namespace or ""
    tags = [t for t in (technique.lower() if technique else "", tag) if t]

    # Deliberately NOT "Terminal shell in container" / proc sh|bash|zsh: that pattern
    # matches rt-shell-in-container, a CURATED rule whose tactic is hard-coded to
    # Execution, which would silently override whichever real tactic `tag` carries. Every
    # curated rule in agents/runtime.py keys off proc/file/connect, not off `tags` -- so the
    # one way to land an event on the exact tactic its tags name is to pick a rule/proc/file
    # combination none of those matchers reacts to, and let it fall through to the
    # tag-driven Falco relay (`_falco_native_alert`). "cat /etc/shadow" is exactly that.
    confirmed = _base("Read sensitive file untrusted", namespace=ns,
                      pod=anchor.resource.name, proc="cat", file="/etc/shadow", tags=tags)

    corroborated = _base("Read sensitive file untrusted", namespace=ns,
                         pod="demo-unrecognised-pod-abc123", proc="cat", file="/etc/shadow",
                         tags=tags)

    # No tags at all: _falco_native_alert relays it but cannot place it on a tactic, so it
    # cannot match any finding by construction -- this one is runtime-only on any cluster.
    runtime_only = _base("Unusual outbound connection (demo custom rule)", namespace=ns,
                         pod="demo-unplaced-pod-xyz789", proc="curl")

    return [confirmed, corroborated, runtime_only]


# The same tag vocabulary agents/runtime.py's Falco relay reads, duplicated rather than
# imported from that module's private table: this is demo-data generation, a different
# concern from detection, and the two must not silently drift from a shared private symbol.
_TAG_FOR_TACTIC = {
    "Initial Access": "mitre_initial_access", "Execution": "mitre_execution",
    "Persistence": "mitre_persistence", "Privilege Escalation": "mitre_privilege_escalation",
    "Defense Evasion": "mitre_defense_evasion", "Credential Access": "mitre_credential_access",
    "Discovery": "mitre_discovery", "Lateral Movement": "mitre_lateral_movement",
    "Impact": "mitre_impact",
}
