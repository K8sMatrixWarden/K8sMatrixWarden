"""Post a scan summary to Slack (or any webhook that accepts the same JSON).

Sends only what a person would read in the channel: counts per owner and the top issues with
their fix. No secrets, no raw evidence. Sending is always an explicit command; a scan never
posts anywhere by itself.
"""
from __future__ import annotations

import json
import urllib.request
from collections import Counter

from .remediation import fix_for


def slack_payload(result, min_severity: str = "HIGH", dashboard_url: str = "", top: int = 5) -> dict:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    floor = order.get(min_severity.upper(), 3)
    issues = sorted((i for i in result.workload_issues if order.get(i["severity"], 0) >= floor),
                    key=lambda i: -i.get("score", 0))
    per_owner = Counter(i.get("owner", i.get("namespace") or "cluster-wide") for i in issues)
    r = result.risk
    head = (f"{r.rating_emoji} *{result.cluster_name}*: risk {r.cluster_risk}/10 ({r.rating}), "
            f"{len(issues)} issue(s) at {min_severity.upper()} or worse")
    lines = [head]
    if per_owner:
        lines.append("*By owner:* " + ", ".join(f"{o} {n}" for o, n in per_owner.most_common(8)))
    for i in issues[:top]:
        fix = fix_for(i["rule_id"]).get("how", "")
        lines.append(f"• *[{i['severity']}]* {i['title']} on `{i['workload']}`"
                     f" (owner {i.get('owner', '-')}, score {i.get('score', 0):.0f})" + (f"\n    _fix:_ {fix}" if fix else ""))
    if len(issues) > top:
        lines.append(f"…and {len(issues) - top} more.")
    if dashboard_url:
        lines.append(f"<{dashboard_url}|Open the dashboard>")
    return {"text": "\n".join(lines)}


def send(webhook_url: str, payload: dict, timeout: int = 15) -> int:
    if not webhook_url.startswith("https://"):
        raise ValueError("the webhook must be an https:// URL")
    req = urllib.request.Request(webhook_url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:      # nosec B310: https enforced above
        return resp.status
