"""Every command and snippet an engineer is told to run names the real object, with no
leftover template placeholder, and the dashboard escapes it exactly once."""
import re

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.explain import explain_finding
from k8smatrixwarden.core.finding_context import FINDING_CONTEXT, fill
from k8smatrixwarden.core.models import ResourceRef
from k8smatrixwarden.core.remediation import FIXES
from k8smatrixwarden.web.pages import dashboard_page

# values only the engineer can supply
_ALLOWED = {"<digest>", "<new>"}
_LEFT = re.compile(r"\{name\}|\{namespace\}|\{kind\}|<name>|<pod>|<ns>|<kind>|<workload>")


def _finding(rule_id):
    rule = build_platform().registry.rules.get(rule_id)
    return rule.finding(ResourceRef("Service", "web", "team-a"), "m",
                        evidence={"subject": {"namespace": "team-a"}})


def test_no_placeholder_survives_for_any_rule():
    for rid in sorted(set(FIXES) | set(FINDING_CONTEXT)):
        f = _finding(rid)
        texts = [fill(t, f, braces=True) for t in FINDING_CONTEXT.get(rid, {}).get("validation", [])]
        texts += [fill(v, f) for v in FIXES.get(rid, {}).values()]
        for t in texts:
            assert not _LEFT.search(t), (rid, t)


def test_jq_braces_do_not_stop_the_fill():
    f = _finding("rbac-broad-subject-admin")
    assert "{name:.metadata.name" in fill(FINDING_CONTEXT["rbac-cluster-admin-user-binding"]
                                          ["validation"][0], f, braces=True)


def test_dashboard_escapes_validation_once():
    assert "(d.validation||[]).map(esc)" not in dashboard_page()
