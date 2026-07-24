"""Interactive Chat interface, scripted turns (§3.1, §7.4)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.cli.chat import ChatSession, run_chat


def _session():
    return ChatSession(build_platform(), mock=True)


def test_help_and_exit():
    s = _session()
    assert "Commands" in s.handle_turn("help").output
    t = s.handle_turn("exit")
    assert t.quit is True


def test_coverage_turn():
    out = _session().handle_turn("show coverage").output
    assert "MITRE tactic coverage" in out
    assert "Privilege Escalation" in out


def test_nl_scan_requires_confirmation_then_runs():
    s = _session()
    t1 = s.handle_turn("scan production for Persistence")
    assert t1.needs_confirmation
    assert "Proceed" in t1.output
    assert "Persistence" in t1.output
    # confirm -> runs and returns a report
    t2 = s.handle_turn("y")
    assert "K8s SECURITY REPORT" in t2.output or "Risk" in t2.output


def test_nl_scan_can_be_cancelled():
    s = _session()
    s.handle_turn("scan for Credential Access")
    t = s.handle_turn("n")
    assert "Cancelled" in t.output


def test_cis_intent_runs_benchmark():
    out = _session().handle_turn("run the cis benchmark").output
    assert "CIS Kubernetes Benchmark" in out
    assert "PASS" in out


def test_container_escape_alias_via_chat():
    s = _session()
    t = s.handle_turn("scan only Container Escape")
    assert t.needs_confirmation
    # the resolved plan should mention the workload shard rules
    assert "workload" in t.output


def _scan(s):
    """Helper: run a full scan so follow-ups have a last_result."""
    s.handle_turn("is my cluster secure?")
    return s.handle_turn("y")


# ── synonym / varied phrasing ─────────────────────────────────────────── #
def test_synonym_phrasings_resolve():
    for phrase in ("scan for privesc", "any leaked secrets?",
                   "look for container breakout", "check roles and permissions"):
        t = _session().handle_turn(phrase)
        assert t.needs_confirmation, f"{phrase!r} did not resolve to a scan"


# ── informational Q&A ─────────────────────────────────────────────────── #
def test_capabilities_and_lists():
    s = _session()
    assert "Kubernetes security assistant" in s.handle_turn("what can you do?").output
    assert "Persistence" in s.handle_turn("list tactics").output
    assert "workload_pod_security" in s.handle_turn("list modules").output
    assert "Container Escape" in s.handle_turn("list techniques").output


def test_explain_tactic_and_rule_and_domain():
    s = _session()
    assert "Lateral Movement" in s.handle_turn("explain lateral movement").output
    assert "workload-privileged-container" in \
        s.handle_turn("what is workload_pod_security").output
    out = s.handle_turn("explain workload-privileged-container").output
    assert "Privileged container" in out or "privileged" in out.lower()


def test_greeting_and_thanks():
    s = _session()
    assert "Hi" in s.handle_turn("hey").output
    assert "welcome" in s.handle_turn("thanks!").output.lower()


# ── session memory / follow-ups ───────────────────────────────────────── #
def test_followups_require_prior_scan():
    s = _session()
    assert "don't have any results" in s.handle_turn("show criticals").output.lower()
    assert "don't have any results" in s.handle_turn("export markdown").output.lower()


def test_show_criticals_after_scan():
    s = _session()
    _scan(s)
    out = s.handle_turn("show criticals").output
    assert "CRITICAL finding" in out


def test_details_followup():
    s = _session()
    _scan(s)
    out = s.handle_turn("details workload-privileged-container").output
    assert "workload-privileged-container" in out
    assert "MITRE" in out


def test_export_writes_file(tmp_path=None):
    import os
    s = _session()
    _scan(s)
    cwd = os.getcwd()
    try:
        os.chdir(os.environ.get("TEMP", "."))
        out = s.handle_turn("export markdown").output
        assert "Saved" in out and ".md" in out
    finally:
        os.chdir(cwd)


# ── smart fallback / namespace validation ─────────────────────────────── #
def test_garbage_target_falls_back_not_full_scan():
    t = _session().handle_turn("scan the frobnicator")
    assert not t.needs_confirmation
    assert "couldn't turn" in t.output.lower()


def test_unknown_namespace_is_rejected_with_suggestion():
    out = _session().handle_turn("scan prod for rbac").output
    assert "namespace" in out.lower()
    assert "production" in out          # fuzzy suggestion


def test_confirmation_recovers_if_user_changes_mind():
    s = _session()
    s.handle_turn("scan for persistence")      # sets a pending confirmation
    t = s.handle_turn("list tactics")          # not y/n -> should not get stuck
    assert "Persistence" in t.output           # the new request was handled


def test_run_chat_loop_with_scripted_io():
    inputs = iter(["help", "show coverage", "exit"])
    outputs = []
    code = run_chat(build_platform(), mock=True,
                    input_fn=lambda _p: next(inputs),
                    print_fn=outputs.append)
    assert code == 0
    joined = "\n".join(outputs)
    assert "k8smatrixwarden chat" in joined        # banner
    assert "Commands" in joined           # help
    assert "coverage" in joined.lower()
