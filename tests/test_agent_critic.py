"""
Evidence critic (Phase 4). LLM client is a stub, no network.
Covers: detects missing evidence, approves supported findings, fails open on garbage / API error.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents import critic


def _client(text):
    resp = types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text=text)])
    return types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **_: resp))


def test_critic_detects_missing_evidence():
    c = _client('{"approved": false, "issues": ["no evidence for RCE"], '
                '"recommended_actions": ["run correlate_runtime"]}')
    v = critic.review("scan server01", "RCE present", client=c, model="m")
    assert v["approved"] is False
    assert "no evidence for RCE" in v["issues"]
    assert v["recommended_actions"] == ["run correlate_runtime"]


def test_critic_approves_when_supported():
    c = _client('reasoning... {"approved": true, "issues": [], "recommended_actions": []}')
    v = critic.review("scan", "backed by tool output", client=c, model="m")
    assert v["approved"] is True and v["issues"] == []


def test_critic_fails_open_on_garbage():
    v = critic.review("scan", "ok", client=_client("not json at all"), model="m")
    assert v["approved"] is True and v["issues"] == []


def test_critic_fails_open_on_api_error():
    def boom(**_):
        raise RuntimeError("api down")
    c = types.SimpleNamespace(messages=types.SimpleNamespace(create=boom))
    v = critic.review("scan", "ok", client=c, model="m")
    assert v["approved"] is True
