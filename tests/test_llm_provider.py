"""
Provider/model agnosticism of the OPTIONAL agent layer (§4).

Proves the contract the whole design turns on: the deterministic scanner does not need an
LLM, the LLM that IS used is whatever the operator configured, and no failure of that LLM
can change a scan's result. Everything here is offline, no key and no network.
"""
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents import llm_provider as lp
from k8smatrixwarden.bootstrap import build_platform
from k8smatrixwarden.core.models import ScanMode, ScanRequest, Scope, ScopeLevel, Selector

_LLM_ENV = ("K8SMATRIXWARDEN_LLM_PROVIDER", "K8SMATRIXWARDEN_LLM_MODEL",
            "K8SMATRIXWARDEN_LLM_BASE_URL", "K8SMATRIXWARDEN_LLM_API_KEY",
            "K8SMATRIXWARDEN_LLM_API_KEY_ENV", "K8SMATRIXWARDEN_LLM_EXTRA",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY")


class _Env:
    """Set/clear LLM environment for one test, always restoring afterwards."""

    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in _LLM_ENV}
        for k in _LLM_ENV:
            os.environ.pop(k, None)
        os.environ.update({k: v for k, v in self.values.items() if v is not None})
        return self

    def __exit__(self, *_):
        for k in _LLM_ENV:
            os.environ.pop(k, None)
        for k, v in self.saved.items():
            if v is not None:
                os.environ[k] = v


# --------------------------------------------------------------------------- #
# Configuration: provider and model come from the operator, not from source.
# --------------------------------------------------------------------------- #
def test_no_configuration_means_not_configured():
    with _Env():
        cfg = lp.resolve_config({})
        assert not cfg.configured
        assert cfg.problems() == ["no provider configured"]
        assert lp.status({})["status"] == "NOT CONFIGURED"


def test_provider_and_model_are_configurable_by_environment():
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="openai",
              K8SMATRIXWARDEN_LLM_MODEL="some-model-v9",
              K8SMATRIXWARDEN_LLM_API_KEY="k"):
        cfg = lp.resolve_config({})
        assert (cfg.provider, cfg.model) == ("openai", "some-model-v9")
        assert cfg.problems() == []


def test_model_change_requires_no_source_change():
    """The same source resolves to whichever model the operator names."""
    for model in ("model-a", "model-b", "llama3.1:70b"):
        with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="openai-compatible",
                  K8SMATRIXWARDEN_LLM_BASE_URL="http://localhost:8000/v1",
                  K8SMATRIXWARDEN_LLM_MODEL=model):
            assert lp.resolve_config({}).model == model


def test_config_file_block_is_used_when_env_is_absent():
    with _Env():
        cfg = lp.resolve_config({"llm": {"provider": "ollama", "model": "qwen2.5"}})
        assert cfg.provider == "ollama" and cfg.model == "qwen2.5"
        # ollama ships a default local endpoint and needs no credential
        assert cfg.base_url.endswith("/v1") and cfg.problems() == []


def test_environment_overrides_the_config_file():
    with _Env(K8SMATRIXWARDEN_LLM_MODEL="env-wins"):
        cfg = lp.resolve_config({"llm": {"provider": "ollama", "model": "file-loses"}})
        assert cfg.model == "env-wins"


def test_provider_autodetected_from_conventional_credential():
    with _Env(OPENAI_API_KEY="sk-test", K8SMATRIXWARDEN_LLM_MODEL="m"):
        assert lp.resolve_config({}).provider == "openai"
    with _Env(ANTHROPIC_API_KEY="sk-test"):
        assert lp.resolve_config({}).provider == "anthropic"


def test_unknown_provider_is_reported_not_raised():
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="not-a-provider"):
        cfg = lp.resolve_config({})
        assert "unknown provider" in cfg.problems()[0]
        assert lp.status({})["status"] == "INVALID"
        try:
            lp.get_provider(cfg)
            assert False, "expected LLMUnavailable"
        except lp.LLMUnavailable:
            pass


def test_missing_model_is_reported():
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="openai", K8SMATRIXWARDEN_LLM_API_KEY="k"):
        assert any("no model" in p for p in lp.resolve_config({}).problems())


def test_missing_credentials_reported_for_remote_provider():
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="anthropic",
              K8SMATRIXWARDEN_LLM_MODEL="whatever"):
        assert any("credentials" in p for p in lp.resolve_config({}).problems())


def test_redacted_config_never_leaks_the_key():
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="openai", K8SMATRIXWARDEN_LLM_MODEL="m",
              K8SMATRIXWARDEN_LLM_API_KEY="super-secret"):
        blob = json.dumps(lp.resolve_config({}).redacted())
        assert "super-secret" not in blob and '"credentials": "present"' in blob


def test_malformed_extra_json_does_not_break_resolution():
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="ollama", K8SMATRIXWARDEN_LLM_MODEL="m",
              K8SMATRIXWARDEN_LLM_EXTRA="{not json"):
        assert lp.resolve_config({}).extra == {}


# --------------------------------------------------------------------------- #
# Wire translation: the same neutral loop drives either provider shape.
# --------------------------------------------------------------------------- #
def test_openai_response_translation_extracts_tool_calls():
    resp = lp._from_openai({"choices": [{"message": {
        "content": "looking",
        "tool_calls": [{"id": "c1", "function": {"name": "run_scan",
                                                 "arguments": '{"mock": true}'}}]}}]})
    assert resp.text == "looking" and resp.wants_tools
    assert resp.tool_calls[0].name == "run_scan"
    assert resp.tool_calls[0].args == {"mock": True}


def test_openai_translation_survives_unparseable_arguments():
    resp = lp._from_openai({"choices": [{"message": {
        "tool_calls": [{"id": "c1", "function": {"name": "t", "arguments": "{oops"}}]}}]})
    assert resp.tool_calls[0].args == {}


def test_anthropic_translation_merges_consecutive_tool_results():
    call = lp.ToolCall("t1", "run_scan", {})
    msgs = lp._to_anthropic([
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "t1", "content": "ok", "is_error": False},
        {"role": "tool", "tool_call_id": "t2", "content": "ok2", "is_error": False},
    ])
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert len(msgs[-1]["content"]) == 2          # both results in ONE user turn


def test_openai_translation_round_trips_tool_calls():
    call = lp.ToolCall("t1", "run_scan", {"mock": True})
    msgs = lp._to_openai("sys", [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "t1", "content": "ok"},
    ])
    assert msgs[0]["role"] == "system"
    assert msgs[2]["tool_calls"][0]["function"]["name"] == "run_scan"
    assert msgs[3] == {"role": "tool", "tool_call_id": "t1", "content": "ok"}


# --------------------------------------------------------------------------- #
# Graceful degradation: LLM problems never touch the deterministic scanner.
# --------------------------------------------------------------------------- #
def _mock_scan():
    platform = build_platform()
    from k8smatrixwarden.agents.scanner import ScannerAgent
    request = ScanRequest(scope=Scope(ScopeLevel.CLUSTER), selector=Selector(),
                          mode=ScanMode.SYNC)
    return ScannerAgent(platform).scan(request, platform.make_collector(mock=True))


def test_scanner_produces_identical_results_with_and_without_an_llm():
    with _Env():
        without = _mock_scan()
    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="openai",
              K8SMATRIXWARDEN_LLM_MODEL="does-not-exist",
              K8SMATRIXWARDEN_LLM_API_KEY="invalid"):
        with_bad_llm = _mock_scan()
    assert without.counts == with_bad_llm.counts
    assert without.risk.cluster_risk == with_bad_llm.risk.cluster_risk
    assert ({(f.rule_id, str(f.resource)) for f in without.findings}
            == {(f.rule_id, str(f.resource)) for f in with_bad_llm.findings})


def test_provider_failure_degrades_to_unavailable_not_a_crash():
    """A provider that errors on every call surfaces as LLMUnavailable, the signal the
    chat REPL already handles by falling back to the deterministic interpreter."""
    class _Boom:
        messages = types.SimpleNamespace(
            create=lambda **_: (_ for _ in ()).throw(RuntimeError("provider down")))

    provider = lp.as_provider(_Boom(), model="m")
    try:
        provider.chat(system="s", messages=[{"role": "user", "content": "x"}], tools=[])
        assert False, "expected LLMUnavailable"
    except lp.LLMUnavailable as exc:
        assert "provider down" in str(exc)


def test_status_does_not_touch_the_network_unless_probed():
    calls = []

    class _Counting:
        messages = types.SimpleNamespace(
            create=lambda **_: calls.append(1))

    with _Env(K8SMATRIXWARDEN_LLM_PROVIDER="anthropic",
              K8SMATRIXWARDEN_LLM_MODEL="m", K8SMATRIXWARDEN_LLM_API_KEY="k"):
        out = lp.status({})
    assert out["status"] == "CONFIGURED" and out["connectivity"] == "not probed"
    assert calls == []


def test_raw_client_is_wrapped_without_importing_an_sdk():
    resp = types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text="hi")])
    raw = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **_: resp))
    out = lp.as_provider(raw, model="m").chat(system="", messages=[], tools=[])
    assert out.text == "hi" and not out.wants_tools


# --------------------------------------------------------------------------- #
# Deterministic provider selection.
#
# Several providers may be credentialed at once. The tool must never quietly pick one,
# and which one it picks must not depend on dict or environment iteration order.
# --------------------------------------------------------------------------- #
_LLM_ENV = ("K8SMATRIXWARDEN_LLM_PROVIDER", "K8SMATRIXWARDEN_LLM_MODEL",
            "K8SMATRIXWARDEN_LLM_BASE_URL", "K8SMATRIXWARDEN_LLM_API_KEY",
            "K8SMATRIXWARDEN_LLM_API_KEY_ENV", "K8SMATRIXWARDEN_LLM_EXTRA",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY",
            "OLLAMA_HOST")


def _clean_env(**overrides):
    """Clear every LLM-related variable, apply overrides, return a restore callable."""
    saved = {k: os.environ.get(k) for k in _LLM_ENV}
    for k in _LLM_ENV:
        os.environ.pop(k, None)
    os.environ.update(overrides)

    def restore():
        for k in _LLM_ENV:
            os.environ.pop(k, None)
            if saved[k] is not None:
                os.environ[k] = saved[k]
    return restore


def test_nothing_configured_is_not_configured_not_an_error():
    restore = _clean_env()
    try:
        cfg = lp.resolve_config()
        assert cfg.configured is False
        assert cfg.provider_source == "none"
        assert lp.status()["status"] == "NOT CONFIGURED"
    finally:
        restore()


def test_a_single_credential_auto_detects_that_provider():
    restore = _clean_env(ANTHROPIC_API_KEY="k")
    try:
        cfg = lp.resolve_config()
        assert cfg.provider == "anthropic" and cfg.provider_source == "auto-detected"
        assert cfg.ambiguous_with == [] and cfg.problems() == []
    finally:
        restore()


def test_an_openai_compatible_credential_auto_detects_openai():
    restore = _clean_env(OPENAI_API_KEY="k", K8SMATRIXWARDEN_LLM_MODEL="m")
    try:
        assert lp.resolve_config().provider == "openai"
    finally:
        restore()


def test_a_local_endpoint_variable_is_an_auto_detect_candidate():
    restore = _clean_env(OLLAMA_HOST="http://localhost:11434")
    try:
        cfg = lp.resolve_config()
        assert cfg.provider == "ollama"
        assert cfg.base_url == "http://localhost:11434/v1"
        # A local server needs no key, only a model name.
        assert cfg.problems() == [f"no model configured for provider 'ollama' "
                                  f"(set K8SMATRIXWARDEN_LLM_MODEL)"]
    finally:
        restore()


def test_two_credentials_are_ambiguous_and_refuse_to_guess():
    restore = _clean_env(ANTHROPIC_API_KEY="a", OPENAI_API_KEY="b")
    try:
        cfg = lp.resolve_config()
        assert cfg.ambiguous_with == ["openai"]
        assert any("ambiguous" in p for p in cfg.problems())
        assert lp.status()["status"] == "AMBIGUOUS"
        try:
            lp.get_provider()
            assert False, "an ambiguous configuration must not silently resolve"
        except lp.LLMUnavailable as exc:
            assert "ambiguous" in str(exc)
    finally:
        restore()


def test_auto_detection_order_is_fixed_not_environment_dependent():
    """Same two keys, inserted in the opposite order: the choice must not move."""
    first = _clean_env(ANTHROPIC_API_KEY="a", OPENAI_API_KEY="b")
    try:
        a = lp.resolve_config().provider
    finally:
        first()
    second = _clean_env(OPENAI_API_KEY="b", ANTHROPIC_API_KEY="a")
    try:
        b = lp.resolve_config().provider
    finally:
        second()
    assert a == b == "anthropic"
    assert lp.autodetect_candidates.__doc__          # documented, not incidental


def test_an_explicit_provider_beats_the_environment_and_clears_ambiguity():
    restore = _clean_env(ANTHROPIC_API_KEY="a", OPENAI_API_KEY="b",
                         K8SMATRIXWARDEN_LLM_PROVIDER="anthropic")
    try:
        env_cfg = lp.resolve_config()
        assert env_cfg.provider_source == "environment"
        assert env_cfg.ambiguous_with == [] and env_cfg.problems() == []
        arg_cfg = lp.resolve_config(provider="openai", model="gpt-x")
        assert arg_cfg.provider == "openai" and arg_cfg.provider_source == "explicit"
    finally:
        restore()


def test_config_file_provider_is_used_when_the_environment_is_silent():
    restore = _clean_env()
    try:
        cfg = lp.resolve_config({"llm": {"provider": "openai", "model": "m",
                                         "base_url": "http://x/v1"}})
        assert cfg.provider_source == "config"
        assert cfg.model == "m" and cfg.problems() == []
    finally:
        restore()


def test_environment_beats_the_config_file():
    restore = _clean_env(K8SMATRIXWARDEN_LLM_PROVIDER="anthropic",
                         K8SMATRIXWARDEN_LLM_MODEL="env-model",
                         K8SMATRIXWARDEN_LLM_API_KEY="k")
    try:
        cfg = lp.resolve_config({"llm": {"provider": "openai", "model": "cfg-model"}})
        assert cfg.provider == "anthropic" and cfg.model == "env-model"
    finally:
        restore()


def test_an_explicit_model_overrides_every_other_source():
    restore = _clean_env(K8SMATRIXWARDEN_LLM_PROVIDER="anthropic",
                         K8SMATRIXWARDEN_LLM_MODEL="env-model",
                         K8SMATRIXWARDEN_LLM_API_KEY="k")
    try:
        assert lp.resolve_config(model="chosen").model == "chosen"
    finally:
        restore()


def test_an_unknown_provider_is_reported_not_guessed_at():
    restore = _clean_env()
    try:
        cfg = lp.resolve_config(provider="does-not-exist")
        assert cfg.problems() and "unknown provider" in cfg.problems()[0]
        assert lp.status(provider="does-not-exist")["status"] == "INVALID"
    finally:
        restore()


def test_the_selected_provider_is_visible_without_touching_the_network():
    restore = _clean_env(K8SMATRIXWARDEN_LLM_PROVIDER="openai",
                         K8SMATRIXWARDEN_LLM_MODEL="m",
                         K8SMATRIXWARDEN_LLM_API_KEY="k")
    try:
        info = lp.status()
        assert info["provider"] == "openai" and info["model"] == "m"
        assert info["provider_source"] == "environment"
        assert info["connectivity"] == "not probed"
        assert info["credentials"] == "present"
        assert "k" not in str(info), "the key itself must never be echoed"
    finally:
        restore()
