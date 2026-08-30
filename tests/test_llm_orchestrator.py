"""
LLM orchestrator (optional chat path). Everything here is offline, the Anthropic client is
replaced with a stub, so no key and no network are needed. Verifies that a multi-step query
dispatches run_scan then correlate_runtime, plus schema/dispatch/heuristic edge cases.
"""
import os
import sys
import types
from typing import Annotated, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.agents import llm_orchestrator as llm


# --------------------------------------------------------------------------- #
# Fakes: SDK message/blocks + a scripted client that returns canned tool calls.
# --------------------------------------------------------------------------- #
class _Block(types.SimpleNamespace):
    pass


def _tool_use(name, tid, args):
    return _Block(type="tool_use", name=name, id=tid, input=args)


def _text(s):
    return _Block(type="text", text=s)


class _Resp(types.SimpleNamespace):
    pass


class _FakeMessages:
    def __init__(self, script):
        self._script = list(script)

    def create(self, **_kw):
        return self._script.pop(0)


class _FakeClient:
    def __init__(self, script):
        self.messages = _FakeMessages(script)


def _install_fake_anthropic(script):
    """Put a stub `anthropic` module in sys.modules and return a restore callable."""
    mod = types.ModuleType("anthropic")
    mod.Anthropic = lambda *a, **k: _FakeClient(script)
    mod.APIError = Exception
    prev = sys.modules.get("anthropic")
    sys.modules["anthropic"] = mod
    return lambda: (sys.modules.__setitem__("anthropic", prev) if prev
                    else sys.modules.pop("anthropic", None))


def _with_recording_tools(monkeypatch_target, calls):
    """Patch build_tools() (as llm imports it) with stubs that record their invocation."""
    def make(name):
        def tool(**kwargs):
            calls.append(name)
            return {"ok": name}
        tool.__doc__ = f"stub {name}"
        return tool
    import k8smatrixwarden.mcp.server as server
    server.build_tools = lambda *a, **k: {"run_scan": make("run_scan"),
                                          "correlate_runtime": make("correlate_runtime")}


# --------------------------------------------------------------------------- #
# The headline test: find privesc, then verify exploitation -> two chained tools.
# --------------------------------------------------------------------------- #
def test_multi_step_query_chains_run_scan_then_correlate_runtime():
    import k8smatrixwarden.mcp.server as server
    saved_build = server.build_tools
    calls = []
    _with_recording_tools(server, calls)
    restore = _install_fake_anthropic([
        _Resp(stop_reason="tool_use",
              content=[_tool_use("run_scan", "t1", {"tactics": ["Privilege Escalation"]})]),
        _Resp(stop_reason="tool_use",
              content=[_tool_use("correlate_runtime", "t2", {"events": []})]),
        _Resp(stop_reason="end_turn", content=[_text("Found privesc; not exploited.")]),
    ])
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    try:
        out = llm.run_agentic(
            "find privilege escalation and verify exploitation", platform=None)
    finally:
        restore()
        server.build_tools = saved_build
        os.environ.pop("ANTHROPIC_API_KEY", None)

    assert calls == ["run_scan", "correlate_runtime"], calls
    assert out == "Found privesc; not exploited."


def test_unknown_tool_returns_structured_error():
    text, is_error = llm._dispatch({}, "nope", {})
    assert is_error and "unknown tool" in text


def test_tool_exception_does_not_crash_dispatch():
    def boom(**_):
        raise ValueError("kaboom")
    text, is_error = llm._dispatch({"boom": boom}, "boom", {})
    assert is_error and "kaboom" in text


def test_empty_response_yields_placeholder():
    """A model that returns no content still produces an answer string, never None."""
    restore = _install_fake_anthropic([_Resp(stop_reason="end_turn", content=[])])
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    try:
        assert llm.run_agentic("scan", platform=None) == "(no response)"
    finally:
        restore()
        os.environ.pop("ANTHROPIC_API_KEY", None)


def test_looks_multi_step_heuristic():
    assert llm._looks_multi_step("find privesc, then verify exploitation")
    assert llm._looks_multi_step("scan for secrets and correlate runtime")
    assert not llm._looks_multi_step("scan the cluster")


def test_schema_reuses_annotated_descriptions_and_required():
    def sample(target: Annotated[str, _fielddesc("the target")],
               limit: Annotated[Optional[int], _fielddesc("row cap")] = None):
        """docstring"""
    schema = llm._schema("sample", sample)
    assert schema["name"] == "sample"
    assert schema["description"] == "docstring"
    props = schema["input_schema"]["properties"]
    assert props["target"] == {"type": "string", "description": "the target"}
    assert props["limit"]["type"] == "integer"
    # `target` has no default -> required; `limit` is optional with a default -> not.
    assert schema["input_schema"]["required"] == ["target"]


def test_missing_key_raises_unavailable():
    saved = {k: os.environ.pop(k) for k in list(os.environ)
             if k.startswith("K8SMATRIXWARDEN_LLM_") or k in ("ANTHROPIC_API_KEY",
                                                              "OPENAI_API_KEY")}
    try:
        llm.run_agentic("scan then verify", platform=None)
        assert False, "expected LLMUnavailable"
    except llm.LLMUnavailable:
        pass
    finally:
        os.environ.update(saved)


class _Field:
    def __init__(self, description):
        self.description = description


def _fielddesc(desc):
    return _Field(desc)
