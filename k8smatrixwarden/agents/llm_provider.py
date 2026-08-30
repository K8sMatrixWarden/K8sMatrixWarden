"""
Provider- and model-agnostic LLM access for the OPTIONAL agent layer (§4).

The deterministic scanner never imports this module. Nothing in rules, evidence,
detection, scoring, correlation, the threat matrix or reporting depends on an LLM being
present, configured, or working. This file exists only so the two optional surfaces (the
`chat` REPL's agentic path and its critic) can talk to whatever model the OPERATOR chose,
without that choice being written into the source.

Resolution order (first hit wins, per field):

    1. environment  , K8SMATRIXWARDEN_LLM_PROVIDER / _MODEL / _BASE_URL / _API_KEY[_ENV]
    2. config file  , the "llm" block of config/agent.json (or a passed-in config dict)
    3. auto-detect  , a provider whose conventional API-key variable is set

Two adapters cover the field:

    anthropic         , the Anthropic SDK (Claude models)
    openai-compatible , any server speaking the OpenAI chat-completions API. That is
                        OpenAI itself, Azure OpenAI, OpenRouter, Together, Groq, vLLM,
                        llama.cpp's server, LM Studio and Ollama (`/v1`), i.e. local
                        models too. Point `base_url` at it and name the model.

Adding a third adapter means adding one class and one `_PROVIDERS` entry; it does not
touch the loop that uses it.

Everything here fails soft. A missing SDK, missing credential, unknown provider, invalid
model or a network error raises `LLMUnavailable`, which every caller already treats as
"fall back to the deterministic path".
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional


class LLMUnavailable(RuntimeError):
    """The optional LLM path cannot run. Never fatal: callers fall back to deterministic
    behaviour, and a scan's correctness never depends on this succeeding."""


# --------------------------------------------------------------------------- #
# Neutral message / response types. Adapters translate to and from their own wire
# format, so the tool loop above never sees a vendor-shaped message.
# --------------------------------------------------------------------------- #
@dataclass
class ToolCall:
    id: str
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list = field(default_factory=list)   # list[ToolCall]

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
_ENV_PREFIX = "K8SMATRIXWARDEN_LLM_"

#: provider key -> (adapter class name, conventional API-key env var, default model).
#: `default_model` is a convenience only. Any model the provider serves can be selected
#: with K8SMATRIXWARDEN_LLM_MODEL or the config file, with no source change. An
#: OpenAI-compatible endpoint has no meaningful default (a local server's model name is
#: whatever the operator loaded), so it must be named explicitly.
_PROVIDERS: dict[str, dict] = {
    "anthropic": {"key_env": "ANTHROPIC_API_KEY", "default_model": "claude-sonnet-5"},
    "openai": {"key_env": "OPENAI_API_KEY", "default_model": ""},
    # Aliases for the same OpenAI-compatible adapter, they differ only in defaults.
    "azure-openai": {"key_env": "AZURE_OPENAI_API_KEY", "default_model": ""},
    "openai-compatible": {"key_env": "OPENAI_API_KEY", "default_model": ""},
    "ollama": {"key_env": "", "default_model": "",
               "default_base_url": "http://localhost:11434/v1"},
}
#: Which adapter implements each provider key.
_ADAPTER = {"anthropic": "anthropic"}   # everything else -> openai-compatible


@dataclass
class LLMConfig:
    provider: str = ""
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    #: Free-form per-provider settings (Azure `deployment`/`api_version`, custom headers).
    #: Deliberately untyped: providers do not expose the same knobs, and inventing a
    #: lowest-common-denominator schema would either lose settings or invent fake ones.
    extra: dict = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.provider)

    def problems(self) -> list[str]:
        """Why this configuration cannot be used, empty when it is usable."""
        if not self.provider:
            return ["no provider configured"]
        if self.provider not in _PROVIDERS:
            return [f"unknown provider {self.provider!r} "
                    f"(supported: {', '.join(sorted(_PROVIDERS))})"]
        out = []
        if not self.model:
            out.append(f"no model configured for provider {self.provider!r} "
                       f"(set {_ENV_PREFIX}MODEL)")
        needs_key = bool(_PROVIDERS[self.provider]["key_env"]) and not self.base_url
        if needs_key and not self.api_key:
            out.append(f"no credentials (set {_PROVIDERS[self.provider]['key_env']} "
                       f"or {_ENV_PREFIX}API_KEY)")
        return out

    def redacted(self) -> dict:
        """Safe to print/log/serialise, never carries the secret itself."""
        return {"provider": self.provider or None, "model": self.model or None,
                "base_url": self.base_url or None,
                "credentials": "present" if self.api_key else "absent",
                "extra": {k: v for k, v in self.extra.items() if "key" not in k.lower()}}


def _env(name: str) -> str:
    return (os.environ.get(_ENV_PREFIX + name) or "").strip()


def _autodetect_provider() -> str:
    """Pick a provider from whichever conventional credential is present. Deterministic
    order so two configured keys always resolve the same way."""
    for name in ("anthropic", "openai"):
        if os.environ.get(_PROVIDERS[name]["key_env"]):
            return name
    return ""


def resolve_config(config: Optional[dict] = None) -> LLMConfig:
    """Build the effective LLM configuration. Never raises, an unusable configuration is
    reported through `LLMConfig.problems()` so `doctor` can show it and the agent path can
    decline cleanly."""
    block = dict((config or {}).get("llm") or {})
    provider = (_env("PROVIDER") or str(block.get("provider") or "")
                or _autodetect_provider()).strip().lower()
    meta = _PROVIDERS.get(provider, {})

    model = (_env("MODEL") or str(block.get("model") or "")
             or str(meta.get("default_model") or "")).strip()
    base_url = (_env("BASE_URL") or str(block.get("base_url") or "")
                or str(meta.get("default_base_url") or "")).strip()

    key_env = _env("API_KEY_ENV") or str(block.get("api_key_env") or "") \
        or str(meta.get("key_env") or "")
    api_key = (_env("API_KEY") or (os.environ.get(key_env, "") if key_env else "")).strip()

    extra = dict(block.get("extra") or {})
    raw_extra = _env("EXTRA")
    if raw_extra:
        try:
            parsed = json.loads(raw_extra)
            if isinstance(parsed, dict):
                extra.update(parsed)
        except ValueError:
            pass                      # a malformed extra blob must not break resolution
    return LLMConfig(provider=provider, model=model, base_url=base_url,
                     api_key=api_key, extra=extra)


# --------------------------------------------------------------------------- #
# Adapters
# --------------------------------------------------------------------------- #
class LLMProvider:
    """Minimal surface the agent loop needs: one tool-enabled chat turn, and a ping."""

    name = "base"

    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg

    def chat(self, *, system: str, messages: list, tools: list,
             max_tokens: int = 4096) -> LLMResponse:  # pragma: no cover - interface
        raise NotImplementedError

    def ping(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        try:
            import anthropic
        except ImportError as exc:
            raise LLMUnavailable(
                "the 'anthropic' package is not installed, run "
                '`pip install -e ".[agent]"` or select an OpenAI-compatible provider'
            ) from exc
        kwargs: dict[str, Any] = {}
        if cfg.api_key:
            kwargs["api_key"] = cfg.api_key
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        self._sdk = anthropic
        self._client = anthropic.Anthropic(**kwargs)

    def chat(self, *, system, messages, tools, max_tokens=4096) -> LLMResponse:
        try:
            resp = self._client.messages.create(
                model=self.cfg.model, max_tokens=max_tokens, system=system,
                tools=[_anthropic_tool(t) for t in tools],
                messages=_to_anthropic(messages))
        except Exception as exc:
            raise LLMUnavailable(f"{self.cfg.provider} API error: {exc}") from exc
        text = "".join(b.text for b in resp.content
                       if getattr(b, "type", None) == "text"
                       and getattr(b, "text", ""))
        calls = [ToolCall(b.id, b.name, dict(b.input or {})) for b in resp.content
                 if getattr(b, "type", None) == "tool_use"]
        return LLMResponse(text=text.strip(), tool_calls=calls)

    def ping(self) -> None:
        try:
            self._client.messages.create(
                model=self.cfg.model, max_tokens=1,
                messages=[{"role": "user", "content": "ping"}])
        except Exception as exc:
            raise LLMUnavailable(f"{self.cfg.provider} unreachable: {exc}") from exc


class OpenAICompatibleProvider(LLMProvider):
    """Any server speaking the OpenAI chat-completions API.

    Uses the `openai` SDK when installed, and otherwise falls back to a plain
    `urllib.request` POST, so a local model behind an OpenAI-compatible endpoint works
    with no third-party package at all (the project's stdlib-first stance)."""

    name = "openai-compatible"

    def __init__(self, cfg: LLMConfig):
        super().__init__(cfg)
        self._client = None
        try:
            import openai
            kwargs: dict[str, Any] = {"api_key": cfg.api_key or "not-needed"}
            if cfg.base_url:
                kwargs["base_url"] = cfg.base_url
            self._client = openai.OpenAI(**kwargs)
        except Exception:
            self._client = None      # stdlib HTTP fallback below

    def _endpoint(self) -> str:
        base = (self.cfg.base_url or "https://api.openai.com/v1").rstrip("/")
        return f"{base}/chat/completions"

    def _post(self, payload: dict) -> dict:
        import urllib.error
        import urllib.request
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        headers.update(self.cfg.extra.get("headers") or {})
        req = urllib.request.Request(self._endpoint(), data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise LLMUnavailable(f"{self.cfg.provider} HTTP {exc.code}: {detail}") from exc
        except Exception as exc:
            raise LLMUnavailable(f"{self.cfg.provider} unreachable: {exc}") from exc

    def chat(self, *, system, messages, tools, max_tokens=4096) -> LLMResponse:
        payload = {"model": self.cfg.model, "max_tokens": max_tokens,
                   "messages": _to_openai(system, messages),
                   "tools": [_openai_tool(t) for t in tools]}
        if self._client is not None:
            try:
                resp = self._client.chat.completions.create(
                    model=self.cfg.model, max_tokens=max_tokens,
                    messages=payload["messages"], tools=payload["tools"])
                data = resp.model_dump()
            except Exception as exc:
                raise LLMUnavailable(f"{self.cfg.provider} API error: {exc}") from exc
        else:
            data = self._post(payload)
        return _from_openai(data)

    def ping(self) -> None:
        self._post({"model": self.cfg.model, "max_tokens": 1,
                    "messages": [{"role": "user", "content": "ping"}]})


class _RawClientProvider(AnthropicProvider):
    """Wrap an already-constructed Anthropic-shaped SDK client.

    Lets a caller (or a test) inject a preconfigured client without this module importing
    or configuring the SDK itself. Reuses AnthropicProvider's request/response translation
    verbatim, only construction differs, so there is no second code path to keep in sync.
    """

    def __init__(self, client, model: str = ""):
        LLMProvider.__init__(self, LLMConfig(provider="anthropic", model=model))
        self._client = client
        self._sdk = None


def as_provider(obj, *, model: str = "") -> LLMProvider:
    """Coerce `obj` to an LLMProvider: pass one through, wrap a raw SDK client."""
    if isinstance(obj, LLMProvider):
        if model:
            obj.cfg.model = model
        return obj
    return _RawClientProvider(obj, model=model)


def get_provider(cfg: Optional[LLMConfig] = None,
                 config: Optional[dict] = None) -> LLMProvider:
    """Build the configured provider, or raise LLMUnavailable explaining why not."""
    cfg = cfg or resolve_config(config)
    problems = cfg.problems()
    if problems:
        raise LLMUnavailable("; ".join(problems))
    if _ADAPTER.get(cfg.provider) == "anthropic":
        return AnthropicProvider(cfg)
    return OpenAICompatibleProvider(cfg)


def status(config: Optional[dict] = None, *, probe: bool = False) -> dict:
    """LLM health for `doctor`. Never raises. `probe=True` makes one tiny live call to
    verify credentials and model name; without it no network is touched."""
    cfg = resolve_config(config)
    out = {**cfg.redacted(), "configured": cfg.configured,
           "problems": cfg.problems(), "connectivity": "not probed"}
    if not cfg.configured:
        out["status"] = "NOT CONFIGURED"
        return out
    if out["problems"]:
        out["status"] = "INVALID"
        return out
    out["status"] = "CONFIGURED"
    if probe:
        try:
            get_provider(cfg).ping()
            out["connectivity"] = "available"
        except LLMUnavailable as exc:
            out["connectivity"] = f"unavailable: {exc}"
            out["status"] = "UNAVAILABLE"
    return out


# --------------------------------------------------------------------------- #
# Wire-format translation
# --------------------------------------------------------------------------- #
def _anthropic_tool(tool: dict) -> dict:
    return {"name": tool["name"], "description": tool.get("description", ""),
            "input_schema": tool.get("input_schema") or {"type": "object",
                                                         "properties": {}}}


def _openai_tool(tool: dict) -> dict:
    return {"type": "function",
            "function": {"name": tool["name"],
                         "description": (tool.get("description", "") or "")[:1024],
                         "parameters": tool.get("input_schema")
                         or {"type": "object", "properties": {}}}}


def _to_anthropic(messages: list) -> list:
    """Neutral messages -> Anthropic content blocks. Consecutive tool results are merged
    into one user message, which is what the API expects after a tool_use turn."""
    out: list[dict] = []
    for msg in messages:
        role = msg.get("role")
        if role == "user":
            out.append({"role": "user", "content": msg.get("content", "")})
        elif role == "assistant":
            blocks: list[dict] = []
            if msg.get("content"):
                blocks.append({"type": "text", "text": msg["content"]})
            for call in msg.get("tool_calls") or []:
                blocks.append({"type": "tool_use", "id": call.id, "name": call.name,
                               "input": call.args})
            out.append({"role": "assistant", "content": blocks or [
                {"type": "text", "text": "(no content)"}]})
        elif role == "tool":
            block = {"type": "tool_result", "tool_use_id": msg.get("tool_call_id", ""),
                     "content": msg.get("content", ""),
                     "is_error": bool(msg.get("is_error"))}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return out


def _to_openai(system: str, messages: list) -> list:
    out: list[dict] = [{"role": "system", "content": system}] if system else []
    for msg in messages:
        role = msg.get("role")
        if role == "user":
            out.append({"role": "user", "content": msg.get("content", "")})
        elif role == "assistant":
            entry: dict[str, Any] = {"role": "assistant",
                                     "content": msg.get("content") or None}
            calls = msg.get("tool_calls") or []
            if calls:
                entry["tool_calls"] = [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.name, "arguments": json.dumps(c.args)}}
                    for c in calls]
            out.append(entry)
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": msg.get("tool_call_id", ""),
                        "content": msg.get("content", "")})
    return out


def _from_openai(data: dict) -> LLMResponse:
    choices = data.get("choices") or []
    message = (choices[0] or {}).get("message", {}) if choices else {}
    calls = []
    for raw in message.get("tool_calls") or []:
        fn = raw.get("function", {}) or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            args = {}
        calls.append(ToolCall(raw.get("id", ""), fn.get("name", ""),
                              args if isinstance(args, dict) else {}))
    return LLMResponse(text=(message.get("content") or "").strip(), tool_calls=calls)
