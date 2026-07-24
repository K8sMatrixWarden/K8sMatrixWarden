"""
Optional LLM-powered orchestration for the local `chat` REPL (§7.4 extension).

When driven from an MCP client (Claude Desktop / Cursor), the CLIENT already orchestrates, 
it reads the 30 tool schemas and chains them. The one surface with no external orchestrator
is the standalone `chat` command, which parses with regex and can't chain. This module fills
exactly that gap, and nothing else.

Reuse, don't rebuild, two existing seams do all the work:
  * ``mcp.server.build_tools()``     -> the same 30 callables MCP exposes (the tool catalog)
  * their ``Annotated[...]`` hints    -> already on every parameter for FastMCP; reused here
                                         to generate the tool JSON-schemas

Everything else (plan -> call -> observe -> repeat -> final answer) is the Anthropic SDK's
tool-use loop below. There is no planner, DAG, state machine, or workflow engine here, just
the documented tool dispatch loop wired onto the existing catalog. Regex interpretation stays
the fallback and the offline default; this path only runs when ANTHROPIC_API_KEY is set.
"""
from __future__ import annotations

import inspect
import json
import logging
import os
import re
import time
from typing import Any, Callable, Union, get_args, get_origin

MODEL_DEFAULT = "claude-opus-4-8"
_MAX_STEPS = 12  # hard cap so a runaway tool loop can't spin forever

log = logging.getLogger("k8smatrixwarden.llm")

from .security_profile import SECURITY_SYSTEM_PROMPT  # noqa: E402 (default system prompt)
from .tool_registry import enrich_schemas             # noqa: E402 (Phase 7)


class LLMUnavailable(RuntimeError):
    """The agentic path can't run (no key, SDK missing, or the API call failed).

    The chat REPL catches this and falls back to the regex interpreter, so the LLM path is
    always strictly additive, its absence or failure never breaks offline behaviour."""


# --------------------------------------------------------------------------- #
# Multi-step heuristic, decides whether a query is worth an LLM round-trip.
# Lightweight regex only; never calls a model to decide whether to call a model.
# --------------------------------------------------------------------------- #
_MULTI = re.compile(
    r"\b(then|and then|after that|afterwards|followed by|"
    r"and (?:also |then )?(?:check|verify|correlate|confirm|determine|see whether|"
    r"find out|summari[sz])|verify|correlate|cross[- ]?reference|actively exploit\w*)\b",
    re.I,
)
_VERBS = re.compile(
    r"\b(scan|check|verify|correlate|find|list|detect|summari[sz]\w+|exploit|audit|"
    r"map|build|determine|report)\b", re.I)


def _looks_multi_step(query: str) -> bool:
    """True if the query reads like more than one chained action. No LLM used."""
    if _MULTI.search(query):
        return True
    return len({v.lower() for v in _VERBS.findall(query)}) >= 2


# --------------------------------------------------------------------------- #
# Tool-schema generation, reuse the Annotated hints, don't hand-write JSON.
# --------------------------------------------------------------------------- #
_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean",
               list: "array", dict: "object"}


def _json_type(tp) -> str:
    origin = get_origin(tp)
    if origin in (list, tuple):
        return "array"
    if origin is dict:
        return "object"
    return _JSON_TYPES.get(tp, "string")


def _unwrap(annotation):
    """Reduce a possibly-``Annotated[Optional[T], Field(description=...)]`` hint to
    (base_type, description, is_optional)."""
    description = ""
    is_optional = False
    if hasattr(annotation, "__metadata__"):          # Annotated[...]
        args = get_args(annotation)
        annotation = args[0]
        for meta in args[1:]:
            desc = getattr(meta, "description", None)  # pydantic FieldInfo
            if desc:
                description = desc
    if get_origin(annotation) is Union:              # Optional[T] == Union[T, None]
        parts = get_args(annotation)
        non_none = [a for a in parts if a is not type(None)]
        is_optional = len(non_none) != len(parts)
        if non_none:
            annotation = non_none[0]
    return annotation, description, is_optional


def _schema(name: str, fn: Callable) -> dict:
    """Build an Anthropic tool definition from a build_tools() callable, reusing the
    Annotated parameter hints already present for FastMCP."""
    props: dict[str, Any] = {}
    required: list[str] = []
    for pname, param in inspect.signature(fn).parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        base, desc, optional = _unwrap(param.annotation)
        prop: dict[str, Any] = {"type": _json_type(base)}
        if desc:
            prop["description"] = desc
        if prop["type"] == "array":
            item_args = get_args(base)
            prop["items"] = {"type": _json_type(item_args[0]) if item_args else "string"}
        props[pname] = prop
        if param.default is inspect.Parameter.empty and not optional:
            required.append(pname)
    return {"name": name, "description": inspect.getdoc(fn) or name,
            "input_schema": {"type": "object", "properties": props, "required": required}}


# --------------------------------------------------------------------------- #
# Dispatch, execute one tool call; never raise (one bad tool must not kill the loop).
# --------------------------------------------------------------------------- #
def _dispatch(tools: dict[str, Callable], name: str, args: dict) -> tuple[str, bool]:
    """Run tool `name` with `args`. Returns (result_text, is_error)."""
    fn = tools.get(name)
    if fn is None:
        return f"error: unknown tool {name!r}", True
    started = time.monotonic()
    try:
        result = fn(**(args or {}))
    except TypeError as exc:
        return f"error: bad arguments for {name}: {exc}", True
    except Exception as exc:  # isolation, surface the failure to the model, keep looping
        log.warning("tool %s raised: %s", name, exc)
        return f"error: tool {name} failed: {type(exc).__name__}: {exc}", True
    log.info("tool %s ok in %.0fms", name, (time.monotonic() - started) * 1000)
    if isinstance(result, str):
        return result, False
    try:
        return json.dumps(result, default=str), False
    except (TypeError, ValueError):
        return str(result), False


# --------------------------------------------------------------------------- #
# The agentic entry point.
# --------------------------------------------------------------------------- #
def run_agentic(query: str, platform=None, *, model: str = MODEL_DEFAULT,
                system: str = None, prelude: str = "", client=None,
                trace: list = None, max_steps: int = _MAX_STEPS, memory=None) -> str:
    """Answer a request by letting Claude pick and chain the existing tools (the raw loop).

    The extra knobs are used by investigate() and default to today's behaviour:
      system   , system prompt (defaults to the security profile, Phase 1)
      prelude  , text prepended to the first user message (retrieved memory, Phase 3)
      client   , reuse an Anthropic client so the critic shares one; built if None
      trace    , if a list, each dispatched tool name is appended (for lesson-saving)
      max_steps, tool-iteration cap (config.max_tool_iterations)
    Raises LLMUnavailable if the key/SDK is missing or the API fails, so the caller can fall
    back to the regex interpreter. The tool dispatcher itself is unchanged."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise LLMUnavailable("ANTHROPIC_API_KEY is not set")
    try:
        import anthropic
    except ImportError as exc:
        raise LLMUnavailable("the 'anthropic' package is not installed, run "
                             "`pip install -e \".[agent]\"` to enable LLM chat") from exc

    from ..mcp.server import build_tools
    tools = build_tools()
    schemas = enrich_schemas([_schema(name, fn) for name, fn in tools.items()])
    if client is None:
        client = anthropic.Anthropic()
    user = f"{prelude}\n\n{query}" if prelude else query
    messages: list[dict] = [{"role": "user", "content": user}]
    system = system or SECURITY_SYSTEM_PROMPT
    log.info("agentic run: model=%s tools=%d prelude=%d", model, len(schemas), len(prelude))

    try:
        for _ in range(max_steps):
            resp = client.messages.create(model=model, max_tokens=4096, system=system,
                                          tools=schemas, messages=messages)
            if resp.stop_reason != "tool_use":
                return _final_text(resp)
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for block in resp.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                if trace is not None:
                    trace.append(block.name)
                text, is_error = _dispatch(tools, block.name, block.input)
                if memory is not None:                 # Upgrade 2, score + persist + hint
                    text = _score_and_hint(memory, block.name, text, is_error)
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": text, "is_error": is_error})
            messages.append({"role": "user", "content": results})
        return "Stopped after too many tool steps, try a narrower request."
    except anthropic.APIError as exc:  # auth / rate-limit / timeout / connection all subclass this
        raise LLMUnavailable(f"Anthropic API error: {exc}") from exc


def _final_text(resp) -> str:
    parts = [b.text for b in resp.content
             if getattr(b, "type", None) == "text" and getattr(b, "text", "")]
    return "\n".join(parts).strip() or "(no response)"


def _score_and_hint(memory, name: str, text: str, is_error: bool) -> str:
    """Evaluate a tool result's quality, persist it, and append a hint to what the model sees
    (Upgrade 2). Best-effort, a memory/eval failure never breaks the tool loop."""
    from .tool_quality import evaluate_tool_result
    try:
        q = evaluate_tool_result(name, text)
        memory.save_tool_quality(name, q["score"], ", ".join(q["missing_information"]),
                                 ", ".join(q["recommended_followups"]))
    except Exception:  # pragma: no cover - never let quality scoring break dispatch
        return text
    if is_error or q["score"] >= 1.0:
        return text
    return (f"{text}\n[quality {q['score']:.2f}] missing: "
            f"{', '.join(q['missing_information']) or 'n/a'}; consider: "
            f"{', '.join(q['recommended_followups']) or 'deeper enumeration'}")


# --------------------------------------------------------------------------- #
# Controlled agent loop (Phase 8): profile + memory -> tool loop -> critic -> save.
# Wraps run_agentic; the tool dispatcher above is untouched.
# --------------------------------------------------------------------------- #
def load_agent_config(path: str = None) -> dict:
    """Load config/agent.json; a missing/invalid file falls back to the shipped defaults."""
    default = {"memory": {"enabled": True},
               "critic": {"enabled": True, "max_validation_rounds": 3,
                          "minimum_confidence": 0.75},
               "learning": {"enabled": True}, "max_tool_iterations": _MAX_STEPS}
    p = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "config", "agent.json")
    try:
        with open(p, encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, ValueError):
        return default
    for k, v in default.items():
        loaded.setdefault(k, v)
    return loaded


def investigate(query: str, platform=None, *, model: str = MODEL_DEFAULT,
                config: dict = None, memory=None, client=None) -> str:
    """The controlled validation loop (Phase 8 + Upgrade 1/2/3): inject profile + relevant
    memory + tool-quality hints, run the (unchanged) tool loop, critique the draft, and RE-RUN
    with the critic's feedback until it approves or the round cap is hit. Then score confidence
    from the evidence and persist the finding + successful tool sequence. Each stage is gated by
    config; disabling everything reduces to a single run_agentic call. Raises LLMUnavailable
    like run_agentic."""
    from .validation_loop import should_continue
    from .confidence import calculate_confidence, verification_status

    cfg = config or load_agent_config()
    ccfg = cfg.get("critic", {})
    rounds = int(ccfg.get("max_validation_rounds", 3))
    min_conf = float(ccfg.get("minimum_confidence", 0.75))

    mem, owns_mem = memory, False
    if cfg["memory"]["enabled"] and mem is None:
        from .memory import Memory
        mem, owns_mem = Memory(), True

    prelude = ""
    if mem and cfg["memory"]["enabled"]:
        prelude = mem.prelude_for(query)
        hints = mem.tool_quality_hints()               # Upgrade 2, inject learned tool quality
        if hints:
            prelude = f"{prelude}\n\n{hints}" if prelude else hints
    if client is None and os.getenv("ANTHROPIC_API_KEY"):
        import anthropic
        client = anthropic.Anthropic()

    trace: list = []
    verdict = dict(_APPROVED)
    draft, feedback = "", ""
    for _ in range(max(1, rounds)):                    # Upgrade 1, critic-triggered re-run
        q = query if not feedback else f"{query}\n\n{feedback}"
        draft = run_agentic(q, platform, model=model, prelude=prelude, client=client,
                            trace=trace, max_steps=cfg["max_tool_iterations"], memory=mem)
        if not (cfg["critic"]["enabled"] and client is not None):
            break
        from .critic import review
        verdict = review(query, draft, client=client, model=model,
                         evidence="tools used: " + " -> ".join(trace))
        if verdict["approved"] or not should_continue(verdict, min_conf):
            break
        feedback = _feedback_text(verdict)

    # Upgrade 3, evidence-based confidence; the critic's own (lower) confidence wins.
    conf = min(calculate_confidence(draft, " -> ".join(trace), draft),
               float(verdict.get("confidence", 1.0)))
    status = verification_status(conf)

    answer = draft + _report_footer(conf, status, trace)
    if not verdict["approved"]:
        answer += "\n\n⚠ Critic flagged unresolved gaps:"
        answer += "".join(f"\n  - {i}" for i in verdict["missing_evidence"])
        if verdict["recommended_tools"]:
            answer += "\n  Suggested next: " + ", ".join(verdict["recommended_tools"])

    if mem:
        from .memory import extract_asset
        asset = extract_asset(query)
        if cfg["learning"]["enabled"] and trace:
            mem.save_lesson(task=query, successful_tool_sequence=trace,
                            lesson=(f"validated ({status}, confidence {conf})"
                                    if verdict["approved"]
                                    else "; ".join(verdict["missing_evidence"])))
        if cfg["memory"]["enabled"] and asset:
            mem.save_finding(asset=asset, finding=_summary(draft), severity="INFO",
                             evidence=" -> ".join(trace),
                             status="reported" if verdict["approved"] else "needs-validation",
                             confidence=conf, verification_status=status, evidence_items=trace)
        if owns_mem:
            mem.close()
    return answer


_APPROVED = {"approved": True, "confidence": 1.0, "missing_evidence": [],
             "recommended_tools": [], "reason": "", "issues": [], "recommended_actions": []}


def _feedback_text(verdict: dict) -> str:
    parts = ["The previous assessment was NOT sufficiently validated, gather more evidence "
             "before concluding."]
    if verdict.get("missing_evidence"):
        parts.append("Missing evidence: " + ", ".join(verdict["missing_evidence"]) + ".")
    if verdict.get("recommended_tools"):
        parts.append("Run these tools to validate: " + ", ".join(verdict["recommended_tools"])
                     + ".")
    if verdict.get("reason"):
        parts.append("Critic reason: " + verdict["reason"])
    return " ".join(parts)


def _report_footer(confidence: float, status: str, trace: list) -> str:
    return (f"\n\n, \nConfidence: {round(confidence * 100)}% · Status: {status}"
            f"\nEvidence: {' -> '.join(trace) if trace else 'none'}")


def _summary(text: str) -> str:
    stripped = (text or "").strip()
    return (stripped.splitlines()[0] if stripped else "(no summary)")[:200]
