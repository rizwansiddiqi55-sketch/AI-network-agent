"""Tool-use loop around the Anthropic Messages API."""
from __future__ import annotations

from importlib import resources
from typing import Any

from .tools import TOOL_SCHEMAS, Toolbox

DEFAULT_MODEL = "claude-opus-5-5"
MAX_TURNS = 20


def load_system_prompt() -> str:
    return resources.files("netagent").joinpath("system_prompt.md").read_text(encoding="utf-8")


def run_agent(
    question: str,
    toolbox: Toolbox,
    client: Any | None = None,
    model: str = DEFAULT_MODEL,
    max_turns: int = MAX_TURNS,
) -> str:
    if client is None:
        import anthropic

        client = anthropic.Anthropic()
    messages: list[dict[str, Any]] = [{"role": "user", "content": question}]
    system = load_system_prompt()
    for _ in range(max_turns):
        resp = client.messages.create(
            model=model, max_tokens=4096, system=system, tools=TOOL_SCHEMAS, messages=messages
        )
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")
        results = [
            {"type": "tool_result", "tool_use_id": b.id, "content": toolbox.call(b.name, dict(b.input))}
            for b in resp.content
            if b.type == "tool_use"
        ]
        messages.append({"role": "user", "content": results})
    return "Stopped: turn limit reached before a conclusion. Review the audit log for evidence gathered."
