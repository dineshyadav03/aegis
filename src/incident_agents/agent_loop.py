"""Generic Gemini tool-calling loop — our equivalent of LangGraph's
create_react_agent, implemented directly against the google-genai SDK
(manual function calling, verified against the live API 2026-09-05).
"""

from __future__ import annotations

import time
from typing import Any, Callable

from google import genai
from google.genai import errors, types


def run_tool_agent(
    client: genai.Client,
    model: str,
    system_instruction: str,
    user_message: str,
    tool_specs: list[types.Tool],
    tool_functions: dict[str, Callable[..., Any]],
    temperature: float = 0.0,
    max_turns: int = 5,
    max_retries: int = 3,
) -> tuple[str, list[dict[str, Any]]]:
    """Runs a tool-calling conversation to completion.

    Returns (final_text, calls_made) where calls_made is a list of
    {"name": str, "args": dict} for every tool invocation — used to build
    the reasoning trail (--show-reasoning).
    """
    config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        temperature=temperature,
        tools=tool_specs,
    )
    contents: list[types.Content] = [
        types.Content(role="user", parts=[types.Part.from_text(text=user_message)])
    ]
    calls_made: list[dict[str, Any]] = []

    for _ in range(max_turns):
        response = _generate_with_retry(client, model, contents, config, max_retries)
        function_calls = response.function_calls or []
        if not function_calls:
            return response.text or "", calls_made

        contents.append(response.candidates[0].content)
        response_parts = []
        for fc in function_calls:
            fn = tool_functions.get(fc.name)
            args = dict(fc.args) if fc.args else {}
            if fn is None:
                result: Any = {"error": f"unknown tool: {fc.name}"}
            else:
                try:
                    result = fn(**args)
                except Exception as exc:  # noqa: BLE001 — surfaced to the model, not crashed
                    result = {"error": str(exc)}
            calls_made.append({"name": fc.name, "args": args, "result": result})
            response_payload = result if isinstance(result, dict) else {"result": result}
            response_parts.append(types.Part.from_function_response(name=fc.name, response=response_payload))
        contents.append(types.Content(role="user", parts=response_parts))

    return "", calls_made


def simple_generate(
    client: genai.Client,
    model: str,
    system_instruction: str,
    user_text: str,
    temperature: float = 0.0,
    response_mime_type: str | None = None,
    response_schema: Any = None,
    max_retries: int = 4,
):
    """A plain (no tool-calling) generate_content call — for narrative/judgment
    text or structured JSON output where the model doesn't need to invoke tools.
    """
    config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        temperature=temperature,
        response_mime_type=response_mime_type,
        response_schema=response_schema,
    )
    contents = [types.Content(role="user", parts=[types.Part.from_text(text=user_text)])]
    return _generate_with_retry(client, model, contents, config, max_retries)


def results_for(calls_made: list[dict[str, Any]], tool_name: str) -> list[Any]:
    """Convenience: pull every result a given tool returned during the run."""
    return [c["result"] for c in calls_made if c["name"] == tool_name]


def _generate_with_retry(
    client: genai.Client,
    model: str,
    contents: list[types.Content],
    config: types.GenerateContentConfig,
    max_retries: int,
):
    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            return client.models.generate_content(model=model, contents=contents, config=config)
        except errors.ServerError as exc:
            last_error = exc
            if attempt < max_retries - 1:
                time.sleep(min(2**attempt * 2, 20))
    raise last_error  # type: ignore[misc]
