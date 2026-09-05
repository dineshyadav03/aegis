"""Classify node: risk-assess and enrich every detected item into a finding.

Severity assignment is deterministic (tools/classification.py) for
consistency; Gemini adds a short rationale narrative per run, used in the
reasoning trail — it does not get to override severity.

Phase 3 (GraphRAG, PROJECT_DOCUMENTATION.md §5.10): each item's retrieved
CVE/CWE/ATT&CK context can escalate severity by one level when a similar,
high-CVSS real-world CVE is found — see tools/classification.py's
risk_assessor_tool.

GraphRAG retrieval is genuinely LLM-driven when Gemini is available: a
single `agent_loop.run_tool_agent` call is given a `cve_lookup` tool and
decides, per finding, whether a CVE/ATT&CK lookup is worth doing and what
to search for — rather than Aegis always querying the graph for every
finding with a fixed template string. This is what `run_tool_agent` and
`results_for` (agent_loop.py) were originally built for; see
PROJECT_DOCUMENTATION.md §5.16 for why they went unused through Phase 3
and were wired in here afterward. Fast Mode (no client) falls back to a
deterministic lookup for every finding, guaranteeing full coverage without
an LLM in the loop.

Phase 4 (cross-run memory, PROJECT_DOCUMENTATION.md §5.15): each item is
checked against investigation_history (keyed by source IP + pattern type)
for prior occurrences across past runs, which can likewise escalate
severity for a recurring pattern. The check here is read-only — Respond
records this run's findings into history exactly once, after Reflect's
loop concludes, so retries within one run don't inflate the count.
"""

from __future__ import annotations

import json

from google.genai import types

from ..agent_loop import results_for, run_tool_agent, simple_generate
from ..anonymize import Anonymizer
from ..config import get_client, get_model_name, get_temperature
from ..memory import check_history
from ..state import AgentState
from ..tools.classification import context_enricher_tool, risk_assessor_tool
from ..tools.graphrag import cve_graph_retrieval_tool

_SYSTEM_PROMPT = (
    "You are a security threat classification specialist. You are given a list "
    "of findings, each already assigned a severity (High/Medium/Low) by "
    "deterministic risk-assessment rules. Write one short paragraph (2-3 "
    "sentences) explaining the overall risk picture and why the highest-severity "
    "findings deserve that severity. Do not change or contradict the assigned "
    "severities. User/IP identifiers are hashed tokens."
)

_CVE_LOOKUP_SYSTEM_PROMPT = (
    "You are a security threat classification specialist. You are given a "
    "numbered list of security findings. For each finding that plausibly maps "
    "to a known real-world vulnerability class (e.g. brute force, privilege "
    "escalation, credential exposure), call the cve_lookup tool with that "
    "finding's index and a short, specific search query describing the "
    "underlying vulnerability pattern. Skip findings that are too generic or "
    "unlikely to have a specific real CVE analog (e.g. a plain foreign login "
    "with no other signal). You do not need to call the tool for every "
    "finding — use judgment. User/IP identifiers are hashed tokens."
)

_CVE_LOOKUP_TOOL = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name="cve_lookup",
            description="Retrieve related CVE, CWE, and MITRE ATT&CK context for one finding.",
            parameters_json_schema={
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "The finding's index in the provided list."},
                    "query": {
                        "type": "string",
                        "description": "A short, specific description of the vulnerability pattern to search for.",
                    },
                },
                "required": ["index", "query"],
            },
        )
    ]
)


def _llm_driven_graph_lookup(client, model: str, temperature: float, items: list[dict]) -> dict[int, dict]:
    """Lets Gemini decide, per finding, whether and how to query GraphRAG.

    Returns {index: graph_context} only for indices Gemini actually chose to
    look up — everything else is left out (risk_assessor_tool treats a
    missing/None graph_context as "no escalation," same as before).
    """
    numbered = [
        {"index": i, "pattern": item.get("pattern") or item.get("anomaly"), "description": item["description"]}
        for i, item in enumerate(items)
    ]
    user_message = json.dumps(numbered)

    def _cve_lookup(index: int, query: str) -> dict:
        return cve_graph_retrieval_tool(query)

    _, calls_made = run_tool_agent(
        client,
        model,
        _CVE_LOOKUP_SYSTEM_PROMPT,
        user_message,
        [_CVE_LOOKUP_TOOL],
        {"cve_lookup": _cve_lookup},
        temperature,
    )

    graph_contexts: dict[int, dict] = {}
    for call in calls_made:
        if call["name"] != "cve_lookup":
            continue
        index = call["args"].get("index")
        if isinstance(index, int):
            graph_contexts[index] = call["result"]
    return graph_contexts


def classify_node(state: AgentState) -> AgentState:
    anomalies = state.get("anomalies", [])
    items = [{**item, **context_enricher_tool(item)} for item in anomalies]

    trail = list(state.get("reasoning_trail", []))
    client = get_client()
    model = get_model_name()
    temperature = get_temperature()

    if client and items:
        try:
            graph_contexts = _llm_driven_graph_lookup(client, model, temperature, items)
            trail.append(
                f"Classify: Gemini chose to look up CVE/ATT&CK context for "
                f"{len(graph_contexts)} of {len(items)} finding(s)."
            )
        except Exception as exc:  # noqa: BLE001
            graph_contexts = {}
            trail.append(f"Classify: LLM-driven GraphRAG lookup unavailable ({exc}); skipping graph escalation.")
    else:
        # Fast Mode / no client: deterministic full-coverage lookup, same as
        # the original Phase 3 behavior — every finding gets checked.
        graph_contexts = {}
        for i, item in enumerate(items):
            query_text = f"{item.get('pattern') or item.get('anomaly')}: {item['description']}"
            graph_contexts[i] = cve_graph_retrieval_tool(query_text)

    findings = []
    for i, item in enumerate(items):
        pattern_type = item.get("pattern") or item.get("anomaly")
        graph_context = graph_contexts.get(i)
        history_context = check_history(item.get("ip"), pattern_type)
        risk = risk_assessor_tool(item, item.get("threat_intel"), graph_context, history_context)
        findings.append({**item, **risk, "graph_context": graph_context, "history_context": history_context})

    if client and findings:
        anonymizer = Anonymizer()
        redacted = [
            {
                **{k: v for k, v in f.items() if k not in ("user", "ip")},
                "user": anonymizer.hash(f.get("user")),
                "ip": anonymizer.hash(f.get("ip")),
            }
            for f in findings
        ]
        try:
            response = simple_generate(client, model, _SYSTEM_PROMPT, json.dumps(redacted), temperature)
            trail.append(f"Classify: {response.text.strip()}")
        except Exception as exc:  # noqa: BLE001
            trail.append(f"Classify: assessed {len(findings)} findings (LLM rationale unavailable: {exc}).")
    else:
        severities = {f["severity"] for f in findings}
        trail.append(
            f"Classify: assessed {len(findings)} findings, severities present: {sorted(severities) or 'none'}."
            + (" [Fast Mode: rule-based only]" if not client else "")
        )

    return {**state, "findings": findings, "reasoning_trail": trail}
