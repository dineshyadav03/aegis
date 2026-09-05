"""Detect node: rule-based pattern/anomaly detection + threat-intel lookup,
with an optional Gemini narrative summary for the reasoning trail.

Detection itself is always deterministic (Python tools) for reliability;
Gemini is used only to narrate what was found, never to decide it.
"""

from __future__ import annotations

import json

from ..agent_loop import simple_generate
from ..anonymize import Anonymizer
from ..config import get_client, get_model_name, get_temperature, get_thresholds
from ..state import AgentState
from ..tools.detection import anomaly_detector_tool, pattern_detector_tool
from ..tools.threat_intel import threat_lookup_tool

_SYSTEM_PROMPT = (
    "You are a security threat detection specialist. You are given a list of "
    "already-detected patterns and anomalies (from deterministic rules) plus "
    "threat-intelligence lookups. Write a single short paragraph (2-3 sentences) "
    "summarizing what was found and why it matters. Do not invent findings not "
    "present in the data. User/IP identifiers are hashed tokens — refer to them "
    "as-is, do not attempt to guess real values."
)


def detect_node(state: AgentState) -> AgentState:
    events = state.get("events", [])
    thresholds = get_thresholds()

    patterns = pattern_detector_tool(events, thresholds)
    anomalies = anomaly_detector_tool(events, thresholds)
    combined = patterns + anomalies

    for item in combined:
        ip = item.get("ip")
        item["threat_intel"] = threat_lookup_tool(ip) if ip else None

    trail = list(state.get("reasoning_trail", []))
    client = get_client()
    if client and combined:
        anonymizer = Anonymizer()
        redacted = [
            {
                **{k: v for k, v in item.items() if k not in ("user", "ip")},
                "user": anonymizer.hash(item.get("user")),
                "ip": anonymizer.hash(item.get("ip")),
            }
            for item in combined
        ]
        try:
            response = simple_generate(
                client, get_model_name(), _SYSTEM_PROMPT, json.dumps(redacted), get_temperature()
            )
            trail.append(f"Detect: {response.text.strip()}")
        except Exception as exc:  # noqa: BLE001
            trail.append(f"Detect: found {len(combined)} anomalies (LLM narrative unavailable: {exc}).")
    else:
        trail.append(
            f"Detect: found {len(combined)} anomalies "
            f"({len(patterns)} pattern-based, {len(anomalies)} statistical)."
            + (" [Fast Mode: rule-based only]" if not client else "")
        )

    return {**state, "anomalies": combined, "reasoning_trail": trail}
