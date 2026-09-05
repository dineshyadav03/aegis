"""Ingest node: parse and validate the raw security log file.

Deterministic only — there's nothing for an LLM to judge here, just parsing
and a data-quality score.
"""

from __future__ import annotations

from ..anonymize import Anonymizer
from ..state import AgentState
from ..tools.parsers import data_validator_tool, parse_log_file

anonymizer = Anonymizer()


def ingest_node(state: AgentState) -> AgentState:
    log_path = state["log_path"]
    events = parse_log_file(log_path)
    validation = data_validator_tool(events)

    trail = list(state.get("reasoning_trail", []))
    trail.append(
        f"Ingest: parsed {len(events)} events from {log_path} "
        f"(data quality score: {validation['quality_score']})."
    )

    return {
        **state,
        "events": events,
        "data_quality_score": validation["quality_score"],
        "reasoning_trail": trail,
    }
