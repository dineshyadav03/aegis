"""Shared state passed between every node in the Aegis pipeline."""

from typing import Any, TypedDict


class AgentState(TypedDict, total=False):
    # Ingest
    log_path: str
    events: list[dict[str, Any]]
    data_quality_score: float

    # Detect
    anomalies: list[dict[str, Any]]

    # Classify
    findings: list[dict[str, Any]]

    # Reflect
    needs_reanalysis: bool
    reflection_retry_count: int
    reflection_notes: list[str]

    # Respond
    autonomous_actions_taken: list[dict[str, Any]]

    # Report
    report: str
    slack_notified: bool

    # Cross-cutting
    reasoning_trail: list[str]
    confidence_scores: dict[str, float]
