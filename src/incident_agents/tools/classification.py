"""Classify-stage tools: risk assessment and context enrichment.

Designed fresh for Aegis — the reference tutorial's classify_node severity
logic was never fully visible in the source material (see
PROJECT_DOCUMENTATION.md §5.11).
"""

from __future__ import annotations

from typing import Any

from ..config import RECURRING_MIN_TIMES_FLAGGED, get_thresholds

_DESCRIPTIONS = {
    "brute_force": "Repeated failed login attempts against the same account from the same source.",
    "privilege_escalation": "A user invoked elevated (sudo) privileges.",
    "offhours_large_download": "An unusually large data transfer occurred outside normal business hours.",
    "foreign_login": "A successful login originated from an unexpected country.",
}

GRAPH_ESCALATION_MIN_CVSS = 7.0
GRAPH_ESCALATION_MIN_SIMILARITY = 0.5


def risk_assessor_tool(
    item: dict[str, Any],
    threat_intel: dict[str, Any] | None = None,
    graph_context: dict[str, Any] | None = None,
    history_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Tool: assign a severity (High/Medium/Low) to a detected pattern/anomaly.

    Note (found via live testing 2026-09-05, see PROJECT_DOCUMENTATION.md):
    privilege_escalation is NOT automatically High. A blanket "every sudo is
    High" rule was the original design, but Aegis's own Reflect agent
    correctly flagged that as unjustified for routine, zero-risk internal
    maintenance — exactly the alert-fatigue problem Aegis exists to prevent.
    Severity now requires actual risk signal (threat-intel score, or a
    pattern intrinsically tied to an external actor), not just event type.

    graph_context (Phase 3, GraphRAG — PROJECT_DOCUMENTATION.md §5.10) can
    escalate severity by one level (never downgrade) when a similar, high-
    CVSS real-world CVE is retrieved — this is the mechanism that makes
    GraphRAG actually change decisions rather than just decorate the report.
    Thresholds (CVSS >= 7.0, similarity >= 0.5) are a starting point pending
    live tuning once Neo4j/Voyage AI credentials are available.

    history_context (Phase 4, cross-run memory — PROJECT_DOCUMENTATION.md
    §5.15) can likewise escalate by one level when the same identity has
    triggered this same pattern_type at least RECURRING_MIN_TIMES_FLAGGED
    times before — a one-off Low-confidence anomaly is noise; the same
    anomaly recurring repeatedly from the same source is a pattern.
    """
    kind = item.get("pattern") or item.get("anomaly")
    confidence = float(item.get("confidence", 0.5))
    risk_score = float((threat_intel or {}).get("risk_score", 0.0))
    reputation = (threat_intel or {}).get("reputation")
    thresholds = get_thresholds()

    if risk_score >= thresholds.high_risk_score:
        severity = "High"
    elif kind == "brute_force" and item.get("count", 0) >= 10:
        severity = "High"
    elif kind == "privilege_escalation" and reputation == "malicious":
        severity = "High"
    elif kind == "privilege_escalation":
        # Elevated privilege use always deserves a look, but only "High"
        # when there's corroborating risk — otherwise it's routine.
        severity = "Medium"
    elif confidence >= 0.7:
        severity = "Medium"
    else:
        severity = "Low"

    if graph_context and graph_context.get("available") and graph_context.get("matches"):
        best_match = max(graph_context["matches"], key=lambda m: m.get("similarity_score") or 0)
        cvss = best_match.get("cvss_score") or 0
        similarity = best_match.get("similarity_score") or 0
        if cvss >= GRAPH_ESCALATION_MIN_CVSS and similarity >= GRAPH_ESCALATION_MIN_SIMILARITY:
            if severity == "Low":
                severity = "Medium"
            elif severity == "Medium":
                severity = "High"

    if history_context and history_context.get("times_flagged", 0) >= RECURRING_MIN_TIMES_FLAGGED:
        if severity == "Low":
            severity = "Medium"
        elif severity == "Medium":
            severity = "High"

    return {"severity": severity, "risk_score": risk_score, "confidence": confidence}


def context_enricher_tool(item: dict[str, Any]) -> dict[str, Any]:
    """Tool: attach a human-readable description to a detected pattern/anomaly.

    In Phase 3 this is the attachment point for GraphRAG-retrieved
    CVE/CWE/ATT&CK context (see PROJECT_DOCUMENTATION.md §5.10).
    """
    kind = item.get("pattern") or item.get("anomaly")
    return {"description": _DESCRIPTIONS.get(kind, "Unclassified security event.")}
