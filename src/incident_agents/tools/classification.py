"""Classify-stage tools: risk assessment and context enrichment.

Designed fresh for Aegis — the reference tutorial's classify_node severity
logic was never fully visible in the source material (see
PROJECT_DOCUMENTATION.md §5.11).
"""

from __future__ import annotations

from typing import Any

_DESCRIPTIONS = {
    "brute_force": "Repeated failed login attempts against the same account from the same source.",
    "privilege_escalation": "A user invoked elevated (sudo) privileges.",
    "offhours_large_download": "An unusually large data transfer occurred outside normal business hours.",
    "foreign_login": "A successful login originated from an unexpected country.",
}

def risk_assessor_tool(item: dict[str, Any], threat_intel: dict[str, Any] | None = None) -> dict[str, Any]:
    """Tool: assign a severity (High/Medium/Low) to a detected pattern/anomaly.

    Note (found via live testing 2026-09-05, see PROJECT_DOCUMENTATION.md):
    privilege_escalation is NOT automatically High. A blanket "every sudo is
    High" rule was the original design, but Aegis's own Reflect agent
    correctly flagged that as unjustified for routine, zero-risk internal
    maintenance — exactly the alert-fatigue problem Aegis exists to prevent.
    Severity now requires actual risk signal (threat-intel score, or a
    pattern intrinsically tied to an external actor), not just event type.
    """
    kind = item.get("pattern") or item.get("anomaly")
    confidence = float(item.get("confidence", 0.5))
    risk_score = float((threat_intel or {}).get("risk_score", 0.0))
    reputation = (threat_intel or {}).get("reputation")

    if risk_score >= 8.0:
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

    return {"severity": severity, "risk_score": risk_score, "confidence": confidence}


def context_enricher_tool(item: dict[str, Any]) -> dict[str, Any]:
    """Tool: attach a human-readable description to a detected pattern/anomaly.

    In Phase 3 this is the attachment point for GraphRAG-retrieved
    CVE/CWE/ATT&CK context (see PROJECT_DOCUMENTATION.md §5.10).
    """
    kind = item.get("pattern") or item.get("anomaly")
    return {"description": _DESCRIPTIONS.get(kind, "Unclassified security event.")}


def classify_findings(
    anomalies: list[dict[str, Any]],
    threat_lookup: Any,
) -> list[dict[str, Any]]:
    """Runs risk assessment + context enrichment over every detected item."""
    findings = []
    for item in anomalies:
        ip = item.get("ip")
        intel = threat_lookup(ip) if ip else None
        risk = risk_assessor_tool(item, intel)
        context = context_enricher_tool(item)
        findings.append({**item, **risk, **context, "threat_intel": intel})
    return findings
