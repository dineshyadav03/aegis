"""Reflect node: review Classify's findings before anything acts on them.

This is the "Reasoning Agent (LangGraph with reflection)" from the original
concept slide — see PROJECT_DOCUMENTATION.md §5.4 and §7a. Combines a
deterministic consistency check (always runs) with an optional Gemini
critique (JSON verdict) when a client is available.
"""

from __future__ import annotations

import json

from ..agent_loop import simple_generate
from ..anonymize import Anonymizer
from ..config import get_client, get_model_name, get_temperature, get_thresholds
from ..state import AgentState

_SYSTEM_PROMPT = (
    "You are a security threat classification reviewer. You are given a list "
    "of findings with assigned severities. Check whether the severities are "
    "justified by the evidence (confidence scores, threat-intel risk scores, "
    "pattern/anomaly type). Respond with ONLY a JSON object of the exact shape "
    '{"approve": true|false, "notes": "short explanation"}. Set approve=false '
    "only if something looks genuinely unjustified (e.g. a High severity with "
    "very low confidence and no threat-intel support). User/IP identifiers are "
    "hashed tokens."
)


def _deterministic_check(findings: list[dict]) -> tuple[bool, list[str]]:
    """Returns (needs_reanalysis, notes)."""
    notes = []
    needs_reanalysis = False

    for f in findings:
        if f.get("severity") == "High" and float(f.get("confidence", 1.0)) < 0.5:
            notes.append(f"High severity with low confidence ({f.get('confidence')}) on {f.get('pattern') or f.get('anomaly')}.")
            needs_reanalysis = True

        risk_score = float((f.get("threat_intel") or {}).get("risk_score", 0.0))
        if risk_score >= 8.0 and f.get("severity") != "High":
            notes.append(f"Threat-intel risk score {risk_score} but severity only {f.get('severity')}.")
            needs_reanalysis = True

    return needs_reanalysis, notes


def reflect_node(state: AgentState) -> AgentState:
    findings = state.get("findings", [])
    retry_count = state.get("reflection_retry_count", 0)
    thresholds = get_thresholds()

    needs_reanalysis, notes = _deterministic_check(findings)

    trail = list(state.get("reasoning_trail", []))
    client = get_client()
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
            response = simple_generate(
                client,
                get_model_name(),
                _SYSTEM_PROMPT,
                json.dumps(redacted),
                get_temperature(),
                response_mime_type="application/json",
            )
            verdict = json.loads(response.text)
            if not verdict.get("approve", True):
                needs_reanalysis = True
                notes.append(f"Gemini reflection: {verdict.get('notes', 'no reason given')}")
            trail.append(f"Reflect: {'approved' if not needs_reanalysis else 'flagged for re-analysis'} — {verdict.get('notes', '')}")
        except Exception as exc:  # noqa: BLE001
            trail.append(f"Reflect: LLM critique unavailable ({exc}); using deterministic checks only.")
    else:
        trail.append(
            "Reflect: deterministic consistency check only"
            + (" [Fast Mode]" if not client else "")
            + (f" — {'; '.join(notes)}" if notes else " — no issues found.")
        )

    if needs_reanalysis and retry_count >= thresholds.max_reflection_retries:
        trail.append(
            f"Reflect: retry cap ({thresholds.max_reflection_retries}) reached — proceeding despite unresolved concerns."
        )
        needs_reanalysis = False
        notes.append("Unresolved: proceeded after exhausting reflection retries.")

    return {
        **state,
        "needs_reanalysis": needs_reanalysis,
        "reflection_retry_count": retry_count + (1 if needs_reanalysis else 0),
        "reflection_notes": notes,
        "reasoning_trail": trail,
    }
