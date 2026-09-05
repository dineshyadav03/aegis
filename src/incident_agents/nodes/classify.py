"""Classify node: risk-assess and enrich every detected item into a finding.

Severity assignment is deterministic (tools/classification.py) for
consistency; Gemini adds a short rationale narrative per run, used in the
reasoning trail — it does not get to override severity in Phase 1.

Phase 3 (GraphRAG, PROJECT_DOCUMENTATION.md §5.10): each item's retrieved
CVE/CWE/ATT&CK context can escalate severity by one level when a similar,
high-CVSS real-world CVE is found — see tools/classification.py's
risk_assessor_tool. Gracefully skipped (no escalation) if Neo4j/Voyage AI
aren't configured.

Phase 4 (cross-run memory, PROJECT_DOCUMENTATION.md §5.15): each item is
checked against investigation_history (keyed by source IP + pattern type)
for prior occurrences across past runs, which can likewise escalate
severity for a recurring pattern. The check here is read-only — Respond
records this run's findings into history exactly once, after Reflect's
loop concludes, so retries within one run don't inflate the count.
"""

from __future__ import annotations

import json

from ..agent_loop import simple_generate
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


def classify_node(state: AgentState) -> AgentState:
    anomalies = state.get("anomalies", [])

    findings = []
    for item in anomalies:
        context = context_enricher_tool(item)
        pattern_type = item.get("pattern") or item.get("anomaly")
        query_text = f"{pattern_type}: {context['description']}"
        graph_context = cve_graph_retrieval_tool(query_text)
        history_context = check_history(item.get("ip"), pattern_type)
        risk = risk_assessor_tool(item, item.get("threat_intel"), graph_context, history_context)
        findings.append(
            {**item, **risk, **context, "graph_context": graph_context, "history_context": history_context}
        )

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
                client, get_model_name(), _SYSTEM_PROMPT, json.dumps(redacted), get_temperature()
            )
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
