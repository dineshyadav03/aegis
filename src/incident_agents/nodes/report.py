"""Report node: generate the final Markdown incident report.

Calls Gemini directly (not a tool-calling loop) with a deterministic
fallback template when no client is available, an LLM error occurs, or
there are no findings — matching the reference tutorial's
_llm_report/_fallback_report split (PROJECT_DOCUMENTATION.md §5.6).
"""

from __future__ import annotations

import json
from collections import Counter

from ..agent_loop import simple_generate
from ..anonymize import Anonymizer
from ..config import get_client, get_model_name, get_temperature
from ..state import AgentState
from ..tools.alerting import send_slack_alert

_SYSTEM_PROMPT = (
    "You are a security analyst. Write a succinct Markdown incident report. "
    "Structure it as:\n"
    "## Summary\n(counts by severity)\n"
    "## Findings by Severity\n(group High/Medium/Low, one bullet per finding)\n"
    "## Actions Taken Automatically\n(list any auto-blocked IPs; write 'None' if empty)\n"
    "## Recommended Actions For You\nsplit into Immediate and Urgent\n\n"
    "Be precise and avoid fluff. User/IP identifiers are hashed tokens — refer "
    "to them as-is."
)


def _fallback_report(findings: list[dict], autonomous_actions: list[dict]) -> str:
    if not findings:
        return "# Security Incident Report\n\nNo suspicious activity detected."

    counts = Counter(f.get("severity", "Low") for f in findings)
    lines = [
        "# Security Incident Report",
        "",
        "## Summary",
        f"- High: {counts.get('High', 0)}",
        f"- Medium: {counts.get('Medium', 0)}",
        f"- Low: {counts.get('Low', 0)}",
        "",
        "## Findings by Severity",
    ]
    for severity in ("High", "Medium", "Low"):
        items = [f for f in findings if f.get("severity") == severity]
        if not items:
            continue
        lines.append(f"### {severity}")
        for f in items:
            kind = f.get("pattern") or f.get("anomaly")
            lines.append(f"- **{kind}** — user: {f.get('user')}, ip: {f.get('ip')}")

    lines += ["", "## Actions Taken Automatically"]
    if autonomous_actions:
        for a in autonomous_actions:
            lines.append(f"- Blocked IP {a['ip']} (reason: {a['reason']})")
    else:
        lines.append("None")

    lines += [
        "",
        "## Recommended Actions For You",
        "### 🚨 Immediate",
        "- Reset compromised account passwords",
        "- Isolate affected systems",
        "- Initiate incident response procedures",
        "### ⚠️ Urgent",
        "- Review and update access controls",
        "- Enable MFA on affected accounts",
    ]
    return "\n".join(lines)


def report_node(state: AgentState) -> AgentState:
    findings = state.get("findings", [])
    autonomous_actions = state.get("autonomous_actions_taken", [])
    trail = list(state.get("reasoning_trail", []))

    if not findings:
        report = "# Security Incident Report\n\nNo suspicious activity detected."
        trail.append("Report: no findings, skipped generation.")
        return {**state, "report": report, "reasoning_trail": trail}

    client = get_client()
    report = None
    if client:
        anonymizer = Anonymizer()
        redacted = [
            {
                **{k: v for k, v in f.items() if k not in ("user", "ip")},
                "user": anonymizer.hash(f.get("user")),
                "ip": anonymizer.hash(f.get("ip")),
            }
            for f in findings
        ]
        redacted_actions = [{**a, "ip": anonymizer.hash(a["ip"])} for a in autonomous_actions]
        payload = json.dumps({"findings": redacted, "autonomous_actions": redacted_actions})
        try:
            response = simple_generate(client, get_model_name(), _SYSTEM_PROMPT, payload, get_temperature())
            report = response.text.strip()
            trail.append("Report: generated via Gemini.")
        except Exception as exc:  # noqa: BLE001
            trail.append(f"Report: Gemini generation failed ({exc}); using fallback template.")

    if not report:
        report = _fallback_report(findings, autonomous_actions)
        if client is None:
            trail.append("Report: generated via fallback template [Fast Mode: no API key].")

    slack_notified = False
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    if high_count > 0:
        summary = (
            f"🛡️ Aegis: {high_count} High-severity finding(s) detected "
            f"({len(autonomous_actions)} IP(s) auto-blocked). Full report generated — see Aegis output."
        )
        slack_notified = send_slack_alert(summary)
        trail.append(f"Report: Slack alert {'sent' if slack_notified else 'not sent (no webhook configured or post failed)'}.")

    return {**state, "report": report, "slack_notified": slack_notified, "reasoning_trail": trail}
