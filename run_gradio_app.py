"""Aegis web interface — see PROJECT_DOCUMENTATION.md §5.8."""

from __future__ import annotations

import html
import os
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import gradio as gr

from incident_agents.graph import build_graph

_MODEL_CHOICES = ["gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.8-flash", "gemini-3.1-pro-preview"]

_SEVERITY_STYLE = {
    "High": ("#dc2626", "#fff"),
    "Medium": ("#d97706", "#fff"),
    "Low": ("#64748b", "#fff"),
}

THEME = gr.themes.Soft(
    primary_hue=gr.themes.colors.blue,
    secondary_hue=gr.themes.colors.slate,
    neutral_hue=gr.themes.colors.slate,
    font=(gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui", "sans-serif"),
)

CUSTOM_CSS = """
.aegis-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 20px 24px;
    border-radius: 12px;
    background: #0f172a;
    margin-bottom: 18px;
}
.aegis-header .icon {
    font-size: 28px;
    line-height: 1;
}
.aegis-header h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 700;
    color: #f8fafc;
}
.aegis-header p {
    margin: 2px 0 0;
    font-size: 13px;
    color: #94a3b8;
}

.stat-row { display: flex; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; }
.stat-card {
    flex: 1;
    min-width: 110px;
    background: var(--block-background-fill);
    border: 1px solid var(--border-color-primary);
    border-radius: 10px;
    padding: 14px 16px;
    border-top: 3px solid var(--stat-accent, #64748b);
}
.stat-card .value { font-size: 26px; font-weight: 700; color: var(--body-text-color); line-height: 1; }
.stat-card .label { font-size: 12px; color: var(--body-text-color-subdued); margin-top: 4px; text-transform: uppercase; letter-spacing: .04em; }

.finding-card {
    background: var(--block-background-fill);
    border: 1px solid var(--border-color-primary);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
.finding-card .top-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap; }
.severity-badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .03em;
    padding: 3px 9px;
    border-radius: 999px;
}
.finding-card .kind { font-weight: 600; color: var(--body-text-color); }
.finding-card .identity { font-family: var(--font-mono); font-size: 12px; color: var(--body-text-color-subdued); }
.finding-card .sub-line { font-size: 12.5px; color: var(--body-text-color-subdued); margin-top: 3px; }
.finding-card .sub-line b { color: var(--body-text-color); font-weight: 600; }
.attack-chip {
    display: inline-block;
    font-size: 11px;
    font-family: var(--font-mono);
    background: var(--background-fill-secondary);
    border: 1px solid var(--border-color-primary);
    border-radius: 5px;
    padding: 1px 6px;
    margin-left: 4px;
}
.empty-state { color: var(--body-text-color-subdued); font-size: 13px; padding: 8px 2px; }

.action-card {
    background: var(--block-background-fill);
    border: 1px solid var(--border-color-primary);
    border-left: 3px solid #16a34a;
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 8px;
    font-size: 13px;
}
"""


@contextmanager
def _model_override(model: str, temperature: float, fast_mode: bool):
    old_model = os.environ.get("AEGIS_MODEL")
    old_temp = os.environ.get("AEGIS_TEMPERATURE")
    old_key = os.environ.get("GEMINI_API_KEY")
    os.environ["AEGIS_MODEL"] = model
    os.environ["AEGIS_TEMPERATURE"] = str(temperature)
    if fast_mode:
        os.environ.pop("GEMINI_API_KEY", None)
    try:
        yield
    finally:
        if old_model is not None:
            os.environ["AEGIS_MODEL"] = old_model
        if old_temp is not None:
            os.environ["AEGIS_TEMPERATURE"] = old_temp
        if old_key is not None:
            os.environ["GEMINI_API_KEY"] = old_key


def _stat_card(value: int | str, label: str, accent: str) -> str:
    return (
        f'<div class="stat-card" style="--stat-accent:{accent}">'
        f'<div class="value">{value}</div><div class="label">{html.escape(label)}</div></div>'
    )


def _render_stats(result: dict) -> str:
    findings = result.get("findings", [])
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.get("severity", "Low")] = counts.get(f.get("severity", "Low"), 0) + 1
    cards = [
        _stat_card(len(result.get("events", [])), "Events Processed", "#3b82f6"),
        _stat_card(counts["High"], "High Severity", _SEVERITY_STYLE["High"][0]),
        _stat_card(counts["Medium"], "Medium Severity", _SEVERITY_STYLE["Medium"][0]),
        _stat_card(counts["Low"], "Low Severity", _SEVERITY_STYLE["Low"][0]),
        _stat_card(len(result.get("autonomous_actions_taken", [])), "Auto-Blocked", "#16a34a"),
    ]
    return f'<div class="stat-row">{"".join(cards)}</div>'


def _render_findings(findings: list[dict]) -> str:
    if not findings:
        return '<div class="empty-state">No suspicious activity detected.</div>'

    order = {"High": 0, "Medium": 1, "Low": 2}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity", "Low"), 3))

    cards = []
    for f in findings:
        severity = f.get("severity", "Low")
        bg, fg = _SEVERITY_STYLE.get(severity, _SEVERITY_STYLE["Low"])
        kind = html.escape(str(f.get("pattern") or f.get("anomaly") or "unknown"))
        user = html.escape(str(f.get("user") or "—"))
        ip = html.escape(str(f.get("ip") or "—"))

        sub_lines = []
        graph_context = f.get("graph_context") or {}
        for match in graph_context.get("matches", [])[:1]:
            chips = "".join(
                f'<span class="attack-chip">ATT&amp;CK {html.escape(a["attack_id"])}</span>'
                for a in match.get("attack_context", [])[:2]
                if a.get("attack_id")
            )
            sub_lines.append(
                f'<div class="sub-line">Related: <b>{html.escape(match["cve_id"])}</b> '
                f'(CVSS {match.get("cvss_score", "?")}) {chips}</div>'
            )
        history = f.get("history_context")
        if history:
            sub_lines.append(
                f'<div class="sub-line">Previously seen: <b>{history["times_flagged"]}x</b> before '
                f'(first seen {html.escape(str(history["first_seen"])[:10])})</div>'
            )

        cards.append(
            '<div class="finding-card">'
            '<div class="top-row">'
            f'<span class="severity-badge" style="background:{bg};color:{fg}">{severity}</span>'
            f'<span class="kind">{kind}</span>'
            f'<span class="identity">user: {user} · ip: {ip}</span>'
            "</div>"
            + "".join(sub_lines)
            + "</div>"
        )
    return "".join(cards)


def _render_actions(actions: list[dict]) -> str:
    if not actions:
        return '<div class="empty-state">No autonomous actions taken this run.</div>'
    return "".join(
        f'<div class="action-card">Blocked <b>{html.escape(a["ip"])}</b> '
        f'&mdash; reason: {html.escape(str(a["reason"]))}</div>'
        for a in actions
    )


def analyze(file, show_reasoning, model, temperature, fast_mode):
    if file is None:
        empty = '<div class="empty-state">Upload a CSV or JSON security log file, then click Analyze.</div>'
        return empty, empty, "", "", gr.update(visible=False)

    with _model_override(model, temperature, fast_mode):
        app = build_graph()
        config = {"configurable": {"thread_id": str(uuid.uuid4())}}
        result = app.invoke({"log_path": file.name}, config=config)

    stats_html = _render_stats(result)
    findings_html = _render_findings(result.get("findings", []))
    actions_html = _render_actions(result.get("autonomous_actions_taken", []))
    report = result.get("report") or "# Security Incident Report\n\nNo suspicious activity detected."

    reasoning_md = ""
    if show_reasoning:
        lines = result.get("reasoning_trail", [])
        reasoning_md = "\n".join(f"- {line}" for line in lines) or "*No reasoning trail recorded.*"

    return stats_html, findings_html, actions_html, report, gr.update(value=reasoning_md, visible=bool(reasoning_md))


with gr.Blocks(title="Aegis") as demo:
    gr.HTML(
        '<div class="aegis-header">'
        '<div class="icon">🛡️</div>'
        "<div><h1>Aegis</h1><p>Automated cybersecurity threat detection using AI agents</p></div>"
        "</div>"
    )

    with gr.Row():
        with gr.Column(scale=1, min_width=280):
            with gr.Group():
                gr.Markdown("**Security Logs**")
                file_input = gr.File(label="Upload CSV or JSON", file_types=[".csv", ".json"])
                gr.Markdown(
                    "_No file handy? Run `scripts/generate_sample_logs.py` for sample data._",
                    elem_classes=["empty-state"],
                )

            with gr.Group():
                gr.Markdown("**Configuration**")
                model_dropdown = gr.Dropdown(choices=_MODEL_CHOICES, value=_MODEL_CHOICES[0], label="Model")
                temperature = gr.Slider(0, 1, value=0.0, step=0.1, label="Temperature")
                show_reasoning = gr.Checkbox(label="Show agent reasoning trail", value=True)
                fast_mode = gr.Checkbox(label="Fast mode (rule-based only, skip LLM calls)", value=False)

            analyze_btn = gr.Button("Analyze Security Logs", variant="primary", size="lg")

        with gr.Column(scale=2):
            stats_output = gr.HTML()

            with gr.Tabs():
                with gr.Tab("Findings"):
                    findings_output = gr.HTML()
                    gr.Markdown("**Actions Taken Automatically**")
                    actions_output = gr.HTML()
                with gr.Tab("Full Report"):
                    report_output = gr.Markdown()

            with gr.Accordion("Agent Reasoning Process", open=False):
                reasoning_output = gr.Markdown(visible=False)

    analyze_btn.click(
        fn=analyze,
        inputs=[file_input, show_reasoning, model_dropdown, temperature, fast_mode],
        outputs=[stats_output, findings_output, actions_output, report_output, reasoning_output],
    )

if __name__ == "__main__":
    demo.launch(css=CUSTOM_CSS, theme=THEME)
