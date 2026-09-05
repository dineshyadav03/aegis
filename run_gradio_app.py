"""Aegis web interface — see PROJECT_DOCUMENTATION.md §5.8."""

from __future__ import annotations

import os
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import gradio as gr

from incident_agents.graph import build_graph

_MODEL_CHOICES = ["gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.8-flash", "gemini-3.1-pro-preview"]

CUSTOM_CSS = """
.main-header {
    text-align: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 20px;
}
.status-box {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 8px;
    padding: 15px;
    margin: 10px 0;
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


def analyze(file, show_reasoning, model, temperature, fast_mode):
    if file is None:
        return "*Upload a CSV or JSON security log file first.*", "", "❌ No file uploaded."

    with _model_override(model, temperature, fast_mode):
        app = build_graph()
        config = {"configurable": {"thread_id": str(uuid.uuid4())}}
        result = app.invoke({"log_path": file.name}, config=config)

    report = result.get("report") or "# Security Incident Report\n\nNo suspicious activity detected."

    reasoning_md = ""
    if show_reasoning:
        lines = result.get("reasoning_trail", [])
        reasoning_md = "### 🤖 Agent Reasoning Process\n" + "\n".join(f"- {line}" for line in lines)
        actions = result.get("autonomous_actions_taken", [])
        reasoning_md += f"\n\n### ⚡ Autonomous Actions Taken\n{len(actions)} action(s)"
        for a in actions:
            reasoning_md += f"\n- Blocked `{a['ip']}` ({a['reason']})"

    findings = result.get("findings", [])
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.get("severity", "Low")] = counts.get(f.get("severity", "Low"), 0) + 1
    status = (
        f"✅ Analysis complete — {len(result.get('events', []))} events processed, "
        f"{len(findings)} findings (High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']})"
    )

    return report, reasoning_md, status


with gr.Blocks(title="🛡️ Aegis") as demo:
    gr.HTML(
        """
        <div class="main-header">
            <h1>🛡️ Aegis</h1>
            <p>Automated cybersecurity threat detection using AI agents</p>
        </div>
        """
    )

    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### 📁 Upload Security Logs")
            file_input = gr.File(label="Upload CSV or JSON file", file_types=[".csv", ".json"])
            gr.Markdown("*Or run `scripts/generate_sample_logs.py` for sample data.*")

            gr.Markdown("### ⚙️ Configuration")
            show_reasoning = gr.Checkbox(label="Show Agent Reasoning Process", value=True)
            model_dropdown = gr.Dropdown(
                choices=_MODEL_CHOICES, value=_MODEL_CHOICES[0], label="AI Model"
            )
            temperature = gr.Slider(0, 1, value=0.0, step=0.1, label="Temperature")
            fast_mode = gr.Checkbox(label="Fast Mode (Skip AI Processing)", value=False)

            analyze_btn = gr.Button("🔍 Analyze Security Logs", variant="primary")

            gr.Markdown("### 📊 Status")
            status_box = gr.Markdown("Upload a file and click Analyze to begin.")

        with gr.Column(scale=2):
            gr.Markdown("### 📋 Analysis Results")
            report_output = gr.Markdown()
            reasoning_output = gr.Markdown()

    analyze_btn.click(
        fn=analyze,
        inputs=[file_input, show_reasoning, model_dropdown, temperature, fast_mode],
        outputs=[report_output, reasoning_output, status_box],
    )

if __name__ == "__main__":
    demo.launch(css=CUSTOM_CSS)
