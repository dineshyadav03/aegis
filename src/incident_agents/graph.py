"""StateGraph wiring for the Aegis pipeline — see PROJECT_DOCUMENTATION.md §5.7."""

from __future__ import annotations

import sqlite3

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from .config import get_checkpoint_db_path, get_thresholds
from .nodes.classify import classify_node
from .nodes.detect import detect_node
from .nodes.ingest import ingest_node
from .nodes.reflect import reflect_node
from .nodes.report import report_node
from .nodes.respond import respond_node
from .state import AgentState


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("ingest", ingest_node)
    graph.add_node("detect", detect_node)
    graph.add_node("classify", classify_node)
    graph.add_node("reflect", reflect_node)
    graph.add_node("respond", respond_node)
    graph.add_node("report", report_node)

    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "detect")

    def has_anomalies(state: AgentState) -> str:
        return "classify" if state.get("anomalies") else END

    graph.add_conditional_edges("detect", has_anomalies, {"classify": "classify", END: END})

    graph.add_edge("classify", "reflect")

    def reflection_verdict(state: AgentState) -> str:
        thresholds = get_thresholds()
        if state.get("reflection_retry_count", 0) > thresholds.max_reflection_retries:
            return "respond"
        return "classify" if state.get("needs_reanalysis") else "respond"

    graph.add_conditional_edges("reflect", reflection_verdict, {"classify": "classify", "respond": "respond"})

    def needs_report(state: AgentState) -> str:
        levels = {f.get("severity", "Low") for f in state.get("findings", [])}
        return "report" if any(s in ("High", "Medium") for s in levels) else END

    graph.add_conditional_edges("respond", needs_report, {"report": "report", END: END})

    graph.add_edge("report", END)

    # Persistent (Phase 4) — was InMemorySaver in Phases 1-3. check_same_thread=False
    # because Gradio's analyze() may run on a different thread than the connection
    # was opened on; each build_graph() call still gets its own connection.
    conn = sqlite3.connect(get_checkpoint_db_path(), check_same_thread=False)
    checkpointer = SqliteSaver(conn)
    return graph.compile(checkpointer=checkpointer)
