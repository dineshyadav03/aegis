"""Environment/config accessors for Aegis."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from google import genai

load_dotenv()

# Anchor default data paths to the project root, not the process's current
# working directory — a real bug found while testing the Gradio app: it can
# be launched from a different CWD than the CLI, and a bare relative path
# ("data/checkpoints.sqlite") silently resolved to the wrong location and
# failed with "unable to open database file". Absolute paths fix this for
# every caller, CLI or Gradio, regardless of launch directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# We use manual (non-automatic) function calling throughout — see agent_loop.py
# — so the SDK's "use Chat.send_message instead" nudge doesn't apply here.
logging.getLogger("google_genai.models").setLevel(logging.ERROR)

# Phase 4: restrict checkpoint deserialization to known-safe types (recommended
# by langgraph-checkpoint-sqlite's own docs) — defense in depth in case the
# local checkpoint DB is ever tampered with, even though it's not exposed to
# any external service.
os.environ.setdefault("LANGGRAPH_STRICT_MSGPACK", "true")

DEFAULT_MODEL = "gemini-3.6-flash"  # confirmed working end-to-end during Phase 1 — see PROJECT_DOCUMENTATION.md §5.12


def get_gemini_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY")


def get_abuseipdb_key() -> str | None:
    return os.environ.get("ABUSEIPDB_API_KEY")


def get_slack_webhook_url() -> str | None:
    return os.environ.get("SLACK_WEBHOOK_URL")


def get_model_name() -> str:
    return os.environ.get("AEGIS_MODEL", DEFAULT_MODEL)


def get_temperature() -> float:
    return float(os.environ.get("AEGIS_TEMPERATURE", "0.0"))


def get_client() -> genai.Client | None:
    """Returns a configured Gemini client, or None if no API key is set.

    Nodes fall back to deterministic rule-based logic when this returns None,
    matching the reference tutorial's "Fast Mode" behavior.
    """
    key = get_gemini_key()
    if not key:
        return None
    return genai.Client(api_key=key)


def get_voyage_key() -> str | None:
    return os.environ.get("VOYAGE_API_KEY")


def get_neo4j_config() -> tuple[str, str, str] | None:
    """Returns (uri, username, password), or None if any piece is missing."""
    uri = os.environ.get("NEO4J_URI")
    username = os.environ.get("NEO4J_USERNAME")
    password = os.environ.get("NEO4J_PASSWORD")
    if not (uri and username and password):
        return None
    return uri, username, password


def get_neo4j_driver():
    """Returns a connected neo4j Driver, or None if not configured.

    GraphRAG retrieval falls back to skipping CVE/CWE/ATT&CK enrichment
    (Classify proceeds on rule-based severity alone) when this returns None —
    same graceful-degradation pattern as every other external service here.
    """
    from neo4j import GraphDatabase

    config = get_neo4j_config()
    if not config:
        return None
    uri, username, password = config
    return GraphDatabase.driver(uri, auth=(username, password))


@dataclass(frozen=True)
class Thresholds:
    brute_force_min_attempts: int = 5
    off_hours_cutoff_hour: int = 5
    off_hours_min_bytes: int = 1_000_000
    # risk_score is on AbuseIPDB's native 0-100 abuseConfidenceScore scale
    # (Phase 1's mock used an invented 0-10 scale; Phase 2 adopts the real
    # API's scale directly rather than converting, see PROJECT_DOCUMENTATION.md).
    high_risk_score: float = 80.0
    suspicious_risk_score: float = 25.0
    auto_block_min_risk_score: float = 80.0
    max_reflection_retries: int = 2


def get_thresholds() -> Thresholds:
    return Thresholds(
        brute_force_min_attempts=int(os.environ.get("AEGIS_BRUTE_FORCE_MIN_ATTEMPTS", "5")),
        off_hours_cutoff_hour=int(os.environ.get("AEGIS_OFF_HOURS_CUTOFF_HOUR", "5")),
        off_hours_min_bytes=int(os.environ.get("AEGIS_OFF_HOURS_MIN_BYTES", "1000000")),
        high_risk_score=float(os.environ.get("AEGIS_HIGH_RISK_SCORE", "80.0")),
        suspicious_risk_score=float(os.environ.get("AEGIS_SUSPICIOUS_RISK_SCORE", "25.0")),
        auto_block_min_risk_score=float(os.environ.get("AEGIS_AUTO_BLOCK_MIN_RISK_SCORE", "80.0")),
        max_reflection_retries=int(os.environ.get("AEGIS_MAX_REFLECTION_RETRIES", "2")),
    )


def get_data_path() -> str:
    return os.environ.get("AEGIS_DATA_PATH", str(PROJECT_ROOT / "data" / "security_logs.csv"))


def get_checkpoint_db_path() -> str:
    path = os.environ.get("AEGIS_CHECKPOINT_DB_PATH", str(PROJECT_ROOT / "data" / "checkpoints.sqlite"))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def get_history_db_path() -> str:
    return os.environ.get("AEGIS_HISTORY_DB_PATH", str(PROJECT_ROOT / "data" / "investigation_history.sqlite"))


def get_blocklist_path() -> str:
    return os.environ.get("AEGIS_BLOCKLIST_PATH", str(PROJECT_ROOT / "blocklist.json"))


RECURRING_MIN_TIMES_FLAGGED = 3
