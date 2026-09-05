"""Environment/config accessors for Aegis."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv
from google import genai

load_dotenv()

# We use manual (non-automatic) function calling throughout — see agent_loop.py
# — so the SDK's "use Chat.send_message instead" nudge doesn't apply here.
logging.getLogger("google_genai.models").setLevel(logging.ERROR)

DEFAULT_MODEL = "gemini-3.8-flash"


def get_gemini_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY")


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


@dataclass(frozen=True)
class Thresholds:
    brute_force_min_attempts: int = 5
    off_hours_cutoff_hour: int = 5
    off_hours_min_bytes: int = 1_000_000
    auto_block_min_risk_score: float = 8.0
    max_reflection_retries: int = 2


def get_thresholds() -> Thresholds:
    return Thresholds(
        brute_force_min_attempts=int(os.environ.get("AEGIS_BRUTE_FORCE_MIN_ATTEMPTS", "5")),
        off_hours_cutoff_hour=int(os.environ.get("AEGIS_OFF_HOURS_CUTOFF_HOUR", "5")),
        off_hours_min_bytes=int(os.environ.get("AEGIS_OFF_HOURS_MIN_BYTES", "1000000")),
        auto_block_min_risk_score=float(os.environ.get("AEGIS_AUTO_BLOCK_MIN_RISK_SCORE", "8.0")),
        max_reflection_retries=int(os.environ.get("AEGIS_MAX_REFLECTION_RETRIES", "2")),
    )


def get_data_path() -> str:
    return os.environ.get("AEGIS_DATA_PATH", "data/security_logs.csv")
