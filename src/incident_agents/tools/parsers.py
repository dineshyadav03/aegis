"""Ingest-stage tools: parsing and validating raw security log files."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def read_csv_events(log_path: str) -> list[dict[str, Any]]:
    with open(log_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_json_events(log_path: str) -> list[dict[str, Any]]:
    with open(log_path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return data


def parse_log_file(log_path: str) -> list[dict[str, Any]]:
    """Dispatches to the right parser based on file extension."""
    suffix = Path(log_path).suffix.lower()
    if suffix == ".json":
        return read_json_events(log_path)
    return read_csv_events(log_path)


def csv_parser_tool(log_path: str) -> dict[str, Any]:
    """Tool: parse a CSV security log file into a list of event dicts."""
    events = read_csv_events(log_path)
    return {"events": events, "count": len(events)}


def json_parser_tool(log_path: str) -> dict[str, Any]:
    """Tool: parse a JSON security log file into a list of event dicts."""
    events = read_json_events(log_path)
    return {"events": events, "count": len(events)}


def data_validator_tool(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Tool: score data quality — fraction of events with all required fields present."""
    required = {"timestamp", "event_type", "user", "source_ip"}
    if not events:
        return {"quality_score": 0.0, "total": 0, "valid": 0, "missing_fields": []}

    valid = 0
    missing_fields: set[str] = set()
    for e in events:
        present = {k for k in required if e.get(k)}
        if present == required:
            valid += 1
        else:
            missing_fields |= required - present

    return {
        "quality_score": round(valid / len(events), 3),
        "total": len(events),
        "valid": valid,
        "missing_fields": sorted(missing_fields),
    }
