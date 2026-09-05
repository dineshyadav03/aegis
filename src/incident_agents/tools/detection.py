"""Detect-stage tools: rule-based pattern and anomaly detection.

Note: the geographic-anomaly logic here is our own design — the reference
tutorial's version was never fully visible in the source material (cut off
mid-scroll; see PROJECT_DOCUMENTATION.md §5.11).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from ..config import Thresholds

EXPECTED_COUNTRIES = {"US"}


def pattern_detector_tool(events: list[dict[str, Any]], thresholds: Thresholds) -> list[dict[str, Any]]:
    """Detect known attack patterns: brute force, privilege escalation."""
    patterns: list[dict[str, Any]] = []

    fails_by_key: dict[tuple[str, str], list[str]] = defaultdict(list)
    for e in events:
        if e.get("event_type") == "login" and e.get("status") == "fail":
            key = (e.get("user"), e.get("source_ip"))
            fails_by_key[key].append(e.get("timestamp"))

    for (user, ip), timestamps in fails_by_key.items():
        if len(timestamps) >= thresholds.brute_force_min_attempts:
            patterns.append(
                {
                    "pattern": "brute_force",
                    "user": user,
                    "ip": ip,
                    "count": len(timestamps),
                    "confidence": 0.8,
                }
            )

    for e in events:
        if e.get("event_type") == "sudo":
            patterns.append(
                {
                    "pattern": "privilege_escalation",
                    "user": e.get("user"),
                    "ip": e.get("source_ip"),
                    "message": e.get("message", ""),
                    "confidence": 0.9,
                }
            )

    return patterns


def anomaly_detector_tool(events: list[dict[str, Any]], thresholds: Thresholds) -> list[dict[str, Any]]:
    """Detect statistical anomalies: off-hours large downloads, geographic anomalies."""
    anomalies: list[dict[str, Any]] = []

    for e in events:
        if e.get("event_type") == "data_download":
            try:
                ts = datetime.fromisoformat(str(e.get("timestamp")).replace("T", " "))
                num_bytes = int(e.get("bytes", 0))
            except (ValueError, TypeError):
                continue
            if ts.hour < thresholds.off_hours_cutoff_hour and num_bytes >= thresholds.off_hours_min_bytes:
                anomalies.append(
                    {
                        "anomaly": "offhours_large_download",
                        "user": e.get("user"),
                        "ip": e.get("source_ip"),
                        "bytes": num_bytes,
                        "timestamp": e.get("timestamp"),
                        "confidence": 0.7,
                    }
                )

    for e in events:
        if e.get("event_type") == "login" and e.get("status") == "success":
            country = e.get("country")
            if country and country not in EXPECTED_COUNTRIES:
                anomalies.append(
                    {
                        "anomaly": "foreign_login",
                        "user": e.get("user"),
                        "ip": e.get("source_ip"),
                        "country": country,
                        "timestamp": e.get("timestamp"),
                        "confidence": 0.6,
                    }
                )

    return anomalies
