"""Threat intelligence lookups.

Phase 1: mocked, matching the reference tutorial's interface so Phase 2 can
swap in a real AbuseIPDB call by rewriting only this file.
"""

from __future__ import annotations

from typing import Any

_MOCK_HIGH_RISK_IPS = {"198.51.100.23", "203.0.113.77"}


def threat_lookup_tool(ip: str) -> dict[str, Any]:
    """Tool: look up an IP's threat-intel reputation. Mocked in Phase 1."""
    if ip in _MOCK_HIGH_RISK_IPS:
        return {
            "ip": ip,
            "risk_score": 9.2,
            "threat_type": "known_malicious",
            "reputation": "malicious",
            "last_seen": "2026-08-01",
        }
    return {
        "ip": ip,
        "risk_score": 0.0,
        "threat_type": "Unknown",
        "reputation": "Unknown",
        "last_seen": None,
    }
