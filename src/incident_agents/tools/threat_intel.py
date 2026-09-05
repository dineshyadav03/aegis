"""Threat intelligence lookups — real AbuseIPDB integration (Phase 2).

Falls back to a safe "Unknown" result (never crashes the pipeline) when no
API key is configured, the request times out, the free-tier rate limit is
hit, or any other network/API error occurs — matching the same
graceful-degradation pattern used for the Gemini client (config.get_client).
"""

from __future__ import annotations

from typing import Any

import requests

from ..config import get_abuseipdb_key, get_thresholds

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT_SECONDS = 5

# Our synthetic dataset (scripts/generate_sample_logs.py) uses RFC 5737
# documentation/test-net IPs (198.51.100.0/24 etc) — these are reserved and
# never routable, so they will NEVER have real AbuseIPDB reports. Rather than
# planting a real malicious IP in a public repo's test fixtures (which would
# change reputation over time and amounts to distributing an IOC without
# context), we keep a small, explicit override so the demo dataset still
# exercises the auto-block path deterministically. Every other IP goes
# through the real API untouched.
_DEMO_OVERRIDE_IPS: dict[str, dict[str, Any]] = {
    "198.51.100.23": {
        "risk_score": 92.0,
        "threat_type": "known_malicious (demo fixture)",
        "reputation": "malicious",
        "last_seen": "2026-08-01",
        "total_reports": 47,
    }
}

_UNKNOWN_RESULT: dict[str, Any] = {
    "risk_score": 0.0,
    "threat_type": "Unknown",
    "reputation": "Unknown",
    "last_seen": None,
    "total_reports": 0,
}


def _reputation_for(risk_score: float) -> str:
    thresholds = get_thresholds()
    if risk_score >= thresholds.high_risk_score:
        return "malicious"
    if risk_score >= thresholds.suspicious_risk_score:
        return "suspicious"
    return "clean"


def threat_lookup_tool(ip: str) -> dict[str, Any]:
    """Tool: look up an IP's threat-intel reputation via AbuseIPDB.

    risk_score is AbuseIPDB's native abuseConfidenceScore (0-100).
    """
    if ip in _DEMO_OVERRIDE_IPS:
        return {"ip": ip, **_DEMO_OVERRIDE_IPS[ip]}

    api_key = get_abuseipdb_key()
    if not api_key:
        return {"ip": ip, **_UNKNOWN_RESULT}

    try:
        response = requests.get(
            _ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
    except requests.RequestException:
        # Network error, timeout, or non-2xx (including 429 rate-limit) —
        # degrade to "Unknown" rather than failing the whole pipeline.
        return {"ip": ip, **_UNKNOWN_RESULT}

    risk_score = float(data.get("abuseConfidenceScore", 0))
    return {
        "ip": ip,
        "risk_score": risk_score,
        "threat_type": data.get("usageType") or "Unknown",
        "reputation": _reputation_for(risk_score),
        "last_seen": data.get("lastReportedAt"),
        "total_reports": data.get("totalReports", 0),
    }
