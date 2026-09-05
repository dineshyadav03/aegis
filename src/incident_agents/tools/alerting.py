"""Slack alerting — fires on High-severity findings (Phase 2).

Best-effort: a failed Slack post never crashes the pipeline or blocks the
report from being returned to the user.
"""

from __future__ import annotations

import requests

from ..config import get_slack_webhook_url

_TIMEOUT_SECONDS = 5


def send_slack_alert(summary: str) -> bool:
    """Posts a short alert to the configured Slack webhook. Returns success."""
    webhook_url = get_slack_webhook_url()
    if not webhook_url:
        return False

    try:
        response = requests.post(
            webhook_url,
            json={"text": summary},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False
