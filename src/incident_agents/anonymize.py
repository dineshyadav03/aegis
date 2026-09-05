"""PII anonymization: hash usernames/IPs before anything reaches the LLM.

The reverse-lookup map lives only in memory for the current run — it is
never persisted to disk and never sent to the LLM. It exists so the final
report can still say "the same user across 3 findings" using a stable
short hash, without the raw value ever leaving this process boundary
except into the human-facing Markdown report.
"""

from __future__ import annotations

import hashlib
import os

_SALT = os.environ.get("AEGIS_ANONYMIZE_SALT", "aegis-local-salt")


class Anonymizer:
    def __init__(self) -> None:
        self._reverse: dict[str, str] = {}

    def hash(self, value: str | None) -> str | None:
        if not value:
            return value
        digest = hashlib.sha256(f"{_SALT}:{value}".encode()).hexdigest()[:12]
        token = f"h_{digest}"
        self._reverse[token] = value
        return token

    def unhash(self, token: str) -> str | None:
        return self._reverse.get(token)

    def anonymize_event(self, event: dict) -> dict:
        anonymized = dict(event)
        if "user" in anonymized:
            anonymized["user"] = self.hash(anonymized["user"])
        if "source_ip" in anonymized:
            anonymized["source_ip"] = self.hash(anonymized["source_ip"])
        return anonymized

    def anonymize_events(self, events: list[dict]) -> list[dict]:
        return [self.anonymize_event(e) for e in events]
