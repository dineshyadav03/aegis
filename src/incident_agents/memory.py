"""Cross-run investigation history — Phase 4 persistent memory.

Distinct from graph.py's LangGraph checkpointer: the checkpointer persists
one run's internal state for potential resumption; this module tracks
*recurrence* across separate runs (e.g. "this IP has been flagged 3 times
this month"), which is what "Aegis remembers past investigations" actually
means to a user. A plain SQLite table, not the checkpointer's storage —
different concern, kept separate rather than overloaded onto one mechanism.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import get_history_db_path


def _connect() -> sqlite3.Connection:
    path = Path(get_history_db_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS investigation_history (
            identity TEXT NOT NULL,
            pattern_type TEXT NOT NULL,
            times_flagged INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_severity TEXT,
            PRIMARY KEY (identity, pattern_type)
        )
        """
    )
    return conn


def check_history(identity: str | None, pattern_type: str) -> dict | None:
    """Returns prior-occurrence info for (identity, pattern_type), or None
    if never seen before. Read-only — does not record this occurrence.
    """
    if not identity:
        return None
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT times_flagged, first_seen, last_seen, last_severity "
            "FROM investigation_history WHERE identity = ? AND pattern_type = ?",
            (identity, pattern_type),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return {
        "times_flagged": row[0],
        "first_seen": row[1],
        "last_seen": row[2],
        "last_severity": row[3],
    }


def record_finding(identity: str | None, pattern_type: str, severity: str) -> None:
    """Upserts one occurrence. Call exactly once per real finding per run —
    Respond node does this after Reflect's loop concludes, so retries within
    a single run don't inflate the count.
    """
    if not identity:
        return
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO investigation_history (identity, pattern_type, times_flagged, first_seen, last_seen, last_severity)
            VALUES (?, ?, 1, ?, ?, ?)
            ON CONFLICT (identity, pattern_type) DO UPDATE SET
                times_flagged = times_flagged + 1,
                last_seen = excluded.last_seen,
                last_severity = excluded.last_severity
            """,
            (identity, pattern_type, now, now, severity),
        )
        conn.commit()
    finally:
        conn.close()
