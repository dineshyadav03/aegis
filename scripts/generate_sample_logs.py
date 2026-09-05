"""Generates a synthetic security_logs.csv/.json for testing Aegis.

No real dataset from the reference tutorial was ever captured (only its
output) — see PROJECT_DOCUMENTATION.md §5.11 — so this is built fresh,
with deliberately planted anomalies so the pipeline has real signal.
"""

from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

USERS = ["jsmith", "kbrown", "adoyle", "mchen", "rpatel"]
BENIGN_IPS = ["10.0.0.12", "10.0.0.45", "10.0.0.88", "10.0.0.101"]
ATTACKER_IP = "198.51.100.23"  # matches _MOCK_HIGH_RISK_IPS in tools/threat_intel.py
FOREIGN_IP = "203.0.113.50"

BASE_TIME = datetime(2026, 9, 1, 9, 0, 0)


def _ts(offset_minutes: int) -> str:
    return (BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def generate_events() -> list[dict]:
    events = []
    minute = 0

    # Benign baseline traffic
    for _ in range(120):
        minute += random.randint(1, 6)
        user = random.choice(USERS)
        ip = random.choice(BENIGN_IPS)
        events.append(
            {
                "timestamp": _ts(minute),
                "event_type": "login",
                "user": user,
                "source_ip": ip,
                "status": "success",
                "country": "US",
                "bytes": "",
                "message": "",
            }
        )

    # A few legitimate small downloads during business hours
    for _ in range(15):
        minute += random.randint(1, 10)
        events.append(
            {
                "timestamp": _ts(minute),
                "event_type": "data_download",
                "user": random.choice(USERS),
                "source_ip": random.choice(BENIGN_IPS),
                "status": "success",
                "country": "US",
                "bytes": str(random.randint(1000, 50000)),
                "message": "",
            }
        )

    # Brute-force attack: 8 failed logins from the same attacker IP against one account
    for i in range(8):
        events.append(
            {
                "timestamp": _ts(500 + i),
                "event_type": "login",
                "user": "jsmith",
                "source_ip": ATTACKER_IP,
                "status": "fail",
                "country": "RU",
                "bytes": "",
                "message": "",
            }
        )

    # Off-hours large download (hour < 5, >= 1MB) from the same attacker IP
    off_hours_ts = datetime(2026, 9, 2, 3, 15, 0).isoformat()
    events.append(
        {
            "timestamp": off_hours_ts,
            "event_type": "data_download",
            "user": "jsmith",
            "source_ip": ATTACKER_IP,
            "status": "success",
            "country": "RU",
            "bytes": "5000000",
            "message": "",
        }
    )

    # Foreign login (unexpected country, non-attacker IP — a separate lower-confidence signal)
    events.append(
        {
            "timestamp": _ts(700),
            "event_type": "login",
            "user": "mchen",
            "source_ip": FOREIGN_IP,
            "status": "success",
            "country": "CN",
            "bytes": "",
            "message": "",
        }
    )

    # A couple of legitimate admin sudo actions
    for i in range(2):
        minute += random.randint(5, 20)
        events.append(
            {
                "timestamp": _ts(minute),
                "event_type": "sudo",
                "user": "adoyle",
                "source_ip": random.choice(BENIGN_IPS),
                "status": "success",
                "country": "US",
                "bytes": "",
                "message": "routine maintenance",
            }
        )

    random.shuffle(events)
    return events


def main() -> None:
    events = generate_events()
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    csv_path = data_dir / "security_logs.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(events[0].keys()))
        writer.writeheader()
        writer.writerows(events)

    json_path = data_dir / "security_logs.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"events": events}, f, indent=2)

    print(f"Wrote {len(events)} events to {csv_path} and {json_path}")


if __name__ == "__main__":
    main()
