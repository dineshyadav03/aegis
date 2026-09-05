"""CLI entrypoint: python -m src.incident_agents.run"""

from __future__ import annotations

import argparse
import sys
import uuid

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from .config import get_client, get_data_path
from .graph import build_graph


def print_status() -> None:
    client = get_client()
    print("=== Configuration Status ===")
    print(f"Gemini API Key: {'✅ Set' if client else '❌ Not set (Fast Mode: rule-based only)'}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis — AI Cyber Defense Multi-Agent System")
    parser.add_argument("--logs", default=None, help="Path to a security log file (CSV or JSON)")
    parser.add_argument("--out", default=None, help="Optional path to write the Markdown report to")
    parser.add_argument("--show-reasoning", action="store_true", help="Print the agent reasoning trail")
    args = parser.parse_args()

    log_path = args.logs or get_data_path()
    print_status()

    app = build_graph()
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}
    result = app.invoke({"log_path": log_path}, config=config)

    print("=" * 60)
    print(result.get("report") or "# Security Incident Report\n\nNo suspicious activity detected.")

    if args.show_reasoning:
        print()
        print("=" * 60)
        print("🤖 AGENT REASONING PROCESS")
        print("=" * 60)
        for line in result.get("reasoning_trail", []):
            print(f"- {line}")
        actions = result.get("autonomous_actions_taken", [])
        print()
        print(f"⚡ Autonomous actions taken: {len(actions)}")
        for a in actions:
            print(f"  - Blocked {a['ip']} ({a['reason']})")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(result.get("report", ""))
        print(f"\nReport written to {args.out}")


if __name__ == "__main__":
    main()
