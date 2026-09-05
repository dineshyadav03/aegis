import json

import pytest

from incident_agents.nodes import respond


@pytest.fixture(autouse=True)
def _isolated_blocklist(tmp_path, monkeypatch):
    # BLOCKLIST_PATH is resolved once at import time, so point the module-level
    # constant itself at a temp file rather than the env var (which respond.py
    # never re-reads after import).
    path = tmp_path / "blocklist.json"
    monkeypatch.setattr(respond, "BLOCKLIST_PATH", path)
    monkeypatch.setenv("AEGIS_HISTORY_DB_PATH", str(tmp_path / "history.sqlite"))
    return path


def _malicious_high_finding(ip="1.2.3.4"):
    return {
        "ip": ip,
        "pattern": "brute_force",
        "severity": "High",
        "confidence": 0.95,
        "threat_intel": {"reputation": "malicious", "risk_score": 90.0},
    }


def test_confirmed_malicious_high_finding_gets_auto_blocked(_isolated_blocklist):
    state = {"findings": [_malicious_high_finding()], "reasoning_trail": []}
    result = respond.respond_node(state)
    assert len(result["autonomous_actions_taken"]) == 1
    assert result["autonomous_actions_taken"][0]["ip"] == "1.2.3.4"
    assert json.loads(_isolated_blocklist.read_text())[0]["ip"] == "1.2.3.4"


def test_high_severity_without_malicious_reputation_is_not_blocked():
    finding = _malicious_high_finding()
    finding["threat_intel"] = {"reputation": "unknown", "risk_score": 90.0}
    state = {"findings": [finding], "reasoning_trail": []}
    result = respond.respond_node(state)
    assert result["autonomous_actions_taken"] == []


def test_malicious_reputation_below_risk_threshold_is_not_blocked():
    finding = _malicious_high_finding()
    finding["threat_intel"] = {"reputation": "malicious", "risk_score": 10.0}
    state = {"findings": [finding], "reasoning_trail": []}
    result = respond.respond_node(state)
    assert result["autonomous_actions_taken"] == []


def test_medium_severity_malicious_finding_is_not_blocked():
    finding = _malicious_high_finding()
    finding["severity"] = "Medium"
    state = {"findings": [finding], "reasoning_trail": []}
    result = respond.respond_node(state)
    assert result["autonomous_actions_taken"] == []


def test_already_blocked_ip_is_not_added_twice(_isolated_blocklist):
    state = {"findings": [_malicious_high_finding()], "reasoning_trail": []}
    respond.respond_node(state)
    result = respond.respond_node(state)
    assert result["autonomous_actions_taken"] == []
    assert len(json.loads(_isolated_blocklist.read_text())) == 1


def test_finding_without_ip_is_skipped_safely():
    finding = _malicious_high_finding()
    finding["ip"] = None
    state = {"findings": [finding], "reasoning_trail": []}
    result = respond.respond_node(state)
    assert result["autonomous_actions_taken"] == []


def test_respond_records_every_finding_into_history():
    state = {
        "findings": [
            _malicious_high_finding(ip="1.2.3.4"),
            {"ip": "5.6.7.8", "anomaly": "foreign_login", "severity": "Low", "threat_intel": {}},
        ],
        "reasoning_trail": [],
    }
    respond.respond_node(state)
    from incident_agents.memory import check_history

    assert check_history("1.2.3.4", "brute_force")["times_flagged"] == 1
    assert check_history("5.6.7.8", "foreign_login")["times_flagged"] == 1
