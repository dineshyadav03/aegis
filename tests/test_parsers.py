import json

from incident_agents.tools.parsers import (
    data_validator_tool,
    parse_log_file,
    read_csv_events,
    read_json_events,
)


def test_read_csv_events(tmp_path):
    csv_path = tmp_path / "logs.csv"
    csv_path.write_text(
        "timestamp,event_type,user,source_ip\n"
        "2026-09-01T09:00:00,login,jsmith,10.0.0.1\n"
    )
    events = read_csv_events(str(csv_path))
    assert len(events) == 1
    assert events[0]["user"] == "jsmith"


def test_read_json_events_wrapped_in_events_key(tmp_path):
    json_path = tmp_path / "logs.json"
    json_path.write_text(json.dumps({"events": [{"user": "kbrown"}]}))
    events = read_json_events(str(json_path))
    assert events == [{"user": "kbrown"}]


def test_read_json_events_bare_list(tmp_path):
    json_path = tmp_path / "logs.json"
    json_path.write_text(json.dumps([{"user": "kbrown"}]))
    events = read_json_events(str(json_path))
    assert events == [{"user": "kbrown"}]


def test_parse_log_file_dispatches_by_extension(tmp_path):
    csv_path = tmp_path / "a.csv"
    csv_path.write_text("timestamp,event_type\n2026-09-01T00:00:00,login\n")
    json_path = tmp_path / "b.json"
    json_path.write_text(json.dumps({"events": [{"event_type": "login"}]}))

    assert parse_log_file(str(csv_path))[0]["event_type"] == "login"
    assert parse_log_file(str(json_path))[0]["event_type"] == "login"


def test_data_validator_tool_all_fields_present():
    events = [
        {"timestamp": "t", "event_type": "login", "user": "u", "source_ip": "1.2.3.4"},
        {"timestamp": "t", "event_type": "login", "user": "u", "source_ip": "1.2.3.4"},
    ]
    result = data_validator_tool(events)
    assert result["quality_score"] == 1.0
    assert result["valid"] == 2
    assert result["missing_fields"] == []


def test_data_validator_tool_missing_fields():
    events = [
        {"timestamp": "t", "event_type": "login", "user": "u", "source_ip": "1.2.3.4"},
        {"timestamp": "t", "event_type": "login"},  # missing user, source_ip
    ]
    result = data_validator_tool(events)
    assert result["quality_score"] == 0.5
    assert set(result["missing_fields"]) == {"user", "source_ip"}


def test_data_validator_tool_empty_events():
    result = data_validator_tool([])
    assert result["quality_score"] == 0.0
    assert result["total"] == 0
