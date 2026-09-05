import pytest

from incident_agents import memory


@pytest.fixture(autouse=True)
def _isolated_history_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HISTORY_DB_PATH", str(tmp_path / "history.sqlite"))


def test_check_history_returns_none_for_unseen_identity():
    assert memory.check_history("1.2.3.4", "brute_force") is None


def test_check_history_returns_none_for_missing_identity():
    assert memory.check_history(None, "brute_force") is None


def test_record_finding_then_check_history_roundtrips():
    memory.record_finding("1.2.3.4", "brute_force", "High")
    result = memory.check_history("1.2.3.4", "brute_force")
    assert result["times_flagged"] == 1
    assert result["last_severity"] == "High"


def test_record_finding_increments_times_flagged_on_repeat():
    memory.record_finding("1.2.3.4", "brute_force", "Medium")
    memory.record_finding("1.2.3.4", "brute_force", "High")
    result = memory.check_history("1.2.3.4", "brute_force")
    assert result["times_flagged"] == 2
    assert result["last_severity"] == "High"


def test_record_finding_is_isolated_per_pattern_type():
    memory.record_finding("1.2.3.4", "brute_force", "High")
    memory.record_finding("1.2.3.4", "foreign_login", "Low")
    assert memory.check_history("1.2.3.4", "brute_force")["times_flagged"] == 1
    assert memory.check_history("1.2.3.4", "foreign_login")["times_flagged"] == 1


def test_record_finding_is_isolated_per_identity():
    memory.record_finding("1.2.3.4", "brute_force", "High")
    memory.record_finding("5.6.7.8", "brute_force", "High")
    assert memory.check_history("1.2.3.4", "brute_force")["times_flagged"] == 1
    assert memory.check_history("5.6.7.8", "brute_force")["times_flagged"] == 1


def test_record_finding_does_nothing_for_missing_identity():
    memory.record_finding(None, "brute_force", "High")
    assert memory.check_history(None, "brute_force") is None
