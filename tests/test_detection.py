from incident_agents.config import Thresholds
from incident_agents.tools.detection import anomaly_detector_tool, pattern_detector_tool

THRESHOLDS = Thresholds()  # defaults: brute_force_min_attempts=5, off_hours_cutoff_hour=5, off_hours_min_bytes=1_000_000


def _fail_login(user="jsmith", ip="1.2.3.4", ts="2026-09-01T09:00:00"):
    return {"event_type": "login", "status": "fail", "user": user, "source_ip": ip, "timestamp": ts}


def test_brute_force_fires_at_exactly_the_threshold():
    events = [_fail_login(ts=f"2026-09-01T09:0{i}:00") for i in range(THRESHOLDS.brute_force_min_attempts)]
    patterns = pattern_detector_tool(events, THRESHOLDS)
    assert len(patterns) == 1
    assert patterns[0]["pattern"] == "brute_force"
    assert patterns[0]["count"] == THRESHOLDS.brute_force_min_attempts


def test_brute_force_does_not_fire_one_below_threshold():
    events = [_fail_login(ts=f"2026-09-01T09:0{i}:00") for i in range(THRESHOLDS.brute_force_min_attempts - 1)]
    assert pattern_detector_tool(events, THRESHOLDS) == []


def test_brute_force_is_keyed_by_user_and_ip_pair():
    # Same count of fails, but split across two different IPs -> neither should fire alone.
    half = THRESHOLDS.brute_force_min_attempts - 1
    events = [_fail_login(ip="1.1.1.1", ts=f"2026-09-01T09:0{i}:00") for i in range(half)]
    events += [_fail_login(ip="2.2.2.2", ts=f"2026-09-01T10:0{i}:00") for i in range(half)]
    assert pattern_detector_tool(events, THRESHOLDS) == []


def test_privilege_escalation_fires_on_any_sudo_event():
    events = [{"event_type": "sudo", "user": "adoyle", "source_ip": "10.0.0.1", "message": "routine"}]
    patterns = pattern_detector_tool(events, THRESHOLDS)
    assert len(patterns) == 1
    assert patterns[0]["pattern"] == "privilege_escalation"
    assert patterns[0]["confidence"] == 0.9


def test_offhours_large_download_requires_both_hour_and_size():
    off_hours_big = {
        "event_type": "data_download",
        "user": "jsmith",
        "source_ip": "1.2.3.4",
        "timestamp": "2026-09-02T03:15:00",
        "bytes": THRESHOLDS.off_hours_min_bytes,
    }
    anomalies = anomaly_detector_tool([off_hours_big], THRESHOLDS)
    assert len(anomalies) == 1
    assert anomalies[0]["anomaly"] == "offhours_large_download"


def test_daytime_large_download_does_not_fire():
    daytime_big = {
        "event_type": "data_download",
        "user": "jsmith",
        "source_ip": "1.2.3.4",
        "timestamp": "2026-09-02T14:00:00",  # 2pm, not off-hours
        "bytes": THRESHOLDS.off_hours_min_bytes,
    }
    assert anomaly_detector_tool([daytime_big], THRESHOLDS) == []


def test_offhours_small_download_does_not_fire():
    off_hours_small = {
        "event_type": "data_download",
        "user": "jsmith",
        "source_ip": "1.2.3.4",
        "timestamp": "2026-09-02T03:15:00",
        "bytes": 100,
    }
    assert anomaly_detector_tool([off_hours_small], THRESHOLDS) == []


def test_foreign_login_fires_for_unexpected_country():
    event = {
        "event_type": "login",
        "status": "success",
        "user": "mchen",
        "source_ip": "5.6.7.8",
        "country": "CN",
        "timestamp": "2026-09-01T20:00:00",
    }
    anomalies = anomaly_detector_tool([event], THRESHOLDS)
    assert len(anomalies) == 1
    assert anomalies[0]["anomaly"] == "foreign_login"


def test_domestic_login_does_not_fire():
    event = {
        "event_type": "login",
        "status": "success",
        "user": "kbrown",
        "source_ip": "10.0.0.1",
        "country": "US",
        "timestamp": "2026-09-01T09:00:00",
    }
    assert anomaly_detector_tool([event], THRESHOLDS) == []


def test_failed_foreign_login_does_not_fire_as_anomaly():
    # Only successful logins should be checked for geographic anomaly.
    event = {
        "event_type": "login",
        "status": "fail",
        "user": "mchen",
        "source_ip": "5.6.7.8",
        "country": "CN",
        "timestamp": "2026-09-01T20:00:00",
    }
    assert anomaly_detector_tool([event], THRESHOLDS) == []


def test_thresholds_are_configurable_not_hardcoded():
    custom = Thresholds(brute_force_min_attempts=2)
    events = [_fail_login(ts="2026-09-01T09:00:00"), _fail_login(ts="2026-09-01T09:01:00")]
    assert pattern_detector_tool(events, custom) != []
    assert pattern_detector_tool(events, THRESHOLDS) == []  # same events, default threshold of 5
