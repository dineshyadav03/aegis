from incident_agents.anonymize import Anonymizer


def test_hash_is_deterministic_for_same_value():
    a = Anonymizer()
    assert a.hash("jsmith") == a.hash("jsmith")


def test_hash_differs_across_values():
    a = Anonymizer()
    assert a.hash("jsmith") != a.hash("mchen")


def test_hash_of_none_or_empty_passes_through():
    a = Anonymizer()
    assert a.hash(None) is None
    assert a.hash("") == ""


def test_unhash_recovers_original_value():
    a = Anonymizer()
    token = a.hash("jsmith")
    assert a.unhash(token) == "jsmith"


def test_unhash_unknown_token_returns_none():
    a = Anonymizer()
    assert a.unhash("h_doesnotexist") is None


def test_reverse_map_is_per_instance_not_shared():
    a = Anonymizer()
    b = Anonymizer()
    token = a.hash("jsmith")
    assert b.unhash(token) is None


def test_anonymize_event_hashes_user_and_source_ip_only():
    a = Anonymizer()
    event = {"user": "jsmith", "source_ip": "1.2.3.4", "event_type": "login"}
    result = a.anonymize_event(event)
    assert result["user"] != "jsmith"
    assert result["source_ip"] != "1.2.3.4"
    assert result["event_type"] == "login"
    assert a.unhash(result["user"]) == "jsmith"


def test_anonymize_events_handles_a_list():
    a = Anonymizer()
    events = [{"user": "jsmith"}, {"user": "mchen"}]
    results = a.anonymize_events(events)
    assert a.unhash(results[0]["user"]) == "jsmith"
    assert a.unhash(results[1]["user"]) == "mchen"
