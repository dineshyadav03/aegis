from incident_agents.config import RECURRING_MIN_TIMES_FLAGGED, get_thresholds
from incident_agents.tools.classification import context_enricher_tool, risk_assessor_tool

THRESHOLDS = get_thresholds()


def test_high_risk_score_forces_high_severity():
    item = {"anomaly": "foreign_login", "confidence": 0.2}
    threat_intel = {"risk_score": THRESHOLDS.high_risk_score, "reputation": "malicious"}
    result = risk_assessor_tool(item, threat_intel)
    assert result["severity"] == "High"


def test_brute_force_with_high_count_is_high():
    item = {"pattern": "brute_force", "count": 10, "confidence": 0.6}
    result = risk_assessor_tool(item)
    assert result["severity"] == "High"


def test_privilege_escalation_with_malicious_reputation_is_high():
    item = {"pattern": "privilege_escalation", "confidence": 0.9}
    result = risk_assessor_tool(item, {"risk_score": 0.0, "reputation": "malicious"})
    assert result["severity"] == "High"


def test_privilege_escalation_alone_is_medium_not_high():
    # This is the exact bug Aegis's own Reflect agent caught: routine sudo
    # usage with no corroborating risk signal must not be blanket-High.
    item = {"pattern": "privilege_escalation", "confidence": 0.9}
    result = risk_assessor_tool(item)
    assert result["severity"] == "Medium"


def test_moderate_confidence_is_medium():
    item = {"anomaly": "offhours_large_download", "confidence": 0.75}
    result = risk_assessor_tool(item)
    assert result["severity"] == "Medium"


def test_low_confidence_is_low():
    item = {"anomaly": "foreign_login", "confidence": 0.3}
    result = risk_assessor_tool(item)
    assert result["severity"] == "Low"


def test_graph_context_escalates_low_to_medium():
    item = {"anomaly": "foreign_login", "confidence": 0.3}
    graph_context = {
        "available": True,
        "matches": [{"cvss_score": 8.0, "similarity_score": 0.8}],
    }
    result = risk_assessor_tool(item, graph_context=graph_context)
    assert result["severity"] == "Medium"


def test_graph_context_escalates_medium_to_high():
    item = {"anomaly": "offhours_large_download", "confidence": 0.75}
    graph_context = {
        "available": True,
        "matches": [{"cvss_score": 9.0, "similarity_score": 0.9}],
    }
    result = risk_assessor_tool(item, graph_context=graph_context)
    assert result["severity"] == "High"


def test_graph_context_below_thresholds_does_not_escalate():
    item = {"anomaly": "foreign_login", "confidence": 0.3}
    graph_context = {
        "available": True,
        "matches": [{"cvss_score": 3.0, "similarity_score": 0.2}],
    }
    result = risk_assessor_tool(item, graph_context=graph_context)
    assert result["severity"] == "Low"


def test_unavailable_graph_context_does_not_escalate():
    item = {"anomaly": "foreign_login", "confidence": 0.3}
    graph_context = {"available": False, "reason": "Neo4j not configured"}
    result = risk_assessor_tool(item, graph_context=graph_context)
    assert result["severity"] == "Low"


def test_history_context_escalates_low_to_medium():
    item = {"anomaly": "foreign_login", "confidence": 0.3}
    history_context = {"times_flagged": RECURRING_MIN_TIMES_FLAGGED}
    result = risk_assessor_tool(item, history_context=history_context)
    assert result["severity"] == "Medium"


def test_history_context_below_recurrence_threshold_does_not_escalate():
    item = {"anomaly": "foreign_login", "confidence": 0.3}
    history_context = {"times_flagged": RECURRING_MIN_TIMES_FLAGGED - 1}
    result = risk_assessor_tool(item, history_context=history_context)
    assert result["severity"] == "Low"


def test_severity_never_exceeds_high_when_already_high():
    item = {"pattern": "brute_force", "count": 10, "confidence": 0.9}
    graph_context = {"available": True, "matches": [{"cvss_score": 9.0, "similarity_score": 0.9}]}
    history_context = {"times_flagged": RECURRING_MIN_TIMES_FLAGGED}
    result = risk_assessor_tool(item, graph_context=graph_context, history_context=history_context)
    assert result["severity"] == "High"


def test_context_enricher_returns_known_description():
    result = context_enricher_tool({"pattern": "brute_force"})
    assert "failed login" in result["description"].lower()


def test_context_enricher_falls_back_for_unknown_kind():
    result = context_enricher_tool({"pattern": "something_new"})
    assert result["description"] == "Unclassified security event."
