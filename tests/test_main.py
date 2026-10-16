
from app.main import analyze_message


def test_analysis_returns_email_details():
    email = """From: test@example.com
Subject: Meeting reminder

Our project meeting is scheduled for tomorrow.
"""

    result = analyze_message(email)

    assert result["email"]["sender"] == "test@example.com"
    assert result["email"]["subject"] == "Meeting reminder"


def test_analysis_includes_rule_based_results():
    email = """
    Subject: Urgent action required

    Verify your account immediately.
    Visit https://example.com/login
    """

    result = analyze_message(email)

    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in ["low", "medium", "high"]
    assert len(result["indicators"]) > 0


def test_analysis_includes_ml_prediction():
    result = analyze_message(
        "Please review the meeting agenda for tomorrow."
    )

    assert result["ml_prediction"] in [
        "Phishing Email",
        "Safe Email",
    ]

    assert 0.0 <= result["ml_phishing_probability"] <= 1.0


def test_suspicious_email_is_flagged_by_both_systems():
    email = """
    Subject: Account suspended

    Urgent action required! Confirm your password immediately.
    Visit http://192.168.1.10/login
    """

    result = analyze_message(email)

    # Rule-based detector finds explicit suspicious indicators.
    indicator_types = {
        indicator["type"] for indicator in result["indicators"]
    }
    assert "credential_request" in indicator_types
    assert "ip_address_url" in indicator_types

    # ML model returns its own independent prediction.
    assert result["ml_prediction"] in [
        "Phishing Email",
        "Safe Email",
    ]
