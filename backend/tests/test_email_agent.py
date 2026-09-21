from agents.app.agents.commander import classify_input
from agents.app.agents.email_agent import email_agent_node


def test_email_with_url_is_classified_as_email():
    raw_input = (
        "From: security@fake-bank.com\n"
        "Subject: Urgent verification\n\n"
        "Click https://example.com/login"
    )

    input_type, reason = classify_input(raw_input)

    assert input_type == "email"
    assert reason == "input looks like email content"


def test_email_agent_uses_unified_scan_result():
    raw_input = (
        "From: security@fake-bank.com\n"
        "Subject: Urgent account verification\n\n"
        "Urgent! Verify your account immediately. "
        "Enter your password and OTP."
    )

    state = {
        "session_id": "email-test",
        "raw_input": raw_input,
        "input_type": "email",
        "findings": [],
    }

    result = email_agent_node(state)

    assert result["risk_score"] > 0
    assert result["risk_level"] in {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert "email_scan_result" in result

    unified = result["email_scan_result"]

    assert unified["input_type"] == "email"
    assert unified["risk_score"] == result["risk_score"]
    assert unified["severity"] == result["risk_level"]

    assert any(
        finding["agent"] == "email_scanner"
        for finding in result["findings"]
    )


def test_normal_email_has_low_risk():
    raw_input = (
        "From: professor@college.edu\n"
        "Subject: Class schedule\n\n"
        "The class will begin at 10 AM tomorrow."
    )

    state = {
        "session_id": "normal-email-test",
        "raw_input": raw_input,
        "input_type": "email",
        "findings": [],
    }

    result = email_agent_node(state)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"