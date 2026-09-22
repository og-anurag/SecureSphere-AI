from agents.app.agents.payment_agent import payment_agent_node
from app.utils.scan_adapter import payment_result_to_scan_result


def test_payment_result_to_unified_scan_result():
    raw_result = {
        "upi_id": "lotterywinner@upi",
        "risk": "High",
        "score": 60,
        "reasons": [
            "UPI handle contains scam-associated terms: lottery, winner",
            "UPI handle 'lotterywinner' is mostly digits, common in throwaway scam IDs",
        ],
        "features": {
            "valid_format": True,
            "is_known_scam": True,
            "has_suspicious_naming": True,
            "is_random_looking": False,
        },
    }

    result = payment_result_to_scan_result(raw_result)

    assert result.input_type == "payment"
    assert result.target == "lotterywinner@upi"
    assert result.risk_score == 60
    assert result.severity == "high"
    assert result.verdict == "malicious"
    assert result.recommendation == "block"
    assert result.confidence == 0.6

    assert result.features["valid_format"] is True
    assert result.features["is_known_scam"] is True

    assert len(result.findings) == 2
    assert all(
        finding.agent == "payment_scanner"
        for finding in result.findings
    )


def test_payment_agent_consumes_precomputed_result():
    precomputed = {
        "input_type": "payment",
        "target": "lotterywinner@upi",
        "verdict": "malicious",
        "risk_score": 60,
        "severity": "high",
        "confidence": 0.6,
        "findings": [
            {
                "agent": "payment_scanner",
                "signal": "payment_heuristic",
                "detail": "UPI handle contains scam-associated terms: lottery, winner",
                "severity": "high",
            }
        ],
        "features": {
            "valid_format": True,
            "is_known_scam": True,
            "has_suspicious_naming": True,
        },
        "threat_intel": {},
        "recommendation": "block",
    }

    state = {
        "session_id": "payment-agent-test",
        "raw_input": "lotterywinner@upi",
        "input_type": "payment",
        "findings": [],
        "precomputed_scan_result": precomputed,
    }

    result = payment_agent_node(state)

    assert result["risk_score"] == 60
    assert result["risk_level"] == "high"
    assert result["payment_scan_result"] == precomputed

    assert any(
        finding["agent"] == "payment_scanner"
        for finding in result["findings"]
    )


def test_payment_agent_handles_invalid_input():
    state = {
        "session_id": "payment-invalid-test",
        "raw_input": "not-a-valid-payment",
        "input_type": "payment",
        "findings": [],
    }

    result = payment_agent_node(state)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"

    assert any(
        finding["signal"] == "unparseable_payment_input"
        for finding in result["findings"]
    )