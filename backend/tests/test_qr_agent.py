from agents.app.agents.qr_agent import qr_agent_node
from app.utils.scan_adapter import qr_result_to_scan_result


def test_qr_result_to_unified_scan_result():
    result = {
        "risk": "High",
        "score": 60,
        "reasons": [
            "QR code links to: http://192.168.1.100/login",
            "Site does not use HTTPS",
        ],
        "features": {
            "decoded": True,
            "content_type": "url",
        },
        "decoded_content": "http://192.168.1.100/login",
    }

    unified = qr_result_to_scan_result(
        result=result,
        target="http://192.168.1.100/login",
    )

    assert unified.input_type == "qr"
    assert unified.target == "http://192.168.1.100/login"
    assert unified.risk_score == 60
    assert unified.severity == "high"
    assert unified.verdict == "malicious"
    assert unified.recommendation == "block"
    assert unified.confidence == 0.6
    assert len(unified.findings) == 2


def test_qr_agent_consumes_precomputed_result():
    precomputed = {
        "input_type": "qr",
        "target": "http://example.com",
        "verdict": "suspicious",
        "risk_score": 60,
        "severity": "high",
        "confidence": 0.6,
        "findings": [
            {
                "agent": "qr_scanner",
                "signal": "qr_heuristic",
                "detail": "Suspicious QR URL",
                "severity": "high",
            }
        ],
        "features": {
            "decoded": True,
            "content_type": "url",
        },
        "threat_intel": {},
        "recommendation": "block",
    }

    state = {
        "raw_input": "http://example.com",
        "input_type": "qr",
        "findings": [],
        "precomputed_scan_result": precomputed,
    }

    result = qr_agent_node(state)

    assert result["risk_score"] == 60
    assert result["risk_level"] == "high"
    assert result["qr_scan_result"] == precomputed
    assert len(result["findings"]) == 1
    assert result["findings"][0]["agent"] == "qr_scanner"