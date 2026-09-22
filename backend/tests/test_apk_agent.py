from app.utils.scan_adapter import apk_result_to_scan_result
from agents.app.agents.apk_agent import apk_agent_node


def test_apk_agent_flagged_hash(monkeypatch):
    def fake_virustotal(file_hash):
        return {
            "checked": True,
            "flagged": True,
            "stats": {
                "malicious": 8,
                "suspicious": 2,
                "harmless": 50,
            },
        }

    monkeypatch.setattr(
        "agents.app.agents.apk_agent.check_virustotal_file_hash",
        fake_virustotal,
    )

    state = {
        "session_id": "apk-malicious-test",
        "raw_input": "a" * 64,
        "input_type": "apk",
        "findings": [],
    }

    result = apk_agent_node(state)

    assert result["risk_score"] == 100
    assert result["risk_level"] == "critical"
    assert "apk_scan_result" in result

    unified = result["apk_scan_result"]

    assert unified["input_type"] == "apk"
    assert unified["risk_score"] == 100
    assert unified["severity"] == "critical"
    assert unified["verdict"] == "malicious"
    assert unified["recommendation"] == "block"

    assert any(
        finding["agent"] == "virustotal"
        for finding in result["findings"]
    )


def test_apk_agent_unavailable_virustotal(monkeypatch):
    def fake_virustotal(file_hash):
        return {
            "checked": False,
            "flagged": False,
            "error": "no_api_key",
        }

    monkeypatch.setattr(
        "agents.app.agents.apk_agent.check_virustotal_file_hash",
        fake_virustotal,
    )

    state = {
        "session_id": "apk-unavailable-test",
        "raw_input": "b" * 64,
        "input_type": "apk",
        "findings": [],
    }

    result = apk_agent_node(state)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert "apk_scan_result" in result

    unified = result["apk_scan_result"]

    assert unified["verdict"] == "unknown"
    assert unified["recommendation"] == "warn"

    assert any(
        finding["signal"] == "check_unavailable"
        for finding in result["findings"]
    )


def test_apk_agent_detects_dangerous_permissions(monkeypatch):
    def fake_virustotal(file_hash):
        return {
            "checked": True,
            "flagged": False,
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 60,
            },
        }

    monkeypatch.setattr(
        "agents.app.agents.apk_agent.check_virustotal_file_hash",
        fake_virustotal,
    )

    state = {
        "session_id": "apk-permission-test",
        "raw_input": (
            "APK hash: "
            + "c" * 64
            + "\n"
            + "READ_SMS\n"
            + "REQUEST_INSTALL_PACKAGES"
        ),
        "input_type": "apk",
        "findings": [],
    }

    result = apk_agent_node(state)

    assert "apk_scan_result" in result

    assert any(
        finding["signal"] == "dangerous_permissions"
        for finding in result["findings"]
    )
def test_binary_apk_result_to_unified_scan_result():
    raw_result = {
        "risk": "High",
        "score": 60,
        "reasons": [
            "Suspicious permission: android.permission.READ_SMS",
            "Suspicious permission: android.permission.SEND_SMS",
            "Suspicious permission: android.permission.RECORD_AUDIO",
            "Suspicious permission: android.permission.CAMERA",
        ],
        "features": {
            "has_suspicious_permissions": True,
            "permission_count": 4,
            "has_dex": True,
            "has_native_libraries": True,
            "file_count": 42,
            "manifest_parsed": True,
        },
    }

    result = apk_result_to_scan_result(
        raw_result,
        target="test-malicious.apk",
    )

    assert result.input_type == "apk"
    assert result.target == "test-malicious.apk"
    assert result.risk_score == 60
    assert result.severity == "high"
    assert result.verdict == "malicious"
    assert result.recommendation == "block"
    assert result.confidence == 0.6

    assert result.features["has_suspicious_permissions"] is True
    assert result.features["permission_count"] == 4

    assert len(result.findings) == 4
    assert all(
        finding.agent == "apk_scanner"
        for finding in result.findings
    )
def test_apk_agent_consumes_precomputed_binary_scan_result():
    precomputed = {
        "input_type": "apk",
        "target": "uploaded.apk",
        "verdict": "malicious",
        "risk_score": 60,
        "severity": "high",
        "confidence": 0.6,
        "findings": [
            {
                "agent": "apk_scanner",
                "signal": "apk_heuristic",
                "detail": "Suspicious permission: android.permission.READ_SMS",
                "severity": "high",
            }
        ],
        "features": {
            "has_suspicious_permissions": True,
            "permission_count": 1,
        },
        "threat_intel": {},
        "recommendation": "block",
    }

    state = {
        "session_id": "binary-apk-agent-test",
        "raw_input": "uploaded.apk",
        "input_type": "apk",
        "findings": [],
        "precomputed_scan_result": precomputed,
    }

    result = apk_agent_node(state)

    assert result["risk_score"] == 60
    assert result["risk_level"] == "high"
    assert result["apk_scan_result"] == precomputed

    assert any(
        finding["agent"] == "apk_scanner"
        for finding in result["findings"]
    )