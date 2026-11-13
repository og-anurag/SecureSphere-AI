from app.utils.scan_adapter import url_result_to_scan_result


def test_google_safe_browsing_flag_raises_risk():
    result = {
        "url": "https://example.com",
        "score": 20,
        "risk": "Low",
        "reasons": [],
        "features": {
            "uses_https": True,
            "google_safe_browsing": {
                "checked": True,
                "flagged": True,
                "matches": [
                    {"threatType": "SOCIAL_ENGINEERING"}
                ],
            },
        },
    }

    unified = url_result_to_scan_result(result)

    assert unified.risk_score == 70
    assert unified.verdict == "malicious"
    assert unified.severity == "high"
    assert unified.recommendation == "block"
    assert unified.threat_intel["google_safe_browsing"]["flagged"] is True
    assert any(
        finding.agent == "google_safe_browsing"
        for finding in unified.findings
    )