from app.utils.scan_adapter import url_result_to_scan_result


def test_url_result_to_scan_result():
    result = {
        "url": "https://example.com/",
        "score": 35,
        "risk": "Medium",
        "reasons": [
            "Contains suspicious keyword: login",
        ],
        "features": {
            "uses_https": True,
        },
    }

    unified = url_result_to_scan_result(result)

    assert unified.input_type == "url"
    assert unified.target == "https://example.com/"
    assert unified.risk_score == 35
    assert unified.severity == "medium"
    assert unified.verdict == "suspicious"
    assert unified.recommendation == "warn"
    assert 0.0 <= unified.confidence <= 1.0
    assert len(unified.findings) == 1
    assert unified.findings[0].agent == "url_scanner"