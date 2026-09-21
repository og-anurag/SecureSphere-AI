from typing import Any

from app.schemas.scan_schema import ScanFinding, ScanResult


def url_result_to_scan_result(result: dict[str, Any]) -> ScanResult:
    """Convert the existing URL scanner result into the unified scan format."""

    score = int(result.get("score", 0))
    risk = str(result.get("risk", "Low"))

    severity_map = {
        "Low": "low",
        "Medium": "medium",
        "High": "high",
    }

    severity = severity_map.get(risk, "low")

    if severity == "high":
        verdict = "malicious"
        recommendation = "block"
    elif severity == "medium":
        verdict = "suspicious"
        recommendation = "warn"
    else:
        verdict = "benign"
        recommendation = "allow"

    confidence = min(max(score / 100, 0.0), 1.0)

    findings = [
        ScanFinding(
            agent="url_scanner",
            signal="url_heuristic",
            detail=reason,
            severity=severity,
        )
        for reason in result.get("reasons", [])
    ]

    return ScanResult(
        input_type="url",
        target=result["url"],
        verdict=verdict,
        risk_score=score,
        severity=severity,
        confidence=confidence,
        findings=findings,
        features=result.get("features", {}),
        threat_intel={},
        recommendation=recommendation,
    )