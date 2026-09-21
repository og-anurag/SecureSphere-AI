from typing import Any

from app.schemas.scan_schema import ScanFinding, ScanResult


def url_result_to_scan_result(result: dict[str, Any]) -> ScanResult:
    """Convert the existing URL scanner result into the unified scan format."""

    score = int(result.get("score", 0))
    risk = str(result.get("risk", "Low"))

    features = result.get("features", {})
    safe_browsing = features.get("google_safe_browsing", {})

    findings = [
        ScanFinding(
            agent="url_scanner",
            signal="url_heuristic",
            detail=reason,
            severity={
                "Low": "low",
                "Medium": "medium",
                "High": "high",
            }.get(risk, "low"),
        )
        for reason in result.get("reasons", [])
    ]

    # External threat intelligence can raise the risk,
    # but a failed/unavailable provider does not affect the score.
    if safe_browsing.get("checked") and safe_browsing.get("flagged"):
        score = min(score + 50, 100)

        findings.append(
            ScanFinding(
                agent="google_safe_browsing",
                signal="threat_match",
                detail="Google Safe Browsing flagged this URL.",
                severity="high",
            )
        )

    if score >= 60:
        severity = "high"
        verdict = "malicious"
        recommendation = "block"
    elif score >= 30:
        severity = "medium"
        verdict = "suspicious"
        recommendation = "warn"
    else:
        severity = "low"
        verdict = "benign"
        recommendation = "allow"

    confidence = min(max(score / 100, 0.0), 1.0)

    return ScanResult(
        input_type="url",
        target=result["url"],
        verdict=verdict,
        risk_score=score,
        severity=severity,
        confidence=confidence,
        findings=findings,
        features=features,
        threat_intel={
            "google_safe_browsing": safe_browsing,
        },
        recommendation=recommendation,
    )