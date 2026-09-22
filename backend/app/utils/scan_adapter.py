from typing import Any

from app.schemas.scan_schema import ScanFinding, ScanResult


def url_result_to_scan_result(
    result: dict[str, Any],
) -> ScanResult:
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


def email_result_to_scan_result(
    result: dict[str, Any],
    target: str,
) -> ScanResult:
    """Convert the existing email scanner result into the unified scan format."""

    score = min(max(int(result.get("score", 0)), 0), 100)
    risk = str(result.get("risk", "Low"))

    severity_map = {
        "Low": "low",
        "Medium": "medium",
        "High": "high",
    }

    severity = severity_map.get(risk, "low")

    findings = [
        ScanFinding(
            agent="email_scanner",
            signal="email_heuristic",
            detail=reason,
            severity=severity,
        )
        for reason in result.get("reasons", [])
    ]

    if score >= 80:
        verdict = "malicious"
        severity = "critical"
        recommendation = "block"
    elif score >= 60:
        verdict = "malicious"
        severity = "high"
        recommendation = "block"
    elif score >= 30:
        verdict = "suspicious"
        severity = "medium"
        recommendation = "warn"
    else:
        verdict = "benign"
        severity = "low"
        recommendation = "allow"

    confidence = min(max(score / 100, 0.0), 1.0)

    return ScanResult(
        input_type="email",
        target=target,
        verdict=verdict,
        risk_score=score,
        severity=severity,
        confidence=confidence,
        findings=findings,
        features=result.get("features", {}),
        threat_intel={},
        recommendation=recommendation,
    )


def apk_hash_result_to_scan_result(
    result: dict[str, Any],
    target: str,
) -> ScanResult:
    """Convert a VirusTotal APK/file-hash result into the unified scan format."""

    checked = bool(result.get("checked", False))
    flagged = bool(result.get("flagged", False))

    if flagged:
        score = 100
        severity = "critical"
        verdict = "malicious"
        recommendation = "block"

        findings = [
            ScanFinding(
                agent="virustotal",
                signal="file_hash_match",
                detail=(
                    f"VirusTotal flagged this file: "
                    f"{result.get('stats', {})}"
                ),
                severity="critical",
            )
        ]

    elif checked:
        score = 0
        severity = "low"
        verdict = "benign"
        recommendation = "allow"

        findings = []

    else:
        score = 0
        severity = "low"
        verdict = "unknown"
        recommendation = "warn"

        findings = [
            ScanFinding(
                agent="virustotal",
                signal="check_unavailable",
                detail="VirusTotal could not verify this file hash.",
                severity="low",
            )
        ]

    return ScanResult(
        input_type="apk",
        target=target,
        verdict=verdict,
        risk_score=score,
        severity=severity,
        confidence=1.0 if checked else 0.0,
        findings=findings,
        features={},
        threat_intel={
            "virustotal": result,
        },
        recommendation=recommendation,
    )


def apk_result_to_scan_result(
    result: dict[str, Any],
    target: str,
) -> ScanResult:
    """Convert the binary APK scanner result into the unified scan format."""

    score = min(max(int(result.get("score", 0)), 0), 100)

    if score >= 80:
        severity = "critical"
        verdict = "malicious"
        recommendation = "block"
    elif score >= 60:
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

    findings = [
        ScanFinding(
            agent="apk_scanner",
            signal="apk_heuristic",
            detail=reason,
            severity=severity,
        )
        for reason in result.get("reasons", [])
    ]

    return ScanResult(
        input_type="apk",
        target=target,
        verdict=verdict,
        risk_score=score,
        severity=severity,
        confidence=min(max(score / 100, 0.0), 1.0),
        findings=findings,
        features=result.get("features", {}),
        threat_intel={},
        recommendation=recommendation,
    )