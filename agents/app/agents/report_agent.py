from ..state import SecurityState


# Severity contribution for findings that do not already have
# a scanner-provided risk score.
SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
}


# In-memory session store keyed by session_id -> list of past input_types.
# Replace with Redis/Postgres when moving beyond the prototype stage.
SESSION_HISTORY: dict[str, list[str]] = {}


def _score_findings(findings: list[dict]) -> int:
    """Calculate a score from agent findings."""

    return min(
        sum(
            SEVERITY_WEIGHTS.get(
                finding.get("severity", "low"),
                0,
            )
            for finding in findings
        ),
        100,
    )


def _risk_level(score: int) -> str:
    """Convert a numeric risk score into a normalized risk level."""

    if score >= 70:
        return "critical"

    if score >= 40:
        return "high"

    if score >= 15:
        return "medium"

    return "low"


def _check_campaign_correlation(
    state: SecurityState,
) -> str | None:
    """
    Track security stages seen during a session.

    This is a potential multi-stage attack pattern indicator,
    not proof of a coordinated campaign.
    """

    session_id = state.get("session_id", "default")

    history = SESSION_HISTORY.setdefault(
        session_id,
        [],
    )

    input_type = state["input_type"]

    if input_type not in history:
        history.append(input_type)

    stage_order = [
        "email",
        "url",
        "apk",
        "payment",
    ]

    seen_stages = [
        stage
        for stage in stage_order
        if stage in history
    ]

    if len(seen_stages) >= 2:
        return (
            "This session has involved multiple security stages: "
            f"{', '.join(seen_stages)}. "
            "This may indicate a multi-stage attack pattern."
        )

    return None


def report_generator_node(
    state: SecurityState,
) -> SecurityState:
    """
    Generate the final security report.

    If an upstream scanner already provides a risk score,
    use that as the authoritative base score.

    Otherwise calculate a score from agent findings.
    """

    findings = state.get("findings", [])

    # Prefer an upstream scanner-provided score.
    scanner_score = state.get("risk_score")

    if scanner_score is not None:
        score = int(scanner_score)
    else:
        score = _score_findings(findings)

    score = min(max(score, 0), 100)

    level = _risk_level(score)

    campaign_note = _check_campaign_correlation(state)

    state["risk_score"] = score
    state["risk_level"] = level
    state["correlated_campaign"] = campaign_note

    state["final_report"] = {
        "input_type": state.get("input_type"),
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "campaign_correlation": campaign_note,
        "recommendation": _recommendation_for(level),
    }

    return state


def _recommendation_for(level: str) -> str:
    """Return a recommendation based on normalized risk level."""

    return {
        "low": (
            "No significant threat detected. "
            "Proceed with normal caution."
        ),
        "medium": (
            "Some risk indicators found. "
            "Verify the source before continuing."
        ),
        "high": (
            "Multiple strong risk indicators found. "
            "Do not enter credentials or make payments."
        ),
        "critical": (
            "This strongly matches a known attack pattern. "
            "Do not proceed — report and block."
        ),
    }[level]