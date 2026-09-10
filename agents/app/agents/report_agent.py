from app.state import SecurityState

SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 30}

# In-memory session store keyed by session_id -> list of past input_types.
# Swap for Redis/Postgres once you move past the prototype stage.
SESSION_HISTORY: dict[str, list[str]] = {}


def _score_findings(findings: list[dict]) -> int:
    score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    return min(score, 100)


def _risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def _check_campaign_correlation(state: SecurityState) -> str | None:
    """
    Minimal version of the 'email -> website -> apk -> payment' correlation
    described in the brief. Tracks which stages have been seen for this
    session_id and flags it as a coordinated campaign once 2+ stages appear.
    """
    session_id = state.get("session_id", "default")
    history = SESSION_HISTORY.setdefault(session_id, [])
    if state["input_type"] not in history:
        history.append(state["input_type"])

    stage_order = ["email", "url", "apk", "payment"]
    seen_stages = [s for s in stage_order if s in history]
    if len(seen_stages) >= 2:
        return f"This session has now involved {', '.join(seen_stages)} — matches a multi-stage attack pattern."
    return None


def report_generator_node(state: SecurityState) -> SecurityState:
    findings = state.get("findings", [])
    score = _score_findings(findings)
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
    return {
        "low": "No significant threat detected. Proceed with normal caution.",
        "medium": "Some risk indicators found. Verify the source before continuing.",
        "high": "Multiple strong risk indicators found. Do not enter credentials or make payments.",
        "critical": "This strongly matches a known attack pattern. Do not proceed — report and block.",
    }[level]
