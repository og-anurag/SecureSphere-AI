from ..state import SecurityState

from app.utils.url_checker import check_url


def browser_agent_node(state: SecurityState) -> SecurityState:
    """Run the production backend URL scanner through LangGraph."""

    raw_input = state["raw_input"].strip()

    result = check_url(raw_input)

    findings = state.setdefault("findings", [])

    # Convert existing URL scanner reasons into LangGraph findings.
    risk = result.get("risk", "Low")

    severity_map = {
        "Low": "low",
        "Medium": "medium",
        "High": "high",
    }

    severity = severity_map.get(risk, "low")

    for reason in result.get("reasons", []):
        findings.append({
            "agent": "browser_agent",
            "signal": "url_heuristic",
            "detail": reason,
            "severity": severity,
        })

    # Preserve the scanner's structured features for later
    # risk aggregation/reporting stages.
    features = result.get("features", {})

    state["risk_score"] = int(result.get("score", 0))
    state["risk_level"] = str(result.get("risk", "Low")).lower()

    # Keep useful scanner output available to downstream agents.
    state["url_scan_result"] = {
        "url": result.get("url"),
        "score": result.get("score", 0),
        "risk": result.get("risk", "Low"),
        "reasons": result.get("reasons", []),
        "features": features,
    }

    return state