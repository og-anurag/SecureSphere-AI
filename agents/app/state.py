"""
Shared state passed between every node in the LangGraph.
Add fields here as you add agents (SSL check, typosquatting, etc).
"""
from typing import TypedDict, List, Optional


class Finding(TypedDict):
    agent: str          # which agent produced this
    signal: str          # short machine-readable name, e.g. "blacklisted_url"
    detail: str          # human-readable explanation
    severity: str         # "low" | "medium" | "high"


class SecurityState(TypedDict, total=False):
    session_id: str          # groups events from the same user session -> enables correlation
    raw_input: str            # what the user submitted (URL, email text, hash, UPI id...)
    input_type: str           # "url" | "email" | "apk" | "payment" | "unknown"
    classification_reason: str    # why Commander routed it this way

    findings: List[Finding]      # every signal raised by every agent this run
    risk_score: int          # 0-100, filled in by the correlation step
    risk_level: str          # "low" | "medium" | "high" | "critical"

    correlated_campaign: Optional[str]  # e.g. "matches earlier phishing email in this session"

    final_report: dict         # what Report Generator produces, returned to the user
