"""
Shared state passed between every node in the LangGraph.
Add fields here as you add agents (SSL check, typosquatting, etc).
"""

from typing import TypedDict, List, Optional, Any


class Finding(TypedDict):
    agent: str
    signal: str
    detail: str
    severity: str


class SecurityState(TypedDict, total=False):
    session_id: str
    raw_input: str
    input_type: str
    classification_reason: str

    findings: List[Finding]

    # A scanner can calculate a unified result before LangGraph runs.
    # Example: the binary APK upload scanner.
    precomputed_scan_result: dict[str, Any]

    # Agent-specific unified results.
    url_scan_result: dict[str, Any]
    email_scan_result: dict[str, Any]
    apk_scan_result: dict[str, Any]

    risk_score: int
    risk_level: str

    correlated_campaign: Optional[str]

    final_report: dict