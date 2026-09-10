import re
from app.state import SecurityState

URGENCY_PHRASES = [
    "act now", "urgent", "verify your account", "suspended", "click here immediately",
    "limited time", "your account will be closed", "confirm your identity", "final notice",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "confirm your ssn", "otp", "one time password", "cvv", "pin number",
]


def email_agent_node(state: SecurityState) -> SecurityState:
    text = state["raw_input"].lower()
    findings = state.setdefault("findings", [])

    # 1. Urgency / pressure language — classic social engineering
    hits = [p for p in URGENCY_PHRASES if p in text]
    if hits:
        findings.append({
            "agent": "email_agent",
            "signal": "urgency_language",
            "detail": f"Email uses pressure tactics: {', '.join(hits[:3])}",
            "severity": "medium",
        })

    # 2. Requests for credentials/OTP — no legitimate service asks this way
    cred_hits = [p for p in CREDENTIAL_REQUEST_PHRASES if p in text]
    if cred_hits:
        findings.append({
            "agent": "email_agent",
            "signal": "credential_request",
            "detail": f"Email requests sensitive info: {', '.join(cred_hits[:3])}",
            "severity": "high",
        })

    # 3. Sender / reply-to mismatch (classic spoofing tell)
    from_match = re.search(r"from:\s*.*<([^>]+)>", text)
    reply_match = re.search(r"reply-to:\s*.*<([^>]+)>", text)
    if from_match and reply_match:
        from_domain = from_match.group(1).split("@")[-1]
        reply_domain = reply_match.group(1).split("@")[-1]
        if from_domain != reply_domain:
            findings.append({
                "agent": "email_agent",
                "signal": "sender_replyto_mismatch",
                "detail": f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'.",
                "severity": "high",
            })

    # 4. Embedded links — hand off URL(s) so Browser Agent logic can be reused
    links = re.findall(r"https?://[^\s]+", state["raw_input"])
    if links:
        findings.append({
            "agent": "email_agent",
            "signal": "contains_links",
            "detail": f"Email contains {len(links)} link(s): {links[:3]}",
            "severity": "low",
        })
        # NOTE for teammates: this is the hook for cross-agent correlation —
        # feed these links into browser_agent_node in a follow-up graph run
        # and tag the result with the same session_id.

    return state
