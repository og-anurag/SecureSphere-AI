"""
Commander AI - the router/brain of the system.

For an MVP, classification is done with fast regex heuristics first
(cheap, deterministic, no API cost). Fall back to the LLM only for
ambiguous free-text input (e.g. "is this email legit: ...").
Swap in a proper LLM classifier once the heuristics feel limiting.
"""
import re
from app.state import SecurityState

URL_PATTERN = re.compile(r"https?://[^\s]+")
UPI_PATTERN = re.compile(r"[\w.\-]+@[a-zA-Z]+")  # e.g. someone@upi
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$")  # md5 or sha256
APK_PATTERN = re.compile(r"\.apk(\s|$)", re.IGNORECASE)


def classify_input(raw_input: str) -> tuple[str, str]:
    text = raw_input.strip()

    if HASH_PATTERN.match(text):
        return "apk", "input matches a file hash format"

    if APK_PATTERN.search(text):
        return "apk", "input references a .apk file"

    if URL_PATTERN.search(text):
        return "url", "input contains a URL"

    if UPI_PATTERN.fullmatch(text):
        return "payment", "input matches UPI ID format"

    # crude email heuristic: has "From:", "Subject:", or looks like a forwarded email
    if any(k in text for k in ["From:", "Subject:", "Reply-To:"]) or "\n" in text and "@" in text:
        return "email", "input looks like email content"

    return "unknown", "no pattern matched — needs manual routing or LLM fallback"


def commander_node(state: SecurityState) -> SecurityState:
    input_type, reason = classify_input(state["raw_input"])
    state["input_type"] = input_type
    state["classification_reason"] = reason
    state.setdefault("findings", [])
    return state


def route_after_commander(state: SecurityState) -> str:
    """Used by LangGraph's conditional edge to pick the next node."""
    mapping = {
        "url": "browser_agent",
        "email": "email_agent",
        "apk": "apk_agent",
        "payment": "payment_agent",
    }
    return mapping.get(state["input_type"], "report_generator")  # unknown -> skip straight to report
