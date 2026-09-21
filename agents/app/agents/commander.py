"""
Commander AI - the router/brain of the system.

For an MVP, classification is done with fast regex heuristics first
(cheap, deterministic, no API cost). Fall back to the LLM only for
ambiguous free-text input.
"""

import re

from ..state import SecurityState


URL_PATTERN = re.compile(r"https?://[^\s]+")
UPI_PATTERN = re.compile(r"[\w.\-]+@[a-zA-Z]+")
HASH_PATTERN = re.compile(
    r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$"
)
APK_PATTERN = re.compile(
    r"\.apk(\s|$)",
    re.IGNORECASE,
)


def classify_input(raw_input: str) -> tuple[str, str]:
    """Classify raw security input into a specialized agent."""

    text = raw_input.strip()

    # 1. File hashes
    if HASH_PATTERN.match(text):
        return "apk", "input matches a file hash format"

    # 2. APK files
    if APK_PATTERN.search(text):
        return "apk", "input references a .apk file"

    # 3. Email must be detected BEFORE URLs.
    # Emails frequently contain links, so URL detection cannot come first.
    if any(
        keyword in text
        for keyword in ["From:", "Subject:", "Reply-To:"]
    ) or ("\n" in text and "@" in text):
        return "email", "input looks like email content"

    # 4. Standalone URLs or text containing a URL
    if URL_PATTERN.search(text):
        return "url", "input contains a URL"

    # 5. UPI/payment identifier
    if UPI_PATTERN.fullmatch(text):
        return "payment", "input matches UPI ID format"

    # 6. Unknown/free-form input
    return (
        "unknown",
        "no pattern matched -- needs manual routing or LLM fallback",
    )


def commander_node(state: SecurityState) -> SecurityState:
    """Classify the input and store the routing decision."""

    input_type, reason = classify_input(
        state["raw_input"]
    )

    state["input_type"] = input_type
    state["classification_reason"] = reason
    state.setdefault("findings", [])

    return state


def route_after_commander(state: SecurityState) -> str:
    """Route the classified input to the appropriate LangGraph agent."""

    mapping = {
        "url": "browser_agent",
        "email": "email_agent",
        "apk": "apk_agent",
        "payment": "payment_agent",
    }

    # Unknown input goes directly to the report generator.
    return mapping.get(
        state["input_type"],
        "report_generator",
    )