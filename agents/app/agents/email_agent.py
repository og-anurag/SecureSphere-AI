import re

from ..state import SecurityState
from app.utils.email_checker import check_email
from app.utils.scan_adapter import email_result_to_scan_result


def _extract_email_parts(raw_input: str) -> tuple[str, str, str]:
    """Extract sender, subject, and body from a raw email-like input."""

    sender = ""
    subject = ""

    from_match = re.search(
        r"(?im)^from:\s*(?:.*<)?([^<>\s]+@[^<>\s]+)>?\s*$",
        raw_input,
    )

    subject_match = re.search(
        r"(?im)^subject:\s*(.*)$",
        raw_input,
    )

    if from_match:
        sender = from_match.group(1).strip()

    if subject_match:
        subject = subject_match.group(1).strip()

    body_lines = []

    for line in raw_input.splitlines():
        if re.match(r"(?i)^from:\s*", line):
            continue

        if re.match(r"(?i)^subject:\s*", line):
            continue

        body_lines.append(line)

    body = "\n".join(body_lines).strip()

    return sender, subject, body


def email_agent_node(state: SecurityState) -> SecurityState:
    """Run the production email scanner through LangGraph."""

    raw_input = state["raw_input"].strip()

    sender, subject, body = _extract_email_parts(raw_input)

    result = check_email(
        sender=sender,
        subject=subject,
        body=body,
    )

    unified = email_result_to_scan_result(
        result,
        target=subject or sender or raw_input[:200],
    )

    findings = state.setdefault("findings", [])

    for finding in unified.findings:
        findings.append({
            "agent": finding.agent,
            "signal": finding.signal,
            "detail": finding.detail,
            "severity": finding.severity,
        })

    state["risk_score"] = unified.risk_score
    state["risk_level"] = unified.severity

    state["email_scan_result"] = unified.model_dump()

    return state