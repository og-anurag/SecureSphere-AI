
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import ScanHistory

STAGE_ORDER = ["email", "url", "apk", "payment", "qr"]

# Automatically retain detailed scan history for 21 days.
SCAN_RETENTION_DAYS = 21


def get_scan_retention_cutoff():
    """Return the UTC timestamp before which scan records expire."""
    return datetime.now(timezone.utc) - timedelta(
        days=SCAN_RETENTION_DAYS
    )


def cleanup_expired_scans(db: Session) -> int:
    """
    Delete scan history older than 21 days.
    Does not delete users or account information.
    """
    cutoff = get_scan_retention_cutoff()

    deleted_count = (
        db.query(ScanHistory)
        .filter(ScanHistory.created_at < cutoff)
        .delete(synchronize_session=False)
    )

    return deleted_count


def save_scan(
    db: Session,
    user_id: int,
    input_type: str,
    target: str,
    risk: str,
    score: int,
    reasons: list[str]
):
    """Save a scan and clean up expired scan history."""

    # Remove expired records before saving the new scan.
    cleanup_expired_scans(db)

    record = ScanHistory(
        user_id=user_id,
        input_type=input_type,
        target=target[:500],
        risk=risk,
        score=score,
        reasons=json.dumps(reasons[:20]),
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return record


def check_campaign_correlation(
    db: Session,
    user_id: int,
    lookback: int = 20
):
    """
    Check recent risky scans within the 21-day retention period.
    """

    cutoff = get_scan_retention_cutoff()

    recent = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id)
        .filter(ScanHistory.created_at >= cutoff)
        .filter(ScanHistory.risk.in_(["Medium", "High"]))
        .order_by(ScanHistory.created_at.desc())
        .limit(lookback)
        .all()
    )

    seen_stages = []

    for row in recent:
        if row.input_type not in seen_stages:
            seen_stages.append(row.input_type)

    if len(seen_stages) >= 2:
        ordered = [
            stage for stage in STAGE_ORDER
            if stage in seen_stages
        ]

        return {
            "flagged": True,
            "stages": ordered,
            "message": (
                f"Recent risky activity spans {', '.join(ordered)} — "
                "this matches a multi-stage attack pattern "
                "(e.g. phishing email leading to a fake site, "
                "app, or payment request)."
            ),
        }

    return {
        "flagged": False,
        "stages": seen_stages,
        "message": None,
    }
