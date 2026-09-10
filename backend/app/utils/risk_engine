import json
from sqlalchemy.orm import Session

from app.models import ScanHistory

STAGE_ORDER = ["email", "url", "apk", "payment", "qr"]


def save_scan(db: Session, user_id: int, input_type: str, target: str, risk: str, score: int, reasons: list[str]):
    """Persists a scan result so we can build history + cross-agent correlation."""
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


def check_campaign_correlation(db: Session, user_id: int, lookback: int = 20):
    """
    Looks at a user's recent scan history. If 2+ distinct scan types show up
    as High/Medium risk within the recent window, flag it as a likely
    multi-stage attack (e.g. phishing email -> fake site -> malicious APK -> payment).
    """
    recent = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id)
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
        ordered = [s for s in STAGE_ORDER if s in seen_stages]
        return {
            "flagged": True,
            "stages": ordered,
            "message": (
                f"Recent risky activity spans {', '.join(ordered)} — "
                "this matches a multi-stage attack pattern (e.g. phishing email "
                "leading to a fake site, app, or payment request)."
            ),
        }

    return {"flagged": False, "stages": seen_stages, "message": None}
