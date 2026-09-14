import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.schemas.history_schema import HistoryResponse, HistoryItem
from app.utils.risk_engine import check_campaign_correlation
from app.utils.auth import get_current_user
from app.database import get_db
from app.models import User, ScanHistory

router = APIRouter()


@router.get("/history", response_model=HistoryResponse)
def get_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )

    items = [
        HistoryItem(
            id=r.id,
            input_type=r.input_type,
            target=r.target,
            risk=r.risk,
            score=r.score,
            reasons=json.loads(r.reasons) if r.reasons else [],
            created_at=r.created_at,
        )
        for r in rows
    ]

    correlation = check_campaign_correlation(db, current_user.id)
    high_risk_count = sum(1 for r in rows if r.risk == "High")

    return HistoryResponse(
        total_scans=len(rows),
        high_risk_count=high_risk_count,
        campaign_flagged=correlation["flagged"],
        campaign_message=correlation["message"],
        items=items,
    )
