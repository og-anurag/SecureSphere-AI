import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScanFeedback


router = APIRouter()


ALLOWED_LABELS = {"false_positive", "false_negative"}
ALLOWED_RISKS = {"low", "medium", "high", "critical"}

# Letters, digits, dots and hyphens only (covers punycode too).
HOSTNAME_PATTERN = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")


class FeedbackRequest(BaseModel):
    hostname: str = Field(max_length=255)
    shown_risk: str = Field(max_length=20)
    shown_score: int = Field(ge=0, le=100)
    label: str = Field(max_length=20)


@router.post("/feedback", status_code=201)
def submit_feedback(
    request: FeedbackRequest,
    db: Session = Depends(get_db),
):
    hostname = request.hostname.strip().lower()
    risk = request.shown_risk.strip().lower()

    if request.label not in ALLOWED_LABELS:
        raise HTTPException(status_code=422, detail="Invalid label")

    if risk not in ALLOWED_RISKS:
        raise HTTPException(status_code=422, detail="Invalid risk level")

    if not HOSTNAME_PATTERN.fullmatch(hostname):
        raise HTTPException(
            status_code=422,
            detail="hostname must be a plain hostname, not a URL",
        )

    db.add(
        ScanFeedback(
            hostname=hostname,
            shown_risk=risk,
            shown_score=request.shown_score,
            label=request.label,
        )
    )
    db.commit()

    return {"status": "recorded"}