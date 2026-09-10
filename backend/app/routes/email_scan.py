from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.schemas.email_schema import EmailRequest, EmailResponse
from app.utils.email_checker import check_email
from app.utils.risk_engine import save_scan
from app.utils.auth import get_current_user
from app.database import get_db
from app.models import User

router = APIRouter()


@router.post("/scan-email", response_model=EmailResponse)
def scan_email(
    request: EmailRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = check_email(request.sender, request.subject, request.body)

    save_scan(
        db, current_user.id, "email", request.subject or request.sender,
        result["risk"], result["score"], result["reasons"]
    )

    return result
