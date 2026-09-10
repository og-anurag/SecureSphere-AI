from fastapi import APIRouter, Depends

from app.schemas.email_schema import EmailRequest, EmailResponse
from app.utils.email_checker import check_email
from app.utils.auth import get_current_user
from app.models import User


router = APIRouter()


@router.post("/scan-email", response_model=EmailResponse)
def scan_email(
    request: EmailRequest,
    current_user: User = Depends(get_current_user)
):
    return check_email(
        request.sender,
        request.subject,
        request.body
    )