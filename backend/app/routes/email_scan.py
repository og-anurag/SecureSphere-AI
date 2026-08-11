from fastapi import APIRouter
from app.schemas.email_schema import EmailRequest, EmailResponse
from app.utils.email_checker import check_email

router = APIRouter()

@router.post("/scan-email", response_model=EmailResponse)
def scan_email(request: EmailRequest):
    return check_email(
        request.sender,
        request.subject,
        request.body
)