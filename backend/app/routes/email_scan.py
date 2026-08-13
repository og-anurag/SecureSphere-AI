from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.schemas.email_schema import EmailRequest, EmailResponse
from app.utils.email_checker import check_email
from app.utils.auth import verify_token


router = APIRouter()

security = HTTPBearer()


@router.post("/scan-email", response_model=EmailResponse)
def scan_email(
    request: EmailRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    payload = verify_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return check_email(
        request.sender,
        request.subject,
        request.body
    )