from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.schemas.url_schema import URLRequest, URLResponse
from app.utils.url_checker import check_url
from app.utils.auth import verify_token


router = APIRouter()

security = HTTPBearer()


@router.post("/scan-url", response_model=URLResponse)
def scan_url(
    request: URLRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    payload = verify_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    result = check_url(str(request.url))

    return result