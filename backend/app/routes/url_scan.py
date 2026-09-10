from fastapi import APIRouter, Depends

from app.schemas.url_schema import URLRequest, URLResponse
from app.utils.url_checker import check_url
from app.utils.auth import get_current_user
from app.models import User


router = APIRouter()


@router.post("/scan-url", response_model=URLResponse)
def scan_url(
    request: URLRequest,
    current_user: User = Depends(get_current_user)
):
    result = check_url(str(request.url))

    return result