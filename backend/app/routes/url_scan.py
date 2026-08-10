from fastapi import APIRouter
from app.schemas.url_schema import URLRequest, URLResponse
from app.utils.url_checker import check_url

router = APIRouter()

@router.post("/scan-url", response_model=URLResponse)
def scan_url(request: URLRequest):
    result = check_url(str(request.url))
    return result
    