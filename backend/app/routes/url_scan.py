from fastapi import APIRouter
from pydantic import BaseModel
from app.utils.url_checker import check_url

router = APIRouter()


class URLRequest(BaseModel):
    url: str


@router.post("/scan-url")
def scan_url(request: URLRequest):
    result = check_url(request.url)
    return result
    