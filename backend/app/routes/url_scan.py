from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class URLRequest(BaseModel):
    url: str


@router.post("/scan-url")
def scan_url(request: URLRequest):
    return {
        "received_url": request.url,
        "message": "URL received successfully."
    }