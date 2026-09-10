from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.schemas.url_schema import URLRequest, URLResponse
from app.utils.url_checker import check_url
from app.utils.risk_engine import save_scan
from app.utils.auth import get_current_user
from app.database import get_db
from app.models import User

router = APIRouter()


@router.post("/scan-url", response_model=URLResponse)
def scan_url(
    request: URLRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = check_url(str(request.url))

    save_scan(
        db, current_user.id, "url", result["url"],
        result["risk"], result["score"], result["reasons"]
    )

    return result
