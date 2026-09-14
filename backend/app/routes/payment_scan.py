from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.schemas.payment_schema import PaymentRequest, PaymentResponse
from app.utils.payment_checker import check_payment
from app.utils.risk_engine import save_scan
from app.utils.auth import get_current_user
from app.database import get_db
from app.models import User

router = APIRouter()


@router.post("/scan-payment", response_model=PaymentResponse)
def scan_payment(
    request: PaymentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = check_payment(request.upi_id)

    save_scan(
        db, current_user.id, "payment", result["upi_id"],
        result["risk"], result["score"], result["reasons"]
    )

    return result
