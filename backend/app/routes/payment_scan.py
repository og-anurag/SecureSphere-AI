from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from agents.app.graph import security_graph

from app.schemas.payment_schema import PaymentRequest, PaymentResponse
from app.utils.payment_checker import check_payment
from app.utils.scan_adapter import payment_result_to_scan_result
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

    unified_result = payment_result_to_scan_result(result)

    graph_state = {
        "session_id": f"payment-{current_user.id}",
        "raw_input": request.upi_id,
        "input_type": "payment",
        "findings": [],
        "precomputed_scan_result": unified_result.model_dump(),
    }

    security_graph.invoke(graph_state)

    save_scan(
        db,
        current_user.id,
        "payment",
        result["upi_id"],
        result["risk"],
        result["score"],
        result["reasons"],
    )

    return result