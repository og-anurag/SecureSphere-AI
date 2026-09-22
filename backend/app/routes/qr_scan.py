from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from agents.app.graph import security_graph
from app.utils.scan_adapter import qr_result_to_scan_result
from app.schemas.qr_schema import QRResponse
from app.utils.qr_checker import check_qr
from app.utils.risk_engine import save_scan
from app.utils.auth import get_current_user
from app.database import get_db
from app.models import User


router = APIRouter()

MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".bmp")


@router.post("/scan-qr", response_model=QRResponse)
async def scan_qr(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed",
        )

    contents = await file.read(MAX_IMAGE_SIZE + 1)

    if len(contents) > MAX_IMAGE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Image is too large. Maximum size is 10 MB.",
        )

    result = check_qr(contents)

    target = result.get("decoded_content") or file.filename

    unified_result = qr_result_to_scan_result(
        result=result,
        target=target,
    )

    graph_state = {
        "session_id": f"qr-upload-{current_user.id}",
        "raw_input": target,
        "input_type": "qr",
        "findings": [],
        "precomputed_scan_result": unified_result.model_dump(),
    }

    security_graph.invoke(graph_state)

    save_scan(
        db,
        current_user.id,
        "qr",
        target,
        result["risk"],
        result["score"],
        result["reasons"],
    )

    return result