from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException,
    Depends
)
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

import zipfile
from io import BytesIO

from app.schemas.apk_schema import APKResponse
from app.utils.apk_checker import check_apk
from app.utils.auth import verify_token


router = APIRouter()

security = HTTPBearer()


@router.post("/scan-apk", response_model=APKResponse)
async def scan_apk(
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    # Verify JWT token
    token = credentials.credentials

    payload = verify_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    # Check file extension
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Only APK files are allowed"
        )

    # Read uploaded file
    contents = await file.read()
    file_size = len(contents)

    # Validate APK ZIP structure
    try:
        with zipfile.ZipFile(BytesIO(contents)) as apk:

            if "AndroidManifest.xml" not in apk.namelist():
                raise HTTPException(
                    status_code=400,
                    detail="Invalid APK: AndroidManifest.xml not found"
                )

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail="Invalid APK file"
        )

    # Analyze APK
    result = check_apk(contents)

    return {
        "filename": file.filename,
        "file_size": file_size,
        "risk": result["risk"],
        "score": result["score"],
        "reasons": result["reasons"],
        "features": result["features"]
    }