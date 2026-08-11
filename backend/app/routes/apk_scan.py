from fastapi import APIRouter, UploadFile, File, HTTPException
import zipfile
from io import BytesIO
from app.schemas.apk_schema import APKResponse
from app.utils.apk_checker import check_apk


router = APIRouter()

@router.post("/scan-apk", response_model=APKResponse)
async def scan_apk(file: UploadFile = File(...)):

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Only APK files are allowed"
    )

    contents = await file.read()
    file_size = len(contents)

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

    result = check_apk(contents)

    return {
        "filename": file.filename,
        "file_size": file_size,
        "risk": result["risk"],
        "score": result["score"],
        "reasons": result["reasons"],
        "features": result["features"]
}