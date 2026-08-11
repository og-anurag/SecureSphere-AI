SUSPICIOUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
]

import zipfile
from io import BytesIO


def check_apk(contents: bytes):
    score = 0
    reasons = []
    features = {
        "has_suspicious_permissions": False,
        "permission_count": 0
    }

    with zipfile.ZipFile(BytesIO(contents)) as apk:
        files = apk.namelist()

        # Check AndroidManifest.xml
        if "AndroidManifest.xml" not in files:
            score += 50
            reasons.append("AndroidManifest.xml is missing")

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "features": features
    }