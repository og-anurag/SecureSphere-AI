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

from androguard.core.apk import APK


def check_apk(contents: bytes):
    score = 0
    reasons = []

    features = {
        "has_suspicious_permissions": False,
        "permission_count": 0,
        "has_dex": False,
        "has_native_libraries": False,
        "file_count": 0,
        "manifest_parsed": False
    }

    # Open APK as a ZIP file
    with zipfile.ZipFile(BytesIO(contents)) as apk:
        files = apk.namelist()

        # Count files inside APK
        features["file_count"] = len(files)

        # Check for DEX files
        features["has_dex"] = any(
            file_name.endswith(".dex")
            for file_name in files
        )

        # Check for native libraries
        features["has_native_libraries"] = any(
            file_name.endswith(".so")
            for file_name in files
        )

    # Parse AndroidManifest.xml using Androguard
    try:
        andro_apk = APK(contents, raw=True)

        manifest_xml = andro_apk.get_android_manifest_xml()

        if manifest_xml is None:
            return {
                "risk": "Low",
                "score": 0,
                "reasons": [
                    "AndroidManifest.xml could not be parsed"
                ],
                "features": features
            }

        features["manifest_parsed"] = True

        # Get permissions from the APK
        permissions = andro_apk.get_permissions()

    except Exception:
        return {
            "risk": "Low",
            "score": 0,
            "reasons": [
                "AndroidManifest.xml could not be parsed"
            ],
            "features": features
        }

    # Check for suspicious permissions
    found_permissions = []

    for permission in SUSPICIOUS_PERMISSIONS:
        if permission in permissions:
            found_permissions.append(permission)

    features["permission_count"] = len(found_permissions)

    if found_permissions:
        features["has_suspicious_permissions"] = True

        for permission in found_permissions:
            score += 15
            reasons.append(
                f"Suspicious permission: {permission}"
            )

    # Determine risk level
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