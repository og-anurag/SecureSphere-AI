from pathlib import Path

from fastapi.testclient import TestClient
from app.main import app

BACKEND_DIR = Path(__file__).resolve().parents[1]
TEST_APK = BACKEND_DIR / "test_valid.apk"
TEST_NON_APK = BACKEND_DIR / "test.txt"
client = TestClient(app)

def get_auth_token():
    client.post(
        "/auth/register",
        json={
            "username": "pytestlogin",
            "email": "pytestlogin@example.com",
            "password": "Test@123"
        }
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "pytestlogin@example.com",
            "password": "Test@123"
        }
    )

    assert response.status_code == 200

    return response.json()["access_token"]


def test_apk_scan_with_authentication():
    token = get_auth_token()

    with TEST_APK.open("rb") as apk:
        response = client.post(
            "/scan-apk",
            headers={
                "Authorization": f"Bearer {token}"
            },
            files={
                "file": (
                    "test_valid.apk",
                    apk,
                    "application/vnd.android.package-archive"
                )
            }
        )

    assert response.status_code == 200

    data = response.json()

    assert data["filename"] == "test_valid.apk"
    assert "risk" in data
    assert "score" in data
    assert "reasons" in data
    assert "features" in data


def test_apk_scan_without_authentication():
    with TEST_APK.open("rb") as apk:
        response = client.post(
            "/scan-apk",
            files={
                "file": (
                    "test_valid.apk",
                    apk,
                    "application/vnd.android.package-archive"
                )
            }
        )

    assert response.status_code == 401


def test_non_apk_file_rejected():
    token = get_auth_token()

    with TEST_NON_APK.open("rb") as test_file:
        response = client.post(
            "/scan-apk",
            headers={
                "Authorization": f"Bearer {token}"
            },
            files={
                "file": (
                    "test.txt",
                    test_file,
                    "text/plain"
                )
            }
        )

    assert response.status_code == 400

    assert response.json()["detail"] == "Only APK files are allowed"