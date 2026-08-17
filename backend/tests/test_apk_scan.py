from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)

TEST_APK = Path("test_valid.apk")


def get_auth_token():
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

    with open("test.txt", "rb") as test_file:
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