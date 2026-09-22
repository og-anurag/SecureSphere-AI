from pathlib import Path
from app.utils import scan_adapter
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
def test_apk_scan_creates_unified_result(monkeypatch):
    token = get_auth_token()

    captured = {}

    original_adapter = scan_adapter.apk_result_to_scan_result

    def capture_unified_result(result, target):
        unified = original_adapter(result, target)
        captured["result"] = unified
        return unified

    monkeypatch.setattr(
        "app.routes.apk_scan.apk_result_to_scan_result",
        capture_unified_result,
    )

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
    assert "result" in captured

    unified = captured["result"]

    assert unified.input_type == "apk"
    assert unified.target == "test_valid.apk"
    assert 0 <= unified.risk_score <= 100
    assert unified.severity in {
        "low",
        "medium",
        "high",
        "critical",
    }
    assert unified.verdict in {
        "benign",
        "suspicious",
        "malicious",
        "unknown",
    }
    assert unified.recommendation in {
        "allow",
        "warn",
        "block",
    }