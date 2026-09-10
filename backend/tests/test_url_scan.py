from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


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


def test_url_scan_with_authentication():
    token = get_auth_token()

    response = client.post(
        "/scan-url",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "url": "https://example.com/"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "url" in data
    assert "risk" in data
    assert "score" in data
    assert "features" in data


def test_url_scan_without_authentication():
    response = client.post(
        "/scan-url",
        json={
            "url": "https://example.com/"
        }
    )

    assert response.status_code == 401