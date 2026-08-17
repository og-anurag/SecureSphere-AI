from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_register_user():
    response = client.post(
        "/auth/register",
        json={
            "username": "pytestuser",
            "email": "pytest@example.com",
            "password": "Test@123"
        }
    )

    assert response.status_code in [200, 400]


def test_login_user():
    # Make sure the user exists
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

    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password():
    response = client.post(
        "/auth/login",
        json={
            "email": "pytestlogin@example.com",
            "password": "WrongPassword"
        }
    )

    assert response.status_code == 401


def test_protected_endpoint_without_token():
    response = client.get("/auth/me")

    assert response.status_code == 401