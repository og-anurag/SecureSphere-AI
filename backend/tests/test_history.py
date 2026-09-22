from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import ScanHistory, User


client = TestClient(app)


def get_auth_token():
    client.post(
        "/auth/register",
        json={
            "username": "historypytest",
            "email": "historypytest@example.com",
            "password": "Test@123",
        },
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "historypytest@example.com",
            "password": "Test@123",
        },
    )

    assert response.status_code == 200
    return response.json()["access_token"]


def test_history_counts_critical_as_high_risk():
    token = get_auth_token()

    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == "historypytest@example.com"
        ).first()

        assert user is not None
        user_id = user.id

        db.query(ScanHistory).filter(
            ScanHistory.user_id == user_id
        ).delete()

        db.add(
            ScanHistory(
                user_id=user_id,
                input_type="url",
                target="critical-test",
                risk="Critical",
                score=80,
                reasons='["critical test finding"]',
            )
        )

        db.commit()
    finally:
        db.close()

    response = client.get(
        "/history",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total_scans"] == 1
    assert data["high_risk_count"] == 1