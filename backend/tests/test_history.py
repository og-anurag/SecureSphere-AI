
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import ScanHistory, User
from app.utils.risk_engine import cleanup_expired_scans


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


def test_cleanup_deletes_scans_older_than_21_days():
    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == "historypytest@example.com"
        ).first()

        assert user is not None

        user_id = user.id

        # Remove previous test records for this user.
        db.query(ScanHistory).filter(
            ScanHistory.user_id == user_id
        ).delete()

        now = datetime.now(timezone.utc)

        old_scan = ScanHistory(
            user_id=user_id,
            input_type="url",
            target="expired-test-url",
            risk="High",
            score=90,
            reasons='["expired test"]',
            created_at=now - timedelta(days=22),
        )

        recent_scan = ScanHistory(
            user_id=user_id,
            input_type="url",
            target="recent-test-url",
            risk="Low",
            score=10,
            reasons='["recent test"]',
            created_at=now - timedelta(days=5),
        )

        db.add_all([old_scan, recent_scan])
        db.commit()

        deleted_count = cleanup_expired_scans(db)
        db.commit()

        remaining = (
            db.query(ScanHistory)
            .filter(ScanHistory.user_id == user_id)
            .all()
        )

        # Exactly the expired record should be deleted.
        assert deleted_count == 1
        assert len(remaining) == 1
        assert remaining[0].target == "recent-test-url"

        # User account must remain untouched.
        assert db.query(User).filter(
            User.id == user_id
        ).first() is not None

    finally:
        db.close()
