from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import ScanFeedback


client = TestClient(app)

TEST_HOST = "feedback-test.example.com"


def test_feedback_is_recorded_and_stores_only_hostname():
    response = client.post(
        "/feedback",
        json={
            "hostname": TEST_HOST,
            "shown_risk": "Medium",
            "shown_score": 40,
            "label": "false_positive",
        },
    )

    assert response.status_code == 201

    db = SessionLocal()

    try:
        row = (
            db.query(ScanFeedback)
            .filter(ScanFeedback.hostname == TEST_HOST)
            .first()
        )

        assert row is not None
        assert row.label == "false_positive"
        assert row.shown_risk == "medium"

        db.delete(row)
        db.commit()
    finally:
        db.close()


def test_feedback_rejects_invalid_label():
    response = client.post(
        "/feedback",
        json={
            "hostname": TEST_HOST,
            "shown_risk": "low",
            "shown_score": 0,
            "label": "whatever",
        },
    )

    assert response.status_code == 422


def test_feedback_rejects_a_full_url_instead_of_hostname():
    response = client.post(
        "/feedback",
        json={
            "hostname": "https://evil.example/path?token=secret",
            "shown_risk": "low",
            "shown_score": 0,
            "label": "false_positive",
        },
    )

    assert response.status_code == 422