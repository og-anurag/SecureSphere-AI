from fastapi.testclient import TestClient

from app.main import app
from app.routes import payment_scan


client = TestClient(app)


def get_auth_token():
    client.post(
        "/auth/register",
        json={
            "username": "paymentpytest",
            "email": "paymentpytest@example.com",
            "password": "Test@123",
        },
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "paymentpytest@example.com",
            "password": "Test@123",
        },
    )

    assert response.status_code == 200

    return response.json()["access_token"]


def test_payment_scan_invokes_langgraph(monkeypatch):
    token = get_auth_token()

    captured = {}

    def fake_graph_invoke(state):
        captured["state"] = state

        return {
            **state,
            "risk_score": 60,
            "risk_level": "high",
            "final_report": {
                "input_type": "payment",
                "risk_score": 60,
                "risk_level": "high",
            },
        }

    monkeypatch.setattr(
        payment_scan.security_graph,
        "invoke",
        fake_graph_invoke,
    )

    response = client.post(
        "/scan-payment",
        headers={
            "Authorization": f"Bearer {token}",
        },
        json={
            "upi_id": "lotterywinner@upi",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["upi_id"] == "lotterywinner@upi"
    assert "risk" in data
    assert "score" in data
    assert "reasons" in data
    assert "features" in data

    assert "state" in captured

    graph_state = captured["state"]

    assert graph_state["input_type"] == "payment"
    assert graph_state["raw_input"] == "lotterywinner@upi"
    assert "precomputed_scan_result" in graph_state

    precomputed = graph_state["precomputed_scan_result"]

    assert precomputed["input_type"] == "payment"
    assert precomputed["target"] == "lotterywinner@upi"
    assert 0 <= precomputed["risk_score"] <= 100
    assert precomputed["severity"] in {
        "low",
        "medium",
        "high",
        "critical",
    }