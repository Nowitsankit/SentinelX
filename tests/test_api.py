from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200


def test_list_alerts_endpoint():
    response = client.get("/api/alerts")
    assert response.status_code == 200


def test_list_events_endpoint():
    response = client.get("/api/events")
    assert response.status_code == 200


def test_list_endpoints_endpoint():
    response = client.get("/api/endpoints")
    assert response.status_code == 200