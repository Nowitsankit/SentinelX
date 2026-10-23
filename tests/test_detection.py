import sqlite3
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

import backend.app.main as sentinelx


def setup_test_database(monkeypatch, tmp_path):
    """Use a temporary SQLite database instead of sentinelx.db."""

    test_db = tmp_path / "test_sentinelx.db"

    monkeypatch.setattr(sentinelx, "DB_PATH", test_db)

    sentinelx.initialize_database()

    return test_db


def send_failed_login(client, username="test-user", hostname="TEST-PC"):
    event = {
        "event_type": "authentication_failure",
        "hostname": hostname,
        "username": username,
        "source_ip": "192.0.2.10",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "os_name": "Windows",
        "source": "pytest",
    }

    return client.post("/api/events", json=event)


def test_four_failures_do_not_create_alert(monkeypatch, tmp_path):
    setup_test_database(monkeypatch, tmp_path)
    client = TestClient(sentinelx.app)

    for _ in range(4):
        response = send_failed_login(client)
        assert response.status_code == 201
        assert response.json()["alert_created"] is False

    with sqlite3.connect(sentinelx.DB_PATH) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE title = 'Repeated authentication failures'"
        ).fetchone()[0]

    assert count == 0


def test_five_failures_create_high_alert(monkeypatch, tmp_path):
    setup_test_database(monkeypatch, tmp_path)
    client = TestClient(sentinelx.app)

    for index in range(5):
        response = send_failed_login(client)
        assert response.status_code == 201

        if index < 4:
            assert response.json()["alert_created"] is False
        else:
            assert response.json()["alert_created"] is True

    with sqlite3.connect(sentinelx.DB_PATH) as conn:
        alert = conn.execute(
            """
            SELECT severity, event_count
            FROM alerts
            WHERE title = 'Repeated authentication failures'
            """
        ).fetchone()

    assert alert is not None
    assert alert[0] == "High"
    assert alert[1] == 5


def test_different_users_are_counted_separately(monkeypatch, tmp_path):
    setup_test_database(monkeypatch, tmp_path)
    client = TestClient(sentinelx.app)

    for _ in range(4):
        response = send_failed_login(client, username="user-A")
        assert response.status_code == 201

    response = send_failed_login(client, username="user-B")
    assert response.status_code == 201
    assert response.json()["alert_created"] is False

    with sqlite3.connect(sentinelx.DB_PATH) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE title = 'Repeated authentication failures'"
        ).fetchone()[0]

    assert count == 0


def test_repeated_failures_do_not_create_duplicate_active_alert(
    monkeypatch, tmp_path
):
    setup_test_database(monkeypatch, tmp_path)
    client = TestClient(sentinelx.app)

    # First five failures should create one alert.
    for _ in range(5):
        response = send_failed_login(client, username="repeat-user")
        assert response.status_code == 201

    # Additional failures should not create another active alert.
    for _ in range(3):
        response = send_failed_login(client, username="repeat-user")
        assert response.status_code == 201
        assert response.json()["alert_created"] is False

    with sqlite3.connect(sentinelx.DB_PATH) as conn:
        count = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE title = 'Repeated authentication failures'
              AND hostname = 'TEST-PC'
              AND username = 'repeat-user'
              AND status IN ('New', 'Investigating')
            """
        ).fetchone()[0]

    assert count == 1


def test_old_failures_outside_window_do_not_trigger_alert(
    monkeypatch, tmp_path
):
    setup_test_database(monkeypatch, tmp_path)
    client = TestClient(sentinelx.app)

    # Send four failures with timestamps older than the 5-minute window.
    old_timestamp = (
        datetime.now(timezone.utc) - timedelta(minutes=10)
    ).isoformat()

    for _ in range(4):
        event = {
            "event_type": "authentication_failure",
            "hostname": "TEST-PC",
            "username": "window-user",
            "source_ip": "192.0.2.10",
            "timestamp": old_timestamp,
            "os_name": "Windows",
            "source": "pytest",
        }

        response = client.post("/api/events", json=event)
        assert response.status_code == 201
        assert response.json()["alert_created"] is False

    # One recent failure should not trigger an alert either.
    response = send_failed_login(
        client, username="window-user", hostname="TEST-PC"
    )

    assert response.status_code == 201
    assert response.json()["alert_created"] is False

