"""
NACSystem - Unit Tests for the FastAPI Policy Engine
=====================================================
These tests verify that our API endpoints work correctly
WITHOUT needing a real PostgreSQL or Redis connection.

HOW IT WORKS:
  - We use "mock" objects to fake the database and Redis responses.
  - unittest.mock.patch replaces a real function (like get_db) with
    a fake one that returns pre-defined test data.
  - This way, tests run instantly and don't depend on Docker services.

RUN WITH:
  pytest test_main.py -v
"""

import hashlib
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from main import app, sha256_hash

# ── Create a test client ─────────────────────────────────────
# WHY: TestClient lets us send fake HTTP requests to our FastAPI
# app without starting a real server. It simulates the browser
# or FreeRADIUS sending requests.
client = TestClient(app)


# ════════════════════════════════════════════════════════════
# TEST 1: POST /auth  (Authentication)
# ════════════════════════════════════════════════════════════

@patch("main.get_db")
def test_auth_accepts_valid_password(mock_get_db):
    """
    Test that /auth returns HTTP 204 (accept) when we send
    a valid username and password that matches the SHA-256 hash
    stored in the database.
    """
    # ── Arrange: set up fake database response ────────────
    # Create a fake cursor that returns a SHA-256 hash for "testpass123"
    test_password = "testpass123"
    stored_hash = sha256_hash(test_password)

    fake_cursor = MagicMock()
    # fetchall returns rows like: [{"attribute": "SHA-256-Password", "value": "hash..."}]
    fake_cursor.fetchall.return_value = [
        {"attribute": "SHA-256-Password", "value": stored_hash}
    ]

    # Make get_db() return a fake connection with our fake cursor
    fake_conn = MagicMock()
    fake_conn.cursor.return_value = fake_cursor
    mock_get_db.return_value = fake_conn

    # ── Act: send the auth request ────────────────────────
    response = client.post("/auth", data={
        "username": "testuser",
        "password": test_password,
    })

    # ── Assert: check that the response is "accept" ───────
    # 204 = rlm_rest interprets this as Access-Accept
    assert response.status_code == 204


@patch("main.get_db")
def test_auth_rejects_wrong_password(mock_get_db):
    """
    Test that /auth returns HTTP 401 (reject) when the password
    is wrong — the hash won't match what's in the database.
    """
    # Stored hash is for "testpass123", but we'll send "wrongpassword"
    stored_hash = sha256_hash("testpass123")

    fake_cursor = MagicMock()
    fake_cursor.fetchall.return_value = [
        {"attribute": "SHA-256-Password", "value": stored_hash}
    ]

    fake_conn = MagicMock()
    fake_conn.cursor.return_value = fake_cursor
    mock_get_db.return_value = fake_conn

    response = client.post("/auth", data={
        "username": "testuser",
        "password": "wrongpassword",
    })

    # 401 = rlm_rest interprets this as Access-Reject
    assert response.status_code == 401


# ════════════════════════════════════════════════════════════
# TEST 2: POST /authorize  (Authorization)
# ════════════════════════════════════════════════════════════

@patch("main.get_db")
def test_authorize_returns_vlan_attributes(mock_get_db):
    """
    Test that /authorize returns the correct JSON structure
    with VLAN attributes that rlm_rest expects.

    Expected format:
    {
        "control": { ... },
        "reply": {
            "Tunnel-Type": {"value": ["13"], "op": ":="},
            "Tunnel-Private-Group-Id": {"value": ["20"], "op": ":="}
        }
    }
    """
    # ── Arrange: fake DB returns user + group + VLAN data ─
    fake_cursor = MagicMock()

    # We need fetchone/fetchall to return different data on each call:
    #   1st call (radcheck)     → user exists with SHA-256 password
    #   2nd call (radusergroup) → user belongs to "employee" group
    #   3rd call (radgroupreply) → employee group gets VLAN 20
    fake_cursor.fetchone.side_effect = [
        # 1st fetchone: radcheck row
        {"attribute": "SHA-256-Password", "value": "somehash"},
        # 2nd fetchone: radusergroup row
        {"groupname": "employee"},
    ]
    fake_cursor.fetchall.return_value = [
        # radgroupreply rows for the "employee" group
        {"attribute": "Tunnel-Type", "value": "13"},
        {"attribute": "Tunnel-Medium-Type", "value": "6"},
        {"attribute": "Tunnel-Private-Group-Id", "value": "20"},
    ]

    fake_conn = MagicMock()
    fake_conn.cursor.return_value = fake_cursor
    mock_get_db.return_value = fake_conn

    # ── Act: send the authorize request ───────────────────
    response = client.post("/authorize", data={
        "username": "testuser",
    })

    # ── Assert: check response structure ──────────────────
    assert response.status_code == 200

    body = response.json()

    # Must have "control" and "reply" keys (rlm_rest requirement)
    assert "control" in body
    assert "reply" in body

    # The reply must contain VLAN attributes
    reply = body["reply"]
    assert "Tunnel-Type" in reply
    assert "Tunnel-Private-Group-Id" in reply

    # VLAN 20 for employee group
    assert reply["Tunnel-Private-Group-Id"]["value"] == ["20"]


# ════════════════════════════════════════════════════════════
# TEST 3: POST /accounting  (Accounting)
# ════════════════════════════════════════════════════════════

@patch("main.get_redis")
@patch("main.get_db")
def test_accounting_start_returns_204(mock_get_db, mock_get_redis):
    """
    Test that /accounting returns HTTP 204 (success) when we
    send an Accounting-Start packet. This tells FreeRADIUS
    that we successfully recorded the session.
    """
    # ── Arrange: fake DB and Redis ────────────────────────
    fake_cursor = MagicMock()
    fake_conn = MagicMock()
    fake_conn.cursor.return_value = fake_cursor
    mock_get_db.return_value = fake_conn

    fake_redis = MagicMock()
    mock_get_redis.return_value = fake_redis

    # ── Act: send an Accounting-Start packet ──────────────
    response = client.post("/accounting", data={
        "Acct-Status-Type": "Start",
        "username": "testuser",
        "Acct-Session-Id": "test-session-001",
        "Acct-Unique-Session-Id": "unique-001",
        "NAS-IP-Address": "10.0.0.1",
        "Calling-Station-Id": "AA:BB:CC:DD:EE:FF",
        "Framed-IP-Address": "192.168.1.100",
    })

    # ── Assert: 204 means rlm_rest treats it as "ok" ─────
    assert response.status_code == 204

    # Verify that the INSERT query was actually executed
    # (cursor.execute was called at least once)
    assert fake_cursor.execute.called

    # Verify that the session was cached in Redis
    assert fake_redis.set.called


# ════════════════════════════════════════════════════════════
# TEST 4: GET /health  (Health Check)
# ════════════════════════════════════════════════════════════

@patch("main.get_redis")
@patch("main.get_db")
def test_health_check(mock_get_db, mock_get_redis):
    """
    Test that /health returns 200 and shows all services as connected.
    This is the simplest test — good for verifying the test setup works.
    """
    # Fake a working DB connection
    mock_get_db.return_value = MagicMock()

    # Fake a working Redis connection
    fake_redis = MagicMock()
    fake_redis.ping.return_value = True
    mock_get_redis.return_value = fake_redis

    response = client.get("/health")

    assert response.status_code == 200

    body = response.json()
    assert body["api"] == "healthy"
    assert body["postgres"] == "connected"
    assert body["redis"] == "connected"
