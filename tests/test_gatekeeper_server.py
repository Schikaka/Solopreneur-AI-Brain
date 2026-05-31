import pytest

from gatekeeper_server import create_app
from security_tokens import authorization_header, gatekeeper_payload, payload_hash


@pytest.fixture(autouse=True)
def secure_gatekeeper_env(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "testing")
    monkeypatch.setenv("DATABASE_ENCRYPTION_KEY", "test-database-encryption-key")
    monkeypatch.setenv("GATEKEEPER_JWT_SECRET", "test-gatekeeper-jwt-secret")
    monkeypatch.setenv("LICENSE_DB_PATH", str(tmp_path / "database.db"))
    monkeypatch.setenv("LICENSE_SEED_KEYS", "DEMO123,TEST456")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("EMERGENT_LLM_KEY", raising=False)


def signed_headers(payload):
    return {
        "Authorization": authorization_header(payload),
        "X-Payload-SHA256": payload_hash(payload),
    }


def post_signed(client, license_key, stats=None):
    payload = gatekeeper_payload(stats if stats is not None else {}, license_key)
    return client.post("/verify-and-generate", json=payload, headers=signed_headers(payload))


def test_gatekeeper_rejects_invalid_license():
    client = create_app().test_client()

    response = post_signed(client, "BADKEY")

    assert response.status_code == 403
    assert response.get_json()["error"] == "Invalid license key."


def test_gatekeeper_requires_signed_request():
    client = create_app().test_client()

    response = client.post(
        "/verify-and-generate",
        json={"stats": {}, "license_key": "DEMO123"},
    )

    assert response.status_code == 401
    assert "token" in response.get_json()["error"].lower()


def test_gatekeeper_rejects_payload_hash_mismatch():
    client = create_app().test_client()
    payload = gatekeeper_payload({}, "DEMO123")
    headers = signed_headers(payload)
    headers["X-Payload-SHA256"] = "0" * 64

    response = client.post("/verify-and-generate", json=payload, headers=headers)

    assert response.status_code == 401
    assert "hash" in response.get_json()["error"].lower()


def test_gatekeeper_index_page_is_visible():
    client = create_app().test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Gatekeeper Online" in response.data
    assert b"Verify And Generate" in response.data


def test_gatekeeper_valid_license_returns_narrative_without_local_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("EMERGENT_LLM_KEY", raising=False)
    client = create_app().test_client()

    response = post_signed(
        client,
        "DEMO123",
        {
            "total_revenue": 1000,
            "total_spend": 250,
            "avg_roas": 4,
            "total_conversions": 10,
            "top_campaign": "Search",
        },
    )

    payload = response.get_json()

    assert response.status_code == 200
    assert "narrative" in payload
    assert "Gatekeeper verified" in payload["narrative"]


def test_gatekeeper_limits_reports_per_minute(monkeypatch):
    monkeypatch.setenv("GATEKEEPER_REPORTS_PER_MINUTE", "5")
    client = create_app().test_client()
    stats = {
        "total_revenue": 1000,
        "total_spend": 250,
        "avg_roas": 4,
        "total_conversions": 10,
        "top_campaign": "Search",
    }

    responses = [post_signed(client, "DEMO123", stats) for _ in range(6)]

    assert [response.status_code for response in responses[:5]] == [200] * 5
    assert responses[5].status_code == 429
    assert "Too many" in responses[5].get_json()["error"]
