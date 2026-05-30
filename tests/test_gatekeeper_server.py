from gatekeeper_server import create_app


def test_gatekeeper_rejects_invalid_license():
    client = create_app().test_client()

    response = client.post(
        "/verify-and-generate",
        json={"stats": {}, "license_key": "BADKEY"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Invalid license key."


def test_gatekeeper_valid_license_returns_narrative_without_local_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("EMERGENT_LLM_KEY", raising=False)
    client = create_app().test_client()

    response = client.post(
        "/verify-and-generate",
        json={
            "license_key": "DEMO123",
            "stats": {
                "total_revenue": 1000,
                "total_spend": 250,
                "avg_roas": 4,
                "total_conversions": 10,
                "top_campaign": "Search",
            },
        },
    )

    payload = response.get_json()

    assert response.status_code == 200
    assert "narrative" in payload
    assert "Gatekeeper verified" in payload["narrative"]
