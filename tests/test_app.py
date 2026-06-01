from io import BytesIO

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    return app.test_client()


@pytest.fixture(autouse=True)
def fake_gatekeeper(monkeypatch):
    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"narrative": "Gatekeeper narrative"}

    def post(url, json, headers, timeout):
        assert url.endswith("/verify-and-generate")
        assert json["license_key"]
        assert headers["Authorization"].startswith("Bearer ")
        assert len(headers["X-Payload-SHA256"]) == 64
        return Response()

    monkeypatch.setattr("narrative_logic.requests.post", post)


def test_healthz(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_admin_page(client):
    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Workspace Admin" in response.data


def test_index_has_nonce_csp(client):
    response = client.get("/")
    csp = response.headers["Content-Security-Policy"]

    assert response.status_code == 200
    assert "script-src" in csp
    assert "'nonce-" in csp
    assert "https://cdn.tailwindcss.com" in csp
    assert "https://cdnjs.cloudflare.com" in csp
    assert b'<script nonce="' in response.data
    assert b"Past Reports" in response.data
    assert b"indexedDB.open" in response.data
    assert b"Privacy & Security" in response.data


def test_app_has_no_upload_dir_config(client):
    assert "UPLOAD_DIR" not in client.application.config


def test_sample_report(client):
    response = client.get("/api/sample")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["stats"]["total_revenue"] == 13650.0
    assert payload["insights"][0]["title"] == "Highest ROAS day"


def test_sample_report_is_cached(client, monkeypatch):
    calls = 0

    def fake_analyze_data(path, license_key):
        nonlocal calls
        calls += 1
        return {"report": "cached sample", "license_key_seen": license_key}

    monkeypatch.setattr("app.analyze_data", fake_analyze_data)

    first_response = client.get("/api/sample?license_key=DEMO123")
    second_response = client.get("/api/sample?license_key=DEMO123")

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.get_json()["report"] == "cached sample"
    assert calls == 1


def test_upload_requires_file(client):
    response = client.post("/api/analyze", data={})

    assert response.status_code == 400
    assert "Upload a CSV" in response.get_json()["error"]


def test_upload_rejects_non_csv(client):
    response = client.post(
        "/api/analyze",
        data={"file": (BytesIO(b"not,csv"), "report.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Only CSV files are supported."


def test_upload_processes_csv_in_memory(client, monkeypatch):
    csv_bytes = (
        b"Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue\n"
        b"2026-05-01,Search,100,50,1000,5,300\n"
    )
    captured = {}

    def fake_analyze_data(source, license_key):
        captured["source"] = source
        captured["payload"] = source.getvalue()
        captured["license_key"] = license_key
        return {
            "stats": {"total_revenue": 300, "total_spend": 100, "avg_roas": 3, "total_conversions": 5},
            "insights": [],
            "daily_trends": [],
            "narrative": "In-memory report",
        }

    monkeypatch.setattr("app.analyze_data", fake_analyze_data)

    response = client.post(
        "/api/analyze",
        data={"file": (BytesIO(csv_bytes), "report.csv"), "license_key": "DEMO123"},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert isinstance(captured["source"], BytesIO)
    assert captured["payload"] == csv_bytes
    assert captured["license_key"] == "DEMO123"


def test_upload_valid_csv(client):
    csv_bytes = (
        b"Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue\n"
        b"2026-05-01,Search,100,50,1000,5,300\n"
        b"2026-05-02,Search,120,60,1200,8,400\n"
    )

    response = client.post(
        "/api/analyze",
        data={"file": (BytesIO(csv_bytes), "report.csv"), "license_key": "DEMO123"},
        content_type="multipart/form-data",
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["stats"]["total_spend"] == 220.0
    assert payload["stats"]["total_conversions"] == 13
