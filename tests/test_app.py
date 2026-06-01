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
    assert b"Audit" in response.data
    assert b"View Audit" in response.data
    assert b"Security & Compliance Health" in response.data
    assert b"Database Encryption" in response.data
    assert b"SAST Scan" in response.data
    assert b"IPS Blacklist" in response.data
    assert b"/api/compliance-health" in response.data
    assert b"narrativeai.localHistoryVault" in response.data
    assert b"Math anomaly detected" in response.data


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
    assert b"System Checking" in response.data
    assert b'role="status" aria-label="System heartbeat status" aria-live="polite"' in response.data
    assert b"/api/system-status" in response.data
    assert b"renderReportSkeleton" in response.data
    assert b"skeleton-stage-stats" in response.data
    assert b"skeleton-stage-chart" in response.data
    assert b"skeleton-stage-narrative" in response.data
    assert b"animation-delay: var(--skeleton-delay, 0s)" in response.data
    assert b"Elite Stability Notice" in response.data
    assert b"Strategic Directive" in response.data
    assert b"directive-tone" in response.data
    assert b"directive-goal" in response.data
    assert b"Tweak this report..." in response.data
    assert b"/refine" in response.data
    assert b"Fact-Check Lock" in response.data
    assert b'id="mobile-menu-button"' in response.data
    assert b'aria-controls="builder-drawer"' in response.data
    assert b'id="builder-drawer"' in response.data
    assert b'id="drawer-backdrop"' in response.data
    assert b"setDrawerOpen" in response.data
    assert b"drawerMediaQuery" in response.data
    assert b'aria-label="Upload marketing CSV"' in response.data
    assert b'aria-label="Copy narrative to clipboard"' in response.data
    assert b":focus-visible" in response.data
    assert b'aria-live="polite"' in response.data


def test_system_status_ready(client, monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

    def get(url, timeout):
        assert url == "http://gatekeeper.test/healthz"
        assert timeout == 1.5
        return Response()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.get", get)

    response = client.get("/api/system-status")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "ready"
    assert payload["message"] == "System Ready"
    assert payload["gatekeeper"] == "ok"


def test_system_status_degraded_when_gatekeeper_is_unavailable(client, monkeypatch):
    def get(url, timeout):
        raise TimeoutError("offline")

    monkeypatch.setattr("app.requests.get", get)

    response = client.get("/api/system-status")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "degraded"
    assert payload["message"] == "System Degraded"
    assert "optimizing resources" in payload["stability_notice"]


def test_compliance_health_proxy(client, monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "ok": True,
                "checks": {
                    "database_encryption": {"ok": True, "status": "encrypted"},
                    "sast_scan": {"ok": True, "status": "passed"},
                    "ips_blacklist": {"ok": True, "status": "active", "count": 0},
                },
                "ips_blacklist_count": 0,
            }

    def get(url, timeout):
        assert url == "http://gatekeeper.test/admin/compliance-health"
        assert timeout == 1.5
        return Response()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.get", get)

    response = client.get("/api/compliance-health")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["ok"] is True
    assert payload["checks"]["sast_scan"]["status"] == "passed"


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

    def fake_analyze_data(source, license_key, directive=None):
        captured["source"] = source
        captured["payload"] = source.getvalue()
        captured["license_key"] = license_key
        captured["directive"] = directive
        return {
            "stats": {"total_revenue": 300, "total_spend": 100, "avg_roas": 3, "total_conversions": 5},
            "insights": [],
            "daily_trends": [],
            "directive": directive,
            "narrative": "In-memory report",
        }

    monkeypatch.setattr("app.analyze_data", fake_analyze_data)

    response = client.post(
        "/api/analyze",
        data={
            "file": (BytesIO(csv_bytes), "report.csv"),
            "license_key": "DEMO123",
            "tone": "Persuasive",
            "goal": "Budget Request",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert isinstance(captured["source"], BytesIO)
    assert captured["payload"] == csv_bytes
    assert captured["license_key"] == "DEMO123"
    assert captured["directive"] == {"tone": "Persuasive", "goal": "Budget Request"}


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


def test_refine_route_calls_refinement_backend(client, monkeypatch):
    captured = {}

    def fake_refine_report(stats, narrative, instruction, license_key, directive=None, report_id=None):
        captured["stats"] = stats
        captured["narrative"] = narrative
        captured["instruction"] = instruction
        captured["license_key"] = license_key
        captured["directive"] = directive
        captured["report_id"] = report_id
        return {
            "narrative": "Refined narrative",
            "model": "gpt-4o-mini",
            "fact_check_locked": True,
        }

    monkeypatch.setattr("app.refine_report", fake_refine_report)

    response = client.post(
        "/refine",
        json={
            "license_key": "DEMO123",
            "stats": {"total_revenue": 300, "total_spend": 100, "avg_roas": 3},
            "narrative": "Original narrative",
            "instruction": "Make it sharper",
            "directive": {"tone": "Precise", "goal": "Retention"},
            "report_id": "report-123",
        },
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["model"] == "gpt-4o-mini"
    assert payload["fact_check_locked"] is True
    assert captured["license_key"] == "DEMO123"
    assert captured["instruction"] == "Make it sharper"
    assert captured["directive"] == {"tone": "Precise", "goal": "Retention"}
    assert captured["report_id"] == "report-123"
