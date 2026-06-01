from io import BytesIO
from pathlib import Path

import pytest

import build_dist
import app as app_module
from app import create_app


DEVICE_HEADERS = {
    "X-Device-ID": "a" * 64,
    "X-Device-HMAC": "b" * 64,
    "X-Session-Token": "session.jwt",
}


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
        if json.get("hardware_id"):
            assert headers["X-Device-ID"] == json["hardware_id"]
            assert headers["X-Device-HMAC"] == json["device_hmac"]
            assert headers["X-Session-Token"] == json["session_token"]
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
    assert b"Stripe Payment Link" in response.data
    assert b"/api/business-settings" in response.data
    assert b"Payment Link" in response.data
    assert b"Audit" in response.data
    assert b"View Audit" in response.data
    assert b"Security & Compliance Health" in response.data
    assert b"Database Encryption" in response.data
    assert b"SAST Scan" in response.data
    assert b"IPS Blacklist" in response.data
    assert b"/api/compliance-health" in response.data
    assert b"narrativeai.localHistoryVault" in response.data
    assert b"Math anomaly detected" in response.data
    assert b"Session Monitor" in response.data
    assert b"Active Devices" in response.data
    assert b"Flagged Keys" in response.data
    assert b"/api/session-monitor" in response.data
    assert b"Sales & Leads" in response.data
    assert b"Generate 48h Demo Key" in response.data
    assert b"Agency Name" in response.data
    assert b"Pitched" in response.data
    assert b"Replied" in response.data
    assert b"Booked" in response.data
    assert b"Closed" in response.data
    assert b"/api/leads/add" in response.data
    assert b"/api/demo-key" in response.data


def test_index_has_nonce_csp(client):
    response = client.get("/")
    csp = response.headers["Content-Security-Policy"]

    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains; preload"
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
    assert b"/api/check-updates" in response.data
    assert b"appVersion" in response.data
    assert b"license-splash" in response.data
    assert b"startup-license-key" in response.data
    assert b"initialStripePaymentLink" in response.data
    assert b"Upgrade to Pro" in response.data
    assert b"dashboard-upgrade-link" in response.data
    assert b"forceHttpsUrl" in response.data
    assert b'href="/about"' in response.data
    assert b"/api/business-settings" in response.data
    assert b"A premium update is available." in response.data
    assert b"renderReportSkeleton" in response.data
    assert b"skeleton-stage-stats" in response.data
    assert b"skeleton-stage-chart" in response.data
    assert b"skeleton-stage-narrative" in response.data
    assert b"animation-delay: var(--skeleton-delay, 0s)" in response.data
    assert b"Elite Stability Notice" in response.data
    assert b"Strategic Directive" in response.data
    assert b"directive-tone" in response.data
    assert b"directive-goal" in response.data
    assert b"directive-business-type" in response.data
    assert b"Business Type" in response.data
    assert b"E-commerce" in response.data
    assert b"B2B SaaS" in response.data
    assert b"Local Service" in response.data
    assert b"Tweak this report..." in response.data
    assert b"/refine" in response.data
    assert b"Fact-Check Lock" in response.data
    assert b'id="mobile-menu-button"' in response.data
    assert b'aria-controls="builder-drawer"' in response.data
    assert b'id="builder-drawer"' in response.data
    assert b'id="drawer-backdrop"' in response.data
    assert b"setDrawerOpen" in response.data
    assert b"drawerMediaQuery" in response.data
    assert b'aria-label="Upload up to 3 marketing CSV files"' in response.data
    assert b"multiple" in response.data
    assert b"channel-badges" in response.data
    assert b"Channel Mix" in response.data
    assert b'aria-label="Copy narrative to clipboard"' in response.data
    assert b":focus-visible" in response.data
    assert b'aria-live="polite"' in response.data
    assert b"cpu_cores" in response.data
    assert b"screen_resolution" in response.data
    assert b"browser_engine" in response.data
    assert b"crypto.subtle.digest" in response.data
    assert b"X-Device-ID" in response.data
    assert b"X-Device-HMAC" in response.data
    assert b"renewSecureSession" in response.data
    assert b"Suggest a Feature" in response.data
    assert b'id="feedback-panel"' in response.data
    assert b"/api/feedback" in response.data
    assert b"submitStrategistFeedback" in response.data


def test_about_page_contains_elite_privacy_guarantee(client):
    response = client.get("/about")

    assert response.status_code == 200
    assert b"Elite Privacy Guarantee" in response.data
    assert b"Zero raw CSV retention" in response.data
    assert b"Local report ownership" in response.data
    assert b"Protected access boundary" in response.data


def test_domain_url_forces_https_in_production(monkeypatch):
    monkeypatch.delenv("GATEKEEPER_URL", raising=False)
    monkeypatch.delenv("GATEKEEPER_PUBLIC_URL", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DOMAIN_URL", "http://narrativeai-gatekeeper.onrender.com")

    assert app_module._gatekeeper_url() == "https://narrativeai-gatekeeper.onrender.com"


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


def test_session_monitor_proxy(client, monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "ok": True,
                "active_devices": [{"device_fingerprint": "device-abc"}],
                "alerts": [{"alert_type": "hardware_lock_violation"}],
                "active_device_count": 1,
                "alert_count": 1,
            }

    def get(url, timeout):
        assert url == "http://gatekeeper.test/admin/session-monitor"
        assert timeout == 1.5
        return Response()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.get", get)

    response = client.get("/api/session-monitor")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["active_device_count"] == 1
    assert payload["alerts"][0]["alert_type"] == "hardware_lock_violation"


def test_sales_leads_and_demo_key_proxies(client, monkeypatch):
    class GetResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "ok": True,
                "leads": [
                    {
                        "agency_name": "Northstar Media",
                        "contact": "owner@example.com",
                        "status": "Pitched",
                        "notes": "Send demo",
                    }
                ],
            }

    class PostResponse:
        status_code = 201

        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def get(url, timeout):
        assert url == "http://gatekeeper.test/admin/leads"
        assert timeout == 1.5
        return GetResponse()

    def post(url, json, timeout):
        assert timeout == 1.5
        if url == "http://gatekeeper.test/admin/leads/add":
            assert json["agency_name"] == "Northstar Media"
            return PostResponse({"ok": True, "lead": json, "leads": [json]})
        if url == "http://gatekeeper.test/admin/demo-key":
            assert json == {"hours": 48}
            return PostResponse(
                {
                    "ok": True,
                    "demo_key": {
                        "license_key": "DEMO-ABC",
                        "expires_at": "2026-06-03T00:00:00+00:00",
                        "duration_hours": 48,
                    },
                }
            )
        raise AssertionError(url)

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.get", get)
    monkeypatch.setattr("app.requests.post", post)

    leads_response = client.get("/api/leads")
    add_response = client.post(
        "/api/leads/add",
        json={
            "agency_name": "Northstar Media",
            "contact": "owner@example.com",
            "status": "Pitched",
            "notes": "Send demo",
        },
    )
    demo_response = client.post("/api/demo-key")

    assert leads_response.status_code == 200
    assert leads_response.get_json()["leads"][0]["agency_name"] == "Northstar Media"
    assert add_response.status_code == 201
    assert add_response.get_json()["lead"]["status"] == "Pitched"
    assert demo_response.status_code == 201
    assert demo_response.get_json()["demo_key"]["duration_hours"] == 48


def test_business_settings_proxy_get_and_post(client, monkeypatch):
    class GetResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True, "settings": {"stripe_payment_link": "https://buy.stripe.com/test"}}

    class PostResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True, "settings": {"stripe_payment_link": "https://buy.stripe.com/new"}}

    def get(url, timeout):
        assert url == "http://gatekeeper.test/admin/business-settings"
        assert timeout == 1.5
        return GetResponse()

    def post(url, json, timeout):
        assert url == "http://gatekeeper.test/admin/business-settings"
        assert json == {"stripe_payment_link": "https://buy.stripe.com/new"}
        assert timeout == 1.5
        return PostResponse()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.get", get)
    monkeypatch.setattr("app.requests.post", post)

    get_response = client.get("/api/business-settings")
    post_response = client.post("/api/business-settings", json={"stripe_payment_link": "https://buy.stripe.com/new"})

    assert get_response.status_code == 200
    assert get_response.get_json()["settings"]["stripe_payment_link"] == "https://buy.stripe.com/test"
    assert post_response.status_code == 200
    assert post_response.get_json()["settings"]["stripe_payment_link"] == "https://buy.stripe.com/new"


def test_check_updates_proxy(client, monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "ok": True,
                "current_version": "1.0.0",
                "latest_version": "1.1.0",
                "update_available": True,
                "message": "A premium update is available.",
            }

    def post(url, json, timeout):
        assert url == "http://gatekeeper.test/check-updates"
        assert json == {"current_version": "1.0.0"}
        assert timeout == 1.5
        return Response()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.post", post)

    response = client.post("/api/check-updates")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["update_available"] is True
    assert payload["message"] == "A premium update is available."


def test_strategist_feedback_proxy(client, monkeypatch):
    class Response:
        status_code = 202

        def raise_for_status(self):
            return None

        def json(self):
            return {"ok": True, "status": "received", "forwarded": False}

    captured = {}

    def post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("app.requests.post", post)

    response = client.post(
        "/api/feedback",
        json={
            "message": "Add a monthly export board.",
            "email": "owner@example.com",
            "license_key": "DEMO123",
            "page": "/",
        },
    )
    payload = response.get_json()

    assert response.status_code == 202
    assert payload["ok"] is True
    assert captured["url"] == "http://gatekeeper.test/feedback"
    assert captured["timeout"] == 2.0
    assert captured["json"]["message"] == "Add a monthly export board."
    assert captured["json"]["app_version"] == "1.0.0"


def test_app_has_no_upload_dir_config(client):
    assert "UPLOAD_DIR" not in client.application.config


def test_build_dist_uses_windowed_pyinstaller_bundle():
    command = build_dist.build_command()
    joined = " ".join(str(part) for part in command)

    assert "-m PyInstaller" in joined
    assert "--onefile" in command
    assert "--windowed" in command
    assert "templates" in joined
    assert "static" in joined
    assert "dummy_marketing_data.csv" in joined


def test_launch_assets_exist():
    root = Path(__file__).resolve().parents[1]
    launch_assets = root / "logic" / "launch_assets.md"
    landing_prompt = root / "landing_page_prompt.txt"
    business_plan = root / "BUSINESS_PLAN.md"

    assert (root / "launch_assets" / "linkedin_scripts.md").exists()
    assert (root / "launch_assets" / "twitter_hooks.md").exists()
    assert (root / "launch_assets" / "demo_script.md").exists()
    assert (root / "launch_assets" / "refined_scripts.md").exists()
    assert "Elite AGENCY Hook" in launch_assets.read_text()
    assert "Privacy-First" in launch_assets.read_text()
    assert "60-Second Demo Script" in launch_assets.read_text()
    assert "Emergent App Builder" in landing_prompt.read_text()
    assert "Demo-based Closing" in business_plan.read_text()
    refined_scripts = (root / "launch_assets" / "refined_scripts.md").read_text()
    assert "Loss Aversion Pitch" in refined_scripts
    assert "Strategic Alliance Pitch" in refined_scripts


def test_sample_report(client):
    response = client.get("/api/sample")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["stats"]["total_revenue"] == 13650.0
    assert payload["insights"][0]["title"] == "Highest ROAS day"


def test_sample_report_is_cached(client, monkeypatch):
    calls = 0

    def fake_analyze_data(path, license_key, device_auth=None):
        nonlocal calls
        calls += 1
        return {"report": "cached sample", "license_key_seen": license_key, "device_auth_seen": device_auth}

    monkeypatch.setattr("app.analyze_data", fake_analyze_data)

    first_response = client.get("/api/sample?license_key=DEMO123", headers=DEVICE_HEADERS)
    second_response = client.get("/api/sample?license_key=DEMO123", headers=DEVICE_HEADERS)

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.get_json()["report"] == "cached sample"
    assert second_response.get_json()["device_auth_seen"]["hardware_id"] == DEVICE_HEADERS["X-Device-ID"]
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

    def fake_analyze_data(source, license_key, directive=None, device_auth=None):
        captured["source"] = source
        captured["payload"] = source[0]["source"].getvalue()
        captured["filename"] = source[0]["filename"]
        captured["license_key"] = license_key
        captured["directive"] = directive
        captured["device_auth"] = device_auth
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
            "business_type": "Local Service",
        },
        content_type="multipart/form-data",
        headers=DEVICE_HEADERS,
    )

    assert response.status_code == 200
    assert isinstance(captured["source"][0]["source"], BytesIO)
    assert captured["payload"] == csv_bytes
    assert captured["filename"] == "report.csv"
    assert captured["license_key"] == "DEMO123"
    assert captured["directive"] == {
        "tone": "Persuasive",
        "goal": "Budget Request",
        "business_type": "Local Service",
    }
    assert captured["device_auth"]["hardware_id"] == DEVICE_HEADERS["X-Device-ID"]


def test_upload_accepts_up_to_three_channel_csvs(client, monkeypatch):
    google_bytes = (
        b"Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue\n"
        b"2026-05-01,Search,100,50,1000,5,300\n"
    )
    meta_bytes = (
        b"Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue\n"
        b"2026-05-01,Awareness,80,40,2000,3,160\n"
    )
    captured = {}

    def fake_analyze_data(source, license_key, directive=None, device_auth=None):
        captured["filenames"] = [item["filename"] for item in source]
        captured["payloads"] = [item["source"].getvalue() for item in source]
        return {
            "stats": {"total_revenue": 460, "total_spend": 180, "avg_roas": 2.56, "blended_roas": 2.56, "total_conversions": 8},
            "channel_metrics": [],
            "insights": [],
            "daily_trends": [],
            "directive": directive,
            "narrative": "Multi-channel report",
        }

    monkeypatch.setattr("app.analyze_data", fake_analyze_data)

    response = client.post(
        "/api/analyze",
        data={
            "file": [
                (BytesIO(google_bytes), "google_ads.csv"),
                (BytesIO(meta_bytes), "meta.csv"),
            ],
            "license_key": "DEMO123",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert captured["filenames"] == ["google_ads.csv", "meta.csv"]
    assert captured["payloads"] == [google_bytes, meta_bytes]


def test_upload_rejects_more_than_three_csvs(client):
    csv_bytes = (
        b"Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue\n"
        b"2026-05-01,Search,100,50,1000,5,300\n"
    )

    response = client.post(
        "/api/analyze",
        data={
            "file": [
                (BytesIO(csv_bytes), "one.csv"),
                (BytesIO(csv_bytes), "two.csv"),
                (BytesIO(csv_bytes), "three.csv"),
                (BytesIO(csv_bytes), "four.csv"),
            ],
            "license_key": "DEMO123",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "up to 3" in response.get_json()["error"]


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

    def fake_refine_report(stats, narrative, instruction, license_key, directive=None, report_id=None, device_auth=None):
        captured["stats"] = stats
        captured["narrative"] = narrative
        captured["instruction"] = instruction
        captured["license_key"] = license_key
        captured["directive"] = directive
        captured["report_id"] = report_id
        captured["device_auth"] = device_auth
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
            "directive": {"tone": "Precise", "goal": "Retention", "business_type": "B2B SaaS"},
            "report_id": "report-123",
        },
        headers=DEVICE_HEADERS,
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["model"] == "gpt-4o-mini"
    assert payload["fact_check_locked"] is True
    assert captured["license_key"] == "DEMO123"
    assert captured["instruction"] == "Make it sharper"
    assert captured["directive"] == {"tone": "Precise", "goal": "Retention", "business_type": "B2B SaaS"}
    assert captured["report_id"] == "report-123"
    assert captured["device_auth"]["hardware_id"] == DEVICE_HEADERS["X-Device-ID"]
