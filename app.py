import io
import os
import sys
from hashlib import sha256
from pathlib import Path
from secrets import token_urlsafe

import requests
from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from narrative_logic import analyze_data, refine_report, sanitize_directive


BASE_DIR = Path(__file__).parent
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")


def resource_path(*parts):
    base_dir = Path(getattr(sys, "_MEIPASS", BASE_DIR))
    return base_dir.joinpath(*parts)


DEFAULT_SAMPLE_PATH = resource_path("dummy_marketing_data.csv")
ALLOWED_EXTENSIONS = {".csv"}
DEFAULT_GATEKEEPER_URL = "http://localhost:5001"
DEFAULT_RENDER_URL = "https://narrativeai-gatekeeper.onrender.com"
STABILITY_NOTICE = (
    "Our AI systems are currently optimizing resources. Your report has been prioritized. "
    "Please wait 30 seconds and retry."
)


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


def _render_domain_url():
    hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
    if hostname:
        return f"https://{hostname}"
    if os.getenv("RENDER"):
        return DEFAULT_RENDER_URL
    return ""


def _normalize_service_url(value):
    normalized = str(value or "").strip().rstrip("/")
    if not normalized:
        return ""
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    if (
        os.getenv("APP_ENV") == "production"
        and normalized.startswith("http://")
        and "localhost" not in normalized
        and "127.0.0.1" not in normalized
    ):
        normalized = f"https://{normalized.removeprefix('http://')}"
    return normalized.rstrip("/")


def _gatekeeper_url():
    return _normalize_service_url(
        os.getenv("GATEKEEPER_URL")
        or os.getenv("GATEKEEPER_PUBLIC_URL")
        or os.getenv("DOMAIN_URL")
        or _render_domain_url()
        or DEFAULT_GATEKEEPER_URL
    )


def _default_business_settings():
    return {"stripe_payment_link": os.getenv("STRIPE_PAYMENT_LINK", "").strip()}


def _device_auth_from_request():
    return {
        "hardware_id": request.headers.get("X-Device-ID", "").strip(),
        "device_hmac": request.headers.get("X-Device-HMAC", "").strip(),
        "session_token": request.headers.get("X-Session-Token", "").strip(),
    }


def create_app(test_config=None):
    app = Flask(
        __name__,
        template_folder=str(resource_path("templates")),
        static_folder=str(resource_path("static")),
    )
    app_env = os.getenv("APP_ENV", "development")
    max_upload_mb = _env_int("MAX_UPLOAD_MB", 8)
    secret_key = os.getenv("SECRET_KEY", "development-secret-change-me")

    if app_env == "production" and secret_key in {"", "change-me-before-deploy"}:
        raise RuntimeError("SECRET_KEY must be set before running in production.")

    app.config.from_mapping(
        APP_ENV=app_env,
        MAX_CONTENT_LENGTH=max_upload_mb * 1024 * 1024,
        SAMPLE_CSV_PATH=Path(os.getenv("SAMPLE_CSV_PATH", DEFAULT_SAMPLE_PATH)),
        SECRET_KEY=secret_key,
        APP_VERSION=os.getenv("APP_VERSION", APP_VERSION),
    )

    if test_config:
        app.config.update(test_config)

    sample_report_cache = {}

    @app.before_request
    def create_csp_nonce():
        g.csp_nonce = token_urlsafe(16)

    @app.context_processor
    def inject_security_context():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.after_request
    def add_security_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "script-src-attr 'none'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        if request.path.startswith("/api/") or request.path == "/refine":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_upload(error):
        return jsonify({"error": "CSV upload is too large.", "stability_notice": STABILITY_NOTICE}), 413

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(500)
    def handle_server_error(error):
        app.logger.exception("Unhandled server error")
        return jsonify({"error": "Unexpected server error.", "stability_notice": STABILITY_NOTICE}), 500

    @app.get("/healthz")
    @app.get("/HEALTHZ")
    def health_check():
        return jsonify({"status": "ok"})

    @app.get("/api/system-status")
    def system_status():
        status_payload = {
            "status": "ready",
            "app": "ok",
            "gatekeeper": "ok",
            "message": "System Ready",
        }

        try:
            gatekeeper_response = requests.get(f"{_gatekeeper_url()}/healthz", timeout=1.5)
            gatekeeper_response.raise_for_status()
        except Exception:
            status_payload.update(
                {
                    "status": "degraded",
                    "gatekeeper": "degraded",
                    "message": "System Degraded",
                    "stability_notice": STABILITY_NOTICE,
                }
            )

        return jsonify(status_payload)

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            app_version=app.config["APP_VERSION"],
            stripe_payment_link=_default_business_settings()["stripe_payment_link"],
        )

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/admin")
    def admin():
        gatekeeper_url = _gatekeeper_url()
        return render_template("admin.html", gatekeeper_url=gatekeeper_url)

    @app.get("/api/business-settings")
    def business_settings():
        try:
            response = requests.get(f"{_gatekeeper_url()}/admin/business-settings", timeout=1.5)
            response.raise_for_status()
            return jsonify(response.json())
        except Exception:
            return jsonify(
                {
                    "ok": False,
                    "settings": _default_business_settings(),
                    "error": "Business settings are unavailable.",
                }
            ), 503

    @app.post("/api/business-settings")
    def save_business_settings():
        payload = request.get_json(silent=True) or {}
        try:
            response = requests.post(
                f"{_gatekeeper_url()}/admin/business-settings",
                json={"stripe_payment_link": str(payload.get("stripe_payment_link", "")).strip()},
                timeout=1.5,
            )
            response.raise_for_status()
            return jsonify(response.json())
        except requests.HTTPError:
            error_payload = {}
            try:
                error_payload = response.json()
            except Exception:
                error_payload = {"error": "Business settings could not be saved."}
            return jsonify(error_payload), response.status_code
        except Exception:
            return jsonify({"error": "Business settings could not be saved."}), 503

    @app.get("/api/leads")
    def leads():
        try:
            response = requests.get(f"{_gatekeeper_url()}/admin/leads", timeout=1.5)
            response.raise_for_status()
            return jsonify(response.json())
        except Exception:
            return jsonify({"ok": False, "leads": [], "error": "Lead tracker is unavailable."}), 503

    @app.post("/api/leads/add")
    def add_lead():
        payload = request.get_json(silent=True) or {}
        try:
            response = requests.post(
                f"{_gatekeeper_url()}/admin/leads/add",
                json={
                    "agency_name": str(payload.get("agency_name", "")).strip(),
                    "contact": str(payload.get("contact", "")).strip(),
                    "status": str(payload.get("status", "")).strip(),
                    "notes": str(payload.get("notes", "")).strip(),
                },
                timeout=1.5,
            )
            response.raise_for_status()
            return jsonify(response.json()), response.status_code
        except requests.HTTPError:
            error_payload = {}
            try:
                error_payload = response.json()
            except Exception:
                error_payload = {"error": "Lead could not be saved."}
            return jsonify(error_payload), response.status_code
        except Exception:
            return jsonify({"error": "Lead could not be saved."}), 503

    @app.post("/api/demo-key")
    def demo_key():
        try:
            response = requests.post(f"{_gatekeeper_url()}/admin/demo-key", json={"hours": 48}, timeout=1.5)
            response.raise_for_status()
            return jsonify(response.json()), response.status_code
        except requests.HTTPError:
            error_payload = {}
            try:
                error_payload = response.json()
            except Exception:
                error_payload = {"error": "Demo key could not be generated."}
            return jsonify(error_payload), response.status_code
        except Exception:
            return jsonify({"error": "Demo key could not be generated."}), 503

    @app.post("/api/check-updates")
    def check_updates():
        payload = {"current_version": app.config["APP_VERSION"]}
        try:
            response = requests.post(f"{_gatekeeper_url()}/check-updates", json=payload, timeout=1.5)
            response.raise_for_status()
            return jsonify(response.json())
        except Exception:
            return jsonify(
                {
                    "ok": False,
                    "update_available": False,
                    "current_version": app.config["APP_VERSION"],
                    "error": "Update check is unavailable.",
                }
            ), 503

    @app.get("/api/compliance-health")
    def compliance_health():
        try:
            response = requests.get(f"{_gatekeeper_url()}/admin/compliance-health", timeout=1.5)
            response.raise_for_status()
            return jsonify(response.json())
        except Exception:
            return jsonify(
                {
                    "ok": False,
                    "status": "degraded",
                    "checks": {
                        "database_encryption": {
                            "ok": False,
                            "status": "unavailable",
                            "detail": "Gatekeeper compliance endpoint is unavailable.",
                        },
                        "sast_scan": {
                            "ok": False,
                            "status": "unavailable",
                            "detail": "Gatekeeper compliance endpoint is unavailable.",
                        },
                        "ips_blacklist": {
                            "ok": False,
                            "status": "unavailable",
                            "detail": "Gatekeeper compliance endpoint is unavailable.",
                            "count": 0,
                        },
                    },
                    "ips_blacklist_count": 0,
                    "stability_notice": STABILITY_NOTICE,
                }
            ), 503

    @app.get("/api/session-monitor")
    def session_monitor():
        try:
            response = requests.get(f"{_gatekeeper_url()}/admin/session-monitor", timeout=1.5)
            response.raise_for_status()
            return jsonify(response.json())
        except Exception:
            return jsonify(
                {
                    "ok": False,
                    "active_devices": [],
                    "alerts": [],
                    "active_device_count": 0,
                    "alert_count": 0,
                    "error": "Session Monitor is unavailable.",
                    "stability_notice": STABILITY_NOTICE,
                }
            ), 503

    @app.get("/api/sample")
    def sample_report():
        license_key = request.args.get("license_key") or os.getenv("DEMO_LICENSE_KEY", "DEMO123")
        device_auth = _device_auth_from_request()
        sample_path = Path(app.config["SAMPLE_CSV_PATH"])
        try:
            sample_fingerprint = sample_path.stat().st_mtime_ns
            resolved_sample_path = str(sample_path.resolve())
        except OSError:
            sample_fingerprint = None
            resolved_sample_path = str(sample_path)

        license_hash = sha256(str(license_key).encode("utf-8")).hexdigest()
        device_hash = sha256(str(device_auth.get("hardware_id", "")).encode("utf-8")).hexdigest()
        cache_key = (resolved_sample_path, sample_fingerprint, license_hash, device_hash)
        if cache_key in sample_report_cache:
            return jsonify(sample_report_cache[cache_key])

        try:
            report = analyze_data(sample_path, license_key=license_key, device_auth=device_auth)
            if len(sample_report_cache) > 16:
                sample_report_cache.clear()
            sample_report_cache[cache_key] = report
            return jsonify(report)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except Exception as exc:
            app.logger.exception("Sample analysis failed")
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/analyze")
    def analyze_upload():
        uploaded_files = [
            uploaded_file
            for uploaded_file in request.files.getlist("file")
            if uploaded_file and uploaded_file.filename
        ]
        if not uploaded_files:
            return jsonify({"error": "Upload a CSV file to analyze."}), 400
        if len(uploaded_files) > 3:
            return jsonify({"error": "Upload up to 3 CSV files for one strategic attribution report."}), 400

        for uploaded_file in uploaded_files:
            filename = uploaded_file.filename or ""
            extension = Path(filename).suffix.lower()
            if extension not in ALLOWED_EXTENSIONS:
                return jsonify({"error": "Only CSV files are supported."}), 400

        license_key = request.form.get("license_key", "").strip()
        if not license_key:
            return jsonify({"error": "Enter a valid license key to generate reports."}), 403
        device_auth = _device_auth_from_request()
        directive = sanitize_directive(
            {
                "tone": request.form.get("tone", ""),
                "goal": request.form.get("goal", ""),
            }
        )

        csv_sources = []
        try:
            for uploaded_file in uploaded_files:
                csv_bytes = uploaded_file.read()
                if not csv_bytes:
                    return jsonify({"error": f"{uploaded_file.filename} is empty."}), 400
                csv_sources.append(
                    {
                        "source": io.BytesIO(csv_bytes),
                        "filename": uploaded_file.filename,
                    }
                )
            return jsonify(
                analyze_data(
                    csv_sources,
                    license_key=license_key,
                    directive=directive,
                    device_auth=device_auth,
                )
            )
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except Exception as exc:
            app.logger.exception("Uploaded CSV analysis failed")
            return jsonify({"error": str(exc)}), 400
        finally:
            for uploaded_file in uploaded_files:
                uploaded_file.close()
            csv_sources = []

    @app.post("/refine")
    def refine():
        payload = request.get_json(silent=True) or {}
        license_key = str(payload.get("license_key", "")).strip()
        stats = payload.get("stats")
        narrative = str(payload.get("narrative", "")).strip()
        instruction = str(payload.get("instruction", "")).strip()
        directive = sanitize_directive(payload.get("directive"))
        report_id = str(payload.get("report_id", "")).strip()
        device_auth = _device_auth_from_request()

        if not license_key:
            return jsonify({"error": "Enter a valid license key to refine reports."}), 403
        if not isinstance(stats, dict):
            return jsonify({"error": "Stats payload must be a JSON object."}), 400
        if not narrative:
            return jsonify({"error": "Original narrative is required."}), 400
        if not instruction:
            return jsonify({"error": "Refinement instruction is required."}), 400

        try:
            return jsonify(
                refine_report(
                    stats,
                    narrative,
                    instruction,
                    license_key,
                    directive=directive,
                    report_id=report_id or None,
                    device_auth=device_auth,
                )
            )
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except Exception as exc:
            app.logger.exception("Report refinement failed")
            return jsonify({"error": str(exc), "stability_notice": STABILITY_NOTICE}), 400

    return app


app = create_app()


if __name__ == "__main__":
    port = _env_int("PORT", 5000)
    debug = False if os.getenv("APP_ENV") == "production" else os.getenv("FLASK_DEBUG", "0") == "1"
    default_host = "0.0.0.0" if os.getenv("APP_ENV") == "production" or os.getenv("RENDER") else "127.0.0.1"
    app.run(host=os.getenv("HOST", default_host), port=port, debug=debug)
