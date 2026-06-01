import io
import os
from hashlib import sha256
from pathlib import Path
from secrets import token_urlsafe

import requests
from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from narrative_logic import analyze_data


BASE_DIR = Path(__file__).parent
DEFAULT_SAMPLE_PATH = BASE_DIR / "dummy_marketing_data.csv"
ALLOWED_EXTENSIONS = {".csv"}
STABILITY_NOTICE = (
    "Our AI systems are currently optimizing resources. Your report has been prioritized. "
    "Please wait 30 seconds and retry."
)


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


def create_app(test_config=None):
    app = Flask(__name__)
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
        if request.path.startswith("/api/"):
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
    def health_check():
        return jsonify({"status": "ok"})

    @app.get("/api/system-status")
    def system_status():
        gatekeeper_url = os.getenv("GATEKEEPER_URL", "http://localhost:5001").rstrip("/")
        status_payload = {
            "status": "ready",
            "app": "ok",
            "gatekeeper": "ok",
            "message": "System Ready",
        }

        try:
            gatekeeper_response = requests.get(f"{gatekeeper_url}/healthz", timeout=1.5)
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
        return render_template("index.html")

    @app.route("/admin")
    def admin():
        return render_template("admin.html")

    @app.get("/api/sample")
    def sample_report():
        license_key = request.args.get("license_key") or os.getenv("DEMO_LICENSE_KEY", "DEMO123")
        sample_path = Path(app.config["SAMPLE_CSV_PATH"])
        try:
            sample_fingerprint = sample_path.stat().st_mtime_ns
            resolved_sample_path = str(sample_path.resolve())
        except OSError:
            sample_fingerprint = None
            resolved_sample_path = str(sample_path)

        license_hash = sha256(str(license_key).encode("utf-8")).hexdigest()
        cache_key = (resolved_sample_path, sample_fingerprint, license_hash)
        if cache_key in sample_report_cache:
            return jsonify(sample_report_cache[cache_key])

        try:
            report = analyze_data(sample_path, license_key=license_key)
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
        uploaded_file = request.files.get("file")
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"error": "Upload a CSV file to analyze."}), 400

        filename = uploaded_file.filename or ""
        extension = Path(filename).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({"error": "Only CSV files are supported."}), 400

        license_key = request.form.get("license_key", "").strip()
        if not license_key:
            return jsonify({"error": "Enter a valid license key to generate reports."}), 403

        try:
            csv_bytes = uploaded_file.read()
            if not csv_bytes:
                return jsonify({"error": "CSV file is empty."}), 400
            return jsonify(analyze_data(io.BytesIO(csv_bytes), license_key=license_key))
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except Exception as exc:
            app.logger.exception("Uploaded CSV analysis failed")
            return jsonify({"error": str(exc)}), 400
        finally:
            uploaded_file.close()
            csv_bytes = b""

    return app


app = create_app()


if __name__ == "__main__":
    port = _env_int("PORT", 5000)
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=port, debug=debug)
