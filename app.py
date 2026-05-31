import os
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from narrative_logic import analyze_data


BASE_DIR = Path(__file__).parent
DEFAULT_UPLOAD_DIR = BASE_DIR / "uploads"
DEFAULT_SAMPLE_PATH = BASE_DIR / "dummy_marketing_data.csv"
ALLOWED_EXTENSIONS = {".csv"}


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
        UPLOAD_DIR=Path(os.getenv("UPLOAD_DIR", DEFAULT_UPLOAD_DIR)),
    )

    if test_config:
        app.config.update(test_config)

    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_upload(error):
        return jsonify({"error": "CSV upload is too large."}), 413

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(500)
    def handle_server_error(error):
        app.logger.exception("Unhandled server error")
        return jsonify({"error": "Unexpected server error."}), 500

    @app.get("/healthz")
    def health_check():
        return jsonify({"status": "ok"})

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/admin")
    def admin():
        return render_template("admin.html")

    @app.get("/api/sample")
    def sample_report():
        license_key = request.args.get("license_key") or os.getenv("DEMO_LICENSE_KEY", "DEMO123")
        try:
            return jsonify(analyze_data(app.config["SAMPLE_CSV_PATH"], license_key=license_key))
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

        filename = secure_filename(uploaded_file.filename)
        extension = Path(filename).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            return jsonify({"error": "Only CSV files are supported."}), 400

        upload_path = app.config["UPLOAD_DIR"] / f"{uuid.uuid4().hex}-{filename}"
        license_key = request.form.get("license_key", "").strip()
        if not license_key:
            return jsonify({"error": "Enter a valid license key to generate reports."}), 403

        try:
            uploaded_file.save(upload_path)
            return jsonify(analyze_data(upload_path, license_key=license_key))
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except Exception as exc:
            app.logger.exception("Uploaded CSV analysis failed")
            return jsonify({"error": str(exc)}), 400
        finally:
            upload_path.unlink(missing_ok=True)

    return app


app = create_app()


if __name__ == "__main__":
    port = _env_int("PORT", 5000)
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=port, debug=debug)
