import json
import hmac
import os
import time

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template_string, request

from license_store import LicenseStore
from security_tokens import TokenError, gatekeeper_payload, payload_hash, verify_gatekeeper_jwt


try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:  # pragma: no cover - local fallback is covered in tests.
    Limiter = None
    get_remote_address = None


load_dotenv()

OPENAI_TIMEOUT_SECONDS = 30
GATEKEEPER_LIMIT = "5 per minute"
GATEKEEPER_PAGE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NarrativeAI Gatekeeper</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f8fafc;
        --surface: #ffffff;
        --text: #172033;
        --muted: #667085;
        --line: #e2e8f0;
        --blue: #2563eb;
        --green: #15803d;
        --red: #b42318;
      }

      * {
        box-sizing: border-box;
      }

      body {
        display: grid;
        min-height: 100vh;
        place-items: center;
        margin: 0;
        background: var(--bg);
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }

      main {
        width: min(720px, calc(100% - 32px));
        padding: 28px;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: var(--surface);
        box-shadow: 0 18px 45px rgba(20, 32, 55, 0.08);
      }

      h1 {
        margin: 0;
        font-size: clamp(28px, 4vw, 42px);
        line-height: 1;
      }

      p {
        color: var(--muted);
        line-height: 1.55;
      }

      .status {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 18px;
        color: var(--green);
        font-size: 14px;
        font-weight: 800;
      }

      .dot {
        width: 9px;
        height: 9px;
        border-radius: 999px;
        background: currentColor;
      }

      form {
        display: grid;
        gap: 12px;
        margin-top: 22px;
      }

      label {
        color: var(--muted);
        font-size: 13px;
        font-weight: 800;
      }

      input {
        width: 100%;
        min-height: 44px;
        padding: 10px 12px;
        border: 1px solid var(--line);
        border-radius: 8px;
        color: var(--text);
        font: inherit;
        font-weight: 750;
      }

      button {
        min-height: 44px;
        border: 0;
        border-radius: 8px;
        background: var(--blue);
        color: #ffffff;
        cursor: pointer;
        font: inherit;
        font-weight: 800;
      }

      pre {
        min-height: 96px;
        margin: 18px 0 0;
        padding: 14px;
        overflow: auto;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: #f8fafc;
        color: var(--muted);
        white-space: pre-wrap;
      }

      .error {
        color: var(--red);
      }
    </style>
  </head>
  <body>
    <main>
      <div class="status"><span class="dot" aria-hidden="true"></span>Gatekeeper Online</div>
      <h1>NarrativeAI Gatekeeper</h1>
      <p>This server verifies encrypted license records and generates narratives without exposing the API key to the local client.</p>
      <form id="gatekeeper-form">
        <label for="license-key">Test License Key</label>
        <input id="license-key" value="DEMO123" autocomplete="off" spellcheck="false">
        <button type="submit">Verify And Generate</button>
      </form>
      <pre id="result">Protected endpoint ready. Signed app requests only.</pre>
    </main>
    <script>
      const form = document.querySelector("#gatekeeper-form");
      const result = document.querySelector("#result");
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        result.className = "";
        result.textContent = "The generator endpoint now only accepts signed client requests from NarrativeAI.";
      });
    </script>
  </body>
</html>
"""


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


def _rate_limit_count():
    return _env_int("GATEKEEPER_REPORTS_PER_MINUTE", 5)


def _extract_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def _configure_rate_limiting(app):
    if Limiter is not None:
        return Limiter(
            key_func=get_remote_address,
            app=app,
            storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
            default_limits=[],
            headers_enabled=True,
        )

    request_log = {}
    window_seconds = 60

    @app.before_request
    def fallback_rate_limit():
        if request.endpoint != "verify_and_generate":
            return None

        now = time.monotonic()
        key = (_extract_client_ip(), request.endpoint)
        recent_hits = [hit for hit in request_log.get(key, []) if now - hit < window_seconds]
        if len(recent_hits) >= _rate_limit_count():
            request_log[key] = recent_hits
            return jsonify({"error": "Too many report requests. Try again later."}), 429

        recent_hits.append(now)
        request_log[key] = recent_hits
        return None

    return None


def _rate_limit(limiter):
    if limiter is None:
        return lambda view: view
    return limiter.limit(os.getenv("GATEKEEPER_REPORT_LIMIT", GATEKEEPER_LIMIT))


def _bearer_token():
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return ""
    return authorization.split(" ", 1)[1].strip()


def _verify_signed_payload(payload):
    token = _bearer_token()
    if not token:
        raise TokenError("Missing bearer token.")

    expected_hash = payload_hash(payload)
    supplied_hash = request.headers.get("X-Payload-SHA256", "")
    if not hmac.compare_digest(supplied_hash, expected_hash):
        raise TokenError("Payload hash header mismatch.")

    return verify_gatekeeper_jwt(token, payload)


def _format_money(value):
    return f"${float(value):,.2f}"


def _fallback_narrative(stats):
    return (
        "**Executive Summary**\n"
        f"Gatekeeper verified the license and analyzed {_format_money(stats['total_revenue'])} "
        f"in revenue from {_format_money(stats['total_spend'])} in spend. Average ROAS was "
        f"{stats['avg_roas']}x, with {stats['total_conversions']} conversions led by "
        f"{stats['top_campaign']}.\n\n"
        "The OpenAI API key is not configured on this Gatekeeper instance yet, so this "
        "deterministic narrative confirms the secure split is working without exposing "
        "any private key to the local client."
    )


def generate_narrative(stats):
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("EMERGENT_LLM_KEY")
    if not api_key:
        return _fallback_narrative(stats)

    prompt = (
        "You are a Senior Marketing Account Manager. Write a 3-paragraph "
        "professional executive summary based on these stats: "
        f"{json.dumps(stats)}"
    )
    response = requests.post(
        os.getenv(
            "OPENAI_API_URL",
            os.getenv("EMERGENT_LLM_URL", "https://api.openai.com/v1/chat/completions"),
        ),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": os.getenv("OPENAI_MODEL", os.getenv("EMERGENT_LLM_MODEL", "gpt-4o-mini")),
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=OPENAI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def create_app():
    app = Flask(__name__)
    limiter = _configure_rate_limiting(app)
    license_store = LicenseStore()

    @app.errorhandler(429)
    def handle_rate_limit(error):
        return jsonify({"error": "Too many report requests. Try again later."}), 429

    @app.get("/")
    def index():
        return render_template_string(GATEKEEPER_PAGE)

    @app.get("/healthz")
    def health_check():
        return jsonify({"status": "ok", "service": "gatekeeper"})

    @app.post("/verify-and-generate")
    @_rate_limit(limiter)
    def verify_and_generate():
        payload = request.get_json(silent=True) or {}
        stats = payload.get("stats")
        license_key = str(payload.get("license_key", "")).strip()
        signed_payload = gatekeeper_payload(stats, license_key)

        try:
            _verify_signed_payload(signed_payload)
        except TokenError as exc:
            return jsonify({"error": str(exc)}), 401

        if not license_store.is_valid(license_key):
            return jsonify({"error": "Invalid license key."}), 403

        if not isinstance(stats, dict):
            return jsonify({"error": "Stats payload must be a JSON object."}), 400

        try:
            return jsonify({"narrative": generate_narrative(stats)})
        except Exception as exc:
            app.logger.exception("Gatekeeper narrative generation failed")
            return jsonify({"error": f"Gatekeeper generation failed: {str(exc)}"}), 502

    return app


app = create_app()


if __name__ == "__main__":
    port = _env_int("PORT", 5001)
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=port, debug=debug)
