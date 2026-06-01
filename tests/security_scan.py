#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from license_store import DEFAULT_DEV_DB_KEY, LicenseStore
from security_tokens import DEFAULT_JWT_SECRET


ALLOWED_APP_ENVS = {"development", "testing", "production"}
WEAK_SECRET_MARKERS = (
    "change-me",
    "change_me",
    "development-only",
    "your_key_here",
)


def _env_bool(env, name, default=False):
    value = env.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _production_mode(env):
    return env.get("APP_ENV") == "production"


def _strict_mode(env):
    return _production_mode(env) or _env_bool(env, "SQLCIPHER_REQUIRED")


def _is_weak_secret(value):
    normalized = str(value or "").strip().lower()
    if not normalized:
        return True
    return normalized in {DEFAULT_DEV_DB_KEY.lower(), DEFAULT_JWT_SECRET.lower()} or any(
        marker in normalized for marker in WEAK_SECRET_MARKERS
    )


def _check(ok, status, detail, **extra):
    payload = {
        "ok": bool(ok),
        "status": status,
        "detail": detail,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    payload.update(extra)
    return payload


def scan_environment_isolation(env):
    app_env = env.get("APP_ENV", "development")
    strict = _strict_mode(env)
    failures = []
    warnings = []

    if app_env not in ALLOWED_APP_ENVS:
        failures.append(f"APP_ENV must be one of {sorted(ALLOWED_APP_ENVS)}.")

    required_secrets = {
        "DATABASE_ENCRYPTION_KEY": env.get("DATABASE_ENCRYPTION_KEY") or env.get("SQLCIPHER_KEY"),
        "GATEKEEPER_JWT_SECRET": env.get("GATEKEEPER_JWT_SECRET") or env.get("JWT_SECRET") or env.get("SECRET_KEY"),
        "STRIPE_WEBHOOK_SECRET": env.get("STRIPE_WEBHOOK_SECRET"),
    }
    for name, value in required_secrets.items():
        if _is_weak_secret(value):
            message = f"{name} is missing or uses a development placeholder."
            if strict:
                failures.append(message)
            else:
                warnings.append(message)

    if failures:
        return _check(False, "failed", " ".join(failures), warnings=warnings, strict=strict)

    detail = "Environment isolation validated."
    if warnings:
        detail = "Environment isolation validated for non-production mode; production requires rotated secrets."
    return _check(True, "validated", detail, warnings=warnings, strict=strict, app_env=app_env)


def scan_database_encryption(env, license_store=None):
    strict = _strict_mode(env)
    try:
        store = license_store or LicenseStore()
    except Exception as exc:
        return _check(False, "failed", f"License database could not initialize: {exc}", strict=strict)

    encrypted = bool(getattr(store, "encrypted", False))
    require_sqlcipher = bool(getattr(store, "require_sqlcipher", False))
    if strict and not encrypted:
        return _check(
            False,
            "failed",
            "SQLCipher encryption is required but the encrypted database driver is unavailable.",
            encrypted=encrypted,
            strict=strict,
            require_sqlcipher=require_sqlcipher,
        )

    if encrypted:
        detail = "SQLCipher license database encryption is active."
        status = "encrypted"
    else:
        detail = "Development database fallback active; production enforces SQLCipher before startup."
        status = "development-fallback"

    return _check(
        True,
        status,
        detail,
        encrypted=encrypted,
        strict=strict,
        require_sqlcipher=require_sqlcipher,
    )


def _read_text(path):
    return path.read_text(encoding="utf-8")


def scan_static_controls(base_dir):
    base_dir = Path(base_dir)
    checks = [
        {
            "name": "Signed JWT handshake",
            "path": "gatekeeper_server.py",
            "required": ("verify_gatekeeper_jwt", "X-Payload-SHA256", "payload_hash"),
        },
        {
            "name": "Semantic Firewall",
            "path": "gatekeeper_server.py",
            "required": ("class SemanticFirewall", "SEMANTIC_FIREWALL.inspect"),
        },
        {
            "name": "Hacker honey-pot middleware",
            "path": "gatekeeper_server.py",
            "required": ("/api/v1/debug_admin", "HONEYPOT_BLACKLIST", "logging.CRITICAL"),
        },
        {
            "name": "WAF-friendly edge header check",
            "path": "gatekeeper_server.py",
            "required": ("X-Forwarded-Proto", "ALLOWED_HOSTS", "WAF_HEADER_CHECK", "validate_waf_headers"),
        },
        {
            "name": "Stripe webhook signature verification",
            "path": "gatekeeper_server.py",
            "required": ("/stripe/webhook", "verify_stripe_webhook_signature", "Stripe-Signature", "STRIPE_WEBHOOK_SECRET"),
        },
        {
            "name": "Version update handshake",
            "path": "gatekeeper_server.py",
            "required": ("/check-updates", "is_newer_version", "update_available"),
        },
        {
            "name": "Client update handshake proxy",
            "path": "app.py",
            "required": ("/api/check-updates", "current_version", "APP_VERSION"),
        },
        {
            "name": "Client device fingerprinting",
            "path": "templates/index.html",
            "required": (
                "cpu_cores",
                "screen_resolution",
                "browser_engine",
                "crypto.subtle.digest",
                "X-Device-ID",
                "X-Device-HMAC",
                "renewSecureSession",
            ),
        },
        {
            "name": "Hardware license lock",
            "path": "license_store.py",
            "required": ("locked_device_id", "auth_alerts", "validate_device_lock", "device_hmac"),
        },
        {
            "name": "Secure session verifier",
            "path": "gatekeeper_server.py",
            "required": ("_verify_device_session_token", "secure_session_rejected", "session_token"),
        },
        {
            "name": "Admin session monitor",
            "path": "templates/admin.html",
            "required": ("Session Monitor", "refreshSessionMonitor", "/api/session-monitor"),
        },
        {
            "name": "Sales lead tracker",
            "path": "gatekeeper_server.py",
            "required": ("CREATE TABLE IF NOT EXISTS leads", "/admin/leads/add", "LeadStore", "LEAD_STATUSES"),
        },
        {
            "name": "Demo key expiry",
            "path": "license_store.py",
            "required": ("expires_at", "create_demo_key", "timedelta(hours=duration_hours)", "expired_license"),
        },
        {
            "name": "Admin sales interface",
            "path": "templates/admin.html",
            "required": ("Sales & Leads", "Generate 48h Demo Key", "/api/leads/add", "/api/demo-key"),
        },
        {
            "name": "Production Gatekeeper URL sync",
            "path": "narrative_logic.py",
            "required": ("GATEKEEPER_PUBLIC_URL", "DEFAULT_GATEKEEPER_URL", "GATEKEEPER_URL", "DOMAIN_URL", "DEFAULT_RENDER_URL"),
        },
        {
            "name": "Render readiness check",
            "path": "gatekeeper_server.py",
            "required": ("/readyness", "readiness_payload", "Strict-Transport-Security", "SQLCipher is required"),
        },
        {
            "name": "Tiered Flask-Limiter quotas",
            "path": "gatekeeper_server.py",
            "required": ("flask_limiter", "DEMO_RATE_LIMIT", "ELITE_RATE_LIMIT", "_license_rate_limit_value", "license_tier"),
        },
        {
            "name": "SQLCipher license vault default",
            "path": "license_store.py",
            "required": ("licenses_store.db", "pysqlcipher3.dbapi2", "PRAGMA key", "DATABASE_ENCRYPTION_KEY", "tier"),
        },
        {
            "name": "Truth-Verification middleware",
            "path": "gatekeeper_server.py",
            "required": ("verify_truth_locked_numbers", "Corrective Message", "truth_verification_corrective_retry", "openai_corrected"),
        },
        {
            "name": "Admin Math Verified flag",
            "path": "templates/admin.html",
            "required": ("Math Verified", "math_verified", "math_anomaly_detected"),
        },
        {
            "name": "Client HTTPS AJAX guard",
            "path": "templates/index.html",
            "required": ("forceHttpsUrl", "Upgrade to Pro", "dashboard-upgrade-link"),
        },
        {
            "name": "Multi-channel CSV upload UI",
            "path": "templates/index.html",
            "required": ("multiple", "channel-badges", "maxUploadFiles", "Channel Mix"),
        },
        {
            "name": "Cross-channel analytics",
            "path": "narrative_logic.py",
            "required": ("MAX_CHANNEL_FILES", "build_channel_metrics", "blended_roas", "strategic_attribution", "channel_metrics"),
        },
        {
            "name": "Strategic attribution CMO prompt",
            "path": "gatekeeper_server.py",
            "required": ("Strategic Attribution", "channel_metrics", "budget reallocation", "awareness channels create demand"),
        },
        {
            "name": "Proactive health alerts",
            "path": "gatekeeper_server.py",
            "required": ("HEALTH_ALERT_WEBHOOK_URL", "HEALTH_ALERT_LATENCY_SECONDS", "send_proactive_health_alert", "latency_seconds"),
        },
        {
            "name": "Strategist feedback gatekeeper route",
            "path": "gatekeeper_server.py",
            "required": ("/feedback", "strategist_feedback_received", "STRATEGIST_FEEDBACK_WEBHOOK_URL"),
        },
        {
            "name": "Strategist feedback client proxy",
            "path": "app.py",
            "required": ("/api/feedback", "/feedback", "Feedback message is required."),
        },
        {
            "name": "Strategist feedback dashboard button",
            "path": "templates/index.html",
            "required": ("Suggest a Feature", "feedback-panel", "/api/feedback", "submitStrategistFeedback"),
        },
        {
            "name": "Cloudflare CDN guide",
            "path": "README.md",
            "required": ("Cloudflare CDN Setup", "Cache Rules", "Bot Management", "Full (strict)", "/api/*"),
        },
        {
            "name": "Elite privacy guarantee",
            "path": "templates/about.html",
            "required": ("Elite Privacy Guarantee", "Zero raw CSV retention", "Fact-Check Lock", "Protected access boundary"),
        },
        {
            "name": "Startup validation",
            "path": "gatekeeper_server.py",
            "required": ("run_startup_validation", "security_scan.py"),
        },
        {
            "name": "RAM-only CSV upload",
            "path": "app.py",
            "required": ("io.BytesIO(csv_bytes)",),
            "forbidden": ("UPLOAD_DIR", "uploaded_file.save("),
        },
        {
            "name": "Local client does not hold provider keys",
            "path": "app.py",
            "forbidden": ("OPENAI_API_KEY", "EMERGENT_LLM_KEY"),
        },
    ]

    failures = []
    passed = []
    for item in checks:
        path = base_dir / item["path"]
        if not path.exists():
            failures.append(f"{item['name']}: missing {item['path']}")
            continue

        text = _read_text(path)
        missing = [needle for needle in item.get("required", ()) if needle not in text]
        forbidden = [needle for needle in item.get("forbidden", ()) if needle in text]
        if missing or forbidden:
            details = []
            if missing:
                details.append(f"missing {missing}")
            if forbidden:
                details.append(f"forbidden {forbidden}")
            failures.append(f"{item['name']}: {', '.join(details)}")
            continue

        passed.append(item["name"])

    if failures:
        return _check(False, "failed", "Static application security scan failed.", failures=failures, passed=passed)

    return _check(True, "passed", "Static application security controls verified.", passed=passed)


def run_security_scan(base_dir=None, env=None, license_store=None):
    resolved_base_dir = Path(base_dir or Path(__file__).resolve().parents[1])
    resolved_env = dict(os.environ if env is None else env)
    checks = {
        "environment_isolation": scan_environment_isolation(resolved_env),
        "database_encryption": scan_database_encryption(resolved_env, license_store=license_store),
        "sast_scan": scan_static_controls(resolved_base_dir),
    }
    ok = all(item["ok"] for item in checks.values())
    return {
        "ok": ok,
        "status": "pass" if ok else "fail",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


def format_security_scan_failures(result):
    failures = []
    for name, check in (result.get("checks") or {}).items():
        if not check.get("ok"):
            failures.append(f"{name}: {check.get('detail', 'failed')}")
    return "; ".join(failures) or "Security scan failed."


def main():
    result = run_security_scan()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
