import hashlib
import hmac
import importlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()

BASE_DIR = Path(__file__).parent
DEFAULT_LICENSE_DB_PATH = BASE_DIR / "database.db"
DEFAULT_DEV_DB_KEY = "development-only-sqlcipher-key-change-me"


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _production_mode():
    return os.getenv("APP_ENV") == "production"


def _load_sqlcipher_dbapi(require_sqlcipher=False):
    for module_name in ("pysqlcipher3.dbapi2", "sqlcipher3.dbapi2"):
        try:
            return importlib.import_module(module_name), True
        except ImportError:
            continue

    if require_sqlcipher:
        raise RuntimeError("pysqlcipher3 or sqlcipher3 is required for encrypted license storage.")

    import sqlite3

    return sqlite3, False


def _sql_string_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _license_hash(license_key):
    normalized = str(license_key or "").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _normalize_device_id(device_id):
    return str(device_id or "").strip().lower()


def device_hmac(license_key, device_id):
    return hmac.new(
        str(license_key or "").strip().encode("utf-8"),
        _normalize_device_id(device_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _device_fingerprint(device_id):
    normalized = _normalize_device_id(device_id)
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


def _seed_keys_from_env():
    raw_keys = os.getenv("LICENSE_SEED_KEYS")
    if raw_keys is None:
        if _production_mode():
            return []
        return ["DEMO123", "TEST456"]

    return [key.strip() for key in raw_keys.split(",") if key.strip()]


def _database_encryption_key():
    key = os.getenv("DATABASE_ENCRYPTION_KEY") or os.getenv("SQLCIPHER_KEY")
    if key:
        return key

    if _production_mode():
        raise RuntimeError("DATABASE_ENCRYPTION_KEY must be set in production.")

    return DEFAULT_DEV_DB_KEY


class LicenseStore:
    def __init__(
        self,
        db_path=None,
        encryption_key=None,
        seed_keys=None,
        require_sqlcipher=None,
    ):
        self.db_path = Path(db_path or os.getenv("LICENSE_DB_PATH", DEFAULT_LICENSE_DB_PATH))
        self.encryption_key = encryption_key or _database_encryption_key()
        self.seed_keys = _seed_keys_from_env() if seed_keys is None else seed_keys
        self.require_sqlcipher = (
            _env_bool("SQLCIPHER_REQUIRED", default=_production_mode())
            if require_sqlcipher is None
            else require_sqlcipher
        )
        self.dbapi, self.encrypted = _load_sqlcipher_dbapi(self.require_sqlcipher)

    def connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = self.dbapi.connect(str(self.db_path))
        if self.encrypted:
            cursor = connection.cursor()
            cursor.execute(f"PRAGMA key = {_sql_string_literal(self.encryption_key)}")
            cursor.execute("PRAGMA cipher_page_size = 4096")
            cursor.execute("PRAGMA kdf_iter = 256000")
            cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
            cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
            cursor.close()
        return connection

    def ensure_initialized(self):
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS license_keys (
                    key_hash TEXT PRIMARY KEY,
                    active INTEGER NOT NULL DEFAULT 1,
                    label TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            existing_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(license_keys)").fetchall()
            }
            required_columns = {
                "locked_device_id": "TEXT",
                "locked_at": "TEXT",
                "last_seen_at": "TEXT",
                "last_seen_ip": "TEXT",
                "last_seen_user_agent": "TEXT",
                "last_seen_path": "TEXT",
                "use_count": "INTEGER NOT NULL DEFAULT 0",
            }
            for column, definition in required_columns.items():
                if column not in existing_columns:
                    connection.execute(f"ALTER TABLE license_keys ADD COLUMN {column} {definition}")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_alerts (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    attempted_device_id TEXT,
                    locked_device_id TEXT,
                    ip TEXT,
                    user_agent TEXT,
                    path TEXT,
                    detail TEXT NOT NULL
                )
                """
            )
            created_at = datetime.now(timezone.utc).isoformat()
            for license_key in self.seed_keys:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO license_keys (key_hash, active, label, created_at)
                    VALUES (?, 1, ?, ?)
                    """,
                    (_license_hash(license_key), "seeded", created_at),
                )
            connection.commit()

    def is_valid(self, license_key):
        normalized = str(license_key or "").strip()
        if not normalized:
            return False

        self.ensure_initialized()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT active FROM license_keys WHERE key_hash = ? LIMIT 1",
                (_license_hash(normalized),),
            ).fetchone()

        return bool(row and int(row[0]) == 1)

    def _record_auth_alert(
        self,
        connection,
        *,
        key_hash,
        alert_type,
        detail,
        attempted_device_id="",
        locked_device_id="",
        ip="",
        user_agent="",
        path="",
    ):
        connection.execute(
            """
            INSERT INTO auth_alerts (
                id,
                created_at,
                key_hash,
                alert_type,
                attempted_device_id,
                locked_device_id,
                ip,
                user_agent,
                path,
                detail
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                datetime.now(timezone.utc).isoformat(),
                key_hash,
                alert_type,
                attempted_device_id,
                locked_device_id,
                ip,
                user_agent,
                path,
                detail,
            ),
        )

    def validate_device_lock(
        self,
        license_key,
        device_id,
        supplied_device_hmac,
        *,
        ip="",
        user_agent="",
        path="",
    ):
        normalized_license = str(license_key or "").strip()
        normalized_device_id = _normalize_device_id(device_id)
        normalized_hmac = str(supplied_device_hmac or "").strip().lower()

        if not normalized_license:
            return {"ok": False, "error": "Invalid license key.", "reason": "missing_license"}
        if not normalized_device_id or not normalized_hmac:
            return {"ok": False, "error": "Device identity is required.", "reason": "missing_device_identity"}

        expected_hmac = device_hmac(normalized_license, normalized_device_id)
        key_hash = _license_hash(normalized_license)
        self.ensure_initialized()
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT active, locked_device_id
                FROM license_keys
                WHERE key_hash = ?
                LIMIT 1
                """,
                (key_hash,),
            ).fetchone()

            if not row or int(row[0]) != 1:
                return {"ok": False, "error": "Invalid license key.", "reason": "invalid_license"}

            locked_device_id = _normalize_device_id(row[1])
            if not hmac.compare_digest(expected_hmac, normalized_hmac):
                self._record_auth_alert(
                    connection,
                    key_hash=key_hash,
                    alert_type="device_hmac_invalid",
                    attempted_device_id=normalized_device_id,
                    locked_device_id=locked_device_id,
                    ip=ip,
                    user_agent=user_agent,
                    path=path,
                    detail="Device-ID HMAC did not match the submitted license key.",
                )
                connection.commit()
                return {"ok": False, "error": "Device identity could not be verified.", "reason": "invalid_device_hmac"}

            now = datetime.now(timezone.utc).isoformat()
            if not locked_device_id:
                connection.execute(
                    """
                    UPDATE license_keys
                    SET locked_device_id = ?,
                        locked_at = ?,
                        last_seen_at = ?,
                        last_seen_ip = ?,
                        last_seen_user_agent = ?,
                        last_seen_path = ?,
                        use_count = COALESCE(use_count, 0) + 1
                    WHERE key_hash = ?
                    """,
                    (normalized_device_id, now, now, ip, user_agent, path, key_hash),
                )
                connection.commit()
                return {"ok": True, "status": "locked", "device_fingerprint": _device_fingerprint(normalized_device_id)}

            if not hmac.compare_digest(locked_device_id, normalized_device_id):
                self._record_auth_alert(
                    connection,
                    key_hash=key_hash,
                    alert_type="hardware_lock_violation",
                    attempted_device_id=normalized_device_id,
                    locked_device_id=locked_device_id,
                    ip=ip,
                    user_agent=user_agent,
                    path=path,
                    detail="License key was used from a different Device-ID.",
                )
                connection.commit()
                return {
                    "ok": False,
                    "error": "License key is locked to another device.",
                    "reason": "hardware_lock_violation",
                }

            connection.execute(
                """
                UPDATE license_keys
                SET last_seen_at = ?,
                    last_seen_ip = ?,
                    last_seen_user_agent = ?,
                    last_seen_path = ?,
                    use_count = COALESCE(use_count, 0) + 1
                WHERE key_hash = ?
                """,
                (now, ip, user_agent, path, key_hash),
            )
            connection.commit()
            return {"ok": True, "status": "active", "device_fingerprint": _device_fingerprint(normalized_device_id)}

    def session_monitor(self, limit=12):
        self.ensure_initialized()
        with self.connect() as connection:
            device_rows = connection.execute(
                """
                SELECT
                    key_hash,
                    locked_device_id,
                    locked_at,
                    last_seen_at,
                    last_seen_ip,
                    last_seen_user_agent,
                    last_seen_path,
                    use_count
                FROM license_keys
                WHERE locked_device_id IS NOT NULL AND locked_device_id <> ''
                ORDER BY COALESCE(last_seen_at, locked_at, created_at) DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
            alert_rows = connection.execute(
                """
                SELECT
                    id,
                    created_at,
                    key_hash,
                    alert_type,
                    attempted_device_id,
                    locked_device_id,
                    ip,
                    user_agent,
                    path,
                    detail
                FROM auth_alerts
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()

        devices = [
            {
                "key_fingerprint": str(row[0])[:12],
                "device_fingerprint": _device_fingerprint(row[1]),
                "locked_at": row[2],
                "last_seen_at": row[3],
                "last_seen_ip": row[4],
                "last_seen_user_agent": row[5],
                "last_seen_path": row[6],
                "use_count": int(row[7] or 0),
            }
            for row in device_rows
        ]
        alerts = [
            {
                "id": row[0],
                "created_at": row[1],
                "key_fingerprint": str(row[2])[:12],
                "alert_type": row[3],
                "attempted_device_fingerprint": _device_fingerprint(row[4]),
                "locked_device_fingerprint": _device_fingerprint(row[5]),
                "ip": row[6],
                "user_agent": row[7],
                "path": row[8],
                "detail": row[9],
            }
            for row in alert_rows
        ]
        return {
            "active_devices": devices,
            "alerts": alerts,
            "active_device_count": len(devices),
            "alert_count": len(alerts),
        }


def is_valid_license_key(license_key):
    return LicenseStore().is_valid(license_key)
