import hashlib
import importlib
import os
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


def is_valid_license_key(license_key):
    return LicenseStore().is_valid(license_key)
