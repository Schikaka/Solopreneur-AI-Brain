from datetime import datetime, timedelta, timezone

from license_store import DEFAULT_LICENSE_DB_PATH, LicenseStore, device_hmac


def test_license_store_seeds_and_validates_keys(tmp_path):
    store = LicenseStore(
        db_path=tmp_path / "database.db",
        encryption_key="test-database-key",
        seed_keys=["DEMO123"],
        require_sqlcipher=False,
    )

    assert store.is_valid("DEMO123") is True
    assert store.is_valid("BADKEY") is False
    assert DEFAULT_LICENSE_DB_PATH.name == "licenses_store.db"


def test_license_store_can_require_sqlcipher_when_unavailable(tmp_path, monkeypatch):
    def missing_sqlcipher(name):
        raise ImportError(name)

    monkeypatch.setattr("license_store.importlib.import_module", missing_sqlcipher)

    try:
        LicenseStore(
            db_path=tmp_path / "database.db",
            encryption_key="test-database-key",
            seed_keys=[],
            require_sqlcipher=True,
        )
    except RuntimeError as exc:
        assert "pysqlcipher3" in str(exc)
    else:
        raise AssertionError("SQLCipher should be mandatory when require_sqlcipher=True.")


def test_license_store_locks_first_device_and_flags_second(tmp_path):
    store = LicenseStore(
        db_path=tmp_path / "database.db",
        encryption_key="test-database-key",
        seed_keys=["DEMO123"],
        require_sqlcipher=False,
    )
    first_device = "a" * 64
    second_device = "b" * 64

    first = store.validate_device_lock("DEMO123", first_device, device_hmac("DEMO123", first_device), ip="127.0.0.1")
    same = store.validate_device_lock("DEMO123", first_device, device_hmac("DEMO123", first_device), ip="127.0.0.1")
    blocked = store.validate_device_lock(
        "DEMO123",
        second_device,
        device_hmac("DEMO123", second_device),
        ip="198.51.100.10",
    )
    monitor = store.session_monitor()

    assert first["ok"] is True
    assert first["status"] == "locked"
    assert same["ok"] is True
    assert same["status"] == "active"
    assert blocked["ok"] is False
    assert blocked["reason"] == "hardware_lock_violation"
    assert monitor["active_device_count"] == 1
    assert monitor["alert_count"] == 1
    assert monitor["alerts"][0]["alert_type"] == "hardware_lock_violation"


def test_demo_license_keys_expire(tmp_path):
    store = LicenseStore(
        db_path=tmp_path / "database.db",
        encryption_key="test-database-key",
        seed_keys=[],
        require_sqlcipher=False,
    )
    active_demo = store.create_demo_key(hours=48)
    expired_key = "EXPIRED-DEMO-KEY"
    expired_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    store.create_license_key(expired_key, label="expired-demo", expires_at=expired_at)

    assert active_demo["license_key"].startswith("DEMO-")
    assert active_demo["tier"] == "demo"
    assert active_demo["duration_hours"] == 48
    assert store.is_valid(active_demo["license_key"]) is True
    assert store.is_valid(expired_key) is False
    assert store.validate_device_lock(
        expired_key,
        "a" * 64,
        device_hmac(expired_key, "a" * 64),
    )["reason"] == "expired_license"


def test_license_store_classifies_demo_and_elite_tiers(tmp_path):
    store = LicenseStore(
        db_path=tmp_path / "licenses_store.db",
        encryption_key="test-database-key",
        seed_keys=["DEMO123", "ELITE999"],
        require_sqlcipher=False,
    )
    store.create_license_key("MANUAL-ELITE", tier="elite")

    assert store.license_tier("DEMO123") == "demo"
    assert store.license_tier("ELITE999") == "elite"
    assert store.license_tier("MANUAL-ELITE") == "elite"
    assert store.license_tier("UNKNOWN") == "demo"
