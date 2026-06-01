from license_store import LicenseStore, device_hmac


def test_license_store_seeds_and_validates_keys(tmp_path):
    store = LicenseStore(
        db_path=tmp_path / "database.db",
        encryption_key="test-database-key",
        seed_keys=["DEMO123"],
        require_sqlcipher=False,
    )

    assert store.is_valid("DEMO123") is True
    assert store.is_valid("BADKEY") is False


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
