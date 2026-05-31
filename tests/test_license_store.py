from license_store import LicenseStore


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
