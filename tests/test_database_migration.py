"""
test_database_migration.py

Tests that initialize_database() correctly migrates a pre-existing database
(created before tags/TOTP columns existed) without losing data, and that it
behaves correctly on a fresh database too.
"""

from __future__ import annotations

import sqlite3

from vaultkeeper.storage.database import initialize_database

OLD_SCHEMA = """
CREATE TABLE entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    url TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(service_name, username)
);
"""


class TestSchemaMigration:
    def test_fresh_database_has_all_columns(self, tmp_path):
        db_path = tmp_path / "fresh.db"
        initialize_database(db_path)

        conn = sqlite3.connect(db_path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(entries)").fetchall()}
        conn.close()

        assert "tag" in columns
        assert "encrypted_totp_secret" in columns

    def test_old_database_gets_new_columns_added(self, tmp_path):
        db_path = tmp_path / "old.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(OLD_SCHEMA)
        conn.commit()
        conn.close()

        initialize_database(db_path)

        conn = sqlite3.connect(db_path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(entries)").fetchall()}
        conn.close()

        assert "tag" in columns
        assert "encrypted_totp_secret" in columns

    def test_old_database_existing_rows_are_preserved(self, tmp_path):
        db_path = tmp_path / "old.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(OLD_SCHEMA)
        conn.execute(
            "INSERT INTO entries (service_name, username, encrypted_password, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("OldSite", "user@x.com", "encrypted-blob", "2026-01-01 00:00:00", "2026-01-01 00:00:00"),
        )
        conn.commit()
        conn.close()

        initialize_database(db_path)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT service_name, username, encrypted_password FROM entries"
        ).fetchone()
        conn.close()

        assert row == ("OldSite", "user@x.com", "encrypted-blob")

    def test_migrated_new_columns_default_to_empty_string(self, tmp_path):
        db_path = tmp_path / "old.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(OLD_SCHEMA)
        conn.execute(
            "INSERT INTO entries (service_name, username, encrypted_password, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("OldSite", "user@x.com", "encrypted-blob", "2026-01-01 00:00:00", "2026-01-01 00:00:00"),
        )
        conn.commit()
        conn.close()

        initialize_database(db_path)

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT tag, encrypted_totp_secret FROM entries").fetchone()
        conn.close()

        assert row == ("", "")

    def test_running_initialize_twice_is_safe(self, tmp_path):
        """initialize_database() must be idempotent — main.py calls it on every run."""
        db_path = tmp_path / "vault.db"
        initialize_database(db_path)
        initialize_database(db_path)  # should not raise

        conn = sqlite3.connect(db_path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(entries)").fetchall()}
        conn.close()
        assert "tag" in columns
