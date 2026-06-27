"""
database.py

SQLite connection management and schema setup. Only the encrypted password
field touches encryption — everything else here is plain SQLite plumbing.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from vaultkeeper import config
from vaultkeeper.utils.exceptions import DatabaseError

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name    TEXT NOT NULL,
    username        TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    url             TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    tag             TEXT DEFAULT '',
    encrypted_totp_secret TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(service_name, username)
);

CREATE INDEX IF NOT EXISTS idx_entries_service_name ON entries(service_name);
"""

# Columns that may not exist yet on databases created before this feature was
# added. _migrate_schema() adds any that are missing, so existing vaults
# upgrade in place without losing data.
_MIGRATION_COLUMNS = [
    ("tag", "TEXT DEFAULT ''"),
    ("encrypted_totp_secret", "TEXT DEFAULT ''"),
]


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add any columns introduced after the original schema, if missing.

    Must run on tables that may pre-date these columns, so this only ALTERs
    — it never assumes the tag column already exists. The tag index is
    created here too, AFTER the column is guaranteed to exist (it can't be
    part of the main SCHEMA script, since CREATE TABLE IF NOT EXISTS is a
    no-op against an older existing table and a same-script index creation
    against a not-yet-added column would fail).
    """
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(entries)").fetchall()
    }
    for column_name, column_def in _MIGRATION_COLUMNS:
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE entries ADD COLUMN {column_name} {column_def}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_tag ON entries(tag)")
    conn.commit()


def initialize_database(db_path: Optional[Path] = None) -> None:
    """Create the database file and schema if they don't already exist, and
    migrate any pre-existing database to the latest column set."""
    config.ensure_data_dir()
    resolved_path = db_path if db_path is not None else config.DB_PATH
    try:
        with sqlite3.connect(resolved_path) as conn:
            conn.executescript(SCHEMA)
            conn.commit()
            _migrate_schema(conn)
    except sqlite3.Error as exc:
        raise DatabaseError(f"Failed to initialize database: {exc}") from exc


@contextmanager
def get_connection(db_path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    """
    Context manager yielding a SQLite connection with row factory set to
    sqlite3.Row (so results can be accessed by column name).

    If db_path is not provided, resolves config.DB_PATH at call time (not
    import time), so tests can safely monkeypatch config.DB_PATH.
    """
    resolved_path = db_path if db_path is not None else config.DB_PATH
    conn = None
    try:
        conn = sqlite3.connect(resolved_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        if conn is not None:
            conn.rollback()
        raise DatabaseError(f"Database operation failed: {exc}") from exc
    finally:
        if conn is not None:
            conn.close()


def database_exists(db_path: Optional[Path] = None) -> bool:
    """Check whether the vault database file already exists on disk."""
    resolved_path = db_path if db_path is not None else config.DB_PATH
    return resolved_path.exists()
