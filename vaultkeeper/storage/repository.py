"""
repository.py

Repository layer: all CRUD operations on credential entries. This is the
only layer that should directly touch both the database AND the cipher —
it encrypts passwords on the way in, and decrypts them on the way out.
"""

from __future__ import annotations

import sqlite3
from typing import List, Optional

from vaultkeeper.crypto.cipher import Cipher
from vaultkeeper.storage.database import get_connection
from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.exceptions import (
    DatabaseError,
    DuplicateEntryError,
    EntryNotFoundError,
)


class EntryRepository:
    """Handles persistence of Entry objects, encrypting/decrypting as needed."""

    def __init__(self, cipher: Cipher):
        self._cipher = cipher

    # --- Create -------------------------------------------------------------

    def add(self, entry: Entry) -> Entry:
        """Encrypt and insert a new entry. Raises DuplicateEntryError on conflict."""
        entry.touch_created()
        encrypted_password = self._cipher.encrypt(entry.password)
        encrypted_totp = self._cipher.encrypt(entry.totp_secret) if entry.totp_secret else ""

        try:
            with get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO entries
                        (service_name, username, encrypted_password, url, notes,
                         tag, encrypted_totp_secret, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.service_name,
                        entry.username,
                        encrypted_password,
                        entry.url,
                        entry.notes,
                        entry.tag,
                        encrypted_totp,
                        entry.created_at,
                        entry.updated_at,
                    ),
                )
                entry.id = cursor.lastrowid
                return entry
        except DatabaseError as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise DuplicateEntryError(
                    f"An entry for '{entry.service_name}' with username "
                    f"'{entry.username}' already exists."
                ) from exc
            raise

    # --- Read ----------------------------------------------------------------

    def get_by_id(self, entry_id: int) -> Entry:
        """Fetch a single entry by its primary key, decrypting its password."""
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM entries WHERE id = ?", (entry_id,)
            ).fetchone()
        if row is None:
            raise EntryNotFoundError(f"No entry found with id {entry_id}.")
        return self._row_to_entry(row)

    def get_by_service(self, service_name: str) -> List[Entry]:
        """Fetch all entries matching a service name exactly (case-insensitive)."""
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE LOWER(service_name) = LOWER(?)",
                (service_name,),
            ).fetchall()
        if not rows:
            raise EntryNotFoundError(f"No entry found for service '{service_name}'.")
        return [self._row_to_entry(row) for row in rows]

    def search(self, query: str) -> List[Entry]:
        """Fuzzy (substring, case-insensitive) search by service name."""
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE service_name LIKE ? ORDER BY service_name",
                (f"%{query}%",),
            ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def list_all(self) -> List[Entry]:
        """Return all entries, ordered alphabetically by service name."""
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM entries ORDER BY service_name COLLATE NOCASE"
            ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    # --- Update ----------------------------------------------------------------

    def update(self, entry: Entry) -> Entry:
        """Update an existing entry (identified by entry.id). Re-encrypts password
        and TOTP secret (if present)."""
        if entry.id is None:
            raise ValueError("Cannot update an entry without an id.")

        entry.touch_updated()
        encrypted_password = self._cipher.encrypt(entry.password)
        encrypted_totp = self._cipher.encrypt(entry.totp_secret) if entry.totp_secret else ""

        with get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE entries
                SET service_name = ?, username = ?, encrypted_password = ?,
                    url = ?, notes = ?, tag = ?, encrypted_totp_secret = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    entry.service_name,
                    entry.username,
                    encrypted_password,
                    entry.url,
                    entry.notes,
                    entry.tag,
                    encrypted_totp,
                    entry.updated_at,
                    entry.id,
                ),
            )
            if cursor.rowcount == 0:
                raise EntryNotFoundError(f"No entry found with id {entry.id}.")
        return entry

    # --- Delete ----------------------------------------------------------------

    def delete(self, entry_id: int) -> None:
        """Delete an entry by id."""
        with get_connection() as conn:
            cursor = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            if cursor.rowcount == 0:
                raise EntryNotFoundError(f"No entry found with id {entry_id}.")

    # --- Filtering ----------------------------------------------------------------

    def list_by_tag(self, tag: str) -> List[Entry]:
        """Return all entries with an exact (case-insensitive) tag match."""
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE LOWER(tag) = LOWER(?) "
                "ORDER BY service_name COLLATE NOCASE",
                (tag,),
            ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def list_tags(self) -> List[str]:
        """Return the distinct set of non-empty tags currently in use."""
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT tag FROM entries WHERE tag != '' ORDER BY tag COLLATE NOCASE"
            ).fetchall()
        return [row[0] for row in rows]

    def find_stale(self, days_threshold: int) -> List[Entry]:
        """Return entries whose updated_at is older than `days_threshold` days."""
        all_entries = self.list_all()
        stale = []
        for entry in all_entries:
            days = entry.days_since_update()
            if days is not None and days >= days_threshold:
                stale.append(entry)
        return stale

    # --- Helpers -----------------------------------------------------------------

    def _row_to_entry(self, row: sqlite3.Row) -> Entry:
        """Convert a DB row into an Entry, decrypting the password and TOTP secret."""
        decrypted_password = self._cipher.decrypt(row["encrypted_password"])

        encrypted_totp = row["encrypted_totp_secret"] if "encrypted_totp_secret" in row.keys() else ""
        decrypted_totp = self._cipher.decrypt(encrypted_totp) if encrypted_totp else ""

        return Entry(
            id=row["id"],
            service_name=row["service_name"],
            username=row["username"],
            password=decrypted_password,
            url=row["url"] or "",
            notes=row["notes"] or "",
            tag=row["tag"] if "tag" in row.keys() and row["tag"] else "",
            totp_secret=decrypted_totp,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
