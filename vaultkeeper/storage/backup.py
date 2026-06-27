"""
backup.py

Export and import the vault as an encrypted backup file. The backup format
re-encrypts every entry's password under a backup-specific key derived from
a backup passphrase (which may be the same as the master password, or a
different one supplied at export time) — so backups are self-contained and
don't depend on the original vault_config.json salt.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from vaultkeeper.config import DATE_FORMAT
from vaultkeeper.crypto.cipher import Cipher
from vaultkeeper.crypto.key_derivation import derive_key, generate_salt, salt_from_str, salt_to_str
from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.exceptions import BackupError

BACKUP_FORMAT_VERSION = 1


def export_backup(entries: List[Entry], backup_passphrase: str, output_path: Path) -> None:
    """
    Export all entries to an encrypted JSON backup file.

    Each entry's password is re-encrypted with a key derived from
    `backup_passphrase` (independent of the live vault's master password),
    so the backup file is self-contained and portable.
    """
    try:
        salt = generate_salt()
        key = derive_key(backup_passphrase, salt)
        cipher = Cipher(key)

        backup_entries = []
        for entry in entries:
            backup_entries.append({
                "service_name": entry.service_name,
                "username": entry.username,
                "encrypted_password": cipher.encrypt(entry.password),
                "url": entry.url,
                "notes": entry.notes,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            })

        backup_data = {
            "format_version": BACKUP_FORMAT_VERSION,
            "exported_at": datetime.now().strftime(DATE_FORMAT),
            "salt": salt_to_str(salt),
            "entry_count": len(backup_entries),
            "entries": backup_entries,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)

    except OSError as exc:
        raise BackupError(f"Failed to write backup file: {exc}") from exc


def import_backup(backup_passphrase: str, input_path: Path) -> List[Entry]:
    """
    Read and decrypt an encrypted backup file, returning a list of Entry
    objects ready to be re-inserted into a (possibly different) vault.

    Raises:
        BackupError: If the file is missing, malformed, or the passphrase
            is wrong (decryption of any entry fails).
    """
    if not input_path.exists():
        raise BackupError(f"Backup file not found: {input_path}")

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            backup_data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise BackupError(f"Failed to read backup file: {exc}") from exc

    if backup_data.get("format_version") != BACKUP_FORMAT_VERSION:
        raise BackupError(
            f"Unsupported backup format version: {backup_data.get('format_version')}"
        )

    salt = salt_from_str(backup_data["salt"])
    key = derive_key(backup_passphrase, salt)
    cipher = Cipher(key)

    entries: List[Entry] = []
    try:
        for raw in backup_data["entries"]:
            password = cipher.decrypt(raw["encrypted_password"])
            entries.append(Entry(
                service_name=raw["service_name"],
                username=raw["username"],
                password=password,
                url=raw.get("url", ""),
                notes=raw.get("notes", ""),
                created_at=raw.get("created_at"),
                updated_at=raw.get("updated_at"),
            ))
    except Exception as exc:  # noqa: BLE001
        raise BackupError(
            "Failed to decrypt backup — incorrect passphrase or corrupted file."
        ) from exc

    return entries
