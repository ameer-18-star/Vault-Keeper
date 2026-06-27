"""
csv_io.py

Bulk import of existing passwords from a plain CSV file, and CSV export
for users who want a portable (unencrypted!) copy outside VaultKeeper.

Expected CSV columns (header row required): service_name, username,
password, url, notes, tag — extra/missing optional columns are tolerated;
only service_name, username, and password are required per row.

SECURITY NOTE: unlike storage/backup.py (which is encrypted), a CSV export
is plaintext by nature — that's the whole point of CSV interoperability
with other tools/spreadsheets. We warn loudly about this in the CLI layer.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import List

from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.exceptions import BackupError

REQUIRED_COLUMNS = {"service_name", "username", "password"}
OPTIONAL_COLUMNS = {"url", "notes", "tag"}


@dataclass
class CsvImportResult:
    entries: List[Entry]
    skipped_rows: List[tuple]  # (row_number, reason)


def import_from_csv(input_path: Path) -> CsvImportResult:
    """
    Read a CSV file of existing credentials and return parsed Entry objects.
    Rows missing a required field are skipped (not fatal) and reported back
    so the caller can show the user what was skipped and why.
    """
    if not input_path.exists():
        raise BackupError(f"CSV file not found: {input_path}")

    try:
        with open(input_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise BackupError("CSV file appears to be empty.")

            header = {name.strip().lower() for name in reader.fieldnames}
            missing = REQUIRED_COLUMNS - header
            if missing:
                raise BackupError(
                    f"CSV is missing required column(s): {', '.join(sorted(missing))}. "
                    f"Required columns: {', '.join(sorted(REQUIRED_COLUMNS))}."
                )

            entries: List[Entry] = []
            skipped: List[tuple] = []

            for row_num, raw_row in enumerate(reader, start=2):  # row 1 = header
                row = {k.strip().lower(): (v or "").strip() for k, v in raw_row.items() if k}

                service_name = row.get("service_name", "")
                username = row.get("username", "")
                password = row.get("password", "")

                if not service_name or not username or not password:
                    skipped.append((row_num, "missing service_name, username, or password"))
                    continue

                entries.append(Entry(
                    service_name=service_name,
                    username=username,
                    password=password,
                    url=row.get("url", ""),
                    notes=row.get("notes", ""),
                    tag=row.get("tag", ""),
                ))

            return CsvImportResult(entries=entries, skipped_rows=skipped)

    except csv.Error as exc:
        raise BackupError(f"Failed to parse CSV file: {exc}") from exc
    except OSError as exc:
        raise BackupError(f"Failed to read CSV file: {exc}") from exc


def export_to_csv(entries: List[Entry], output_path: Path) -> None:
    """
    Write entries to a plaintext CSV file. Caller is responsible for warning
    the user that this file is NOT encrypted (see cli/commands.py).
    """
    fieldnames = ["service_name", "username", "password", "url", "notes", "tag", "updated_at"]
    try:
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow({
                    "service_name": entry.service_name,
                    "username": entry.username,
                    "password": entry.password,
                    "url": entry.url,
                    "notes": entry.notes,
                    "tag": entry.tag,
                    "updated_at": entry.updated_at or "",
                })
    except OSError as exc:
        raise BackupError(f"Failed to write CSV file: {exc}") from exc
