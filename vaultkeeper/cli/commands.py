"""
commands.py

Command implementations for VaultKeeper. Each function corresponds to one
CLI subcommand and is called from main.py's argparse dispatch.

Commands take a `Cipher` (already unlocked via master password) and build
an EntryRepository internally — this keeps main.py thin and keeps all
business logic testable in isolation from argparse.
"""

from __future__ import annotations

import getpass
from pathlib import Path
from typing import Optional

from vaultkeeper.cli import display
from vaultkeeper.crypto.cipher import Cipher
from vaultkeeper.crypto.password_gen import generate_password
from vaultkeeper.storage.backup import export_backup, import_backup
from vaultkeeper.storage.csv_io import export_to_csv, import_from_csv
from vaultkeeper.storage.models import Entry
from vaultkeeper.storage.repository import EntryRepository
from vaultkeeper.utils import validators
from vaultkeeper.utils.audit import run_audit
from vaultkeeper.utils.clipboard import copy_with_autoclear
from vaultkeeper.utils.exceptions import (
    DuplicateEntryError,
    EntryNotFoundError,
    ValidationError,
)
from vaultkeeper.utils.strength_checker import check_strength
from vaultkeeper.utils.totp import generate_code, validate_totp_secret


# --- add -------------------------------------------------------------------------

def cmd_add(
    cipher: Cipher,
    service_name: str,
    username: str,
    password: Optional[str] = None,
    url: str = "",
    notes: str = "",
    tag: str = "",
    totp_secret: Optional[str] = None,
    auto_generate: bool = False,
    gen_length: int = 16,
) -> None:
    """Add a new credential entry, optionally auto-generating the password."""
    repo = EntryRepository(cipher)

    try:
        service_name = validators.validate_service_name(service_name)
        username = validators.validate_username(username)
        tag = validators.validate_tag(tag)

        if auto_generate:
            password = generate_password(length=gen_length)
            display.info(f"Generated password: {password}")
        elif not password:
            password = getpass.getpass("Password: ")

        if not password:
            raise ValidationError("Password cannot be empty.")

        if totp_secret:
            totp_secret = validate_totp_secret(totp_secret)

        entry = Entry(
            service_name=service_name,
            username=username,
            password=password,
            url=url,
            notes=notes,
            tag=tag,
            totp_secret=totp_secret or "",
        )
        saved = repo.add(entry)
        display.success(f"Added entry for '{saved.service_name}' (id={saved.id}).")

    except (ValidationError, DuplicateEntryError) as exc:
        display.error(str(exc))


# --- get -------------------------------------------------------------------------

def cmd_get(cipher: Cipher, service_name: str, show: bool = False, no_clipboard: bool = False) -> None:
    """Retrieve an entry by service name. Copies password to clipboard by default."""
    repo = EntryRepository(cipher)
    try:
        entries = repo.get_by_service(service_name)
    except EntryNotFoundError as exc:
        display.error(str(exc))
        return

    for entry in entries:
        display.print_entry_detail(entry, show_password=show)
        if entry.has_totp():
            totp_code = generate_code(entry.totp_secret)
            display.info(f"2FA code: {totp_code.code} (expires in {totp_code.seconds_remaining}s)")
        if not no_clipboard:
            copied = copy_with_autoclear(entry.password)
            if copied:
                display.info(f"Password copied to clipboard (clears in 15s).")
            else:
                display.warning(
                    "Clipboard unavailable in this environment — use --show to view the password."
                )


# --- list ------------------------------------------------------------------------

def cmd_list(cipher: Cipher, tag: Optional[str] = None, stale_days: Optional[int] = None) -> None:
    """List entries. Optionally filter by tag, or by staleness (days since update)."""
    repo = EntryRepository(cipher)

    if stale_days is not None:
        entries = repo.find_stale(stale_days)
        if not entries:
            display.success(f"No entries are older than {stale_days} days. Nothing's stale.")
            return
        display.warning(f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
                         f"not updated in {stale_days}+ days:")
        display.print_entries_table(entries, show_passwords=False, show_age=True)
        return

    if tag:
        tag = validators.validate_tag(tag)
        entries = repo.list_by_tag(tag)
        if not entries:
            display.warning(f"No entries found with tag '{tag}'.")
            return
    else:
        entries = repo.list_all()

    display.print_entries_table(entries, show_passwords=False)


# --- tags ------------------------------------------------------------------------

def cmd_tags(cipher: Cipher) -> None:
    """List all distinct tags currently in use, with entry counts."""
    repo = EntryRepository(cipher)
    tags = repo.list_tags()
    if not tags:
        display.warning("No tags in use yet. Add one with: add --tag <name> ...")
        return

    print()
    for tag in tags:
        count = len(repo.list_by_tag(tag))
        print(f"  {tag} ({count} entr{'y' if count == 1 else 'ies'})")
    print()


# --- search ----------------------------------------------------------------------

def cmd_search(cipher: Cipher, query: str) -> None:
    """Fuzzy search entries by service name."""
    repo = EntryRepository(cipher)
    try:
        query = validators.validate_non_empty(query, "Search query")
    except ValidationError as exc:
        display.error(str(exc))
        return

    results = repo.search(query)
    display.print_entries_table(results, show_passwords=False)


# --- update ------------------------------------------------------------------------

def cmd_update(
    cipher: Cipher,
    service_name: str,
    new_username: Optional[str] = None,
    new_password: Optional[str] = None,
    new_url: Optional[str] = None,
    new_notes: Optional[str] = None,
    new_tag: Optional[str] = None,
    new_totp_secret: Optional[str] = None,
) -> None:
    """Update an existing entry. Only provided fields are changed."""
    repo = EntryRepository(cipher)
    try:
        matches = repo.get_by_service(service_name)
    except EntryNotFoundError as exc:
        display.error(str(exc))
        return

    if len(matches) > 1:
        display.warning(
            f"Multiple entries found for '{service_name}'. Updating the first match "
            f"(id={matches[0].id}). Use delete + add if you need finer control."
        )

    entry = matches[0]
    try:
        if new_username:
            entry.username = validators.validate_username(new_username)
        if new_password:
            entry.password = new_password
        if new_url is not None:
            entry.url = new_url
        if new_notes is not None:
            entry.notes = new_notes
        if new_tag is not None:
            entry.tag = validators.validate_tag(new_tag)
        if new_totp_secret is not None:
            entry.totp_secret = validate_totp_secret(new_totp_secret) if new_totp_secret else ""
    except ValidationError as exc:
        display.error(str(exc))
        return

    repo.update(entry)
    display.success(f"Updated entry for '{entry.service_name}' (id={entry.id}).")


# --- regen ------------------------------------------------------------------------

def cmd_regen(
    cipher: Cipher,
    service_name: str,
    auto_generate: bool = False,
    gen_length: int = 16,
) -> None:
    """
    Rotate the password for an existing entry.

    Without --generate: prompts you to type/paste in a password you've
    already changed on the website yourself, and just updates the record.

    With --generate: creates a new secure password, saves it, and prints it
    clearly so you can copy it into the website's "change password" form.
    """
    repo = EntryRepository(cipher)
    try:
        matches = repo.get_by_service(service_name)
    except EntryNotFoundError as exc:
        display.error(str(exc))
        return

    entry = matches[0]
    if len(matches) > 1:
        display.warning(
            f"Multiple entries found for '{service_name}'. Rotating the first match "
            f"(id={entry.id})."
        )

    if auto_generate:
        new_password = generate_password(length=gen_length)
        display.info(f"New password generated for '{entry.service_name}':")
        print(f"\n  {new_password}\n")
        display.warning(
            "Go update this on the website now — VaultKeeper only stores it locally, "
            "it doesn't change anything on the service itself."
        )
    else:
        display.info(
            f"Enter the new password for '{entry.service_name}' "
            f"(the one you've already set on the website):"
        )
        new_password = getpass.getpass("New password: ")
        if not new_password:
            display.error("Password cannot be empty. Rotation cancelled.")
            return

    entry.password = new_password
    repo.update(entry)
    display.success(f"Password rotated for '{entry.service_name}' (id={entry.id}).")


# --- delete ------------------------------------------------------------------------

def cmd_delete(cipher: Cipher, service_name: str, confirm: bool = False) -> None:
    """Delete an entry by service name, with confirmation unless --yes is passed."""
    repo = EntryRepository(cipher)
    try:
        matches = repo.get_by_service(service_name)
    except EntryNotFoundError as exc:
        display.error(str(exc))
        return

    for entry in matches:
        if not confirm:
            answer = input(
                f"Delete '{entry.service_name}' ({entry.username})? [y/N]: "
            ).strip().lower()
            if answer != "y":
                display.info(f"Skipped '{entry.service_name}'.")
                continue
        repo.delete(entry.id)
        display.success(f"Deleted entry for '{entry.service_name}'.")


# --- generate ------------------------------------------------------------------------

def cmd_generate(
    length: int = 16,
    no_uppercase: bool = False,
    no_lowercase: bool = False,
    no_digits: bool = False,
    no_symbols: bool = False,
    exclude_ambiguous: bool = False,
) -> None:
    """Generate a standalone password without saving it anywhere."""
    try:
        password = generate_password(
            length=length,
            use_uppercase=not no_uppercase,
            use_lowercase=not no_lowercase,
            use_digits=not no_digits,
            use_symbols=not no_symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
        print(password)
        result = check_strength(password)
        display.print_strength_result(result)
    except ValidationError as exc:
        display.error(str(exc))


# --- check-strength ------------------------------------------------------------------

def cmd_check_strength(password: Optional[str] = None) -> None:
    """Check the strength of a given password (prompts securely if not provided)."""
    if not password:
        password = getpass.getpass("Password to check: ")
    result = check_strength(password)
    display.print_strength_result(result)


# --- export ------------------------------------------------------------------------

def cmd_export(cipher: Cipher, output_path: str) -> None:
    """Export the full vault to an encrypted backup file."""
    repo = EntryRepository(cipher)
    entries = repo.list_all()

    if not entries:
        display.warning("Vault is empty — nothing to export.")
        return

    passphrase = getpass.getpass("Set a passphrase to protect this backup: ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        display.error("Passphrases did not match. Export cancelled.")
        return

    try:
        export_backup(entries, passphrase, Path(output_path))
        display.success(f"Exported {len(entries)} entries to {output_path}.")
    except Exception as exc:  # noqa: BLE001
        display.error(f"Export failed: {exc}")


# --- import ------------------------------------------------------------------------

def cmd_import(cipher: Cipher, input_path: str) -> None:
    """Import entries from an encrypted backup file into the current vault."""
    passphrase = getpass.getpass("Backup passphrase: ")

    try:
        entries = import_backup(passphrase, Path(input_path))
    except Exception as exc:  # noqa: BLE001
        display.error(f"Import failed: {exc}")
        return

    repo = EntryRepository(cipher)
    imported, skipped = 0, 0
    for entry in entries:
        entry.id = None  # force insert, not update
        try:
            repo.add(entry)
            imported += 1
        except DuplicateEntryError:
            skipped += 1

    display.success(f"Imported {imported} entries ({skipped} skipped as duplicates).")


# --- import-csv ------------------------------------------------------------------------

def cmd_import_csv(cipher: Cipher, input_path: str) -> None:
    """
    Bulk-import existing passwords from a plain CSV file (service_name,
    username, password, url, notes, tag columns; only the first three are
    required). Duplicates (same service+username) are skipped, not errored.
    """
    try:
        result = import_from_csv(Path(input_path))
    except Exception as exc:  # noqa: BLE001
        display.error(f"CSV import failed: {exc}")
        return

    if result.skipped_rows:
        display.warning(f"{len(result.skipped_rows)} row(s) skipped while parsing:")
        for row_num, reason in result.skipped_rows:
            print(f"    row {row_num}: {reason}")

    if not result.entries:
        display.warning("No valid rows found to import.")
        return

    repo = EntryRepository(cipher)
    imported, duplicates = 0, 0
    for entry in result.entries:
        try:
            repo.add(entry)
            imported += 1
        except DuplicateEntryError:
            duplicates += 1

    display.success(
        f"Imported {imported} entries from CSV ({duplicates} skipped as duplicates)."
    )


# --- export-csv ------------------------------------------------------------------------

def cmd_export_csv(cipher: Cipher, output_path: str, confirm: bool = False) -> None:
    """
    Export the vault to a PLAINTEXT CSV file. Unlike `export` (which is
    encrypted), this is intended for moving data into spreadsheets or other
    tools — so we warn loudly and require explicit confirmation.
    """
    repo = EntryRepository(cipher)
    entries = repo.list_all()

    if not entries:
        display.warning("Vault is empty — nothing to export.")
        return

    if not confirm:
        display.warning(
            f"This will write ALL {len(entries)} passwords to '{output_path}' "
            f"as PLAIN TEXT (not encrypted). Anyone with access to that file "
            f"can read every password."
        )
        answer = input("Type 'yes' to continue: ").strip().lower()
        if answer != "yes":
            display.info("CSV export cancelled.")
            return

    try:
        export_to_csv(entries, Path(output_path))
        display.success(f"Exported {len(entries)} entries to {output_path} (plaintext).")
    except Exception as exc:  # noqa: BLE001
        display.error(f"CSV export failed: {exc}")


# --- audit ------------------------------------------------------------------------

def cmd_audit(cipher: Cipher) -> None:
    """Scan the vault for reused and weak passwords."""
    repo = EntryRepository(cipher)
    entries = repo.list_all()

    if not entries:
        display.warning("Vault is empty — nothing to audit.")
        return

    report = run_audit(entries)
    display.print_audit_report(report)
