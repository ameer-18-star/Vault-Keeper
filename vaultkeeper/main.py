#!/usr/bin/env python3
"""
main.py

Entry point for VaultKeeper. Handles:
  - First-run setup (creating the master password + database).
  - Master password login (with brute-force lockout) on every subsequent run.
  - argparse subcommand dispatch to vaultkeeper.cli.commands.

Usage examples:
    python -m vaultkeeper.main add --service GitHub --username ali@example.com
    python -m vaultkeeper.main get GitHub
    python -m vaultkeeper.main list
    python -m vaultkeeper.main generate --length 20 --exclude-ambiguous
"""

from __future__ import annotations

import argparse
import getpass
import sys

from vaultkeeper import config
from vaultkeeper.auth import lockout, master_auth
from vaultkeeper.cli import commands, display
from vaultkeeper.storage.database import database_exists, initialize_database
from vaultkeeper.utils.exceptions import (
    InvalidMasterPasswordError,
    VaultKeeperError,
    VaultLockedOutError,
    VaultNotInitializedError,
)
from vaultkeeper.utils.validators import validate_master_password


def first_run_setup() -> None:
    """Interactive first-run flow: create the master password and database."""
    display.banner()
    print("No vault found. Let's set one up.\n")

    while True:
        pw = getpass.getpass("Create a master password (min 10 characters): ")
        try:
            validate_master_password(pw)
        except VaultKeeperError as exc:
            display.error(str(exc))
            continue

        confirm = getpass.getpass("Confirm master password: ")
        if pw != confirm:
            display.error("Passwords did not match. Try again.\n")
            continue
        break

    master_auth.setup_master_password(pw)
    initialize_database()
    display.success("Vault created successfully. You're ready to go!\n")


def login() -> "Cipher":  # noqa: F821 - Cipher imported lazily to avoid unused-import noise
    """Prompt for the master password, enforcing lockout, and return an unlocked Cipher."""
    from vaultkeeper.crypto.cipher import Cipher  # local import for clarity at call site

    try:
        lockout.check_lockout()
    except VaultLockedOutError as exc:
        display.error(str(exc))
        sys.exit(1)

    pw = getpass.getpass("Master password: ")
    try:
        cipher = master_auth.verify_master_password(pw)
    except InvalidMasterPasswordError as exc:
        duration = lockout.record_failed_attempt()
        display.error(str(exc))
        if duration:
            display.warning(f"Too many failed attempts. Locked out for {duration} seconds.")
        sys.exit(1)
    except VaultNotInitializedError as exc:
        display.error(str(exc))
        sys.exit(1)

    lockout.record_successful_attempt()
    return cipher


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultkeeper",
        description="VaultKeeper — a local, encrypted CLI password manager.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # add
    p_add = sub.add_parser("add", help="Add a new credential entry.")
    p_add.add_argument("--service", required=True, help="Service/site name.")
    p_add.add_argument("--username", required=True, help="Username or email.")
    p_add.add_argument("--password", help="Password (omit to be prompted, or use --generate).")
    p_add.add_argument("--generate", action="store_true", help="Auto-generate a secure password.")
    p_add.add_argument("--length", type=int, default=config.DEFAULT_PASSWORD_LENGTH,
                        help="Length for --generate.")
    p_add.add_argument("--url", default="", help="Optional URL for the service.")
    p_add.add_argument("--notes", default="", help="Optional notes.")
    p_add.add_argument("--tag", default="", help="Optional tag/category (e.g. work, banking).")
    p_add.add_argument("--totp-secret", help="Optional base32 TOTP secret for 2FA codes.")

    # get
    p_get = sub.add_parser("get", help="Retrieve a credential entry.")
    p_get.add_argument("service", help="Service/site name to look up.")
    p_get.add_argument("--show", action="store_true", help="Print the password instead of just copying it.")
    p_get.add_argument("--no-clipboard", action="store_true", help="Don't copy the password to clipboard.")

    # list
    p_list = sub.add_parser("list", help="List entries (passwords masked).")
    p_list.add_argument("--tag", help="Only show entries with this tag.")
    p_list.add_argument("--stale-days", type=int,
                         help="Only show entries not updated in this many days.")

    # search
    p_search = sub.add_parser("search", help="Fuzzy search entries by service name.")
    p_search.add_argument("query", help="Search term.")

    # update
    p_update = sub.add_parser("update", help="Update an existing entry.")
    p_update.add_argument("service", help="Service/site name to update.")
    p_update.add_argument("--username", help="New username.")
    p_update.add_argument("--password", help="New password.")
    p_update.add_argument("--url", help="New URL.")
    p_update.add_argument("--notes", help="New notes.")
    p_update.add_argument("--tag", help="New tag/category.")
    p_update.add_argument("--totp-secret", help="New base32 TOTP secret (pass '' to remove).")

    # delete
    p_delete = sub.add_parser("delete", help="Delete an entry.")
    p_delete.add_argument("service", help="Service/site name to delete.")
    p_delete.add_argument("--yes", action="store_true", help="Skip confirmation prompt.")

    # regen
    p_regen = sub.add_parser("regen", help="Rotate the password for an existing entry.")
    p_regen.add_argument("service", help="Service/site name to rotate.")
    p_regen.add_argument("--generate", action="store_true",
                          help="Generate a new password instead of entering one you already set.")
    p_regen.add_argument("--length", type=int, default=config.DEFAULT_PASSWORD_LENGTH,
                          help="Length for --generate.")

    # tags
    sub.add_parser("tags", help="List all tags currently in use.")

    # generate
    p_gen = sub.add_parser("generate", help="Generate a standalone secure password.")
    p_gen.add_argument("--length", type=int, default=config.DEFAULT_PASSWORD_LENGTH)
    p_gen.add_argument("--no-uppercase", action="store_true")
    p_gen.add_argument("--no-lowercase", action="store_true")
    p_gen.add_argument("--no-digits", action="store_true")
    p_gen.add_argument("--no-symbols", action="store_true")
    p_gen.add_argument("--exclude-ambiguous", action="store_true")

    # check-strength
    p_strength = sub.add_parser("check-strength", help="Check the strength of a password.")
    p_strength.add_argument("password", nargs="?", help="Password to check (omit to be prompted securely).")

    # export
    p_export = sub.add_parser("export", help="Export the vault to an encrypted backup file.")
    p_export.add_argument("output_path", help="Path to write the backup file.")

    # import
    p_import = sub.add_parser("import", help="Import entries from an encrypted backup file.")
    p_import.add_argument("input_path", help="Path to the backup file.")

    # import-csv
    p_import_csv = sub.add_parser(
        "import-csv", help="Bulk-import existing passwords from a plain CSV file."
    )
    p_import_csv.add_argument(
        "input_path",
        help="Path to a CSV with columns: service_name, username, password, url, notes, tag "
             "(only the first three are required).",
    )

    # export-csv
    p_export_csv = sub.add_parser(
        "export-csv", help="Export the vault to a PLAINTEXT CSV file (not encrypted)."
    )
    p_export_csv.add_argument("output_path", help="Path to write the CSV file.")
    p_export_csv.add_argument("--yes", action="store_true",
                               help="Skip the plaintext-export confirmation prompt.")

    # audit
    sub.add_parser("audit", help="Scan the vault for reused and weak passwords.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # `generate` and `check-strength` (with a positional password) don't need vault access.
    if args.command == "generate":
        commands.cmd_generate(
            length=args.length,
            no_uppercase=args.no_uppercase,
            no_lowercase=args.no_lowercase,
            no_digits=args.no_digits,
            no_symbols=args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
        return

    if args.command == "check-strength":
        commands.cmd_check_strength(password=args.password)
        return

    # Everything else requires an unlocked vault.
    if not database_exists() or not master_auth.vault_is_initialized():
        first_run_setup()
        cipher = login()
    else:
        # Existing vault: make sure schema is up to date (adds any columns
        # introduced by newer features, e.g. tags/TOTP) before logging in.
        initialize_database()
        cipher = login()

    if args.command == "add":
        commands.cmd_add(
            cipher,
            service_name=args.service,
            username=args.username,
            password=args.password,
            url=args.url,
            notes=args.notes,
            tag=args.tag,
            totp_secret=args.totp_secret,
            auto_generate=args.generate,
            gen_length=args.length,
        )
    elif args.command == "get":
        commands.cmd_get(cipher, args.service, show=args.show, no_clipboard=args.no_clipboard)
    elif args.command == "list":
        commands.cmd_list(cipher, tag=args.tag, stale_days=args.stale_days)
    elif args.command == "search":
        commands.cmd_search(cipher, args.query)
    elif args.command == "update":
        commands.cmd_update(
            cipher,
            service_name=args.service,
            new_username=args.username,
            new_password=args.password,
            new_url=args.url,
            new_notes=args.notes,
            new_tag=args.tag,
            new_totp_secret=args.totp_secret,
        )
    elif args.command == "delete":
        commands.cmd_delete(cipher, args.service, confirm=args.yes)
    elif args.command == "regen":
        commands.cmd_regen(cipher, args.service, auto_generate=args.generate, gen_length=args.length)
    elif args.command == "tags":
        commands.cmd_tags(cipher)
    elif args.command == "export":
        commands.cmd_export(cipher, args.output_path)
    elif args.command == "import":
        commands.cmd_import(cipher, args.input_path)
    elif args.command == "import-csv":
        commands.cmd_import_csv(cipher, args.input_path)
    elif args.command == "export-csv":
        commands.cmd_export_csv(cipher, args.output_path, confirm=args.yes)
    elif args.command == "audit":
        commands.cmd_audit(cipher)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except VaultKeeperError as exc:
        display.error(str(exc))
        sys.exit(1)
