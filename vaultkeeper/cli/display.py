"""
display.py

Output formatting for the CLI: tables, colored status messages, banners.
Uses `tabulate` for tables and ANSI codes directly (kept dependency-light;
falls back gracefully on terminals without color support is out of scope
for a moderate-level project, but codes are simple SGR sequences that most
terminals — including Windows 10+ — handle fine).
"""

from __future__ import annotations

from typing import List

from tabulate import tabulate

from vaultkeeper.storage.models import Entry


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def success(message: str) -> None:
    print(f"{Color.GREEN}✔ {message}{Color.RESET}")


def error(message: str) -> None:
    print(f"{Color.RED}✘ {message}{Color.RESET}")


def warning(message: str) -> None:
    print(f"{Color.YELLOW}⚠ {message}{Color.RESET}")


def info(message: str) -> None:
    print(f"{Color.CYAN}ℹ {message}{Color.RESET}")


def banner() -> None:
    print(f"{Color.BOLD}{Color.BLUE}")
    print("╔══════════════════════════════════════╗")
    print("║            VAULTKEEPER                ║")
    print("║   Local Encrypted Password Manager    ║")
    print("╚══════════════════════════════════════╝")
    print(Color.RESET)


def print_entries_table(entries: List[Entry], show_passwords: bool = False, show_age: bool = False) -> None:
    """Print a table of entries. Passwords are masked unless explicitly shown.

    If show_age is True, replaces the Updated column with a 'Days ago' column
    (used by the stale-entries view, where the count is the point).
    """
    if not entries:
        warning("No entries to display.")
        return

    if show_age:
        headers = ["ID", "Service", "Username", "Tag", "Days since update"]
    else:
        headers = ["ID", "Service", "Username", "Tag", "Password", "2FA", "Updated"]

    rows = []
    for e in entries:
        if show_age:
            days = e.days_since_update()
            rows.append([
                e.id,
                e.service_name,
                e.username,
                e.tag or "-",
                days if days is not None else "-",
            ])
        else:
            password_display = e.password if show_passwords else "•" * 10
            rows.append([
                e.id,
                e.service_name,
                e.username,
                e.tag or "-",
                password_display,
                "✔" if e.has_totp() else "-",
                e.updated_at or "-",
            ])
    print(tabulate(rows, headers=headers, tablefmt="rounded_grid"))


def print_entry_detail(entry: Entry, show_password: bool = True) -> None:
    """Print a single entry's full details (used by `get`)."""
    print(f"\n{Color.BOLD}{entry.service_name}{Color.RESET}")
    print(f"  Username: {entry.username}")
    if show_password:
        print(f"  Password: {Color.YELLOW}{entry.password}{Color.RESET}")
    if entry.url:
        print(f"  URL:      {entry.url}")
    if entry.notes:
        print(f"  Notes:    {entry.notes}")
    if entry.tag:
        print(f"  Tag:      {entry.tag}")
    if entry.has_totp():
        print(f"  2FA:      enabled")
    days = entry.days_since_update()
    age_note = f" ({days} days ago)" if days is not None else ""
    print(f"  Updated:  {Color.GRAY}{entry.updated_at}{age_note}{Color.RESET}\n")


def print_strength_result(result) -> None:
    """Print a StrengthResult from utils.strength_checker."""
    level_colors = {
        "Very Weak": Color.RED,
        "Weak": Color.RED,
        "Moderate": Color.YELLOW,
        "Strong": Color.GREEN,
        "Very Strong": Color.GREEN,
    }
    color = level_colors.get(result.level.value, Color.RESET)
    print(f"\nStrength: {color}{Color.BOLD}{result.level.value}{Color.RESET} ({result.score}/100)")
    print(f"Estimated entropy: {result.entropy_bits} bits")
    for line in result.feedback:
        print(f"  • {line}")
    print()


def print_audit_report(report) -> None:
    """Print an AuditReport from utils.audit."""
    print(f"\n{Color.BOLD}Vault Audit — {report.total_entries} entries scanned{Color.RESET}\n")

    if not report.has_issues:
        success("No reused or weak passwords found. Nice work!")
        print()
        return

    if report.reuse_groups:
        print(f"{Color.RED}{Color.BOLD}Reused passwords:{Color.RESET}")
        for group in report.reuse_groups:
            services = ", ".join(e.service_name for e in group.entries)
            print(f"  • {len(group.entries)} entries share one password ({group.password_hint}): {services}")
        print()

    if report.weak_entries:
        print(f"{Color.YELLOW}{Color.BOLD}Weak passwords:{Color.RESET}")
        for weak in report.weak_entries:
            print(f"  • {weak.entry.service_name}: {weak.strength.level.value} "
                  f"({weak.strength.score}/100)")
        print()

    info("Tip: use `regen <service> --generate` to rotate any of these.")
    print()
