"""
validators.py

Input validation helpers used across the CLI layer. Keeping validation logic
here (rather than scattered through command handlers) makes rules easy to
find and test in isolation.
"""

from __future__ import annotations

from vaultkeeper.utils.exceptions import ValidationError


def validate_non_empty(value: str, field_name: str) -> str:
    """Ensure a string field is not empty/whitespace-only. Returns the stripped value."""
    if value is None or not value.strip():
        raise ValidationError(f"{field_name} cannot be empty.")
    return value.strip()


def validate_master_password(password: str) -> str:
    """
    Validate master password meets minimum security requirements.
    This is intentionally stricter than the per-entry password rules, since
    the master password protects everything else.
    """
    if not password:
        raise ValidationError("Master password cannot be empty.")
    if len(password) < 10:
        raise ValidationError("Master password must be at least 10 characters long.")
    if password.lower() in {"password", "password123", "letmein", "qwerty123456"}:
        raise ValidationError("That master password is far too common — choose another.")
    return password


def validate_password_length(length: int, min_len: int, max_len: int) -> int:
    """Ensure a requested password length falls within allowed bounds."""
    if not (min_len <= length <= max_len):
        raise ValidationError(f"Length must be between {min_len} and {max_len}.")
    return length


def validate_service_name(service_name: str) -> str:
    """Validate a service name field."""
    return validate_non_empty(service_name, "Service name")


def validate_username(username: str) -> str:
    """Validate a username/email field."""
    return validate_non_empty(username, "Username")


def validate_tag(tag: str) -> str:
    """
    Validate (and normalize) a tag. Empty string is allowed (means "no tag"),
    but a non-empty tag is lowercased and trimmed for consistent filtering.
    """
    if tag is None:
        return ""
    return tag.strip().lower()
