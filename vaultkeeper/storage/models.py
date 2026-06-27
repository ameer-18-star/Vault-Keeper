"""
models.py

Data model(s) for VaultKeeper. Using a dataclass keeps entries strongly typed
and self-documenting, instead of passing raw tuples/dicts around the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from vaultkeeper.config import DATE_FORMAT


@dataclass
class Entry:
    """
    Represents a single credential entry.

    `password` and `totp_secret` hold PLAINTEXT values only transiently in
    memory (e.g. right after decryption, or right before encryption). They
    are never written to disk in this form — the repository layer is
    responsible for encrypting/decrypting both fields at the storage boundary.
    """

    service_name: str
    username: str
    password: str = field(repr=False)  # repr=False avoids accidental plaintext logging
    url: str = ""
    notes: str = ""
    tag: str = ""
    totp_secret: str = field(default="", repr=False)
    id: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def touch_updated(self) -> None:
        """Update the `updated_at` timestamp to now."""
        self.updated_at = datetime.now().strftime(DATE_FORMAT)

    def touch_created(self) -> None:
        """Set both `created_at` and `updated_at` to now (used on insert)."""
        now = datetime.now().strftime(DATE_FORMAT)
        self.created_at = now
        self.updated_at = now

    def days_since_update(self) -> Optional[int]:
        """Number of whole days since updated_at, or None if unset/unparseable."""
        if not self.updated_at:
            return None
        try:
            updated = datetime.strptime(self.updated_at, DATE_FORMAT)
        except ValueError:
            return None
        return (datetime.now() - updated).days

    def has_totp(self) -> bool:
        """Whether this entry has a TOTP secret configured."""
        return bool(self.totp_secret)
