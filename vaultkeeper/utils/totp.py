"""
totp.py

Generates live 6-digit TOTP (Time-based One-Time Password) codes from a
stored secret, using the industry-standard `pyotp` library (same algorithm
Google Authenticator, Authy, etc. use — RFC 6238).

VaultKeeper only *stores and displays* codes here; it doesn't validate
codes against a server. The secret itself is encrypted at rest by the same
Cipher used for passwords (see repository.py).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pyotp

from vaultkeeper.utils.exceptions import ValidationError


@dataclass
class TotpCode:
    code: str
    seconds_remaining: int


def validate_totp_secret(secret: str) -> str:
    """
    Validate that a string is a usable base32 TOTP secret by attempting to
    construct a TOTP object and generate a code from it.
    """
    secret = secret.strip().replace(" ", "").upper()
    if not secret:
        raise ValidationError("TOTP secret cannot be empty.")
    try:
        totp = pyotp.TOTP(secret)
        totp.now()  # raises if the secret isn't valid base32
    except Exception as exc:  # noqa: BLE001
        raise ValidationError(
            "That doesn't look like a valid TOTP secret (expected base32, "
            "e.g. 'JBSWY3DPEHPK3PXP')."
        ) from exc
    return secret


def generate_code(secret: str) -> TotpCode:
    """Generate the current 6-digit TOTP code and seconds remaining until it rotates."""
    totp = pyotp.TOTP(secret)
    code = totp.now()
    seconds_remaining = totp.interval - (int(time.time()) % totp.interval)
    return TotpCode(code=code, seconds_remaining=seconds_remaining)
