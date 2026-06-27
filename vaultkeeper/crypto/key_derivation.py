"""
key_derivation.py

Derives a symmetric encryption key from the user's master password using
PBKDF2HMAC (SHA-256). We deliberately use a well-vetted, standard library
construction rather than anything custom.

The salt is generated once per vault and persisted in vault_config.json
(plaintext is fine — a salt is not a secret, its only job is to defeat
precomputed rainbow tables and ensure two identical passwords don't produce
identical keys).
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from vaultkeeper.config import KDF_ITERATIONS, KDF_SALT_BYTES


def generate_salt() -> bytes:
    """Generate a new cryptographically secure random salt."""
    return os.urandom(KDF_SALT_BYTES)


def derive_key(master_password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 32-byte key from the master password and salt, then encode it
    as a URL-safe base64 string — the format Fernet expects.

    Args:
        master_password: The plaintext master password (never stored).
        salt: Random bytes unique to this vault.
        iterations: PBKDF2 iteration count (higher = slower = more brute-force
            resistant). Defaults to the project-wide constant.

    Returns:
        A base64-encoded 32-byte key suitable for use with Fernet.
    """
    if not master_password:
        raise ValueError("Master password must not be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def salt_to_str(salt: bytes) -> str:
    """Encode raw salt bytes as a string for JSON storage."""
    return base64.urlsafe_b64encode(salt).decode("utf-8")


def salt_from_str(salt_str: str) -> bytes:
    """Decode a stored salt string back into raw bytes."""
    return base64.urlsafe_b64decode(salt_str.encode("utf-8"))
