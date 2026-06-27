"""
exceptions.py

Custom exception hierarchy for VaultKeeper. Using specific exception types
(rather than bare Exception/ValueError everywhere) makes error handling in the
CLI layer precise and makes intent obvious when reading the code.
"""


class VaultKeeperError(Exception):
    """Base class for all VaultKeeper-specific exceptions."""


# --- Authentication / setup errors --------------------------------------------------

class VaultNotInitializedError(VaultKeeperError):
    """Raised when an operation requires a vault that hasn't been set up yet."""


class VaultAlreadyExistsError(VaultKeeperError):
    """Raised when trying to initialize a vault that already exists."""


class InvalidMasterPasswordError(VaultKeeperError):
    """Raised when the supplied master password fails verification."""


class VaultLockedOutError(VaultKeeperError):
    """Raised when too many failed master password attempts have occurred."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Vault is locked. Try again in {retry_after_seconds} seconds."
        )


# --- Crypto errors -------------------------------------------------------------------

class DecryptionError(VaultKeeperError):
    """Raised when decryption fails (wrong key, corrupted/tampered ciphertext)."""


class EncryptionError(VaultKeeperError):
    """Raised when encryption of a value fails unexpectedly."""


# --- Storage / data errors ------------------------------------------------------------

class EntryNotFoundError(VaultKeeperError):
    """Raised when a requested credential entry does not exist."""


class DuplicateEntryError(VaultKeeperError):
    """Raised when attempting to add an entry that already exists (same service+username)."""


class DatabaseError(VaultKeeperError):
    """Raised for unexpected database-layer failures."""


# --- Validation errors -----------------------------------------------------------------

class ValidationError(VaultKeeperError):
    """Raised when user-supplied input fails validation."""


# --- Import / export errors -------------------------------------------------------------

class BackupError(VaultKeeperError):
    """Raised when export or import of a vault backup fails."""
