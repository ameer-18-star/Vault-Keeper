"""
master_auth.py

Handles master password setup and verification.

Design: We never store the master password. Instead, on vault creation we:
  1. Generate a random salt.
  2. Derive a Fernet key from (master_password, salt) via PBKDF2.
  3. Encrypt a known "canary" string with that key and store the ciphertext.

On login, we re-derive the key from the entered password + stored salt, then
try decrypting the canary. If it decrypts to the expected value, the password
is correct — without ever needing to store the password itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from vaultkeeper import config
from vaultkeeper.crypto.cipher import Cipher
from vaultkeeper.crypto.key_derivation import derive_key, generate_salt, salt_from_str, salt_to_str
from vaultkeeper.utils.exceptions import (
    InvalidMasterPasswordError,
    VaultAlreadyExistsError,
    VaultNotInitializedError,
)

CANARY_PLAINTEXT = "vaultkeeper-canary-value-do-not-change"


def _vault_config_path() -> Path:
    """Resolve the vault config path at call time (not import time)."""
    return config.VAULT_CONFIG_PATH


def vault_is_initialized() -> bool:
    """Check whether a master password has already been set up."""
    return _vault_config_path().exists()


def setup_master_password(master_password: str) -> Cipher:
    """
    Initialize a brand-new vault: generate a salt, derive a key, encrypt the
    canary, and persist the salt + KDF params + encrypted canary to disk.

    Returns:
        A ready-to-use Cipher instance for the new vault.

    Raises:
        VaultAlreadyExistsError: If a vault config already exists.
    """
    if vault_is_initialized():
        raise VaultAlreadyExistsError(
            "A vault already exists. Delete vault_config.json and vault.db "
            "to start over, or use the login flow instead."
        )

    config.ensure_data_dir()

    salt = generate_salt()
    key = derive_key(master_password, salt)
    cipher = Cipher(key)
    encrypted_canary = cipher.encrypt(CANARY_PLAINTEXT)

    vault_config = {
        "salt": salt_to_str(salt),
        "kdf_iterations": config.KDF_ITERATIONS,
        "kdf_algorithm": config.KDF_ALGORITHM,
        "canary": encrypted_canary,
    }

    with open(_vault_config_path(), "w", encoding="utf-8") as f:
        json.dump(vault_config, f, indent=2)

    return cipher


def verify_master_password(master_password: str) -> Cipher:
    """
    Verify a master password attempt against the stored canary and return a
    ready-to-use Cipher if correct.

    Raises:
        VaultNotInitializedError: If no vault config exists yet.
        InvalidMasterPasswordError: If the password is incorrect.
    """
    if not vault_is_initialized():
        raise VaultNotInitializedError(
            "No vault found. Run the setup flow to create a master password first."
        )

    with open(_vault_config_path(), "r", encoding="utf-8") as f:
        vault_config = json.load(f)

    salt = salt_from_str(vault_config["salt"])
    iterations = vault_config.get("kdf_iterations", config.KDF_ITERATIONS)
    key = derive_key(master_password, salt, iterations=iterations)
    cipher = Cipher(key)

    if not cipher.verify_canary(vault_config["canary"], CANARY_PLAINTEXT):
        raise InvalidMasterPasswordError("Incorrect master password.")

    return cipher


def change_master_password(current_password: str, new_password: str) -> Cipher:
    """
    Re-key the vault: verify the current password, derive a new salt/key for
    the new password, and store a new encrypted canary.

    NOTE: This does NOT re-encrypt existing entries — that's the caller's
    responsibility (see cli/commands.py for the full re-key flow, which
    decrypts all entries with the old cipher and re-saves them with the new one).
    """
    # Verifies current password is correct; raises InvalidMasterPasswordError if not.
    verify_master_password(current_password)

    salt = generate_salt()
    key = derive_key(new_password, salt)
    new_cipher = Cipher(key)
    encrypted_canary = new_cipher.encrypt(CANARY_PLAINTEXT)

    vault_config = {
        "salt": salt_to_str(salt),
        "kdf_iterations": config.KDF_ITERATIONS,
        "kdf_algorithm": config.KDF_ALGORITHM,
        "canary": encrypted_canary,
    }

    with open(_vault_config_path(), "w", encoding="utf-8") as f:
        json.dump(vault_config, f, indent=2)

    return new_cipher
