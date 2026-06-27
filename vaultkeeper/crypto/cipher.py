"""
cipher.py

Thin, intention-revealing wrapper around Fernet symmetric encryption.
Fernet (from the `cryptography` package) handles AES-128-CBC + HMAC
authentication for us — we don't implement any crypto primitives ourselves.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from vaultkeeper.utils.exceptions import DecryptionError, EncryptionError


class Cipher:
    """Encrypts and decrypts strings using a derived Fernet key."""

    def __init__(self, key: bytes):
        """
        Args:
            key: A base64-encoded 32-byte key, typically produced by
                key_derivation.derive_key().
        """
        try:
            self._fernet = Fernet(key)
        except Exception as exc:  # noqa: BLE001 - re-raise as our own type
            raise EncryptionError(f"Invalid encryption key: {exc}") from exc

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string, returning a base64 token as str."""
        if plaintext is None:
            plaintext = ""
        try:
            token = self._fernet.encrypt(plaintext.encode("utf-8"))
            return token.decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"Failed to encrypt value: {exc}") from exc

    def decrypt(self, token: str) -> str:
        """Decrypt a base64 Fernet token back into the original string."""
        try:
            plaintext = self._fernet.decrypt(token.encode("utf-8"))
            return plaintext.decode("utf-8")
        except InvalidToken as exc:
            raise DecryptionError(
                "Failed to decrypt value — wrong master password or corrupted data."
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise DecryptionError(f"Unexpected decryption failure: {exc}") from exc

    def verify_canary(self, encrypted_canary: str, expected_plaintext: str) -> bool:
        """
        Verify the derived key is correct by decrypting a known "canary" value
        and checking it matches what we expect. Used during master password
        login instead of ever storing the master password itself.
        """
        try:
            return self.decrypt(encrypted_canary) == expected_plaintext
        except DecryptionError:
            return False
