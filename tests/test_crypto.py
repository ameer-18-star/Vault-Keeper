"""
test_crypto.py

Tests for key derivation and the Fernet cipher wrapper.
"""

from __future__ import annotations

import pytest

from vaultkeeper.crypto.cipher import Cipher
from vaultkeeper.crypto.key_derivation import (
    derive_key,
    generate_salt,
    salt_from_str,
    salt_to_str,
)
from vaultkeeper.utils.exceptions import DecryptionError


class TestKeyDerivation:
    def test_generate_salt_returns_correct_length(self):
        salt = generate_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 16  # KDF_SALT_BYTES

    def test_generate_salt_is_random(self):
        assert generate_salt() != generate_salt()

    def test_derive_key_is_deterministic_given_same_inputs(self):
        salt = generate_salt()
        key1 = derive_key("my-password", salt, iterations=1000)
        key2 = derive_key("my-password", salt, iterations=1000)
        assert key1 == key2

    def test_derive_key_differs_with_different_passwords(self):
        salt = generate_salt()
        key1 = derive_key("password-one", salt, iterations=1000)
        key2 = derive_key("password-two", salt, iterations=1000)
        assert key1 != key2

    def test_derive_key_differs_with_different_salts(self):
        key1 = derive_key("same-password", generate_salt(), iterations=1000)
        key2 = derive_key("same-password", generate_salt(), iterations=1000)
        assert key1 != key2

    def test_derive_key_rejects_empty_password(self):
        with pytest.raises(ValueError):
            derive_key("", generate_salt(), iterations=1000)

    def test_salt_roundtrip_through_string_encoding(self):
        salt = generate_salt()
        encoded = salt_to_str(salt)
        decoded = salt_from_str(encoded)
        assert decoded == salt


class TestCipher:
    def _make_cipher(self, password: str = "test-pw", iterations: int = 1000) -> Cipher:
        salt = generate_salt()
        key = derive_key(password, salt, iterations=iterations)
        return Cipher(key)

    def test_encrypt_decrypt_roundtrip(self):
        cipher = self._make_cipher()
        plaintext = "my-secret-password-123!"
        token = cipher.encrypt(plaintext)
        assert cipher.decrypt(token) == plaintext

    def test_encrypted_token_is_not_plaintext(self):
        cipher = self._make_cipher()
        plaintext = "super-secret-value"
        token = cipher.encrypt(plaintext)
        assert plaintext not in token

    def test_decrypt_fails_with_wrong_key(self):
        salt = generate_salt()
        key1 = derive_key("correct-password", salt, iterations=1000)
        key2 = derive_key("wrong-password", salt, iterations=1000)

        cipher1 = Cipher(key1)
        cipher2 = Cipher(key2)

        token = cipher1.encrypt("secret")
        with pytest.raises(DecryptionError):
            cipher2.decrypt(token)

    def test_decrypt_fails_on_corrupted_token(self):
        cipher = self._make_cipher()
        token = cipher.encrypt("secret")
        corrupted = token[:-5] + "XXXXX"
        with pytest.raises(DecryptionError):
            cipher.decrypt(corrupted)

    def test_verify_canary_succeeds_with_correct_key(self):
        cipher = self._make_cipher()
        canary = cipher.encrypt("known-value")
        assert cipher.verify_canary(canary, "known-value") is True

    def test_verify_canary_fails_with_wrong_key(self):
        salt = generate_salt()
        key1 = derive_key("pw1", salt, iterations=1000)
        key2 = derive_key("pw2", salt, iterations=1000)
        cipher1, cipher2 = Cipher(key1), Cipher(key2)

        canary = cipher1.encrypt("known-value")
        assert cipher2.verify_canary(canary, "known-value") is False

    def test_encrypt_handles_empty_string(self):
        cipher = self._make_cipher()
        token = cipher.encrypt("")
        assert cipher.decrypt(token) == ""
