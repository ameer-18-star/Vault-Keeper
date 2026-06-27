"""
test_key_derivation.py

Additional edge-case coverage for key derivation, separate from the core
crypto round-trip tests in test_crypto.py — focused specifically on KDF
parameter handling (iteration counts, key format) since this is the
single most security-critical function in the whole project.
"""

from __future__ import annotations

import base64

import pytest

from vaultkeeper.crypto.key_derivation import derive_key, generate_salt


class TestKeyDerivationFormat:
    def test_derived_key_is_valid_base64(self):
        salt = generate_salt()
        key = derive_key("password", salt, iterations=1000)
        # Should not raise — Fernet keys must be valid urlsafe base64.
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32  # Fernet requires a 32-byte key

    def test_derived_key_is_bytes(self):
        salt = generate_salt()
        key = derive_key("password", salt, iterations=1000)
        assert isinstance(key, bytes)

    def test_higher_iterations_still_produce_valid_key(self):
        salt = generate_salt()
        key = derive_key("password", salt, iterations=50_000)
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32

    def test_different_iteration_counts_produce_different_keys(self):
        salt = generate_salt()
        key_a = derive_key("password", salt, iterations=1000)
        key_b = derive_key("password", salt, iterations=2000)
        assert key_a != key_b

    @pytest.mark.parametrize("password", [
        "short",
        "a-much-longer-password-with-many-characters-1234567890",
        "пароль-with-unicode-чарактерс",
        "🔒emoji-password🔑",
        "   leading-and-trailing-spaces   ",
    ])
    def test_derive_key_handles_varied_password_inputs(self, password):
        salt = generate_salt()
        key = derive_key(password, salt, iterations=1000)
        assert len(base64.urlsafe_b64decode(key)) == 32
