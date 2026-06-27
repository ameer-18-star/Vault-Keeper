"""
test_totp.py

Tests for TOTP secret validation and live code generation.
"""

from __future__ import annotations

import re

import pytest

from vaultkeeper.utils.exceptions import ValidationError
from vaultkeeper.utils.totp import generate_code, validate_totp_secret

# A well-known example secret used in RFC 6238 / pyotp's own documentation —
# not a real account, safe to use as a test fixture.
VALID_SECRET = "JBSWY3DPEHPK3PXP"


class TestValidateTotpSecret:
    def test_accepts_valid_base32_secret(self):
        assert validate_totp_secret(VALID_SECRET) == VALID_SECRET

    def test_normalizes_lowercase_to_uppercase(self):
        assert validate_totp_secret(VALID_SECRET.lower()) == VALID_SECRET

    def test_strips_whitespace(self):
        assert validate_totp_secret(f"  {VALID_SECRET}  ") == VALID_SECRET

    def test_strips_internal_spaces(self):
        # Some authenticator apps display secrets in space-separated groups.
        spaced = "JBSW Y3DP EHPK 3PXP"
        assert validate_totp_secret(spaced) == VALID_SECRET

    def test_rejects_empty_string(self):
        with pytest.raises(ValidationError):
            validate_totp_secret("")

    def test_rejects_invalid_base32(self):
        with pytest.raises(ValidationError):
            validate_totp_secret("not-valid-base32-!!!")


class TestGenerateCode:
    def test_returns_six_digit_code(self):
        result = generate_code(VALID_SECRET)
        assert re.fullmatch(r"\d{6}", result.code)

    def test_seconds_remaining_is_within_valid_window(self):
        result = generate_code(VALID_SECRET)
        assert 0 < result.seconds_remaining <= 30

    def test_same_secret_produces_same_code_within_window(self):
        # Two calls in immediate succession should land in the same 30s window.
        result1 = generate_code(VALID_SECRET)
        result2 = generate_code(VALID_SECRET)
        assert result1.code == result2.code

    def test_different_secrets_produce_different_codes(self):
        other_secret = "KRSXG5CTMVRXEZLU"
        result1 = generate_code(VALID_SECRET)
        result2 = generate_code(other_secret)
        # Astronomically unlikely to collide for two different secrets at the same instant.
        assert result1.code != result2.code
