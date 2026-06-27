"""
test_password_gen.py

Tests for the secure password generator.
"""

from __future__ import annotations

import string

import pytest

from vaultkeeper.crypto.password_gen import AMBIGUOUS_CHARS, generate_password
from vaultkeeper.utils.exceptions import ValidationError


class TestGeneratePassword:
    def test_default_length_is_16(self):
        pw = generate_password()
        assert len(pw) == 16

    @pytest.mark.parametrize("length", [8, 12, 20, 32, 64, 128])
    def test_respects_requested_length(self, length):
        pw = generate_password(length=length)
        assert len(pw) == length

    def test_rejects_length_below_minimum(self):
        with pytest.raises(ValidationError):
            generate_password(length=4)

    def test_rejects_length_above_maximum(self):
        with pytest.raises(ValidationError):
            generate_password(length=999)

    def test_rejects_all_character_sets_disabled(self):
        with pytest.raises(ValidationError):
            generate_password(
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False,
            )

    def test_only_lowercase_produces_only_lowercase(self):
        pw = generate_password(
            length=50,
            use_uppercase=False,
            use_lowercase=True,
            use_digits=False,
            use_symbols=False,
        )
        assert all(c in string.ascii_lowercase for c in pw)

    def test_only_digits_produces_only_digits(self):
        pw = generate_password(
            length=50,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=True,
            use_symbols=False,
        )
        assert all(c in string.digits for c in pw)

    def test_includes_at_least_one_char_from_each_enabled_pool(self):
        # Run several times since this is probabilistic by nature of shuffling,
        # but generation explicitly guarantees one-per-pool, so it should always pass.
        for _ in range(20):
            pw = generate_password(
                length=10,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True,
                use_symbols=True,
            )
            assert any(c in string.ascii_uppercase for c in pw)
            assert any(c in string.ascii_lowercase for c in pw)
            assert any(c in string.digits for c in pw)

    def test_exclude_ambiguous_removes_confusable_chars(self):
        for _ in range(20):
            pw = generate_password(length=40, exclude_ambiguous=True)
            assert not any(c in AMBIGUOUS_CHARS for c in pw)

    def test_passwords_are_random_across_calls(self):
        passwords = {generate_password(length=20) for _ in range(50)}
        # Astronomically unlikely to collide if randomness is working correctly.
        assert len(passwords) == 50

    def test_no_symbols_excludes_punctuation(self):
        pw = generate_password(length=50, use_symbols=False)
        assert not any(c in "!@#$%^&*()-_=+[]{};:,.<>?/~" for c in pw)
