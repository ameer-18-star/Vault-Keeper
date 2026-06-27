"""
test_strength_checker.py

Tests for the entropy-based password strength evaluator.
"""

from __future__ import annotations

import pytest

from vaultkeeper.utils.strength_checker import StrengthLevel, check_strength


class TestStrengthChecker:
    def test_empty_password_is_very_weak(self):
        result = check_strength("")
        assert result.level == StrengthLevel.VERY_WEAK
        assert result.score == 0

    def test_common_password_scores_very_low(self):
        result = check_strength("password")
        assert result.score <= 5
        assert any("commonly used" in fb for fb in result.feedback)

    def test_all_digits_scores_low(self):
        result = check_strength("12345678")
        assert result.level in (StrengthLevel.VERY_WEAK, StrengthLevel.WEAK)

    def test_long_random_mixed_password_scores_high(self):
        result = check_strength("Xk9#mQ2vL7$nR4tZw8&p")
        assert result.level in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG)

    def test_short_password_flagged_regardless_of_complexity(self):
        result = check_strength("X9$a")
        assert any("short" in fb.lower() for fb in result.feedback)

    def test_repeated_characters_flagged(self):
        result = check_strength("aaaaaaaaA1!")
        assert any("repeating" in fb.lower() for fb in result.feedback)

    def test_sequential_pattern_flagged(self):
        result = check_strength("abcd1234XY")
        assert any("sequential" in fb.lower() or "pattern" in fb.lower() for fb in result.feedback)

    def test_letters_only_suggests_adding_numbers_or_symbols(self):
        result = check_strength("OnlyLettersHereABC")
        assert any("numbers or symbols" in fb.lower() for fb in result.feedback)

    def test_score_is_within_valid_range(self):
        passwords = ["", "a", "password", "Xk9#mQ2vL7$nR4tZw8&p", "1234567890" * 5]
        for pw in passwords:
            result = check_strength(pw)
            assert 0 <= result.score <= 100

    def test_entropy_increases_with_length_for_same_character_set(self):
        short_result = check_strength("Ab1!")
        long_result = check_strength("Ab1!Ab1!Ab1!Ab1!")
        assert long_result.entropy_bits > short_result.entropy_bits

    def test_no_feedback_message_when_password_is_clean(self):
        # A long, random, non-patterned password should get the "no weaknesses" message.
        result = check_strength("Zq8$wM3#kP9@vL2&nR7!")
        assert "No major weaknesses detected." in result.feedback
