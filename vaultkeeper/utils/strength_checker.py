"""
strength_checker.py

A lightweight, dependency-free password strength evaluator based on
Shannon entropy plus a handful of common-pattern penalties. This is not as
sophisticated as zxcvbn, but it's transparent, fast, and good enough for a
moderate-level project — and avoids pulling in a heavy dependency.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "letmein", "dragon", "111111", "baseball", "iloveyou", "trustno1",
    "sunshine", "master", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1",
}


class StrengthLevel(str, Enum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class StrengthResult:
    score: int                 # 0-100
    level: StrengthLevel
    entropy_bits: float
    feedback: list[str]


def _character_pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approximate size of common symbol set
    return pool or 1


def _calculate_entropy(password: str) -> float:
    """Approximate Shannon entropy in bits: length * log2(pool size)."""
    pool_size = _character_pool_size(password)
    return len(password) * math.log2(pool_size)


def check_strength(password: str) -> StrengthResult:
    """
    Evaluate password strength using entropy plus pattern-based penalties.

    Returns:
        A StrengthResult with a 0-100 score, a human-readable level, the
        raw entropy estimate, and specific feedback strings.
    """
    feedback: list[str] = []

    if not password:
        return StrengthResult(0, StrengthLevel.VERY_WEAK, 0.0, ["Password is empty."])

    entropy = _calculate_entropy(password)
    score = min(100, int(entropy / 80 * 100))  # 80 bits ~ treated as "max" for scoring

    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 5)
        feedback.append("This is one of the most commonly used passwords — avoid it.")

    if len(password) < 8:
        score = min(score, 20)
        feedback.append("Password is quite short; aim for 12+ characters.")

    if re.fullmatch(r"[a-zA-Z]+", password):
        feedback.append("Add numbers or symbols for a meaningful strength boost.")

    if re.fullmatch(r"[0-9]+", password):
        score = min(score, 15)
        feedback.append("All-digit passwords are weak regardless of length.")

    if re.search(r"(.)\1{2,}", password):
        feedback.append("Avoid repeating the same character multiple times in a row.")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty)", password.lower()):
        score = min(score, 30)
        feedback.append("Avoid sequential or keyboard-pattern substrings.")

    if not feedback:
        feedback.append("No major weaknesses detected.")

    level = _score_to_level(score)
    return StrengthResult(score=score, level=level, entropy_bits=round(entropy, 1), feedback=feedback)


def _score_to_level(score: int) -> StrengthLevel:
    if score < 20:
        return StrengthLevel.VERY_WEAK
    if score < 40:
        return StrengthLevel.WEAK
    if score < 60:
        return StrengthLevel.MODERATE
    if score < 80:
        return StrengthLevel.STRONG
    return StrengthLevel.VERY_STRONG
