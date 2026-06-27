"""
password_gen.py

Cryptographically secure password generation using the `secrets` module
(never `random`, which is not safe for security purposes).
"""

from __future__ import annotations

import secrets
import string

from vaultkeeper.config import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from vaultkeeper.utils.exceptions import ValidationError

AMBIGUOUS_CHARS = "il1Lo0O|"


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Desired password length.
        use_uppercase: Include A-Z.
        use_lowercase: Include a-z.
        use_digits: Include 0-9.
        use_symbols: Include punctuation symbols.
        exclude_ambiguous: Strip visually-confusable characters (l, 1, I, O, 0, etc).

    Returns:
        A randomly generated password string.

    Raises:
        ValidationError: If length is out of bounds or no character sets are selected.
    """
    if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
        raise ValidationError(
            f"Password length must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters."
        )

    pools = []
    if use_uppercase:
        pools.append(string.ascii_uppercase)
    if use_lowercase:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/~")

    if not pools:
        raise ValidationError("At least one character set must be enabled.")

    if exclude_ambiguous:
        pools = [
            "".join(ch for ch in pool if ch not in AMBIGUOUS_CHARS)
            for pool in pools
        ]
        pools = [pool for pool in pools if pool]  # drop now-empty pools

    full_alphabet = "".join(pools)

    # Guarantee at least one character from each selected pool, for password
    # policies that require a mix of character classes.
    password_chars = [secrets.choice(pool) for pool in pools]

    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(full_alphabet) for _ in range(remaining))

    # Shuffle so the guaranteed characters aren't predictably at the front.
    secure_random = secrets.SystemRandom()
    secure_random.shuffle(password_chars)

    return "".join(password_chars)
