"""
audit.py

Vault-wide security audit: detects reused passwords across entries and
flags weak ones using the existing entropy-based strength checker. This
intentionally reuses utils.strength_checker rather than duplicating logic.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.strength_checker import StrengthResult, check_strength

# Entries scoring below this are flagged as "weak" in the audit (Weak or Very Weak).
WEAK_SCORE_THRESHOLD = 40


@dataclass
class ReuseGroup:
    password_hint: str  # never the real password — see _hint()
    entries: List[Entry]


@dataclass
class WeakEntry:
    entry: Entry
    strength: StrengthResult


@dataclass
class AuditReport:
    reuse_groups: List[ReuseGroup]
    weak_entries: List[WeakEntry]
    total_entries: int

    @property
    def has_issues(self) -> bool:
        return bool(self.reuse_groups or self.weak_entries)


def _hint(password: str) -> str:
    """
    A non-reversible, non-identifying display hint for a reused password
    group (we never want to print the actual shared password). Shows length
    only, e.g. '12 characters' — enough to distinguish groups without
    leaking the secret itself.
    """
    return f"{len(password)} characters"


def run_audit(entries: List[Entry]) -> AuditReport:
    """
    Scan all entries for:
      1. Password reuse — the same password used across 2+ different entries.
      2. Weak passwords — entries scoring below WEAK_SCORE_THRESHOLD.
    """
    by_password: Dict[str, List[Entry]] = defaultdict(list)
    for entry in entries:
        by_password[entry.password].append(entry)

    reuse_groups = [
        ReuseGroup(password_hint=_hint(pw), entries=group)
        for pw, group in by_password.items()
        if len(group) > 1
    ]
    # Most-reused first, since that's the most urgent to fix.
    reuse_groups.sort(key=lambda g: len(g.entries), reverse=True)

    weak_entries = []
    for entry in entries:
        result = check_strength(entry.password)
        if result.score < WEAK_SCORE_THRESHOLD:
            weak_entries.append(WeakEntry(entry=entry, strength=result))
    weak_entries.sort(key=lambda w: w.strength.score)

    return AuditReport(
        reuse_groups=reuse_groups,
        weak_entries=weak_entries,
        total_entries=len(entries),
    )
