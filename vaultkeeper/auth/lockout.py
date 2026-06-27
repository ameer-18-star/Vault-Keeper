"""
lockout.py

Simple brute-force throttling for master password attempts. State is
persisted to a small JSON file so lockouts survive process restarts
(otherwise an attacker could just restart the CLI to reset their attempt count).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from vaultkeeper import config
from vaultkeeper.utils.exceptions import VaultLockedOutError

LOCKOUT_STATE_FILENAME = "lockout_state.json"


def _state_path() -> Path:
    return config.DATA_DIR / LOCKOUT_STATE_FILENAME


def _load_state() -> dict:
    path = _state_path()
    if not path.exists():
        return {"failed_attempts": 0, "locked_until": 0, "lockout_count": 0}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"failed_attempts": 0, "locked_until": 0, "lockout_count": 0}


def _save_state(state: dict) -> None:
    config.ensure_data_dir()
    with open(_state_path(), "w", encoding="utf-8") as f:
        json.dump(state, f)


def check_lockout() -> None:
    """
    Raise VaultLockedOutError if currently within a lockout window.
    Call this BEFORE prompting for a master password attempt.
    """
    state = _load_state()
    now = time.time()
    locked_until = state.get("locked_until", 0)
    if now < locked_until:
        raise VaultLockedOutError(retry_after_seconds=int(locked_until - now))


def record_failed_attempt() -> Optional[int]:
    """
    Record a failed master password attempt. If MAX_FAILED_ATTEMPTS is
    reached, trigger a lockout (with exponential backoff on repeated lockouts)
    and return the lockout duration in seconds. Otherwise return None.
    """
    state = _load_state()
    state["failed_attempts"] = state.get("failed_attempts", 0) + 1

    if state["failed_attempts"] >= config.MAX_FAILED_ATTEMPTS:
        lockout_count = state.get("lockout_count", 0) + 1
        duration = int(
            config.LOCKOUT_SECONDS * (config.LOCKOUT_BACKOFF_MULTIPLIER ** (lockout_count - 1))
        )
        state["locked_until"] = time.time() + duration
        state["lockout_count"] = lockout_count
        state["failed_attempts"] = 0
        _save_state(state)
        return duration

    _save_state(state)
    return None


def record_successful_attempt() -> None:
    """Reset failed-attempt tracking after a successful login."""
    _save_state({"failed_attempts": 0, "locked_until": 0, "lockout_count": 0})
