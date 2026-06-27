"""
clipboard.py

Copies a value to the system clipboard and automatically clears it after a
timeout, so a retrieved password doesn't linger on the clipboard indefinitely.
Uses a background thread so the CLI remains responsive while waiting to clear.
"""

from __future__ import annotations

import threading
from typing import Optional

try:
    import pyperclip
    _PYPERCLIP_AVAILABLE = True
except ImportError:
    _PYPERCLIP_AVAILABLE = False

from vaultkeeper.config import CLIPBOARD_CLEAR_SECONDS


def copy_with_autoclear(value: str, clear_after_seconds: int = CLIPBOARD_CLEAR_SECONDS) -> bool:
    """
    Copy `value` to the clipboard and schedule it to be cleared after
    `clear_after_seconds`, but ONLY if the clipboard still contains the
    same value at that time (so we don't clobber something the user copied
    in the meantime).

    Returns:
        True if the value was copied successfully, False if no clipboard
        backend is available (e.g. headless environment with no copy tool).
    """
    if not _PYPERCLIP_AVAILABLE:
        return False

    try:
        pyperclip.copy(value)
    except Exception:
        # pyperclip can raise if no backend (xclip/xsel/pbcopy/etc) is installed.
        return False

    def _clear_later() -> None:
        try:
            current = pyperclip.paste()
            if current == value:
                pyperclip.copy("")
        except Exception:
            pass

    timer = threading.Timer(clear_after_seconds, _clear_later)
    timer.daemon = True
    timer.start()
    return True


def is_clipboard_available() -> bool:
    """Check whether a clipboard backend is usable in this environment."""
    if not _PYPERCLIP_AVAILABLE:
        return False
    try:
        pyperclip.paste()
        return True
    except Exception:
        return False
