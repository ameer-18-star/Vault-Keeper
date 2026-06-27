"""
config.py

Central configuration: file paths, KDF parameters, and tunable constants.
Nothing secret lives here — only parameters and locations.
"""

from pathlib import Path

# --- Directory / file locations -------------------------------------------------

BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"

DB_PATH: Path = DATA_DIR / "vault.db"
VAULT_CONFIG_PATH: Path = DATA_DIR / "vault_config.json"
LOG_PATH: Path = DATA_DIR / "vaultkeeper.log"

# --- Key derivation parameters ---------------------------------------------------
# These are NOT secret. They are stored alongside the salt in vault_config.json
# and are required to re-derive the same key from the master password.

KDF_ALGORITHM: str = "PBKDF2HMAC-SHA256"
KDF_ITERATIONS: int = 260_000
KDF_SALT_BYTES: int = 16

# --- Lockout / brute-force throttling --------------------------------------------

MAX_FAILED_ATTEMPTS: int = 5
LOCKOUT_SECONDS: int = 30          # base lockout duration
LOCKOUT_BACKOFF_MULTIPLIER: float = 2.0  # doubles each repeated lockout

# --- Clipboard ---------------------------------------------------------------------

CLIPBOARD_CLEAR_SECONDS: int = 15

# --- Password generator defaults --------------------------------------------------

DEFAULT_PASSWORD_LENGTH: int = 16
MIN_PASSWORD_LENGTH: int = 8
MAX_PASSWORD_LENGTH: int = 128

# --- Misc --------------------------------------------------------------------------

DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"


def ensure_data_dir() -> None:
    """Create the data directory if it does not already exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
