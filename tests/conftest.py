"""
conftest.py

Shared pytest fixtures. The key trick here: every test that touches storage
or auth gets a fresh, isolated temp directory injected as config.DATA_DIR,
config.DB_PATH, and config.VAULT_CONFIG_PATH — so tests never read/write the
real data/ directory and never interfere with each other.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from vaultkeeper import config
from vaultkeeper.crypto.cipher import Cipher
from vaultkeeper.crypto.key_derivation import derive_key, generate_salt
from vaultkeeper.storage.database import initialize_database
from vaultkeeper.storage.repository import EntryRepository


@pytest.fixture()
def isolated_data_dir(monkeypatch):
    """Point config paths at a fresh temp directory for the duration of a test."""
    tmpdir = tempfile.mkdtemp(prefix="vaultkeeper_test_")
    tmp_path = Path(tmpdir)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "vault.db")
    monkeypatch.setattr(config, "VAULT_CONFIG_PATH", tmp_path / "vault_config.json")

    yield tmp_path

    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture()
def test_cipher() -> Cipher:
    """A Cipher built from a fixed test master password/salt (fast: low iterations)."""
    salt = generate_salt()
    key = derive_key("test-master-password-123", salt, iterations=1000)
    return Cipher(key)


@pytest.fixture()
def repo(isolated_data_dir, test_cipher) -> EntryRepository:
    """A repository backed by an isolated, initialized test database."""
    initialize_database(isolated_data_dir / "vault.db")
    return EntryRepository(test_cipher)
