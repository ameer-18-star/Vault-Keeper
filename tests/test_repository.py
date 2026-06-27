"""
test_repository.py

Tests for EntryRepository CRUD operations, using the isolated `repo` fixture
from conftest.py so each test gets a fresh, throwaway SQLite database.
"""

from __future__ import annotations

import pytest

from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.exceptions import DuplicateEntryError, EntryNotFoundError


def make_entry(service="GitHub", username="ali@example.com", password="hunter2!", **kwargs):
    return Entry(service_name=service, username=username, password=password, **kwargs)


class TestAdd:
    def test_add_returns_entry_with_id(self, repo):
        saved = repo.add(make_entry())
        assert saved.id is not None
        assert saved.id > 0

    def test_add_sets_timestamps(self, repo):
        saved = repo.add(make_entry())
        assert saved.created_at is not None
        assert saved.updated_at is not None
        assert saved.created_at == saved.updated_at

    def test_add_persists_encrypted_password_correctly(self, repo):
        saved = repo.add(make_entry(password="correct-horse-battery-staple"))
        fetched = repo.get_by_id(saved.id)
        assert fetched.password == "correct-horse-battery-staple"

    def test_add_duplicate_service_and_username_raises(self, repo):
        repo.add(make_entry(service="GitHub", username="ali@example.com"))
        with pytest.raises(DuplicateEntryError):
            repo.add(make_entry(service="GitHub", username="ali@example.com"))

    def test_add_same_service_different_username_succeeds(self, repo):
        repo.add(make_entry(service="GitHub", username="personal@example.com"))
        saved2 = repo.add(make_entry(service="GitHub", username="work@example.com"))
        assert saved2.id is not None


class TestRead:
    def test_get_by_id_not_found_raises(self, repo):
        with pytest.raises(EntryNotFoundError):
            repo.get_by_id(99999)

    def test_get_by_service_not_found_raises(self, repo):
        with pytest.raises(EntryNotFoundError):
            repo.get_by_service("NonexistentService")

    def test_get_by_service_is_case_insensitive(self, repo):
        repo.add(make_entry(service="GitHub"))
        results = repo.get_by_service("github")
        assert len(results) == 1
        assert results[0].service_name == "GitHub"

    def test_search_finds_partial_matches(self, repo):
        repo.add(make_entry(service="GitHub", username="a@example.com"))
        repo.add(make_entry(service="GitLab", username="b@example.com"))
        repo.add(make_entry(service="Twitter", username="c@example.com"))

        results = repo.search("Git")
        names = {e.service_name for e in results}
        assert names == {"GitHub", "GitLab"}

    def test_search_returns_empty_list_for_no_matches(self, repo):
        repo.add(make_entry(service="GitHub"))
        results = repo.search("NoSuchThing")
        assert results == []

    def test_list_all_returns_alphabetical_order(self, repo):
        repo.add(make_entry(service="Zoom", username="a@x.com"))
        repo.add(make_entry(service="Apple", username="b@x.com"))
        repo.add(make_entry(service="Microsoft", username="c@x.com"))

        results = repo.list_all()
        names = [e.service_name for e in results]
        assert names == ["Apple", "Microsoft", "Zoom"]

    def test_list_all_empty_vault_returns_empty_list(self, repo):
        assert repo.list_all() == []


class TestUpdate:
    def test_update_changes_password(self, repo):
        saved = repo.add(make_entry(password="old-password"))
        saved.password = "new-password"
        repo.update(saved)

        fetched = repo.get_by_id(saved.id)
        assert fetched.password == "new-password"

    def test_update_bumps_updated_at_but_not_created_at(self, repo):
        saved = repo.add(make_entry())
        original_created = saved.created_at

        saved.notes = "updated notes"
        updated = repo.update(saved)

        fetched = repo.get_by_id(saved.id)
        assert fetched.notes == "updated notes"
        assert updated.updated_at is not None

    def test_update_nonexistent_entry_raises(self, repo):
        ghost = make_entry()
        ghost.id = 99999
        with pytest.raises(EntryNotFoundError):
            repo.update(ghost)

    def test_update_without_id_raises_value_error(self, repo):
        entry = make_entry()
        entry.id = None
        with pytest.raises(ValueError):
            repo.update(entry)


class TestDelete:
    def test_delete_removes_entry(self, repo):
        saved = repo.add(make_entry())
        repo.delete(saved.id)
        with pytest.raises(EntryNotFoundError):
            repo.get_by_id(saved.id)

    def test_delete_nonexistent_entry_raises(self, repo):
        with pytest.raises(EntryNotFoundError):
            repo.delete(99999)

    def test_delete_one_entry_does_not_affect_others(self, repo):
        e1 = repo.add(make_entry(service="GitHub", username="a@x.com"))
        e2 = repo.add(make_entry(service="GitLab", username="b@x.com"))

        repo.delete(e1.id)

        with pytest.raises(EntryNotFoundError):
            repo.get_by_id(e1.id)
        assert repo.get_by_id(e2.id) is not None


class TestEncryptionAtRest:
    def test_password_is_actually_encrypted_in_database(self, repo, isolated_data_dir):
        """Verify the raw DB column never contains the plaintext password."""
        import sqlite3

        saved = repo.add(make_entry(password="totally-secret-value"))

        conn = sqlite3.connect(isolated_data_dir / "vault.db")
        row = conn.execute(
            "SELECT encrypted_password FROM entries WHERE id = ?", (saved.id,)
        ).fetchone()
        conn.close()

        raw_value = row[0]
        assert "totally-secret-value" not in raw_value

    def test_totp_secret_is_actually_encrypted_in_database(self, repo, isolated_data_dir):
        """Verify the raw DB column never contains the plaintext TOTP secret."""
        import sqlite3

        saved = repo.add(make_entry(totp_secret="JBSWY3DPEHPK3PXP"))

        conn = sqlite3.connect(isolated_data_dir / "vault.db")
        row = conn.execute(
            "SELECT encrypted_totp_secret FROM entries WHERE id = ?", (saved.id,)
        ).fetchone()
        conn.close()

        raw_value = row[0]
        assert "JBSWY3DPEHPK3PXP" not in raw_value


class TestTags:
    def test_entry_without_tag_defaults_to_empty_string(self, repo):
        saved = repo.add(make_entry())
        assert saved.tag == ""

    def test_add_and_fetch_preserves_tag(self, repo):
        saved = repo.add(make_entry(tag="work"))
        fetched = repo.get_by_id(saved.id)
        assert fetched.tag == "work"

    def test_list_by_tag_returns_only_matching_entries(self, repo):
        repo.add(make_entry(service="GitHub", username="a@x.com", tag="work"))
        repo.add(make_entry(service="GitLab", username="b@x.com", tag="work"))
        repo.add(make_entry(service="Netflix", username="c@x.com", tag="personal"))

        work_entries = repo.list_by_tag("work")
        assert {e.service_name for e in work_entries} == {"GitHub", "GitLab"}

    def test_list_by_tag_is_case_insensitive(self, repo):
        repo.add(make_entry(tag="Work"))
        assert len(repo.list_by_tag("work")) == 1
        assert len(repo.list_by_tag("WORK")) == 1

    def test_list_by_tag_no_matches_returns_empty_list(self, repo):
        repo.add(make_entry(tag="work"))
        assert repo.list_by_tag("nonexistent") == []

    def test_list_tags_returns_distinct_sorted_tags(self, repo):
        repo.add(make_entry(service="A", username="a@x.com", tag="work"))
        repo.add(make_entry(service="B", username="b@x.com", tag="personal"))
        repo.add(make_entry(service="C", username="c@x.com", tag="work"))

        assert repo.list_tags() == ["personal", "work"]

    def test_list_tags_excludes_empty_tags(self, repo):
        repo.add(make_entry(service="A", username="a@x.com", tag=""))
        repo.add(make_entry(service="B", username="b@x.com", tag="work"))

        assert repo.list_tags() == ["work"]

    def test_update_can_change_tag(self, repo):
        saved = repo.add(make_entry(tag="personal"))
        saved.tag = "work"
        repo.update(saved)

        fetched = repo.get_by_id(saved.id)
        assert fetched.tag == "work"


class TestTotpSecret:
    def test_entry_without_totp_has_no_totp(self, repo):
        saved = repo.add(make_entry())
        fetched = repo.get_by_id(saved.id)
        assert fetched.has_totp() is False
        assert fetched.totp_secret == ""

    def test_add_and_fetch_preserves_totp_secret(self, repo):
        saved = repo.add(make_entry(totp_secret="JBSWY3DPEHPK3PXP"))
        fetched = repo.get_by_id(saved.id)
        assert fetched.totp_secret == "JBSWY3DPEHPK3PXP"
        assert fetched.has_totp() is True

    def test_update_can_add_totp_secret_to_existing_entry(self, repo):
        saved = repo.add(make_entry())
        assert saved.totp_secret == ""

        saved.totp_secret = "JBSWY3DPEHPK3PXP"
        repo.update(saved)

        fetched = repo.get_by_id(saved.id)
        assert fetched.has_totp() is True

    def test_update_can_remove_totp_secret(self, repo):
        saved = repo.add(make_entry(totp_secret="JBSWY3DPEHPK3PXP"))
        saved.totp_secret = ""
        repo.update(saved)

        fetched = repo.get_by_id(saved.id)
        assert fetched.has_totp() is False


class TestStaleDetection:
    def test_find_stale_excludes_fresh_entries(self, repo):
        repo.add(make_entry())
        assert repo.find_stale(180) == []

    def test_find_stale_includes_backdated_entries(self, repo, isolated_data_dir):
        import sqlite3
        from datetime import datetime, timedelta

        saved = repo.add(make_entry())
        old_date = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(isolated_data_dir / "vault.db")
        conn.execute("UPDATE entries SET updated_at = ? WHERE id = ?", (old_date, saved.id))
        conn.commit()
        conn.close()

        stale = repo.find_stale(180)
        assert len(stale) == 1
        assert stale[0].id == saved.id

    def test_find_stale_respects_threshold_boundary(self, repo, isolated_data_dir):
        import sqlite3
        from datetime import datetime, timedelta

        saved = repo.add(make_entry())
        # Exactly 100 days old — should be included when threshold is 100.
        boundary_date = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(isolated_data_dir / "vault.db")
        conn.execute("UPDATE entries SET updated_at = ? WHERE id = ?", (boundary_date, saved.id))
        conn.commit()
        conn.close()

        assert len(repo.find_stale(100)) == 1
        assert len(repo.find_stale(101)) == 0
