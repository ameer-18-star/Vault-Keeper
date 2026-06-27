"""
test_csv_io.py

Tests for bulk CSV import/export.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vaultkeeper.storage.csv_io import export_to_csv, import_from_csv
from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.exceptions import BackupError


@pytest.fixture()
def tmp_csv_dir(tmp_path) -> Path:
    return tmp_path


class TestImportFromCsv:
    def test_imports_valid_rows(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_text(
            "service_name,username,password\n"
            "GitHub,a@x.com,pw123\n"
            "Gmail,b@x.com,pw456\n",
            encoding="utf-8",
        )
        result = import_from_csv(csv_path)
        assert len(result.entries) == 2
        assert result.entries[0].service_name == "GitHub"
        assert result.entries[0].password == "pw123"

    def test_imports_optional_columns_when_present(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_text(
            "service_name,username,password,url,notes,tag\n"
            "GitHub,a@x.com,pw123,https://github.com,my notes,work\n",
            encoding="utf-8",
        )
        result = import_from_csv(csv_path)
        entry = result.entries[0]
        assert entry.url == "https://github.com"
        assert entry.notes == "my notes"
        assert entry.tag == "work"

    def test_missing_optional_columns_default_to_empty(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_text(
            "service_name,username,password\nGitHub,a@x.com,pw123\n", encoding="utf-8"
        )
        result = import_from_csv(csv_path)
        entry = result.entries[0]
        assert entry.url == ""
        assert entry.notes == ""
        assert entry.tag == ""

    def test_skips_rows_missing_required_fields(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_text(
            "service_name,username,password\n"
            "GitHub,a@x.com,pw123\n"
            ",missing@x.com,pw456\n"  # missing service_name
            "Gmail,,pw789\n"  # missing username
            "Slack,c@x.com,\n",  # missing password
            encoding="utf-8",
        )
        result = import_from_csv(csv_path)
        assert len(result.entries) == 1
        assert len(result.skipped_rows) == 3

    def test_raises_on_missing_required_column(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_text("service_name,username\nGitHub,a@x.com\n", encoding="utf-8")
        with pytest.raises(BackupError):
            import_from_csv(csv_path)

    def test_raises_on_missing_file(self, tmp_csv_dir):
        with pytest.raises(BackupError):
            import_from_csv(tmp_csv_dir / "does_not_exist.csv")

    def test_handles_utf8_bom(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_bytes(
            b"\xef\xbb\xbfservice_name,username,password\nGitHub,a@x.com,pw123\n"
        )
        result = import_from_csv(csv_path)
        assert len(result.entries) == 1
        assert result.entries[0].service_name == "GitHub"

    def test_column_names_are_case_insensitive(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "passwords.csv"
        csv_path.write_text(
            "Service_Name,USERNAME,Password\nGitHub,a@x.com,pw123\n", encoding="utf-8"
        )
        result = import_from_csv(csv_path)
        assert len(result.entries) == 1

    def test_empty_csv_raises(self, tmp_csv_dir):
        csv_path = tmp_csv_dir / "empty.csv"
        csv_path.write_text("", encoding="utf-8")
        with pytest.raises(BackupError):
            import_from_csv(csv_path)


class TestExportToCsv:
    def test_export_creates_file_with_header(self, tmp_csv_dir):
        entries = [Entry(service_name="GitHub", username="a@x.com", password="pw123")]
        output_path = tmp_csv_dir / "export.csv"
        export_to_csv(entries, output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "service_name" in content
        assert "GitHub" in content
        assert "pw123" in content

    def test_export_import_round_trip_preserves_data(self, tmp_csv_dir):
        original = [
            Entry(
                service_name="GitHub",
                username="a@x.com",
                password="pw123!",
                url="https://github.com",
                notes="test notes",
                tag="work",
            )
        ]
        output_path = tmp_csv_dir / "export.csv"
        export_to_csv(original, output_path)

        result = import_from_csv(output_path)
        assert len(result.entries) == 1
        restored = result.entries[0]
        assert restored.service_name == "GitHub"
        assert restored.username == "a@x.com"
        assert restored.password == "pw123!"
        assert restored.url == "https://github.com"
        assert restored.notes == "test notes"
        assert restored.tag == "work"

    def test_export_empty_list_creates_header_only_file(self, tmp_csv_dir):
        output_path = tmp_csv_dir / "export.csv"
        export_to_csv([], output_path)
        content = output_path.read_text(encoding="utf-8")
        assert "service_name" in content
        lines = [line for line in content.splitlines() if line.strip()]
        assert len(lines) == 1  # header only
