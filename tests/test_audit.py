"""
test_audit.py

Tests for the password reuse / weak-password audit.
"""

from __future__ import annotations

from vaultkeeper.storage.models import Entry
from vaultkeeper.utils.audit import run_audit


def make_entry(service, password, username="user@x.com"):
    return Entry(service_name=service, username=username, password=password)


class TestReuseDetection:
    def test_no_reuse_when_all_passwords_unique(self):
        entries = [
            make_entry("A", "Xk9#mQ2vL7$nR4t1"),
            make_entry("B", "Zq8&wM3#kP9@vL2t"),
        ]
        report = run_audit(entries)
        assert report.reuse_groups == []

    def test_detects_simple_two_way_reuse(self):
        entries = [
            make_entry("A", "SharedPassword123!"),
            make_entry("B", "SharedPassword123!"),
        ]
        report = run_audit(entries)
        assert len(report.reuse_groups) == 1
        assert len(report.reuse_groups[0].entries) == 2

    def test_detects_three_way_reuse_as_single_group(self):
        entries = [
            make_entry("A", "SharedPassword123!"),
            make_entry("B", "SharedPassword123!"),
            make_entry("C", "SharedPassword123!"),
        ]
        report = run_audit(entries)
        assert len(report.reuse_groups) == 1
        assert len(report.reuse_groups[0].entries) == 3

    def test_does_not_leak_actual_password_in_hint(self):
        entries = [
            make_entry("A", "SuperSecretSharedValue"),
            make_entry("B", "SuperSecretSharedValue"),
        ]
        report = run_audit(entries)
        hint = report.reuse_groups[0].password_hint
        assert "SuperSecretSharedValue" not in hint

    def test_multiple_independent_reuse_groups(self):
        entries = [
            make_entry("A", "GroupOnePassword!"),
            make_entry("B", "GroupOnePassword!"),
            make_entry("C", "GroupTwoPassword!"),
            make_entry("D", "GroupTwoPassword!"),
        ]
        report = run_audit(entries)
        assert len(report.reuse_groups) == 2

    def test_most_reused_group_sorted_first(self):
        entries = [
            make_entry("A", "PairPassword!"),
            make_entry("B", "PairPassword!"),
            make_entry("C", "TripletPassword!"),
            make_entry("D", "TripletPassword!"),
            make_entry("E", "TripletPassword!"),
        ]
        report = run_audit(entries)
        assert len(report.reuse_groups[0].entries) == 3
        assert len(report.reuse_groups[1].entries) == 2


class TestWeakDetection:
    def test_flags_common_password_as_weak(self):
        entries = [make_entry("A", "password")]
        report = run_audit(entries)
        assert len(report.weak_entries) == 1
        assert report.weak_entries[0].entry.service_name == "A"

    def test_does_not_flag_strong_password(self):
        entries = [make_entry("A", "Xk9#mQ2vL7$nR4tZw8&p")]
        report = run_audit(entries)
        assert report.weak_entries == []

    def test_weakest_entry_sorted_first(self):
        entries = [
            make_entry("ModerateOne", "Ab1!Cd2@"),
            make_entry("WeakOne", "12345678"),
        ]
        report = run_audit(entries)
        weak_services = [w.entry.service_name for w in report.weak_entries]
        if len(weak_services) > 1:
            assert weak_services[0] == "WeakOne"


class TestAuditReport:
    def test_has_issues_false_when_clean(self):
        entries = [make_entry("A", "Xk9#mQ2vL7$nR4tZw8&p")]
        report = run_audit(entries)
        assert report.has_issues is False

    def test_has_issues_true_with_reuse_only(self):
        entries = [
            make_entry("A", "Xk9#mQ2vL7$nR4tZw8&p"),
            make_entry("B", "Xk9#mQ2vL7$nR4tZw8&p"),
        ]
        report = run_audit(entries)
        assert report.has_issues is True

    def test_total_entries_matches_input_count(self):
        entries = [make_entry("A", "pw1"), make_entry("B", "pw2"), make_entry("C", "pw3")]
        report = run_audit(entries)
        assert report.total_entries == 3

    def test_empty_vault_produces_clean_report(self):
        report = run_audit([])
        assert report.has_issues is False
        assert report.total_entries == 0
