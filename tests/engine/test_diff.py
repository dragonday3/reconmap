"""Tests for DiffEngine."""
from datetime import datetime, timezone

import pytest

from reconmap.engine.diff import DiffEngine
from reconmap.models.asset import AssetSnapshot, Subdomain, Port, SecretLeak


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_snapshot(
    domain: str = "example.com",
    subdomains: list[Subdomain] | None = None,
    ports: list[Port] | None = None,
    leaks: list[SecretLeak] | None = None,
) -> AssetSnapshot:
    return AssetSnapshot(
        target_domain=domain,
        subdomains=subdomains or [],
        ports=ports or [],
        leaks=leaks or [],
    )


def make_subdomain(name: str, domain: str = "example.com") -> Subdomain:
    now = datetime.now(timezone.utc)
    return Subdomain(
        target_domain=domain,
        subdomain=name,
        source="test",
        first_seen=now,
        last_seen=now,
    )


def make_port(ip: str = "1.2.3.4", port: int = 80) -> Port:
    return Port(ip=ip, port=port, source="test")


def make_leak(
    repo: str = "user/repo",
    file_path: str = "config.py",
    line_number: int = 1,
    secret_type: str = "api_key",
) -> SecretLeak:
    return SecretLeak(
        target_domain="example.com",
        repo=repo,
        file_path=file_path,
        line_number=line_number,
        secret_type=secret_type,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSubdomainDiffs:
    """Tests for subdomain change detection."""

    def test_new_subdomain_produces_new_subdomain_change(self):
        """Test 1: New subdomain in after → Change(change_type='new_subdomain', severity='medium')."""
        before = make_snapshot()
        after = make_snapshot(subdomains=[make_subdomain("api.example.com")])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        c = changes[0]
        assert c.change_type == "new_subdomain"
        assert c.severity == "medium"

    def test_removed_subdomain_produces_subdomain_removed_change(self):
        """Test 2: Removed subdomain from before → Change(change_type='subdomain_removed', severity='low')."""
        before = make_snapshot(subdomains=[make_subdomain("old.example.com")])
        after = make_snapshot()
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        c = changes[0]
        assert c.change_type == "subdomain_removed"
        assert c.severity == "low"

    def test_no_subdomain_change_when_same(self):
        """Identical subdomains produce no changes."""
        sub = make_subdomain("api.example.com")
        before = make_snapshot(subdomains=[sub])
        after = make_snapshot(subdomains=[make_subdomain("api.example.com")])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert not any(c.asset_type == "subdomain" for c in changes)

    def test_asset_key_for_subdomain_is_subdomain_name(self):
        """Test 11: asset_key for subdomain = subdomain name."""
        before = make_snapshot()
        after = make_snapshot(subdomains=[make_subdomain("api.example.com")])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        assert changes[0].asset_key == "api.example.com"


class TestPortDiffs:
    """Tests for port change detection."""

    def test_new_port_produces_new_port_change(self):
        """Test 3: New port in after → Change(change_type='new_port', severity='high')."""
        before = make_snapshot()
        after = make_snapshot(ports=[make_port("1.2.3.4", 443)])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        c = changes[0]
        assert c.change_type == "new_port"
        assert c.severity == "high"

    def test_closed_port_produces_port_closed_change(self):
        """Test 4: Closed port → Change(change_type='port_closed', severity='info')."""
        before = make_snapshot(ports=[make_port("1.2.3.4", 22)])
        after = make_snapshot()
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        c = changes[0]
        assert c.change_type == "port_closed"
        assert c.severity == "info"

    def test_asset_key_for_port_is_ip_colon_port(self):
        """Test 12: asset_key for port = 'ip:port' format."""
        before = make_snapshot()
        after = make_snapshot(ports=[make_port("10.0.0.1", 8080)])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        assert changes[0].asset_key == "10.0.0.1:8080"

    def test_no_port_change_when_same(self):
        """Identical ports produce no changes."""
        before = make_snapshot(ports=[make_port("1.2.3.4", 80)])
        after = make_snapshot(ports=[make_port("1.2.3.4", 80)])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert not any(c.asset_type == "port" for c in changes)


class TestLeakDiffs:
    """Tests for secret leak change detection."""

    def test_new_leak_produces_new_leak_change(self):
        """Test 5: New leak in after → Change(change_type='new_leak', severity='critical')."""
        before = make_snapshot()
        after = make_snapshot(leaks=[make_leak()])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        c = changes[0]
        assert c.change_type == "new_leak"
        assert c.severity == "critical"

    def test_no_leak_removed_change_type(self):
        """Test 10: No 'leak removed' change type (leaks only flow new→not old)."""
        before = make_snapshot(leaks=[make_leak("user/repo", "old.py", 1)])
        after = make_snapshot()
        engine = DiffEngine()
        changes = engine.diff(before, after)
        change_types = [c.change_type for c in changes]
        assert "leak_removed" not in change_types
        # no leak changes at all — leaks in before but not after produce nothing
        assert not any(c.asset_type == "leak" for c in changes)

    def test_existing_leak_not_in_before_appears_as_new(self):
        """Leak present in after but not before → new_leak."""
        existing = make_leak("user/repo", "file.py", 5)
        new_leak = make_leak("user/repo", "file.py", 99)
        before = make_snapshot(leaks=[existing])
        after = make_snapshot(leaks=[existing, new_leak])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        leak_changes = [c for c in changes if c.asset_type == "leak"]
        assert len(leak_changes) == 1
        assert leak_changes[0].change_type == "new_leak"

    def test_details_dict_for_new_leak_contains_expected_keys(self):
        """Test 13: details dict for new_leak contains repo, file_path, secret_type."""
        before = make_snapshot()
        after = make_snapshot(leaks=[make_leak("org/repo", "secrets.py", 42, "aws_key")])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) == 1
        details = changes[0].details
        assert "repo" in details
        assert "file_path" in details
        assert "secret_type" in details
        assert details["repo"] == "org/repo"
        assert details["file_path"] == "secrets.py"
        assert details["secret_type"] == "aws_key"


class TestIdenticalSnapshots:
    """Test 6: Identical before == after → empty changes list."""

    def test_identical_snapshots_produce_no_changes(self):
        sub = make_subdomain("api.example.com")
        port = make_port("1.2.3.4", 443)
        leak = make_leak()

        before = make_snapshot(subdomains=[sub], ports=[port], leaks=[leak])
        # after has same content (different objects but same data)
        after = make_snapshot(
            subdomains=[make_subdomain("api.example.com")],
            ports=[make_port("1.2.3.4", 443)],
            leaks=[make_leak()],
        )
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert changes == []

    def test_empty_before_and_after_produce_no_changes(self):
        before = make_snapshot()
        after = make_snapshot()
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert changes == []


class TestEmptyBeforeSnapshot:
    """Test 7: Empty before snapshot → all after assets appear as new."""

    def test_empty_before_all_after_subdomains_are_new(self):
        before = make_snapshot()
        after = make_snapshot(subdomains=[
            make_subdomain("www.example.com"),
            make_subdomain("api.example.com"),
        ])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        new_sub_changes = [c for c in changes if c.change_type == "new_subdomain"]
        assert len(new_sub_changes) == 2

    def test_empty_before_all_after_ports_are_new(self):
        before = make_snapshot()
        after = make_snapshot(ports=[make_port("1.2.3.4", 80), make_port("1.2.3.4", 443)])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        new_port_changes = [c for c in changes if c.change_type == "new_port"]
        assert len(new_port_changes) == 2

    def test_empty_before_all_after_leaks_are_new(self):
        before = make_snapshot()
        after = make_snapshot(leaks=[make_leak("r/r", "a.py", 1), make_leak("r/r", "b.py", 2)])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        new_leak_changes = [c for c in changes if c.change_type == "new_leak"]
        assert len(new_leak_changes) == 2


class TestChangeMetadata:
    """Tests for snapshot_id and target_domain on changes."""

    def test_snapshot_id_on_all_changes_equals_after_snapshot_id(self):
        """Test 8: snapshot_id on all Changes equals after.snapshot_id."""
        before = make_snapshot()
        after = make_snapshot(
            subdomains=[make_subdomain("api.example.com")],
            ports=[make_port("1.2.3.4", 443)],
            leaks=[make_leak()],
        )
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) > 0
        for c in changes:
            assert c.snapshot_id == after.snapshot_id

    def test_target_domain_on_all_changes_equals_after_target_domain(self):
        """Test 9: target_domain on all Changes equals after.target_domain."""
        before = make_snapshot(domain="other.com")
        after = make_snapshot(
            domain="example.com",
            subdomains=[make_subdomain("api.example.com", domain="example.com")],
        )
        engine = DiffEngine()
        changes = engine.diff(before, after)
        assert len(changes) > 0
        for c in changes:
            assert c.target_domain == "example.com"

    def test_all_changes_have_timestamp(self):
        """All Change objects have a timestamp."""
        before = make_snapshot()
        after = make_snapshot(subdomains=[make_subdomain("api.example.com")])
        engine = DiffEngine()
        changes = engine.diff(before, after)
        for c in changes:
            assert isinstance(c.timestamp, datetime)
