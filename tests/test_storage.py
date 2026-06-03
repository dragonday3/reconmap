"""Tests for the async SQLAlchemy storage layer."""
import pytest
from datetime import datetime, timezone, timedelta

from reconmap.storage.db import Storage
from reconmap.models.asset import (
    AssetSnapshot,
    Change,
    Port,
    SecretLeak,
    Subdomain,
    TargetDomain,
)


@pytest.fixture
async def storage():
    s = Storage(db_url="sqlite+aiosqlite:///:memory:")
    await s.init()
    yield s
    await s.close()


# ── 1. init() creates tables without error ────────────────────────────────────

async def test_init_creates_tables_without_error():
    """init() should complete without raising."""
    s = Storage(db_url="sqlite+aiosqlite:///:memory:")
    await s.init()
    await s.close()


# ── 2. add_target + list_targets round-trip ───────────────────────────────────

async def test_add_and_list_targets(storage):
    """add_target + list_targets should round-trip domain correctly."""
    target = TargetDomain(domain="example.com")
    await storage.add_target(target)
    targets = await storage.list_targets()
    assert len(targets) == 1
    assert targets[0].domain == "example.com"


# ── 3. list_targets returns empty list when no targets ────────────────────────

async def test_list_targets_empty(storage):
    """list_targets should return empty list when no targets exist."""
    targets = await storage.list_targets()
    assert targets == []


# ── 4. save_snapshot + get_snapshots round-trip ───────────────────────────────

async def test_save_and_get_snapshot(storage):
    """save_snapshot + get_snapshots should preserve snapshot_id."""
    snapshot = AssetSnapshot(target_domain="example.com")
    await storage.save_snapshot(snapshot)
    snapshots = await storage.get_snapshots("example.com")
    assert len(snapshots) == 1
    assert snapshots[0].snapshot_id == snapshot.snapshot_id
    assert snapshots[0].target_domain == "example.com"


# ── 5. get_snapshots respects limit parameter ─────────────────────────────────

async def test_get_snapshots_respects_limit(storage):
    """get_snapshots should return at most `limit` snapshots."""
    for _ in range(5):
        await storage.save_snapshot(AssetSnapshot(target_domain="example.com"))
    snapshots = await storage.get_snapshots("example.com", limit=3)
    assert len(snapshots) == 3


# ── 6. get_snapshots returns newest first ─────────────────────────────────────

async def test_get_snapshots_descending_order(storage):
    """get_snapshots should return snapshots newest-first."""
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    snap_old = AssetSnapshot(
        target_domain="example.com",
        timestamp=base,
    )
    snap_new = AssetSnapshot(
        target_domain="example.com",
        timestamp=base + timedelta(hours=1),
    )
    await storage.save_snapshot(snap_old)
    await storage.save_snapshot(snap_new)
    snapshots = await storage.get_snapshots("example.com")
    assert snapshots[0].snapshot_id == snap_new.snapshot_id
    assert snapshots[1].snapshot_id == snap_old.snapshot_id


# ── 7. get_latest_snapshot returns most recent ────────────────────────────────

async def test_get_latest_snapshot_returns_most_recent(storage):
    """get_latest_snapshot should return the snapshot with the latest timestamp."""
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    snap_old = AssetSnapshot(target_domain="example.com", timestamp=base)
    snap_new = AssetSnapshot(
        target_domain="example.com", timestamp=base + timedelta(hours=2)
    )
    await storage.save_snapshot(snap_old)
    await storage.save_snapshot(snap_new)
    latest = await storage.get_latest_snapshot("example.com")
    assert latest is not None
    assert latest.snapshot_id == snap_new.snapshot_id


# ── 8. get_latest_snapshot returns None when no snapshots ─────────────────────

async def test_get_latest_snapshot_returns_none_when_empty(storage):
    """get_latest_snapshot should return None if no snapshots exist."""
    result = await storage.get_latest_snapshot("nosuchdomain.com")
    assert result is None


# ── 9. save_changes + get_changes round-trip ─────────────────────────────────

async def test_save_and_get_changes(storage):
    """save_changes + get_changes should preserve all fields."""
    change = Change(
        target_domain="example.com",
        snapshot_id="snap-001",
        change_type="new_subdomain",
        severity="high",
        asset_type="subdomain",
        asset_key="api.example.com",
        details={"ip": "1.2.3.4"},
    )
    await storage.save_changes([change])
    changes = await storage.get_changes("example.com")
    assert len(changes) == 1
    c = changes[0]
    assert c.target_domain == "example.com"
    assert c.snapshot_id == "snap-001"
    assert c.change_type == "new_subdomain"
    assert c.severity == "high"
    assert c.asset_type == "subdomain"
    assert c.asset_key == "api.example.com"
    assert c.details == {"ip": "1.2.3.4"}


# ── 10. save_changes with empty list → no error ───────────────────────────────

async def test_save_changes_empty_list(storage):
    """save_changes([]) should not raise an error."""
    await storage.save_changes([])  # Must not raise
    changes = await storage.get_changes("example.com")
    assert changes == []


# ── 11. get_changes returns newest first ─────────────────────────────────────

async def test_get_changes_descending_order(storage):
    """get_changes should return changes newest-first."""
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    change_old = Change(
        target_domain="example.com",
        snapshot_id="snap-001",
        timestamp=base,
        change_type="new_subdomain",
        severity="low",
        asset_type="subdomain",
        asset_key="old.example.com",
    )
    change_new = Change(
        target_domain="example.com",
        snapshot_id="snap-002",
        timestamp=base + timedelta(hours=1),
        change_type="new_port",
        severity="medium",
        asset_type="port",
        asset_key="1.2.3.4:443",
    )
    await storage.save_changes([change_old, change_new])
    changes = await storage.get_changes("example.com")
    assert changes[0].snapshot_id == "snap-002"
    assert changes[1].snapshot_id == "snap-001"


# ── 12. add_target twice for same domain → no error (OR IGNORE) ───────────────

async def test_add_target_duplicate_no_error(storage):
    """add_target for the same domain twice should not raise (OR IGNORE)."""
    target = TargetDomain(domain="example.com")
    await storage.add_target(target)
    await storage.add_target(target)  # Must not raise
    targets = await storage.list_targets()
    assert len(targets) == 1  # Only one row stored


# ── 13. Snapshot with subdomains/ports/leaks round-trips via JSON ─────────────

async def test_snapshot_with_assets_json_roundtrip(storage):
    """AssetSnapshot containing subdomains, ports and leaks should survive JSON round-trip."""
    subdomain = Subdomain(
        target_domain="example.com",
        subdomain="api.example.com",
        source="amass",
        ip_addresses=["192.168.1.1"],
    )
    port = Port(
        ip="192.168.1.1",
        port=443,
        protocol="tcp",
        service="https",
        source="nmap",
    )
    leak = SecretLeak(
        target_domain="example.com",
        repo="org/repo",
        file_path="config.env",
        secret_type="aws_key",
        line_number=10,
        raw_match="AKIA...",
        html_url="https://github.com/org/repo/blob/main/config.env#L10",
    )
    original = AssetSnapshot(
        target_domain="example.com",
        subdomains=[subdomain],
        ports=[port],
        leaks=[leak],
    )
    await storage.save_snapshot(original)
    retrieved = await storage.get_latest_snapshot("example.com")
    assert retrieved is not None
    assert retrieved.snapshot_id == original.snapshot_id
    assert len(retrieved.subdomains) == 1
    assert retrieved.subdomains[0].subdomain == "api.example.com"
    assert retrieved.subdomains[0].ip_addresses == ["192.168.1.1"]
    assert len(retrieved.ports) == 1
    assert retrieved.ports[0].port == 443
    assert retrieved.ports[0].service == "https"
    assert len(retrieved.leaks) == 1
    assert retrieved.leaks[0].secret_type == "aws_key"
    assert retrieved.leaks[0].line_number == 10


# ── Bonus: tags round-trip ────────────────────────────────────────────────────

async def test_add_target_tags_preserved(storage):
    """Tags should survive the add_target / list_targets round-trip."""
    target = TargetDomain(domain="tagged.com", tags=["web", "api", "prod"])
    await storage.add_target(target)
    targets = await storage.list_targets()
    assert len(targets) == 1
    assert targets[0].tags == ["web", "api", "prod"]


# ── Bonus: get_snapshots returns empty for unknown domain ─────────────────────

async def test_get_snapshots_unknown_domain_returns_empty(storage):
    """get_snapshots for a domain with no data should return empty list."""
    result = await storage.get_snapshots("unknown.com")
    assert result == []


# ── Bonus: get_changes returns empty for unknown domain ──────────────────────

async def test_get_changes_unknown_domain_returns_empty(storage):
    """get_changes for a domain with no data should return empty list."""
    result = await storage.get_changes("unknown.com")
    assert result == []
