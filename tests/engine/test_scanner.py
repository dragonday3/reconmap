"""Tests for Scanner orchestrator."""
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from reconmap.collectors.certstream import CertStreamCollector
from reconmap.collectors.shodan import ShodanCollector
from reconmap.collectors.github import GitHubCollector
from reconmap.collectors.dns_resolver import DNSResolverCollector
from reconmap.engine.scanner import Scanner
from reconmap.models.asset import AssetSnapshot, Subdomain, Port, SecretLeak


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_subdomain(
    name: str,
    target: str = "example.com",
    source: str = "test",
    ip_addresses: list[str] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> Subdomain:
    now = datetime.now(timezone.utc)
    return Subdomain(
        target_domain=target,
        subdomain=name,
        source=source,
        ip_addresses=ip_addresses or [],
        first_seen=first_seen or now,
        last_seen=last_seen or now,
    )


def make_port(ip: str = "1.2.3.4", port: int = 80, source: str = "test") -> Port:
    return Port(ip=ip, port=port, source=source)


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


def make_passive_collector(snapshot: AssetSnapshot) -> CertStreamCollector:
    """Return a real CertStreamCollector instance with a mocked collect method."""
    collector = CertStreamCollector()
    collector.collect = AsyncMock(return_value=snapshot)
    return collector


def make_shodan_collector(snapshot: AssetSnapshot) -> ShodanCollector:
    collector = ShodanCollector()
    collector.collect = AsyncMock(return_value=snapshot)
    return collector


def make_dns_collector(snapshot: AssetSnapshot) -> DNSResolverCollector:
    collector = DNSResolverCollector()
    collector.collect = AsyncMock(return_value=snapshot)
    return collector


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScannerDefaultCollectors:
    """Test 10: Scanner() with no args creates 4 default collectors."""

    def test_default_collectors_count(self):
        scanner = Scanner()
        assert len(scanner._collectors) == 4

    def test_default_collectors_types(self):
        scanner = Scanner()
        types = [type(c) for c in scanner._collectors]
        assert CertStreamCollector in types
        assert ShodanCollector in types
        assert GitHubCollector in types
        assert DNSResolverCollector in types


class TestScannerCustomCollectors:
    """Test 9: Custom collectors parameter overrides default list."""

    def test_custom_collectors_override(self):
        mock_snap = AssetSnapshot(target_domain="example.com")
        collector = make_passive_collector(mock_snap)
        scanner = Scanner(collectors=[collector])
        assert len(scanner._collectors) == 1
        assert scanner._collectors[0] is collector

    @pytest.mark.asyncio
    async def test_custom_collectors_are_used_in_run(self):
        snap = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com")],
        )
        collector = make_passive_collector(snap)
        scanner = Scanner(collectors=[collector])
        result = await scanner.run("example.com")
        collector.collect.assert_awaited_once_with("example.com")
        assert len(result.subdomains) == 1


class TestScannerMergesResults:
    """Test 1: Scanner with mocked collectors → run() returns merged AssetSnapshot."""

    @pytest.mark.asyncio
    async def test_run_returns_asset_snapshot(self):
        snap = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("www.example.com")],
        )
        collector = make_passive_collector(snap)
        scanner = Scanner(collectors=[collector])
        result = await scanner.run("example.com")
        assert isinstance(result, AssetSnapshot)
        assert result.target_domain == "example.com"
        assert len(result.subdomains) == 1

    @pytest.mark.asyncio
    async def test_run_merges_from_multiple_passive_collectors(self):
        snap1 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("www.example.com")],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com")],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        subdomain_names = {s.subdomain for s in result.subdomains}
        assert "www.example.com" in subdomain_names
        assert "api.example.com" in subdomain_names


class TestSubdomainDeduplication:
    """Test 2: Subdomains deduped by name."""

    @pytest.mark.asyncio
    async def test_same_subdomain_from_two_collectors_deduped(self):
        snap1 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", source="certstream")],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", source="shodan")],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert len(result.subdomains) == 1
        assert result.subdomains[0].subdomain == "api.example.com"


class TestIPAddressUnion:
    """Test 3: IP addresses unioned when same subdomain from two sources."""

    @pytest.mark.asyncio
    async def test_ip_addresses_are_unioned(self):
        snap1 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", ip_addresses=["1.1.1.1"])],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", ip_addresses=["2.2.2.2"])],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert len(result.subdomains) == 1
        ips = set(result.subdomains[0].ip_addresses)
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips

    @pytest.mark.asyncio
    async def test_duplicate_ips_are_deduplicated(self):
        snap1 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", ip_addresses=["1.1.1.1"])],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", ip_addresses=["1.1.1.1", "2.2.2.2"])],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        ips = result.subdomains[0].ip_addresses
        assert len(ips) == len(set(ips))  # no duplicates


class TestSubdomainTimestamps:
    """Test 4: first_seen = earliest, last_seen = latest when merging same subdomain."""

    @pytest.mark.asyncio
    async def test_first_seen_is_earliest_last_seen_is_latest(self):
        now = datetime.now(timezone.utc)
        earlier = now - timedelta(days=10)
        later = now + timedelta(days=5)

        snap1 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", first_seen=now, last_seen=now)],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("api.example.com", first_seen=earlier, last_seen=later)],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        sub = result.subdomains[0]
        assert sub.first_seen == earlier
        assert sub.last_seen == later


class TestPortDeduplication:
    """Test 5: Ports deduped by (ip, port)."""

    @pytest.mark.asyncio
    async def test_same_port_from_two_collectors_deduped(self):
        snap1 = AssetSnapshot(
            target_domain="example.com",
            ports=[make_port("1.2.3.4", 443)],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            ports=[make_port("1.2.3.4", 443)],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert len(result.ports) == 1
        assert result.ports[0].ip == "1.2.3.4"
        assert result.ports[0].port == 443

    @pytest.mark.asyncio
    async def test_different_ports_kept_separately(self):
        snap1 = AssetSnapshot(
            target_domain="example.com",
            ports=[make_port("1.2.3.4", 80)],
        )
        snap2 = AssetSnapshot(
            target_domain="example.com",
            ports=[make_port("1.2.3.4", 443)],
        )
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert len(result.ports) == 2


class TestLeakDeduplication:
    """Test 6: Leaks deduped by (repo, file_path, line_number)."""

    @pytest.mark.asyncio
    async def test_same_leak_from_two_collectors_deduped(self):
        leak = make_leak("user/repo", "config.py", 42)
        snap1 = AssetSnapshot(target_domain="example.com", leaks=[leak])
        snap2 = AssetSnapshot(target_domain="example.com", leaks=[leak])
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert len(result.leaks) == 1

    @pytest.mark.asyncio
    async def test_different_leaks_kept_separately(self):
        leak1 = make_leak("user/repo", "config.py", 42)
        leak2 = make_leak("user/repo", "config.py", 99)
        snap1 = AssetSnapshot(target_domain="example.com", leaks=[leak1])
        snap2 = AssetSnapshot(target_domain="example.com", leaks=[leak2])
        c1 = make_passive_collector(snap1)
        c2 = make_shodan_collector(snap2)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert len(result.leaks) == 2


class TestDNSCollectorReceivesMergedSubdomains:
    """Test 7: DNS collector receives merged subdomains from passive collectors as input."""

    @pytest.mark.asyncio
    async def test_dns_collector_receives_merged_subdomains(self):
        sub1 = make_subdomain("www.example.com", source="certstream")
        sub2 = make_subdomain("api.example.com", source="shodan")

        passive_snap = AssetSnapshot(target_domain="example.com", subdomains=[sub1])
        shodan_snap = AssetSnapshot(target_domain="example.com", subdomains=[sub2])
        dns_snap = AssetSnapshot(target_domain="example.com", subdomains=[])

        c_passive = make_passive_collector(passive_snap)
        c_shodan = make_shodan_collector(shodan_snap)
        c_dns = make_dns_collector(dns_snap)

        scanner = Scanner(collectors=[c_passive, c_shodan, c_dns])
        await scanner.run("example.com")

        # DNS must be called with existing_subdomains that includes both passive results
        call_kwargs = c_dns.collect.call_args
        existing = call_kwargs.kwargs.get("existing_subdomains") or call_kwargs[1].get("existing_subdomains")
        existing_names = {s.subdomain for s in existing}
        assert "www.example.com" in existing_names
        assert "api.example.com" in existing_names


class TestCollectorExceptionHandling:
    """Test 8: A collector that raises an exception → still returns valid snapshot."""

    @pytest.mark.asyncio
    async def test_failing_collector_does_not_crash_scanner(self):
        failing = make_passive_collector(AssetSnapshot(target_domain="example.com"))
        failing.collect = AsyncMock(side_effect=RuntimeError("network error"))

        good_snap = AssetSnapshot(
            target_domain="example.com",
            subdomains=[make_subdomain("www.example.com")],
        )
        good = make_shodan_collector(good_snap)

        scanner = Scanner(collectors=[failing, good])
        result = await scanner.run("example.com")
        assert isinstance(result, AssetSnapshot)
        assert len(result.subdomains) == 1
        assert result.subdomains[0].subdomain == "www.example.com"


class TestEmptySnapshots:
    """Test 11: Empty snapshots from all collectors → empty merged snapshot."""

    @pytest.mark.asyncio
    async def test_all_empty_collectors_returns_empty_snapshot(self):
        empty = AssetSnapshot(target_domain="example.com")
        c1 = make_passive_collector(empty)
        c2 = make_shodan_collector(empty)
        scanner = Scanner(collectors=[c1, c2])
        result = await scanner.run("example.com")
        assert result.subdomains == []
        assert result.ports == []
        assert result.leaks == []
        assert result.target_domain == "example.com"
