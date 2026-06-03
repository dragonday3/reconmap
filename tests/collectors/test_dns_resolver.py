"""Tests for DNSResolverCollector — async DNS resolution and prefix brute-force."""
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception

from reconmap.collectors.dns_resolver import COMMON_PREFIXES, DNSResolverCollector
from reconmap.models.asset import Subdomain

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_answer(ip: str):
    """Return a mock dns answer object whose iteration yields one rdata str()==ip.

    Uses a side_effect on __iter__ so the iterator is freshly created on every
    call — avoids exhaustion when the same answer mock is iterated multiple times.
    """
    rdata = MagicMock()
    rdata.__str__ = MagicMock(return_value=ip)
    answer = MagicMock()
    answer.__iter__ = MagicMock(side_effect=lambda: iter([rdata]))
    return answer


def _make_existing_subdomain(domain: str, subdomain: str, source: str = "certstream", ips: list[str] | None = None) -> Subdomain:
    now = datetime.now(timezone.utc)
    return Subdomain(
        target_domain=domain,
        subdomain=subdomain,
        ip_addresses=ips or [],
        source=source,
        first_seen=now,
        last_seen=now,
    )


# ---------------------------------------------------------------------------
# Test 1 — Resolves a known subdomain → ip_addresses populated correctly
# ---------------------------------------------------------------------------

async def test_resolves_known_subdomain_ip_populated():
    answer = _make_answer("1.2.3.4")
    with patch("dns.asyncresolver.resolve", new=AsyncMock(return_value=answer)):
        sub = _make_existing_subdomain("example.com", "mail.example.com", source="certstream")
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=[sub])

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "mail.example.com" in subdomain_map
    assert "1.2.3.4" in subdomain_map["mail.example.com"].ip_addresses


# ---------------------------------------------------------------------------
# Test 2 — NXDOMAIN → ip_addresses stays empty, no exception raised
# ---------------------------------------------------------------------------

async def test_nxdomain_ip_addresses_stay_empty():
    with patch(
        "dns.asyncresolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        sub = _make_existing_subdomain("example.com", "mail.example.com", source="certstream")
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=[sub])

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "mail.example.com" in subdomain_map
    assert subdomain_map["mail.example.com"].ip_addresses == []


# ---------------------------------------------------------------------------
# Test 3 — Timeout → ip_addresses stays empty, no exception raised
# ---------------------------------------------------------------------------

async def test_timeout_ip_addresses_stay_empty():
    with patch(
        "dns.asyncresolver.resolve",
        new=AsyncMock(side_effect=asyncio.TimeoutError()),
    ):
        sub = _make_existing_subdomain("example.com", "api.example.com", source="certstream")
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=[sub])

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "api.example.com" in subdomain_map
    assert subdomain_map["api.example.com"].ip_addresses == []


# ---------------------------------------------------------------------------
# Test 4 — Common prefix resolves → new Subdomain added with source="dns"
# ---------------------------------------------------------------------------

async def test_common_prefix_resolved_new_subdomain_added_with_dns_source():
    answer = _make_answer("5.6.7.8")

    def resolve_side_effect(name, record_type):
        if name == "www.example.com":
            return answer
        raise dns.exception.DNSException("NXDOMAIN")

    with patch("dns.asyncresolver.resolve", new=AsyncMock(side_effect=resolve_side_effect)):
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com")

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "www.example.com" in subdomain_map
    assert subdomain_map["www.example.com"].source == "dns"
    assert "5.6.7.8" in subdomain_map["www.example.com"].ip_addresses


# ---------------------------------------------------------------------------
# Test 5 — Common prefix NXDOMAIN → NOT added to results
# ---------------------------------------------------------------------------

async def test_common_prefix_nxdomain_not_added():
    with patch(
        "dns.asyncresolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com")

    assert snapshot.subdomains == []


# ---------------------------------------------------------------------------
# Test 6 — Existing subdomain passed in → preserved in output, source unchanged
# ---------------------------------------------------------------------------

async def test_existing_subdomain_preserved_source_unchanged():
    with patch(
        "dns.asyncresolver.resolve",
        new=AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN")),
    ):
        sub = _make_existing_subdomain("example.com", "portal.example.com", source="shodan")
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=[sub])

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "portal.example.com" in subdomain_map
    assert subdomain_map["portal.example.com"].source == "shodan"


# ---------------------------------------------------------------------------
# Test 7 — Existing subdomain that resolves → ip_addresses updated, source unchanged
# ---------------------------------------------------------------------------

async def test_existing_subdomain_resolves_ips_updated_source_unchanged():
    answer = _make_answer("9.9.9.9")

    def resolve_side_effect(name, record_type):
        if name == "api.example.com":
            return answer
        raise dns.exception.DNSException("NXDOMAIN")

    with patch("dns.asyncresolver.resolve", new=AsyncMock(side_effect=resolve_side_effect)):
        sub = _make_existing_subdomain("example.com", "api.example.com", source="certstream", ips=[])
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=[sub])

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "api.example.com" in subdomain_map
    found = subdomain_map["api.example.com"]
    assert "9.9.9.9" in found.ip_addresses
    # source must NOT be changed to "dns"
    assert found.source == "certstream"


# ---------------------------------------------------------------------------
# Test 8 — is_available() returns True
# ---------------------------------------------------------------------------

def test_is_available_returns_true():
    collector = DNSResolverCollector()
    assert collector.is_available() is True


# ---------------------------------------------------------------------------
# Test 9 — requires_key is False
# ---------------------------------------------------------------------------

def test_requires_key_is_false():
    assert DNSResolverCollector.requires_key is False


# ---------------------------------------------------------------------------
# Test 10 — None existing_subdomains → only common-prefix brute force runs
# ---------------------------------------------------------------------------

async def test_none_existing_subdomains_only_prefix_brute_force():
    answer = _make_answer("2.2.2.2")

    def resolve_side_effect(name, record_type):
        if name == "cdn.example.com":
            return answer
        raise dns.exception.DNSException("NXDOMAIN")

    with patch("dns.asyncresolver.resolve", new=AsyncMock(side_effect=resolve_side_effect)):
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=None)

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    # Only the resolved prefix candidate should be present
    assert "cdn.example.com" in subdomain_map
    assert subdomain_map["cdn.example.com"].source == "dns"
    # No other subdomains (all others NXDOMAIN)
    assert len(snapshot.subdomains) == 1


# ---------------------------------------------------------------------------
# Test 11 — All 20 COMMON_PREFIXES are attempted
# ---------------------------------------------------------------------------

async def test_all_common_prefixes_attempted():
    mock_resolve = AsyncMock(side_effect=dns.exception.DNSException("NXDOMAIN"))

    with patch("dns.asyncresolver.resolve", new=mock_resolve):
        collector = DNSResolverCollector()
        await collector.collect("example.com")

    # Collect all names that were queried
    queried_names = {c.args[0] for c in mock_resolve.call_args_list}
    expected_names = {f"{prefix}.example.com" for prefix in COMMON_PREFIXES}
    assert expected_names.issubset(queried_names)


# ---------------------------------------------------------------------------
# Test 12 — Multiple IPs returned for a single subdomain
# ---------------------------------------------------------------------------

async def test_multiple_ips_for_single_subdomain():
    rdata1 = MagicMock()
    rdata1.__str__ = MagicMock(return_value="10.0.0.1")
    rdata2 = MagicMock()
    rdata2.__str__ = MagicMock(return_value="10.0.0.2")
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter([rdata1, rdata2]))

    def resolve_side_effect(name, record_type):
        if name == "www.example.com":
            return answer
        raise dns.exception.DNSException("NXDOMAIN")

    with patch("dns.asyncresolver.resolve", new=AsyncMock(side_effect=resolve_side_effect)):
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com")

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "www.example.com" in subdomain_map
    ips = subdomain_map["www.example.com"].ip_addresses
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips
    assert len(ips) == 2


# ---------------------------------------------------------------------------
# Test 13 — target_domain set correctly on snapshot and discovered subdomains
# ---------------------------------------------------------------------------

async def test_target_domain_set_correctly():
    answer = _make_answer("3.3.3.3")

    def resolve_side_effect(name, record_type):
        if name == "git.target.org":
            return answer
        raise dns.exception.DNSException("NXDOMAIN")

    with patch("dns.asyncresolver.resolve", new=AsyncMock(side_effect=resolve_side_effect)):
        collector = DNSResolverCollector()
        snapshot = await collector.collect("target.org")

    assert snapshot.target_domain == "target.org"
    for sub in snapshot.subdomains:
        assert sub.target_domain == "target.org"


# ---------------------------------------------------------------------------
# Test 14 — collector name class attribute is "dns"
# ---------------------------------------------------------------------------

def test_collector_name_is_dns():
    assert DNSResolverCollector.name == "dns"


# ---------------------------------------------------------------------------
# Test 15 — Existing subdomain already in prefix set → source NOT overwritten
# ---------------------------------------------------------------------------

async def test_existing_subdomain_matching_prefix_source_not_overwritten():
    """www.example.com exists as a known subdomain; when it resolves the source
    must remain the original source, not 'dns'."""
    answer = _make_answer("7.7.7.7")

    def resolve_side_effect(name, record_type):
        if name == "www.example.com":
            return answer
        raise dns.exception.DNSException("NXDOMAIN")

    with patch("dns.asyncresolver.resolve", new=AsyncMock(side_effect=resolve_side_effect)):
        # www.example.com is both a known subdomain AND a common prefix candidate
        sub = _make_existing_subdomain("example.com", "www.example.com", source="crtsh")
        collector = DNSResolverCollector()
        snapshot = await collector.collect("example.com", existing_subdomains=[sub])

    subdomain_map = {s.subdomain: s for s in snapshot.subdomains}
    assert "www.example.com" in subdomain_map
    # Should appear exactly once — not duplicated
    count = sum(1 for s in snapshot.subdomains if s.subdomain == "www.example.com")
    assert count == 1
    # Source preserved from the known subdomain
    assert subdomain_map["www.example.com"].source == "crtsh"
    assert "7.7.7.7" in subdomain_map["www.example.com"].ip_addresses
