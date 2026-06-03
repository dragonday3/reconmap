"""Tests for CertStreamCollector (crt.sh CT log queries)."""
import pytest
import respx
import httpx

from reconmap.collectors.certstream import CertStreamCollector

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

CRTSH_RESPONSE = [
    {
        "name_value": "api.example.com\nwww.example.com",
        "not_before": "2024-01-01T00:00:00",
    },
    {
        "name_value": "*.example.com",
        "not_before": "2024-02-01T00:00:00",
    },
    {
        "name_value": "unrelated.other.com",
        "not_before": "2024-01-15T00:00:00",
    },
]

CRT_URL_PATTERN = r"https://crt\.sh/.*"


# ---------------------------------------------------------------------------
# Test 1 — Normal response produces correct Subdomain objects
# ---------------------------------------------------------------------------

@respx.mock
async def test_normal_response_extracts_subdomains():
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=CRTSH_RESPONSE)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    names = {s.subdomain for s in snapshot.subdomains}
    # api, www, and stripped wildcard "example.com" itself should appear
    assert "api.example.com" in names
    assert "www.example.com" in names
    # unrelated.other.com must NOT appear
    assert "unrelated.other.com" not in names


# ---------------------------------------------------------------------------
# Test 2 — Wildcard entries have "*." stripped
# ---------------------------------------------------------------------------

@respx.mock
async def test_wildcard_stripped():
    data = [{"name_value": "*.example.com", "not_before": "2024-03-01T00:00:00"}]
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=data)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    names = {s.subdomain for s in snapshot.subdomains}
    # "*.example.com" → strip "*." → "example.com" (matches domain exactly)
    assert "example.com" in names
    assert not any(n.startswith("*.") for n in names)


# ---------------------------------------------------------------------------
# Test 3 — Multiline name_value — both names extracted when valid
# ---------------------------------------------------------------------------

@respx.mock
async def test_multiline_name_value_both_extracted():
    data = [
        {
            "name_value": "mail.example.com\nsmtp.example.com",
            "not_before": "2024-04-01T00:00:00",
        }
    ]
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=data)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    names = {s.subdomain for s in snapshot.subdomains}
    assert "mail.example.com" in names
    assert "smtp.example.com" in names


# ---------------------------------------------------------------------------
# Test 4 — Names not matching target domain are filtered out
# ---------------------------------------------------------------------------

@respx.mock
async def test_non_matching_domains_filtered():
    data = [
        {"name_value": "evil.attacker.com", "not_before": "2024-01-01T00:00:00"},
        {"name_value": "legit.example.com", "not_before": "2024-01-01T00:00:00"},
    ]
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=data)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    names = {s.subdomain for s in snapshot.subdomains}
    assert "evil.attacker.com" not in names
    assert "legit.example.com" in names


# ---------------------------------------------------------------------------
# Test 5 — Duplicate subdomain across entries → single Subdomain with
#           correct first_seen (earliest) and last_seen (latest)
# ---------------------------------------------------------------------------

@respx.mock
async def test_duplicate_subdomain_dedup_with_correct_dates():
    data = [
        {"name_value": "api.example.com", "not_before": "2024-01-01T00:00:00"},
        {"name_value": "api.example.com", "not_before": "2024-06-01T00:00:00"},
    ]
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=data)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    api_subs = [s for s in snapshot.subdomains if s.subdomain == "api.example.com"]
    assert len(api_subs) == 1

    sub = api_subs[0]
    assert sub.first_seen.year == 2024
    assert sub.first_seen.month == 1
    assert sub.last_seen.month == 6


# ---------------------------------------------------------------------------
# Test 6 — crt.sh returns 500 → empty snapshot, no exception raised
# ---------------------------------------------------------------------------

@respx.mock
async def test_http_500_returns_empty_snapshot():
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(500)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.subdomains == []
    assert snapshot.ports == []
    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 7 — Timeout → empty snapshot, no exception raised
# ---------------------------------------------------------------------------

@respx.mock
async def test_timeout_returns_empty_snapshot():
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.subdomains == []


# ---------------------------------------------------------------------------
# Test 8 — is_available() always returns True
# ---------------------------------------------------------------------------

def test_is_available_returns_true():
    collector = CertStreamCollector()
    assert collector.is_available() is True


# ---------------------------------------------------------------------------
# Test 9 — requires_key is False
# ---------------------------------------------------------------------------

def test_requires_key_is_false():
    assert CertStreamCollector.requires_key is False


# ---------------------------------------------------------------------------
# Test 10 — Empty JSON array → empty snapshot with no subdomains
# ---------------------------------------------------------------------------

@respx.mock
async def test_empty_json_array_returns_empty_snapshot():
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=[])
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.subdomains == []


# ---------------------------------------------------------------------------
# Test 11 — Domain itself (not a subdomain) in name_value → included
# ---------------------------------------------------------------------------

@respx.mock
async def test_domain_itself_included():
    data = [{"name_value": "example.com", "not_before": "2024-05-01T00:00:00"}]
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=data)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    names = {s.subdomain for s in snapshot.subdomains}
    assert "example.com" in names


# ---------------------------------------------------------------------------
# Test 12 — source field on returned Subdomain objects is "certstream"
# ---------------------------------------------------------------------------

@respx.mock
async def test_subdomain_source_is_certstream():
    data = [{"name_value": "dev.example.com", "not_before": "2024-01-01T00:00:00"}]
    respx.get(url__regex=CRT_URL_PATTERN).mock(
        return_value=httpx.Response(200, json=data)
    )
    collector = CertStreamCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.subdomains) == 1
    assert snapshot.subdomains[0].source == "certstream"


# ---------------------------------------------------------------------------
# Test 13 — collector name class attribute
# ---------------------------------------------------------------------------

def test_collector_name():
    assert CertStreamCollector.name == "certstream"
