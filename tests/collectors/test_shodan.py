"""Tests for ShodanCollector (Shodan InternetDB free API)."""
import socket
from unittest.mock import patch

import httpx
import pytest
import respx

from reconmap.collectors.shodan import ShodanCollector, PORT_SERVICES

# ---------------------------------------------------------------------------
# Helper: build a minimal InternetDB JSON response
# ---------------------------------------------------------------------------

def _internetdb_json(ip: str, ports: list[int] | None = None) -> dict:
    return {
        "ip": ip,
        "ports": ports or [],
        "hostnames": [],
        "tags": [],
        "cpes": [],
        "vulns": [],
    }


# ---------------------------------------------------------------------------
# Test 1 — Normal response: single IP, multiple ports → correct Port objects
# ---------------------------------------------------------------------------

@respx.mock
async def test_normal_response_single_ip_multiple_ports():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("1.2.3.4", 0))]
        respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
            return_value=httpx.Response(
                200, json=_internetdb_json("1.2.3.4", [22, 80, 443])
            )
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert len(snapshot.ports) == 3
    port_nums = {p.port for p in snapshot.ports}
    assert port_nums == {22, 80, 443}
    for p in snapshot.ports:
        assert p.ip == "1.2.3.4"
        assert p.protocol == "tcp"


# ---------------------------------------------------------------------------
# Test 2 — Multiple IPs for same domain → ports from all IPs returned
# ---------------------------------------------------------------------------

@respx.mock
async def test_multiple_ips_ports_from_all_returned():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (None, None, None, None, ("1.1.1.1", 0)),
            (None, None, None, None, ("2.2.2.2", 0)),
        ]
        respx.get("https://internetdb.shodan.io/1.1.1.1").mock(
            return_value=httpx.Response(200, json=_internetdb_json("1.1.1.1", [22]))
        )
        respx.get("https://internetdb.shodan.io/2.2.2.2").mock(
            return_value=httpx.Response(200, json=_internetdb_json("2.2.2.2", [443]))
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    ips_seen = {p.ip for p in snapshot.ports}
    assert "1.1.1.1" in ips_seen
    assert "2.2.2.2" in ips_seen
    assert len(snapshot.ports) == 2


# ---------------------------------------------------------------------------
# Test 3 — 404 response → skip that IP, return empty ports (no exception)
# ---------------------------------------------------------------------------

@respx.mock
async def test_404_response_returns_empty_ports():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("5.5.5.5", 0))]
        respx.get("https://internetdb.shodan.io/5.5.5.5").mock(
            return_value=httpx.Response(404)
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.ports == []


# ---------------------------------------------------------------------------
# Test 4 — Non-200 (e.g. 500) response → skip, no exception
# ---------------------------------------------------------------------------

@respx.mock
async def test_500_response_returns_empty_ports():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("6.6.6.6", 0))]
        respx.get("https://internetdb.shodan.io/6.6.6.6").mock(
            return_value=httpx.Response(500)
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.ports == []


# ---------------------------------------------------------------------------
# Test 5 — Timeout → skip, no exception
# ---------------------------------------------------------------------------

@respx.mock
async def test_timeout_returns_empty_ports():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("7.7.7.7", 0))]
        respx.get("https://internetdb.shodan.io/7.7.7.7").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.ports == []


# ---------------------------------------------------------------------------
# Test 6 — Service name inferred for port 22 → service="ssh"
# ---------------------------------------------------------------------------

@respx.mock
async def test_service_inferred_port_22_is_ssh():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("10.0.0.1", 0))]
        respx.get("https://internetdb.shodan.io/10.0.0.1").mock(
            return_value=httpx.Response(200, json=_internetdb_json("10.0.0.1", [22]))
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert len(snapshot.ports) == 1
    assert snapshot.ports[0].service == "ssh"


# ---------------------------------------------------------------------------
# Test 7 — Service name inferred for port 443 → service="https"
# ---------------------------------------------------------------------------

@respx.mock
async def test_service_inferred_port_443_is_https():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("10.0.0.2", 0))]
        respx.get("https://internetdb.shodan.io/10.0.0.2").mock(
            return_value=httpx.Response(200, json=_internetdb_json("10.0.0.2", [443]))
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert len(snapshot.ports) == 1
    assert snapshot.ports[0].service == "https"


# ---------------------------------------------------------------------------
# Test 8 — Unknown port → service=""
# ---------------------------------------------------------------------------

@respx.mock
async def test_unknown_port_service_is_empty_string():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("10.0.0.3", 0))]
        respx.get("https://internetdb.shodan.io/10.0.0.3").mock(
            return_value=httpx.Response(
                200, json=_internetdb_json("10.0.0.3", [12345])
            )
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert len(snapshot.ports) == 1
    assert snapshot.ports[0].service == ""


# ---------------------------------------------------------------------------
# Test 9 — DNS resolution fails → returns empty snapshot, no exception
# ---------------------------------------------------------------------------

async def test_dns_failure_returns_empty_snapshot():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.side_effect = socket.gaierror("Name not found")
        collector = ShodanCollector()
        snapshot = await collector.collect("nonexistent.invalid")

    assert snapshot.target_domain == "nonexistent.invalid"
    assert snapshot.ports == []
    assert snapshot.subdomains == []


# ---------------------------------------------------------------------------
# Test 10 — is_available() returns True (requires_key=False → base class ok)
# ---------------------------------------------------------------------------

def test_is_available_returns_true():
    collector = ShodanCollector()
    assert collector.is_available() is True


# ---------------------------------------------------------------------------
# Test 11 — requires_key class attribute is False
# ---------------------------------------------------------------------------

def test_requires_key_is_false():
    assert ShodanCollector.requires_key is False


# ---------------------------------------------------------------------------
# Test 12 — Port source field equals "shodan"
# ---------------------------------------------------------------------------

@respx.mock
async def test_port_source_is_shodan():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(None, None, None, None, ("10.0.0.4", 0))]
        respx.get("https://internetdb.shodan.io/10.0.0.4").mock(
            return_value=httpx.Response(200, json=_internetdb_json("10.0.0.4", [80]))
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    assert len(snapshot.ports) == 1
    assert snapshot.ports[0].source == "shodan"


# ---------------------------------------------------------------------------
# Test 13 — collector name class attribute
# ---------------------------------------------------------------------------

def test_collector_name():
    assert ShodanCollector.name == "shodan"


# ---------------------------------------------------------------------------
# Test 14 — One IP 404, another IP 200 → only second IP's ports returned
# ---------------------------------------------------------------------------

@respx.mock
async def test_mixed_responses_one_404_one_200():
    with patch("reconmap.collectors.shodan.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (None, None, None, None, ("3.3.3.3", 0)),
            (None, None, None, None, ("4.4.4.4", 0)),
        ]
        respx.get("https://internetdb.shodan.io/3.3.3.3").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://internetdb.shodan.io/4.4.4.4").mock(
            return_value=httpx.Response(200, json=_internetdb_json("4.4.4.4", [22, 443]))
        )
        collector = ShodanCollector()
        snapshot = await collector.collect("example.com")

    # Only ports from 4.4.4.4 should appear
    ips = {p.ip for p in snapshot.ports}
    assert ips == {"4.4.4.4"}
    assert len(snapshot.ports) == 2


# ---------------------------------------------------------------------------
# Test 15 — PORT_SERVICES covers key well-known ports
# ---------------------------------------------------------------------------

def test_port_services_map_contains_key_entries():
    assert PORT_SERVICES[21] == "ftp"
    assert PORT_SERVICES[22] == "ssh"
    assert PORT_SERVICES[80] == "http"
    assert PORT_SERVICES[443] == "https"
    assert PORT_SERVICES[3306] == "mysql"
    assert PORT_SERVICES[27017] == "mongodb"
