"""Shodan InternetDB collector — free, unauthenticated passive port data."""
import asyncio
import logging
import socket

import httpx

from reconmap.collectors.base import BaseCollector
from reconmap.models.asset import AssetSnapshot, Port

logger = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

PORT_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


class ShodanCollector(BaseCollector):
    name = "shodan"
    requires_key = False  # InternetDB is free, no key needed

    async def collect(self, domain: str) -> AssetSnapshot:
        """Resolve domain to IPs, query InternetDB for each, return port data."""
        ips = self._resolve_ips(domain)
        if not ips:
            logger.warning("Could not resolve IPs for %s", domain)
            return AssetSnapshot(target_domain=domain)

        async with httpx.AsyncClient(timeout=10.0) as client:
            tasks = [self._query_ip(client, domain, ip) for ip in ips]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        ports: list[Port] = []
        for result in results:
            if isinstance(result, list):
                ports.extend(result)

        return AssetSnapshot(target_domain=domain, ports=ports)

    def _resolve_ips(self, domain: str) -> list[str]:
        """Resolve domain to IPv4 addresses. Returns empty list on failure."""
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list({info[4][0] for info in infos})
        except socket.gaierror as exc:
            logger.warning("DNS resolution failed for %s: %s", domain, exc)
            return []

    async def _query_ip(
        self, client: httpx.AsyncClient, domain: str, ip: str
    ) -> list[Port]:
        """Query InternetDB for a single IP. Returns list of Port objects."""
        url = INTERNETDB_URL.format(ip=ip)
        try:
            response = await client.get(url)
            if response.status_code == 404:
                return []
            if response.status_code != 200:
                logger.warning(
                    "InternetDB returned %s for %s", response.status_code, ip
                )
                return []
            data = response.json()
        except httpx.TimeoutException:
            logger.warning("InternetDB timeout for %s", ip)
            return []
        except Exception as exc:
            logger.warning("InternetDB error for %s: %s", ip, exc)
            return []

        ports: list[Port] = []
        for port_num in data.get("ports", []):
            ports.append(
                Port(
                    ip=ip,
                    port=port_num,
                    protocol="tcp",
                    service=PORT_SERVICES.get(port_num, ""),
                    banner="",
                    source=self.name,
                )
            )
        return ports
