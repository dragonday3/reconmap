import asyncio
import logging
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception

from reconmap.collectors.base import BaseCollector
from reconmap.models.asset import AssetSnapshot, Subdomain

logger = logging.getLogger(__name__)

COMMON_PREFIXES = [
    "www", "api", "mail", "smtp", "dev", "staging", "admin",
    "test", "cdn", "static", "app", "portal", "dashboard",
    "auth", "login", "vpn", "remote", "git", "ci", "monitor",
]


class DNSResolverCollector(BaseCollector):
    name = "dns"
    requires_key = False

    def __init__(self, concurrency: int = 20):
        self._sem = asyncio.Semaphore(concurrency)

    async def collect(self, domain: str, existing_subdomains: list[Subdomain] | None = None) -> AssetSnapshot:
        """
        Resolve existing subdomains to IPs, then brute-force common prefixes.
        Returns AssetSnapshot with all discovered/updated subdomains.
        """
        # Build list of names to resolve: existing + common prefixes
        known_names: set[str] = set()
        subdomain_map: dict[str, Subdomain] = {}

        if existing_subdomains:
            for sub in existing_subdomains:
                known_names.add(sub.subdomain)
                subdomain_map[sub.subdomain] = sub.model_copy()

        # Add common-prefix candidates not already known
        prefix_candidates = {f"{prefix}.{domain}" for prefix in COMMON_PREFIXES}
        all_names = known_names | prefix_candidates

        # Resolve all concurrently
        tasks = [self._resolve(name) for name in all_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        now = datetime.now(timezone.utc)
        resolved: dict[str, list[str]] = {}  # name -> [ip, ...]

        for name, result in zip(all_names, results):
            if isinstance(result, list) and result:
                resolved[name] = result

        # Build final subdomain list
        final: dict[str, Subdomain] = {}

        # Update existing subdomains with resolved IPs
        for name, sub in subdomain_map.items():
            ips = resolved.get(name, sub.ip_addresses)
            final[name] = Subdomain(
                target_domain=sub.target_domain,
                subdomain=name,
                ip_addresses=ips,
                source=sub.source,
                first_seen=sub.first_seen,
                last_seen=now if ips else sub.last_seen,
            )

        # Add newly discovered subdomains from prefix brute-force
        for name in prefix_candidates:
            if name in resolved and name not in final:
                final[name] = Subdomain(
                    target_domain=domain,
                    subdomain=name,
                    ip_addresses=resolved[name],
                    source=self.name,
                    first_seen=now,
                    last_seen=now,
                )

        return AssetSnapshot(target_domain=domain, subdomains=list(final.values()))

    async def _resolve(self, name: str) -> list[str]:
        """Resolve a hostname to IPv4 addresses. Returns [] on any failure."""
        async with self._sem:
            try:
                answers = await asyncio.wait_for(
                    dns.asyncresolver.resolve(name, "A"),
                    timeout=5.0,
                )
                return [str(rdata) for rdata in answers]
            except (
                dns.exception.DNSException,
                asyncio.TimeoutError,
                Exception,
            ):
                return []
