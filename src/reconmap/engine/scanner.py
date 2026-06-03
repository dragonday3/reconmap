import asyncio
import logging

from reconmap.collectors.base import BaseCollector
from reconmap.collectors.certstream import CertStreamCollector
from reconmap.collectors.shodan import ShodanCollector
from reconmap.collectors.github import GitHubCollector
from reconmap.collectors.dns_resolver import DNSResolverCollector
from reconmap.models.asset import AssetSnapshot, Subdomain, Port, SecretLeak

logger = logging.getLogger(__name__)


class Scanner:
    """Orchestrates all collectors for a domain. Returns a merged AssetSnapshot."""

    def __init__(
        self,
        github_token: str | None = None,
        shodan_key: str | None = None,
        collectors: list[BaseCollector] | None = None,
    ):
        if collectors is not None:
            self._collectors = collectors
        else:
            self._collectors = [
                CertStreamCollector(),
                ShodanCollector(),
                GitHubCollector(token=github_token),
                DNSResolverCollector(),
            ]

    async def run(self, domain: str) -> AssetSnapshot:
        """Run all collectors and merge results into a single AssetSnapshot."""
        # Step 1: Run CertStream + Shodan + GitHub concurrently
        passive_collectors = [c for c in self._collectors if not isinstance(c, DNSResolverCollector)]
        dns_collectors = [c for c in self._collectors if isinstance(c, DNSResolverCollector)]

        passive_tasks = [c.collect(domain) for c in passive_collectors]
        passive_snapshots = await asyncio.gather(*passive_tasks, return_exceptions=True)

        partial_snapshots = []
        for result in passive_snapshots:
            if isinstance(result, AssetSnapshot):
                partial_snapshots.append(result)
            elif isinstance(result, Exception):
                logger.warning("Collector failed: %s", result)

        # Merge passive results
        merged = self._merge(domain, partial_snapshots)

        # Step 2: Run DNS resolver with discovered subdomains as input
        for dns_collector in dns_collectors:
            try:
                dns_snapshot = await dns_collector.collect(domain, existing_subdomains=merged.subdomains)
                # Merge DNS results back in
                merged = self._merge(domain, [merged, dns_snapshot])
            except Exception as exc:
                logger.warning("DNS collector failed: %s", exc)

        return merged

    def _merge(self, domain: str, snapshots: list[AssetSnapshot]) -> AssetSnapshot:
        """
        Merge multiple partial AssetSnapshots into one.
        - Subdomains: dedup by subdomain name; union of ip_addresses; keep earliest first_seen, latest last_seen
        - Ports: dedup by (ip, port); keep first occurrence
        - Leaks: dedup by (repo, file_path, line_number)
        """
        subdomain_map: dict[str, Subdomain] = {}
        port_map: dict[tuple, Port] = {}
        leak_set: set[tuple] = set()
        leaks: list[SecretLeak] = []

        for snap in snapshots:
            for sub in snap.subdomains:
                key = sub.subdomain
                if key in subdomain_map:
                    existing = subdomain_map[key]
                    merged_ips = list(set(existing.ip_addresses) | set(sub.ip_addresses))
                    subdomain_map[key] = Subdomain(
                        target_domain=existing.target_domain,
                        subdomain=existing.subdomain,
                        ip_addresses=merged_ips,
                        source=existing.source,
                        first_seen=min(existing.first_seen, sub.first_seen),
                        last_seen=max(existing.last_seen, sub.last_seen),
                    )
                else:
                    subdomain_map[key] = sub

            for port in snap.ports:
                key = (port.ip, port.port)
                if key not in port_map:
                    port_map[key] = port

            for leak in snap.leaks:
                key = (leak.repo, leak.file_path, leak.line_number)
                if key not in leak_set:
                    leak_set.add(key)
                    leaks.append(leak)

        return AssetSnapshot(
            target_domain=domain,
            subdomains=list(subdomain_map.values()),
            ports=list(port_map.values()),
            leaks=leaks,
        )
