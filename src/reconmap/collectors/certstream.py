import logging
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

import httpx

from reconmap.collectors.base import BaseCollector
from reconmap.models.asset import AssetSnapshot, Subdomain

logger = logging.getLogger(__name__)


class CertStreamCollector(BaseCollector):
    name = "certstream"
    requires_key = False

    async def collect(self, domain: str) -> AssetSnapshot:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    logger.warning(
                        "crt.sh returned %s for %s", response.status_code, domain
                    )
                    return AssetSnapshot(target_domain=domain)
                try:
                    data = response.json()
                except Exception as exc:
                    logger.warning("crt.sh JSON parse error for %s: %s", domain, exc)
                    return AssetSnapshot(target_domain=domain)
        except httpx.TimeoutException:
            logger.warning("crt.sh timeout for %s", domain)
            return AssetSnapshot(target_domain=domain)
        except Exception as exc:
            logger.warning("crt.sh error for %s: %s", domain, exc)
            return AssetSnapshot(target_domain=domain)

        # Parse entries: build dict[subdomain_name -> (first_seen_dt, last_seen_dt)]
        seen: dict[str, tuple[datetime, datetime]] = {}

        for entry in data:
            raw_not_before = entry.get("not_before", "")
            try:
                dt = dateutil_parser.parse(raw_not_before)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception as exc:
                logger.debug("Failed to parse date %r: %s", raw_not_before, exc)
                dt = datetime.now(timezone.utc)

            for name in entry.get("name_value", "").split("\n"):
                name = name.strip()
                if name.startswith("*."):
                    name = name[2:]
                if not name:
                    continue
                if name != domain and not name.endswith(f".{domain}"):
                    continue
                if name in seen:
                    first_seen, last_seen = seen[name]
                    seen[name] = (min(first_seen, dt), max(last_seen, dt))
                else:
                    seen[name] = (dt, dt)

        subdomains = [
            Subdomain(
                target_domain=domain,
                subdomain=name,
                source=self.name,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            for name, (first_seen, last_seen) in seen.items()
        ]

        return AssetSnapshot(target_domain=domain, subdomains=subdomains)
