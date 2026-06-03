"""GitHub code search collector — finds secrets and hardcoded endpoints."""
import asyncio
import logging
import re

import httpx

from reconmap.collectors.base import BaseCollector
from reconmap.models.asset import AssetSnapshot, SecretLeak

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt":          re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key":  re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "api_key":      re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
    "password":     re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']'),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
}


def _redact(match: str) -> str:
    """Show first 4 chars + **** to avoid logging full secrets."""
    if len(match) <= 4:
        return "****"
    return match[:4] + "****"


class GitHubCollector(BaseCollector):
    name = "github"
    requires_key = False  # token optional; rate limit lower without it

    def __init__(self, token: str | None = None):
        self._token = token

    def is_available(self) -> bool:
        return True  # works without token (lower rate limit)

    def _headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github.v3.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"token {self._token}"
        return headers

    async def collect(self, domain: str) -> AssetSnapshot:
        leaks: list[SecretLeak] = []
        try:
            async with httpx.AsyncClient(timeout=15.0, headers=self._headers()) as client:
                leaks = await self._search(client, domain)
        except Exception as exc:
            logger.warning("GitHub collector error for %s: %s", domain, exc)
        return AssetSnapshot(target_domain=domain, leaks=leaks)

    async def _search(self, client: httpx.AsyncClient, domain: str) -> list[SecretLeak]:
        leaks: list[SecretLeak] = []
        params = {"q": domain, "per_page": 30}
        try:
            response = await client.get(GITHUB_SEARCH_URL, params=params)
        except httpx.TimeoutException:
            logger.warning("GitHub search timeout for %s", domain)
            return []

        if response.status_code == 403:
            logger.warning("GitHub search forbidden for %s (rate limit or token issue)", domain)
            return []
        if response.status_code == 429:
            logger.warning("GitHub search rate limited for %s", domain)
            return []
        if response.status_code != 200:
            logger.warning("GitHub search returned %s for %s", response.status_code, domain)
            return []

        try:
            data = response.json()
        except Exception as exc:
            logger.warning("GitHub search JSON parse error for %s: %s", domain, exc)
            return []

        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            for match_info in item.get("text_matches", []):
                fragment = match_info.get("fragment", "")
                for secret_type, pattern in SECRET_PATTERNS.items():
                    m = pattern.search(fragment)
                    if m:
                        raw = m.group(0)
                        leaks.append(SecretLeak(
                            target_domain=domain,
                            repo=repo,
                            file_path=file_path,
                            line_number=0,
                            secret_type=secret_type,
                            raw_match=_redact(raw),
                            html_url=html_url,
                            source=self.name,
                        ))

        return leaks
