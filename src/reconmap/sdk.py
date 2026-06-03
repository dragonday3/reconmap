import asyncio
from reconmap.engine.scanner import Scanner
from reconmap.engine.diff import DiffEngine
from reconmap.storage.db import Storage
from reconmap.models.asset import AssetSnapshot, Change, TargetDomain


class ReconMap:
    """High-level SDK for programmatic access to reconmap."""

    def __init__(
        self,
        shodan_key: str | None = None,
        github_token: str | None = None,
        db_url: str | None = None,
    ):
        self._scanner = Scanner(shodan_key=shodan_key, github_token=github_token)
        self._diff = DiffEngine()
        self._storage = Storage(db_url=db_url)
        self._initialized = False

    async def _ensure_init(self) -> None:
        if not self._initialized:
            await self._storage.init()
            self._initialized = True

    async def scan(self, domain: str) -> AssetSnapshot:
        """Run passive scan, persist snapshot, return result."""
        await self._ensure_init()
        snapshot = await self._scanner.run(domain)
        await self._storage.save_snapshot(snapshot)
        await self._storage.add_target(TargetDomain(domain=domain))
        return snapshot

    async def diff(self, domain: str) -> list[Change]:
        """Diff latest two snapshots for domain. Returns [] if < 2 snapshots."""
        await self._ensure_init()
        snapshots = await self._storage.get_snapshots(domain, limit=2)
        if len(snapshots) < 2:
            return []
        # get_snapshots returns newest first, so index 0 = after, index 1 = before
        return self._diff.diff(before=snapshots[1], after=snapshots[0])

    async def get_changes(self, domain: str, limit: int = 50) -> list[Change]:
        """Retrieve stored changes from DB."""
        await self._ensure_init()
        return await self._storage.get_changes(domain, limit=limit)

    async def close(self) -> None:
        await self._storage.close()
