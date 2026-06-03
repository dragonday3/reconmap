import json
import logging
import os
import re
from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, MetaData, String, Table, Text,
    delete, insert, select, text,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from reconmap.models.asset import AssetSnapshot, Change, TargetDomain

logger = logging.getLogger(__name__)

metadata = MetaData()

targets_table = Table(
    "targets",
    metadata,
    Column("domain", String, primary_key=True),
    Column("tags", Text, default="[]"),       # JSON array stored as text
    Column("created_at", String, nullable=False),
)

snapshots_table = Table(
    "snapshots",
    metadata,
    Column("snapshot_id", String, primary_key=True),
    Column("target_domain", String, nullable=False),
    Column("timestamp", String, nullable=False),
    Column("data", Text, nullable=False),      # Full AssetSnapshot JSON
)

changes_table = Table(
    "changes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("target_domain", String, nullable=False),
    Column("snapshot_id", String, nullable=False),
    Column("timestamp", String, nullable=False),
    Column("change_type", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("asset_type", String, nullable=False),
    Column("asset_key", String, nullable=False),
    Column("details", Text, nullable=False),   # JSON
)


def _parse_dt(s: str) -> datetime:
    """Parse ISO datetime string, handling both naive and aware formats.

    Python 3.10's fromisoformat does not handle the '+00:00' timezone suffix
    that comes from datetime.isoformat() on timezone-aware datetimes.
    This helper normalises both cases.
    """
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        # Fallback for Python 3.10 with +00:00 timezone suffix
        s_clean = re.sub(r'\+00:00$', '', s)
        dt = datetime.fromisoformat(s_clean)
        return dt.replace(tzinfo=timezone.utc)


def _get_db_url() -> str:
    """Get database URL from DATABASE_URL env var or default to SQLite."""
    url = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./reconmap.db")
    return url


class Storage:
    def __init__(self, db_url: str | None = None):
        url = db_url or _get_db_url()
        self._engine: AsyncEngine = create_async_engine(url, echo=False)

    async def init(self) -> None:
        """Create all tables if they don't exist."""
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def close(self) -> None:
        """Dispose engine connections."""
        await self._engine.dispose()

    # --- Targets ---

    async def add_target(self, target: TargetDomain) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(targets_table).prefix_with("OR IGNORE").values(
                    domain=target.domain,
                    tags=json.dumps(target.tags),
                    created_at=target.created_at.isoformat(),
                )
            )

    async def list_targets(self) -> list[TargetDomain]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(select(targets_table))
            return [
                TargetDomain(
                    domain=row.domain,
                    tags=json.loads(row.tags or "[]"),
                    created_at=_parse_dt(row.created_at),
                )
                for row in rows
            ]

    # --- Snapshots ---

    async def save_snapshot(self, snapshot: AssetSnapshot) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(snapshots_table).values(
                    snapshot_id=snapshot.snapshot_id,
                    target_domain=snapshot.target_domain,
                    timestamp=snapshot.timestamp.isoformat(),
                    data=snapshot.model_dump_json(),
                )
            )

    async def get_snapshots(self, domain: str, limit: int = 10) -> list[AssetSnapshot]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                select(snapshots_table)
                .where(snapshots_table.c.target_domain == domain)
                .order_by(snapshots_table.c.timestamp.desc())
                .limit(limit)
            )
            return [AssetSnapshot.model_validate_json(row.data) for row in rows]

    async def get_latest_snapshot(self, domain: str) -> AssetSnapshot | None:
        snapshots = await self.get_snapshots(domain, limit=1)
        return snapshots[0] if snapshots else None

    # --- Changes ---

    async def save_changes(self, changes: list[Change]) -> None:
        if not changes:
            return
        async with self._engine.begin() as conn:
            for change in changes:
                await conn.execute(
                    insert(changes_table).values(
                        target_domain=change.target_domain,
                        snapshot_id=change.snapshot_id,
                        timestamp=change.timestamp.isoformat(),
                        change_type=change.change_type,
                        severity=change.severity,
                        asset_type=change.asset_type,
                        asset_key=change.asset_key,
                        details=json.dumps(change.details),
                    )
                )

    async def get_changes(self, domain: str, limit: int = 50) -> list[Change]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                select(changes_table)
                .where(changes_table.c.target_domain == domain)
                .order_by(changes_table.c.timestamp.desc())
                .limit(limit)
            )
            return [
                Change(
                    target_domain=row.target_domain,
                    snapshot_id=row.snapshot_id,
                    timestamp=_parse_dt(row.timestamp),
                    change_type=row.change_type,
                    severity=row.severity,
                    asset_type=row.asset_type,
                    asset_key=row.asset_key,
                    details=json.loads(row.details or "{}"),
                )
                for row in rows
            ]
