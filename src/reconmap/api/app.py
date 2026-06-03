from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query

from reconmap.models.asset import AssetSnapshot, Change, TargetDomain
from reconmap.storage.db import Storage
from reconmap.engine.scanner import Scanner
from reconmap.engine.diff import DiffEngine
from reconmap import __version__


def _make_storage() -> Storage:
    return Storage()


async def get_storage() -> Storage:
    storage = _make_storage()
    await storage.init()
    try:
        yield storage
    finally:
        await storage.close()


StorageDep = Annotated[Storage, Depends(get_storage)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure DB tables exist
    storage = _make_storage()
    await storage.init()
    await storage.close()
    yield


app = FastAPI(
    title="reconmap",
    description="Passive Attack Surface Intelligence Platform",
    version=__version__,
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {"status": "ok", "version": __version__}


@app.post("/targets", response_model=TargetDomain, status_code=201)
async def add_target(target: TargetDomain, storage: StorageDep):
    await storage.add_target(target)
    return target


@app.get("/targets", response_model=list[TargetDomain])
async def list_targets(storage: StorageDep):
    return await storage.list_targets()


@app.get("/targets/{domain}/snapshots/latest", response_model=AssetSnapshot)
async def get_latest_snapshot(domain: str, storage: StorageDep):
    snapshot = await storage.get_latest_snapshot(domain)
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"No snapshots found for {domain}")
    return snapshot


@app.get("/targets/{domain}/snapshots", response_model=list[AssetSnapshot])
async def list_snapshots(
    domain: str,
    storage: StorageDep,
    limit: int = Query(10, ge=1, le=100),
):
    return await storage.get_snapshots(domain, limit=limit)


@app.post("/targets/{domain}/scan", response_model=AssetSnapshot, status_code=201)
async def scan_target(
    domain: str,
    storage: StorageDep,
    github_token: str | None = Query(None),
):
    """Trigger a passive scan for the domain. Saves snapshot and changes to DB."""
    scanner = Scanner(github_token=github_token)
    snapshot = await scanner.run(domain)

    # Compute diff vs latest snapshot
    previous = await storage.get_latest_snapshot(domain)
    if previous:
        diff_engine = DiffEngine()
        changes = diff_engine.diff(previous, snapshot)
        await storage.save_changes(changes)

    await storage.save_snapshot(snapshot)

    # Ensure target exists
    await storage.add_target(TargetDomain(domain=domain))

    return snapshot


@app.get("/targets/{domain}/changes", response_model=list[Change])
async def list_changes(
    domain: str,
    storage: StorageDep,
    limit: int = Query(50, ge=1, le=500),
):
    return await storage.get_changes(domain, limit=limit)
