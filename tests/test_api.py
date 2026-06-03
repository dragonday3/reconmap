"""Tests for the FastAPI REST API endpoints."""
import pytest
import httpx
from fastapi import status
from unittest.mock import AsyncMock, patch

from reconmap.api.app import app, get_storage
from reconmap.models.asset import AssetSnapshot, TargetDomain, Change, Subdomain, Port
from reconmap.storage.db import Storage
from reconmap.engine.scanner import Scanner
from reconmap import __version__


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def client():
    """AsyncClient backed by in-memory SQLite storage via dependency override."""
    storage = Storage(db_url="sqlite+aiosqlite:///:memory:")
    await storage.init()

    async def override():
        yield storage

    app.dependency_overrides[get_storage] = override

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c

    app.dependency_overrides.clear()
    await storage.close()


@pytest.fixture
async def storage():
    """Standalone in-memory storage for tests that need direct access."""
    s = Storage(db_url="sqlite+aiosqlite:///:memory:")
    await s.init()
    yield s
    await s.close()


@pytest.fixture
async def client_with_storage():
    """Returns (client, storage) tuple for tests that need to pre-seed data."""
    s = Storage(db_url="sqlite+aiosqlite:///:memory:")
    await s.init()

    async def override():
        yield s

    app.dependency_overrides[get_storage] = override

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c, s

    app.dependency_overrides.clear()
    await s.close()


# ---------------------------------------------------------------------------
# Test 1: GET /health
# ---------------------------------------------------------------------------

async def test_health_returns_ok(client):
    response = await client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


# ---------------------------------------------------------------------------
# Test 2: POST /targets → 201, returns TargetDomain
# ---------------------------------------------------------------------------

async def test_add_target_returns_201(client):
    response = await client.post("/targets", json={"domain": "example.com"})
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["domain"] == "example.com"


# ---------------------------------------------------------------------------
# Test 3: GET /targets → 200, returns list (empty initially)
# ---------------------------------------------------------------------------

async def test_list_targets_empty(client):
    response = await client.get("/targets")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


# ---------------------------------------------------------------------------
# Test 4: POST /targets then GET /targets → domain appears in list
# ---------------------------------------------------------------------------

async def test_add_target_then_list(client):
    await client.post("/targets", json={"domain": "example.com"})
    response = await client.get("/targets")
    assert response.status_code == status.HTTP_200_OK
    domains = [t["domain"] for t in response.json()]
    assert "example.com" in domains


# ---------------------------------------------------------------------------
# Test 5: GET /targets/{domain}/snapshots → 200, empty list initially
# ---------------------------------------------------------------------------

async def test_list_snapshots_empty(client):
    response = await client.get("/targets/example.com/snapshots")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


# ---------------------------------------------------------------------------
# Test 6: GET /targets/{domain}/snapshots/latest → 404 when no snapshots
# ---------------------------------------------------------------------------

async def test_get_latest_snapshot_404_when_empty(client):
    response = await client.get("/targets/example.com/snapshots/latest")
    assert response.status_code == status.HTTP_404_NOT_FOUND


# ---------------------------------------------------------------------------
# Test 7: GET /targets/{domain}/snapshots/latest → 200 after scan
# ---------------------------------------------------------------------------

async def test_get_latest_snapshot_after_scan(client):
    mock_snap = AssetSnapshot(target_domain="example.com")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
        await client.post("/targets/example.com/scan")
    response = await client.get("/targets/example.com/snapshots/latest")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["target_domain"] == "example.com"


# ---------------------------------------------------------------------------
# Test 8: GET /targets/{domain}/changes → 200, empty list initially
# ---------------------------------------------------------------------------

async def test_list_changes_empty(client):
    response = await client.get("/targets/example.com/changes")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


# ---------------------------------------------------------------------------
# Test 9: POST /targets/{domain}/scan → 201, returns snapshot (mock Scanner)
# ---------------------------------------------------------------------------

async def test_scan_creates_snapshot(client):
    mock_snap = AssetSnapshot(target_domain="example.com")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
        response = await client.post("/targets/example.com/scan")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["target_domain"] == "example.com"
    assert "snapshot_id" in data


# ---------------------------------------------------------------------------
# Test 10: POST /targets/{domain}/scan twice → second scan computes diff, changes stored
# ---------------------------------------------------------------------------

async def test_scan_twice_produces_changes(client):
    snap1 = AssetSnapshot(
        target_domain="example.com",
        subdomains=[
            Subdomain(
                target_domain="example.com",
                subdomain="api.example.com",
                source="certstream",
            )
        ],
    )
    snap2 = AssetSnapshot(
        target_domain="example.com",
        subdomains=[
            Subdomain(
                target_domain="example.com",
                subdomain="api.example.com",
                source="certstream",
            ),
            Subdomain(
                target_domain="example.com",
                subdomain="new.example.com",
                source="certstream",
            ),
        ],
    )
    with patch.object(Scanner, "run", new=AsyncMock(return_value=snap1)):
        await client.post("/targets/example.com/scan")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=snap2)):
        await client.post("/targets/example.com/scan")

    response = await client.get("/targets/example.com/changes")
    assert response.status_code == status.HTTP_200_OK
    changes = response.json()
    assert len(changes) >= 1
    change_types = [c["change_type"] for c in changes]
    assert "new_subdomain" in change_types


# ---------------------------------------------------------------------------
# Test 11: GET /targets/{domain}/snapshots returns snapshots after scan
# ---------------------------------------------------------------------------

async def test_list_snapshots_after_scan(client):
    mock_snap = AssetSnapshot(target_domain="example.com")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
        await client.post("/targets/example.com/scan")
    response = await client.get("/targets/example.com/snapshots")
    assert response.status_code == status.HTTP_200_OK
    snapshots = response.json()
    assert len(snapshots) == 1
    assert snapshots[0]["target_domain"] == "example.com"


# ---------------------------------------------------------------------------
# Test 12: GET /targets/{domain}/changes returns changes after second scan
# ---------------------------------------------------------------------------

async def test_list_changes_after_two_scans(client):
    snap1 = AssetSnapshot(
        target_domain="example.com",
        ports=[Port(ip="1.2.3.4", port=80, source="shodan")],
    )
    snap2 = AssetSnapshot(
        target_domain="example.com",
        ports=[
            Port(ip="1.2.3.4", port=80, source="shodan"),
            Port(ip="1.2.3.4", port=443, source="shodan"),
        ],
    )
    with patch.object(Scanner, "run", new=AsyncMock(return_value=snap1)):
        await client.post("/targets/example.com/scan")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=snap2)):
        await client.post("/targets/example.com/scan")

    response = await client.get("/targets/example.com/changes")
    assert response.status_code == status.HTTP_200_OK
    changes = response.json()
    assert len(changes) >= 1
    assert any(c["change_type"] == "new_port" for c in changes)


# ---------------------------------------------------------------------------
# Test 13: GET /targets/{domain}/snapshots?limit=1 → respects limit
# ---------------------------------------------------------------------------

async def test_list_snapshots_respects_limit(client):
    snap1 = AssetSnapshot(target_domain="example.com")
    snap2 = AssetSnapshot(target_domain="example.com")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=snap1)):
        await client.post("/targets/example.com/scan")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=snap2)):
        await client.post("/targets/example.com/scan")

    response = await client.get("/targets/example.com/snapshots?limit=1")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 1


# ---------------------------------------------------------------------------
# Test 14: POST /targets duplicate domain → no error (201 or 200)
# ---------------------------------------------------------------------------

async def test_add_duplicate_target_no_error(client):
    r1 = await client.post("/targets", json={"domain": "example.com"})
    r2 = await client.post("/targets", json={"domain": "example.com"})
    assert r1.status_code == status.HTTP_201_CREATED
    assert r2.status_code == status.HTTP_201_CREATED


# ---------------------------------------------------------------------------
# Test 15: Version in /health matches reconmap.__version__
# ---------------------------------------------------------------------------

async def test_health_version_matches_package_version(client):
    response = await client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["version"] == __version__


# ---------------------------------------------------------------------------
# Test 16: Scan auto-creates target in /targets list
# ---------------------------------------------------------------------------

async def test_scan_auto_registers_target(client):
    mock_snap = AssetSnapshot(target_domain="newdomain.com")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
        await client.post("/targets/newdomain.com/scan")
    response = await client.get("/targets")
    domains = [t["domain"] for t in response.json()]
    assert "newdomain.com" in domains


# ---------------------------------------------------------------------------
# Test 17: GET /targets/{domain}/snapshots limit query param validation (max 100)
# ---------------------------------------------------------------------------

async def test_list_snapshots_limit_out_of_range(client):
    response = await client.get("/targets/example.com/snapshots?limit=999")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ---------------------------------------------------------------------------
# Test 18: Snapshot returned from scan contains correct snapshot_id roundtrip
# ---------------------------------------------------------------------------

async def test_scan_snapshot_id_in_db(client):
    mock_snap = AssetSnapshot(target_domain="example.com")
    with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
        scan_resp = await client.post("/targets/example.com/scan")
    snap_id_from_api = scan_resp.json()["snapshot_id"]

    list_resp = await client.get("/targets/example.com/snapshots")
    snap_ids = [s["snapshot_id"] for s in list_resp.json()]
    assert snap_id_from_api in snap_ids
