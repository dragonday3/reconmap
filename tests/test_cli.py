import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from typer.testing import CliRunner

from reconmap.cli import app
from reconmap.engine.scanner import Scanner
from reconmap.storage.db import Storage
from reconmap.models.asset import (
    AssetSnapshot, SecretLeak, Subdomain, Port,
)

runner = CliRunner()


def make_snapshot(leaks=None, subdomains=None, ports=None, **kwargs) -> AssetSnapshot:
    return AssetSnapshot(
        target_domain="example.com",
        leaks=leaks or [],
        subdomains=subdomains or [],
        ports=ports or [],
        **kwargs,
    )


def make_leak() -> SecretLeak:
    return SecretLeak(
        target_domain="example.com",
        repo="acme/infra",
        file_path=".env",
        secret_type="AWS_SECRET",
        raw_match="AKIAIOSFODNN7EXAMPLE",
    )


class TestCLIHelp:
    def test_help_exits_zero(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_scan_help_exits_zero(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0


class TestScanCommand:
    def test_scan_no_leaks_exits_zero(self):
        mock_snap = make_snapshot()
        with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
            result = runner.invoke(app, ["scan", "example.com", "--quiet"])
        assert result.exit_code == 0

    def test_scan_with_leaks_exits_one(self):
        leak = make_leak()
        mock_snap = make_snapshot(leaks=[leak])
        with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
            result = runner.invoke(app, ["scan", "example.com", "--quiet"])
        assert result.exit_code == 1

    def test_scan_json_output_valid(self):
        mock_snap = make_snapshot()
        with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
            result = runner.invoke(app, ["scan", "example.com", "--output", "json", "--quiet"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "snapshot" in data
        assert "changes" in data

    def test_scan_html_output_contains_doctype(self):
        mock_snap = make_snapshot()
        with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
            result = runner.invoke(app, ["scan", "example.com", "--output", "html", "--quiet"])
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

    def test_scan_out_file_creates_file(self, tmp_path):
        mock_snap = make_snapshot()
        out = str(tmp_path / "result.json")
        with patch.object(Scanner, "run", new=AsyncMock(return_value=mock_snap)):
            result = runner.invoke(app, ["scan", "example.com", "--output", "json", "--out-file", out, "--quiet"])
        assert result.exit_code == 0
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert "snapshot" in data


class TestDiffCommand:
    def test_diff_less_than_two_snapshots_exits_zero(self):
        """diff exits 0 when fewer than 2 snapshots exist (nothing to diff)."""
        async def mock_init(self):
            pass

        async def mock_close(self):
            pass

        async def mock_get_snapshots(self, domain, limit=2):
            return []

        with patch.object(Storage, "init", mock_init), \
             patch.object(Storage, "close", mock_close), \
             patch.object(Storage, "get_snapshots", mock_get_snapshots):
            result = runner.invoke(app, ["diff", "example.com", "--quiet"])
        assert result.exit_code == 0

    def test_diff_with_high_severity_change_exits_one(self):
        """diff exits 1 when a high-severity change is found."""
        from reconmap.models.asset import Change

        snap1 = make_snapshot()
        snap2 = make_snapshot(
            ports=[Port(ip="1.2.3.4", port=22, source="shodan")]
        )

        high_change = Change(
            target_domain="example.com",
            snapshot_id=snap2.snapshot_id,
            change_type="new_port",
            severity="high",
            asset_type="port",
            asset_key="1.2.3.4:22",
        )

        async def mock_init(self):
            pass

        async def mock_close(self):
            pass

        async def mock_get_snapshots(self, domain, limit=2):
            return [snap2, snap1]

        from reconmap.engine.diff import DiffEngine

        with patch.object(Storage, "init", mock_init), \
             patch.object(Storage, "close", mock_close), \
             patch.object(Storage, "get_snapshots", mock_get_snapshots), \
             patch.object(DiffEngine, "diff", return_value=[high_change]):
            result = runner.invoke(app, ["diff", "example.com", "--quiet"])
        assert result.exit_code == 1
