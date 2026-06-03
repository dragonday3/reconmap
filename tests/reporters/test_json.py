import json
import pytest
from datetime import datetime, timezone

from reconmap.reporters.json_reporter import JSONReporter
from reconmap.models.asset import AssetSnapshot, Change, Subdomain, Port, SecretLeak


def make_snapshot(**kwargs) -> AssetSnapshot:
    defaults = {"target_domain": "example.com"}
    defaults.update(kwargs)
    return AssetSnapshot(**defaults)


def make_change(**kwargs) -> Change:
    defaults = {
        "target_domain": "example.com",
        "snapshot_id": "snap-001",
        "change_type": "new_subdomain",
        "severity": "medium",
        "asset_type": "subdomain",
        "asset_key": "sub.example.com",
    }
    defaults.update(kwargs)
    return Change(**defaults)


def make_subdomain(**kwargs) -> Subdomain:
    defaults = {
        "target_domain": "example.com",
        "subdomain": "api.example.com",
        "ip_addresses": ["1.2.3.4"],
        "source": "certstream",
    }
    defaults.update(kwargs)
    return Subdomain(**defaults)


class TestJSONReporter:
    def test_generate_returns_dict_with_snapshot_id(self):
        reporter = JSONReporter()
        snapshot = make_snapshot()
        result = reporter.generate(snapshot)
        assert isinstance(result, dict)
        assert "snapshot_id" in result

    def test_generate_output_is_json_serializable(self):
        reporter = JSONReporter()
        snapshot = make_snapshot()
        result = reporter.generate(snapshot)
        # Should not raise
        serialized = json.dumps(result)
        assert isinstance(serialized, str)

    def test_generate_changes_empty_list(self):
        reporter = JSONReporter()
        result = reporter.generate_changes([])
        assert result == []

    def test_generate_changes_single_change_has_correct_keys(self):
        reporter = JSONReporter()
        change = make_change()
        result = reporter.generate_changes([change])
        assert len(result) == 1
        item = result[0]
        assert "change_type" in item
        assert "severity" in item
        assert "asset_key" in item
        assert item["change_type"] == "new_subdomain"
        assert item["severity"] == "medium"

    def test_write_creates_file_with_valid_json(self, tmp_path):
        reporter = JSONReporter()
        snapshot = make_snapshot()
        out = str(tmp_path / "output.json")
        reporter.write(snapshot, out)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert "snapshot_id" in data
        assert data["target_domain"] == "example.com"

    def test_write_changes_creates_file_with_valid_json(self, tmp_path):
        reporter = JSONReporter()
        changes = [make_change(), make_change(change_type="new_port", severity="high", asset_type="port", asset_key="1.2.3.4:80")]
        out = str(tmp_path / "changes.json")
        reporter.write_changes(changes, out)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_snapshot_with_subdomains_serialized_correctly(self):
        reporter = JSONReporter()
        sub = make_subdomain()
        snapshot = make_snapshot(subdomains=[sub])
        result = reporter.generate(snapshot)
        assert "subdomains" in result
        assert len(result["subdomains"]) == 1
        assert result["subdomains"][0]["subdomain"] == "api.example.com"
        assert result["subdomains"][0]["ip_addresses"] == ["1.2.3.4"]

    def test_round_trip_model_validate(self):
        reporter = JSONReporter()
        sub = make_subdomain()
        snapshot = make_snapshot(subdomains=[sub])
        serialized = reporter.generate(snapshot)
        restored = AssetSnapshot.model_validate(serialized)
        assert restored.snapshot_id == snapshot.snapshot_id
        assert restored.target_domain == snapshot.target_domain
        assert len(restored.subdomains) == 1
        assert restored.subdomains[0].subdomain == sub.subdomain
