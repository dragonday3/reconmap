import json
from datetime import datetime
from typing import Literal

import pytest
from pydantic import ValidationError

from reconmap.models import (
    AssetSnapshot,
    Change,
    ChangeType,
    Port,
    SecretLeak,
    SeverityLevel,
    Subdomain,
    TargetDomain,
)


class TestTargetDomain:
    """Tests for TargetDomain model."""

    def test_target_domain_constructs_with_domain_only(self):
        """TargetDomain should construct with just domain=."""
        domain = TargetDomain(domain="example.com")
        assert domain.domain == "example.com"

    def test_target_domain_tags_defaults_to_empty_list(self):
        """TargetDomain.tags should default to empty list."""
        domain = TargetDomain(domain="example.com")
        assert domain.tags == []
        assert isinstance(domain.tags, list)

    def test_target_domain_created_at_auto_populated(self):
        """TargetDomain.created_at should auto-populate as datetime."""
        domain = TargetDomain(domain="example.com")
        assert isinstance(domain.created_at, datetime)
        assert domain.created_at is not None

    def test_target_domain_with_tags(self):
        """TargetDomain should accept tags."""
        domain = TargetDomain(domain="example.com", tags=["web", "api"])
        assert domain.tags == ["web", "api"]

    def test_target_domain_model_dump(self):
        """TargetDomain.model_dump() should produce expected keys."""
        domain = TargetDomain(domain="example.com")
        dumped = domain.model_dump()
        assert "domain" in dumped
        assert "tags" in dumped
        assert "created_at" in dumped
        assert dumped["domain"] == "example.com"


class TestSubdomain:
    """Tests for Subdomain model."""

    def test_subdomain_constructs_with_required_fields(self):
        """Subdomain should construct with required fields."""
        sub = Subdomain(
            target_domain="example.com",
            subdomain="api.example.com",
            source="amass",
        )
        assert sub.target_domain == "example.com"
        assert sub.subdomain == "api.example.com"
        assert sub.source == "amass"

    def test_subdomain_ip_addresses_defaults_to_empty_list(self):
        """Subdomain.ip_addresses should default to empty list."""
        sub = Subdomain(
            target_domain="example.com",
            subdomain="api.example.com",
            source="amass",
        )
        assert sub.ip_addresses == []
        assert isinstance(sub.ip_addresses, list)

    def test_subdomain_with_ip_addresses(self):
        """Subdomain should accept ip_addresses."""
        sub = Subdomain(
            target_domain="example.com",
            subdomain="api.example.com",
            source="amass",
            ip_addresses=["192.168.1.1", "10.0.0.1"],
        )
        assert sub.ip_addresses == ["192.168.1.1", "10.0.0.1"]

    def test_subdomain_timestamps_auto_populated(self):
        """Subdomain first_seen and last_seen should auto-populate."""
        sub = Subdomain(
            target_domain="example.com",
            subdomain="api.example.com",
            source="amass",
        )
        assert isinstance(sub.first_seen, datetime)
        assert isinstance(sub.last_seen, datetime)

    def test_subdomain_model_dump(self):
        """Subdomain.model_dump() should produce expected keys."""
        sub = Subdomain(
            target_domain="example.com",
            subdomain="api.example.com",
            source="amass",
        )
        dumped = sub.model_dump()
        assert "target_domain" in dumped
        assert "subdomain" in dumped
        assert "ip_addresses" in dumped
        assert "source" in dumped
        assert "first_seen" in dumped
        assert "last_seen" in dumped


class TestPort:
    """Tests for Port model."""

    def test_port_constructs_with_required_fields(self):
        """Port should construct with required fields (ip, port, source)."""
        port = Port(ip="192.168.1.1", port=80, source="nmap")
        assert port.ip == "192.168.1.1"
        assert port.port == 80
        assert port.source == "nmap"

    def test_port_protocol_defaults_to_tcp(self):
        """Port.protocol should default to 'tcp'."""
        port = Port(ip="192.168.1.1", port=80, source="nmap")
        assert port.protocol == "tcp"

    def test_port_service_defaults_to_empty_string(self):
        """Port.service should default to empty string."""
        port = Port(ip="192.168.1.1", port=80, source="nmap")
        assert port.service == ""

    def test_port_banner_defaults_to_empty_string(self):
        """Port.banner should default to empty string."""
        port = Port(ip="192.168.1.1", port=80, source="nmap")
        assert port.banner == ""

    def test_port_with_optional_fields(self):
        """Port should accept optional fields."""
        port = Port(
            ip="192.168.1.1",
            port=443,
            source="nmap",
            protocol="tcp",
            service="https",
            banner="nginx/1.18.0",
        )
        assert port.protocol == "tcp"
        assert port.service == "https"
        assert port.banner == "nginx/1.18.0"

    def test_port_model_dump(self):
        """Port.model_dump() should produce expected keys."""
        port = Port(ip="192.168.1.1", port=80, source="nmap")
        dumped = port.model_dump()
        assert "ip" in dumped
        assert "port" in dumped
        assert "protocol" in dumped
        assert "service" in dumped
        assert "banner" in dumped
        assert "source" in dumped


class TestSecretLeak:
    """Tests for SecretLeak model."""

    def test_secret_leak_constructs_with_required_fields(self):
        """SecretLeak should construct with required fields."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            secret_type="api_key",
            source="github",
        )
        assert leak.target_domain == "example.com"
        assert leak.repo == "user/repo"
        assert leak.file_path == "src/config.py"
        assert leak.secret_type == "api_key"

    def test_secret_leak_source_defaults_to_github(self):
        """SecretLeak.source should default to 'github'."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            secret_type="api_key",
        )
        assert leak.source == "github"

    def test_secret_leak_line_number_defaults_to_zero(self):
        """SecretLeak.line_number should default to 0."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            secret_type="api_key",
        )
        assert leak.line_number == 0

    def test_secret_leak_raw_match_defaults_to_empty_string(self):
        """SecretLeak.raw_match should default to empty string."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            secret_type="api_key",
        )
        assert leak.raw_match == ""

    def test_secret_leak_html_url_defaults_to_empty_string(self):
        """SecretLeak.html_url should default to empty string."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            secret_type="api_key",
        )
        assert leak.html_url == ""

    def test_secret_leak_with_all_fields(self):
        """SecretLeak should accept all fields."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            line_number=42,
            secret_type="api_key",
            raw_match="api_key=sk_live_123",
            html_url="https://github.com/user/repo/blob/main/src/config.py#L42",
            source="github",
        )
        assert leak.line_number == 42
        assert leak.raw_match == "api_key=sk_live_123"
        assert leak.html_url == "https://github.com/user/repo/blob/main/src/config.py#L42"

    def test_secret_leak_model_dump(self):
        """SecretLeak.model_dump() should produce expected keys."""
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="src/config.py",
            secret_type="api_key",
        )
        dumped = leak.model_dump()
        assert "target_domain" in dumped
        assert "repo" in dumped
        assert "file_path" in dumped
        assert "line_number" in dumped
        assert "secret_type" in dumped
        assert "raw_match" in dumped
        assert "html_url" in dumped
        assert "source" in dumped


class TestAssetSnapshot:
    """Tests for AssetSnapshot model."""

    def test_asset_snapshot_constructs_with_target_domain_only(self):
        """AssetSnapshot should construct with just target_domain=."""
        snapshot = AssetSnapshot(target_domain="example.com")
        assert snapshot.target_domain == "example.com"

    def test_asset_snapshot_id_auto_generates_uuid(self):
        """AssetSnapshot.snapshot_id should auto-generate as UUID string."""
        snapshot = AssetSnapshot(target_domain="example.com")
        assert isinstance(snapshot.snapshot_id, str)
        assert len(snapshot.snapshot_id) == 36  # UUID4 string format
        assert snapshot.snapshot_id.count("-") == 4  # UUID format: 8-4-4-4-12

    def test_asset_snapshot_different_instances_different_ids(self):
        """Two separate AssetSnapshot instances should have different snapshot_id."""
        snapshot1 = AssetSnapshot(target_domain="example.com")
        snapshot2 = AssetSnapshot(target_domain="example.com")
        assert snapshot1.snapshot_id != snapshot2.snapshot_id

    def test_asset_snapshot_subdomains_defaults_to_empty_list(self):
        """AssetSnapshot.subdomains should default to empty list."""
        snapshot = AssetSnapshot(target_domain="example.com")
        assert snapshot.subdomains == []
        assert isinstance(snapshot.subdomains, list)

    def test_asset_snapshot_ports_defaults_to_empty_list(self):
        """AssetSnapshot.ports should default to empty list."""
        snapshot = AssetSnapshot(target_domain="example.com")
        assert snapshot.ports == []
        assert isinstance(snapshot.ports, list)

    def test_asset_snapshot_leaks_defaults_to_empty_list(self):
        """AssetSnapshot.leaks should default to empty list."""
        snapshot = AssetSnapshot(target_domain="example.com")
        assert snapshot.leaks == []
        assert isinstance(snapshot.leaks, list)

    def test_asset_snapshot_timestamp_auto_populated(self):
        """AssetSnapshot.timestamp should auto-populate as datetime."""
        snapshot = AssetSnapshot(target_domain="example.com")
        assert isinstance(snapshot.timestamp, datetime)

    def test_asset_snapshot_with_nested_assets(self):
        """AssetSnapshot should accept nested subdomains, ports, and leaks."""
        subdomain = Subdomain(
            target_domain="example.com",
            subdomain="api.example.com",
            source="amass",
        )
        port = Port(ip="192.168.1.1", port=80, source="nmap")
        leak = SecretLeak(
            target_domain="example.com",
            repo="user/repo",
            file_path="config.py",
            secret_type="api_key",
        )
        snapshot = AssetSnapshot(
            target_domain="example.com",
            subdomains=[subdomain],
            ports=[port],
            leaks=[leak],
        )
        assert len(snapshot.subdomains) == 1
        assert len(snapshot.ports) == 1
        assert len(snapshot.leaks) == 1

    def test_asset_snapshot_model_dump(self):
        """AssetSnapshot.model_dump() should produce expected keys."""
        snapshot = AssetSnapshot(target_domain="example.com")
        dumped = snapshot.model_dump()
        assert "target_domain" in dumped
        assert "snapshot_id" in dumped
        assert "timestamp" in dumped
        assert "subdomains" in dumped
        assert "ports" in dumped
        assert "leaks" in dumped

    def test_asset_snapshot_round_trip_validation(self):
        """AssetSnapshot should survive model_validate(model_dump()) round-trip."""
        original = AssetSnapshot(target_domain="example.com")
        dumped = original.model_dump()
        restored = AssetSnapshot.model_validate(dumped)
        assert original.target_domain == restored.target_domain
        assert original.snapshot_id == restored.snapshot_id
        assert original.subdomains == restored.subdomains
        assert original.ports == restored.ports
        assert original.leaks == restored.leaks

    def test_asset_snapshot_json_serializable(self):
        """AssetSnapshot.model_dump(mode='json') should be JSON-serializable."""
        snapshot = AssetSnapshot(target_domain="example.com")
        dumped = snapshot.model_dump(mode="json")
        json_str = json.dumps(dumped)  # Must not raise
        assert isinstance(json_str, str)
        assert len(json_str) > 0


class TestChange:
    """Tests for Change model."""

    def test_change_constructs_with_required_fields(self):
        """Change should construct with all required fields."""
        change = Change(
            target_domain="example.com",
            snapshot_id="12345",
            change_type="new_subdomain",
            severity="high",
            asset_type="subdomain",
            asset_key="api.example.com",
        )
        assert change.target_domain == "example.com"
        assert change.snapshot_id == "12345"
        assert change.change_type == "new_subdomain"
        assert change.severity == "high"
        assert change.asset_type == "subdomain"
        assert change.asset_key == "api.example.com"

    def test_change_type_rejects_invalid_literal(self):
        """Change.change_type should reject invalid literal."""
        with pytest.raises(ValidationError) as exc_info:
            Change(
                target_domain="example.com",
                snapshot_id="12345",
                change_type="invalid_type",  # type: ignore
                severity="high",
                asset_type="subdomain",
                asset_key="api.example.com",
            )
        assert "change_type" in str(exc_info.value)

    def test_change_severity_rejects_invalid_literal(self):
        """Change.severity should reject invalid literal."""
        with pytest.raises(ValidationError) as exc_info:
            Change(
                target_domain="example.com",
                snapshot_id="12345",
                change_type="new_subdomain",
                severity="invalid_severity",  # type: ignore
                asset_type="subdomain",
                asset_key="api.example.com",
            )
        assert "severity" in str(exc_info.value)

    def test_change_timestamp_auto_populated(self):
        """Change.timestamp should auto-populate as datetime."""
        change = Change(
            target_domain="example.com",
            snapshot_id="12345",
            change_type="new_subdomain",
            severity="high",
            asset_type="subdomain",
            asset_key="api.example.com",
        )
        assert isinstance(change.timestamp, datetime)

    def test_change_details_defaults_to_empty_dict(self):
        """Change.details should default to empty dict."""
        change = Change(
            target_domain="example.com",
            snapshot_id="12345",
            change_type="new_subdomain",
            severity="high",
            asset_type="subdomain",
            asset_key="api.example.com",
        )
        assert change.details == {}
        assert isinstance(change.details, dict)

    def test_change_with_details(self):
        """Change should accept details dict."""
        details = {"ip": "192.168.1.1", "port": 443}
        change = Change(
            target_domain="example.com",
            snapshot_id="12345",
            change_type="new_port",
            severity="medium",
            asset_type="port",
            asset_key="192.168.1.1:443",
            details=details,
        )
        assert change.details == details

    def test_change_valid_change_types(self):
        """Change should accept all valid change_type literals."""
        valid_types = [
            "new_subdomain",
            "subdomain_removed",
            "new_port",
            "port_closed",
            "new_leak",
        ]
        for change_type in valid_types:
            change = Change(
                target_domain="example.com",
                snapshot_id="12345",
                change_type=change_type,  # type: ignore
                severity="high",
                asset_type="test",
                asset_key="test",
            )
            assert change.change_type == change_type

    def test_change_valid_severity_levels(self):
        """Change should accept all valid severity literals."""
        valid_levels = ["critical", "high", "medium", "low", "info"]
        for severity in valid_levels:
            change = Change(
                target_domain="example.com",
                snapshot_id="12345",
                change_type="new_subdomain",
                severity=severity,  # type: ignore
                asset_type="test",
                asset_key="test",
            )
            assert change.severity == severity

    def test_change_model_dump(self):
        """Change.model_dump() should produce expected keys."""
        change = Change(
            target_domain="example.com",
            snapshot_id="12345",
            change_type="new_subdomain",
            severity="high",
            asset_type="subdomain",
            asset_key="api.example.com",
        )
        dumped = change.model_dump()
        assert "target_domain" in dumped
        assert "snapshot_id" in dumped
        assert "timestamp" in dumped
        assert "change_type" in dumped
        assert "severity" in dumped
        assert "asset_type" in dumped
        assert "asset_key" in dumped
        assert "details" in dumped

    def test_change_json_serializable(self):
        """Change.model_dump(mode='json') should be JSON-serializable."""
        change = Change(
            target_domain="example.com",
            snapshot_id="12345",
            change_type="new_subdomain",
            severity="high",
            asset_type="subdomain",
            asset_key="api.example.com",
        )
        dumped = change.model_dump(mode="json")
        json_str = json.dumps(dumped)  # Must not raise
        assert isinstance(json_str, str)
        assert len(json_str) > 0


class TestTypeAliases:
    """Tests for type aliases (SeverityLevel, ChangeType)."""

    def test_severity_level_is_literal_type(self):
        """SeverityLevel should be a Literal type."""
        # Verify it's defined and has the right values
        assert SeverityLevel == Literal["critical", "high", "medium", "low", "info"]

    def test_change_type_is_literal_type(self):
        """ChangeType should be a Literal type."""
        # Verify it's defined and has the right values
        assert ChangeType == Literal[
            "new_subdomain",
            "subdomain_removed",
            "new_port",
            "port_closed",
            "new_leak",
        ]
