import pytest
from pathlib import Path

from reconmap.reporters.html import HTMLReporter
from reconmap.models.asset import AssetSnapshot, Change, Subdomain, Port, SecretLeak

# Use the project templates directory for all tests
TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent.parent / "templates")


def make_reporter() -> HTMLReporter:
    return HTMLReporter(template_dir=TEMPLATES_DIR)


def make_snapshot(**kwargs) -> AssetSnapshot:
    defaults = {"target_domain": "example.com"}
    defaults.update(kwargs)
    return AssetSnapshot(**defaults)


def make_subdomain(**kwargs) -> Subdomain:
    defaults = {
        "target_domain": "example.com",
        "subdomain": "api.example.com",
        "ip_addresses": ["1.2.3.4"],
        "source": "certstream",
    }
    defaults.update(kwargs)
    return Subdomain(**defaults)


def make_port(**kwargs) -> Port:
    defaults = {
        "ip": "1.2.3.4",
        "port": 443,
        "service": "https",
        "source": "shodan",
    }
    defaults.update(kwargs)
    return Port(**defaults)


def make_leak(**kwargs) -> SecretLeak:
    defaults = {
        "target_domain": "example.com",
        "repo": "acme/infra",
        "file_path": ".env",
        "secret_type": "AWS_SECRET",
        "raw_match": "AKIAIOSFODNN7EXAMPLE",
        "source": "github",
    }
    defaults.update(kwargs)
    return SecretLeak(**defaults)


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


class TestHTMLReporter:
    def test_generate_returns_doctype_html(self):
        reporter = make_reporter()
        snapshot = make_snapshot()
        result = reporter.generate(snapshot)
        assert "<!DOCTYPE html>" in result

    def test_target_domain_appears_in_output(self):
        reporter = make_reporter()
        snapshot = make_snapshot(target_domain="targetdomain.io")
        result = reporter.generate(snapshot)
        assert "targetdomain.io" in result

    def test_subdomains_in_output(self):
        reporter = make_reporter()
        sub = make_subdomain(subdomain="mail.example.com")
        snapshot = make_snapshot(subdomains=[sub])
        result = reporter.generate(snapshot)
        assert "mail.example.com" in result

    def test_ports_in_output(self):
        reporter = make_reporter()
        port = make_port(port=8080)
        snapshot = make_snapshot(ports=[port])
        result = reporter.generate(snapshot)
        assert "8080" in result

    def test_leaks_secret_type_in_output(self):
        reporter = make_reporter()
        leak = make_leak(secret_type="GITHUB_TOKEN")
        snapshot = make_snapshot(leaks=[leak])
        result = reporter.generate(snapshot)
        assert "GITHUB_TOKEN" in result

    def test_changes_in_output(self):
        reporter = make_reporter()
        snapshot = make_snapshot()
        change = make_change(change_type="new_port", asset_key="1.2.3.4:80")
        result = reporter.generate(snapshot, changes=[change])
        assert "new_port" in result

    def test_empty_snapshot_shows_no_assets_message(self):
        reporter = make_reporter()
        snapshot = make_snapshot()
        result = reporter.generate(snapshot)
        assert "No assets discovered" in result

    def test_write_creates_html_file(self, tmp_path):
        reporter = make_reporter()
        snapshot = make_snapshot()
        out = str(tmp_path / "report.html")
        reporter.write(snapshot, out)
        with open(out, encoding="utf-8") as fh:
            content = fh.read()
        assert "<!DOCTYPE html>" in content
        assert "example.com" in content
