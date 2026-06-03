import logging
from datetime import datetime, timezone

from reconmap.models.asset import AssetSnapshot, Change, ChangeType, SeverityLevel

logger = logging.getLogger(__name__)

# Severity mapping for each change type
CHANGE_SEVERITY: dict[str, str] = {
    "new_subdomain":     "medium",
    "subdomain_removed": "low",
    "new_port":          "high",
    "port_closed":       "info",
    "new_leak":          "critical",
}


class DiffEngine:
    """Compares two AssetSnapshots and returns the list of Changes."""

    def diff(self, before: AssetSnapshot, after: AssetSnapshot) -> list[Change]:
        changes: list[Change] = []
        now = datetime.now(timezone.utc)

        # Subdomain diffs
        before_subs = {s.subdomain for s in before.subdomains}
        after_subs = {s.subdomain for s in after.subdomains}

        for name in after_subs - before_subs:
            changes.append(Change(
                target_domain=after.target_domain,
                snapshot_id=after.snapshot_id,
                timestamp=now,
                change_type="new_subdomain",
                severity=CHANGE_SEVERITY["new_subdomain"],
                asset_type="subdomain",
                asset_key=name,
                details={"subdomain": name},
            ))

        for name in before_subs - after_subs:
            changes.append(Change(
                target_domain=after.target_domain,
                snapshot_id=after.snapshot_id,
                timestamp=now,
                change_type="subdomain_removed",
                severity=CHANGE_SEVERITY["subdomain_removed"],
                asset_type="subdomain",
                asset_key=name,
                details={"subdomain": name},
            ))

        # Port diffs
        before_ports = {(p.ip, p.port) for p in before.ports}
        after_ports = {(p.ip, p.port) for p in after.ports}

        for ip, port in after_ports - before_ports:
            changes.append(Change(
                target_domain=after.target_domain,
                snapshot_id=after.snapshot_id,
                timestamp=now,
                change_type="new_port",
                severity=CHANGE_SEVERITY["new_port"],
                asset_type="port",
                asset_key=f"{ip}:{port}",
                details={"ip": ip, "port": port},
            ))

        for ip, port in before_ports - after_ports:
            changes.append(Change(
                target_domain=after.target_domain,
                snapshot_id=after.snapshot_id,
                timestamp=now,
                change_type="port_closed",
                severity=CHANGE_SEVERITY["port_closed"],
                asset_type="port",
                asset_key=f"{ip}:{port}",
                details={"ip": ip, "port": port},
            ))

        # Leak diffs (only new leaks — never "leak removed")
        before_leaks = {(l.repo, l.file_path, l.line_number) for l in before.leaks}
        after_leaks_map = {(l.repo, l.file_path, l.line_number): l for l in after.leaks}

        for key, leak in after_leaks_map.items():
            if key not in before_leaks:
                changes.append(Change(
                    target_domain=after.target_domain,
                    snapshot_id=after.snapshot_id,
                    timestamp=now,
                    change_type="new_leak",
                    severity=CHANGE_SEVERITY["new_leak"],
                    asset_type="leak",
                    asset_key=f"{leak.repo}/{leak.file_path}:{leak.line_number}",
                    details={
                        "repo": leak.repo,
                        "file_path": leak.file_path,
                        "secret_type": leak.secret_type,
                    },
                ))

        return changes
