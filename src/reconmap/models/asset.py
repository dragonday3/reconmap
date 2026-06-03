from datetime import datetime, timezone
from typing import Any, Literal
import uuid

from pydantic import BaseModel, Field


class TargetDomain(BaseModel):
    domain: str
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Subdomain(BaseModel):
    target_domain: str
    subdomain: str
    ip_addresses: list[str] = Field(default_factory=list)
    source: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Port(BaseModel):
    ip: str
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str = ""
    banner: str = ""
    source: str


class SecretLeak(BaseModel):
    target_domain: str
    repo: str
    file_path: str
    line_number: int = 0
    secret_type: str
    raw_match: str = ""
    html_url: str = ""
    source: str = "github"


class AssetSnapshot(BaseModel):
    target_domain: str
    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    subdomains: list[Subdomain] = Field(default_factory=list)
    ports: list[Port] = Field(default_factory=list)
    leaks: list[SecretLeak] = Field(default_factory=list)


SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
ChangeType = Literal[
    "new_subdomain",
    "subdomain_removed",
    "new_port",
    "port_closed",
    "new_leak",
]


class Change(BaseModel):
    target_domain: str
    snapshot_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    change_type: ChangeType
    severity: SeverityLevel
    asset_type: str
    asset_key: str
    details: dict[str, Any] = Field(default_factory=dict)
