"""Typed data models for sandbox fleet and state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SandboxSummary:
    sandbox_name: str
    resource_group_name: str
    location: str
    subscription_id: str
    state_file: str
    expires_at_utc: str
    updated_at_utc: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxSummary":
        return cls(
            sandbox_name=str(data.get("sandbox_name", "")),
            resource_group_name=str(data.get("resource_group_name", "")),
            location=str(data.get("location", "")),
            subscription_id=str(data.get("subscription_id", "")),
            state_file=str(data.get("state_file", "")),
            expires_at_utc=str(data.get("expires_at_utc", "")),
            updated_at_utc=str(data.get("updated_at_utc", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sandbox_name": self.sandbox_name,
            "resource_group_name": self.resource_group_name,
            "location": self.location,
            "subscription_id": self.subscription_id,
            "state_file": self.state_file,
            "expires_at_utc": self.expires_at_utc,
            "updated_at_utc": self.updated_at_utc,
        }


@dataclass
class FleetIndex:
    version: int
    workspace_path: str
    workspace_id: str
    active_sandbox: str | None
    sandboxes: dict[str, dict[str, Any]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FleetIndex":
        return cls(
            version=int(data.get("version", 1)),
            workspace_path=str(data.get("workspace_path", "")),
            workspace_id=str(data.get("workspace_id", "")),
            active_sandbox=data.get("active_sandbox"),
            sandboxes=dict(data.get("sandboxes", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "workspace_path": self.workspace_path,
            "workspace_id": self.workspace_id,
            "active_sandbox": self.active_sandbox,
            "sandboxes": self.sandboxes,
        }


@dataclass
class SandboxState:
    data: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxState":
        return cls(data=dict(data))

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)
