"""Shared data models for NetSight scan results."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class HostResult:
    """Discovery/inventory data collected for a single host."""

    ip: str
    alive: bool = False
    hostname: str = "Unknown"
    mac: str = "Unknown"
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    ttl: int | None = None
    response_ms: float | None = None
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    detected_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of this host result."""
        return asdict(self)


@dataclass
class ScanResult:
    """Aggregated result of one scan run."""

    subnet: str
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None
    duration_s: float = 0.0
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def alive_hosts(self) -> list[HostResult]:
        """Return only the hosts that responded during discovery."""
        return [h for h in self.hosts if h.alive]

    @property
    def open_port_count(self) -> int:
        """Total number of open ports found across all alive hosts."""
        return sum(len(h.open_ports) for h in self.alive_hosts)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of this scan result."""
        data = asdict(self)
        data["host_count"] = len(self.alive_hosts)
        data["open_port_count"] = self.open_port_count
        return data
