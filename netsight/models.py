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
    # Convenience field set by watch mode after persistence — not written
    # to the DB (history_db assigns its own autoincrement id).
    scan_id: int | None = field(default=None, repr=False)

    # Plan2 Phase 8 — classify response latency for the UI.
    @property
    def latency_class(self) -> str:
        """``Excellent`` / ``Good`` / ``Poor`` based on response_ms."""
        ms = self.response_ms
        if ms is None:
            return "unknown"
        if ms <= 5:
            return "excellent"
        if ms <= 50:
            return "good"
        return "poor"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of this host result."""
        data = asdict(self)
        data["latency_class"] = self.latency_class
        data["vuln_hints"] = self.vuln_hints
        return data

    @property
    def vuln_hints(self) -> list[str]:
        """Basic security hints from open ports (Plan2 v2.0 feature).

        Pure data — derived from ``self.open_ports``, so changing the
        list of risky ports in one place propagates everywhere.
        """
        hints: list[str] = []
        open_ports = {
            int(p.get("port", 0)) for p in self.open_ports if "port" in p
        }
        risky = {
            21: "FTP (unencrypted, plain-text auth)",
            23: "Telnet (unencrypted, legacy)",
            445: "SMB (ransomware target, disable if unused)",
            1433: "MSSQL (exposed DB)",
            3306: "MySQL (exposed DB)",
            3389: "RDP (remote desktop, brute-force target)",
            5432: "PostgreSQL (exposed DB)",
            5900: "VNC (unencrypted remote desktop)",
            6379: "Redis (no auth by default)",
            8080: "HTTP-Alt (potential unencrypted admin)",
            27017: "MongoDB (no auth by default)",
        }
        for port, note in risky.items():
            if port in open_ports:
                hints.append(note)
        return hints


@dataclass
class ScanResult:
    """Aggregated result of one scan run."""

    subnet: str
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None
    duration_s: float = 0.0
    hosts: list[HostResult] = field(default_factory=list)
    # Provenance: "cli", "watch", "dashboard-reexport", etc. Defaults to
    # "cli" for backwards compatibility with existing rows.
    source: str = "cli"
    # Database this scan will be written to (so exporters can reuse it).
    db_path: str = "netsight.db"

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


@dataclass
class MultiScanResult:
    """Aggregate of scans run across multiple subnets (multi-subnet v2.0).

    Merges hosts from every sub-scan into ``.hosts`` so downstream UI /
    exporter / history code sees a single result. ``children`` keeps the
    per-subnet breakdown for the UI.
    """

    subnet: str = "multi"
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None
    duration_s: float = 0.0
    hosts: list[HostResult] = field(default_factory=list)
    children: list[ScanResult] = field(default_factory=list, repr=False)

    @property
    def alive_hosts(self) -> list[HostResult]:
        return [h for h in self.hosts if h.alive]

    @property
    def open_port_count(self) -> int:
        return sum(len(h.open_ports) for h in self.alive_hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet": self.subnet,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration_s,
            "host_count": len(self.alive_hosts),
            "open_port_count": self.open_port_count,
            "scans": [child.to_dict() for child in self.children],
        }
