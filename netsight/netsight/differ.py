"""Diff two scan results: new/disappeared devices, new/closed open ports.

Pure-data module — no network access. Used by ``netsight diff`` (compare
two history scans) and by watch mode (compare consecutive runs).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netsight.models import HostResult, ScanResult


@dataclass
class HostDelta:
    """Per-host difference between two scans."""

    ip: str
    hostname_a: str = ""
    hostname_b: str = ""
    mac_a: str = ""
    mac_b: str = ""
    vendor_a: str = ""
    vendor_b: str = ""
    os_a: str = ""
    os_b: str = ""
    new_open_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)


@dataclass
class DiffResult:
    """Aggregate difference between scan A (older) and scan B (newer)."""

    subnet_a: str
    subnet_b: str
    started_a: str
    started_b: str
    new_hosts: list[HostResult] = field(default_factory=list)
    gone_hosts: list[HostResult] = field(default_factory=list)
    changed_hosts: list[HostDelta] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def total_changes(self) -> int:
        """Total number of new + gone + changed hosts."""
        return (
            len(self.new_hosts)
            + len(self.gone_hosts)
            + len(self.changed_hosts)
        )


def _ports_of(host: HostResult) -> set[int]:
    """Extract the set of open port numbers from a host."""
    return {int(p["port"]) for p in host.open_ports if "port" in p}


def diff_scans(older: ScanResult, newer: ScanResult) -> DiffResult:
    """Compute the delta from ``older`` to ``newer``.

    A host is:
      * **new** — present in ``newer`` and missing in ``older``
      * **gone** — present in ``older`` and missing in ``newer``
      * **changed** — present in both but port set differs

    Args:
        older: The earlier ScanResult.
        newer: The later ScanResult.

    Returns:
        A :class:`DiffResult` describing every difference.
    """
    diff = DiffResult(
        subnet_a=older.subnet,
        subnet_b=newer.subnet,
        started_a=older.started_at,
        started_b=newer.started_at,
    )
    old_by_ip = {h.ip: h for h in older.alive_hosts}
    new_by_ip = {h.ip: h for h in newer.alive_hosts}

    for ip, new_host in new_by_ip.items():
        if ip not in old_by_ip:
            diff.new_hosts.append(new_host)

    for ip, old_host in old_by_ip.items():
        if ip not in new_by_ip:
            diff.gone_hosts.append(old_host)

    for ip in old_by_ip.keys() & new_by_ip.keys():
        old_h, new_h = old_by_ip[ip], new_by_ip[ip]
        old_ports = _ports_of(old_h)
        new_ports = _ports_of(new_h)
        new_open = sorted(new_ports - old_ports)
        closed = sorted(old_ports - new_ports)
        changed_identity = any(
            getattr(old_h, attr) != getattr(new_h, attr)
            for attr in ("hostname", "mac", "vendor", "os_guess")
        )
        if new_open or closed or changed_identity:
            diff.changed_hosts.append(
                HostDelta(
                    ip=ip,
                    hostname_a=old_h.hostname or "",
                    hostname_b=new_h.hostname or "",
                    mac_a=old_h.mac or "",
                    mac_b=new_h.mac or "",
                    vendor_a=old_h.vendor or "",
                    vendor_b=new_h.vendor or "",
                    os_a=old_h.os_guess or "",
                    os_b=new_h.os_guess or "",
                    new_open_ports=new_open,
                    closed_ports=closed,
                )
            )
        else:
            diff.unchanged_count += 1

    return diff
