"""Per-host information: hostname resolution and MAC address detection.

Hostname lookups use reverse DNS with a hard timeout so a slow resolver
can never hang the scan. MAC addresses come from scapy ARP answers when
available, otherwise from the OS ARP table (``arp -a`` on Windows/macOS,
``/proc/net/arp`` on Linux).
"""

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import threading

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

#: Cache so repeated lookups within a scan run are cheap.
_ARP_TABLE_CACHE: dict[str, str] | None = None
_ARP_CACHE_LOCK = threading.Lock()


def resolve_hostname(ip: str, timeout: float = 1.5) -> str:
    """Reverse-DNS resolve an IP address with a hard timeout.

    Args:
        ip: IPv4 address to resolve.
        timeout: Maximum seconds to wait for the resolver.

    Returns:
        The primary hostname, or ``"Unknown"`` on any failure/timeout.
    """
    result: list[str] = []

    def _lookup() -> None:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            result.append(name)
        except (socket.herror, socket.gaierror, OSError):
            return

    worker = threading.Thread(target=_lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return result[0] if result else "Unknown"


def _run_arp_command() -> str:
    """Return the raw output of the OS ``arp -a`` command."""
    try:
        proc = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout or ""


def _parse_arp_table_posix(text: str) -> dict[str, str]:
    """Parse Linux/macOS style 'arp -a' output."""
    # e.g.:  router (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
    table: dict[str, str] = {}
    pattern = re.compile(
        r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:.-]{11,17})"
    )
    for ip, mac in pattern.findall(text):
        if mac.lower() not in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
            table[ip] = _normalize_mac(mac)
    return table


def _parse_arp_table_windows(text: str) -> dict[str, str]:
    """Parse Windows style 'arp -a' output."""
    # e.g.:  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic
    table: dict[str, str] = {}
    pattern = re.compile(
        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+\w+",
        re.MULTILINE,
    )
    for ip, mac in pattern.findall(text):
        if mac.lower() != "ff-ff-ff-ff-ff-ff":
            table[ip] = _normalize_mac(mac)
    return table


def _parse_proc_net_arp(text: str) -> dict[str, str]:
    """Parse Linux /proc/net/arp content."""
    table: dict[str, str] = {}
    for line in text.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 4 and parts[2] != "0x0":
            ip, mac = parts[0], parts[3]
            if mac != "00:00:00:00:00:00":
                table[ip] = _normalize_mac(mac)
    return table


def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase colon-separated form."""
    sep = ":" if ":" in mac else "-"
    parts = [p.zfill(2) for p in mac.split(sep)]
    return ":".join(parts).lower()


def get_arp_table(force_refresh: bool = False) -> dict[str, str]:
    """Return the OS ARP table as an {ip: mac} mapping.

    Args:
        force_refresh: Bypass the per-process cache.
    """
    global _ARP_TABLE_CACHE
    with _ARP_CACHE_LOCK:
        if _ARP_TABLE_CACHE is not None and not force_refresh:
            return _ARP_TABLE_CACHE

        table: dict[str, str] = {}
        if IS_LINUX and os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", encoding="utf-8") as fh:
                    table = _parse_proc_net_arp(fh.read())
            except OSError:
                table = _parse_arp_table_posix(_run_arp_command())
        elif IS_WINDOWS:
            table = _parse_arp_table_windows(_run_arp_command())
        else:  # macOS / other
            table = _parse_arp_table_posix(_run_arp_command())

        _ARP_TABLE_CACHE = table
        return table


def get_mac(ip: str) -> str:
    """Best-effort MAC address for an IP from the OS ARP table.

    Args:
        ip: IPv4 address.

    Returns:
        Normalized MAC string, or ``"Unknown"`` if not present.
    """
    return get_arp_table().get(ip, "Unknown")
