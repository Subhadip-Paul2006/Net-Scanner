"""Threaded ping sweep to find alive hosts.

Prefers ARP requests via ``scapy`` on the local subnet (faster and more
reliable than ICMP on a LAN) and falls back to ICMP echo via the system
``ping`` command when scapy or raw-socket privileges are unavailable.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

#: Set to the RuntimeError message when an ARP sweep fails and ICMP is used
#: as fallback, so callers can surface it to the user.
last_fallback_reason: str | None = None

IS_WINDOWS = platform.system() == "Windows"

# Lazy scapy import: importing scapy probes the OS's raw-socket providers at
# import time (WMI/L0 lookups), which can take 30+ seconds on some Windows
# hosts. Deferring the import until ``arp_sweep`` actually runs keeps simple
# commands (``--help``, ``history``, ``quick`` when scapy isn't installed)
# fast even when scapy is present.
_ARP_MODULE = None


def _arp_module():
    """Lazily import scapy's ARP helpers (5s hard timeout).

    Importing scapy probes raw-socket providers (GLPK, Npcap, WMI) on
    Windows; on a poorly-configured host the import call can spin for
    30+ seconds. Running it in a daemon thread with a finite ``join``
    keeps ``netsight scan`` responsive even when the provider hangs.
    """
    global _ARP_MODULE
    if _ARP_MODULE is not None:
        return _ARP_MODULE

    result_ref: list = []

    def _import() -> None:
        try:
            from scapy.all import ARP, Ether, srp  # type: ignore  # noqa: TCH
            result_ref.append((ARP, Ether, srp))
        except Exception:  # noqa: BLE001 - scapy raises non-ImportError
            result_ref.append(False)

    worker = threading.Thread(target=_import, daemon=True)
    worker.start()
    worker.join(timeout=5.0)
    if not result_ref or result_ref[0] is False:
        # Cache the failure so we don't probe again during this process.
        _ARP_MODULE = False
        return None
    _ARP_MODULE = result_ref[0]
    return _ARP_MODULE


def _has_scapy() -> bool:
    return _arp_module() is not None


@dataclass
class SweepResult:
    """Result of probing one IP address."""

    ip: str
    alive: bool
    mac: str | None = None
    ttl: int | None = None
    response_ms: float | None = None


def expand_subnet(cidr: str, limit: int = 65536) -> list[str]:
    """Expand a CIDR into host addresses, capped at ``limit`` addresses.

    Args:
        cidr: Network in CIDR notation.
        limit: Maximum number of addresses to return.

    Returns:
        List of host IP strings (network/broadcast excluded for subnets
        larger than a /31).
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > 2:
        hosts = [str(ip) for ip in network.hosts()]
    else:
        hosts = [str(ip) for ip in network]
    return hosts[:limit]


def _ping_command(ip: str, timeout_ms: int) -> list[str]:
    """Build the OS-appropriate ping command for one echo request."""
    if IS_WINDOWS:
        # Clamp minimum to 1ms — ping -w 0 is invalid.
        return ["ping", "-n", "1", "-w", str(max(1, timeout_ms)), ip]
    # Linux/macOS: -c count, -W per-reply timeout in whole seconds.
    # Ceiling division so 1500ms -> 2s (never truncate to 1s and drop
    # slow hosts early); clamp to >= 1 so a 0/ms input can't hang ping.
    timeout_s = max(1, (timeout_ms + 999) // 1000)
    return ["ping", "-c", "1", "-W", str(timeout_s), ip]


def _parse_ttl(output: str) -> int | None:
    """Extract the TTL value from ping command output."""
    match = re.search(r"ttl[= ](\d+)", output, re.IGNORECASE)
    return int(match.group(1)) if match else None


def ping_host(ip: str, timeout_ms: int = 800) -> SweepResult:
    """ICMP-ping a single host via the system ping command.

    Args:
        ip: Target IPv4 address.
        timeout_ms: Per-host timeout in milliseconds.

    Returns:
        A :class:`SweepResult` with liveness, TTL, and response time.
    """
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            _ping_command(ip, timeout_ms),
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_ms / 1000) + 1.0,
        )
    except (subprocess.TimeoutExpired, OSError):
        return SweepResult(ip=ip, alive=False)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if proc.returncode == 0:
        output = proc.stdout or ""
        return SweepResult(
            ip=ip,
            alive=True,
            ttl=_parse_ttl(output),
            response_ms=round(elapsed_ms, 2),
        )
    return SweepResult(ip=ip, alive=False)


def arp_sweep(cidr: str, timeout: float = 2.0) -> list[SweepResult]:  # noqa: N803
    """Discover alive hosts on the local subnet with ARP requests (scapy).

    Args:
        cidr: Local subnet in CIDR notation.
        timeout: Seconds to wait for ARP replies.

    Returns:
        List of :class:`SweepResult` for every host that answered.

    Raises:
        RuntimeError: If scapy is unavailable or raw sockets are denied.
    """
    modules = _arp_module()
    if modules is None:
        raise RuntimeError("scapy is not installed")
    ARP, Ether, srp = modules
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)  # type: ignore[operator]
        answered, _ = srp(packet, timeout=timeout, verbose=False)  # type: ignore[misc]
    except PermissionError as exc:
        raise RuntimeError(
            "ARP sweep requires admin/root (raw socket) privileges"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"ARP sweep failed: {exc}") from exc

    results: list[SweepResult] = []
    for _, received in answered:
        server = getattr(received, "psrc", None)
        mac = getattr(received, "hwsrc", None)
        if server:
            results.append(SweepResult(ip=server, alive=True, mac=mac))
    return results


def ping_sweep(
    targets: list[str],
    max_workers: int = 100,     # Plan2 Phase 4 — 100 workers for home LAN
    timeout_ms: int = 800,
    progress_callback: Callable[[int, int], None] | None = None,
) -> list[SweepResult]:
    """ICMP sweep over a list of targets using a thread pool.

    Args:
        targets: IPv4 addresses to probe.
        max_workers: Thread pool size.
        timeout_ms: Per-host ping timeout in milliseconds.
        progress_callback: Optional callable(completed, total) invoked as
            hosts finish, for progress-bar updates.

    Returns:
        A :class:`SweepResult` per target, order not guaranteed.
    """
    results: list[SweepResult] = []
    total = len(targets)
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(ping_host, ip, timeout_ms): ip for ip in targets}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:  # noqa: BLE001 - one host must not kill sweep
                results.append(SweepResult(ip=futures[future], alive=False))
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total)
    return results


def sweep(
    cidr: str,
    max_workers: int = 100,
    timeout_ms: int = 800,
    prefer_arp: bool = True,
    progress_callback: Callable[[int, int], None] | None = None,
) -> list[SweepResult]:
    """Sweep a subnet for alive hosts (ARP first, ICMP fallback).

    Args:
        cidr: Target subnet in CIDR notation.
        max_workers: Thread pool size for the ICMP fallback.
        timeout_ms: Per-host timeout for the ICMP fallback.
        prefer_arp: Try scapy ARP sweep first when True.
        progress_callback: Optional callable(completed, total).

    Returns:
        Alive-only list of :class:`SweepResult`. When ARP answers, only
        responders are returned; otherwise ICMP results are filtered to
        alive hosts.
    """
    global last_fallback_reason
    last_fallback_reason = None
    if prefer_arp and _ARP_MODULE is False:
        _fell_back = True  # scapy already failed once — skip retries

    if prefer_arp and _has_scapy():
        try:
            arp_results = arp_sweep(cidr, timeout=max(1.0, timeout_ms / 1000))
            if arp_results:
                if progress_callback is not None:
                    progress_callback(1, 1)
                # Enrich with TTL/RTT via individual pings (threaded).
                ips = [r.ip for r in arp_results]
                by_ip = {r.ip: r for r in arp_results}
                for res in ping_sweep(ips, max_workers, timeout_ms):
                    if res.ip in by_ip:
                        by_ip[res.ip].ttl = res.ttl
                        by_ip[res.ip].response_ms = res.response_ms
                return list(by_ip.values())
        except RuntimeError as exc:
            last_fallback_reason = str(exc)

    if prefer_arp and not _has_scapy():
        last_fallback_reason = "scapy is not installed"

    targets = expand_subnet(cidr)
    icmp_results = ping_sweep(targets, max_workers, timeout_ms, progress_callback)

    from netsight.host_info import get_arp_table
    arp_table = get_arp_table(force_refresh=True)

    alive_by_ip = {r.ip: r for r in icmp_results if r.alive}
    target_set = set(targets)

    for ip, mac in arp_table.items():
        if ip in target_set and ip not in alive_by_ip:
            alive_by_ip[ip] = SweepResult(ip=ip, alive=True, mac=mac)
        elif ip in alive_by_ip and alive_by_ip[ip].mac is None:
            alive_by_ip[ip].mac = mac

    return list(alive_by_ip.values())


def sweep_multi(
    cidrs: list[str],
    max_workers: int = 100,
    timeout_ms: int = 800,
    prefer_arp: bool = True,
    progress_callback: Callable[[int, int], None] | None = None,
) -> list[SweepResult]:
    """Sweep several CIDRs concurrently, one ThreadPoolExecutor each.

    Args:
        cidrs: List of subnets in CIDR notation.
        max_workers: Thread pool size **per subnet** (total concurrent threads
            = ``max_workers * len(cidrs)``).
        timeout_ms: Per-host timeout for the ICMP fallback.
        prefer_arp: Try scapy ARP sweep on each subnet when True.
        progress_callback: Optional callable(completed, total). Completed =
            number of subnets finished; total = len(cidrs).

    Returns:
        A merged list of :class:`SweepResult` from all subnets.
    """
    combined: list[SweepResult] = []
    if not cidrs:
        return combined

    with ThreadPoolExecutor(max_workers=len(cidrs)) as subnet_pool:
        futures = {
            subnet_pool.submit(
                sweep, cidr, max_workers, timeout_ms, prefer_arp,
            ): cidr
            for cidr in cidrs
        }
        completed = 0
        for future in as_completed(futures):
            combined.extend(future.result())
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, len(cidrs))

    _fill_macs_from_arp_table(combined)  # Catch ICMP-only fallback paths.
    return combined


_ARP_CACHE: dict[str, str] | None = None
_ARP_LOCK = threading.Lock()


def _fill_macs_from_arp_table(results: list[SweepResult]) -> None:
    """Best-effort MAC enrichment from the OS ARP table after ICMP sweep."""
    from netsight.host_info import get_arp_table

    with _ARP_LOCK:
        table = get_arp_table()
    for res in results:
        if res.mac is None and res.ip in table:
            res.mac = table[res.ip]
