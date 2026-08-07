"""Threaded TCP connect port scanner.

Plain ``socket.connect_ex`` based scanning — no raw sockets, no SYN scan,
no exploitation. Optionally grabs a service banner from open ports.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

#: Well-known ports scanned by default ("common" set).
COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    3389, 3306, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 27017,
]

#: Ports that start TLS immediately — plain banner reads won't work well.
_TLS_PORTS = {443, 8443, 993, 995, 465}


@dataclass
class PortResult:
    """Result of probing one TCP port."""

    port: int
    status: str  # "open", "closed", "filtered"
    banner: str = ""


@dataclass
class PortScanResult:
    """Aggregate of a port scan against one host."""

    ip: str
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open(self) -> list[PortResult]:
        """Only the open-port results."""
        return [p for p in self.ports if p.status == "open"]

    @property
    def open_ports(self) -> list[int]:
        """Sorted list of open port numbers."""
        return sorted(p.port for p in self.open)


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification into a deduplicated, sorted port list.

    Accepts ``"common"``, single ports (``"80"``), comma lists
    (``"80,443,8080"``), ranges (``"1-1024"``), and combinations
    (``"22,80,8000-8100"``).

    Args:
        spec: Port specification string.

    Returns:
        Sorted unique list of valid port numbers.

    Raises:
        ValueError: When any token is not a valid port/range.
    """
    if spec.strip().lower() == "common":
        return list(COMMON_PORTS)

    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s, *_ = token.split("-", 2)
            start, end = int(start_s), int(end_s)
            if end < start:
                raise ValueError(f"Invalid range '{token}'")
            for port in range(start, end + 1):
                _validate_port(port)
                ports.add(port)
        else:
            _validate_port(int(token))
            ports.add(int(token))
    if not ports:
        raise ValueError(f"No valid ports in specification '{spec}'")
    return sorted(ports)


def _validate_port(port: int) -> None:
    """Raise ValueError if ``port`` is outside 1-65535."""
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} is out of range (1-65535)")


def grab_banner(sock: socket.socket, timeout: float = 1.5) -> str:
    """Attempt a non-invasive banner grab on an open socket.

    Sends nothing for services that speak first (FTP, SMTP, SSH, ...);
    sends a minimal ``HEAD`` request to likely-HTTP ports. Returns an
    empty string when no banner is available.
    """
    try:
        sock.settimeout(timeout)
        port = sock.getpeername()[1]
        if port not in _TLS_PORTS:
            if port in (80, 8080, 8000, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(128)
            return data.decode("utf-8", errors="replace").strip()[:120]
        return ""
    except OSError:
        return ""


def scan_port(ip: str, port: int, timeout: float = 1.0,
              banner: bool = True) -> PortResult:
    """Probe one TCP port on one host.

    Args:
        ip: Target IPv4 address.
        port: TCP port number.
        timeout: Connection timeout in seconds.
        banner: Try to grab a banner when the port is open.

    Returns:
        A :class:`PortResult` describing ``open``/``closed``/``filtered``.
        (``filtered`` = timed out; ``closed`` = connection refused.)
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            grabbed = grab_banner(sock) if banner else ""
            return PortResult(port=port, status="open", banner=grabbed)
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
        return PortResult(port=port, status="closed")
    except socket.timeout:
        return PortResult(port=port, status="filtered")
    except socket.gaierror:
        return PortResult(port=port, status="filtered")
    except OSError:
        # Host unreachable etc. — treat as filtered rather than crashing.
        return PortResult(port=port, status="filtered")


def scan_host(
    ip: str,
    ports: list[int],
    max_workers: int = 100,
    timeout: float = 1.0,
    banner: bool = True,
    progress_callback: Callable[[int, int], None] | None = None,
) -> PortScanResult:
    """Scan a list of TCP ports on one host with a thread pool.

    Args:
        ip: Target IPv4 address.
        ports: Ports to probe.
        max_workers: Thread pool size (default 100).
        timeout: Per-connection timeout in seconds — no hanging sockets.
        banner: Attempt banner grabbing on open ports.
        progress_callback: Optional callable(completed, total).

    Returns:
        A :class:`PortScanResult` containing all probe results, sorted
        by port number.
    """
    result = PortScanResult(ip=ip)
    total = len(ports)
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(scan_port, ip, port, timeout, banner): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                result.ports.append(future.result())
            except Exception:  # noqa: BLE001 - never die on one bad probe
                result.ports.append(
                    PortResult(port=futures[future], status="filtered")
                )
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total)
    result.ports.sort(key=lambda p: p.port)
    return result
