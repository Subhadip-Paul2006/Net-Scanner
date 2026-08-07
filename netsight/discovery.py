"""Local network/interface discovery.

Enumerates active network interfaces and computes the local subnet (CIDR)
using ``netifaces`` when available, falling back to ``psutil`` plus a UDP
socket trick to find the default-route interface.

This module is import-safe and independently testable: all library calls go
through small wrapper functions that tests can monkeypatch.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import psutil

try:  # optional but preferred
    import netifaces  # type: ignore

    HAS_NETIFACES = True
except ImportError:  # pragma: no cover - depends on environment
    netifaces = None  # type: ignore[assignment]
    HAS_NETIFACES = False

#: RFC1918 private ranges the tool is allowed to scan without warnings.
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

#: Upper bound on the size of a scan target (a /16).
MAX_TARGET_HOSTS = 65536


@dataclass
class InterfaceInfo:
    """Details about one network interface."""

    name: str
    ip: str
    netmask: str
    cidr: str
    is_default: bool = False


def cidr_from_ip_netmask(ip: str, netmask: str) -> str:
    """Compute the CIDR notation for an IP/netmask pair.

    Args:
        ip: IPv4 address of the interface, e.g. ``"192.168.1.10"``.
        netmask: Dotted-quad netmask, e.g. ``"255.255.255.0"``.

    Returns:
        Network address in CIDR notation, e.g. ``"192.168.1.0/24"``.
    """
    network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
    return str(network)


def is_private_target(cidr: str) -> bool:
    """Check whether a CIDR range is RFC1918-private (or loopback/link-local).

    Args:
        cidr: Network in CIDR notation.

    Returns:
        True when the whole network falls inside private space.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if network.version != 4:
        return False
    if network.is_loopback or network.is_link_local:
        return True
    return any(network.subnet_of(priv) for priv in PRIVATE_NETWORKS)


def validate_target(cidr: str, allow_public: bool = False) -> str | None:
    """Validate a scan target CIDR against NetSight safety rules.

    Args:
        cidr: The requested target network.
        allow_public: Permit public ranges (still bounded by size).

    Returns:
        ``None`` when the target is acceptable, otherwise a human-readable
        reason the target was rejected.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return f"'{cidr}' is not a valid CIDR network."
    if network.version != 4:
        return "Only IPv4 targets are supported in v1.0."
    if network.num_addresses > MAX_TARGET_HOSTS:
        return (
            f"Target {network} has {network.num_addresses} addresses; "
            f"the maximum allowed is {MAX_TARGET_HOSTS} (a /16)."
        )
    if not allow_public and not is_private_target(cidr):
        return (
            f"Target {network} is not in a private RFC1918 range. "
            "NetSight only scans private networks / your own subnet."
        )
    return None


def _interfaces_from_netifaces() -> list[InterfaceInfo]:
    """Enumerate interfaces using the netifaces library."""
    results: list[InterfaceInfo] = []
    gateways = netifaces.gateways()  # type: ignore[union-attr]
    default_iface = None
    default_gw = gateways.get("default", {}).get(netifaces.AF_INET)  # type: ignore[union-attr]
    if default_gw:
        default_iface = default_gw[1]

    for name in netifaces.interfaces():  # type: ignore[union-attr]
        addrs = netifaces.ifaddresses(name)  # type: ignore[union-attr]
        inet = addrs.get(netifaces.AF_INET)  # type: ignore[union-attr]
        if not inet:
            continue
        for entry in inet:
            ip = entry.get("addr")
            netmask = entry.get("netmask", "255.255.255.0")
            if not ip or ip.startswith("127."):
                continue
            try:
                cidr = cidr_from_ip_netmask(ip, netmask)
            except ValueError:
                continue
            results.append(
                InterfaceInfo(
                    name=name,
                    ip=ip,
                    netmask=netmask,
                    cidr=cidr,
                    is_default=(name == default_iface),
                )
            )
    return results


def _default_route_ip() -> str | None:
    """Find the outbound IP used for the default route via a UDP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2.0)
        # No traffic is actually sent for UDP connect().
        sock.connect(("192.168.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _interfaces_from_psutil() -> list[InterfaceInfo]:
    """Enumerate interfaces using psutil as a netifaces fallback."""
    results: list[InterfaceInfo] = []
    default_ip = _default_route_ip()
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        stat = stats.get(name)
        if stat is not None and not stat.isup:
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if ip.startswith("127."):
                continue
            netmask = addr.netmask or "255.255.255.0"
            try:
                cidr = cidr_from_ip_netmask(ip, netmask)
            except ValueError:
                continue
            results.append(
                InterfaceInfo(
                    name=name,
                    ip=ip,
                    netmask=netmask,
                    cidr=cidr,
                    is_default=(ip == default_ip),
                )
            )
    return results


def enumerate_interfaces() -> list[InterfaceInfo]:
    """Enumerate active IPv4 interfaces and their subnets.

    Prefers ``netifaces`` when installed, otherwise falls back to
    ``psutil``. Loopback addresses are always excluded.

    Returns:
        A list of :class:`InterfaceInfo`, default-route interface first.
    """
    if HAS_NETIFACES:
        interfaces = _interfaces_from_netifaces()
    else:
        interfaces = _interfaces_from_psutil()
    interfaces.sort(key=lambda i: not i.is_default)
    return interfaces


def default_subnet() -> str | None:
    """Return the CIDR of the default-route interface, if one was found."""
    for iface in enumerate_interfaces():
        if iface.is_default:
            return iface.cidr
    interfaces = enumerate_interfaces()
    return interfaces[0].cidr if interfaces else None
