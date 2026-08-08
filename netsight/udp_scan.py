"""Lightweight UDP service detector (feature F9).

Sends minimal well-formed probes for common UDP services and classifies
responses. Pure sockets — no scapy required. Ports of interest:

  - DNS (53), SNMP (161), NTP (123), NetBIOS NS (137), mDNS (5353)
"""

from __future__ import annotations

import socket
import struct

#: UDP services we actively probe. Value = human-readable service name.
UDP_SERVICES: dict[int, str] = {
    53: "dns",
    123: "ntp",
    137: "netbios-ns",
    161: "snmp",
    5353: "mdns",
}

# ---------------------------------------------------------------------------
# Minimal request payloads (RFC-correct, deliberately tiny).
# ---------------------------------------------------------------------------

def _dns_query() -> bytes:
    """A minimal DNS query for "localhost" A record."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"\x09localhost\x00"
    qtail = struct.pack(">HH", 1, 1)  # A, IN
    return header + qname + qtail


def _ntp_request() -> bytes:
    """SNTP client request (48 bytes, LI=0, VN=4, Mode=3)."""
    return b"\x1b" + b"\x00" * 47


def _nbns_query() -> bytes:
    """NetBIOS Name Service wildcard query for "*". """
    header = struct.pack(">HHHHHH", 0xABCD, 0x0000, 1, 0, 0, 0)
    name = bytearray()
    for _ in range(15):
        name += b"CK"
    name += b"AA\x00"
    qtail = struct.pack(">HH", 0x0020, 0x0001)
    return header + bytes(name) + qtail


def _snmp_get() -> bytes:
    """SNMPv1 GET for sysDescr.0 (community "public")."""
    # Hand-rolled ASN.1 — deliberately short and read-only.
    return bytes.fromhex(
        "3029" "020100" "0406" "7075626c6963" "a01c"
        "0204" "00000001" "020100" "020100" "300e"
        "300c" "0608" "2b06010201010100" "0500"
    )


_PROBES: dict[int, bytes] = {
    53: _dns_query(),
    123: _ntp_request(),
    137: _nbns_query(),
    161: _snmp_get(),
    5353: _dns_query(),  # mDNS uses the same wire format as DNS
}


def probe_udp(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Send one UDP probe and report the service banner if it answers.

    Args:
        ip: Target IPv4 address.
        port: UDP port (must be one of :data:`UDP_SERVICES`).
        timeout: Seconds to wait for a reply.

    Returns:
        A short service description (e.g. ``"dns (UDP/53)"``), or None
        when the port didn't respond.
    """
    payload = _PROBES.get(port)
    if payload is None:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(2048)
        return f"{UDP_SERVICES[port]} (UDP/{port}) len={len(data)}"
    except socket.timeout:
        return None
    except OSError:  # port unreachable, host down, etc.
        return None
    finally:
        sock.close()


def scan_udp(ip: str, timeout: float = 2.0) -> dict[int, str]:
    """Probe all known UDP services on one host.

    Returns:
        {port: description} for every UDP service that responded.
    """
    results: dict[int, str] = {}
    for port in UDP_SERVICES:
        desc = probe_udp(ip, port, timeout)
        if desc is not None:
            results[port] = desc
    return results
