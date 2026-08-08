"""Parse raw service banners into structured ``service/version`` strings.

Pure text parsing — no network access. Feeds both the CLI port-detail
view and the export pipeline (feature F7).
"""

from __future__ import annotations

import re

#: Default port -> service names, consulted when the banner itself
#: doesn't reveal the protocol.
_PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 27017: "mongodb",
}


def parse_service_version(port: int, banner: str) -> str | None:
    """Extract a ``<service> <version>`` string from a raw banner.

    Args:
        port: The TCP port the banner came from.
        banner: Raw banner text (may be a single line or multi-line).

    Returns:
        A compact string such as ``"ssh OpenSSH_9.6"`` or
        ``"http nginx/1.24.0"``, or None when nothing could be parsed.
    """
    if not banner or not banner.strip():
        return None
    text = banner.strip()

    # --- SSH ---
    m = re.search(r"SSH-[\d.]+-([^\s]+)", text)
    if m:
        return f"ssh {m.group(1)}"

    # --- HTTP ---
    m = re.search(
        r"(?:HTTP/\d(?:\.\d)?\s+\d{3}.*?^|\n)Server:\s*([^\r\n]+)",
        text, re.IGNORECASE | re.MULTILINE,
    )
    if m:
        server = m.group(1).strip()
        return f"http {server}" if server else "http"
    if text.startswith("HTTP/"):
        return "http"

    # --- FTP ---
    m = re.search(r"220[- ](.*)", text)
    if m:
        detail = m.group(1).strip()
        return f"ftp {detail}" if detail else "ftp"

    # --- SMTP ---
    if text.startswith("220") and "smtp" in text.lower():
        return "smtp"

    # --- POP3 ---
    if text.upper().startswith("+OK"):
        return "pop3"

    # --- IMAP ---
    if text.startswith("* OK") and "imap" in text.lower():
        return "imap"

    # Unknown banner — fall back to the port's conventional service name.
    default = _PORT_SERVICES.get(port)
    if default:
        return f"{default} (unidentified)"
    return None


def parse_all(ports: list[int], banner_map: dict[int, str]) -> dict[int, str]:
    """Map each port to its parsed service/version, if identifiable.

    Args:
        ports: Open ports of a host.
        banner_map: {port: raw banner}.

    Returns:
        {port: "service version"} for ports where parsing succeeded.
    """
    out: dict[int, str] = {}
    for port in ports:
        version = parse_service_version(port, banner_map.get(port, ""))
        if version:
            out[port] = version
    return out
