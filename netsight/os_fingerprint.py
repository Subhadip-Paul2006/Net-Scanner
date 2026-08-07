"""Lightweight OS fingerprinting.

Primary mode: TTL heuristics — the initial TTL of a host's replies hints
at its OS family (Linux/Unix ~64, Windows ~128, network gear ~255).

Optional deep mode: ``nmap -O`` via python-nmap when installed (requires
root/admin and the nmap binary). Discovery/inventory only.
"""

from __future__ import annotations

try:
    import nmap  # type: ignore  # python-nmap

    HAS_NMAP = True
except ImportError:  # pragma: no cover - optional dependency
    nmap = None  # type: ignore[assignment]
    HAS_NMAP = False


def guess_os_from_ttl(ttl: int | None) -> str:
    """Guess an OS family from an observed ping TTL value.

    Args:
        ttl: Observed TTL from a ping reply (after hop decrement).

    Returns:
        A short OS-family guess such as ``"Linux/Unix"``, or ``"Unknown"``.
    """
    if ttl is None or ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device / embedded"


def deep_fingerprint(ip: str, timeout: float = 30.0) -> str:
    """Fingerprint a host using nmap OS detection (optional, slower).

    Args:
        ip: Target IPv4 address.
        timeout: Maximum seconds to wait for nmap.

    Returns:
        Best OS match name, or ``"Unknown"`` when unavailable.

    Raises:
        RuntimeError: When python-nmap/nmap is not available.
    """
    if not HAS_NMAP:
        raise RuntimeError(
            "python-nmap is not installed (pip install python-nmap) "
            "or the nmap binary is missing"
        )
    scanner = nmap.PortScanner()  # type: ignore[union-attr]
    try:
        scanner.scan(ip, arguments=f"-O --osscan-guess --host-timeout {int(timeout)}s")
    except Exception as exc:  # noqa: BLE001 - nmap raises its own error type
        raise RuntimeError(f"nmap OS scan failed: {exc}") from exc

    try:
        host = scanner[ip]
        osmatches = host.get("osmatch", [])
    except KeyError:
        return "Unknown"
    if not osmatches:
        return "Unknown"
    best = max(osmatches, key=lambda m: int(m.get("accuracy", 0)))
    return f"{best.get('name', 'Unknown')} ({best.get('accuracy', '?')}% nmap)"
