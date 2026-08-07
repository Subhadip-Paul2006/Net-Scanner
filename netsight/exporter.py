"""CSV and JSON export of scan results into a timestamped exports/ dir."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from netsight.models import ScanResult

#: One row per (host, open port) in CSV — hosts with no open ports appear
#: once with an empty port column.
CSV_FIELDS = (
    "ip", "hostname", "mac", "vendor", "os_guess", "ttl",
    "response_ms", "alive", "port", "banner", "detected_at",
)


def _default_exports_dir() -> Path:
    """exports/ next to the current working directory (created lazily)."""
    return Path.cwd() / "exports"


def _timestamp_slug() -> str:
    """Filesystem-safe timestamp for export filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _host_rows(scan: ScanResult) -> list[dict[str, object]]:
    """Flatten a ScanResult into CSV rows (one row per host/port pair)."""
    rows: list[dict[str, object]] = []
    for host in scan.hosts:
        if host.open_ports:
            for port in host.open_ports:
                rows.append(
                    {
                        "ip": host.ip,
                        "hostname": host.hostname,
                        "mac": host.mac,
                        "vendor": host.vendor,
                        "os_guess": host.os_guess,
                        "ttl": host.ttl if host.ttl is not None else "",
                        "response_ms": (
                            host.response_ms if host.response_ms is not None else ""
                        ),
                        "alive": host.alive,
                        "port": port.get("port", ""),
                        "banner": port.get("banner", ""),
                        "detected_at": host.detected_at,
                    }
                )
        else:
            rows.append(
                {
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "mac": host.mac,
                    "vendor": host.vendor,
                    "os_guess": host.os_guess,
                    "ttl": host.ttl if host.ttl is not None else "",
                    "response_ms": (
                        host.response_ms if host.response_ms is not None else ""
                    ),
                    "alive": host.alive,
                    "port": "",
                    "banner": "",
                    "detected_at": host.detected_at,
                }
            )
    return rows


def export_json(
    scan: ScanResult,
    directory: str | Path | None = None,
    filename: str | None = None,
) -> Path:
    """Write a scan result to a JSON file.

    Args:
        scan: The completed scan result.
        directory: Output directory (defaults to ./exports).
        filename: Override filename (must end with .json).

    Returns:
        Path to the written file.
    """
    out_dir = Path(directory) if directory else _default_exports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"netsight_scan_{_timestamp_slug()}.json"
    path = out_dir / name
    payload = scan.to_dict()
    payload["exported_at"] = datetime.now().isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def export_csv(
    scan: ScanResult,
    directory: str | Path | None = None,
    filename: str | None = None,
) -> Path:
    """Write a scan result to a CSV file.

    Args:
        scan: The completed scan result.
        directory: Output directory (defaults to ./exports).
        filename: Override filename (must end with .csv).

    Returns:
        Path to the written file.
    """
    out_dir = Path(directory) if directory else _default_exports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"netsight_scan_{_timestamp_slug()}.csv"
    path = out_dir / name
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_FIELDS))
        writer.writeheader()
        writer.writerows(_host_rows(scan))
    return path


def export_scan(
    scan: ScanResult,
    formats: list[str],
    directory: str | Path | None = None,
) -> list[Path]:
    """Export a scan result to one or more formats.

    Args:
        scan: The completed scan result.
        formats: Any of ``"csv"``, ``"json"``.
        directory: Output directory (defaults to ./exports).

    Returns:
        List of written file paths, in the order of ``formats``.

    Raises:
        ValueError: On an unknown format name.
    """
    written: list[Path] = []
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == "csv":
            written.append(export_csv(scan, directory))
        elif fmt == "json":
            written.append(export_json(scan, directory))
        elif fmt:
            raise ValueError(f"Unknown export format '{fmt}' (use csv/json)")
    return written
