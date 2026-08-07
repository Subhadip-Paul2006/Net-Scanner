"""SQLite-backed scan history (netsight.db).

Two normalized tables: ``scans`` (one row per scan run) and ``hosts``
(one row per host in a scan). Designed with clean extension points for
v1.1+ features (device change detection, alerting) — see ``hooks/``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from netsight.models import HostResult, ScanResult, utc_now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    subnet        TEXT NOT NULL,
    host_count    INTEGER NOT NULL DEFAULT 0,
    duration_s    REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    hostname     TEXT,
    mac          TEXT,
    vendor       TEXT,
    os_guess     TEXT,
    ttl          INTEGER,
    response_ms  REAL,
    alive        INTEGER NOT NULL DEFAULT 0,
    open_ports   TEXT NOT NULL DEFAULT '[]',
    detected_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip      ON hosts(ip);
"""


class HistoryDB:
    """Thin wrapper around the netsight.db SQLite database."""

    def __init__(self, db_path: str | Path = "netsight.db") -> None:
        """Open (creating if needed) the history database."""
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> "HistoryDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def save_scan(self, scan: ScanResult) -> int:
        """Persist a completed scan run and its hosts.

        Args:
            scan: The completed :class:`ScanResult`.

        Returns:
            The new scan row id.
        """
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO scans (started_at, finished_at, subnet,
                                   host_count, duration_s)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan.started_at,
                    scan.finished_at or utc_now_iso(),
                    scan.subnet,
                    len(scan.alive_hosts),
                    scan.duration_s,
                ),
            )
            scan_id = int(cursor.lastrowid)  # type: ignore[union-attr]
            for host in scan.hosts:
                self._conn.execute(
                    """
                    INSERT INTO hosts (scan_id, ip, hostname, mac, vendor,
                                       os_guess, ttl, response_ms, alive,
                                       open_ports, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        host.ip,
                        host.hostname,
                        host.mac,
                        host.vendor,
                        host.os_guess,
                        host.ttl,
                        host.response_ms,
                        1 if host.alive else 0,
                        json.dumps(host.open_ports),
                        host.detected_at,
                    ),
                )
        return scan_id

    def list_scans(self, limit: int = 50) -> list[dict[str, object]]:
        """Return recent scan runs, most recent first."""
        cursor = self._conn.execute(
            """
            SELECT id, started_at, finished_at, subnet, host_count, duration_s
            FROM scans ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_scan(self, scan_id: int) -> ScanResult | None:
        """Load a full scan result (with hosts) by scan id.

        Returns:
            The reconstructed :class:`ScanResult`, or None if unknown id.
        """
        cursor = self._conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None

        scan = ScanResult(
            subnet=row["subnet"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            duration_s=row["duration_s"],
        )
        host_cursor = self._conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ? ORDER BY ip", (scan_id,)
        )
        for hrow in host_cursor.fetchall():
            scan.hosts.append(
                HostResult(
                    ip=hrow["ip"],
                    alive=bool(hrow["alive"]),
                    hostname=hrow["hostname"] or "Unknown",
                    mac=hrow["mac"] or "Unknown",
                    vendor=hrow["vendor"] or "Unknown",
                    os_guess=hrow["os_guess"] or "Unknown",
                    ttl=hrow["ttl"],
                    response_ms=hrow["response_ms"],
                    open_ports=json.loads(hrow["open_ports"] or "[]"),
                    detected_at=hrow["detected_at"] or "",
                )
            )
        return scan
