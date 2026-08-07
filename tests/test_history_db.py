"""Unit tests for netsight.history_db — uses a tmp sqlite file."""

from __future__ import annotations

from pathlib import Path

from netsight.history_db import HistoryDB
from netsight.models import HostResult, ScanResult


def _sample_scan() -> ScanResult:
    scan = ScanResult(subnet="192.168.1.0/24", duration_s=2.5)
    scan.hosts = [
        HostResult(
            ip="192.168.1.1",
            alive=True,
            hostname="router",
            mac="aa:bb:cc:dd:ee:ff",
            vendor="Netgear",
            os_guess="Network device / embedded",
            ttl=255,
            response_ms=0.8,
            open_ports=[{"port": 80, "banner": "HTTP/1.1 200 OK"}],
        ),
        HostResult(ip="192.168.1.99", alive=False),
    ]
    return scan


class TestHistoryDB:
    def test_save_and_list(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test.db"
        with HistoryDB(db_file) as db:
            scan_id = db.save_scan(_sample_scan())
            assert scan_id >= 1

            rows = db.list_scans()
            assert len(rows) == 1
            assert rows[0]["subnet"] == "192.168.1.0/24"
            assert rows[0]["host_count"] == 1  # alive hosts only

    def test_get_scan_round_trip(self, tmp_path: Path) -> None:
        db_file = tmp_path / "test.db"
        with HistoryDB(db_file) as db:
            scan_id = db.save_scan(_sample_scan())
            loaded = db.get_scan(scan_id)

        assert loaded is not None
        assert loaded.subnet == "192.168.1.0/24"
        assert len(loaded.hosts) == 2
        host = next(h for h in loaded.hosts if h.ip == "192.168.1.1")
        assert host.hostname == "router"
        assert host.open_ports == [
            {"port": 80, "banner": "HTTP/1.1 200 OK"}
        ]
        dead = next(h for h in loaded.hosts if h.ip == "192.168.1.99")
        assert dead.alive is False

    def test_get_missing_scan_returns_none(self, tmp_path: Path) -> None:
        with HistoryDB(tmp_path / "test.db") as db:
            assert db.get_scan(9999) is None

    def test_multiple_scans_are_separate(self, tmp_path: Path) -> None:
        with HistoryDB(tmp_path / "test.db") as db:
            first = db.save_scan(_sample_scan())
            second = db.save_scan(_sample_scan())
            assert second > first
            rows = db.list_scans()
            assert len(rows) == 2
            # Most recent first.
            assert rows[0]["id"] == second
