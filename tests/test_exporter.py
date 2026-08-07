"""Unit tests for netsight.exporter — writes to a tmp dir only."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from netsight import exporter
from netsight.models import HostResult, ScanResult


def _sample_scan() -> ScanResult:
    scan = ScanResult(subnet="192.168.1.0/24", duration_s=1.5)
    scan.hosts = [
        HostResult(
            ip="192.168.1.1",
            alive=True,
            hostname="router.local",
            mac="00:11:22:33:44:55",
            vendor="Netgear",
            os_guess="Network device / embedded",
            ttl=255,
            response_ms=1.2,
            open_ports=[
                {"port": 80, "banner": "HTTP/1.1 200 OK"},
                {"port": 443, "banner": ""},
            ],
        ),
        HostResult(
            ip="192.168.1.10",
            alive=True,
            hostname="laptop",
            open_ports=[],
        ),
    ]
    return scan


class TestJsonExport:
    def test_json_round_trip(self, tmp_path: Path) -> None:
        scan = _sample_scan()
        path = exporter.export_json(scan, directory=tmp_path)

        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["subnet"] == "192.168.1.0/24"
        assert data["host_count"] == 2
        assert data["open_port_count"] == 2
        assert len(data["hosts"]) == 2
        assert data["hosts"][0]["ip"] == "192.168.1.1"
        assert data["hosts"][0]["open_ports"][0]["banner"] == "HTTP/1.1 200 OK"
        assert "exported_at" in data

    def test_default_filename_is_timestamped(self, tmp_path: Path) -> None:
        path = exporter.export_json(_sample_scan(), directory=tmp_path)
        assert path.name.startswith("netsight_scan_")
        assert path.suffix == ".json"


class TestCsvExport:
    def test_csv_rows_one_per_host_port(self, tmp_path: Path) -> None:
        scan = _sample_scan()
        path = exporter.export_csv(scan, directory=tmp_path)

        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))

        # Host .1 has 2 open ports -> 2 rows; host .10 no ports -> 1 row.
        assert len(rows) == 3
        header = rows[0].keys()
        for field in ("ip", "hostname", "mac", "vendor", "os_guess",
                      "port", "banner"):
            assert field in header

        first = rows[0]
        assert first["ip"] == "192.168.1.1"
        assert first["port"] == "80"
        assert first["banner"] == "HTTP/1.1 200 OK"

        no_ports_row = rows[-1]
        assert no_ports_row["ip"] == "192.168.1.10"
        assert no_ports_row["port"] == ""

    def test_csv_creates_output_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "exports"
        path = exporter.export_csv(_sample_scan(), directory=target)
        assert path.exists()


class TestExportScan:
    def test_multiple_formats(self, tmp_path: Path) -> None:
        scan = _sample_scan()
        written = exporter.export_scan(scan, ["csv", "json"], tmp_path)
        assert len(written) == 2
        suffixes = {p.suffix for p in written}
        assert suffixes == {".csv", ".json"}
        for path in written:
            assert path.exists()

    def test_unknown_format_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            exporter.export_scan(_sample_scan(), ["xml"], tmp_path)
