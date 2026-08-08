"""Tests for Plan2 / v2.0 additions: latency class, vuln hints, PDF export,
multi-subnet sweeps, dashboard charts."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from netsight import exporter, ping_sweep
from netsight.models import HostResult, MultiScanResult, ScanResult
from netsight.pdf_report import export_pdf


class TestModelsV2:
    def test_latency_class_boundaries(self) -> None:
        assert HostResult(ip="x", response_ms=None).latency_class == "unknown"
        assert HostResult(ip="x", response_ms=3.0).latency_class == "excellent"
        assert HostResult(ip="x", response_ms=25.0).latency_class == "good"
        assert HostResult(ip="x", response_ms=200.0).latency_class == "poor"

    def test_vuln_hints_risky_ports(self) -> None:
        host = HostResult(ip="x", open_ports=[
            {"port": 445}, {"port": 3389}, {"port": 80},
        ])
        hints = host.vuln_hints
        assert any("SMB" in h or "ransomware" in h for h in hints)
        assert any("RDP" in h for h in hints)
        assert not any("80" in h for h in hints)  # HTTP not on the risky list

    def test_latency_and_hints_ready(self) -> None:
        host = HostResult(
            ip="x", response_ms=10,
            open_ports=[{"port": 3306, "banner": ""}],
        )
        data = host.to_dict()
        assert data["latency_class"] == "good"
        assert any("MySQL" in h for h in data["vuln_hints"])

    def test_multi_scan_result_merges_hosts(self) -> None:
        a = ScanResult(subnet="192.168.1.0/24")
        a.hosts = [HostResult(ip="192.168.1.1", alive=True)]
        b = ScanResult(subnet="10.0.0.0/24")
        b.hosts = [HostResult(ip="10.0.0.5", alive=True)]
        multi = MultiScanResult(children=[a, b])
        multi.hosts.extend(a.hosts + b.hosts)
        assert len(multi.alive_hosts) == 2
        assert multi.subnet == "multi"


class TestMultiSubnetSweep:
    def test_sweep_multi_merges_results(self) -> None:
        with mock.patch.object(ping_sweep, "sweep") as mock_sweep:
            def fake_sweep(cidr, *_a, **_kw):
                return [
                    ping_sweep.SweepResult(
                        ip=f"{cidr.split('/')[0].rsplit('.', 1)[0]}.1",
                        alive=True,
                    )
                ]
            mock_sweep.side_effect = fake_sweep
            results = ping_sweep.sweep_multi(
                ["192.168.1.0/24", "10.0.0.0/24"], max_workers=2
            )
        assert len(results) == 2
        ips = {r.ip for r in results}
        assert ips == {"192.168.1.1", "10.0.0.1"}

    def test_sweep_multi_empty_list(self) -> None:
        assert ping_sweep.sweep_multi([]) == []


class TestPdfExport:
    def test_pdf_is_wellformed(self, tmp_path: Path) -> None:
        scan = ScanResult(subnet="10.0.0.0/24", duration_s=1.0)
        scan.hosts = [HostResult(ip="10.0.0.1", alive=True)]
        path = export_pdf(scan, directory=tmp_path)
        assert path.suffix == ".pdf"
        raw = path.read_bytes()
        assert raw.startswith(b"%PDF-1.4")
        assert b"%%EOF" in raw

    def test_pdf_via_export_scan(self, tmp_path: Path) -> None:
        scan = ScanResult(subnet="10.0.0.0/24", duration_s=1.0)
        written = exporter.export_scan(scan, ["pdf"], tmp_path)
        assert len(written) == 1 and written[0].suffix == ".pdf"

    def test_pdf_with_unicode_hosts(self, tmp_path: Path) -> None:
        scan = ScanResult(subnet="192.168.0.0/24", duration_s=1.0)
        scan.hosts = [HostResult(
            ip="192.168.0.1", alive=True, hostname="வணக்கம்",  # Tamil
        )]
        path = export_pdf(scan, directory=tmp_path)
        assert path.exists()  # must not raise on unicode


# Dashboard chart: ensure the index route includes SVG when scans exist.
class TestDashboardChart:
    def test_index_contains_svg_after_scan(self) -> None:
        pytest.importorskip("flask")
        from netsight.dashboard import create_app
        from netsight.history_db import HistoryDB

        db_file = Path("netsight.db")
        with HistoryDB(db_file) as db:
            scan = ScanResult(subnet="192.168.1.0/24", duration_s=0.1)
            db.save_scan(scan)

        try:
            app = create_app(db_file)
            app.config["TESTING"] = True
            client = app.test_client()
            resp = client.get("/")
            assert resp.status_code == 200
            assert b"<svg" in resp.data or b"Hosts discovered over time" in resp.data
        finally:
            if db_file.exists():
                db_file.unlink()
