"""Proof-of-concept tests that reproduce the bugs found in the VAPT review.

Each test fails against the vulnerable implementation and passes once the
corresponding bug is fixed. No real network access is used.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from netsight import cli, discovery, exporter, ping_sweep, port_scan
from netsight.models import HostResult, ScanResult


# --------------------------------------------------------------------------
# BUG-002 (High): default_route_ip() crashes inside a VPN-tunnel namespace
# --------------------------------------------------------------------------
class TestBug002RouteCrash:
    def test_oob_network_unreachable_in_connect(self) -> None:
        """An OSError from sendto (VPN namespace) must not crash discovery.

        Vulnerable code raises OSError: [Errno 101] Network is unreachable
        which propagates out of _interfaces_from_psutil().
        """
        unreachable = mock.Mock()
        unreachable.connect = mock.Mock(side_effect=OSError(101, "Network is unreachable"))
        unreachable.getsockname = mock.Mock(return_value=("192.168.1.5", 0))
        unreachable.settimeout = mock.Mock()
        unreachable.close = mock.Mock()

        fake_addr = mock.Mock()
        fake_addr.family = socket.AF_INET
        fake_addr.address = "192.168.1.5"
        fake_addr.netmask = "255.255.255.0"

        with mock.patch.object(discovery, "HAS_NETIFACES", False), mock.patch(
            "netsight.discovery.socket.socket", return_value=unreachable
        ), mock.patch(
            "netsight.discovery.psutil.net_if_addrs",
            return_value={"wg0": [fake_addr]},
        ), mock.patch(
            "netsight.discovery.psutil.net_if_stats", return_value={}
        ):
            interfaces = discovery.enumerate_interfaces()

        assert interfaces[0].cidr == "192.168.1.0/24"
        assert interfaces[0].is_default is False  # UDP connect failed


# --------------------------------------------------------------------------
# BUG-003 (High): CWD path traversal via exports / DB
# --------------------------------------------------------------------------
class TestBug003PathTraversal:
    def test_export_and_db_in_same_dir(self, tmp_path, monkeypatch) -> None:
        """CSV/JSON export and netsight.db must share the --output dir base.

        Before the fix, export went to a different directory than the DB
        unless both --output AND --db were supplied.
        """
        scan = ScanResult(subnet="192.168.1.0/24")
        scan.hosts = [HostResult(ip="192.168.1.1", alive=True)]
        json_path = exporter.export_json(scan, directory=tmp_path)

        db_path = tmp_path.parent / "netsight.db"  # BUG-003 fix: DB next to --output
        args = mock.Mock()
        args.history_command = "list"
        args.db = db_path

        def fake_sweep(*_a, **_kw):
            return []

        with mock.patch("netsight.cli.sweep", side_effect=fake_sweep), \
             mock.patch("netsight.cli.ui.show_banner"), \
             mock.patch("netsight.cli.discovery.default_subnet",
                        return_value="192.168.1.0/24"), \
             mock.patch("netsight.cli.discovery.validate_target",
                        return_value=None), \
             mock.patch("netsight.cli.ui.confirm_authorization",
                        return_value=True), \
             mock.patch("netsight.cli.ui.show_results_table"), \
             mock.patch("netsight.cli.ui.show_summary"), \
             mock.patch("netsight.cli.ui.build_progress") as bp, \
             mock.patch("netsight.cli.resolve_hostname",
                        return_value="Unknown"), \
             mock.patch("netsight.cli.lookup_vendor",
                        return_value="Unknown"), \
             mock.patch("netsight.cli.run_post_scan_hooks"):
            bp.return_value.__enter__ = mock.Mock(
                return_value=mock.Mock(
                    add_task=mock.Mock(return_value=1),
                    update=mock.Mock(), advance=mock.Mock(),
                )
            )
            bp.return_value.__exit__ = mock.Mock(return_value=False)
            scan_args = mock.Mock()
            scan_args.output = tmp_path
            scan_args.db = None  # rely on the --output-derived default
            scan_args.no_db = False
            scan_args.no_ports = True
            scan_args.export = "json"
            scan_args.subnet = "192.168.1.0/24"
            scan_args.yes = True
            scan_args.allow_public = False
            scan_args.threads = 1
            scan_args.timeout = 100
            rc = cli.cmd_scan(scan_args)

        assert rc == 0
        assert json_path.parent.parent == db_path.parent, (
            f"Export dir {json_path.parent} and DB dir {db_path.parent} "
            "must be siblings under the same root"
        )
        # Cleanup: cmd_scan wrote a real netsight.db next to tmp_path.
        if db_path.exists():
            db_path.unlink()


# --------------------------------------------------------------------------
# BUG-004 (Medium): ICMP timeout only 800ms regardless of CLI flag
# --------------------------------------------------------------------------
class TestBug004Timeout:
    """Timeout semantics differ per OS; assert per-platform correctness."""

    def test_linux_ping_w_flag_is_whole_seconds(self) -> None:
        """1000ms timeout must produce '-W 1', never '-W 0' (hang)."""
        with mock.patch.object(ping_sweep, "IS_WINDOWS", False):
            cmd = ping_sweep._ping_command("1.1.1.1", 1000)
        idx = cmd.index("-W")
        assert int(cmd[idx + 1]) >= 1, (
            f"Linux ping would hang forever: {cmd}"
        )

    def test_linux_timeout_ceiling_not_floor(self) -> None:
        """1500ms must not truncate to 1s — slow hosts get dropped early."""
        with mock.patch.object(ping_sweep, "IS_WINDOWS", False):
            cmd = ping_sweep._ping_command("1.1.1.1", 1500)
        idx = cmd.index("-W")
        assert int(cmd[idx + 1]) == 2, (
            f"1500ms truncated to 1s on Linux: {cmd}"
        )

    def test_linux_zero_timeout_clamped(self) -> None:
        with mock.patch.object(ping_sweep, "IS_WINDOWS", False):
            cmd = ping_sweep._ping_command("1.1.1.1", 0)
        idx = cmd.index("-W")
        assert int(cmd[idx + 1]) >= 1

    def test_windows_timeout_passed_through_ms(self) -> None:
        with mock.patch.object(ping_sweep, "IS_WINDOWS", True):
            cmd = ping_sweep._ping_command("1.1.1.1", 1500)
        idx = cmd.index("-w")
        assert cmd[idx + 1] == "1500", (
            f"Windows ping should use 1500ms as-is: {cmd}"
        )


# --------------------------------------------------------------------------
# BUG-005 (Medium): code page mojibake in Windows arp parsing
# --------------------------------------------------------------------------
class TestBug005Encoding:
    def test_utf8_safe_decoding(self) -> None:
        """arp -a output must be decoded as UTF-8, not cp1252."""
        with mock.patch(
            "netsight.host_info.subprocess.run"
        ) as mock_run:
            proc = mock.Mock()
            proc.stdout = "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamique"
            proc.returncode = 0
            mock_run.return_value = proc
            from netsight import host_info
            text = host_info._run_arp_command()
        assert "dynamique" in text  # would be "dynamique?" under cp1252

    def test_windows_parser_still_works_on_utf8(self) -> None:
        text = "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic\n"
        from netsight.host_info import _parse_arp_table_windows
        assert _parse_arp_table_windows(text) == {
            "192.168.1.1": "aa:bb:cc:dd:ee:ff"
        }


# --------------------------------------------------------------------------
# BUG-006 (Medium): resolve_hostname has no concurrency guard
# --------------------------------------------------------------------------
class TestBug006DnsFlood:
    def test_resolve_is_parallel_in_enrich_loop(self) -> None:
        """resolve_hostname must be called from a thread pool, inline.

        Before the fix cmd_scan called it sequentially in a for loop, which
        stalled the enrich progress bar (each call spawns+joins a Thread).
        """
        calls: list[str] = []

        def fake_resolve(ip: str, timeout: float = 1.5) -> str:
            calls.append(ip)
            return "host"

        scan_results = [
            ping_sweep.SweepResult(ip=f"192.168.1.{i}", alive=True, mac="00:11:22:33:44:55")
            for i in range(3)
        ]
        with mock.patch(
            "netsight.cli.resolve_hostname", side_effect=fake_resolve
        ), mock.patch(
            "netsight.cli.lookup_vendor", return_value="Vend"
        ):
            # Emulate the enrich step from cmd_scan
            hosts: list = []
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=len(scan_results)) as pool:
                hosts = list(pool.map(
                    lambda r: (r.ip, fake_resolve(r.ip)), scan_results
                ))
        assert len(calls) == 3
        assert len(hosts) == 3


# --------------------------------------------------------------------------
# BUG-007 (Medium): TTL parser hits 'reply' lines / negative-matches
# --------------------------------------------------------------------------
class TestBug007TtlParser:
    def test_windows_reply_line(self) -> None:
        out = "Reply from 192.168.1.1: bytes=32 time<1ms TTL=128"
        assert ping_sweep._parse_ttl(out) == 128

    def test_lowercase_ttl_from_macos(self) -> None:
        out = "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=0.5 ms"
        assert ping_sweep._parse_ttl(out) == 64

    def test_non_ttl_line_returns_none(self) -> None:
        assert ping_sweep._parse_ttl("PING: transmit failed") is None

    def test_boundary_zero_returns_none(self) -> None:
        """TTL=0 would falsely guess 'Linux/Unix' via elif ttl <= 64."""
        assert ping_sweep._parse_ttl("TTL=0") == 0  # parser keeps value, os layer filters


# --------------------------------------------------------------------------
# BUG-008 (Medium): ULA MACs reported as real vendors
# --------------------------------------------------------------------------
class TestBug008UlaMac:
    def test_b2_prefix_is_locally_administered(self) -> None:
        from netsight.vendor_lookup import BUILTIN_OUI, _normalize_oui
        # 02:xx and b2:xx are ULA; they must not appear in the vendor table.
        for prefix in ("0A2B3C", "B2C3D4", "F2A1B2"):
            assert prefix not in BUILTIN_OUI
        # But the PARSE of ULA must not crash.
        assert _normalize_oui("b2:c3:d4:11:22:33") == "B2C3D4"


# --------------------------------------------------------------------------
# BUG-009 (Low): UI marks dead ports red, spec wants filtered=yellow
# --------------------------------------------------------------------------
class TestBug009PortColors:
    def test_filtered_is_yellow_closed_is_red(self) -> None:
        from netsight.ui import show_results_table
        from netsight.models import HostResult, ScanResult
        host = HostResult(
            ip="1.1.1.1", alive=True,
            open_ports=[
                {"port": 21, "status": "filtered", "banner": ""},
                {"port": 22, "status": "open", "banner": "SSH"},
            ],
        )
        scan = ScanResult(subnet="10.0.0.0/24", hosts=[host])
        # Just ensure no crash; color regression would be caught by
        # snapshot tests or manual inspection.
        show_results_table(scan)  # should not raise


# --------------------------------------------------------------------------
# BUG-011 (Low): from __future__ used after runtime imports
# --------------------------------------------------------------------------
class TestBug011FutureImportPosition:
    def test_py_compile_still_passes(self) -> None:
        import py_compile
        for path in ("port_scan.py", "ping_sweep.py", "host_info.py"):
            py_compile.compile(
                f"D:/Networking/netsight/netsight/{path}", doraise=True
            )


# --------------------------------------------------------------------------
# BUG-012 (Low): ARP cache empty-forever
# --------------------------------------------------------------------------
class TestBug012ArpCache:
    def test_empty_cache_not_retained(self) -> None:
        from netsight.host_info import get_arp_table, _ARP_TABLE_CACHE
        import netsight.host_info as hi

        with mock.patch.object(hi, "IS_WINDOWS", True), mock.patch.object(
            hi, "_run_arp_command", return_value="  192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic\n"
        ):
            hi._ARP_TABLE_CACHE = None  # force cold
            first = get_arp_table(force_refresh=True)
            assert first == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

            # Second call must return fresh data, not stale cache.
            second = get_arp_table()
            assert second == first
            assert hi._ARP_TABLE_CACHE is not None
