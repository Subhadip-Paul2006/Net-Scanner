"""Unit tests for netsight.port_scan — sockets are mocked, nothing real."""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from netsight import port_scan


class TestParsePorts:
    def test_common_keyword(self) -> None:
        ports = port_scan.parse_ports("common")
        assert ports == port_scan.COMMON_PORTS
        assert 80 in ports and 443 in ports and 22 in ports

    def test_single_port(self) -> None:
        assert port_scan.parse_ports("443") == [443]

    def test_list_and_range(self) -> None:
        assert port_scan.parse_ports("22,80,8080-8082") == [22, 80, 8080, 8081, 8082]

    def test_deduplicates_and_sorts(self) -> None:
        assert port_scan.parse_ports("443,80,443") == [80, 443]

    def test_invalid_port_raises(self) -> None:
        with pytest.raises(ValueError):
            port_scan.parse_ports("0")
        with pytest.raises(ValueError):
            port_scan.parse_ports("70000")
        with pytest.raises(ValueError):
            port_scan.parse_ports("notaport")

    def test_reversed_range_raises(self) -> None:
        with pytest.raises(ValueError):
            port_scan.parse_ports("100-50")


class _FakeSock:
    """Minimal socket stand-in for open-port branches."""

    def __init__(self, banner: bytes = b"") -> None:
        self._banner = banner
        self.sent: list[bytes] = []

    def settimeout(self, _t: float) -> None:
        return None

    def getpeername(self) -> tuple[str, int]:
        return ("192.168.1.10", 22)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _n: int) -> bytes:
        return self._banner

    def __enter__(self) -> "_FakeSock":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class TestScanPort:
    def test_open_port_with_banner(self) -> None:
        fake = _FakeSock(banner=b"SSH-2.0-OpenSSH_9.6\r\n")
        with mock.patch(
            "netsight.port_scan.socket.create_connection", return_value=fake
        ):
            result = port_scan.scan_port("192.168.1.10", 22)
        assert result.status == "open"
        assert "OpenSSH" in result.banner

    def test_closed_port(self) -> None:
        with mock.patch(
            "netsight.port_scan.socket.create_connection",
            side_effect=ConnectionRefusedError,
        ):
            result = port_scan.scan_port("192.168.1.10", 81)
        assert result.status == "closed"

    def test_filtered_port_on_timeout(self) -> None:
        with mock.patch(
            "netsight.port_scan.socket.create_connection",
            side_effect=socket.timeout,
        ):
            result = port_scan.scan_port("192.168.1.10", 81)
        assert result.status == "filtered"

    def test_oserror_treated_as_filtered(self) -> None:
        with mock.patch(
            "netsight.port_scan.socket.create_connection",
            side_effect=OSError("no route to host"),
        ):
            result = port_scan.scan_port("192.168.1.10", 81)
        assert result.status == "filtered"


class TestScanHost:
    def test_aggregate_results(self) -> None:
        def fake_scan_port(ip: str, port: int, timeout: float,
                           banner: bool) -> port_scan.PortResult:
            status = "open" if port in (22, 80) else "closed"
            return port_scan.PortResult(port=port, status=status)

        with mock.patch(
            "netsight.port_scan.scan_port", side_effect=fake_scan_port
        ):
            result = port_scan.scan_host("192.168.1.10", [22, 80, 81, 82])

        assert result.open_ports == [22, 80]
        assert len(result.ports) == 4
        # Results sorted by port regardless of completion order.
        assert [p.port for p in result.ports] == [22, 80, 81, 82]

    def test_progress_callback_invoked(self) -> None:
        calls: list[tuple[int, int]] = []

        def fake_scan_port(ip: str, port: int, timeout: float,
                           banner: bool) -> port_scan.PortResult:
            return port_scan.PortResult(port=port, status="closed")

        with mock.patch(
            "netsight.port_scan.scan_port", side_effect=fake_scan_port
        ):
            port_scan.scan_host(
                "192.168.1.10",
                [22, 80],
                progress_callback=lambda done, total: calls.append((done, total)),
            )

        assert len(calls) == 2
        assert all(total == 2 for _, total in calls)

    def test_worker_exception_never_raises(self) -> None:
        with mock.patch(
            "netsight.port_scan.scan_port", side_effect=RuntimeError("boom")
        ):
            result = port_scan.scan_host("192.168.1.10", [22])
        assert result.ports[0].status == "filtered"
