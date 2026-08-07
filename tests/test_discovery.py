"""Unit tests for netsight.discovery — all network calls are mocked."""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from netsight import discovery


class TestCidrFromIpNetmask:
    def test_24_network(self) -> None:
        assert (
            discovery.cidr_from_ip_netmask("192.168.1.10", "255.255.255.0")
            == "192.168.1.0/24"
        )

    def test_16_network(self) -> None:
        assert (
            discovery.cidr_from_ip_netmask("10.20.30.40", "255.255.0.0")
            == "10.20.0.0/16"
        )

    def test_invalid_input_raises(self) -> None:
        with pytest.raises(ValueError):
            discovery.cidr_from_ip_netmask("999.1.1.1", "255.255.255.0")


class TestPrivateTargetChecks:
    @pytest.mark.parametrize(
        "cidr",
        ["10.0.0.0/8", "172.16.5.0/24", "192.168.1.0/24", "127.0.0.0/8"],
    )
    def test_private_ranges_accepted(self, cidr: str) -> None:
        assert discovery.is_private_target(cidr) is True

    @pytest.mark.parametrize(
        "cidr", ["8.8.8.0/24", "1.1.1.0/24", "203.0.113.0/24"]
    )
    def test_public_ranges_rejected(self, cidr: str) -> None:
        assert discovery.is_private_target(cidr) is False

    def test_invalid_cidr_rejected(self) -> None:
        assert discovery.is_private_target("not-a-cidr") is False


class TestValidateTarget:
    def test_valid_private_target(self) -> None:
        assert discovery.validate_target("192.168.1.0/24") is None

    def test_public_target_rejected(self) -> None:
        reason = discovery.validate_target("8.8.8.0/24")
        assert reason is not None
        assert "not in a private" in reason

    def test_public_target_allowed_with_flag(self) -> None:
        assert discovery.validate_target("8.8.8.0/24", allow_public=True) is None

    def test_oversized_target_rejected(self) -> None:
        reason = discovery.validate_target("10.0.0.0/8")
        assert reason is not None
        assert "maximum" in reason

    def test_invalid_target_rejected(self) -> None:
        assert discovery.validate_target("junk") is not None

    def test_ipv6_rejected(self) -> None:
        assert discovery.validate_target("fd00::/64") is not None


class TestEnumerateInterfaces:
    def test_psutil_fallback_enumeration(self) -> None:
        """psutil path: mock net_if_addrs/net_if_stats/default route."""
        addr = socket.AddressInfo if hasattr(socket, "AddressInfo") else tuple
        fake_addr = mock.Mock()
        fake_addr.family = socket.AF_INET
        fake_addr.address = "192.168.1.50"
        fake_addr.netmask = "255.255.255.0"

        fake_stats = mock.Mock()
        fake_stats.isup = True

        with mock.patch.object(discovery, "HAS_NETIFACES", False), mock.patch(
            "netsight.discovery.psutil.net_if_addrs",
            return_value={"Ethernet0": [fake_addr]},
        ), mock.patch(
            "netsight.discovery.psutil.net_if_stats",
            return_value={"Ethernet0": fake_stats},
        ), mock.patch(
            "netsight.discovery._default_route_ip",
            return_value="192.168.1.50",
        ):
            interfaces = discovery.enumerate_interfaces()

        assert len(interfaces) == 1
        assert interfaces[0].cidr == "192.168.1.0/24"
        assert interfaces[0].is_default is True

    def test_loopback_excluded(self) -> None:
        fake_addr = mock.Mock()
        fake_addr.family = socket.AF_INET
        fake_addr.address = "127.0.0.1"
        fake_addr.netmask = "255.0.0.0"

        with mock.patch.object(discovery, "HAS_NETIFACES", False), mock.patch(
            "netsight.discovery.psutil.net_if_addrs",
            return_value={"lo": [fake_addr]},
        ), mock.patch(
            "netsight.discovery.psutil.net_if_stats", return_value={}
        ), mock.patch(
            "netsight.discovery._default_route_ip", return_value=None
        ):
            interfaces = discovery.enumerate_interfaces()

        assert interfaces == []

    def test_default_subnet_uses_default_interface(self) -> None:
        fake = discovery.InterfaceInfo(
            name="eth0",
            ip="10.0.0.5",
            netmask="255.255.255.0",
            cidr="10.0.0.0/24",
            is_default=True,
        )
        with mock.patch.object(
            discovery, "enumerate_interfaces", return_value=[fake]
        ):
            assert discovery.default_subnet() == "10.0.0.0/24"
