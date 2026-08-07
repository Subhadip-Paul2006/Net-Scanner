"""MAC OUI -> vendor lookup.

Uses the ``mac-vendor-lookup`` package when installed; otherwise falls back
to a small bundled OUI prefix table so the feature still works offline.
"""

from __future__ import annotations

import re

try:
    from mac_vendor_lookup import MacLookup  # type: ignore

    HAS_MAC_VENDOR_LOOKUP = True
except ImportError:  # pragma: no cover - optional dependency
    MacLookup = None  # type: ignore[assignment]
    HAS_MAC_VENDOR_LOOKUP = False

_LOOKUP = None
_LOOKUP_FAILED = False

#: Small bundled OUI table (first 3 bytes, uppercase hex without separators).
#: Kept intentionally compact — full IEEE OUI data is available via the
#: optional ``mac-vendor-lookup`` package.
BUILTIN_OUI: dict[str, str] = {
    "000C29": "VMware",
    "000569": "VMware",
    "001C42": "Parallels",
    "080027": "VirtualBox",
    "0050F2": "Microsoft",
    "00155D": "Microsoft Hyper-V",
    "525400": "QEMU/KVM",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "F0D1A9": "Apple",
    "3CE072": "Apple",
    "A4B197": "Apple",
    "F8FFB8": "Apple",
    "001B63": "Apple",
    "ACDE48": "Apple",
    "0017F2": "Apple",
    "A0999B": "Apple",
    "001D4F": "Apple",
    "7C6D62": "Apple",
    "001CB3": "Apple",
    "D49A20": "Apple",
    "98D6BB": "Apple",
    "F0B479": "Apple",
    "C0847D": "Apple",
    "6C96CF": "Apple",
    "A88808": "Apple",
    "341298": "Samsung",
    "8CC8CD": "Samsung",
    "E8508B": "Samsung",
    "5C0A5B": "Samsung",
    "0016DB": "Samsung",
    "E432CB": "Samsung",
    "9CD35B": "Samsung",
    "C8BA94": "Samsung",
    "001EE1": "Samsung",
    "4844F7": "Samsung Electronics",
    "002454": "Nokia",
    "48D705": "Xiaomi",
    "64B473": "Xiaomi",
    "F4F5DB": "Xiaomi",
    "34CE00": "Xiaomi",
    "98F170": "Xiaomi",
    "0C1DAF": "Xiaomi",
    "9C2EA1": "Intel",
    "F4FCE4": "Intel",
    "8086F2": "Intel",
    "A4C494": "Intel",
    "0013E8": "Intel Corporate",
    "847BEB": "HP",
    "E83935": "HP",
    "C4346B": "HP",
    "9C8E99": "HP",
    "D85D4C": "TP-Link",
    "50C7BF": "TP-Link",
    "14CF92": "Huawei",
    "C8D15E": "Huawei",
    "C8D73D": "Huawei",
    "00E0FC": "Huawei",
    "04C06F": "Huawei",
    "84A9C4": "Huawei",
    "1CDEA7": "Cisco",
    "00163E": "Cisco",
    "FCFBFB": "Cisco",
    "D48CB5": "Cisco",
    "00155F": "Cisco",
    "6C9989": "D-Link",
    "BCF685": "D-Link",
    "C8BE19": "D-Link",
    "1C7EE5": "D-Link",
    "28107B": "D-Link",
    "F0B4D2": "D-Link",
    "E46F13": "Netgear",
    "204E71": "Netgear",
    "A42BB0": "Netgear",
    "C04A00": "Netgear",
    "9C3DCF": "Netgear",
    "744401": "Netgear",
    "B03956": "Intel Corporate",
    "8C705A": "LG Electronics",
    "BC5FF4": "LG Electronics",
    "A816D0": "Samsung Electronics",
    "CC6EA4": "Samsung Electronics",
    "B0DF3A": "Samsung Electronics",
    "0022B0": "Samsung Electronics",
    "9C2E70": "Samsung Electronics",
    "24C696": "Samsung Electronics",
    "ECB1D7": "Samsung Electronics",
    "001E13": "Hewlett Packard",
    "0024E8": "Hewlett Packard Enterprise",
    "F4CE46": "Hewlett Packard Enterprise",
    "3CD92B": "Hewlett Packard Enterprise",
    "9CB654": "Hewlett Packard",
    "B499BA": "Dell",
    "D4AE52": "Dell",
    "74867A": "Dell",
    "E4B97A": "Dell",
    "F4E9D4": "Intel Corporate",
    "001CC0": "Liteon Technology",
    "C8F650": "Intel Corporate",
    "0060E0": "Fujitsu",
    "0021E9": "Fujitsu",
    "8CEE48": "Acer",
    "A0AFBD": "Acer",
    "B8AC6F": "Acer",
    "0025AB": "Acer",
    "A83241": "Sony",
    "F8D0AC": "Sony",
    "50EB71": "Sony",
    "84C7EA": "Sony",
    "001A75": "Sony",
    "B8415D": "Sony",
    "30F7C5": "Microsoft",
    "7C1E52": "Microsoft",
    "2818FD": "Microsoft",
    "6045BD": "Microsoft",
    "C83F26": "Microsoft",
    "28E347": "Microsoft",
    "002248": "Microsoft",
}


def _normalize_oui(mac: str) -> str | None:
    """Extract the uppercase 6-hex-digit OUI prefix from a MAC address."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) < 6:
        return None
    return cleaned[:6].upper()


def _get_full_lookup():
    """Lazily instantiate the mac-vendor-lookup client, if installed."""
    global _LOOKUP, _LOOKUP_FAILED
    if not HAS_MAC_VENDOR_LOOKUP or _LOOKUP_FAILED:
        return None
    if _LOOKUP is None:
        try:
            _LOOKUP = MacLookup()
        except Exception:  # noqa: BLE001 - constructor may hit network/disk
            _LOOKUP_FAILED = True
            return None
    return _LOOKUP


def lookup_vendor(mac: str) -> str:
    """Resolve a MAC address to its vendor name.

    Args:
        mac: MAC address in any common format.

    Returns:
        Vendor name, or ``"Unknown"`` when not resolvable.
    """
    if not mac or mac.lower() in ("unknown", ""):
        return "Unknown"

    lookup = _get_full_lookup()
    if lookup is not None:
        try:
            vendor: str = lookup.lookup(mac)
            if vendor:
                return vendor
        except Exception:  # noqa: BLE001 - network/db errors degrade silently
            pass

    oui = _normalize_oui(mac)
    if oui is not None and oui in BUILTIN_OUI:
        return BUILTIN_OUI[oui]
    return "Unknown"
