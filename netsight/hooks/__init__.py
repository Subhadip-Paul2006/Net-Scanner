"""Post-scan lifecycle hooks extension point (v1.1+)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netsight.models import ScanResult


def run_post_scan_hooks(scan: ScanResult, scan_id: int | None = None) -> None:
    """Execute post-scan callbacks (alerts, webhooks, diff engine)."""
    # Extension stub for future integrations
    pass
