"""NetSight command-line interface.

Subcommands:
    scan     Full discovery: sweep, host info, optional port scan & export.
    quick    Fast overview: auto-detect subnet, ping sweep only.
    history  previous scans: ``history list`` / ``history show <id>``.

Safety: every active scan validates the target against RFC1918 ranges and
shows an authorization banner requiring confirmation (skip with --yes).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from netsight import discovery, exporter, history_db, ui
from netsight.hooks import run_post_scan_hooks
from netsight.host_info import resolve_hostname
from netsight.models import HostResult, ScanResult, utc_now_iso
from netsight.os_fingerprint import HAS_NMAP, deep_fingerprint, guess_os_from_ttl
from netsight.ping_sweep import sweep
from netsight.port_scan import parse_ports, scan_host
from netsight.vendor_lookup import lookup_vendor


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="netsight",
        description=(
            "NetSight — private-network discovery & device scanner. "
            "Only scan networks you own or have permission to test."
        ),
    )
    parser.add_argument(
        "--version", action="store_true", help="print version and exit"
    )
    sub = parser.add_subparsers(dest="command")

    # ---- netsight scan ----
    scan = sub.add_parser("scan", help="full discovery scan of a subnet")
    _add_scan_args(scan)

    # ---- netsight quick ----
    quick = sub.add_parser(
        "quick", help="fast overview: auto-detect subnet, sweep only"
    )
    quick.add_argument("--threads", type=int, default=64,
                       help="sweep thread count (default: 64)")
    quick.add_argument("--timeout", type=int, default=800,
                       help="per-host timeout in ms (default: 800)")
    quick.add_argument("-y", "--yes", action="store_true",
                       help="skip authorization confirmation")
    quick.add_argument("--allow-public", action="store_true",
                       help="allow non-RFC1918 targets (expert use only)")

    # ---- netsight history ----
    history = sub.add_parser("history", help="scan history operations")
    history_sub = history.add_subparsers(dest="history_command")
    history_sub.add_parser("list", help="list past scans")
    show = history_sub.add_parser("show", help="show a past scan by ID")
    show.add_argument("scan_id", type=int, help="scan ID from history list")
    show.add_argument("--export", metavar="FORMATS",
                      help="re-export to csv,json (comma separated)")
    for hp in (history_sub.choices["list"], history_sub.choices["show"]):
        hp.add_argument("--db", type=Path, default=Path("netsight.db"),
                        help="history database path (default: ./netsight.db)")

    return parser


def _add_scan_args(scan: argparse.ArgumentParser) -> None:
    """Register flags shared by the ``scan`` subcommand."""
    scan.add_argument("--subnet", help="target CIDR (default: auto-detect)")
    scan.add_argument("--ports", default="common",
                      help="'common', list '80,443', or range '1-1024' "
                           "(default: common)")
    scan.add_argument("--no-ports", action="store_true",
                      help="skip port scanning (discovery only)")
    scan.add_argument("--export", metavar="FORMATS",
                      help="export formats: csv,json (comma separated)")
    scan.add_argument("--output", type=Path, default=None,
                      help="export directory (default: ./exports)")
    scan.add_argument("--threads", type=int, default=64,
                      help="sweep thread count (default: 64)")
    scan.add_argument("--port-threads", type=int, default=100,
                      help="port-scan thread count (default: 100)")
    scan.add_argument("--timeout", type=int, default=800,
                      help="per-host timeout in ms (default: 800)")
    scan.add_argument("--deep-scan", action="store_true",
                      help="use nmap -O for OS detection (slow, needs admin)")
    scan.add_argument("-y", "--yes", action="store_true",
                      help="skip authorization confirmation")
    scan.add_argument("--allow-public", action="store_true",
                      help="allow non-RFC1918 targets (expert use only)")
    scan.add_argument("--no-db", action="store_true",
                      help="do not save this run to the history database")
    scan.add_argument("--db", type=Path, default=Path("netsight.db"),
                      help="history database path (default: ./netsight.db)")


def _pick_subnet(explicit: str | None) -> str | None:
    """Resolve the target subnet: explicit flag or interactive auto-detect."""
    if explicit:
        return explicit
    interfaces = discovery.enumerate_interfaces()
    if not interfaces:
        ui.error("No active IPv4 interfaces found.")
        return None
    if len(interfaces) == 1:
        return interfaces[0].cidr

    ui.show_interface_table(interfaces)
    default_idx = next(
        (i for i, f in enumerate(interfaces) if f.is_default), 0
    )
    raw = ui.console.input(
        f"Select interface [0-{len(interfaces) - 1}] "
        f"(default {default_idx}): "
    ).strip()
    if not raw:
        return interfaces[default_idx].cidr
    try:
        idx = int(raw)
        return interfaces[idx].cidr
    except (ValueError, IndexError):
        ui.error("Invalid selection.")
        return None


def _gate(cidr: str, *, auto_yes: bool, allow_public: bool) -> bool:
    """Run safety validation + consent. Returns False to abort."""
    reason = discovery.validate_target(cidr, allow_public=allow_public)
    if reason is not None:
        ui.error(reason)
        return False
    if not allow_public and not discovery.is_private_target(cidr):
        ui.warn(f"{cidr} is not RFC1918-private — scan refused.")
        return False
    ui.show_authorization_banner()
    if not ui.confirm_authorization(auto_yes=auto_yes):
        ui.warn("Authorization not confirmed — scan aborted.")
        return False
    return True


def cmd_quick(args: argparse.Namespace) -> int:
    """Fast sweep-only scan of the auto-detected local subnet."""
    ui.show_banner()
    cidr = discovery.default_subnet()
    if cidr is None:
        ui.error("Could not auto-detect a local subnet.")
        return 1
    ui.info(f"Auto-detected local subnet: [bold]{cidr}[/bold]")
    if not _gate(cidr, auto_yes=args.yes, allow_public=args.allow_public):
        return 2

    result = ScanResult(subnet=cidr)
    start = time.perf_counter()

    from netsight import ping_sweep

    with ui.build_progress("Sweeping subnet") as progress:
        task_id = progress.add_task("sweep", total=None)
        results = sweep(
            cidr,
            max_workers=args.threads,
            timeout_ms=args.timeout,
        )
        progress.update(task_id, total=1, completed=1)

    if ping_sweep.last_fallback_reason:
        ui.info(
            "ARP sweep unavailable (ICMP fallback): "
            + ping_sweep.last_fallback_reason
        )

    for res in results:
        result.hosts.append(
            HostResult(
                ip=res.ip,
                alive=True,
                mac=res.mac or "Unknown",
                ttl=res.ttl,
                response_ms=res.response_ms,
                os_guess=guess_os_from_ttl(res.ttl),
            )
        )

    result.finished_at = utc_now_iso()
    result.duration_s = time.perf_counter() - start
    ui.show_results_table(result)
    ui.show_summary(result)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Full scan: sweep, enrichment, port scan, export, history."""
    ui.show_banner()
    cidr = _pick_subnet(args.subnet)
    if cidr is None:
        return 1
    ui.info(f"Target subnet: [bold]{cidr}[/bold]")
    if not _gate(cidr, auto_yes=args.yes, allow_public=args.allow_public):
        return 2

    ports: list[int] = []
    if not args.no_ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            ui.error(str(exc))
            return 1

    if args.deep_scan and not HAS_NMAP:
        ui.warn("python-nmap not installed — falling back to TTL heuristics.")

    result = ScanResult(subnet=cidr)
    start = time.perf_counter()

    from netsight import ping_sweep

    # 1) Discover alive hosts.
    with ui.build_progress("Discovering hosts") as progress:
        task_id = progress.add_task("sweep", total=None)
        results = sweep(
            cidr,
            max_workers=args.threads,
            timeout_ms=args.timeout,
        )
        progress.update(task_id, total=1, completed=1)

    if ping_sweep.last_fallback_reason:
        ui.info(
            "ARP sweep unavailable (ICMP fallback): "
            + ping_sweep.last_fallback_reason
        )

    if not results:
        ui.warn("No alive hosts found.")
        result.finished_at = utc_now_iso()
        result.duration_s = time.perf_counter() - start
        ui.show_summary(result)
        return 0

    # 2) Enrich hosts: hostname, MAC vendor, OS guess.
    with ui.build_progress("Enriching hosts") as progress:
        task = progress.add_task("enrich", total=len(results))
        for res in results:
            host = HostResult(
                ip=res.ip,
                alive=True,
                mac=res.mac or "Unknown",
                ttl=res.ttl,
                response_ms=res.response_ms,
            )
            host.hostname = resolve_hostname(res.ip)
            host.vendor = lookup_vendor(host.mac)
            host.os_guess = guess_os_from_ttl(res.ttl)
            if args.deep_scan and HAS_NMAP:
                try:
                    host.os_guess = deep_fingerprint(res.ip)
                except RuntimeError as exc:
                    ui.warn(f"nmap OS scan skipped for {res.ip}: {exc}")
            result.hosts.append(host)
            progress.advance(task)

    # 3) Port scan each host.
    if ports:
        with ui.build_progress("Scanning ports") as progress:
            task = progress.add_task("ports", total=len(result.hosts))
            for host in result.hosts:
                scan_res = scan_host(
                    host.ip,
                    ports,
                    max_workers=args.port_threads,
                    timeout=1.0,
                )
                host.open_ports = [
                    {"port": p.port, "banner": p.banner}
                    for p in scan_res.open
                ]
                progress.advance(task)

    result.finished_at = utc_now_iso()
    result.duration_s = time.perf_counter() - start

    ui.show_results_table(result)
    ui.show_port_details(result)

    # 4) Persist + export.
    scan_id: int | None = None
    if not args.no_db:
        with history_db.HistoryDB(args.db) as db:
            scan_id = db.save_scan(result)
        run_post_scan_hooks(result, scan_id)

    ui.show_summary(result, scan_id=scan_id)

    if args.export:
        formats = [f for f in args.export.split(",") if f.strip()]
        try:
            written = exporter.export_scan(result, formats, args.output)
            for path in written:
                ui.success(f"Exported: {path}")
        except ValueError as exc:
            ui.error(str(exc))
            return 1
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """List past scans or show/re-export one by ID."""
    ui.show_banner()
    db_path = _db_path_from_args(args)
    with history_db.HistoryDB(db_path) as db:
        if args.history_command == "list":
            rows = db.list_scans()
            if not rows:
                ui.info("No scans recorded yet.")
                return 0
            ui.show_history_table(rows)
            return 0

        if args.history_command == "show":
            scan = db.get_scan(args.scan_id)
            if scan is None:
                ui.error(f"No scan with ID {args.scan_id}.")
                return 1
            ui.show_results_table(scan)
            ui.show_port_details(scan)
            ui.show_summary(scan, scan_id=args.scan_id)
            if args.export:
                formats = [f for f in args.export.split(",") if f.strip()]
                try:
                    written = exporter.export_scan(scan, formats)
                    for path in written:
                        ui.success(f"Re-exported: {path}")
                except ValueError as exc:
                    ui.error(str(exc))
                    return 1
            return 0

    ui.error("Specify a history subcommand: list | show <id>")
    return 1


def _db_path_from_args(args: argparse.Namespace) -> Path:
    """History DB path (history subcommands keep the default location)."""
    return Path(getattr(args, "db", None) or "netsight.db")


def main(argv: list[str] | None = None) -> int:
    """Program entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        from netsight import __version__

        print(__version__)
        return 0

    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "quick":
            return cmd_quick(args)
        if args.command == "history":
            return cmd_history(args)
    except KeyboardInterrupt:
        ui.warn("Interrupted by user.")
        return 130

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
