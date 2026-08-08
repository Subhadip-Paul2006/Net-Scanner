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
    quick.add_argument("--log-file", type=Path, default=None, metavar="PATH",
                       help="append structured JSON logs to PATH")

    # ---- netsight diff ----
    diff = sub.add_parser("diff", help="compare two history scans")
    diff.add_argument("old_id", type=int, help="older scan ID")
    diff.add_argument("new_id", type=int, help="newer scan ID")
    diff.add_argument("--db", type=Path, default=Path("netsight.db"),
                      help="history database path")

    # ---- netsight label ----
    label = sub.add_parser("label", help="device labels: set/list/remove")
    label_sub = label.add_subparsers(dest="label_command", required=True)
    label_set = label_sub.add_parser("set", help="label a device")
    label_set.add_argument("ip", help="device IPv4 address")
    label_set.add_argument("label", help="human label, e.g. \"Dad's laptop\"")
    label_set.add_argument("--trusted", action="store_true",
                           help="mark this device as known/trusted")
    label_set.add_argument("--untrusted", action="store_true",
                           help="mark this device as NOT trusted")
    label_set.add_argument("--notes", help="free-form notes")
    label_sub.add_parser("list", help="list all device labels")
    label_rm = label_sub.add_parser("remove", help="remove a label")
    label_rm.add_argument("ip", help="device IPv4 address")
    for lp in (label_set, label_sub.choices["list"], label_rm):
        lp.add_argument("--db", type=Path, default=Path("netsight.db"),
                        help="history database path")

    # ---- netsight probe ----
    probe = sub.add_parser("probe",
                           help="deep look at one host: ports, UDP, traceroute")
    probe.add_argument("ip", help="target IPv4 address (must be RFC1918)")
    probe.add_argument("--ports", default="common",
                       help="TCP ports to probe (default: common)")
    probe.add_argument("--traceroute", action="store_true",
                       help="run OS traceroute to the target")
    probe.add_argument("--deep-os", action="store_true",
                       help="nmap -O on this host (requires python-nmap)")
    probe.add_argument("-y", "--yes", action="store_true",
                       help="skip authorization confirmation")
    probe.add_argument("--allow-public", action="store_true",
                       help="allow non-RFC1918 targets")
    probe.add_argument("--log-file", type=Path, default=None, metavar="PATH",
                       help="append structured JSON logs to PATH")

    # ---- netsight watch ----
    watch = sub.add_parser("watch", help="repeat scan every N seconds, print deltas")
    watch.add_argument("--subnet", help="target CIDR (default: auto-detect)")
    watch.add_argument("--interval", type=int, default=60,
                       help="seconds between scans (default: 60)")
    watch.add_argument("-y", "--yes", action="store_true",
                       help="skip authorization confirmation")
    watch.add_argument("--allow-public", action="store_true",
                       help="allow non-RFC1918 targets")
    watch.add_argument("--threads", type=int, default=64,
                       help="sweep thread count (default: 64)")
    watch.add_argument("--timeout", type=int, default=800,
                       help="per-host timeout in ms (default: 800)")
    watch.add_argument("--alert-toast", action="store_true",
                       help="Windows toast when an unknown device appears")
    watch.add_argument("--alert-slack", metavar="WEBHOOK", default=None,
                       help="Slack incoming webhook for unknown devices")
    watch.add_argument("--alert-email", action="store_true",
                       help="SMTP alert via SIGHT_SMTP_* env vars")
    watch.add_argument("--log-file", type=Path, default=None, metavar="PATH",
                       help="append structured JSON logs to PATH")
    watch.add_argument("--db", type=Path, default=Path("netsight.db"),
                       help="history database path")

    # ---- netsight dashboard ----
    dash = sub.add_parser("dashboard", help="local Flask UI over scan history")
    dash.add_argument("--host", default="127.0.0.1", help="bind host")
    dash.add_argument("--port", type=int, default=8080, help="bind port")
    dash.add_argument("--db", type=Path, default=Path("netsight.db"),
                      help="history database path")
    dash.add_argument("--log-file", type=Path, default=None, metavar="PATH",
                      help="append structured JSON logs to PATH")

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


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two history scans and print the delta (feature F1)."""
    ui.show_banner()
    with history_db.HistoryDB(args.db) as db:
        older = db.get_scan(args.old_id)
        newer = db.get_scan(args.new_id)
    if older is None:
        ui.error(f"No scan with ID {args.old_id}.")
        return 1
    if newer is None:
        ui.error(f"No scan with ID {args.new_id}.")
        return 1

    from netsight.differ import diff_scans
    diff = diff_scans(older, newer)
    ui.show_diff_table(diff)
    return 0


def cmd_label(args: argparse.Namespace) -> int:
    """Manage persistent device labels/trust flags (feature F2)."""
    ui.show_banner()
    with history_db.HistoryDB(args.db) as db:
        if args.label_command == "set":
            trusted = None
            if args.trusted and args.untrusted:
                ui.error("Pick at most one of --trusted / --untrusted.")
                return 1
            if args.trusted:
                trusted = True
            elif args.untrusted:
                trusted = False
            db.set_device(
                args.ip,
                label=args.label,
                trusted=trusted,
                notes=args.notes,
            )
            ui.success(
                f"Labelled [bold]{args.ip}[/bold] — \"{args.label}\""
                + (" [trusted]" if trusted else "")
            )
            return 0

        if args.label_command == "list":
            rows = db.list_devices()
            if not rows:
                ui.info("No device labels set yet.")
                return 0
            ui.show_device_table(rows)
            return 0

        if args.label_command == "remove":
            if db.remove_device(args.ip):
                ui.success(f"Removed label for [bold]{args.ip}[/bold]")
            else:
                ui.warn(f"Nothing stored for {args.ip}.")
            return 0
    ui.error("Specify a label subcommand: set | list | remove")
    return 1


def cmd_probe(args: argparse.Namespace) -> int:
    """Deep, single-host reconnaissance (feature F4)."""
    ui.show_banner()
    if not _gate(args.ip + "/32", auto_yes=args.yes,
                 allow_public=args.allow_public):
        return 2

    ui.info(f"Probing [bold]{args.ip}[/bold]")
    # --- TCP scan with per-port banner ---
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        ui.error(str(exc))
        return 1
    with ui.build_progress("TCP scan") as progress:
        task = progress.add_task("tcp", total=1)
        tcp = scan_host(args.ip, ports, max_workers=100, timeout=1.0)
        progress.update(task, completed=1)

    host = HostResult(ip=args.ip, alive=bool(tcp.open))
    host.open_ports = [
        {"port": p.port, "banner": p.banner, "status": p.status}
        for p in tcp.ports
    ]

    from netsight.service_version import parse_all

    banners = {p["port"]: p.get("banner", "") for p in host.open_ports}
    services = parse_all([p["port"] for p in host.open_ports], banners)

    # --- UDP scan ---
    udp_map: dict[int, str] = {}
    from netsight.udp_scan import scan_udp
    with ui.build_progress("UDP scan") as progress:
        task = progress.add_task("udp", total=1)
        udp_map = scan_udp(args.ip, timeout=1.5)
        progress.update(task, completed=1)

    # --- hostname / vendor / OS ---
    host.hostname = resolve_hostname(args.ip)
    host.mac = host.mac  # placeholder; ARP table read happens below
    from netsight.host_info import get_mac
    host.mac = get_mac(args.ip)
    host.vendor = lookup_vendor(host.mac)
    from netsight.ping_sweep import ping_host
    pinged = ping_host(args.ip, timeout_ms=800)
    host.alive = host.alive or pinged.alive
    host.ttl = pinged.ttl
    host.response_ms = pinged.response_ms
    host.os_guess = guess_os_from_ttl(host.ttl)
    if args.deep_os and HAS_NMAP:
        try:
            host.os_guess = deep_fingerprint(args.ip)
        except RuntimeError as exc:
            ui.warn(f"nmap OS offline for {args.ip}: {exc}")

    # --- traceroute ---
    traceroute_lines: list[str] = []
    if args.traceroute:
        with ui.build_progress("Traceroute") as progress:
            task = progress.add_task("route", total=1)
            traceroute_lines = _traceroute(args.ip)
            progress.update(task, completed=1)

    ui.show_probe_table(args.ip, host, udp_map, services, traceroute_lines)
    if not host.alive:
        ui.warn("Host did not answer ICMP — treating as closed/filtered.")
    return 0


def _traceroute(ip: str) -> list[str]:
    """OS-native traceroute, one line per hop."""
    import subprocess
    import platform
    cmd = (["tracert", "-d", "-w", "2000", "-h", "30", ip]
           if platform.system() == "Windows"
           else ["traceroute", "-n", "-w", "2", "-m", "30", ip])
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    hops = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line and line[0].isdigit():
            hops.append(line)
    return hops


def cmd_watch(args: argparse.Namespace) -> int:
    """Repeat ``scan`` every N seconds and print the diff (feature F5)."""
    ui.show_banner()
    cidr = args.subnet or discovery.default_subnet()
    if cidr is None:
        ui.error("Could not auto-detect a local subnet.")
        return 1
    ui.info(f"Watching [bold]{cidr}[/bold] every {args.interval}s")
    if not _gate(cidr, auto_yes=args.yes, allow_public=args.allow_public):
        return 2

    from netsight.differ import diff_scans
    from netsight import slog
    log = slog.configure(args.log_file)
    db_path = args.db

    previous: ScanResult | None = None
    iteration = 0
    try:
        while True:
            iteration += 1
            ui.console.rule(f"[bold]Pass {iteration} — {time.strftime('%H:%M:%S')}")
            result = _watch_single_pass(cidr, args, db_path)

            if previous is not None:
                diff = diff_scans(previous, result)
                if diff.total_changes:
                    ui.show_diff_table(diff)
                    unknown = db_unknown_ips(db_path, result, args)
                    if unknown:
                        _dispatch_alerts(result, db_path, unknown, args)
                else:
                    ui.success("No changes.")
            else:
                ui.show_results_table(result)
                ui.show_summary(result)

            log.info(
                "watch pass done", extra={
                    "event": "watch_pass", "subnet": cidr,
                    "host_count": len(result.alive_hosts),
                },
            )
            previous = result
            time.sleep(args.interval)
    except KeyboardInterrupt:
        ui.warn("Watch mode stopped.")
        return 0


def _watch_single_pass(cidr: str, args: argparse.Namespace,
                       db_path) -> ScanResult:
    """One full scan iteration inside watch mode."""
    result = ScanResult(subnet=cidr)
    start = time.perf_counter()
    results = sweep(cidr, max_workers=args.threads,
                    timeout_ms=args.timeout)
    for res in results:
        result.hosts.append(
            HostResult(
                ip=res.ip, alive=True, mac=res.mac or "Unknown",
                ttl=res.ttl, response_ms=res.response_ms,
                os_guess=guess_os_from_ttl(res.ttl),
            )
        )
    result.finished_at = utc_now_iso()
    result.duration_s = time.perf_counter() - start

    # Persist + capture scan_id so alerts can reference it.
    with history_db.HistoryDB(db_path) as db:
        scan_id = db.save_scan(result)
        db.touch_devices([h.ip for h in result.alive_hosts],
                         utc_now_iso())
    result.scan_id = scan_id  # convenience for hooks
    return result


def db_unknown_ips(db_path, result: ScanResult, args) -> list[str]:
    """Return alive IPs not yet trusted in the DB (feature F8 input)."""
    with history_db.HistoryDB(db_path) as db:
        alive = [h.ip for h in result.alive_hosts]
        return db.unknown_devices(alive)


def _dispatch_alerts(result: ScanResult, db_path, unknown: list[str],
                     args: argparse.Namespace) -> None:
    """Fire configured alert backends for unknown devices (feature F8)."""
    from netsight.hooks import run_post_scan_hooks
    scan_id = getattr(result, "scan_id", 0) or 0
    run_post_scan_hooks(
        result, scan_id,
        unknown_ips=unknown,
        slack_webhook=args.alert_slack,
        toast=args.alert_toast,
        email=args.alert_email,
    )


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Serve a local Flask dashboard over the SQLite history (feature F6)."""
    ui.show_banner()
    try:
        from netsight.dashboard import create_app
    except ImportError as exc:
        ui.error(f"Dashboard unavailable: {exc}")
        return 1
    app = create_app(str(args.db))
    ui.info(
        f"Dashboard at [bold cyan]http://{args.host}:{args.port}[/bold cyan]"
    )
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
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
        if args.command == "diff":
            return cmd_diff(args)
        if args.command == "label":
            return cmd_label(args)
        if args.command == "probe":
            return cmd_probe(args)
        if args.command == "watch":
            return cmd_watch(args)
        if args.command == "dashboard":
            return cmd_dashboard(args)
    except KeyboardInterrupt:
        ui.warn("Interrupted by user.")
        return 130

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
