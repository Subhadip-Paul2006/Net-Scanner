"""Rich-based terminal UI: banners, progress bars, tables, panels."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from netsight import __version__
from netsight.models import ScanResult

console = Console()

LOGO = r"""
[bold #ff9e00]
███╗   ██╗███████╗████████╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
██╔██╗ ██║█████╗     ██║   ███████╗██║██║  ███╗███████║   ██║   
██║╚██╗██║██╔══╝     ██║   ╚════██║██║██║   ██║██╔══██║   ██║   
██║ ╚████║███████╗   ██║   ███████║██║╚██████╔╝██║  ██║   ██║   
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   [/bold #ff9e00]
"""


def _configure_console() -> Console:
    """Force UTF-8 output so banner glyphs render on legacy Windows shells."""
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass
    return Console(force_terminal=True)


console = _configure_console()


def show_banner() -> None:
    """Print the startup logo and version line."""
    console.print(LOGO)
    console.print(
        f"[dim]  Network Discovery & Device Scanner v{__version__} "
        "— internal inventory only[/dim]\n"
    )


def show_authorization_banner() -> None:
    """Print the mandatory consent/authorization warning before scanning."""
    console.print(
        Panel(
            "[bold yellow]⚠  AUTHORIZATION REQUIRED[/bold yellow]\n\n"
            "You must only scan networks you [bold]own[/bold] or have "
            "[bold]explicit permission[/bold] to test.\n"
            "Scanning is limited to private (RFC1918) ranges "
            "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and your own local "
            "subnet. Unauthorized scanning may be illegal.",
            title="[bold red]Legal Notice[/bold red]",
            border_style="red",
        )
    )


def confirm_authorization(auto_yes: bool = False) -> bool:
    """Ask the operator to confirm authorization to scan.

    Args:
        auto_yes: When True (``--yes`` flag), skip the interactive prompt.

    Returns:
        True when the operator confirmed, False otherwise.
    """
    if auto_yes:
        return True
    try:
        answer = console.input(
            "[bold]Do you confirm you are authorized to scan this network? "
            "[y/N]: [/bold]"
        )
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
    return answer.strip().lower() in ("y", "yes")


def build_progress(description: str) -> Progress:
    """Create a pre-configured rich progress bar for sweeps/scans."""
    return Progress(
        SpinnerColumn(),
        TextColumn(f"[progress.description]{description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def show_interface_table(interfaces: list) -> None:
    """Render detected network interfaces as a table."""
    table = Table(title="Detected Network Interfaces", box=box.ROUNDED)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Interface")
    table.add_column("IP Address")
    table.add_column("Netmask")
    table.add_column("Subnet (CIDR)")
    table.add_column("Default Route")
    for idx, iface in enumerate(interfaces):
        table.add_row(
            str(idx),
            iface.name,
            iface.ip,
            iface.netmask,
            iface.cidr,
            "[green]yes[/green]" if iface.is_default else "-",
        )
    console.print(table)


def show_results_table(scan: ScanResult) -> None:
    """Render alive hosts with color-coded status and open ports."""
    table = Table(
        title=f"Scan Results — {scan.subnet}",
        box=box.ROUNDED,
        show_lines=False,
        expand=True,
    )
    table.add_column("IP Address", style="bold", no_wrap=True, min_width=13)
    table.add_column("Status", no_wrap=True, min_width=8)
    table.add_column("Hostname", max_width=24, overflow="ellipsis")
    table.add_column("MAC", no_wrap=True, min_width=17)
    table.add_column("Vendor", max_width=16, overflow="ellipsis")
    table.add_column("OS Guess", max_width=22, overflow="ellipsis")
    table.add_column("RTT (ms)", justify="right", no_wrap=True, width=8)
    table.add_column("Open Ports", overflow="fold", ratio=1)

    for host in sorted(scan.alive_hosts, key=lambda h: tuple(int(p) for p in h.ip.split("."))):
        ports = ", ".join(str(p["port"]) for p in host.open_ports) or "[dim]-[/dim]"
        rtt = f"{host.response_ms:.1f}" if host.response_ms is not None else "-"
        os_style = "green" if host.os_guess != "Unknown" else "dim"
        table.add_row(
            host.ip,
            "[green]● alive[/green]",
            host.hostname if host.hostname != "Unknown" else "[dim]Unknown[/dim]",
            host.mac,
            host.vendor if host.vendor != "Unknown" else "[dim]Unknown[/dim]",
            f"[{os_style}]{host.os_guess}[/{os_style}]",
            rtt,
            ports,
        )
    console.print(table)


def show_port_details(scan: ScanResult) -> None:
    """Print per-host open-port details with banners, when any exist."""
    for host in scan.alive_hosts:
        if not host.open_ports:
            continue
        table = Table(
            title=f"{host.ip} — open ports", box=box.SIMPLE, show_lines=False
        )
        table.add_column("Port", justify="right", style="bold")
        table.add_column("Status")
        table.add_column("Banner", overflow="fold")
        for port in host.open_ports:
            banner = port.get("banner") or "[dim]-[/dim]"
            table.add_row(
                str(port["port"]), "[green]open[/green]", banner
            )
        console.print(table)


def show_summary(scan: ScanResult, scan_id: int | None = None) -> None:
    """Print the end-of-scan summary panel."""
    lines = [
        f"Subnet:            [bold]{scan.subnet}[/bold]",
        f"Hosts discovered:  [bold green]{len(scan.alive_hosts)}[/bold green]",
        f"Open ports found:  [bold]{scan.open_port_count}[/bold]",
        f"Scan duration:     [bold]{scan.duration_s:.1f}s[/bold]",
    ]
    if scan_id is not None:
        lines.append(f"History entry:     [bold cyan]#{scan_id}[/bold cyan]")
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Scan Summary[/bold]",
            border_style="cyan",
        )
    )


def show_history_table(rows: list[dict[str, object]]) -> None:
    """Render past scan runs as a table."""
    table = Table(title="Scan History", box=box.ROUNDED)
    table.add_column("ID", justify="right", style="bold cyan")
    table.add_column("Started (UTC)")
    table.add_column("Subnet")
    table.add_column("Hosts", justify="right")
    table.add_column("Duration (s)", justify="right")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["started_at"]),
            str(row["subnet"]),
            str(row["host_count"]),
            f"{float(row['duration_s']):.1f}",
        )
    console.print(table)


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    """Numeric IPv4 sort key (lexicographic '…2' < '…10' bug fix)."""
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)


def show_device_table(rows: list[dict[str, Any]]) -> None:
    """Render the device-label inventory (feature F2)."""
    table = Table(
        title="Device Labels", box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan",
    )
    table.add_column("IP", style="bold white", no_wrap=True)
    table.add_column("Label")
    table.add_column("Trusted", justify="center")
    table.add_column("First Seen", no_wrap=True)
    table.add_column("Last Seen", no_wrap=True)
    table.add_column("Seen", justify="right")
    for row in sorted(rows, key=lambda r: _ip_sort_key(str(r["ip"]))):
        trusted = "[green]✓[/green]" if row["trusted"] else "[dim]-[/dim]"
        first = str(row["first_seen"] or "-")[:19]
        last = str(row["last_seen"] or "-")[:19]
        table.add_row(
            str(row["ip"]),
            str(row["label"]) or "[dim]-[/dim]",
            trusted,
            first,
            last,
            str(row["seen_count"]),
        )
    console.print(table)


def show_diff_table(diff) -> None:
    """Render a DiffResult from netsight.differ (feature F1)."""
    table = Table(
        title=(
            f"Scan Diff — [bold]{diff.subnet_b}[/bold] "
            f"(#{diff.started_a[:10]} → #{diff.started_b[:10]})"
        ),
        box=box.ROUNDED, border_style="cyan", header_style="bold cyan",
    )
    table.add_column("IP", no_wrap=True)
    table.add_column("Change")
    table.add_column("Detail", overflow="fold")

    for host in diff.new_hosts:
        table.add_row(host.ip, "[green]+ new device[/green]",
                      f"vendor={host.vendor or '?'}")
    for host in diff.gone_hosts:
        table.add_row(host.ip, "[red]- gone[/red]",
                      f"vendor={host.vendor or '?'}")
    for delta in diff.changed_hosts:
        detail_parts = []
        if delta.new_open_ports:
            detail_parts.append(
                "new ports " + ",".join(str(p) for p in delta.new_open_ports)
            )
        if delta.closed_ports:
            detail_parts.append(
                "closed " + ",".join(str(p) for p in delta.closed_ports)
            )
        if delta.hostname_a != delta.hostname_b:
            detail_parts.append(f"hostname {delta.hostname_a or '?'}→{delta.hostname_b or '?'}")
        if delta.mac_a != delta.mac_b:
            detail_parts.append(f"MAC {delta.mac_a}→{delta.mac_b}")
        if delta.vendor_a != delta.vendor_b:
            detail_parts.append(f"vendor {delta.vendor_a or '?'}→{delta.vendor_b or '?'}")
        if delta.os_a != delta.os_b:
            detail_parts.append(f"OS {delta.os_a or '?'}→{delta.os_b or '?'}")
        table.add_row(delta.ip, "[yellow]changed[/yellow]", " · ".join(detail_parts))
    console.print(table)
    console.print(
        f"[dim]{diff.unchanged_count} hosts unchanged, "
        f"{diff.total_changes} changes detected[/dim]"
    )


def show_probe_table(ip: str, host, udp_map, services, traceroute) -> None:
    """Render the single-host probe report (feature F4)."""
    console.print(
        Panel(
            f"[bold white]{ip}[/bold white]  ·  {host.hostname or 'unknown'}",
            title="[bold]Probe[/bold]", border_style="cyan",
        )
    )
    tbl = Table(
        title=f"{ip} — TCP services", box=box.SIMPLE_HEAVY,
        border_style="cyan", header_style="bold cyan",
    )
    tbl.add_column("Port", justify="right", width=7)
    tbl.add_column("State", width=10)
    tbl.add_column("Service / Version", overflow="fold")
    from netsight.service_version import parse_service_version
    for p in host.open_ports:
        svc = parse_service_version(p["port"], p.get("banner", ""))
        tbl.add_row(str(p["port"]), "[green]open[/green]",
                    svc or "[dim]unknown[/dim]")

    for port, desc in (udp_map or {}).items():
        tbl.add_row(str(port), "[cyan]udp[/cyan]",
                    f"[cyan]{desc}[/cyan]")
    if not host.open_ports and not (udp_map or {}):
        tbl.add_row("-", "[dim]-[/dim]", "[dim]no response[/dim]")
    console.print(tbl)

    console.print(
        Panel(
            "\n".join(
                f"[dim]{k:<14}[/dim] {v}" for k, v in (
                    ("MAC", host.mac),
                    ("Vendor", host.vendor),
                    ("OS Guess", host.os_guess),
                    ("TTL", str(host.ttl) if host.ttl is not None else "—"),
                    ("RTT", f"{host.response_ms:.1f} ms" if host.response_ms else "—"),
                )
            ),
            title="[bold]Fingerprint[/bold]", border_style="cyan",
        )
    )

    if traceroute:
        console.print(
            Panel(
                "\n".join(traceroute) if traceroute else "[dim]no hops[/dim]",
                title="[bold]Traceroute[/bold]", border_style="cyan",
            )
        )


def info(message: str) -> None:
    """Print an informational line."""
    console.print(f"[cyan][*][/cyan] {message}")


def warn(message: str) -> None:
    """Print a warning line."""
    console.print(f"[yellow][!][/yellow] {message}")


def error(message: str) -> None:
    """Print an error line."""
    console.print(f"[red][-][/red] {message}")


def success(message: str) -> None:
    """Print a success line."""
    console.print(f"[green][+][/green] {message}")
