"""Rich-based terminal UI: banners, progress bars, tables, panels."""

from __future__ import annotations

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
[bold #f59e0b]
 █▀▀█  █▀▀▀▀  ▀▀█▀▀  █▀▀▀▀  ▀██▀  █▀▀▀▀  █  █  ▀▀█▀▀
 █ ██  █▀▀      █    ▀▀▀█    ██   █ ▀▀█  █▀▀█    █  
 █  █  █▄▄▄▄    █    ▄▄▄█▄  ▄██▄  ▀▄▄▄█  █  █    █  
 ╚══╝  ╚════╝   ╚═╝  ╚════╝ ╚════╝ ╚════╝ ╚══╝    ╚═╝
 ── ─ ─── ── ────── ── ────── ── ─── ── ────── ── ─── ──[/bold #f59e0b]
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


def info(message: str) -> None:
    """Print an informational line."""
    console.print(f"[cyan]ℹ[/cyan]  {message}")


def warn(message: str) -> None:
    """Print a warning line."""
    console.print(f"[yellow]⚠[/yellow]  {message}")


def error(message: str) -> None:
    """Print an error line."""
    console.print(f"[red]✗[/red]  {message}")


def success(message: str) -> None:
    """Print a success line."""
    console.print(f"[green]✓[/green]  {message}")
