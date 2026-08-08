"""CSV/JSON/HTML export of scan results into a timestamped exports/ dir."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from html import escape
from pathlib import Path

from netsight.models import ScanResult

#: One row per (host, open port) in CSV — hosts with no open ports appear
#: once with an empty port column.
CSV_FIELDS = (
    "ip", "hostname", "mac", "vendor", "os_guess", "ttl",
    "response_ms", "alive", "port", "banner", "detected_at",
)


def _default_exports_dir() -> Path:
    """exports/ next to the current working directory (created lazily)."""
    return Path.cwd() / "exports"


def _timestamp_slug() -> str:
    """Filesystem-safe timestamp for export filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _host_rows(scan: ScanResult) -> list[dict[str, object]]:
    """Flatten a ScanResult into CSV rows (one row per host/port pair)."""
    rows: list[dict[str, object]] = []
    for host in scan.hosts:
        if host.open_ports:
            for port in host.open_ports:
                rows.append(
                    {
                        "ip": host.ip,
                        "hostname": host.hostname,
                        "mac": host.mac,
                        "vendor": host.vendor,
                        "os_guess": host.os_guess,
                        "ttl": host.ttl if host.ttl is not None else "",
                        "response_ms": (
                            host.response_ms if host.response_ms is not None else ""
                        ),
                        "alive": host.alive,
                        "port": port.get("port", ""),
                        "banner": port.get("banner", ""),
                        "detected_at": host.detected_at,
                    }
                )
        else:
            rows.append(
                {
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "mac": host.mac,
                    "vendor": host.vendor,
                    "os_guess": host.os_guess,
                    "ttl": host.ttl if host.ttl is not None else "",
                    "response_ms": (
                        host.response_ms if host.response_ms is not None else ""
                    ),
                    "alive": host.alive,
                    "port": "",
                    "banner": "",
                    "detected_at": host.detected_at,
                }
            )
    return rows


def export_json(
    scan: ScanResult,
    directory: str | Path | None = None,
    filename: str | None = None,
) -> Path:
    """Write a scan result to a JSON file.

    Args:
        scan: The completed scan result.
        directory: Output directory (defaults to ./exports).
        filename: Override filename (must end with .json).

    Returns:
        Path to the written file.
    """
    out_dir = Path(directory) if directory else _default_exports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"netsight_scan_{_timestamp_slug()}.json"
    path = out_dir / name
    payload = scan.to_dict()
    payload["exported_at"] = datetime.now().isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def export_csv(
    scan: ScanResult,
    directory: str | Path | None = None,
    filename: str | None = None,
) -> Path:
    """Write a scan result to a CSV file.

    Args:
        scan: The completed scan result.
        directory: Output directory (defaults to ./exports).
        filename: Override filename (must end with .csv).

    Returns:
        Path to the written file.
    """
    out_dir = Path(directory) if directory else _default_exports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"netsight_scan_{_timestamp_slug()}.csv"
    path = out_dir / name
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_FIELDS))
        writer.writeheader()
        writer.writerows(_host_rows(scan))
    return path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetSight Scan — __SUBNET__</title>
<style>
:root{--bg:#0d1117;--fg:#c9d1d9;--border:#30363d;--dim:#8b949e;
      --green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#79c0ff}
*{{box-sizing:border-box}}
body{{margin:0;padding:24px;background:var(--bg);color:var(--fg);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}}
header{{border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:24px}}
h1{{color:var(--cyan);margin:0 0 4px;font-size:22px}}
.meta{{color:var(--dim);font-size:13px}}
.stats{{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}}
.stat{{background:#161b22;border:1px solid var(--border);border-radius:8px;
  padding:12px 18px;min-width:120px}}
.stat .n{{font-size:24px;font-weight:600;color:var(--green)}}
.stat .l{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.05em}}
table{{width:100%;border-collapse:collapse;background:#161b22;
  border:1px solid var(--border);border-radius:8px;overflow:hidden}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border);
  white-space:nowrap}}
th{{background:#181d26;color:var(--cyan);cursor:pointer;user-select:none;
  font-size:12px;text-transform:uppercase;letter-spacing:.05em}}
th:hover{{background:#1c2128}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
.status{{display:inline-flex;align-items:center;gap:6px;font-weight:600;color:var(--green)}}
.dot{{width:8px;height:8px;border-radius:50%;background:var(--green)}}
.dim{{color:var(--dim)}}
.ports{{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--yellow)}}
input#f{{width:100%;padding:10px 12px;margin:12px 0;background:#161b22;
  border:1px solid var(--border);border-radius:6px;color:var(--fg)}}
footer{{margin-top:24px;color:var(--dim);font-size:12px}}
</style>
</head>
<body>
<header>
  <h1>NetSight Scan Report</h1>
  <div class="meta">
    Target <strong>__SUBNET__</strong> ·
    started __STARTED__ ·
    finished __FINISHED__ ·
    duration __DURATION__s
  </div>
  <div class="stats">
    <div class="stat"><div class="n">__HOSTS_UP__</div><div class="l">Hosts Up</div></div>
    <div class="stat"><div class="n">__OPEN_PORTS__</div><div class="l">Open Ports</div></div>
    <div class="stat"><div class="n">__HOSTS_TOTAL__</div><div class="l">Hosts Scanned</div></div>
  </div>
</header>

<input id="f" placeholder="Filter IP / hostname / vendor / OS / port…" oninput="flt()">

<table id="t">
  <thead><tr>
    <th>IP</th><th>Status</th><th>Hostname</th><th>MAC</th><th>Vendor</th>
    <th>OS</th><th>RTT&nbsp;ms</th><th>Open Ports</th>
  </tr></thead>
  <tbody>
__ROWS__
  </tbody>
</table>

<footer>Generated __GENERATED__ by NetSight v__VERSION__ · internal inventory only</footer>

<script>
function flt(){{
  const q=document.getElementById('f').value.toLowerCase();
  for(const tr of document.querySelectorAll('#t tbody tr'))
    tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none';
}}
document.querySelectorAll('#t th').forEach((th,i)=>{{
  th.addEventListener('click',()=>{{
    const tbody=document.querySelector('#t tbody');
    const rows=[...tbody.rows];
    const asc=th.dataset.asc=th.dataset.asc!=='true';
    rows.sort((a,b)=>{{
      const x=a.cells[i].textContent,y=b.cells[i].textContent;
      const nx=parseFloat(x),ny=parseFloat(y);
      const res=(!isNaN(nx)&&!isNaN(ny))?(nx-ny):x.localeCompare(y);
      return asc?res:-res;
    }});
    for(const r of rows)tbody.appendChild(r);
  }});
}});
</script>
</body>
</html>
"""


def _host_row_html(host) -> str:
    """One <tr> for a host (abbreviates unknown fields for readability)."""
    ports = ", ".join(str(p["port"]) for p in host.open_ports) or "-"
    rtt = f"{host.response_ms:.0f}" if host.response_ms is not None else "-"
    os_cell = (
        host.os_guess if host.os_guess != "Unknown" else '<span class="dim">—</span>'
    )
    vendor = (
        host.vendor if host.vendor != "Unknown" else '<span class="dim">—</span>'
    )
    hostname = (
        host.hostname if host.hostname != "Unknown" else '<span class="dim">—</span>'
    )
    mac = host.mac if host.mac != "Unknown" else '<span class="dim">—</span>'
    return (
        f'<tr><td>{escape(host.ip)}</td>'
        f'<td><span class="status"><span class="dot"></span>alive</span></td>'
        f"<td>{hostname}</td><td>{mac}</td><td>{vendor}</td>"
        f"<td>{os_cell}</td><td>{rtt}</td>"
        f'<td class="ports">{ports}</td></tr>'
    )


def export_html(
    scan: ScanResult,
    directory: str | Path | None = None,
    filename: str | None = None,
) -> Path:
    """Write a scan result to a self-contained, sortable HTML file (F3).

    Args:
        scan: The completed scan result.
        directory: Output directory (defaults to ./exports).
        filename: Override filename.

    Returns:
        Path to the written ``.html`` file.
    """
    out_dir = Path(directory) if directory else _default_exports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"netsight_scan_{_timestamp_slug()}.html"
    path = out_dir / name

    rows = "\n".join(_host_row_html(h) for h in scan.alive_hosts)
    try:
        from netsight import __version__
    except ImportError:  # pragma: no cover
        __version__ = "0.0.0"

    body = (
        _HTML_TEMPLATE.replace("__SUBNET__", escape(scan.subnet))
        .replace("__STARTED__", escape(scan.started_at))
        .replace("__FINISHED__", escape(scan.finished_at or "—"))
        .replace("__DURATION__", f"{scan.duration_s:.1f}")
        .replace("__HOSTS_UP__", str(len(scan.alive_hosts)))
        .replace("__OPEN_PORTS__", str(scan.open_port_count))
        .replace("__HOSTS_TOTAL__", str(len(scan.hosts)))
        .replace("__ROWS__", rows)
        .replace("__GENERATED__", datetime.now().isoformat(timespec="seconds"))
        .replace("__VERSION__", __version__)
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def export_scan(
    scan: ScanResult,
    formats: list[str],
    directory: str | Path | None = None,
) -> list[Path]:
    """Export a scan result to one or more formats.

    Args:
        scan: The completed scan result.
        formats: Any of ``"csv"``, ``"json"``, ``"html"``.
        directory: Output directory (defaults to ./exports).

    Returns:
        List of written file paths, in the order of ``formats``.

    Raises:
        ValueError: On an unknown format name.
    """
    written: list[Path] = []
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == "csv":
            written.append(export_csv(scan, directory))
        elif fmt == "json":
            written.append(export_json(scan, directory))
        elif fmt == "html":
            written.append(export_html(scan, directory))
        elif fmt:
            raise ValueError(
                f"Unknown export format '{fmt}' (use csv/json/html)"
            )
    return written
