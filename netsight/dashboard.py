"""Local Flask dashboard over the SQLite scan history (feature F6).

Read-only views of every past scan plus a JSON API. No write endpoints —
the dashboard surfaces data; it never triggers scans.
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    from flask import Flask, abort, jsonify, render_template_string
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError(
        "Flask is required for the dashboard: pip install flask"
    ) from exc

from netsight.history_db import HistoryDB


_BASE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NetSight Dashboard</title>
<style>
:root{--bg:#0d1117;--fg:#c9d1d9;--border:#30363d;--dim:#8b949e;
      --green:#3fb950;--cyan:#79c0ff;--yellow:#d29922}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
  font:14px/1.5 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
h1{color:var(--cyan);margin-top:0}
table{width:100%;border-collapse:collapse;background:#161b22;
  border:1px solid var(--border);border-radius:8px}
th,td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left}
th{background:#181d26;color:var(--cyan);font-size:12px;
  text-transform:uppercase;letter-spacing:.05em;cursor:pointer}
tr:last-child td{border-bottom:none}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
.ok{color:var(--green)}
.dim{color:var(--dim)}
.pill{padding:2px 8px;border-radius:10px;background:#21262d;
  font-family:ui-monospace,monospace;font-size:12px}
</style></head><body>
<h1>NetSight Dashboard</h1>
__BODY__
</body></html>"""


def _page(body: str) -> str:
    return _BASE.replace("__BODY__", body)


def create_app(db_path: str | Path = "netsight.db") -> Flask:
    """Build the Flask application."""
    app = Flask(__name__)
    app.config["DB_PATH"] = str(db_path)

    def _db() -> HistoryDB:
        return HistoryDB(app.config["DB_PATH"])

    # --- index: scan History table ---
    @app.route("/")
    def index() -> str:
        with _db() as db:
            rows = db.list_scans(limit=200)
        trs = "".join(
            f"<tr><td><a href='/scan/{row['id']}'>#{row['id']}</a></td>"
            f"<td>{row['started_at'][:19]}</td>"
            f"<td><span class='pill'>{row['subnet']}</span></td>"
            f"<td class='ok'>{row['host_count']}</td>"
            f"<td>{row['duration_s']:.1f}s</td></tr>"
            for row in rows
        )
        body = (
            "<table><thead><tr><th>ID</th><th>Started (UTC)</th>"
            "<th>Subnet</th><th>Hosts</th><th>Duration</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>"
        )
        return _page(body)

    # --- scan detail ---
    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id: int) -> str:
        with _db() as db:
            scan = db.get_scan(scan_id)
        if scan is None:
            abort(404)
        rows = "".join(
            f"<tr><td>{host.ip}</td>"
            f"<td>{host.hostname if host.hostname != 'Unknown' else '<span class=dim>—</span>'}</td>"
            f"<td>{host.mac}</td><td>{host.vendor}</td>"
            f"<td>{host.os_guess}</td>"
            f"<td>{host.response_ms or '—'}</td>"
            f"<td>{' '.join(str(p['port']) for p in host.open_ports) or '-'}</td>"
            "</tr>"
            for host in scan.alive_hosts
        )
        body = (
            f"<p><a href='/'>&larr; back</a></p>"
            f"<p class='dim'>Subnet {scan.subnet} · started {scan.started_at[:19]} "
            f"· duration {scan.duration_s:.1f}s</p>"
            "<table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th>"
            "<th>Vendor</th><th>OS</th><th>RTT ms</th><th>Open Ports</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
        return _page(body)

    # --- JSON API ---
    @app.route("/api/scans")
    def api_scans():
        with _db() as db:
            return jsonify(db.list_scans(limit=200))

    @app.route("/api/scan/<int:scan_id>")
    def api_scan(scan_id: int):
        with _db() as db:
            scan = db.get_scan(scan_id)
        if scan is None:
            abort(404)
        return jsonify(scan.to_dict())

    @app.route("/api/devices")
    def api_devices():
        with _db() as db:
            return jsonify(db.list_devices())

    return app
