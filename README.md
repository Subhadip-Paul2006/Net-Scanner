<p align="center">
  <img src="src/logo.png" alt="NetSight Logo" width="100%">
</p>

# NetSight

**Network Discovery & Device Scanner** — a lightweight, enterprise-styled
CLI for inventorying *your own* private networks.

> ⚠️ **Authorization required.** NetSight must only be used on networks
> you own or have explicit permission to test. Every active scan enforces
> RFC1918 target validation and asks for confirmation before sending a
> single packet.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Project layout](#project-layout)
- [Tests](#tests)
- [Safety by design](#safety-by-design)

## Features

- **Local network discovery** — enumerates interfaces via
  `netifaces` (fallback: `psutil`) and computes the local subnet CIDR.
- **Ping sweep** — scapy ARP sweep on the local LAN when raw-socket
  privileges are available, automatic ICMP fallback via the OS `ping`
  command, all threaded with `concurrent.futures`.
- **Host enrichment** — reverse-DNS hostname, MAC from the ARP table,
  MAC OUI vendor lookup, response time, and TTL-based OS guessing
  (Linux/macOS ≈64, Windows ≈128, network gear ≈255 — heuristic, not a
  guarantee).
- **Port scan** — threaded TCP connect scan (default 100 workers) over a
  configurable port set with banner grabbing. No exploitation, no brute force.
- **Latency classification** — each host is tagged `excellent`/`good`/`poor`
  from its ping RTT (Plan2 Phase 8: ≤5ms, ≤50ms, >50ms).
- **Multi-subnet scans** — `--subnet 192.168.1.0/24,10.0.0.0/24` sweeps every
  listed subnet concurrently and merges results (v2.0 🌍).
- **PDF report** — `--export pdf` writes a self-contained, printable PDF
  (stdlib-only; no external PDF library needed) (v2.0 📄).
- **Vulnerability hints** — open risky ports (Telnet, SMB, RDP, DBs, Redis,
  MongoDB) are tagged with one-line warnings in exports + UI (v2.0 🔒).
- **Activity charts** — the dashboard shows a "hosts discovered over time"
  sparkline across scan history (v2.0 📈).
- **Service version (F7)** — banners parsed into `ssh OpenSSH_9.6` /
  `http nginx/1.24` strings; ports fall back to conventional service names.
- **Exports** — timestamped CSV, JSON, and self-contained sortable HTML.
- **Scan history (F1)** — every run stored in `netsight.db` (SQLite);
  `netsight diff OLD NEW` shows new/gone devices and port changes.
- **Device labels (F2)** — persistent per-IP inventory with `trusted`
  flag, human label, and notes.
- **Probe (F4)** — deep single-host reconnaissance: TCP + UDP services,
  traceroute, optional nmap OS scan, rich per-host report.
- **Watch (F5)** — repeat scans every N seconds, print only deltas,
  alert on untrusted device joins.
- **Dashboard (F6)** — local Flask UI over `netsight.db` with JSON API.
- **UDP scan (F9)** — probes DNS/SNMP/NTP/NetBIOS/mDNS on each host.
- **Alert hooks (F8)** — Windows toast / Slack webhook / SMTP email
  when an unknown device appears.
- **Structured logging (F10)** — JSON rotating file via `--log-file`.
- **Polished CLI** — `rich` tables, progress bars, panels.
- **Graceful degradation** — every optional dependency is wrapped in
  `try/except ImportError`; the tool always falls back instead of
  crashing.

## Requirements

- Python **3.12+**
- Core deps: `rich`, `psutil`, `pandas`, and `netifaces` (non-Windows).
- Optional deps: `scapy` (ARP sweep), `python-nmap` (`--deep-scan`),
  `mac-vendor-lookup` (full OUI database), `flask` (dashboard),
  `colorama`.

```bash
pip install -r requirements.txt
```

> **Note on privileges:** scapy-based ARP sweeping needs **admin / root /
> raw-socket** permissions (run from an elevated terminal). Without them —
> or without scapy installed — NetSight transparently falls back to
> ICMP ping via subprocess.

## Usage

All commands can be run via `python main.py ...` from the repo root, or
after `pip install -e .` as `netsight ...`.

```bash
# Fast overview of the auto-detected local subnet (sweep only)
python main.py quick

# Multi-subnet scan (v2.0): comma-separated CIDRs
python main.py scan --subnet 192.168.1.0/24,10.0.0.0/24 --yes

# PDF report along with CSV + JSON (v2.0)
python main.py scan --subnet 192.168.1.0/24 --export csv,json,html,pdf

# Full scan of a subnet with default common ports, export to CSV+JSON
python main.py scan --subnet 192.168.1.0/24 --export csv,json

# Scan with a custom port set and skip the consent prompt (scripts)
python main.py scan --subnet 10.0.0.0/24 --ports 22,80,443 --yes

# Discovery only — no port scan
python main.py scan --subnet 192.168.1.0/24 --no-ports

# Accurate OS detection via nmap (slow, needs admin)
python main.py scan --subnet 192.168.1.0/24 --deep-scan

# Scan history
python main.py history list
python main.py history show 3
python main.py history show 3 --export csv

# Compare two scans: new/gone devices + port deltas (F1)
python main.py diff 1 2

# Label devices you recognize — powers unknown-device alerts (F2)
python main.py label set 192.168.1.99 "Dad's laptop" --trusted
python main.py label list
python main.py label remove 192.168.1.99

# Deep single-host probe: TCP+UDP services, traceroute, OS guess (F4)
python main.py probe 192.168.1.1 --traceroute

# Repeat scans every 60 s, print only the delta, alert on unknown (F5+F8)
python main.py watch --subnet 192.168.1.0/24 --interval 60 \
    --alert-toast --alert-slack https://hooks.slack.com/...

# Local Flask dashboard over the SQLite history (F6)
python main.py dashboard --port 8080

# Structured JSON logging (F10)
python main.py scan --subnet 192.168.1.0/24 --log-file logs/netsight.log
```

Targets are validated before scanning:

- Only RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`),
  loopback and link-local are accepted (override with `--allow-public`,
  still size-limited).
- Any target larger than a /16 is rejected.

## Project layout

```
netsight/
├── netsight/
│   ├── __init__.py
│   ├── cli.py            # entry point, argparse + rich UI wiring
│   ├── models.py         # HostResult / ScanResult dataclasses
│   ├── discovery.py      # interface & subnet detection
│   ├── ping_sweep.py     # ARP/ICMP threaded sweep
│   ├── host_info.py      # hostname, MAC via ARP table
│   ├── vendor_lookup.py  # MAC OUI -> vendor (offline fallback table)
│   ├── os_fingerprint.py # TTL heuristics (+ optional nmap -O)
│   ├── port_scan.py      # threaded TCP connect scan + banner grab (F7)
│   ├── differ.py         # scan-vs-scan delta engine (F1)
│   ├── service_version.py# banner -> "service version" parser (F7)
│   ├── udp_scan.py       # UDP service probes: dns/ntp/netbios/snmp (F9)
│   ├── slog.py           # JSON rotating structured logging (F10)
│   ├── exporter.py       # CSV + JSON + self-contained HTML export (F3)
│   ├── history_db.py     # SQLite scan history + device inventory (F2)
│   ├── dashboard.py      # local Flask UI over history (F6)
│   ├── ui.py             # rich banners, tables, progress, diff/probe views
│   └── hooks/            # alert backends: toast/slack/email (F8)
├── tests/                # pytest suite — all network I/O mocked
├── exports/              # scan reports written here
├── logs/                 # JSON log files (--log-file)
├── netsight.db           # SQLite history + device inventory
├── src/                  # project assets (README logo)
├── requirements.txt
├── README.md
├── BUGREPORT.md          # VAPT findings + fix mapping
└── main.py               # entry-point launcher
```

`discovery.py`, `ping_sweep.py`, `port_scan.py`, `differ.py`,
`service_version.py`, `udp_scan.py` are plain importable modules — no
CLI coupling — so they can be tested or reused directly.

## Tests

Unit tests use mocked network calls only — no real packets are sent.

```bash
python -m pytest -v
```

## Safety by design

NetSight is an **inventory** tool, not an attack tool. It implements
ping sweep, port-state detection, and passive fingerprinting only —
no exploitation, no credential attacks, nothing beyond discovery.
