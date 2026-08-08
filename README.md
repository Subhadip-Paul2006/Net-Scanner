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
  (Linux ~64, Windows ~128, network gear ~255).
- **Port scan** — threaded TCP connect scan (default 100 workers) over a
  configurable port set with basic banner grabbing. No exploitation, no
  brute force.
- **Exports** — timestamped CSV + JSON under `exports/`.
- **Scan history** — every run is stored in `netsight.db` (SQLite);
  list and re-export past scans by ID.
- **Polished CLI** — `rich` tables, progress bars, panels.
- **Graceful degradation** — every optional dependency is wrapped in
  `try/except ImportError`; the tool always falls back instead of
  crashing.

## Requirements

- Python **3.12+**
- Core deps: `rich`, `psutil`, `pandas`, and `netifaces` (non-Windows).
- Optional deps: `scapy` (ARP sweep), `python-nmap` (`--deep-scan`),
  `mac-vendor-lookup` (full OUI database), `colorama`.

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
│   ├── port_scan.py      # threaded TCP connect scan + banner grab
│   ├── exporter.py       # CSV + JSON export
│   ├── history_db.py     # SQLite scan history (scans + hosts tables)
│   ├── ui.py             # rich banners, tables, progress
│   └── hooks/            # v1.1+ extension point (empty stub)
├── tests/
├── requirements.txt
├── README.md
└── main.py
```

`discovery.py`, `ping_sweep.py`, and `port_scan.py` are plain importable
modules — no CLI coupling — so they can be tested or reused directly.

## Tests

Unit tests use mocked network calls only — no real packets are sent.

```bash
python -m pytest -v
```

## Safety by design

NetSight is an **inventory** tool, not an attack tool. It implements
ping sweep, port-state detection, and passive fingerprinting only —
no exploitation, no credential attacks, nothing beyond discovery.
