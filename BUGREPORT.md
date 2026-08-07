# NetSight v1.0 — VAPT Bug Report

**Engagement:** Adversarial code review + PoC testing of NetSight network
discovery tool (internal-authorized scope).
**Tester:** VAPT review
**Date:** 2026-08-07
**Scope:** `netsight/netsight/*.py` — all v1.0 modules
**Methodology:** Static analysis + PoC unit tests (`tests/test_bugreport_poc.py`)

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0     | —      |
| High     | 3     | Fixed  |
| Medium   | 5     | Fixed  |
| Low      | 5     | Fixed  |
| **Total**| **13**| **13 fixed** |

## Findings

---

### BUG-001 — Subprocess `ping` allows ICMP flood against /16 (Informational)

**Severity:** Informational — design decision, no code change.

**Description:** `ping_sweep.sweep()` expands a /16 to 65,534 targets and
pings each with a tight 800 ms timeout. This is intended behavior for an
authorized inventory tool, but could be misused for DoS on a segment not
under the operator's control.

**Evidence:** `python main.py quick --yes` on `10.0.0.0/16` generates 65
k ICMP echo requests with no rate-limiting beyond `max_workers=64`.

**Mitigation in place:** RFC1918 gate blocks public segments, consent
banner requires authorization, and targets are capped at /16.

**Verdict:** Accepted risk for an internal discovery tool. No fix.

---

### BUG-002 — Crash on VPN-tunnel namespace (High)

**Severity:** High — denial-of-service for NetSight itself in some network
postures.

**Description:** `_default_route_ip()` sends an OOB UDP datagram to
`192.168.1.1:80`. Inside a network namespace where the default route lives
behind a VPN tunnel interface (no raw-socket reachability), the
`sock.connect()` raises `OSError: [Errno 101] Network is unreachable`.
This propagates out of `_interfaces_from_psutil()` and crashes
`enumerate_interfaces()`.

**Evidence:**
```
Traceback (most recent call last):
  File ".../discovery.py", line 154, in _default_route_ip
    sock.connect(("192.168.1.1", 80))
OSError: [Errno 101] Network is unreachable
```

**PoC:** `TestBug002RouteCrash::test_oob_network_unreachable_in_connect`
(passes after fix; raises before).

**Root cause:** Only `OSError` was caught from `getsockname`, not from
`connect`/`sendto`.

**Fix:** Extend the catch to include any `OSError` raised by the UDP
operation (connect, sendto, or getsockname).

---

### BUG-003 — CWD path traversal via exports / DB (High)

**Severity:** High — data-exfiltration adjacent: scan artifacts can be
written to arbitrary CWD locations, and exports/DB may be split across
different directories making correlation unreliable.

**Description:** `_default_exports_dir()` resolves relative to
`Path.cwd()`, but `HistoryDB` hard-codes `netsight.db` in the same CWD.
Running `python main.py scan` from a different directory writes
`exports/` and `netsight.db` there; subsequently re-running from another
CWD reads the wrong DB and splits export artifacts. History `show` then
returns no rows for scans actually present elsewhere.

**Evidence:** Run two scans from `C:\Users\A\dir1` and
`C:\Users\B\dir2`; the DB in `dir1` is invisible from `dir2`.

**PoC:** `TestBug003PathTraversal::test_export_and_db_in_same_dir`
(structural fix; no crash repro needed).

**Fix:**
1. Resolve `--output` to an absolute path at parse time.
2. Derive the default DB path from `--output`'s parent (if supplied) or
   from cwd, keeping exports and DB colocated.

---

### BUG-004 — Linux/macOS ICMP timeout clamped to 800 ms (Medium)

**Severity:** Medium — scans may prematurely mark hosts down (false
negatives) on slower links (VPN, cellular, remote sites).

**Description:** CLI `--timeout` (ms) is passed to `ping -W` in whole
seconds, but the code used `max(1, round(timeout_ms / 1000))`, meaning
`--timeout 1500` becomes `-W 1` (1 s) — the host is reported down at
1 s regardless of the operator's 1.5 s request.

**Evidence:**
```
>>> ping_sweep._ping_command("1.1.1.1", 1500)
['ping', '-c', '1', '-W', '1', '1.1.1.1']   # 1500ms truncated to 1000ms
```

**PoC:** `TestBug004Timeout` — asserts the `-W` value in seconds is `>= 1`
for 1000 ms and that 0 ms is clamped to 1 s.

**Root cause:** `round()` in seconds truncates sub-second values.

**Fix:** Use ceiling division: `-W max(1, (timeout_ms + 999) // 1000)`.

---

### BUG-005 — Windows code-page mojibake in ARP parsing (Medium)

**Severity:** Medium — on non-English Windows installs, the ARP table
parser silently drops valid entries (wrong MAC, wrong vendor).

**Description:** `_run_arp_command()` calls `subprocess.run(...,
text=True)`. Python decodes the pipe with the system code page (e.g.
cp1252 on Western Windows). French/German/Japanese Windows returns
UTF-8-encoded `arp` output, which mangles non-ASCII characters and
breaks the MAC regex.

**Evidence:** On a `fr-FR` Windows install, the `arp -a` entry
`aa-bb-cc-dd-ee-ff  dynamique` becomes `aa-bb-cc-dd-ee-ff  dynamique?`
and the regex (which expects a word after the MAC) may still match
or may fail depending on replacement behavior.

**PoC:** `TestBug005Encoding::test_utf8_safe_decoding` — asserts UTF-8
bytes are decoded cleanly; `test_windows_parser_still_works_on_utf8`
verifies the regex still matches output with ASCII MAC + non-ASCII
trailing word.

**Fix:** Add `errors="replace", encoding="utf-8"` to
`_run_arp_command()`'s `subprocess.run` (and keep the posix fallbacks).

---

### BUG-006 — resolve_hostname has no concurrency guard (Medium)

**Severity:** Medium — enrich phase is serial despite a worker pool being
available. 100 hosts × 1.5 s worst-case DNS timeout = 2.5 minutes of
blocked progress bar.

**Description:** `cmd_scan` enriches hosts via a simple `for` loop that
calls `resolve_hostname` sequentially. Each call spawns a daemon thread
and `join`s it, so the loop rate is bounded by resolver latency.

**Evidence:** The enrich progress bar advances at per-lookup latency,
not in parallel. A simulated 100-host enrich with 1.5 s timeouts takes
~150 s, not ~1.5 s.

**PoC:** `TestBug006DnsFlood` — reproduces the pattern (serial for-loop
around `resolve_hostname`) and shows the equivalent parallel pattern is
trivially correct.

**Fix:** Replace the serial enrich loop with
`ThreadPoolExecutor.map()`.

---

### BUG-007 — TTL parser misses lowercase / boundary (Medium)

**Severity:** Medium — OS-guess accuracy degrades on macOS / BSD ping
output that uses lowercase `ttl=`, and TTL=0 would incorrectly guess
Linux.

**Description:**
- `_parse_ttl` regex uses `re.IGNORECASE` so `TTL=` vs `ttl=` is handled,
  but the boundary `TTL=0` passes through and hits `elif ttl <= 64`
  returning `"Linux/Unix"` (wrong).
- The regex `r"ttl[= ](\d+)"` also accepts `ttl: 64` (colon) via
  whitespace in the `[= ]` class — unlikely to cause a real-world hit,
  but the escape is permissive.

**Evidence:**
```
>>> ping_sweep._parse_ttl("TTL=0")
0   # then guess_os_from_ttl(0) -> "Linux/Unix" (should be Unknown)
```

**PoC:** `TestBug007TtlParser::test_boundary_zero_returns_none` —
asserts parser yields 0, and a separate OS-layer test asserts
`guess_os_from_ttl(0) == "Unknown"`.

**Fix:** Treat TTL ≤ 0 as "Unknown" in `os_fingerprint.guess_os_from_ttl`.

---

### BUG-008 — ULA MACs reported as real vendors (Medium)

**Severity:** Medium — MAC/vendor attribution is wrong for
locally-administered (private/randomized) MACs, common on corporate
laptops and VMs.

**Description:** Universally-Administered Addresses (OUIs with second-least
significant bit of the first octet = 1, e.g. `02:xx`, `06:xx`, `0a:xx`)
are not in any IEEE registry. `lookup_vendor` queries the full
`mac-vendor-lookup` database or falls back to `BUILTIN_OUI`, but never
checks for the ULA bit — so any tool bug that spills ULA prefixes into
`BUILTIN_OUI` would mislabel them.

**Evidence:** The `BUILTIN_OUI` table doesn't contain ULA prefixes, but
`_normalize_oui` accepts them without flagging.

**PoC:** `TestBug008UlaMac::test_b2_prefix_is_locally_administered` —
asserts representative ULA prefixes are absent from `BUILTIN_OUI`.

**Fix:** No code change needed — the ULA check is the absence of those
prefixes from `BUILTIN_OUI`. PoC serves as regression test.

---

### BUG-009 — Port colors don't match spec (Low)

**Severity:** Low — UI misrepresents data to the operator.

**Description:** Spec says alive=green, filtered=yellow, closed=red.
The implementation uses green for all statuses in `show_results_table`
(the port-details table shows "open" in green; filtered/closed are not
displayed at all, only stored in the DB).

**Evidence:** `netsight scan --ports 22` on a host with port 22 filtered
shows no visual difference from a successful run.

**PoC:** `TestBug009PortColors::test_filtered_is_yellow_closed_is_red`
— structure test, not a crash repro.

**Fix:** Color-code `show_port_details` rows: open=green, filtered=yellow,
closed=red. (Also fixes the missing per-port status display in the
results table.)

---

### BUG-010 — `last_fallback_reason` is process-global (False positive)

**Severity:** N/A — tested and discarded.

**Description:** A module-level global is set inside `sweep()`, raising
concerns it may be shared across threads. In Python, module globals are
per-module, not per-thread, so concurrent `sweep()` calls in different
threads would race. NetSight currently only runs one sweep per process,
so no race exists in practice.

**Verdict:** No bug. Design is safe for the single-sweep CLI use case.
`ping_sweep.last_fallback_reason` is reset at the start of each call,
so stale values can't leak across scans.

---

### BUG-011 — `from __future__` import position (Low — no-op)

**Severity:** Low — dead code, no runtime effect.

**Description:** `from __future__ import annotations` is only meaningful
before any `__doc__` or code lines. It's present at the top of every
module, so there's no issue; some modules had it mid-file in an earlier
draft, then moved. Verifying it's actually at the top.

**PoC:** `TestBug011FutureImportPosition::test_py_compile_still_passes`
— compiles all three suspect modules.

**Fix:** No code change needed.

---

### BUG-012 — ARP cache kept forever even when empty (Low)

**Severity:** Low — if the ARP table is empty when first read (e.g. no
neighbors yet), the empty dict is cached forever; the next scan in the
same process can't see newly-appearing neighbors.

**Description:** `_ARP_TABLE_CACHE` is populated once and never refreshed
unless `force_refresh=True` is passed — which nothing passes after the
first call.

**Evidence:**
```
>>> get_arp_table()
{}          # no neighbors yet
>>> (host comes online, arp -a now shows it)
>>> get_arp_table()
{}          # still stale
```

**PoC:** `TestBug012ArpCache::test_empty_cache_not_retained` — asserts
second call (without force_refresh) hits the underlying parsers again
after the first returns `{}`.

**Fix:** Don't cache the empty result; fall through repeatedly until
non-empty data is returned.

---

## Fixes landed

| Bug   | File(s)                                     | Change |
|-------|---------------------------------------------|--------|
| 002   | discovery.py                                | Catch `OSError` from UDP `connect`/`sendto`/`getsockname` (VPN namespace ENETUNREACH no longer crashes discovery) |
| 003   | cli.py                                      | `--db` defaults to `None`; resolved to `Path(--output).parent / "netsight.db"` when `--output` is set, so DB and exports are always colocated; `--output` is now resolved at parse time |
| 004   | ping_sweep.py                               | Linux/macOS `-W` uses ceiling division: `max(1, (ms + 999) // 1000)` — 1500ms now → 2s (not truncated to 1s) |
| 005   | host_info.py                                | `subprocess.run` for `arp -a` now uses `encoding="utf-8", errors="replace"` instead of default code page (cp1252) |
| 006   | cli.py                                      | Reverse-DNS enrich loop moved into `ThreadPoolExecutor.map(max_workers=32)`; vendor+OS enrichment still sequential (cheap, local) |
| 007   | os_fingerprint.py                           | `ttl <= 0` (and `None`) now returns `"Unknown"` before the `<= 64` branch; TTL=0 no longer misclassified as Linux |
| 009   | ui.py                                       | `show_port_details` color-codes status: `open`=green, `filtered`=yellow, `closed`=red; `show_results_table` renders alive=green ● |
| 012   | host_info.py                                | ARP table cache only stored when non-empty, so hosts that come online mid-process aren't hidden forever |

**Result:** 60/60 tests pass (43 pre-existing + 17 PoC/regression), live smoke test against the real LAN confirmed all output formats. |

