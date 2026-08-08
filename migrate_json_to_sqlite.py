#!/usr/bin/env python3
"""One-time migration: seed the SQLite all-time history from the legacy JSON state.

Before the SQLite migration the bridge kept attacker history in two JSON files:
  /var/log/suricata/alert-bridge-total-state.json  (cumulative, all days)
  /var/log/suricata/alert-bridge-state.json        (current day)

This imports the INBOUND attacker IPs and their /24 (/64) subnets into the new
seen_ips / seen_subnets tables, so the first day after the switch does not report
every already-known attacker as "new". Inbound only — that mirrors exactly what
the running bridge records for all-time uniqueness.

Safe to run once, before or after the new bridge first starts: it creates the
tables if missing and never overwrites existing rows (INSERT OR IGNORE).

Usage:
  sudo python3 migrate_json_to_sqlite.py
  sudo python3 migrate_json_to_sqlite.py --dry-run
  sudo python3 migrate_json_to_sqlite.py --db /tmp/x.db --total total.json --daily daily.json
"""

import argparse
import ipaddress
import json
import os
import sqlite3
import sys
import syslog

syslog.openlog(ident="migrate_json_to_sqlite", logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)


def _jlog(msg: str, level: int = syslog.LOG_INFO) -> None:
    """Mirror to the journal (todo #6) — this is a one-off manual script, not
    a systemd service, so its stdout is not captured by journald automatically."""
    try:
        syslog.syslog(level, msg)
    except Exception:
        pass

DB_FILE = os.environ.get("DB_FILE", "/var/log/suricata/alert_bridge.db")
TOTAL_STATE_FILE = "/var/log/suricata/alert-bridge-total-state.json"
STATE_FILE = "/var/log/suricata/alert-bridge-state.json"

# Only the uniqueness tables are needed; column layout matches alert-bridge.py.
SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_ips (
    ip TEXT PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_hits INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS seen_subnets (
    subnet TEXT PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_hits INTEGER DEFAULT 1
);
"""


def get_subnet(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        prefix = 24 if ip_obj.version == 4 else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ip


def load(path: str) -> dict:
    if not os.path.exists(path):
        print(f"note: {path} not found — skipping", file=sys.stderr)
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"warning: failed to read {path}: {e}", file=sys.stderr)
        return {}


def main():
    ap = argparse.ArgumentParser(description="Seed SQLite seen_ips/seen_subnets from legacy JSON state.")
    ap.add_argument("--db", default=DB_FILE, help=f"SQLite database (default: {DB_FILE})")
    ap.add_argument("--total", default=TOTAL_STATE_FILE, help="legacy total-state JSON")
    ap.add_argument("--daily", default=STATE_FILE, help="legacy daily-state JSON")
    ap.add_argument("--dry-run", action="store_true", help="report only, write nothing")
    args = ap.parse_args()

    total = load(args.total)
    daily = load(args.daily)

    # Merge inbound per-IP counts; the cumulative file dominates, daily fills gaps.
    ip_hits: dict[str, int] = {}
    for src in (total.get("inbound_counts", {}), daily.get("inbound_counts", {})):
        for ip, cnt in src.items():
            ip_hits[ip] = max(ip_hits.get(ip, 0), int(cnt))

    if not ip_hits:
        print("Nothing to migrate — no inbound_counts found in the JSON state.")
        return

    # Derive subnets from IPs so the format matches the running bridge exactly.
    subnet_hits: dict[str, int] = {}
    for ip, cnt in ip_hits.items():
        subnet_hits[get_subnet(ip)] = subnet_hits.get(get_subnet(ip), 0) + cnt

    print(f"Found {len(ip_hits):,} inbound IPs and {len(subnet_hits):,} subnets to seed.")
    _jlog(f"found {len(ip_hits)} inbound IPs and {len(subnet_hits)} subnets to seed "
          f"(dry_run={args.dry_run})")
    if args.dry_run:
        print("Dry-run: no changes written.")
        return

    os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)
    conn = sqlite3.connect(args.db)
    try:
        conn.executescript(SCHEMA)
        before = conn.total_changes
        conn.executemany(
            "INSERT OR IGNORE INTO seen_ips(ip, total_hits) VALUES(?, ?)",
            list(ip_hits.items()),
        )
        mid = conn.total_changes
        conn.executemany(
            "INSERT OR IGNORE INTO seen_subnets(subnet, total_hits) VALUES(?, ?)",
            list(subnet_hits.items()),
        )
        after = conn.total_changes
        conn.commit()
    finally:
        conn.close()

    ins_ips = mid - before
    ins_subnets = after - mid
    print(f"Seeded {ins_ips:,} new IPs and {ins_subnets:,} new subnets "
          f"({len(ip_hits) - ins_ips:,} IPs / {len(subnet_hits) - ins_subnets:,} subnets already present).")
    _jlog(f"seeded {ins_ips} new IPs and {ins_subnets} new subnets into {args.db}")


if __name__ == "__main__":
    main()
