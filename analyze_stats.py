#!/usr/bin/env python3
"""Analyze the Suricata alert-bridge SQLite database.

Reads /var/log/suricata/alert_bridge.db directly (no journal parsing):
  --sum                 Summary across every recorded day (daily_stats).
  --day YYYY-MM-DD      Full breakdown for one historical day.
  --spikes              Log of all anomaly spike alerts (spike_events).
  --top N               Top N attacker subnets and IPs all-time (seen_subnets / seen_ips).
  --sync-mikrotik       Block /24 subnets with >= MIN unique IPs all-time on MikroTik.

With no mode given, prints the --sum summary.
"""

import argparse
import ipaddress
import json
import os
import sqlite3
import sys
from collections import defaultdict

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    requests = None

DB_FILE = os.environ.get("DB_FILE", "/var/log/suricata/alert_bridge.db")


def load_env():
    env_path = "/opt/alert-bridge/env"
    if os.path.exists(env_path):
        try:
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if v:
                            os.environ[k] = v
        except PermissionError:
            print(f"Warning: Permission denied reading {env_path}. Run with 'sudo' to read MikroTik credentials.", file=sys.stderr)
        except Exception as e:
            print(f"Warning: failed to read {env_path}: {e}", file=sys.stderr)


def connect_db() -> sqlite3.Connection | None:
    if not os.path.exists(DB_FILE):
        print(f"Error: database not found at {DB_FILE}. Is alert-bridge running?", file=sys.stderr)
        return None
    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def aggregate_seen_subnets(conn: sqlite3.Connection, min_ips: int = 1) -> list[tuple[str, int, int]]:
    """Aggregate seen_ips into /24 (or /64) subnets: (subnet, unique_ips, total_hits)."""
    subnets = defaultdict(lambda: {"ips": set(), "hits": 0})
    for row in conn.execute("SELECT ip, total_hits FROM seen_ips"):
        ip_str, hits = row["ip"], row["total_hits"]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            prefix = 24 if ip_obj.version == 4 else 64
            net_str = str(ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False))
        except ValueError:
            continue
        subnets[net_str]["ips"].add(ip_str)
        subnets[net_str]["hits"] += hits
    res = [
        (net, len(info["ips"]), info["hits"])
        for net, info in subnets.items()
        if len(info["ips"]) >= min_ips
    ]
    res.sort(key=lambda x: (x[2], x[1]), reverse=True)
    return res


def cmd_sum(conn: sqlite3.Connection):
    rows = list(conn.execute(
        "SELECT date, total_alerts, unique_ips, unique_subnets, new_ips_count, "
        "new_subnets_count, perm_ips_count, perm_subnets_count FROM daily_stats ORDER BY date"
    ))
    if not rows:
        print("No daily statistics recorded yet (daily_stats is empty).")
        return

    print(f"\n📊 Daily summary — {rows[0]['date']} .. {rows[-1]['date']} ({len(rows)} days)")
    print("=" * 92)
    print(f"{'Date':<12} | {'Alerts':>10} | {'Uniq IP':>9} | {'New IP':>9} | "
          f"{'Uniq Net':>9} | {'New Net':>8} | {'PermIP':>7} | {'PermNet':>7}")
    print("-" * 92)
    tot_alerts = tot_new_ips = tot_new_nets = tot_perm_ips = tot_perm_nets = 0
    for r in rows:
        print(f"{r['date']:<12} | {r['total_alerts']:>10,} | {r['unique_ips']:>9,} | "
              f"{r['new_ips_count']:>9,} | {r['unique_subnets']:>9,} | {r['new_subnets_count']:>8,} | "
              f"{r['perm_ips_count']:>7,} | {r['perm_subnets_count']:>7,}")
        tot_alerts += r["total_alerts"]
        tot_new_ips += r["new_ips_count"]
        tot_new_nets += r["new_subnets_count"]
        tot_perm_ips += r["perm_ips_count"]
        tot_perm_nets += r["perm_subnets_count"]
    print("-" * 92)
    print(f"Totals: {tot_alerts:,} alerts | {tot_new_ips:,} new IPs | {tot_new_nets:,} new subnets | "
          f"{tot_perm_ips:,} perm IPs | {tot_perm_nets:,} perm subnets")
    print("=" * 92)


def cmd_day(conn: sqlite3.Connection, day: str):
    r = conn.execute("SELECT * FROM daily_stats WHERE date=?", (day,)).fetchone()
    if not r:
        print(f"No record for {day}. Available days: use --sum to list.")
        return
    top = json.loads(r["top_subnets_json"])
    print(f"\n🌅 Day report ({day})")
    print("=" * 65)
    print(f"• Total alerts:              {r['total_alerts']:,}")
    print(f"• Unique IPs:                {r['unique_ips']:,}")
    print(f"• New IPs (never seen):      {r['new_ips_count']:,}")
    print(f"• Unique subnets:            {r['unique_subnets']:,}")
    print(f"• New subnets (never seen):  {r['new_subnets_count']:,}")
    print(f"• Avg alerts / IP:           {r['avg_alerts_per_ip']:,}")
    print(f"• Avg alerts / subnet:       {r['avg_alerts_per_subnet']:,}")
    print(f"• Permanent IP blocks:       {r['perm_ips_count']:,}")
    print(f"• Permanent subnet blocks:   {r['perm_subnets_count']:,}")
    print(f"• Single (non-aggregated):   {r['single_ips_count']:,} IPs ({r['single_ips_alerts']:,} alerts)")
    if top:
        print("-" * 65)
        print("TOP subnets (/24, >= 2 IPs):")
        for t in top:
            print(f"  {t['subnet']:<20} {t['ips']:>5,} IP | {t['alerts']:>7,} alerts (avg {t['avg']:,}/IP)")
    print("=" * 65)


def cmd_spikes(conn: sqlite3.Connection):
    rows = list(conn.execute(
        "SELECT timestamp, start_time, end_time, total_alerts, avg_rate_per_min, unique_ips "
        "FROM spike_events ORDER BY id"
    ))
    if not rows:
        print("No anomaly spike events recorded.")
        return
    print(f"\n🚨 Anomaly spike events ({len(rows)} total)")
    print("=" * 78)
    print(f"{'When (UTC)':<21} | {'Window':<15} | {'Alerts':>8} | {'Rate/min':>9} | {'Uniq IP':>8}")
    print("-" * 78)
    for r in rows:
        window = f"{r['start_time']}-{r['end_time']}"
        print(f"{r['timestamp']:<21} | {window:<15} | {r['total_alerts']:>8,} | "
              f"{r['avg_rate_per_min']:>9,} | {r['unique_ips']:>8,}")
    print("=" * 78)


def cmd_top(conn: sqlite3.Connection, n: int):
    subnets = aggregate_seen_subnets(conn, min_ips=1)[:n]
    print(f"\n🏆 Top {n} attacker subnets all-time (/24, by total hits)")
    print("=" * 65)
    print(f"{'Subnet':<22} | {'Unique IPs':>11} | {'Total hits':>11}")
    print("-" * 65)
    for net, uniq, hits in subnets:
        print(f"{net:<22} | {uniq:>11,} | {hits:>11,}")
    print("=" * 65)

    ips = list(conn.execute(
        "SELECT ip, total_hits FROM seen_ips ORDER BY total_hits DESC LIMIT ?", (n,)
    ))
    print(f"\n🏆 Top {n} attacker IPs all-time (by total hits)")
    print("=" * 45)
    print(f"{'IP':<32} | {'Total hits':>10}")
    print("-" * 45)
    for r in ips:
        print(f"{r['ip']:<32} | {r['total_hits']:>10,}")
    print("=" * 45)


def sync_subnets_to_mikrotik(subnets_to_block: list[tuple[str, int, int]]):
    if requests is None:
        print("\nError: 'requests' library not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return
    load_env()
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")
    block_list = os.environ.get("BLOCK_LIST", "suricata-block")
    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials incomplete in /opt/alert-bridge/env:", file=sys.stderr)
        print(f"  MT_HOST = '{mt_host}'", file=sys.stderr)
        print(f"  MT_USER = '{mt_user}'", file=sys.stderr)
        print(f"  MT_PASS = {'(set)' if mt_pass and 'YOUR_' not in mt_pass else '(missing or unconfigured)'}", file=sys.stderr)
        print("Please edit /opt/alert-bridge/env with your router LAN IP and suricata API user password.", file=sys.stderr)
        return
    if not subnets_to_block:
        print("\nNo subnets matched the threshold to sync to MikroTik.")
        return

    print(f"\n🔄 Syncing {len(subnets_to_block)} subnets to MikroTik list '{block_list}'...")

    for subnet_str, unique_cnt, total_hits in subnets_to_block:
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
            family = "ipv6" if net.version == 6 else "ip"
        except ValueError:
            family = "ip"
            net = None

        base_url = f"https://{mt_host}/rest/{family}/firewall/address-list"
        auth = (mt_user, mt_pass)

        # 1. Remove single IPs covered by this subnet, plus any dynamic entry for the subnet itself
        try:
            r_get = requests.get(f"{base_url}?list={block_list}", auth=auth, verify=False, timeout=(5, 10))
            if r_get.status_code == 200:
                entries = r_get.json()
                if isinstance(entries, list):
                    for entry in entries:
                        addr = entry.get("address", "")
                        entry_id = entry.get(".id")
                        if not entry_id or not addr:
                            continue
                        try:
                            addr_obj = ipaddress.ip_address(addr)
                            if net and addr_obj in net:
                                print(f"  🗑️ Removing redundant single IP {addr} (covered by {subnet_str})...", flush=True)
                                requests.delete(f"{base_url}/{entry_id}", auth=auth, verify=False, timeout=(5, 10))
                        except ValueError:
                            if addr == subnet_str and (entry.get("timeout") or entry.get("dynamic") == "true"):
                                requests.delete(f"{base_url}/{entry_id}", auth=auth, verify=False, timeout=(5, 10))
        except requests.RequestException as e:
            print(f"  Warning: failed to query MikroTik entries for {subnet_str}: {e}", file=sys.stderr)

        # 2. Add permanent subnet block
        body = {
            "list": block_list,
            "address": subnet_str,
            "comment": f"PERMANENT SUBNET ({unique_cnt} IPs, {total_hits} hits)"[:60],
        }
        try:
            r_put = requests.put(base_url, json=body, auth=auth, verify=False, timeout=(5, 15))
            if r_put.status_code in (200, 201) or "already" in r_put.text:
                print(f"  🔒 Blocked subnet {subnet_str} ({unique_cnt} IPs, {total_hits} hits)", flush=True)
            else:
                print(f"  ⚠️ Failed to block subnet {subnet_str}: {r_put.status_code} {r_put.text}", flush=True)
        except requests.RequestException as e:
            print(f"  ⚠️ Exception blocking subnet {subnet_str}: {e}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata alert-bridge SQLite statistics.")
    parser.add_argument("--sum", "--total", action="store_true", help="Summary across every recorded day")
    parser.add_argument("--day", metavar="YYYY-MM-DD", help="Full breakdown for one day")
    parser.add_argument("--spikes", action="store_true", help="Log of all anomaly spike alerts")
    parser.add_argument("--top", type=int, metavar="N", help="Top N attacker subnets and IPs all-time")
    parser.add_argument("--min-ips", type=int, default=10, help="Min unique IPs per subnet for --sync-mikrotik (default: 10)")
    parser.add_argument("--sync-mikrotik", "--block-subnets", action="store_true",
                        help="Block /24 subnets with >= --min-ips unique IPs all-time on MikroTik")
    args = parser.parse_args()

    conn = connect_db()
    if conn is None:
        sys.exit(1)

    try:
        did_something = False
        if args.day:
            cmd_day(conn, args.day)
            did_something = True
        if args.spikes:
            cmd_spikes(conn)
            did_something = True
        if args.top:
            cmd_top(conn, args.top)
            did_something = True
        if args.sync_mikrotik:
            subnets = aggregate_seen_subnets(conn, min_ips=max(10, args.min_ips))
            sync_subnets_to_mikrotik(subnets)
            did_something = True
        if args.sum or not did_something:
            cmd_sum(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
