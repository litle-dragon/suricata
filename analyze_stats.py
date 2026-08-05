#!/usr/bin/env python3
"""Analyze Suricata alert bridge statistics by /24 subnets.

Modes:
  - Default: analyzes current day state file (/var/log/suricata/alert-bridge-state.json)
  - With --sum / --total: analyzes all-time cumulative state file (/var/log/suricata/alert-bridge-total-state.json)
  - With --journal: parses historical journalctl logs
  - With --sync-mikrotik: blocks subnets with >=10 unique IPs on MikroTik and removes redundant single IPs
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    requests = None


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
                        if v and not os.environ.get(k):
                            os.environ[k] = v
        except PermissionError:
            print(f"Warning: Permission denied reading {env_path}. Run with 'sudo' to read MikroTik credentials.", file=sys.stderr)
        except Exception as e:
            print(f"Warning: failed to read {env_path}: {e}", file=sys.stderr)


def parse_journal_logs() -> dict[str, dict[str, dict[str, int]]]:
    days_data = defaultdict(lambda: {"inbound": defaultdict(int), "outbound": defaultdict(int)})
    try:
        cmd = ["journalctl", "-u", "alert-bridge", "--output=short-iso", "--no-pager"]
        output = subprocess.check_output(cmd, text=True, errors="replace")
    except Exception as e:
        print(f"Warning: failed to read journalctl: {e}", file=sys.stderr)
        return days_data

    date_pattern = re.compile(r"(\d{4}-\d{2}-\d{2})")
    inbound_pattern = re.compile(r"attacker=([0-9a-fA-F:\.]+)")
    outbound_pattern = re.compile(r"target=([0-9a-fA-F:\.]+)")

    for line in output.splitlines():
        date_match = date_pattern.search(line)
        if not date_match:
            continue
        day = date_match.group(1)

        in_match = inbound_pattern.search(line)
        if in_match:
            ip = in_match.group(1)
            days_data[day]["inbound"][ip] += 1
            continue

        out_match = outbound_pattern.search(line)
        if out_match:
            ip = out_match.group(1)
            days_data[day]["outbound"][ip] += 1
            continue

    return days_data


def load_state_file(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: failed to load {path}: {e}", file=sys.stderr)
    return {}


def aggregate_subnet_24(ip_counts: dict[str, int], min_ips: int = 5) -> list[tuple[str, int, int]]:
    subnets = defaultdict(lambda: {"ips": set(), "total_alerts": 0})

    for ip_str, count in ip_counts.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            prefix = 24 if ip_obj.version == 4 else 64
            net_str = str(ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False))
        except ValueError:
            continue

        subnets[net_str]["ips"].add(ip_str)
        subnets[net_str]["total_alerts"] += count

    res = []
    for net_str, info in subnets.items():
        unique_cnt = len(info["ips"])
        if unique_cnt >= min_ips:
            res.append((net_str, unique_cnt, info["total_alerts"]))

    res.sort(key=lambda x: (x[2], x[1]), reverse=True)
    return res


def print_table(title: str, direction: str, aggregated: list[tuple[str, int, int]]):
    if not aggregated:
        print(f"\n📅 {title} | Traffic: {direction.upper()}")
        print("No subnets matched criteria (min unique IPs).")
        return

    total_subnets = len(aggregated)
    total_unique_ips = sum(unique_ips for _, unique_ips, _ in aggregated)
    total_alerts = sum(alerts for _, _, alerts in aggregated)
    avg_ips_per_subnet = total_unique_ips / total_subnets if total_subnets > 0 else 0.0

    print(f"\n📅 {title} | Traffic: {direction.upper()}")
    print("=" * 65)
    print(f"{'Subnet (/24)':<22} | {'Unique IPs':<12} | {'Total Alerts':<12}")
    print("-" * 65)
    for net_str, unique_ips, alerts in aggregated:
        print(f"{net_str:<22} | {unique_ips:<12} | {alerts:<12}")
    print("-" * 65)
    print(f"Summary: {total_subnets} subnets | {total_unique_ips} total unique IPs | "
          f"Avg IPs/subnet: {avg_ips_per_subnet:.2f} | Total alerts: {total_alerts}")
    print("=" * 65)


def sync_subnets_to_mikrotik(subnets_to_block: list[tuple[str, int, int]]):
    if requests is None:
        print("\nError: 'requests' library not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")
    block_list = os.environ.get("BLOCK_LIST", "suricata-block")
    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials (MT_HOST, MT_USER, MT_PASS) missing or unconfigured in /opt/alert-bridge/env.", file=sys.stderr)
        print("Make sure /opt/alert-bridge/env is configured and run with 'sudo python3 analyze_stats.py --sync-mikrotik'.", file=sys.stderr)
        return
    if not subnets_to_block:
        print("\nNo subnets matched the threshold (>= 10 unique IPs) to sync to MikroTik.")
        return

    print(f"\n🔄 Syncing {len(subnets_to_block)} subnets to MikroTik list '{block_list}'...")

    for subnet_str, unique_cnt, total_alerts in subnets_to_block:
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
            family = "ipv6" if net.version == 6 else "ip"
        except ValueError:
            family = "ip"
            net = None

        base_url = f"https://{mt_host}/rest/{family}/firewall/address-list"
        auth = (mt_user, mt_pass)

        # 1. Query existing address-list entries to remove single IPs covered by subnet
        try:
            r_get = requests.get(
                f"{base_url}?list={block_list}",
                auth=auth,
                verify=False,
                timeout=(5, 10),
            )
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
                                print(f"  🗑️ Removing redundant single IP {addr} (covered by subnet {subnet_str})...", flush=True)
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
            "comment": f"PERMANENT SUBNET ({unique_cnt} IPs, {total_alerts} hits)"[:60],
        }
        try:
            r_put = requests.put(
                base_url,
                json=body,
                auth=auth,
                verify=False,
                timeout=(5, 15),
            )
            if r_put.status_code in (200, 201) or "already" in r_put.text:
                print(f"  🔒 Blocked subnet {subnet_str} on MikroTik ({unique_cnt} IPs, {total_alerts} hits)", flush=True)
            else:
                print(f"  ⚠️ Failed to block subnet {subnet_str}: {r_put.status_code} {r_put.text}", flush=True)
        except requests.RequestException as e:
            print(f"  ⚠️ Exception blocking subnet {subnet_str}: {e}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata alert bridge statistics by /24 subnets.")
    parser.add_argument("--state-file", help="Path to state JSON file")
    parser.add_argument("--min-ips", type=int, default=5, help="Minimum unique IPs per subnet to display (default: 5)")
    parser.add_argument("--sum", "--total", "--journal", dest="sum", action="store_true", help="Read journalctl logs and total state files for complete historical summary")
    parser.add_argument("--sync-mikrotik", "--block-subnets", action="store_true", help="Block subnets with >=10 unique IPs on MikroTik and remove redundant single IPs")
    args = parser.parse_args()

    inbound_counts = {}

    if args.sum:
        # 1. Parse historical journalctl logs
        days_data = parse_journal_logs()

        # 2. Merge daily state file
        daily_state = load_state_file(args.state_file or "/var/log/suricata/alert-bridge-state.json")
        if daily_state and "date" in daily_state:
            day = daily_state["date"]
            for ip, cnt in daily_state.get("inbound_counts", {}).items():
                days_data[day]["inbound"][ip] = max(days_data[day]["inbound"][ip], cnt)

        # 3. Merge total state file
        total_state = load_state_file("/var/log/suricata/alert-bridge-total-state.json")
        total_inbound = defaultdict(int)

        for day in sorted(days_data.keys()):
            for ip, cnt in days_data[day]["inbound"].items():
                total_inbound[ip] += cnt

        for ip, cnt in total_state.get("inbound_counts", {}).items():
            total_inbound[ip] = max(total_inbound[ip], cnt)

        if not total_inbound:
            print("No statistics found in journalctl or state files.")
            return

        sorted_days = sorted(days_data.keys())
        period_str = f"Entire Period ({sorted_days[0]} .. {sorted_days[-1]})" if len(sorted_days) > 1 else f"Entire Period ({sorted_days[0]})" if sorted_days else "Entire Period"

        inbound_agg = aggregate_subnet_24(total_inbound, min_ips=args.min_ips)
        print_table(period_str, "Inbound Summary", inbound_agg)
        inbound_counts = total_inbound

    else:
        state_path = args.state_file or "/var/log/suricata/alert-bridge-state.json"
        state = load_state_file(state_path)
        if not state or "date" not in state:
            print(f"No statistics found in daily state file '{state_path}'.")
            print("Tip: use --sum to read historical logs from journalctl.")
            return

        day = state["date"]
        inbound_counts = state.get("inbound_counts", {})
        inbound_agg = aggregate_subnet_24(inbound_counts, min_ips=args.min_ips)
        print_table(f"Daily Stats ({day})", "Inbound", inbound_agg)
    if args.sync_mikrotik:
        # Filter subnets with >= 10 unique IPs (or args.min_ips if explicitly passed >= 10)
        sync_min_ips = max(10, args.min_ips)
        subnets_to_sync = aggregate_subnet_24(inbound_counts, min_ips=sync_min_ips)
        sync_subnets_to_mikrotik(subnets_to_sync)


if __name__ == "__main__":
    main()
