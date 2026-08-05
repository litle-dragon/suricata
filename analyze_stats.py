#!/usr/bin/env python3
"""Analyze Suricata alert bridge statistics by /24 subnets.

Modes:
  - Default: analyzes current day state file (/var/log/suricata/alert-bridge-state.json)
  - With --sum / --total: analyzes all-time cumulative state file (/var/log/suricata/alert-bridge-total-state.json)
  - With --journal: parses historical journalctl logs
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import defaultdict


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


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata alert bridge statistics by /24 subnets.")
    parser.add_argument("--state-file", help="Path to state JSON file")
    parser.add_argument("--min-ips", type=int, default=5, help="Minimum unique IPs per subnet to display (default: 5)")
    parser.add_argument("--sum", "--total", dest="total", action="store_true", help="Analyze all-time cumulative total state file (/var/log/suricata/alert-bridge-total-state.json)")
    parser.add_argument("--journal", action="store_true", help="Parse historical journalctl logs across all days")
    args = parser.parse_args()

    if args.journal:
        days_data = parse_journal_logs()
        if not days_data:
            print("No statistics found in journalctl.")
            return

        sorted_days = sorted(days_data.keys())
        total_inbound = defaultdict(int)
        total_outbound = defaultdict(int)
        for day in sorted_days:
            for ip, cnt in days_data[day]["inbound"].items():
                total_inbound[ip] += cnt
            for ip, cnt in days_data[day]["outbound"].items():
                total_outbound[ip] += cnt

        period_str = f"Journal History ({sorted_days[0]} .. {sorted_days[-1]})" if len(sorted_days) > 1 else f"Journal History ({sorted_days[0]})"

        inbound_agg = aggregate_subnet_24(total_inbound, min_ips=args.min_ips)
        print_table(period_str, "Inbound Summary", inbound_agg)

        outbound_agg = aggregate_subnet_24(total_outbound, min_ips=args.min_ips)
        print_table(period_str, "Outbound Summary", outbound_agg)

    elif args.total:
        state_path = args.state_file or "/var/log/suricata/alert-bridge-total-state.json"
        state = load_state_file(state_path)
        if not state:
            print(f"No statistics found in total state file '{state_path}'.")
            return

        inbound_counts = state.get("inbound_counts", {})
        outbound_counts = state.get("outbound_counts", {})

        inbound_agg = aggregate_subnet_24(inbound_counts, min_ips=args.min_ips)
        print_table("All-Time Total State", "Inbound Summary", inbound_agg)

        outbound_agg = aggregate_subnet_24(outbound_counts, min_ips=args.min_ips)
        print_table("All-Time Total State", "Outbound Summary", outbound_agg)

    else:
        # Default: Daily state file
        state_path = args.state_file or "/var/log/suricata/alert-bridge-state.json"
        state = load_state_file(state_path)
        if not state or "date" not in state:
            print(f"No statistics found in daily state file '{state_path}'.")
            print("Tip: use --sum (or --total) for all-time cumulative summary.")
            return

        day = state["date"]
        inbound_counts = state.get("inbound_counts", {})
        outbound_counts = state.get("outbound_counts", {})

        inbound_agg = aggregate_subnet_24(inbound_counts, min_ips=args.min_ips)
        print_table(f"Daily Stats ({day})", "Inbound", inbound_agg)

        outbound_agg = aggregate_subnet_24(outbound_counts, min_ips=args.min_ips)
        print_table(f"Daily Stats ({day})", "Outbound", outbound_agg)


if __name__ == "__main__":
    main()
