#!/usr/bin/env python3
"""Analyze Suricata alert bridge statistics by /24 subnets per day.

Sources:
  1. /var/log/suricata/alert-bridge-state.json (current day state)
  2. journalctl -u alert-bridge (historical logs across multiple days)
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
    """
    Parses journalctl output into structure:
    {
       "YYYY-MM-DD": {
           "inbound": {"ip": count, ...},
           "outbound": {"ip": count, ...}
       }
    }
    """
    days_data = defaultdict(lambda: {"inbound": defaultdict(int), "outbound": defaultdict(int)})

    try:
        cmd = ["journalctl", "-u", "alert-bridge", "--output=short-iso", "--no-pager"]
        output = subprocess.check_output(cmd, text=True, errors="replace")
    except Exception as e:
        print(f"Warning: failed to read journalctl: {e}", file=sys.stderr)
        return days_data

    # Match ISO timestamp: 2026-08-04T22:25:23+0300
    date_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2})T")
    inbound_pattern = re.compile(r"(inbound-alert|alert).*?\battacker=([0-9a-fA-F:\.]+)")
    outbound_pattern = re.compile(r"outbound-alert.*?\btarget=([0-9a-fA-F:\.]+)")

    for line in output.splitlines():
        date_match = date_pattern.match(line)
        if not date_match:
            continue
        day = date_match.group(1)

        in_match = inbound_pattern.search(line)
        if in_match:
            ip = in_match.group(2)
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


def aggregate_subnet_24(ip_counts: dict[str, int]) -> list[tuple[str, int, int]]:
    """
    Groups IP counts by /24 subnet.
    Returns sorted list of tuples: (subnet_24_str, unique_ip_count, total_alerts)
    """
    subnets = defaultdict(lambda: {"ips": set(), "total_alerts": 0})

    for ip_str, count in ip_counts.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version == 4:
                net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                net_str = str(net)
            else:
                # IPv6 /64 prefix
                net = ipaddress.ip_network(f"{ip_str}/64", strict=False)
                net_str = str(net)
        except ValueError:
            continue

        subnets[net_str]["ips"].add(ip_str)
        subnets[net_str]["total_alerts"] += count

    res = []
    for net_str, info in subnets.items():
        res.append((net_str, len(info["ips"]), info["total_alerts"]))

    # Sort by total_alerts descending, then unique IPs descending
    res.sort(key=lambda x: (x[2], x[1]), reverse=True)
    return res


def print_table(day: str, direction: str, aggregated: list[tuple[str, int, int]]):
    if not aggregated:
        return

    total_subnets = len(aggregated)
    total_unique_ips = sum(unique_ips for _, unique_ips, _ in aggregated)
    total_alerts = sum(alerts for _, _, alerts in aggregated)
    avg_ips_per_subnet = total_unique_ips / total_subnets if total_subnets > 0 else 0.0

    print(f"\n📅 Date: {day} | Traffic: {direction.upper()}")
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
    parser.add_argument("--state-file", default="/var/log/suricata/alert-bridge-state.json", help="Path to state JSON")
    parser.add_argument("--journal", action="store_true", default=True, help="Parse historical journalctl logs")
    args = parser.parse_argument() if len(sys.argv) > 1 else parser.parse_args([])

    days_data = defaultdict(lambda: {"inbound": defaultdict(int), "outbound": defaultdict(int)})

    # Load from journalctl if available
    if args.journal:
        j_data = parse_journal_logs()
        for day, traffic in j_data.items():
            for ip, cnt in traffic["inbound"].items():
                days_data[day]["inbound"][ip] += cnt
            for ip, cnt in traffic["outbound"].items():
                days_data[day]["outbound"][ip] += cnt

    # Merge current state file if available
    state = load_state_file(args.state_file)
    if state and "date" in state:
        day = state["date"]
        for ip, cnt in state.get("inbound_counts", {}).items():
            days_data[day]["inbound"][ip] = max(days_data[day]["inbound"][ip], cnt)
        for ip, cnt in state.get("outbound_counts", {}).items():
            days_data[day]["outbound"][ip] = max(days_data[day]["outbound"][ip], cnt)

    if not days_data:
        print("No statistics found in state file or journalctl.")
        return

    for day in sorted(days_data.keys()):
        inbound_agg = aggregate_subnet_24(days_data[day]["inbound"])
        print_table(day, "Inbound", inbound_agg)

        outbound_agg = aggregate_subnet_24(days_data[day]["outbound"])
        print_table(day, "Outbound", outbound_agg)


if __name__ == "__main__":
    main()
