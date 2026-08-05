#!/usr/bin/env python3
"""Analyze Suricata alert bridge statistics by /24 subnets from state JSON file.

Reads /var/log/suricata/alert-bridge-state.json and aggregates IP counts by /24 subnets.
"""

import argparse
import ipaddress
import json
import os
import sys
from collections import defaultdict


def load_state_file(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: failed to load {path}: {e}", file=sys.stderr)
    else:
        print(f"Error: state file '{path}' not found.", file=sys.stderr)
    return {}


def aggregate_subnet_24(ip_counts: dict[str, int], min_ips: int = 5) -> list[tuple[str, int, int]]:
    """
    Groups IP counts by /24 subnet, filtering subnets with < min_ips unique IPs.
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
        unique_cnt = len(info["ips"])
        if unique_cnt >= min_ips:
            res.append((net_str, unique_cnt, info["total_alerts"]))

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
    parser = argparse.ArgumentParser(description="Analyze Suricata alert bridge statistics by /24 subnets from state JSON.")
    parser.add_argument("--state-file", default="/var/log/suricata/alert-bridge-state.json", help="Path to state JSON")
    parser.add_argument("--min-ips", type=int, default=5, help="Minimum unique IPs per subnet to display (default: 5)")
    parser.add_argument("--per-day", action="store_true", help="Display breakdown per day")
    parser.add_argument("--sum", action="store_true", help="Display summary aggregated across the entire period")
    args = parser.parse_args()

    # Default behavior if neither --per-day nor --sum is specified: default to --sum
    if not args.per_day and not args.sum:
        show_per_day = False
        show_sum = True
    else:
        show_per_day = args.per_day
        show_sum = args.sum

    state = load_state_file(args.state_file)
    if not state or "date" not in state:
        print("No statistics found in state file.")
        return

    day = state["date"]
    inbound_counts = state.get("inbound_counts", {})
    outbound_counts = state.get("outbound_counts", {})

    if not inbound_counts and not outbound_counts:
        print(f"State file ({day}) contains no alert entries.")
        return

    if show_per_day:
        inbound_agg = aggregate_subnet_24(inbound_counts, min_ips=args.min_ips)
        print_table(f"State File Date: {day}", "Inbound", inbound_agg)

        outbound_agg = aggregate_subnet_24(outbound_counts, min_ips=args.min_ips)
        print_table(f"State File Date: {day}", "Outbound", outbound_agg)

    if show_sum:
        inbound_sum_agg = aggregate_subnet_24(inbound_counts, min_ips=args.min_ips)
        print_table(f"State File Date: {day}", "Inbound Summary", inbound_sum_agg)

        outbound_sum_agg = aggregate_subnet_24(outbound_counts, min_ips=args.min_ips)
        print_table(f"State File Date: {day}", "Outbound Summary", outbound_sum_agg)


if __name__ == "__main__":
    main()
