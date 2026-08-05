#!/usr/bin/env python3
"""Parse Suricata rules file and extract malicious IPs/subnets from 'alert <proto> [...]' source blocks.

Usage:
  python3 parse_rules_ips.py [--rules-file /var/lib/suricata/rules/suricata.rules] [--output malicious_subnets.txt]
"""

import argparse
import ipaddress
import os
import re
import sys
from collections import defaultdict


def aggregate_ips_to_24(items: set[str], min_ips_per_24: int = 2) -> list[str]:
    """
    Aggregates individual IP addresses into parent /24 subnets (or /64 for IPv6).
    Single IPs are converted to /24 only if at least min_ips_per_24 (default: 2) IPs are in that subnet.
    """
    subnets = set()
    ip_groups = defaultdict(set)

    for item in items:
        try:
            net = ipaddress.ip_network(item, strict=False)
            if (net.version == 4 and net.prefixlen < 32) or (net.version == 6 and net.prefixlen < 128):
                subnets.add(net)
            else:
                if net.version == 4:
                    parent = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
                    ip_groups[parent].add(net)
                else:
                    parent = ipaddress.ip_network(f"{net.network_address}/64", strict=False)
                    ip_groups[parent].add(net)
        except ValueError:
            pass

    for parent_net, ips in ip_groups.items():
        if len(ips) >= min_ips_per_24:
            subnets.add(parent_net)
        else:
            for ip_net in ips:
                subnets.add(ip_net)

    # Remove any single IPs that are covered by any parent subnets
    all_subnets = [n for n in subnets if (n.version == 4 and n.prefixlen < 32) or (n.version == 6 and n.prefixlen < 128)]
    all_singles = [n for n in subnets if (n.version == 4 and n.prefixlen == 32) or (n.version == 6 and n.prefixlen == 128)]

    final_set = set(all_subnets)
    for single in all_singles:
        if not any(single.network_address in sub for sub in all_subnets):
            final_set.add(single)

    res = list(final_set)
    res.sort(key=lambda x: (x.version, x.network_address, x.prefixlen))
    return [str(net) for net in res]


def extract_ips_from_rules(rules_path: str, aggregate_24: bool = True, min_ips_per_24: int = 2) -> list[str]:
    """
    Parses Suricata rules file and extracts IPs/subnets from bracketed source blocks
    in rules starting with 'alert <proto> [...]'.
    """
    rule_pattern = re.compile(r"^\s*alert\s+\w+\s+\[([^\]]+)\]", re.IGNORECASE)
    ip_pattern = re.compile(r"([0-9a-fA-F:\.]+(?:/\d{1,3})?)")

    found_raw = set()
    total_rules_matched = 0

    try:
        with open(rules_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                match = rule_pattern.search(line)
                if match:
                    total_rules_matched += 1
                    brackets_content = match.group(1)
                    for item in ip_pattern.findall(brackets_content):
                        item = item.strip().lstrip("!")
                        if not item:
                            continue
                        found_raw.add(item)
    except FileNotFoundError:
        print(f"Error: rules file '{rules_path}' not found.", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error reading rules file: {e}", file=sys.stderr)
        return []

    print(f"Parsed {total_rules_matched} matching 'alert <proto> [...]' rules. Found {len(found_raw)} raw items.", file=sys.stderr)

    if aggregate_24:
        result = aggregate_ips_to_24(found_raw, min_ips_per_24=min_ips_per_24)
        print(f"Aggregated into {len(result)} unique subnets/IPs.", file=sys.stderr)
        return result
    else:
        # No aggregation mode
        subnets = set()
        for item in found_raw:
            try:
                subnets.add(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                pass
        result = sorted(list(subnets), key=lambda x: (ipaddress.ip_network(x, strict=False).version, ipaddress.ip_network(x, strict=False)))
        return result


def main():
    default_rules = "/var/lib/suricata/rules/suricata.rules"
    if not os.path.exists(default_rules):
        default_rules = "/etc/suricata/rules/suricata.rules"

    parser = argparse.ArgumentParser(description="Extract malicious IPs/subnets from Suricata 'alert <proto> [...]' rules.")
    parser.add_argument("--rules-file", default=default_rules, help=f"Path to suricata.rules file (default: {default_rules})")
    parser.add_argument("--output", help="Save extracted subnets to text file")
    parser.add_argument("--aggregate-24", action="store_true", default=True, help="Aggregate individual single IPs into /24 subnets (enabled by default)")
    parser.add_argument("--no-aggregate-24", dest="aggregate_24", action="store_false", help="Do not aggregate single IPs into /24 subnets")
    parser.add_argument("--min-ips-per-24", type=int, default=2, help="Minimum single IPs in subnet required for /24 aggregation (default: 2)")
    args = parser.parse_args()

    subnets = extract_ips_from_rules(args.rules_file, aggregate_24=args.aggregate_24, min_ips_per_24=args.min_ips_per_24)

    if not subnets:
        print("No subnets found or rules file not accessible.")
        return

    if args.output:
        try:
            with open(args.output, "w") as f:
                for net in subnets:
                    f.write(f"{net}\n")
            print(f"Successfully saved {len(subnets)} subnets to '{args.output}'.")
        except Exception as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
    else:
        for net in subnets:
            print(net)


if __name__ == "__main__":
    main()
