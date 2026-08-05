#!/usr/bin/env python3
"""Parse Suricata rules file and extract malicious IPs/subnets from 'alert <proto> [...]' source blocks.

Usage:
  python3 parse_rules_ips.py [--rules-file /var/lib/suricata/rules/suricata.rules] [--output malicios_subnets.txt]
"""

import argparse
import ipaddress
import os
import re
import sys


def extract_ips_from_rules(rules_path: str) -> list[str]:
    """
    Parses Suricata rules file and extracts IPs/subnets from bracketed source blocks
    in rules starting with 'alert <proto> [...]'.
    """
    # Matches 'alert <proto> [...]' where [...] is the source IP block
    rule_pattern = re.compile(r"^\s*alert\s+\w+\s+\[([^\]]+)\]", re.IGNORECASE)
    # Extracts IP or CIDR tokens: e.g. 98.98.195.0/24 or 1.2.3.4
    ip_pattern = re.compile(r"([0-9a-fA-F:\.]+(?:/\d{1,3})?)")

    found_nets = set()
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
                        try:
                            net = ipaddress.ip_network(item, strict=False)
                            found_nets.add(str(net))
                        except ValueError:
                            pass
    except FileNotFoundError:
        print(f"Error: rules file '{rules_path}' not found.", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error reading rules file: {e}", file=sys.stderr)
        return []

    print(f"Parsed {total_rules_matched} matching 'alert <proto> [...]' rules. Found {len(found_nets)} unique IPs/subnets.", file=sys.stderr)
    return sorted(list(found_nets), key=lambda x: (ipaddress.ip_network(x, strict=False).version, ipaddress.ip_network(x, strict=False)))


def main():
    default_rules = "/var/lib/suricata/rules/suricata.rules"
    if not os.path.exists(default_rules):
        default_rules = "/etc/suricata/rules/suricata.rules"

    parser = argparse.ArgumentParser(description="Extract malicious IPs/subnets from Suricata 'alert <proto> [...]' rules.")
    parser.add_argument("--rules-file", default=default_rules, help=f"Path to suricata.rules file (default: {default_rules})")
    parser.add_argument("--output", help="Save extracted subnets to text file")
    args = parser.parse_args()

    subnets = extract_ips_from_rules(args.rules_file)

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
