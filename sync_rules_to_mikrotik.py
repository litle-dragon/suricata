#!/usr/bin/env python3
"""Sync Suricata malicious subnets (from parse_rules_ips.py / malicious_subnets.txt) to MikroTik.

Modes:
  1. Fast RSC Mode (--generate-rsc blocklist.rsc):
     Generates a single RouterOS script file for instant bulk import (/import file-name=blocklist.rsc).
  2. REST API Differential Sync (--api / default):
     Reads current MikroTik address-list via REST API, adds missing subnets, and cleans up redundant single IPs.
"""

import argparse
import ipaddress
import json
import os
import sys

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
                        if v:
                            os.environ[k] = v
        except Exception as e:
            print(f"Warning: failed to read {env_path}: {e}", file=sys.stderr)


def load_malicious_subnets(path: str) -> list[str]:
    if not os.path.exists(path):
        print(f"Error: subnets file '{path}' not found. Run parse_rules_ips.py first.", file=sys.stderr)
        return []

    subnets = set()
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    subnets.add(str(net))
                except ValueError:
                    pass
    return sorted(list(subnets))


def generate_rsc_file(subnets: list[str], output_rsc: str, list_name: str):
    """
    Generates a fast RouterOS import script (.rsc) for bulk address-list updates in 1-2 seconds.
    """
    with open(output_rsc, "w") as f:
        f.write(f"# Auto-generated MikroTik import script for Suricata rules subnets\n")
        f.write(f"/ip firewall address-list remove [find list={list_name}]\n")
        f.write(f"/ip firewall address-list\n")
        for net_str in subnets:
            f.write(f"add list={list_name} address={net_str} comment=\"ET Rule Subnet\"\n")

    print(f"✅ Fast RouterOS script generated: '{output_rsc}' ({len(subnets)} subnets).")
    print(f"👉 Upload to MikroTik and run: /import file-name={output_rsc}")

def sync_api_mikrotik(subnets: list[str], list_name: str):
    """
    Differential sync via RouterOS REST API.
    Adds missing subnets and removes single IPs covered by subnets.
    """
    if requests is None:
        print("Error: 'requests' module not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return

    load_env()
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")

    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials (MT_HOST, MT_USER, MT_PASS) missing or unconfigured in /opt/alert-bridge/env.", file=sys.stderr)
        return

    auth = (mt_user, mt_pass)
    base_url = f"https://{mt_host}/rest/ip/firewall/address-list"

    print(f"🔍 Reading current address-list '{list_name}' from MikroTik ({mt_host})...")

    # 1. Fetch current list entries
    existing_entries = []
    try:
        r = requests.get(f"{base_url}?list={list_name}", auth=auth, verify=False, timeout=(5, 15))
        if r.status_code == 200:
            existing_entries = r.json()
    except requests.RequestException as e:
        print(f"Error fetching address-list from MikroTik: {e}", file=sys.stderr)
        return

    current_addresses = {entry.get("address"): entry.get(".id") for entry in existing_entries if entry.get("address")}

    print(f"Found {len(current_addresses)} existing entries on MikroTik.")

    # 2. Build network objects for subnets to be synced
    subnet_objs = []
    for s in subnets:
        try:
            subnet_objs.append((s, ipaddress.ip_network(s, strict=False)))
        except ValueError:
            pass

    # 3. Clean up single IPs covered by any of the new subnets
    redundant_removed = 0
    for addr_str, entry_id in list(current_addresses.items()):
        try:
            ip_obj = ipaddress.ip_address(addr_str)
            for sub_str, sub_net in subnet_objs:
                if ip_obj in sub_net:
                    print(f"  🗑️ Removing single IP {addr_str} (covered by rule subnet {sub_str})...", flush=True)
                    try:
                        requests.delete(f"{base_url}/{entry_id}", auth=auth, verify=False, timeout=(5, 10))
                        redundant_removed += 1
                    except requests.RequestException:
                        pass
                    break
        except ValueError:
            pass

    # 4. Add missing subnets to MikroTik
    added_subnets = 0
    for sub_str, _ in subnet_objs:
        if sub_str not in current_addresses:
            body = {
                "list": list_name,
                "address": sub_str,
                "comment": "ET Rule Subnet",
            }
            try:
                r_put = requests.put(base_url, json=body, auth=auth, verify=False, timeout=(5, 15))
                if r_put.status_code in (200, 201) or "already" in r_put.text:
                    added_subnets += 1
            except requests.RequestException as e:
                print(f"Failed to add subnet {sub_str}: {e}", file=sys.stderr)

    print(f"\n✅ Sync complete! Added {added_subnets} new subnets, removed {redundant_removed} redundant single IPs.")


def main():
    parser = argparse.ArgumentParser(description="Sync Suricata malicious subnets to MikroTik firewall address-list.")
    parser.add_argument("--subnets-file", default="/opt/alert-bridge/malicious_subnets.txt", help="Path to malicious subnets file")
    parser.add_argument("--list-name", default="suricata-block", help="MikroTik address-list name (default: suricata-block)")
    parser.add_argument("--generate-rsc", help="Generate fast RouterOS import script (.rsc file) instead of REST API sync")
    parser.add_argument("--api", action="store_true", help="Perform REST API differential sync")
    args = parser.parse_args()

    subnets = load_malicious_subnets(args.subnets_file)
    if not subnets:
        return

    if args.generate_rsc:
        generate_rsc_file(subnets, args.generate_rsc, args.list_name)
    else:
        sync_api_mikrotik(subnets, args.list_name)


if __name__ == "__main__":
    main()
