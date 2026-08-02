#!/usr/bin/env python3
"""Sync or seed alert-bridge-state.json from today's journalctl logs.

Reads logs from `journalctl -u alert-bridge --since today`, parses attacker/target IP counts,
filters out whitelisted/home/LAN/DNS IPs, and safely updates /var/log/suricata/alert-bridge-state.json.
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
import time

STATE_FILE = "/var/log/suricata/alert-bridge-state.json"
ENV_FILE = "/opt/alert-bridge/env"


def load_env_wan_ips() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    res = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("WAN_IP=") or line.startswith("WAN_IPV6_PREFIX="):
                    val = line.split("=", 1)[1].strip()
                    for item in val.replace(",", " ").split():
                        item = item.strip()
                        if item:
                            try:
                                res.append(ipaddress.ip_network(item, strict=False))
                            except ValueError:
                                pass
    return res


HOME_AND_LAN_NETS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    # Public DNS Resolvers
    ipaddress.ip_network("1.1.1.1/32"), ipaddress.ip_network("1.0.0.1/32"),
    ipaddress.ip_network("1.1.1.2/32"), ipaddress.ip_network("1.0.0.2/32"),
    ipaddress.ip_network("1.1.1.3/32"), ipaddress.ip_network("1.0.0.3/32"),
    ipaddress.ip_network("8.8.8.8/32"), ipaddress.ip_network("8.8.4.4/32"),
    ipaddress.ip_network("9.9.9.9/32"), ipaddress.ip_network("149.112.112.112/32"),
    ipaddress.ip_network("208.67.222.222/32"), ipaddress.ip_network("208.67.220.220/32"),
    ipaddress.ip_network("94.140.14.14/32"), ipaddress.ip_network("94.140.15.15/32"),
] + load_env_wan_ips()


def is_home_or_lan(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in HOME_AND_LAN_NETS)
    except ValueError:
        return True  # Invalid IP treated as unsafe (home/LAN filter)


def main():
    today = time.strftime("%Y-%m-%d")
    print(f"Syncing alert-bridge state for {today} from journalctl logs...", flush=True)

    try:
        output = subprocess.check_output(
            ["journalctl", "-u", "alert-bridge", "--since", "today", "--no-pager"],
            text=True
        )
    except Exception as e:
        print(f"Error reading journalctl logs: {e}", file=sys.stderr)
        sys.exit(1)

    inbound_counts = {}
    outbound_counts = {}

    inbound_pattern = re.compile(r"(inbound-alert|alert).*?\battacker=([0-9a-fA-F:\.]+)")
    outbound_pattern = re.compile(r"outbound-alert.*?\btarget=([0-9a-fA-F:\.]+)")

    for line in output.splitlines():
        in_match = inbound_pattern.search(line)
        if in_match:
            ip = in_match.group(2)
            if not is_home_or_lan(ip):
                inbound_counts[ip] = inbound_counts.get(ip, 0) + 1
            else:
                print(f"FILTERED OUT home/LAN/DNS IP: {ip}", flush=True)
            continue

        out_match = outbound_pattern.search(line)
        if out_match:
            ip = out_match.group(1)
            if not is_home_or_lan(ip):
                outbound_counts[ip] = outbound_counts.get(ip, 0) + 1
            else:
                print(f"FILTERED OUT home/LAN/DNS IP: {ip}", flush=True)
            continue

    print(f"Found {len(inbound_counts)} inbound attacker IPs, {len(outbound_counts)} outbound target IPs in logs.", flush=True)

    # Load existing state if present
    state = {
        "date": today,
        "quiet_blocks": 0,
        "inbound_counts": {},
        "outbound_counts": {},
        "last_outbound_summary_time": time.time(),
    }
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                existing = json.load(f)
                if existing.get("date") == today:
                    state = existing
        except Exception as e:
            print(f"warning: could not read existing state file: {e}", flush=True)

    # Merge counts (take maximum observed or update)
    for ip, count in inbound_counts.items():
        state["inbound_counts"][ip] = max(state["inbound_counts"].get(ip, 0), count)

    for ip, count in outbound_counts.items():
        state["outbound_counts"][ip] = max(state["outbound_counts"].get(ip, 0), count)

    # Save state back atomically
    tmp_file = STATE_FILE + ".tmp"
    with open(tmp_file, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp_file, STATE_FILE)

    print(f"Successfully updated {STATE_FILE}!", flush=True)
    print("\nTop Inbound Attackers today:")
    for ip, count in sorted(state["inbound_counts"].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {ip}: {count} attempts")


if __name__ == "__main__":
    main()
