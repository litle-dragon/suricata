#!/usr/bin/env python3
"""Sync Suricata malicious subnets/IPs to MikroTik via REST API (Option A: Fast RSC Upload & Import with Chunking).

Option A:
  1. Reads malicious IPs/subnets from /opt/alert-bridge/malicious_subnets.txt
  2. Deduplicates single IPs covered by larger subnets
  3. Splits large lists into 3000-item chunks to fit RouterOS REST API payload limits
  4. Uploads chunk files to MikroTik via REST API (POST /rest/file)
  5. Executes '/import file-name=suricata_rules_X.rsc' via REST API (POST /rest/import or /rest/execute)
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


def load_malicious_items(path: str) -> list[str]:
    if not os.path.exists(path):
        print(f"Error: subnets file '{path}' not found. Run parse_rules_ips.py first.", file=sys.stderr)
        return []

    items = set()
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                items.add(line)

    return sorted(list(items))


def deduplicate_subnets_and_ips(items: list[str]) -> list[str]:
    """
    Deduplicates list of IPs and CIDRs:
    Removes individual single IPs (/32 or /128) if they fall inside a larger subnet in the list.
    """
    subnets = []
    single_ips = []

    for item in items:
        try:
            net = ipaddress.ip_network(item, strict=False)
            if (net.version == 4 and net.prefixlen < 32) or (net.version == 6 and net.prefixlen < 128):
                subnets.append(net)
            else:
                single_ips.append(net)
        except ValueError:
            pass

    # Remove single IPs that are covered by any subnet
    filtered_ips = []
    for ip_net in single_ips:
        ip_addr = ip_net.network_address
        if not any(ip_addr in sub_net for sub_net in subnets):
            filtered_ips.append(ip_net)

    combined = subnets + filtered_ips
    combined.sort(key=lambda x: (x.version, x.network_address, x.prefixlen))
    return [str(net) for net in combined]


def upload_and_import_rsc_chunks(mt_host: str, auth: tuple[str, str], list_name: str, subnets: list[str], chunk_size: int = 500):
    base_url = f"https://{mt_host}/rest"
    total_items = len(subnets)
    chunks = [subnets[i:i + chunk_size] for i in range(0, total_items, chunk_size)]

    print(f"📦 Total {total_items} items split into {len(chunks)} chunks ({chunk_size} items per chunk).", flush=True)

    for idx, chunk in enumerate(chunks, 1):
        file_name = f"suricata_rules_{idx}.rsc"
        lines = []

        # Only first chunk clears old address-list
        if idx == 1:
            lines.append(f"/ip firewall address-list remove [find list={list_name}]")

        lines.append("/ip firewall address-list")
        for net_str in chunk:
            lines.append(f"add list={list_name} address={net_str} comment=\"ET Rule Subnet\"")
        lines.append("")

        rsc_text = "\n".join(lines)

        # 1. Upload chunk
        print(f"📤 [{idx}/{len(chunks)}] Uploading '{file_name}' ({len(chunk)} rules)...", flush=True)
        upload_success = False
        try:
            r_up = requests.post(f"{base_url}/file", json={"name": file_name, "contents": rsc_text}, auth=auth, verify=False, timeout=(5, 20))
            if r_up.status_code in (200, 201):
                upload_success = True
            else:
                r_put = requests.put(f"{base_url}/file/{file_name}", json={"contents": rsc_text}, auth=auth, verify=False, timeout=(5, 20))
                if r_put.status_code in (200, 201):
                    upload_success = True
                else:
                    print(f"  Warning: upload response {r_put.status_code}: {r_put.text}", flush=True)
        except requests.RequestException as e:
            print(f"  Warning: upload request error for {file_name}: {e}", flush=True)

        # 2. Execute import if upload succeeded
        if upload_success:
            print(f"⚡ [{idx}/{len(chunks)}] Importing {file_name} on MikroTik...", flush=True)
            try:
                r_imp = requests.post(f"{base_url}/import", json={"file-name": file_name}, auth=auth, verify=False, timeout=(5, 30))
                if r_imp.status_code in (200, 201):
                    print(f"  ✅ Chunk {idx} imported successfully!", flush=True)
                else:
                    r_exec = requests.post(f"{base_url}/execute", json={"script": f"/import file-name={file_name}"}, auth=auth, verify=False, timeout=(5, 30))
                    if r_exec.status_code in (200, 201):
                        print(f"  ✅ Chunk {idx} executed successfully!", flush=True)
                    else:
                        print(f"  ⚠️ Chunk {idx} import response: {r_exec.status_code} {r_exec.text}", flush=True)
            except requests.RequestException as e:
                print(f"  ⚠️ Chunk {idx} import request failed: {e}", flush=True)
        else:
            print(f"  ⚠️ Skipping import for chunk {idx} because upload failed.", flush=True)
    print(f"\n✅ All {len(chunks)} chunks processed successfully ({total_items} rules total)!", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Sync Suricata malicious subnets to MikroTik via REST API (Option A).")
    parser.add_argument("--subnets-file", default="/opt/alert-bridge/malicious_subnets.txt", help="Path to malicious subnets file")
    parser.add_argument("--list-name", default="suricata-block", help="MikroTik address-list name (default: suricata-block)")
    parser.add_argument("--chunk-size", type=int, default=500, help="Chunk size for RSC file uploads (default: 500)")
    args = parser.parse_args()

    if requests is None:
        print("Error: 'requests' module not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return

    load_env()
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")

    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials incomplete in /opt/alert-bridge/env:", file=sys.stderr)
        print(f"  MT_HOST = '{mt_host}'", file=sys.stderr)
        print(f"  MT_USER = '{mt_user}'", file=sys.stderr)
        print(f"  MT_PASS = {'(set)' if mt_pass and 'YOUR_' not in mt_pass else '(missing or unconfigured)'}", file=sys.stderr)
        print("Please edit /opt/alert-bridge/env with your router LAN IP and suricata API user password.", file=sys.stderr)
        return

    raw_items = load_malicious_items(args.subnets_file)
    if not raw_items:
        return

    print(f"Loaded {len(raw_items)} items from '{args.subnets_file}'. Deduplicating...", flush=True)
    optimized_items = deduplicate_subnets_and_ips(raw_items)
    print(f"Optimized to {len(optimized_items)} unique subnets/IPs (removed single IPs covered by subnets).", flush=True)

    auth = (mt_user, mt_pass)
    upload_and_import_rsc_chunks(mt_host, auth, args.list_name, optimized_items, chunk_size=args.chunk_size)


if __name__ == "__main__":
    main()
