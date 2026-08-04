#!/usr/bin/env python3
"""Suricata eve.json -> Telegram alert + MikroTik auto-block bridge.

Follows eve.json like `tail -F` (survives logrotate), and for every alert
with severity <= MAX_SEVERITY:
  - Classifies flow into Inbound (external attacker -> LAN) or Outbound (LAN -> external target)
  - Tracks daily attempt history per IP for both directions with persistent state (/var/log/suricata/alert-bridge-state.json)
  - Inbound traffic: 1h block for hits 1-2. Escalates to PERMANENT block on MikroTik at hit >= 3
    with a priority Telegram alert.
  - Outbound traffic: always 1h temporary block on MikroTik. Every 6 hours, sends a Telegram
    summary digest listing all outbound target IPs with >= 3 hits today.
  - Rate-limits Telegram messages (COOLDOWN) except for permanent block escalation.
"""

import ipaddress
import json
import os
import time

import requests
import urllib3

urllib3.disable_warnings()  # self-signed cert on the router's www-ssl

EVE_LOG = "/var/log/suricata/eve.json"
STATE_FILE = "/var/log/suricata/alert-bridge-state.json"
MAX_SEVERITY = 2          # 1=high, 2=medium; 3=informational is ignored
BLOCK_TIMEOUT = os.environ.get("BLOCK_TIMEOUT", "1h")  # temporary block duration
COOLDOWN = 300            # seconds before re-alerting same ip+signature
BLOCK_LIST = "suricata-block"
PERMANENT_THRESHOLD = 3   # Inbound attempts today before permanent block
OUTBOUND_SUMMARY_INTERVAL = 6 * 3600  # 6 hours in seconds

# Reputation-list hits: real enough to block, too common to page about
QUIET_PREFIXES = ("ET DROP", "ET CINS", "ET TOR", "ET 3CORESec")

TG_TOKEN = os.environ.get("TG_TOKEN", "")  # empty = skip Telegram, log only
TG_CHAT = os.environ.get("TG_CHAT", "")
TG_THREAD_ID = os.environ.get("TG_THREAD_ID", "")
MT_HOST = os.environ.get("MT_HOST", "")
MT_USER = os.environ.get("MT_USER", "")
MT_PASS = os.environ.get("MT_PASS", "")
WAN_IP = os.environ.get("WAN_IP", "")            # own WAN public IP(s) (CIDR, comma-separated for multi-WAN)
WAN_IPV6_PREFIX = os.environ.get("WAN_IPV6_PREFIX", "")  # own IPv6 prefix(es)


def _parse_cidrs(val: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    res = []
    if not val:
        return res
    for item in val.replace(",", " ").split():
        item = item.strip()
        if item:
            try:
                res.append(ipaddress.ip_network(item, strict=False))
            except ValueError as e:
                print(f"warning: invalid CIDR '{item}': {e}", flush=True)
    return res


_wan_nets = _parse_cidrs(WAN_IP) + _parse_cidrs(WAN_IPV6_PREFIX)

# Never block these, no matter what Suricata says: RFC1918 / CGNAT / loopback
# and well-known public DNS resolvers. Own public IPs come from WAN_IP /
# WAN_IPV6_PREFIX in the env so this file stays deployment-agnostic.
WHITELIST = [
    ipaddress.ip_network(n)
    for n in (
        "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
        "127.0.0.0/8", "100.64.0.0/10",
        # Cloudflare DNS
        "1.1.1.1/32", "1.0.0.1/32", "1.1.1.2/32", "1.0.0.2/32", "1.1.1.3/32", "1.0.0.3/32",
        # Google Public DNS
        "8.8.8.8/32", "8.8.4.4/32",
        # Quad9 DNS
        "9.9.9.9/32", "149.112.112.112/32",
        # OpenDNS (Cisco)
        "208.67.222.222/32", "208.67.220.220/32", "208.67.222.220/32", "208.67.220.222/32",
        # AdGuard DNS
        "94.140.14.14/32", "94.140.15.15/32",
    )
] + _wan_nets

# Match suricata.yaml HOME_NET — used to decide direction of traffic.
HOME_NETS = [ipaddress.ip_network("192.168.0.0/16")] + _wan_nets

_recent: dict[str, float] = {}
_daily_inbound_counts: dict[str, int] = {}
_daily_outbound_counts: dict[str, int] = {}
_quiet_blocks = 0
_digest_day = time.strftime("%Y-%m-%d")
_last_outbound_summary_time = time.time()


def load_state() -> None:
    """Load persistent counters and state from JSON file if available."""
    global _digest_day, _quiet_blocks, _daily_inbound_counts, _daily_outbound_counts, _last_outbound_summary_time
    today = time.strftime("%Y-%m-%d")
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        saved_date = data.get("date", "")
        if saved_date == today:
            _digest_day = saved_date
            _quiet_blocks = data.get("quiet_blocks", 0)
            _daily_inbound_counts = data.get("inbound_counts", {})
            _daily_outbound_counts = data.get("outbound_counts", {})
            _last_outbound_summary_time = data.get("last_outbound_summary_time", time.time())
            print(f"loaded state for {today}: {_quiet_blocks} quiet blocks, "
                  f"{len(_daily_inbound_counts)} inbound IPs, {len(_daily_outbound_counts)} outbound IPs", flush=True)
        else:
            print(f"state file is from previous day ({saved_date}), starting fresh for {today}", flush=True)
    except Exception as e:
        print(f"warning: failed to load state file: {e}", flush=True)


def save_state() -> None:
    """Atomically save current state to JSON file."""
    state = {
        "date": _digest_day,
        "quiet_blocks": _quiet_blocks,
        "inbound_counts": _daily_inbound_counts,
        "outbound_counts": _daily_outbound_counts,
        "last_outbound_summary_time": _last_outbound_summary_time,
    }
    tmp_path = STATE_FILE + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(state, f)
        os.replace(tmp_path, STATE_FILE)
    except Exception as e:
        print(f"warning: failed to save state file: {e}", flush=True)


def whitelisted(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in WHITELIST)


def classify_flow(ev: dict) -> tuple[str, str, str]:
    """
    Returns (direction, target_ip, internal_ip)
    direction: 'inbound' or 'outbound'
    """
    src = ev.get("src_ip", "")
    dest = ev.get("dest_ip", "")

    src_home = False
    dest_home = False
    try:
        if src:
            src_home = any(ipaddress.ip_address(src) in n for n in HOME_NETS)
        if dest:
            dest_home = any(ipaddress.ip_address(dest) in n for n in HOME_NETS)
    except ValueError:
        pass

    if not src_home and dest_home:
        return "inbound", src, dest
    elif src_home and not dest_home:
        return "outbound", dest, src
    else:
        # Fallback: if src is not home, treat as inbound
        return ("inbound", src, dest) if not src_home else ("outbound", dest, src)


def cooled_down(key: str) -> bool:
    now = time.time()
    if now - _recent.get(key, 0) < COOLDOWN:
        return False
    _recent[key] = now
    # keep the dedup table from growing forever
    for k in [k for k, t in _recent.items() if now - t > COOLDOWN * 4]:
        del _recent[k]
    return True


def telegram_send(text: str) -> None:
    if not TG_TOKEN or not TG_CHAT:
        return  # Telegram not configured yet — alerts still logged + blocked
    payload = {"chat_id": TG_CHAT, "text": text}
    if TG_THREAD_ID:
        try:
            payload["message_thread_id"] = int(TG_THREAD_ID)
        except ValueError:
            pass
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json=payload,
            timeout=10,
        )
    except requests.RequestException as e:
        print(f"telegram failed: {e}", flush=True)


def mikrotik_block(ip: str, signature: str, permanent: bool = False) -> bool:
    family = "ipv6" if ipaddress.ip_address(ip).version == 6 else "ip"
    comment_prefix = "PERMANENT (3+ hits): " if permanent else ""
    body = {
        "list": BLOCK_LIST,
        "address": ip,
        "comment": (comment_prefix + signature)[:60],
    }
    if not permanent:
        body["timeout"] = BLOCK_TIMEOUT

    try:
        r = requests.put(
            f"https://{MT_HOST}/rest/{family}/firewall/address-list",
            json=body,
            auth=(MT_USER, MT_PASS),
            verify=False,
            timeout=(5, 15),  # 5s connect, 15s read timeout
        )
        # 400 "already have such entry" is fine — it's already blocked
        return r.status_code in (200, 201) or "already" in r.text
    except requests.RequestException as e:
        print(f"mikrotik block failed for {ip}: {e}", flush=True)
        return False


def check_periodic_tasks() -> None:
    """Checks for midnight day-rollover and 6-hour outbound summary digest."""
    global _quiet_blocks, _digest_day, _daily_inbound_counts, _daily_outbound_counts, _last_outbound_summary_time
    now = time.time()
    today = time.strftime("%Y-%m-%d")

    # 1. Day Rollover at Midnight
    if today != _digest_day:
        if _quiet_blocks:
            telegram_send(f"🌦 {_digest_day}: silently blocked {_quiet_blocks} "
                          "reputation-listed IPs (ET DROP/CINS/TOR)")
        _digest_day = today
        _quiet_blocks = 0
        _daily_inbound_counts.clear()
        _daily_outbound_counts.clear()
        _last_outbound_summary_time = now
        save_state()

    # 2. 6-Hour Outbound Summary Digest
    if now - _last_outbound_summary_time >= OUTBOUND_SUMMARY_INTERVAL:
        _last_outbound_summary_time = now
        frequent_outbound = {
            ip: count for ip, count in _daily_outbound_counts.items() if count >= 3
        }
        if frequent_outbound:
            lines = [f"• `{ip}` — {count} hits" for ip, count in sorted(frequent_outbound.items(), key=lambda x: x[1], reverse=True)]
            text = (
                "📊 Outbound Summary (6h Digest) 📤\n"
                f"Targets with >= 3 hits today ({today}):\n"
                + "\n".join(lines)
            )
            telegram_send(text)
        save_state()


def follow(path: str):
    """tail -F: follow the file across logrotate, truncation, and re-create."""
    f = None
    inode = None
    pos = None
    while True:
        try:
            st = os.stat(path)
            if f is None or st.st_ino != inode or st.st_size < pos:
                if f:
                    f.close()
                f = open(path, "r")
                inode = st.st_ino
                f.seek(0, os.SEEK_END)  # only new events
                pos = f.tell()
            line = f.readline()
            if line:
                pos = f.tell()
                yield line
            else:
                check_periodic_tasks()
                time.sleep(0.5)
        except FileNotFoundError:
            check_periodic_tasks()
            time.sleep(1)


def main() -> None:
    global _quiet_blocks
    load_state()
    print(f"following {EVE_LOG}, blocking via {MT_HOST}", flush=True)
    for line in follow(EVE_LOG):
        check_periodic_tasks()
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert", {})
        if alert.get("severity", 3) > MAX_SEVERITY:
            continue

        direction, target_ip, internal_ip = classify_flow(ev)
        if not target_ip or whitelisted(target_ip):
            continue

        sig = alert.get("signature", "")
        quiet = sig.startswith(QUIET_PREFIXES)

        if direction == "inbound":
            _daily_inbound_counts[target_ip] = _daily_inbound_counts.get(target_ip, 0) + 1
            attempts = _daily_inbound_counts[target_ip]

            if attempts > PERMANENT_THRESHOLD:
                # Already permanently blocked on MikroTik on the 3rd attempt.
                # Ignore subsequent mirrored packets to prevent Telegram spam.
                save_state()
                continue

            permanent = (attempts == PERMANENT_THRESHOLD)

            if not permanent and not cooled_down(f"inbound|{target_ip}|{alert.get('signature_id')}"):
                save_state()
                continue

            blocked = mikrotik_block(target_ip, sig, permanent=permanent)

            if permanent:
                # Sent EXACTLY ONCE on the 3rd attempt when escalating to PERMANENT block
                telegram_send(
                    "🔒 PERMANENT BLOCK (Inbound 📥)\n"
                    f"Attacker IP {target_ip} reached {attempts} attack attempts today!\n"
                    f"Signature: {sig}\n"
                    f"{ev.get('src_ip')}:{ev.get('src_port', '')} → {ev.get('dest_ip')}:{ev.get('dest_port', '')}\n"
                    f"Severity {alert.get('severity')} · "
                    + (f"🔒 PERMANENTLY BLOCKED on MikroTik" if blocked else "⚠️ Permanent block FAILED")
                )
            elif quiet:
                _quiet_blocks += 1
            else:
                telegram_send(
                    "🚨 Suricata alert (Inbound 📥)\n"
                    f"{sig}\n"
                    f"{ev.get('src_ip')}:{ev.get('src_port', '')} → {ev.get('dest_ip')}:{ev.get('dest_port', '')}\n"
                    f"severity {alert.get('severity')} · attempt {attempts}/{PERMANENT_THRESHOLD} today · "
                    + (f"⛔ blocked {BLOCK_TIMEOUT}" if blocked else "⚠️ block FAILED")
                )
            print(f"inbound-alert {sig} attacker={target_ip} attempts={attempts} "
                  f"permanent={permanent} blocked={blocked}", flush=True)

        else:
            # Outbound traffic (LAN -> WAN)
            _daily_outbound_counts[target_ip] = _daily_outbound_counts.get(target_ip, 0) + 1
            attempts = _daily_outbound_counts[target_ip]

            if not cooled_down(f"outbound|{target_ip}|{alert.get('signature_id')}"):
                save_state()
                continue

            blocked = mikrotik_block(target_ip, sig, permanent=False)

            if quiet:
                _quiet_blocks += 1
            else:
                telegram_send(
                    "🚨 Suricata alert (Outbound 📤)\n"
                    f"{sig}\n"
                    f"{ev.get('src_ip')}:{ev.get('src_port', '')} → {ev.get('dest_ip')}:{ev.get('dest_port', '')}\n"
                    f"severity {alert.get('severity')} · hit {attempts} today · "
                    + (f"⛔ blocked {BLOCK_TIMEOUT}" if blocked else "⚠️ block FAILED")
                )
            print(f"outbound-alert {sig} target={target_ip} hits={attempts} "
                  f"blocked={blocked}", flush=True)

        save_state()


if __name__ == "__main__":
    main()
