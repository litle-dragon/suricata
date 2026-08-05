#!/usr/bin/env python3
"""Suricata eve.json -> Telegram alert + MikroTik auto-block bridge.

Follows eve.json like `tail -F` (survives logrotate), and for every alert
with severity <= MAX_SEVERITY:
  - Classifies flow into Inbound (external attacker -> LAN) or Outbound (LAN -> external target)
  - Tracks attempt history per IP and per /24 subnet in 2 state files:
      1. /var/log/suricata/alert-bridge-state.json (Daily state, resets at midnight)
      2. /var/log/suricata/alert-bridge-total-state.json (Cumulative total state across all days)
  - Inbound traffic: 1h block for hits 1-2. Escalates to PERMANENT block on MikroTik at hit >= 3.
  - Subnet aggregation: when a /24 subnet reaches 10 unique attacker IPs today, blocks the entire /24 subnet permanently on MikroTik.
  - Outbound traffic: 1h temporary block on MikroTik.
  - Telegram Digests:
      1. 6-Hour Digest: new unique IPs (not seen before in history), new subnets, avg attacks, TOP subnets (>=2 IPs).
      2. 07:00 AM Daily Report: summary for the previous day (total attacks, unique IPs, avg/IP, permanent blocks, TOP subnets).
"""

import ipaddress
import json
import os
import time
from collections import defaultdict

import requests
import urllib3

urllib3.disable_warnings()  # self-signed cert on the router's www-ssl

EVE_LOG = "/var/log/suricata/eve.json"
STATE_FILE = "/var/log/suricata/alert-bridge-state.json"
TOTAL_STATE_FILE = "/var/log/suricata/alert-bridge-total-state.json"
MAX_SEVERITY = 2          # 1=high, 2=medium; 3=informational is ignored
BLOCK_TIMEOUT = os.environ.get("BLOCK_TIMEOUT", "1h")  # temporary block duration
COOLDOWN = 300            # seconds before re-alerting same ip+signature
BLOCK_LIST = "suricata-block"
PERMANENT_THRESHOLD = 3   # Inbound attempts today before permanent block
SUBNET_THRESHOLD = 10     # Unique IPs in /24 subnet today before blocking whole /24
DIGEST_6H_INTERVAL = 6 * 3600  # 6 hours in seconds

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

HOME_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10")
] + _wan_nets

_recent: dict[str, float] = {}

# Journal 1: Daily state (resets at midnight)
_daily_inbound_counts: dict[str, int] = {}
_daily_outbound_counts: dict[str, int] = {}
_daily_inbound_subnets: dict[str, dict] = {}   # { "subnet": {"unique_ips": [...], "total_alerts": int} }
_daily_outbound_subnets: dict[str, dict] = {}
_daily_permanent_count = 0

# Journal 2: Total state (persistent forever)
_total_inbound_counts: dict[str, int] = {}
_total_outbound_counts: dict[str, int] = {}
_total_inbound_subnets: dict[str, dict] = {}
_total_outbound_subnets: dict[str, dict] = {}

# 6-Hour New Threat Digest Tracking
_recent_6h_new_ips: dict[str, dict] = {}  # { "ip": {"hits": int, "sig": str} }
_last_6h_digest_time = time.time()

# 07:00 AM Daily Report Tracking
_last_7am_report_date = ""
_yesterday_stats: dict = {}

_quiet_blocks = 0
_digest_day = time.strftime("%Y-%m-%d")


def load_state() -> None:
    """Load daily state and total persistent state from JSON files if available."""
    global _digest_day, _quiet_blocks, _daily_inbound_counts, _daily_outbound_counts, _daily_inbound_subnets, _daily_outbound_subnets, _daily_permanent_count
    global _total_inbound_counts, _total_outbound_counts, _total_inbound_subnets, _total_outbound_subnets
    global _recent_6h_new_ips, _last_6h_digest_time, _last_7am_report_date, _yesterday_stats
    today = time.strftime("%Y-%m-%d")

    # 1. Load Daily State
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
            saved_date = data.get("date", "")
            if saved_date == today:
                _digest_day = saved_date
                _quiet_blocks = data.get("quiet_blocks", 0)
                _daily_inbound_counts = data.get("inbound_counts", {})
                _daily_outbound_counts = data.get("outbound_counts", {})
                _daily_inbound_subnets = data.get("inbound_subnets", {})
                _daily_outbound_subnets = data.get("outbound_subnets", {})
                _daily_permanent_count = data.get("daily_permanent_count", 0)
                _recent_6h_new_ips = data.get("recent_6h_new_ips", {})
                _last_6h_digest_time = data.get("last_6h_digest_time", time.time())
                _last_7am_report_date = data.get("last_7am_report_date", "")
                _yesterday_stats = data.get("yesterday_stats", {})
                print(f"loaded daily state for {today}: {_quiet_blocks} quiet blocks, "
                      f"{len(_daily_inbound_counts)} inbound IPs, {len(_daily_inbound_subnets)} inbound subnets", flush=True)
            else:
                print(f"daily state file is from previous day ({saved_date}), starting fresh for {today}", flush=True)
        except Exception as e:
            print(f"warning: failed to load daily state file: {e}", flush=True)

    # 2. Load Total State
    if os.path.exists(TOTAL_STATE_FILE):
        try:
            with open(TOTAL_STATE_FILE, "r") as f:
                t_data = json.load(f)
            _total_inbound_counts = t_data.get("inbound_counts", {})
            _total_outbound_counts = t_data.get("outbound_counts", {})
            _total_inbound_subnets = t_data.get("inbound_subnets", {})
            _total_outbound_subnets = t_data.get("outbound_subnets", {})
            print(f"loaded total state: {len(_total_inbound_counts)} total inbound IPs, "
                  f"{len(_total_inbound_subnets)} total inbound subnets", flush=True)
        except Exception as e:
            print(f"warning: failed to load total state file: {e}", flush=True)


def save_state() -> None:
    """Atomically save current daily and total states to JSON files."""
    daily_state = {
        "date": _digest_day,
        "quiet_blocks": _quiet_blocks,
        "inbound_counts": _daily_inbound_counts,
        "outbound_counts": _daily_outbound_counts,
        "inbound_subnets": _daily_inbound_subnets,
        "outbound_subnets": _daily_outbound_subnets,
        "daily_permanent_count": _daily_permanent_count,
        "recent_6h_new_ips": _recent_6h_new_ips,
        "last_6h_digest_time": _last_6h_digest_time,
        "last_7am_report_date": _last_7am_report_date,
        "yesterday_stats": _yesterday_stats,
    }
    tmp_daily = STATE_FILE + ".tmp"
    try:
        with open(tmp_daily, "w") as f:
            json.dump(daily_state, f)
        os.replace(tmp_daily, STATE_FILE)
    except Exception as e:
        print(f"warning: failed to save daily state file: {e}", flush=True)

    total_state = {
        "inbound_counts": _total_inbound_counts,
        "outbound_counts": _total_outbound_counts,
        "inbound_subnets": _total_inbound_subnets,
        "outbound_subnets": _total_outbound_subnets,
    }
    tmp_total = TOTAL_STATE_FILE + ".tmp"
    try:
        with open(tmp_total, "w") as f:
            json.dump(total_state, f)
        os.replace(tmp_total, TOTAL_STATE_FILE)
    except Exception as e:
        print(f"warning: failed to save total state file: {e}", flush=True)


def get_subnet(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        prefix = 24 if ip_obj.version == 4 else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ip


def record_hit(direction: str, ip: str, sig: str) -> tuple[int, str, int]:
    """
    Records a hit for IP and its subnet in both daily and total state.
    Track new IPs (never seen in history) for the 6h digest.
    Returns: (ip_daily_count, subnet_str, subnet_daily_unique_count)
    """
    subnet_str = get_subnet(ip)

    if direction == "inbound":
        # Check if brand new IP (never seen in total history before)
        if ip not in _total_inbound_counts:
            entry = _recent_6h_new_ips.setdefault(ip, {"hits": 0, "sig": sig})
            entry["hits"] += 1

        _daily_inbound_counts[ip] = _daily_inbound_counts.get(ip, 0) + 1
        ip_daily_count = _daily_inbound_counts[ip]

        s_daily = _daily_inbound_subnets.setdefault(subnet_str, {"unique_ips": [], "total_alerts": 0})
        if ip not in s_daily["unique_ips"]:
            s_daily["unique_ips"].append(ip)
        s_daily["total_alerts"] += 1
        subnet_daily_unique_cnt = len(s_daily["unique_ips"])

        _total_inbound_counts[ip] = _total_inbound_counts.get(ip, 0) + 1

        s_total = _total_inbound_subnets.setdefault(subnet_str, {"unique_ips": [], "total_alerts": 0})
        if ip not in s_total["unique_ips"]:
            s_total["unique_ips"].append(ip)
        s_total["total_alerts"] += 1

        return ip_daily_count, subnet_str, subnet_daily_unique_cnt
    else:
        _daily_outbound_counts[ip] = _daily_outbound_counts.get(ip, 0) + 1
        ip_daily_count = _daily_outbound_counts[ip]

        s_daily = _daily_outbound_subnets.setdefault(subnet_str, {"unique_ips": [], "total_alerts": 0})
        if ip not in s_daily["unique_ips"]:
            s_daily["unique_ips"].append(ip)
        s_daily["total_alerts"] += 1
        subnet_daily_unique_cnt = len(s_daily["unique_ips"])

        _total_outbound_counts[ip] = _total_outbound_counts.get(ip, 0) + 1

        s_total = _total_outbound_subnets.setdefault(subnet_str, {"unique_ips": [], "total_alerts": 0})
        if ip not in s_total["unique_ips"]:
            s_total["unique_ips"].append(ip)
        s_total["total_alerts"] += 1

        return ip_daily_count, subnet_str, subnet_daily_unique_cnt


def whitelisted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in WHITELIST)
    except ValueError:
        return False


def classify_flow(ev: dict) -> tuple[str, str, str]:
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
        return ("inbound", src, dest) if not src_home else ("outbound", dest, src)


def cooled_down(key: str) -> bool:
    now = time.time()
    if now - _recent.get(key, 0) < COOLDOWN:
        return False
    _recent[key] = now
    for k in [k for k, t in _recent.items() if now - t > COOLDOWN * 4]:
        del _recent[k]
    return True


def telegram_send(text: str) -> None:
    if not TG_TOKEN or not TG_CHAT:
        return
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


def mikrotik_block(ip_or_subnet: str, signature: str, permanent: bool = False) -> bool:
    try:
        net = ipaddress.ip_network(ip_or_subnet, strict=False)
        family = "ipv6" if net.version == 6 else "ip"
    except ValueError:
        family = "ip"

    comment_prefix = "PERMANENT: " if permanent else ""
    base_url = f"https://{MT_HOST}/rest/{family}/firewall/address-list"
    auth = (MT_USER, MT_PASS)

    if permanent:
        try:
            r_get = requests.get(
                f"{base_url}?list={BLOCK_LIST}&address={ip_or_subnet}",
                auth=auth,
                verify=False,
                timeout=(5, 10),
            )
            if r_get.status_code == 200:
                entries = r_get.json()
                if isinstance(entries, list):
                    for entry in entries:
                        if entry.get("timeout") or entry.get("dynamic") == "true":
                            entry_id = entry.get(".id")
                            if entry_id:
                                requests.delete(
                                    f"{base_url}/{entry_id}",
                                    auth=auth,
                                    verify=False,
                                    timeout=(5, 10),
                                )
        except requests.RequestException as e:
            print(f"mikrotik lookup/delete failed for {ip_or_subnet}: {e}", flush=True)

    body = {
        "list": BLOCK_LIST,
        "address": ip_or_subnet,
        "comment": (comment_prefix + signature)[:60],
    }
    if not permanent:
        body["timeout"] = BLOCK_TIMEOUT

    try:
        r = requests.put(
            base_url,
            json=body,
            auth=auth,
            verify=False,
            timeout=(5, 15),
        )
        return r.status_code in (200, 201) or "already" in r.text
    except requests.RequestException as e:
        print(f"mikrotik block failed for {ip_or_subnet}: {e}", flush=True)
        return False


def send_6h_new_threats_digest(start_time_str: str, end_time_str: str) -> None:
    """Generates and sends 6-hour new threat digest via Telegram."""
    global _recent_6h_new_ips
    if not _recent_6h_new_ips:
        return

    total_new_ips = len(_recent_6h_new_ips)
    total_new_hits = sum(info.get("hits", 1) for info in _recent_6h_new_ips.values())
    avg_hits_per_new_ip = total_new_hits / total_new_ips if total_new_ips > 0 else 0.0

    # Group new IPs by /24 subnet
    new_subnets = defaultdict(lambda: {"unique_ips": set(), "total_hits": 0})
    for ip, info in _recent_6h_new_ips.items():
        subnet_str = get_subnet(ip)
        new_subnets[subnet_str]["unique_ips"].add(ip)
        new_subnets[subnet_str]["total_hits"] += info.get("hits", 1)

    total_new_subnets = len(new_subnets)

    top_subnets = []
    single_new_ips_count = 0
    single_new_ips_hits = 0

    for subnet_str, s_info in new_subnets.items():
        unique_cnt = len(s_info["unique_ips"])
        hits_cnt = s_info["total_hits"]
        if unique_cnt >= 2:
            avg_sub_hits = hits_cnt / unique_cnt if unique_cnt > 0 else 0.0
            top_subnets.append((subnet_str, unique_cnt, hits_cnt, avg_sub_hits))
        else:
            single_new_ips_count += unique_cnt
            single_new_ips_hits += hits_cnt

    top_subnets.sort(key=lambda x: (x[2], x[1]), reverse=True)

    lines = [
        "📊 6-годинний дайджест нових загроз 📥",
        f"Період: {start_time_str} - {end_time_str}",
        "",
        f"• Унікальних нових IP (раніше не бачили): {total_new_ips}",
        f"• Нових унікальних мереж (/24): {total_new_subnets}",
        f"• Середня кількість атак на новий IP: {avg_hits_per_new_ip:.2f}",
        "",
    ]

    if top_subnets:
        lines.append("ТОП підмереж (/24, від 2+ нових IP):")
        for sub_str, u_cnt, h_cnt, avg_h in top_subnets[:10]:
            lines.append(f"• {sub_str} — {u_cnt} нових IP | {h_cnt} атак (сер. {avg_h:.2f}/IP)")
        lines.append("")

    if single_new_ips_count > 0:
        lines.append(f"Поодинокі нові IP (менше 2 IP в мережі): {single_new_ips_count} IP (всього {single_new_ips_hits} атак)")

    text = "\n".join(lines)
    telegram_send(text)
    _recent_6h_new_ips.clear()


def send_7am_daily_report() -> None:
    """Generates and sends 07:00 AM daily report for yesterday's statistics."""
    global _yesterday_stats
    if not _yesterday_stats or "date" not in _yesterday_stats:
        return

    y_date = _yesterday_stats.get("date", "")
    total_alerts = _yesterday_stats.get("total_alerts", 0)
    unique_ips = _yesterday_stats.get("unique_ips", 0)
    perm_count = _yesterday_stats.get("permanent_count", 0)
    inbound_counts = _yesterday_stats.get("inbound_counts", {})

    avg_alerts_per_ip = total_alerts / unique_ips if unique_ips > 0 else 0.0

    # Group yesterday's inbound counts by /24 subnet (min 2 IPs)
    subnets = defaultdict(lambda: {"ips": set(), "total_alerts": 0})
    for ip, cnt in inbound_counts.items():
        sub_str = get_subnet(ip)
        subnets[sub_str]["ips"].add(ip)
        subnets[sub_str]["total_alerts"] += cnt

    top_subnets = []
    for sub_str, s_info in subnets.items():
        u_cnt = len(s_info["ips"])
        alerts_cnt = s_info["total_alerts"]
        if u_cnt >= 2:
            avg_sub_alerts = alerts_cnt / u_cnt if u_cnt > 0 else 0.0
            top_subnets.append((sub_str, u_cnt, alerts_cnt, avg_sub_alerts))

    top_subnets.sort(key=lambda x: (x[2], x[1]), reverse=True)

    lines = [
        f"🌅 Звіт за попередній день ({y_date}) 📊",
        "",
        f"• Всього атак за добу: {total_alerts:,}",
        f"• Унікальних IP-атакуючих: {unique_ips:,}",
        f"• Середня кількість атак на 1 IP: {avg_alerts_per_ip:.2f}",
        f"• Додано в пермаментний блок за добу: {perm_count:,}",
        "",
    ]

    if top_subnets:
        lines.append("ТОП підмереж (/24, від 2+ IP):")
        for sub_str, u_cnt, a_cnt, avg_a in top_subnets[:10]:
            lines.append(f"• {sub_str} — {u_cnt} IP | {a_cnt} атак (сер. {avg_a:.2f}/IP)")

    text = "\n".join(lines)
    telegram_send(text)


def check_periodic_tasks() -> None:
    global _quiet_blocks, _digest_day, _daily_inbound_counts, _daily_outbound_counts, _daily_inbound_subnets, _daily_outbound_subnets
    global _daily_permanent_count, _last_6h_digest_time, _last_7am_report_date, _yesterday_stats
    now = time.time()
    today = time.strftime("%Y-%m-%d")
    current_hour = time.strftime("%H")

    # 1. Day Rollover at Midnight
    if today != _digest_day:
        # Snapshot yesterday's stats before resetting daily counters
        _yesterday_stats = {
            "date": _digest_day,
            "total_alerts": sum(_daily_inbound_counts.values()),
            "unique_ips": len(_daily_inbound_counts),
            "permanent_count": _daily_permanent_count,
            "inbound_counts": dict(_daily_inbound_counts),
            "inbound_subnets": dict(_daily_inbound_subnets),
        }

        _digest_day = today
        _quiet_blocks = 0
        _daily_permanent_count = 0
        _daily_inbound_counts.clear()
        _daily_outbound_counts.clear()
        _daily_inbound_subnets.clear()
        _daily_outbound_subnets.clear()
        save_state()

    # 2. 6-Hour New Threat Digest (every 6 hours)
    if now - _last_6h_digest_time >= DIGEST_6H_INTERVAL:
        start_time = time.strftime("%H:%M", time.localtime(_last_6h_digest_time))
        end_time = time.strftime("%H:%M", time.localtime(now))
        _last_6h_digest_time = now
        send_6h_new_threats_digest(start_time, f"{end_time} ({today})")
        save_state()

    # 3. 07:00 AM Daily Report (for yesterday's stats)
    if current_hour >= "07" and _last_7am_report_date != today:
        _last_7am_report_date = today
        send_7am_daily_report()
        save_state()


def follow(path: str):
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
                f.seek(0, os.SEEK_END)
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
    global _quiet_blocks, _daily_permanent_count
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
            attempts, subnet_str, subnet_unique_cnt = record_hit("inbound", target_ip, sig)

            # Subnet Aggregation Threshold: block entire /24 if 10 unique IPs reached today
            if subnet_unique_cnt == SUBNET_THRESHOLD:
                blocked_sub = mikrotik_block(subnet_str, f"SUBNET BLOCK (10+ IPs): {sig}", permanent=True)
                print(f"subnet-block {sig} subnet={subnet_str} unique_ips={subnet_unique_cnt} permanent=True blocked={blocked_sub}", flush=True)

            if attempts > PERMANENT_THRESHOLD:
                save_state()
                continue

            permanent = (attempts == PERMANENT_THRESHOLD)

            if not permanent and not cooled_down(f"inbound|{target_ip}|{alert.get('signature_id')}"):
                save_state()
                continue

            blocked = mikrotik_block(target_ip, sig, permanent=permanent)
            if permanent:
                _daily_permanent_count += 1

            if quiet:
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
            attempts, subnet_str, subnet_unique_cnt = record_hit("outbound", target_ip, sig)

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
