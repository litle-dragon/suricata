#!/usr/bin/env python3
"""Suricata eve.json -> Telegram digest + MikroTik auto-block bridge.

Follows eve.json like `tail -F` (survives logrotate), and for every alert
with severity <= MAX_SEVERITY:
  - Classifies flow into Inbound (external attacker -> LAN) or Outbound (LAN -> external target)
  - Inbound traffic: 1h block for hits 1-2. Escalates to PERMANENT block on MikroTik at hit >= 3.
  - Subnet aggregation: when a /24 subnet reaches 10 unique attacker IPs today, blocks the entire /24 permanently.
  - Outbound traffic: 1h temporary block on MikroTik.

Persistence: SQLite at /var/log/suricata/alert_bridge.db (WAL mode) is the single
system of record. Tables: seen_ips / seen_subnets (all-time uniqueness), daily_stats
(full historical daily archive), slot_digests (6h slot archive), spike_events (anomaly log).

Notifications (per-alert Telegram is DISABLED):
  1. Anomaly / Spike Alert: fires only when the inbound alert rate over a sliding
     5-minute window crosses SPIKE_THRESHOLD_N (default 500), with a 15-minute cooldown.
  2. Fixed 6-hour slot digest: aligned to clock slots 00:00-05:59, 06:00-11:59,
     12:00-17:59, 18:00-23:59; each sent at the following boundary.
  3. 07:00 AM daily report: summary of the previous full day, read from daily_stats.
"""

import ipaddress
import json
import os
import sqlite3
import time
from collections import defaultdict

import requests
import urllib3

urllib3.disable_warnings()  # self-signed cert on the router's www-ssl

EVE_LOG = "/var/log/suricata/eve.json"
DB_FILE = os.environ.get("DB_FILE", "/var/log/suricata/alert_bridge.db")
MAX_SEVERITY = 2          # 1=high, 2=medium; 3=informational is ignored
BLOCK_TIMEOUT = os.environ.get("BLOCK_TIMEOUT", "1h")  # temporary block duration
COOLDOWN = 300            # seconds before re-blocking same ip+signature
BLOCK_LIST = "suricata-block"
PERMANENT_THRESHOLD = 3   # Inbound attempts today before permanent block
SUBNET_THRESHOLD = 10     # Unique IPs in /24 subnet today before blocking whole /24

# Anomaly / spike detection over a sliding window
SLIDING_WINDOW = 300      # 5-minute sliding window (seconds)
SPIKE_COOLDOWN = 900      # 15-minute cooldown between spike alerts (seconds)
SPIKE_THRESHOLD_N = int(os.environ.get("SPIKE_THRESHOLD_N", "500"))  # alerts / 5 min to trigger

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

_recent: dict[str, float] = {}  # cooldown throttle for re-blocking

# ── SQLite (system of record) ────────────────────────────────────────────────
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_ips (
    ip TEXT PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_hits INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS seen_subnets (
    subnet TEXT PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_hits INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,
    total_alerts INTEGER NOT NULL,
    unique_ips INTEGER NOT NULL,
    unique_subnets INTEGER NOT NULL,
    new_ips_count INTEGER NOT NULL,
    new_subnets_count INTEGER NOT NULL,
    avg_alerts_per_ip INTEGER NOT NULL,
    avg_alerts_per_subnet INTEGER NOT NULL,
    perm_ips_count INTEGER NOT NULL,
    perm_subnets_count INTEGER NOT NULL,
    single_ips_count INTEGER NOT NULL,
    single_ips_alerts INTEGER NOT NULL,
    top_subnets_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS slot_digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    slot_index INTEGER NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    total_alerts INTEGER NOT NULL,
    new_ips_count INTEGER NOT NULL,
    new_subnets_count INTEGER NOT NULL,
    avg_alerts_per_ip INTEGER NOT NULL,
    avg_alerts_per_subnet INTEGER NOT NULL,
    perm_ips_count INTEGER NOT NULL,
    perm_subnets_count INTEGER NOT NULL,
    single_ips_count INTEGER NOT NULL,
    single_ips_alerts INTEGER NOT NULL,
    top_subnets_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS spike_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    total_alerts INTEGER NOT NULL,
    avg_rate_per_min INTEGER NOT NULL,
    unique_ips INTEGER NOT NULL,
    top_subnets_json TEXT NOT NULL
);
"""

# ── In-memory hot state ───────────────────────────────────────────────────────
# All-time uniqueness caches (mirror of seen_ips / seen_subnets, loaded at startup)
_all_time_seen_ips: set[str] = set()
_all_time_seen_subnets: set[str] = set()

# 5-minute sliding window for anomaly detection
_sliding_window_alerts: list[dict] = []   # {"time": float, "ip": str, "sig": str, "direction": str}
_last_spike_alert_time = 0.0

# 6-hour slot counters (reset at slot boundaries 00/06/12/18)
_slot_index = int(time.strftime("%H")) // 6
_slot_alerts_count = 0
_slot_inbound_counts: dict[str, int] = {}
_slot_inbound_subnets: dict[str, dict] = {}   # subnet -> {"ips": set, "alerts": int}
_slot_new_ips: set[str] = set()
_slot_new_subnets: set[str] = set()
_slot_perm_ips_count = 0
_slot_perm_subnets_count = 0

# Daily counters (reset at midnight)
_digest_day = time.strftime("%Y-%m-%d")
_daily_inbound_counts: dict[str, int] = {}
_daily_inbound_subnets: dict[str, dict] = {}  # subnet -> {"ips": set, "alerts": int}
_daily_outbound_counts: dict[str, int] = {}
_daily_new_ips: set[str] = set()
_daily_new_subnets: set[str] = set()
_daily_permanent_ips_count = 0
_daily_permanent_subnets_count = 0

_last_7am_report_date = ""


def db_init() -> None:
    """Open the SQLite database (WAL mode), create tables, and warm uniqueness caches."""
    global _conn, _all_time_seen_ips, _all_time_seen_subnets
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    _conn = sqlite3.connect(DB_FILE, isolation_level=None)  # autocommit
    _conn.execute("PRAGMA journal_mode=WAL;")
    _conn.execute("PRAGMA synchronous=NORMAL;")
    _conn.executescript(SCHEMA)
    _all_time_seen_ips = {row[0] for row in _conn.execute("SELECT ip FROM seen_ips")}
    _all_time_seen_subnets = {row[0] for row in _conn.execute("SELECT subnet FROM seen_subnets")}
    print(f"opened {DB_FILE}: {len(_all_time_seen_ips)} known IPs, "
          f"{len(_all_time_seen_subnets)} known subnets", flush=True)


def db_seen_ip(ip: str, is_new: bool) -> None:
    if is_new:
        _conn.execute("INSERT OR IGNORE INTO seen_ips(ip) VALUES(?)", (ip,))
    else:
        _conn.execute(
            "UPDATE seen_ips SET last_seen=CURRENT_TIMESTAMP, total_hits=total_hits+1 WHERE ip=?",
            (ip,),
        )


def db_seen_subnet(subnet: str, is_new: bool) -> None:
    if is_new:
        _conn.execute("INSERT OR IGNORE INTO seen_subnets(subnet) VALUES(?)", (subnet,))
    else:
        _conn.execute(
            "UPDATE seen_subnets SET last_seen=CURRENT_TIMESTAMP, total_hits=total_hits+1 WHERE subnet=?",
            (subnet,),
        )


def get_subnet(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        prefix = 24 if ip_obj.version == 4 else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ip


def record_hit(direction: str, ip: str, sig: str) -> tuple[int, str, int]:
    """
    Records an inbound/outbound hit against slot + daily counters and updates
    all-time uniqueness (seen_ips / seen_subnets) for inbound attackers.
    Returns: (ip_daily_count, subnet_str, subnet_daily_unique_count)
    """
    subnet_str = get_subnet(ip)

    if direction != "inbound":
        _daily_outbound_counts[ip] = _daily_outbound_counts.get(ip, 0) + 1
        return _daily_outbound_counts[ip], subnet_str, 0

    global _slot_alerts_count

    # All-time uniqueness (never seen before in history)
    is_new_ip = ip not in _all_time_seen_ips
    if is_new_ip:
        _all_time_seen_ips.add(ip)
        _slot_new_ips.add(ip)
        _daily_new_ips.add(ip)
    db_seen_ip(ip, is_new_ip)

    is_new_subnet = subnet_str not in _all_time_seen_subnets
    if is_new_subnet:
        _all_time_seen_subnets.add(subnet_str)
        _slot_new_subnets.add(subnet_str)
        _daily_new_subnets.add(subnet_str)
    db_seen_subnet(subnet_str, is_new_subnet)

    # Slot counters
    _slot_alerts_count += 1
    _slot_inbound_counts[ip] = _slot_inbound_counts.get(ip, 0) + 1
    s_slot = _slot_inbound_subnets.setdefault(subnet_str, {"ips": set(), "alerts": 0})
    s_slot["ips"].add(ip)
    s_slot["alerts"] += 1

    # Daily counters (drive block thresholds + midnight snapshot)
    _daily_inbound_counts[ip] = _daily_inbound_counts.get(ip, 0) + 1
    ip_daily_count = _daily_inbound_counts[ip]
    s_daily = _daily_inbound_subnets.setdefault(subnet_str, {"ips": set(), "alerts": 0})
    s_daily["ips"].add(ip)
    s_daily["alerts"] += 1
    subnet_daily_unique_cnt = len(s_daily["ips"])

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


# ── Aggregation & formatting helpers ──────────────────────────────────────────
def _top_and_singles(subnets: dict) -> tuple[list[dict], int, int]:
    """
    From {subnet: {"ips": set, "alerts": int}} build:
      - top list (subnets with >= 2 IPs), sorted by alerts desc then IPs desc
      - single_ips_count / single_ips_alerts (subnets with exactly 1 IP, i.e.
        addresses that did not aggregate into a /24)
    """
    top: list[dict] = []
    single_count = 0
    single_alerts = 0
    for subnet, info in subnets.items():
        ip_cnt = len(info["ips"])
        alerts = info["alerts"]
        if ip_cnt >= 2:
            top.append({
                "subnet": subnet,
                "ips": ip_cnt,
                "alerts": alerts,
                "avg": round(alerts / ip_cnt),
            })
        else:
            single_count += ip_cnt
            single_alerts += alerts
    top.sort(key=lambda x: (x["alerts"], x["ips"]), reverse=True)
    return top[:10], single_count, single_alerts


def _format_top_lines(top: list[dict]) -> list[str]:
    lines = ["ТОП10 підмереж по алертам (/24, від 2+ IP):"]
    for t in top:
        lines.append(
            f"• {t['subnet']} — {t['ips']:,} IP | {t['alerts']:,} алертів "
            f"(сер. {t['avg']:,} алерти/IP)"
        )
    return lines


def _slot_bounds(slot_index: int) -> tuple[str, str]:
    start_h = slot_index * 6
    end_h = start_h + 5
    return f"{start_h:02d}:00", f"{end_h:02d}:59"


# ── Notification builders ─────────────────────────────────────────────────────
def send_spike_alert(now: float) -> None:
    """Anomaly / spike alert built from the current 5-minute sliding window."""
    total = len(_sliding_window_alerts)
    unique_ips = len({e["ip"] for e in _sliding_window_alerts})
    avg_rate = round(total / (SLIDING_WINDOW / 60))  # alerts per minute over the window

    subnets: dict[str, dict] = {}
    for e in _sliding_window_alerts:
        subnet = get_subnet(e["ip"])
        info = subnets.setdefault(subnet, {"ips": set(), "alerts": 0})
        info["ips"].add(e["ip"])
        info["alerts"] += 1
    top, single_count, single_alerts = _top_and_singles(subnets)

    start = time.strftime("%H:%M", time.localtime(now - SLIDING_WINDOW))
    end = time.strftime("%H:%M", time.localtime(now))

    lines = [
        "🚨 АНОМАЛЬНИЙ СПЛЕСК АТАК (Spike Alert) ⚠️",
        f"Період: {start} - {end} (останні 5 хвилин)",
        "",
        f"• Всього алертів за 5 хв: {total:,} (поріг: N = {SPIKE_THRESHOLD_N:,})",
        f"• Середня інтенсивність: {avg_rate:,} алертів/хв",
        f"• Унікальних IP-атакуючих: {unique_ips:,}",
        "",
    ]
    if top:
        lines += _format_top_lines(top)
        lines.append("")
    lines.append(f"Поодинокі нові IP: {single_count:,} IP (всього {single_alerts:,} алертів)")

    telegram_send("\n".join(lines))
    _conn.execute(
        "INSERT INTO spike_events(start_time, end_time, total_alerts, avg_rate_per_min, "
        "unique_ips, top_subnets_json) VALUES(?,?,?,?,?,?)",
        (start, end, total, avg_rate, unique_ips, json.dumps(top)),
    )
    print(f"spike-alert total={total} rate={avg_rate}/min unique_ips={unique_ips}", flush=True)


def send_6h_slot_digest(slot_index: int, day: str) -> None:
    """Fixed 6-hour slot digest for the just-completed slot; archives to slot_digests."""
    total = _slot_alerts_count
    unique_ips = len(_slot_inbound_counts)
    unique_subnets = len(_slot_inbound_subnets)
    new_ips = len(_slot_new_ips)
    new_subnets = len(_slot_new_subnets)
    avg_per_ip = round(total / unique_ips) if unique_ips else 0
    avg_per_subnet = round(total / unique_subnets) if unique_subnets else 0
    top, single_count, single_alerts = _top_and_singles(_slot_inbound_subnets)
    start, end = _slot_bounds(slot_index)

    lines = [
        "📊 6-годинний дайджест нових загроз",
        f"Період: {start} - {end} ({day})",
        "",
        f"• Всього алертів за 6 годин: {total:,}",
        f"• Унікальних нових IP (раніше не бачили): {new_ips:,}",
        f"• Унікальних нових підмереж (раніше не бачили): {new_subnets:,}",
        f"• Середня кількість алертів на 1 IP: {avg_per_ip:,}",
        f"• Середня кількість алертів на 1 підмережу: {avg_per_subnet:,}",
        f"• Додано в постійний блок ІР за 6 годин: {_slot_perm_ips_count:,}",
        f"• Додано в постійний блок підмереж за 6 годин: {_slot_perm_subnets_count:,}",
        "",
    ]
    if top:
        lines += _format_top_lines(top)
        lines.append("")
    lines.append(
        f"Поодинокі нові IP (адреси які не агрегувалися в підмережі): "
        f"{single_count:,} IP (всього {single_alerts:,} алертів)"
    )

    telegram_send("\n".join(lines))
    _conn.execute(
        "INSERT INTO slot_digests(date, slot_index, start_time, end_time, total_alerts, "
        "new_ips_count, new_subnets_count, avg_alerts_per_ip, avg_alerts_per_subnet, "
        "perm_ips_count, perm_subnets_count, single_ips_count, single_ips_alerts, top_subnets_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (day, slot_index, start, end, total, new_ips, new_subnets, avg_per_ip, avg_per_subnet,
         _slot_perm_ips_count, _slot_perm_subnets_count, single_count, single_alerts, json.dumps(top)),
    )
    print(f"slot-digest slot={slot_index} {start}-{end} total={total} new_ips={new_ips}", flush=True)


def snapshot_daily_stats(day: str) -> None:
    """Capture the completed day's summary into daily_stats at midnight rollover."""
    total = sum(_daily_inbound_counts.values())
    unique_ips = len(_daily_inbound_counts)
    unique_subnets = len(_daily_inbound_subnets)
    new_ips = len(_daily_new_ips)
    new_subnets = len(_daily_new_subnets)
    avg_per_ip = round(total / unique_ips) if unique_ips else 0
    avg_per_subnet = round(total / unique_subnets) if unique_subnets else 0
    top, single_count, single_alerts = _top_and_singles(_daily_inbound_subnets)

    _conn.execute(
        "INSERT OR REPLACE INTO daily_stats(date, total_alerts, unique_ips, unique_subnets, "
        "new_ips_count, new_subnets_count, avg_alerts_per_ip, avg_alerts_per_subnet, "
        "perm_ips_count, perm_subnets_count, single_ips_count, single_ips_alerts, top_subnets_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (day, total, unique_ips, unique_subnets, new_ips, new_subnets, avg_per_ip, avg_per_subnet,
         _daily_permanent_ips_count, _daily_permanent_subnets_count, single_count, single_alerts,
         json.dumps(top)),
    )
    print(f"daily-snapshot {day} total={total} unique_ips={unique_ips} new_ips={new_ips}", flush=True)


def send_7am_daily_report() -> None:
    """07:00 AM report for the previous full day, read from daily_stats."""
    yesterday = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
    row = _conn.execute(
        "SELECT date, total_alerts, new_ips_count, new_subnets_count, avg_alerts_per_ip, "
        "avg_alerts_per_subnet, perm_ips_count, perm_subnets_count, single_ips_count, "
        "single_ips_alerts, top_subnets_json FROM daily_stats WHERE date=?",
        (yesterday,),
    ).fetchone()
    if not row:
        print(f"7am-report skipped: no daily_stats row for {yesterday}", flush=True)
        return

    (day, total, new_ips, new_subnets, avg_per_ip, avg_per_subnet,
     perm_ips, perm_subnets, single_count, single_alerts, top_json) = row
    top = json.loads(top_json)

    lines = [
        f"🌅 Звіт за попередній день ({day}) 📊",
        "",
        f"• Всього алертів за добу: {total:,}",
        f"• Унікальних нових IP (раніше не бачили): {new_ips:,}",
        f"• Унікальних нових підмереж (раніше не бачили): {new_subnets:,}",
        f"• Середня кількість алертів на 1 IP: {avg_per_ip:,}",
        f"• Середня кількість алертів на 1 підмережу: {avg_per_subnet:,}",
        f"• Додано в постійний блок ІР за добу: {perm_ips:,}",
        f"• Додано в постійний блок підмереж за добу: {perm_subnets:,}",
        "",
    ]
    if top:
        lines += _format_top_lines(top)
        lines.append("")
    lines.append(
        f"Поодинокі нові IP (адреси які не агрегувалися в підмережі): "
        f"{single_count:,} IP (всього {single_alerts:,} алертів)"
    )

    telegram_send("\n".join(lines))
    print(f"7am-report sent for {day}", flush=True)


def _reset_slot_state(new_slot: int) -> None:
    global _slot_index, _slot_alerts_count, _slot_perm_ips_count, _slot_perm_subnets_count
    _slot_index = new_slot
    _slot_alerts_count = 0
    _slot_perm_ips_count = 0
    _slot_perm_subnets_count = 0
    _slot_inbound_counts.clear()
    _slot_inbound_subnets.clear()
    _slot_new_ips.clear()
    _slot_new_subnets.clear()


def _reset_daily_state(new_day: str) -> None:
    global _digest_day, _daily_permanent_ips_count, _daily_permanent_subnets_count
    _digest_day = new_day
    _daily_permanent_ips_count = 0
    _daily_permanent_subnets_count = 0
    _daily_inbound_counts.clear()
    _daily_inbound_subnets.clear()
    _daily_outbound_counts.clear()
    _daily_new_ips.clear()
    _daily_new_subnets.clear()


def check_spike(now: float) -> None:
    """Prune the sliding window and fire an anomaly alert if the threshold is crossed."""
    global _last_spike_alert_time
    cutoff = now - SLIDING_WINDOW
    while _sliding_window_alerts and _sliding_window_alerts[0]["time"] < cutoff:
        _sliding_window_alerts.pop(0)
    if len(_sliding_window_alerts) >= SPIKE_THRESHOLD_N and (now - _last_spike_alert_time) >= SPIKE_COOLDOWN:
        send_spike_alert(now)
        _last_spike_alert_time = now


def check_periodic_tasks() -> None:
    global _last_7am_report_date
    now = time.time()
    today = time.strftime("%Y-%m-%d")
    current_hour = int(time.strftime("%H"))
    cur_slot = current_hour // 6

    # Prune the sliding window even when idle (no new alerts arriving)
    cutoff = now - SLIDING_WINDOW
    while _sliding_window_alerts and _sliding_window_alerts[0]["time"] < cutoff:
        _sliding_window_alerts.pop(0)

    # 1. 6-hour slot boundary: emit digest for the completed slot, then reset
    if cur_slot != _slot_index:
        send_6h_slot_digest(_slot_index, _digest_day)
        _reset_slot_state(cur_slot)

    # 2. Midnight rollover: archive the completed day, then reset daily counters
    if today != _digest_day:
        snapshot_daily_stats(_digest_day)
        _reset_daily_state(today)

    # 3. 07:00 AM daily report for the previous day
    if current_hour >= 7 and _last_7am_report_date != today:
        _last_7am_report_date = today
        send_7am_daily_report()


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
    global _last_7am_report_date, _daily_permanent_ips_count, _daily_permanent_subnets_count
    global _slot_perm_ips_count, _slot_perm_subnets_count
    db_init()
    # Startup guard: if we boot after 07:00, don't re-fire yesterday's report on every restart.
    if int(time.strftime("%H")) >= 7:
        _last_7am_report_date = time.strftime("%Y-%m-%d")
    print(f"following {EVE_LOG}, blocking via {MT_HOST}, spike N={SPIKE_THRESHOLD_N}", flush=True)
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
        now = time.time()

        if direction == "inbound":
            attempts, subnet_str, subnet_unique_cnt = record_hit("inbound", target_ip, sig)

            # Feed anomaly detection with every inbound alert (rate, not per-alert paging)
            _sliding_window_alerts.append(
                {"time": now, "ip": target_ip, "sig": sig, "direction": "inbound"}
            )
            check_spike(now)

            # Subnet aggregation: block entire /24 once 10 unique IPs reached today
            if subnet_unique_cnt == SUBNET_THRESHOLD:
                blocked_sub = mikrotik_block(subnet_str, f"SUBNET BLOCK (10+ IPs): {sig}", permanent=True)
                if blocked_sub:
                    _slot_perm_subnets_count += 1
                    _daily_permanent_subnets_count += 1
                print(f"subnet-block {sig} subnet={subnet_str} unique_ips={subnet_unique_cnt} "
                      f"permanent=True blocked={blocked_sub}", flush=True)

            if attempts > PERMANENT_THRESHOLD:
                continue

            permanent = (attempts == PERMANENT_THRESHOLD)

            if not permanent and not cooled_down(f"inbound|{target_ip}|{alert.get('signature_id')}"):
                continue

            blocked = mikrotik_block(target_ip, sig, permanent=permanent)
            if permanent and blocked:
                _slot_perm_ips_count += 1
                _daily_permanent_ips_count += 1

            print(f"inbound-alert {sig} attacker={target_ip} attempts={attempts} "
                  f"permanent={permanent} blocked={blocked}", flush=True)

        else:
            # Outbound traffic (LAN -> WAN): always a 1h temporary block, no digest
            attempts, subnet_str, _ = record_hit("outbound", target_ip, sig)

            if not cooled_down(f"outbound|{target_ip}|{alert.get('signature_id')}"):
                continue

            blocked = mikrotik_block(target_ip, sig, permanent=False)
            print(f"outbound-alert {sig} target={target_ip} hits={attempts} "
                  f"blocked={blocked}", flush=True)


if __name__ == "__main__":
    main()
