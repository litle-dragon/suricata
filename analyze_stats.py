#!/usr/bin/env python3
"""Analyze the Suricata alert-bridge SQLite database.

Reads /var/log/suricata/alert_bridge.db directly (no journal parsing):
  --sum                 Summary across every recorded day (daily_stats).
  --day YYYY-MM-DD      Full breakdown for one historical day.
  --spikes              Log of all anomaly spike alerts (spike_events).
  --top N               Top N attacker subnets and IPs all-time (seen_subnets / seen_ips).
                        Subnets carry a "Blocked" column (permanent_blocks) so you can
                        tell noisy-but-unblocked subnets apart from ones already handled.
  --list                With --sum/--day: also print actual new-IP/new-subnet/permanently-blocked
                        addresses (not just counts). Terminal preview is capped per group.
  --list-out FILE       Write the full, untruncated address lists to FILE (implies --list;
                        with --sum/--day).
  --sync-mikrotik       Block /24 subnets with >= MIN unique IPs all-time on MikroTik.
                        Subnets already recorded in permanent_blocks are skipped for the
                        block step (no repeat PUT) but still get their redundant single-IP
                        entries cleaned up, so re-running is idempotent and quiet.
  --merge-adjacent      Two-part MikroTik cleanup: removes individually-blocked IPs
                        already covered by an existing subnet of any width (/24 through
                        /21+), then aggregates subnet entries at any level in one pass
                        (/24+/24 -> /23, existing /23+/23 -> /22, etc. via
                        ipaddress.collapse_addresses()). Verifies every DELETE actually
                        succeeded before claiming an aggregation worked.
  --verify-blocks       Cross-check permanent_blocks (SQLite) against the live MikroTik
                        list. An entry is fine if present exactly OR covered by a wider
                        subnet already there (e.g. after --merge-adjacent); only a truly
                        absent entry is reported as missing.
  --messages             Show archived sent messages (slot digests, daily reports, spike
                        alerts, service events) reconstructed in the exact text Telegram
                        received, not a re-derived summary. Combine with:
                          --kind {slot,daily,spike,service,all}  (default: all)
                          --hours N     messages sent in the last N hours
                          --days N      messages covering the last N calendar days
                          --date D      messages covering exactly this calendar date
                          --from/--to   explicit sent-at range ('YYYY-MM-DD[ HH:MM]',
                                        interpreted as local time)
                        Examples: --messages --kind slot --hours 6 (periodic digests
                        from the last 6 hours, no daily reports); --messages --kind
                        daily --days 7 (daily reports for the last week); --messages
                        --date 2026-08-21 (everything covering that one day).

With no mode given, prints the --sum summary.

Every mode also mirrors its key actions to the systemd journal via syslog (see
`_jlog`) — unlike alert-bridge.service, this script runs ad-hoc (manual / cron),
so its stdout isn't captured by journald unless explicitly logged.
"""

import argparse
import configparser
import importlib.util
import ipaddress
import json
import os
import sqlite3
import sys
import syslog
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    requests = None

DB_FILE = os.environ.get("DB_FILE", "/var/log/suricata/alert_bridge.db")

# Same alert-bridge.cfg that alert-bridge.py reads (see [blocking] subnet_threshold
# there) — --min-ips below defaults to it, so this CLI's manual/cron sync matches
# whatever threshold the live daemon is actually enforcing, instead of carrying its
# own separately-hardcoded number that silently drifts out of sync with the daemon's.
CFG_FILE = os.environ.get("CFG_FILE", "/opt/alert-bridge/alert-bridge.cfg")
_cfg = configparser.ConfigParser()
if os.path.exists(CFG_FILE):
    _cfg.read(CFG_FILE)
DEFAULT_MIN_IPS = _cfg.getint("blocking", "subnet_threshold", fallback=5)

syslog.openlog(ident="analyze_stats", logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)


def _jlog(msg: str, level: int = syslog.LOG_INFO) -> None:
    """Mirror a key action to the journal (todo #6) — analyze_stats.py is invoked
    manually or via cron, not as a systemd service, so unlike alert-bridge.py its
    stdout is not captured by journald automatically."""
    try:
        syslog.syslog(level, msg)
    except Exception:
        pass  # journal logging is best-effort; never fail the actual operation over it


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
        except PermissionError:
            print(f"Warning: Permission denied reading {env_path}. Run with 'sudo' to read MikroTik credentials.", file=sys.stderr)
        except Exception as e:
            print(f"Warning: failed to read {env_path}: {e}", file=sys.stderr)


def connect_db() -> sqlite3.Connection | None:
    if not os.path.exists(DB_FILE):
        print(f"Error: database not found at {DB_FILE}. Is alert-bridge running?", file=sys.stderr)
        return None
    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def aggregate_seen_subnets(conn: sqlite3.Connection, min_ips: int = 1) -> list[tuple[str, int, int]]:
    """Aggregate seen_ips into /24 (or /64) subnets: (subnet, unique_ips, total_hits)."""
    subnets = defaultdict(lambda: {"ips": set(), "hits": 0})
    for row in conn.execute("SELECT ip, total_hits FROM seen_ips"):
        ip_str, hits = row["ip"], row["total_hits"]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            prefix = 24 if ip_obj.version == 4 else 64
            net_str = str(ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False))
        except ValueError:
            continue
        subnets[net_str]["ips"].add(ip_str)
        subnets[net_str]["hits"] += hits
    res = [
        (net, len(info["ips"]), info["hits"])
        for net, info in subnets.items()
        if len(info["ips"]) >= min_ips
    ]
    res.sort(key=lambda x: (x[2], x[1]), reverse=True)
    return res


def _permanently_blocked_subnet_set(conn: sqlite3.Connection) -> set[str]:
    """All subnets ever recorded in permanent_blocks (kind='subnet'). Empty set,
    not an error, if the DB predates the permanent_blocks migration."""
    try:
        return {r["ip_or_subnet"] for r in conn.execute(
            "SELECT ip_or_subnet FROM permanent_blocks WHERE kind='subnet'"
        )}
    except sqlite3.OperationalError:
        return set()


def _new_addresses_for_day(conn: sqlite3.Connection, day: str) -> tuple[list[str], list[str]]:
    """New IPs / subnets whose first_seen falls on `day` (proxy for daily_stats new_*_count)."""
    ips = [r["ip"] for r in conn.execute(
        "SELECT ip FROM seen_ips WHERE date(first_seen)=? ORDER BY first_seen", (day,)
    )]
    subnets = [r["subnet"] for r in conn.execute(
        "SELECT subnet FROM seen_subnets WHERE date(first_seen)=? ORDER BY first_seen", (day,)
    )]
    return ips, subnets


def _permanent_blocks_for_day(conn: sqlite3.Connection, day: str) -> list[tuple[str, str]] | None:
    """(ip_or_subnet, kind) permanently blocked on `day`. None if the audit
    table doesn't exist yet (DB predates the permanent_blocks migration)."""
    try:
        rows = conn.execute(
            "SELECT ip_or_subnet, kind FROM permanent_blocks WHERE date(blocked_at)=? ORDER BY blocked_at",
            (day,),
        ).fetchall()
    except sqlite3.OperationalError:
        return None
    return [(r["ip_or_subnet"], r["kind"]) for r in rows]


LIST_PREVIEW_LIMIT = 50  # terminal preview cap per address group; full list goes to --list-out


def _print_address_block(label: str, addresses: list[str], indent: str = "", out_fh=None) -> None:
    """One address per line (not a giant comma-joined line) with a preview
    cap for the terminal; the full list goes to `out_fh` when given."""
    print(f"{indent}{label} ({len(addresses)}):")
    for addr in addresses[:LIST_PREVIEW_LIMIT]:
        print(f"{indent}  {addr}")
    if len(addresses) > LIST_PREVIEW_LIMIT:
        print(f"{indent}  ...і ще {len(addresses) - LIST_PREVIEW_LIMIT} "
              f"(використай --list-out FILE для повного списку)")
    if out_fh is not None:
        out_fh.write(f"# {label} ({len(addresses)})\n")
        out_fh.write("\n".join(addresses) + "\n\n")


def _print_day_addresses(conn: sqlite3.Connection, day: str, indent: str = "", out_fh=None) -> None:
    ips, subnets = _new_addresses_for_day(conn, day)
    if ips:
        _print_address_block("Нові IP", ips, indent, out_fh)
    if subnets:
        _print_address_block("Нові підмережі", subnets, indent, out_fh)

    perm = _permanent_blocks_for_day(conn, day)
    if perm is None:
        print(f"{indent}(таблиця permanent_blocks відсутня в цій базі — оновлений alert-bridge.py "
              f"ще не запускався тут; лічильники perm_ips_count/perm_subnets_count є, адрес нема)")
        return
    perm_ips = [a for a, k in perm if k == "ip"]
    perm_subnets = [a for a, k in perm if k == "subnet"]
    if perm_ips:
        _print_address_block("Заблоковано постійно, IP", perm_ips, indent, out_fh)
    if perm_subnets:
        _print_address_block("Заблоковано постійно, підмережі", perm_subnets, indent, out_fh)
    if not perm:
        print(f"{indent}Заблоковано постійно цього дня: 0")


def cmd_sum(conn: sqlite3.Connection, show_list: bool = False, out_fh=None):
    rows = list(conn.execute(
        "SELECT date, total_alerts, unique_ips, unique_subnets, new_ips_count, "
        "new_subnets_count, perm_ips_count, perm_subnets_count FROM daily_stats ORDER BY date"
    ))
    if not rows:
        print("No daily statistics recorded yet (daily_stats is empty).")
        return

    print(f"\n📊 Daily summary — {rows[0]['date']} .. {rows[-1]['date']} ({len(rows)} days)")
    print("=" * 92)
    print(f"{'Date':<12} | {'Alerts':>10} | {'Uniq IP':>9} | {'New IP':>9} | "
          f"{'Uniq Net':>9} | {'New Net':>8} | {'PermIP':>7} | {'PermNet':>7}")
    print("-" * 92)
    tot_alerts = tot_new_ips = tot_new_nets = tot_perm_ips = tot_perm_nets = 0
    for r in rows:
        print(f"{r['date']:<12} | {r['total_alerts']:>10,} | {r['unique_ips']:>9,} | "
              f"{r['new_ips_count']:>9,} | {r['unique_subnets']:>9,} | {r['new_subnets_count']:>8,} | "
              f"{r['perm_ips_count']:>7,} | {r['perm_subnets_count']:>7,}")
        if show_list:
            _print_day_addresses(conn, r["date"], indent="    ", out_fh=out_fh)
        tot_alerts += r["total_alerts"]
        tot_new_ips += r["new_ips_count"]
        tot_new_nets += r["new_subnets_count"]
        tot_perm_ips += r["perm_ips_count"]
        tot_perm_nets += r["perm_subnets_count"]
    print("-" * 92)
    print(f"Totals: {tot_alerts:,} alerts | {tot_new_ips:,} new IPs | {tot_new_nets:,} new subnets | "
          f"{tot_perm_ips:,} perm IPs | {tot_perm_nets:,} perm subnets")
    print("=" * 92)
    _jlog(f"--sum: {len(rows)} days, {tot_alerts} total alerts, {tot_perm_ips} perm IPs, {tot_perm_nets} perm subnets")


def cmd_day(conn: sqlite3.Connection, day: str, show_list: bool = False, out_fh=None):
    r = conn.execute("SELECT * FROM daily_stats WHERE date=?", (day,)).fetchone()
    if not r:
        print(f"No record for {day}. Available days: use --sum to list.")
        return
    top = json.loads(r["top_subnets_json"])
    print(f"\n🌅 Day report ({day})")
    print("=" * 65)
    print(f"• Total alerts:              {r['total_alerts']:,}")
    print(f"• Unique IPs:                {r['unique_ips']:,}")
    print(f"• New IPs (never seen):      {r['new_ips_count']:,}")
    print(f"• Unique subnets:            {r['unique_subnets']:,}")
    print(f"• New subnets (never seen):  {r['new_subnets_count']:,}")
    print(f"• Avg alerts / IP:           {r['avg_alerts_per_ip']:,}")
    print(f"• Avg alerts / subnet:       {r['avg_alerts_per_subnet']:,}")
    print(f"• Permanent IP blocks:       {r['perm_ips_count']:,}")
    print(f"• Permanent subnet blocks:   {r['perm_subnets_count']:,}")
    print(f"• Single (non-aggregated):   {r['single_ips_count']:,} IPs ({r['single_ips_alerts']:,} alerts)")
    if show_list:
        print("-" * 65)
        _print_day_addresses(conn, day, out_fh=out_fh)
    if top:
        print("-" * 65)
        print("TOP subnets (/24, >= 2 IPs):")
        for t in top:
            print(f"  {t['subnet']:<20} {t['ips']:>5,} IP | {t['alerts']:>7,} alerts (avg {t['avg']:,}/IP)")
    print("=" * 65)
    _jlog(f"--day {day}: {r['total_alerts']} alerts, {r['perm_ips_count']} perm IPs, {r['perm_subnets_count']} perm subnets")


def cmd_geo(conn: sqlite3.Connection):
    """Breakdown of permanent geo/Spamhaus blocks, grouped by kind -- separate
    from --sum/--top (docs/adr/0002: geo/Spamhaus is its own parallel
    pipeline, never touches the ordinary 'ip'/'subnet' permanent_blocks rows
    or seen_ips/seen_subnets uniqueness)."""
    rows = list(conn.execute(
        "SELECT kind, COUNT(*) as cnt, MIN(blocked_at) as first_blocked, MAX(blocked_at) as last_blocked "
        "FROM permanent_blocks WHERE kind LIKE 'geo-%' OR kind='spamhaus' "
        "GROUP BY kind ORDER BY kind"
    ))
    if not rows:
        print("No geo/Spamhaus permanent blocks recorded yet.")
        return
    print("\n🌍 Geo / Spamhaus permanent blocks")
    print("=" * 70)
    total = 0
    for r in rows:
        label = r["kind"][len("geo-"):].upper() if r["kind"].startswith("geo-") else "Spamhaus"
        print(f"{label:<12} | {r['cnt']:>6,} blocks | first {r['first_blocked']} | last {r['last_blocked']}")
        total += r["cnt"]
    print("-" * 70)
    print(f"Total: {total:,} permanent geo/Spamhaus blocks")
    print("=" * 70)
    _jlog(f"--geo: {total} geo/spamhaus permanent blocks across {len(rows)} kinds")


def cmd_spikes(conn: sqlite3.Connection):
    rows = list(conn.execute(
        "SELECT timestamp, start_time, end_time, total_alerts, avg_rate_per_min, unique_ips "
        "FROM spike_events ORDER BY id"
    ))
    if not rows:
        print("No anomaly spike events recorded.")
        return
    print(f"\n🚨 Anomaly spike events ({len(rows)} total)")
    print("=" * 78)
    print(f"{'When (UTC)':<21} | {'Window':<15} | {'Alerts':>8} | {'Rate/min':>9} | {'Uniq IP':>8}")
    print("-" * 78)
    for r in rows:
        window = f"{r['start_time']}-{r['end_time']}"
        print(f"{r['timestamp']:<21} | {window:<15} | {r['total_alerts']:>8,} | "
              f"{r['avg_rate_per_min']:>9,} | {r['unique_ips']:>8,}")
    print("=" * 78)
    _jlog(f"--spikes: {len(rows)} spike events listed")


def cmd_top(conn: sqlite3.Connection, n: int):
    subnets = aggregate_seen_subnets(conn, min_ips=1)[:n]
    blocked_subnets = _permanently_blocked_subnet_set(conn)

    print(f"\n🏆 Top {n} attacker subnets all-time (/24, by total hits)")
    print("=" * 78)
    print(f"{'Subnet':<22} | {'Unique IPs':>11} | {'Total hits':>11} | {'Blocked':>9}")
    print("-" * 78)
    blocked_count = 0
    for net, uniq, hits in subnets:
        is_blocked = net in blocked_subnets
        blocked_count += is_blocked
        print(f"{net:<22} | {uniq:>11,} | {hits:>11,} | {'так' if is_blocked else 'ні':>9}")
    print("=" * 78)
    if not blocked_subnets:
        print("(таблиця permanent_blocks порожня/відсутня — стовпець Blocked покаже "
              "'ні' для всіх, доки oновлений alert-bridge.py / --sync-mikrotik тут не запускався)")

    ips = list(conn.execute(
        "SELECT ip, total_hits FROM seen_ips ORDER BY total_hits DESC LIMIT ?", (n,)
    ))
    print(f"\n🏆 Top {n} attacker IPs all-time (by total hits)")
    print("=" * 45)
    print(f"{'IP':<32} | {'Total hits':>10}")
    print("-" * 45)
    for r in ips:
        print(f"{r['ip']:<32} | {r['total_hits']:>10,}")
    print("=" * 45)
    _jlog(f"--top {n}: {len(subnets)} subnets ({blocked_count} blocked), {len(ips)} IPs listed")


def cmd_verify_blocks(conn: sqlite3.Connection, fix: bool = False):
    """
    Cross-checks permanent_blocks (our SQLite audit of "should be blocked
    forever") against what MikroTik's live block list actually contains.

    An entry counts as verified if it's present EXACTLY OR is covered by a
    wider subnet already on the list — being covered is exactly as
    protective as an exact entry, and is the expected outcome after
    --merge-adjacent collapses several /24s into one wider CIDR, or after a
    single redundant IP gets cleaned up because its subnet already covers
    it. Only a genuinely absent (neither exact nor covered) entry is a real
    problem.

    With fix=True, every genuinely-missing entry (IP or subnet alike) is
    PUT back onto the live list with a PERMANENT comment, then re-verified
    so the closing summary reflects the actual end state.
    """
    if requests is None:
        print("\nError: 'requests' library not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return
    load_env()
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")
    block_list = os.environ.get("BLOCK_LIST", "suricata-block")
    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials incomplete in /opt/alert-bridge/env.", file=sys.stderr)
        return

    try:
        rows = list(conn.execute(
            "SELECT ip_or_subnet, kind, signature, blocked_at FROM permanent_blocks ORDER BY blocked_at"
        ))
    except sqlite3.OperationalError:
        print("No permanent_blocks table in this database — nothing to verify "
              "(an updated alert-bridge.py hasn't run here yet).")
        return
    if not rows:
        print("permanent_blocks is empty — nothing to verify.")
        return

    auth = (mt_user, mt_pass)

    def fetch_live_nets() -> tuple[dict[str, list], dict[str, bool]]:
        # Fetch the live list once per address family — same principle as
        # sync_subnets_to_mikrotik's fix: never re-fetch per row.
        nets_by_family: dict[str, list] = {}
        ok_by_family: dict[str, bool] = {}
        for family in ("ip", "ipv6"):
            url = f"https://{mt_host}/rest/{family}/firewall/address-list"
            try:
                r = requests.get(f"{url}?list={block_list}", auth=auth, verify=False, timeout=(5, 20))
                if r.status_code == 200:
                    data = r.json()
                    nets = []
                    for entry in (data if isinstance(data, list) else []):
                        addr = entry.get("address", "")
                        if not addr:
                            continue
                        try:
                            nets.append(ipaddress.ip_network(addr, strict=False))
                        except ValueError:
                            continue
                    nets_by_family[family] = nets
                    ok_by_family[family] = True
                else:
                    print(f"Warning: failed to fetch {family} block list: HTTP {r.status_code}", file=sys.stderr)
                    nets_by_family[family] = []
                    ok_by_family[family] = False
            except requests.RequestException as e:
                print(f"Warning: failed to fetch {family} block list: {e}", file=sys.stderr)
                nets_by_family[family] = []
                ok_by_family[family] = False
        return nets_by_family, ok_by_family

    def classify() -> tuple[int, int, list[tuple[str, str, str]]]:
        live_nets, fetch_ok = fetch_live_nets()
        verified_exact = 0
        covered_by_wider = 0
        missing: list[tuple[str, str, str]] = []  # (addr, kind, reason)
        for row in rows:
            addr_str, kind, sig = row["ip_or_subnet"], row["kind"], row["signature"] or ""
            try:
                net_check = ipaddress.ip_network(addr_str, strict=False)
            except ValueError:
                missing.append((addr_str, kind, "not a valid IP/subnet in our own record"))
                continue
            family = "ipv6" if net_check.version == 6 else "ip"
            if not fetch_ok[family]:
                missing.append((addr_str, kind, f"could not verify — {family} list fetch failed"))
                continue
            candidates = live_nets[family]
            if net_check in candidates:
                verified_exact += 1
                continue
            if any(n.prefixlen < net_check.prefixlen and net_check.subnet_of(n) for n in candidates):
                covered_by_wider += 1
                continue
            missing.append((addr_str, kind, sig))
        return verified_exact, covered_by_wider, missing

    verified_exact, covered_by_wider, missing = classify()
    total = len(rows)

    if fix and missing:
        fixable = [
            (addr_str, kind, reason) for addr_str, kind, reason in missing
            if "not a valid" not in reason and "could not verify" not in reason
        ]
        print(f"\n🔧 Re-adding {len(fixable)} missing entr{'y' if len(fixable) == 1 else 'ies'} to MikroTik...")
        for addr_str, kind, reason in fixable:
            net_check = ipaddress.ip_network(addr_str, strict=False)
            family = "ipv6" if net_check.version == 6 else "ip"
            base_url = f"https://{mt_host}/rest/{family}/firewall/address-list"
            body = {
                "list": block_list,
                "address": addr_str,
                "comment": f"PERMANENT: {reason or 're-added by --verify-blocks --fix'}"[:60],
            }
            status_code = None
            try:
                r_put = requests.put(base_url, json=body, auth=auth, verify=False, timeout=(5, 15))
                status_code = r_put.status_code
                ok = r_put.status_code in (200, 201) or "already" in r_put.text
            except requests.RequestException as e:
                print(f"  ⚠️ Exception re-adding {addr_str}: {e}", file=sys.stderr)
                ok = False
            if ok:
                print(f"  ✅ Re-added {addr_str} ({kind})")
                _jlog(f"--verify-blocks --fix: re-added {addr_str} ({kind})")
            else:
                print(f"  ⚠️ Failed to re-add {addr_str} ({kind}): HTTP {status_code}", file=sys.stderr)
        # Re-verify against the router's actual post-fix state rather than assuming success.
        verified_exact, covered_by_wider, missing = classify()

    print(f"\n🔍 Verified {total} permanent_blocks entries against live MikroTik '{block_list}' list")
    print("=" * 78)
    print(f"  Exact match on MikroTik:      {verified_exact}")
    print(f"  Covered by a wider subnet:   {covered_by_wider}")
    print(f"  MISSING from MikroTik:       {len(missing)}")
    print("=" * 78)
    if missing:
        print("\nRecorded as permanently blocked, but NOT found on MikroTik (neither exact nor covered):")
        for addr_str, kind, reason in missing:
            print(f"  - {addr_str} ({kind})" + (f" — {reason}" if reason else ""))
        if not fix:
            print("\nRe-add subnets with: sudo python3 analyze_stats.py --sync-mikrotik")
            print("Or re-add everything (IPs included) with: sudo python3 analyze_stats.py --verify-blocks --fix")
    else:
        print("\nAll permanently-blocked addresses/subnets are present on the live "
              "MikroTik list (exact match or covered by a wider subnet).")
    _jlog(f"--verify-blocks: {total} checked, {verified_exact} exact, {covered_by_wider} covered, "
          f"{len(missing)} missing, fix={fix}")


def _record_permanent_block(addr: str, kind: str, signature: str) -> None:
    """
    Writes to permanent_blocks on a short-lived read-write connection —
    `connect_db()` opens the main connection read-only on purpose, so the
    live alert-bridge.py daemon is never at risk from an analytics script.
    """
    try:
        rw = sqlite3.connect(DB_FILE)
        rw.execute(
            "CREATE TABLE IF NOT EXISTS permanent_blocks ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, ip_or_subnet TEXT NOT NULL, "
            "kind TEXT NOT NULL, signature TEXT, blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        rw.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_permanent_blocks_addr ON permanent_blocks(ip_or_subnet)"
        )
        rw.execute(
            "INSERT OR IGNORE INTO permanent_blocks(ip_or_subnet, kind, signature) VALUES(?,?,?)",
            (addr, kind, signature),
        )
        rw.commit()
        rw.close()
    except sqlite3.Error as e:
        print(f"  Warning: failed to record permanent block for {addr} in audit table: {e}", file=sys.stderr)


def merge_adjacent_subnets():
    """
    Two-part cleanup pass over the live MikroTik block list:

    1. Individual-IP redundancy: any permanently-blocked single IP (/32) that
       falls inside an already-blocked subnet — of ANY width on the list, not
       just /24 (a /24, /23, /22, /21, ... aggregate all count) — is removed.
       E.g. IP 1.1.4.20 is deleted if 1.1.0.0/21 is already blocked, even
       though 1.1.4.20 is not inside a /24 written out anywhere.
    2. Subnet aggregation, multi-level: every remaining subnet entry (again,
       any width already on the list) is fed through
       ipaddress.collapse_addresses(), which merges bit-aligned, contiguous
       blocks at any level in one pass — /24+/24 -> /23, two existing
       /23+/23 -> /22, four contiguous /24s straight into /22, etc. It never
       merges unrelated/misaligned neighbors; only exact, lossless CIDR
       aggregation. The narrower originals are deleted and the wider block
       is added — but only once every deletion for that merge is confirmed
       (todo #8): a failed delete skips that merge instead of leaving an
       orphaned wider block layered on top of a still-live narrower one.

    Net effect: the live list ends up as the minimal CIDR set covering
    exactly the same addresses — no single IP left redundant under a
    subnet, no narrower subnet left redundant under a wider one.
    """
    if requests is None:
        print("\nError: 'requests' library not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return
    load_env()
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")
    block_list = os.environ.get("BLOCK_LIST", "suricata-block")
    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials incomplete in /opt/alert-bridge/env.", file=sys.stderr)
        return

    base_url = f"https://{mt_host}/rest/ip/firewall/address-list"
    auth = (mt_user, mt_pass)
    try:
        r = requests.get(f"{base_url}?list={block_list}", auth=auth, verify=False, timeout=(5, 10))
    except requests.RequestException as e:
        print(f"Error: failed to fetch block list: {e}", file=sys.stderr)
        return
    if r.status_code != 200:
        print(f"Error: MikroTik returned {r.status_code}: {r.text}", file=sys.stderr)
        return
    entries = r.json()
    if not isinstance(entries, list):
        print("Error: unexpected response shape from MikroTik.", file=sys.stderr)
        return

    # Split into subnet entries (any width, including previously-merged /23,
    # /22, ...) and single-IP entries. IPv4 only — this REST endpoint
    # (/rest/ip/...) never carried IPv6, matching the rest of this script.
    subnet_entries: dict[ipaddress.IPv4Network, str] = {}
    ip_entries: dict[ipaddress.IPv4Address, tuple[str, str]] = {}  # addr -> (raw string, entry_id)
    for entry in entries:
        addr, entry_id = entry.get("address", ""), entry.get(".id")
        if not addr or not entry_id:
            continue
        try:
            net = ipaddress.ip_network(addr, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        if net.prefixlen == 32:
            ip_entries[net.network_address] = (addr, entry_id)
        else:
            subnet_entries[net] = entry_id

    # ── Part 1: individual IPs covered by an already-blocked subnet ──
    removed_ip_count = 0
    failed_ip_removals = 0
    if subnet_entries and ip_entries:
        subnet_list = list(subnet_entries.keys())
        for ip_addr, (addr_str, entry_id) in list(ip_entries.items()):
            if not any(ip_addr in net for net in subnet_list):
                continue
            try:
                r_del = requests.delete(f"{base_url}/{entry_id}", auth=auth, verify=False, timeout=(5, 10))
                if r_del.status_code in (200, 204):
                    removed_ip_count += 1
                    print(f"  🗑️ Removing redundant single IP {addr_str} (covered by an already-blocked subnet)...", flush=True)
                    del ip_entries[ip_addr]
                else:
                    failed_ip_removals += 1
                    print(f"  ⚠️ Failed to remove covered IP {addr_str}: HTTP {r_del.status_code} {r_del.text}", file=sys.stderr)
            except requests.RequestException as e:
                failed_ip_removals += 1
                print(f"  Warning: failed to remove covered IP {addr_str}: {e}", file=sys.stderr)

    if removed_ip_count or failed_ip_removals:
        print(f"\n🧹 Individual IPs covered by existing subnets: {removed_ip_count} removed"
              + (f", {failed_ip_removals} failed" if failed_ip_removals else "") + ".")
    else:
        print("\nNo individually-blocked IPs are covered by an existing subnet.")
    _jlog(f"--merge-adjacent: removed {removed_ip_count} single IPs covered by subnets "
          f"({failed_ip_removals} failed)")

    # ── Part 2: subnet aggregation, any width, multi-level in one pass ──
    if len(subnet_entries) < 2:
        print("Nothing to aggregate — fewer than two subnet entries on the block list.")
        _jlog("--merge-adjacent: nothing to aggregate, fewer than two subnet entries")
        return

    collapsed = list(ipaddress.collapse_addresses(subnet_entries.keys()))
    merges = [n for n in collapsed if n not in subnet_entries]  # genuinely new (merged) blocks only
    if not merges:
        print(f"Checked {len(subnet_entries)} subnet entries — no adjacent blocks to aggregate.")
        _jlog(f"--merge-adjacent: checked {len(subnet_entries)} subnets, no adjacent aggregation")
        return

    print(f"\n🔗 Found {len(merges)} aggregation(s) among {len(subnet_entries)} subnet entries:")
    merged_ok = 0
    merged_failed = 0
    for supernet in merges:
        covered = [net for net in subnet_entries if net.subnet_of(supernet)]
        print(f"  {' + '.join(str(n) for n in covered)} -> {supernet}")

        removed_ok: list[ipaddress.IPv4Network] = []
        removed_failed: list[ipaddress.IPv4Network] = []
        for net in covered:
            try:
                r_del = requests.delete(f"{base_url}/{subnet_entries[net]}", auth=auth, verify=False, timeout=(5, 10))
                if r_del.status_code in (200, 204):
                    removed_ok.append(net)
                else:
                    removed_failed.append(net)
                    print(f"  ⚠️ Failed to remove {net}: HTTP {r_del.status_code} {r_del.text}", file=sys.stderr)
            except requests.RequestException as e:
                removed_failed.append(net)
                print(f"  Warning: failed to remove {net}: {e}", file=sys.stderr)

        if removed_failed:
            print(f"  ⚠️ {len(removed_failed)}/{len(covered)} entries failed to remove — "
                  f"skipping {supernet} (would otherwise leave a wider block layered on top of "
                  f"still-live narrower entries)")
            merged_failed += 1
            _jlog(f"--merge-adjacent: SKIPPED {supernet}, {len(removed_failed)} deletes failed", syslog.LOG_WARNING)
            continue

        body = {"list": block_list, "address": str(supernet), "comment": f"MERGED ({len(covered)}x)"[:60]}
        try:
            r_put = requests.put(base_url, json=body, auth=auth, verify=False, timeout=(5, 15))
            if r_put.status_code in (200, 201) or "already" in r_put.text:
                print(f"  ✅ Merged {len(removed_ok)} entries into {supernet} "
                      f"(verified {len(removed_ok)}/{len(covered)} removed before adding)")
                _record_permanent_block(str(supernet), "subnet", f"merged from {len(covered)}x")
                merged_ok += 1
                _jlog(f"--merge-adjacent: merged {len(covered)}x into {supernet}")
            else:
                print(f"  ⚠️ Failed to add {supernet}: {r_put.status_code} {r_put.text}")
                merged_failed += 1
                _jlog(f"--merge-adjacent: PUT failed for {supernet}: HTTP {r_put.status_code}", syslog.LOG_WARNING)
        except requests.RequestException as e:
            print(f"  ⚠️ Exception adding {supernet}: {e}", file=sys.stderr)
            merged_failed += 1

    print(f"\n[OK] Aggregation complete: {merged_ok} merged, {merged_failed} skipped/failed.")


def sync_subnets_to_mikrotik(conn: sqlite3.Connection, subnets_to_block: list[tuple[str, int, int]]):
    """
    todo #9/#10: the two counts in the block message come from different
    systems on purpose — `unique_cnt`/`total_hits` are Suricata's all-time
    view from SQLite (seen_ips), independent of what MikroTik's address-list
    currently holds; `removed` is however many individual /32 entries this
    specific run actually deleted from MikroTik. They will not match in
    general — most of the "N IPs seen all-time" were never put on MikroTik as
    standalone entries (cooled-down hits, hits that never escalated past the
    per-IP threshold, etc.), so a smaller `removed` count is expected, not a
    bug. The message below labels both explicitly instead of just "N IPs".

    Subnets already present in `permanent_blocks` are skipped for the PUT
    (todo #10) — every prior run reprocessed every subnet meeting the
    threshold unconditionally, so a subnet blocked on day 1 kept getting a
    "🔒 Blocked subnet X" line (a no-op MikroTik "already have such entry")
    on every subsequent run, which read like it was being re-blocked from
    scratch. Redundant single-IP cleanup for that subnet still runs — new
    per-IP temporary blocks from alert-bridge.py's own 1h-timeout path can
    still land inside an already-blocked subnet's range between syncs.

    Fetches the live block list ONCE per address family (cached), not once
    per subnet: the prior version re-fetched the *entire* address-list for
    every subnet in the loop, so a run over N subnets meant N full-table GETs
    back to back — the likely cause of the "Read timed out" storm seen on a
    59-subnet run against a real router. Every failure mode is now counted
    in the closing summary — a query timeout used to only print a Warning
    line and vanish from the final tally, showing "0 failed" while the log
    above it was full of timeouts.
    """
    if requests is None:
        print("\nError: 'requests' library not installed. Install with: sudo apt install python3-requests", file=sys.stderr)
        return
    load_env()
    mt_host = os.environ.get("MT_HOST", "")
    mt_user = os.environ.get("MT_USER", "")
    mt_pass = os.environ.get("MT_PASS", "")
    block_list = os.environ.get("BLOCK_LIST", "suricata-block")
    if not mt_host or not mt_user or not mt_pass or "YOUR_" in mt_host or "YOUR_" in mt_pass:
        print("\nError: MikroTik credentials incomplete in /opt/alert-bridge/env:", file=sys.stderr)
        print(f"  MT_HOST = '{mt_host}'", file=sys.stderr)
        print(f"  MT_USER = '{mt_user}'", file=sys.stderr)
        print(f"  MT_PASS = {'(set)' if mt_pass and 'YOUR_' not in mt_pass else '(missing or unconfigured)'}", file=sys.stderr)
        print("Please edit /opt/alert-bridge/env with your router LAN IP and suricata API user password.", file=sys.stderr)
        return
    if not subnets_to_block:
        print("\nNo subnets matched the threshold to sync to MikroTik.")
        return

    already_blocked = _permanently_blocked_subnet_set(conn)
    auth = (mt_user, mt_pass)

    # Fetch the live block list once per family (ip / ipv6), cached — see
    # docstring. `None` in the cache means "fetch failed", distinct from an
    # empty (but successfully fetched) list.
    list_cache: dict[str, list | None] = {}

    def fetch_list_once(family: str) -> list | None:
        if family in list_cache:
            return list_cache[family]
        url = f"https://{mt_host}/rest/{family}/firewall/address-list"
        try:
            r = requests.get(f"{url}?list={block_list}", auth=auth, verify=False, timeout=(5, 20))
            if r.status_code == 200:
                data = r.json()
                list_cache[family] = data if isinstance(data, list) else []
            else:
                print(f"  Warning: failed to fetch MikroTik {family} block list: HTTP {r.status_code}", file=sys.stderr)
                list_cache[family] = None
        except requests.RequestException as e:
            print(f"  Warning: failed to fetch MikroTik {family} block list: {e}", file=sys.stderr)
            list_cache[family] = None
        return list_cache[family]

    print(f"\n🔄 Syncing {len(subnets_to_block)} subnets to MikroTik list '{block_list}' "
          f"({sum(1 for s, _, _ in subnets_to_block if s in already_blocked)} already permanently "
          f"blocked — hygiene-only pass for those)...")

    newly_blocked = 0
    skipped_already = 0
    failed = 0
    cleanup_delete_failed = 0
    cleanup_skipped_no_list = 0

    for subnet_str, unique_cnt, total_hits in subnets_to_block:
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
            family = "ipv6" if net.version == 6 else "ip"
        except ValueError:
            family = "ip"
            net = None

        base_url = f"https://{mt_host}/rest/{family}/firewall/address-list"

        # 1. Remove single IPs covered by this subnet, plus any dynamic entry for the subnet itself.
        #    Runs every time regardless of block state — alert-bridge.py's per-IP temp blocks can
        #    keep landing here even after the subnet itself is permanently blocked.
        removed = 0
        live_entries = fetch_list_once(family)
        if live_entries is None:
            cleanup_skipped_no_list += 1
        else:
            for entry in live_entries:
                addr = entry.get("address", "")
                entry_id = entry.get(".id")
                if not entry_id or not addr:
                    continue
                try:
                    addr_obj = ipaddress.ip_address(addr)
                    if net and addr_obj in net:
                        try:
                            r_del = requests.delete(f"{base_url}/{entry_id}", auth=auth, verify=False, timeout=(5, 10))
                            if r_del.status_code in (200, 204):
                                removed += 1
                                print(f"  🗑️ Removing redundant single IP {addr} (covered by {subnet_str})...", flush=True)
                            else:
                                cleanup_delete_failed += 1
                                print(f"  ⚠️ Failed to remove redundant IP {addr}: HTTP {r_del.status_code}", file=sys.stderr)
                        except requests.RequestException as e:
                            cleanup_delete_failed += 1
                            print(f"  Warning: failed to remove redundant IP {addr}: {e}", file=sys.stderr)
                except ValueError:
                    if addr == subnet_str and (entry.get("timeout") or entry.get("dynamic") == "true"):
                        try:
                            requests.delete(f"{base_url}/{entry_id}", auth=auth, verify=False, timeout=(5, 10))
                        except requests.RequestException as e:
                            cleanup_delete_failed += 1
                            print(f"  Warning: failed to remove stale dynamic entry for {subnet_str}: {e}", file=sys.stderr)

        # 2. Add permanent subnet block — skipped if already recorded (todo #10).
        if subnet_str in already_blocked:
            skipped_already += 1
            if removed:
                print(f"  ♻️ {subnet_str} вже заблоковано постійно — очищено {removed} застарілих /32 записів")
            _jlog(f"sync-mikrotik: {subnet_str} already blocked, cleaned {removed} stale /32 entries")
            continue

        body = {
            "list": block_list,
            "address": subnet_str,
            "comment": f"PERMANENT SUBNET ({unique_cnt} IPs, {total_hits} hits)"[:60],
        }
        try:
            r_put = requests.put(base_url, json=body, auth=auth, verify=False, timeout=(5, 15))
            if r_put.status_code in (200, 201) or "already" in r_put.text:
                extra = f"; {removed} MikroTik entries cleaned this run" if removed else ""
                print(f"  🔒 Blocked subnet {subnet_str} ({unique_cnt} IPs seen all-time, "
                      f"{total_hits} hits{extra})", flush=True)
                _record_permanent_block(subnet_str, "subnet", f"sync-mikrotik ({unique_cnt} IPs, {total_hits} hits)")
                newly_blocked += 1
                _jlog(f"sync-mikrotik: blocked {subnet_str} ({unique_cnt} IPs all-time, {total_hits} hits)")
            else:
                print(f"  ⚠️ Failed to block subnet {subnet_str}: {r_put.status_code} {r_put.text}", flush=True)
                failed += 1
                _jlog(f"sync-mikrotik: FAILED to block {subnet_str}: HTTP {r_put.status_code}", syslog.LOG_WARNING)
        except requests.RequestException as e:
            print(f"  ⚠️ Exception blocking subnet {subnet_str}: {e}", flush=True)
            failed += 1

    print(f"\n[OK] Sync complete: {newly_blocked} newly blocked, {skipped_already} already blocked "
          f"(hygiene only), {failed} block failed, {cleanup_delete_failed} cleanup-delete failed, "
          f"{cleanup_skipped_no_list} skipped cleanup (couldn't fetch list).")
    _jlog(f"sync-mikrotik complete: {newly_blocked} newly blocked, {skipped_already} already blocked, "
          f"{failed} block failed, {cleanup_delete_failed} cleanup-delete failed, "
          f"{cleanup_skipped_no_list} skipped cleanup")


# ── --messages: show what the service actually sent ────────────────────────
# Reuses alert-bridge.py's own report formatter so the printed text is
# byte-identical to what Telegram received, instead of a re-derived summary
# in analyze_stats.py's own (different) table format. slot_digests/
# daily_stats/spike_events already carry the structured data needed to
# reconstruct the original message; only service_events (lifecycle/
# reconcile/on-demand) stores literal text, since those have no other
# structured home.

_ALERT_BRIDGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert-bridge.py")


def _load_alert_bridge_module():
    """Lazy import of alert-bridge.py (hyphenated filename -> not import-able
    with a plain `import`) purely for its pure-formatting functions
    (_build_periodic_report_lines / _format_top_lines). No DB connection or
    network call happens at import time."""
    spec = importlib.util.spec_from_file_location("_alert_bridge_fmt", _ALERT_BRIDGE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _render_slot_row(mod, r: sqlite3.Row) -> str:
    header = f"📊 6-годинний дайджест нових загроз\nПеріод: {r['start_time']} - {r['end_time']} ({r['date']})"
    lines = mod._build_periodic_report_lines(
        header, r["total_alerts"], r["new_ips_count"], r["new_subnets_count"],
        r["avg_alerts_per_ip"], r["avg_alerts_per_subnet"],
        r["perm_ips_count"], r["perm_subnets_count"], r["single_ips_count"], r["single_ips_alerts"],
        json.loads(r["top_subnets_json"]), "6 годин",
        new_ips_list=json.loads(r["new_ips_json"]) if r["new_ips_json"] else [],
        new_subnets_list=json.loads(r["new_subnets_json"]) if r["new_subnets_json"] else [],
        perm_ips_list=json.loads(r["perm_ips_json"]) if r["perm_ips_json"] else [],
        perm_subnets_list=json.loads(r["perm_subnets_json"]) if r["perm_subnets_json"] else [],
        geo_counts=json.loads(r["geo_counts_json"]) if r["geo_counts_json"] else {},
        spamhaus_count=r["spamhaus_count"] or 0,
        geo_new_counts=json.loads(r["geo_new_counts_json"]) if r["geo_new_counts_json"] else {},
        spamhaus_new_count=r["spamhaus_new_count"] or 0,
    )
    return "\n".join(lines)


def _render_daily_row(mod, r: sqlite3.Row) -> str:
    header = f"🌅 Звіт за попередній день ({r['date']}) 📊"
    lines = mod._build_periodic_report_lines(
        header, r["total_alerts"], r["new_ips_count"], r["new_subnets_count"],
        r["avg_alerts_per_ip"], r["avg_alerts_per_subnet"],
        r["perm_ips_count"], r["perm_subnets_count"], r["single_ips_count"], r["single_ips_alerts"],
        json.loads(r["top_subnets_json"]), "добу",
        new_ips_list=json.loads(r["new_ips_json"]) if r["new_ips_json"] else [],
        new_subnets_list=json.loads(r["new_subnets_json"]) if r["new_subnets_json"] else [],
        perm_ips_list=json.loads(r["perm_ips_json"]) if r["perm_ips_json"] else [],
        perm_subnets_list=json.loads(r["perm_subnets_json"]) if r["perm_subnets_json"] else [],
        geo_counts=json.loads(r["geo_counts_json"]) if r["geo_counts_json"] else {},
        spamhaus_count=r["spamhaus_count"] or 0,
        geo_new_counts=json.loads(r["geo_new_counts_json"]) if r["geo_new_counts_json"] else {},
        spamhaus_new_count=r["spamhaus_new_count"] or 0,
    )
    return "\n".join(lines)


def _render_spike_row(mod, r: sqlite3.Row) -> str:
    # single_ips_count/single_ips_alerts were never persisted for spike_events
    # (send_spike_alert computes them from the live sliding window, not
    # stored) -- reconstruction is honest about that gap rather than
    # guessing.
    top = json.loads(r["top_subnets_json"])
    lines = [
        "🚨 АНОМАЛЬНИЙ СПЛЕСК АТАК (Spike Alert) ⚠️",
        f"Період: {r['start_time']} - {r['end_time']} (останні 5 хвилин)",
        "",
        f"• Всього алертів за 5 хв: {r['total_alerts']:,}",
        f"• Середня інтенсивність: {r['avg_rate_per_min']:,} алертів/хв",
        f"• Унікальних IP-атакуючих: {r['unique_ips']:,}",
        "",
    ]
    if top:
        lines += mod._format_top_lines(top)
        lines.append("")
    lines.append("(розбивка на поодинокі нові IP для спалахів не архівується окремо)")
    return "\n".join(lines)


_MESSAGE_KIND_QUERIES = {
    "slot": ("slot_digests", "date", "created_at", _render_slot_row),
    "daily": ("daily_stats", "date", "created_at", _render_daily_row),
    "spike": ("spike_events", "DATE(timestamp)", "timestamp", _render_spike_row),
}


def _local_to_utc_str(local_str: str) -> str:
    """User-supplied --from/--to are typed in the operator's own local wall-clock
    (everything else in this tool and in alert-bridge.py's report headers is
    displayed in local time) -- but created_at/timestamp/ts columns are SQLite
    CURRENT_TIMESTAMP, which is always UTC. Convert before comparing, or a
    server not running in UTC (e.g. Europe/Kyiv, UTC+3) silently shifts every
    --from/--to/--hours window by the zone offset."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            local_dt = datetime.strptime(local_str, fmt)
            break
        except ValueError:
            continue
    else:
        raise ValueError(f"unrecognized date/time: {local_str!r} (use 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM')")
    offset = datetime.now() - datetime.utcnow()  # local wall-clock minus UTC, ~current DST-aware offset
    return (local_dt - offset).strftime("%Y-%m-%d %H:%M:%S")


def _messages_window(hours: int | None, days: int | None, date: str | None,
                      dt_from: str | None, dt_to: str | None) -> tuple[str | None, str | None, str | None, str | None]:
    """Computes the two possible cutoffs callers need: a calendar-day floor/
    ceiling (for --days/--date, compared against the `date` column, which
    alert-bridge.py writes as a local calendar date) and a UTC timestamp
    floor/ceiling (for --hours/--from/--to, compared against created_at/
    timestamp/ts, which SQLite always stamps in UTC)."""
    day_from = day_to = None
    ts_from = ts_to = None
    if date:
        day_from = day_to = date
    if days is not None:
        day_from = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    if hours is not None:
        ts_from = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    if dt_from:
        ts_from = _local_to_utc_str(dt_from)
    if dt_to:
        ts_to = _local_to_utc_str(dt_to)
    return day_from, day_to, ts_from, ts_to


def _fetch_kind_rows(conn: sqlite3.Connection, table: str, day_col: str, ts_col: str,
                      day_from, day_to, ts_from, ts_to) -> list[sqlite3.Row]:
    clauses, params = [], []
    if day_from:
        clauses.append(f"{day_col} >= ?"); params.append(day_from)
    if day_to:
        clauses.append(f"{day_col} <= ?"); params.append(day_to)
    if ts_from:
        clauses.append(f"{ts_col} >= ?"); params.append(ts_from)
    if ts_to:
        clauses.append(f"{ts_col} <= ?"); params.append(ts_to)
    sql = f"SELECT * FROM {table}"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += f" ORDER BY {ts_col}"
    return list(conn.execute(sql, params))


def _fetch_service_rows(conn: sqlite3.Connection, day_from, day_to, ts_from, ts_to) -> list[sqlite3.Row]:
    clauses, params = [], []
    if day_from:
        clauses.append("DATE(ts) >= ?"); params.append(day_from)
    if day_to:
        clauses.append("DATE(ts) <= ?"); params.append(day_to)
    if ts_from:
        clauses.append("ts >= ?"); params.append(ts_from)
    if ts_to:
        clauses.append("ts <= ?"); params.append(ts_to)
    sql = "SELECT * FROM service_events"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY ts"
    try:
        return list(conn.execute(sql, params))
    except sqlite3.OperationalError:
        return []  # DB predates the service_events migration


def cmd_messages(conn: sqlite3.Connection, kind: str, hours: int | None, days: int | None,
                  date: str | None, dt_from: str | None, dt_to: str | None) -> None:
    day_from, day_to, ts_from, ts_to = _messages_window(hours, days, date, dt_from, dt_to)
    kinds = list(_MESSAGE_KIND_QUERIES) if kind == "all" else [kind] if kind != "service" else []
    entries: list[tuple[str, str, str, str]] = []  # (sort_ts, kind, meta, text)

    mod = _load_alert_bridge_module()
    for k in kinds:
        table, day_col, ts_col, renderer = _MESSAGE_KIND_QUERIES[k]
        for r in _fetch_kind_rows(conn, table, day_col, ts_col, day_from, day_to, ts_from, ts_to):
            sent = r["sent"] if "sent" in r.keys() else None
            meta = f"{k.upper()} | sent={'так' if sent else 'ні' if sent is not None else '?'}"
            entries.append((str(r[ts_col]), k, meta, renderer(mod, r)))

    if kind in ("all", "service"):
        for r in _fetch_service_rows(conn, day_from, day_to, ts_from, ts_to):
            meta = f"SERVICE/{r['kind']} | ts={r['ts']} | delivered={'так' if r['delivered'] else 'ні'}"
            entries.append((str(r["ts"]), "service", meta, r["text"]))

    entries.sort(key=lambda e: e[0])

    if not entries:
        print("Жодного архівованого повідомлення не знайдено за цими фільтрами.")
        return

    for sort_ts, k, meta, text in entries:
        print("=" * 78)
        print(f"[{meta}]")
        print("-" * 78)
        print(text)
    print("=" * 78)
    print(f"\nВсього повідомлень: {len(entries)}")
    _jlog(f"--messages kind={kind}: {len(entries)} message(s) shown")


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata alert-bridge SQLite statistics.")
    parser.add_argument("--sum", "--total", action="store_true", help="Summary across every recorded day")
    parser.add_argument("--day", metavar="YYYY-MM-DD", help="Full breakdown for one day")
    parser.add_argument("--spikes", action="store_true", help="Log of all anomaly spike alerts")
    parser.add_argument("--top", type=int, metavar="N", help="Top N attacker subnets and IPs all-time")
    parser.add_argument("--geo", action="store_true",
                        help="Breakdown of permanent geo/Spamhaus blocks by country "
                             "(kind LIKE 'geo-%%' OR kind='spamhaus'), separate from --sum/--top")
    parser.add_argument("--list", action="store_true",
                        help="With --sum/--day: also print actual new-IP/new-subnet/permanently-blocked "
                             f"addresses, not just counts (terminal preview capped at {LIST_PREVIEW_LIMIT}/group)")
    parser.add_argument("--list-out", metavar="FILE",
                        help="Write the FULL new-IP/new-subnet/permanently-blocked address lists to "
                             "FILE instead of truncating them in the terminal preview (implies --list, "
                             "with --sum/--day)")
    parser.add_argument("--min-ips", type=int, default=DEFAULT_MIN_IPS,
                        help=f"Min unique IPs per subnet for --sync-mikrotik "
                             f"(default: {DEFAULT_MIN_IPS}, from alert-bridge.cfg [blocking] subnet_threshold)")
    parser.add_argument("--sync-mikrotik", "--block-subnets", action="store_true",
                        help="Block /24 subnets with >= --min-ips unique IPs all-time on MikroTik")
    parser.add_argument("--merge-adjacent", action="store_true",
                        help="Remove single IPs covered by an existing subnet (any width), then "
                             "aggregate subnet entries at any level (/24+/24->/23, /23+/23->/22, ...)")
    parser.add_argument("--verify-blocks", action="store_true",
                        help="Cross-check permanent_blocks (SQLite) against the live MikroTik list — "
                             "reports anything recorded as permanently blocked but actually missing")
    parser.add_argument("--fix", action="store_true",
                        help="With --verify-blocks: re-add every genuinely-missing entry "
                             "(IPs and subnets alike) back onto the live MikroTik list")
    parser.add_argument("--messages", action="store_true",
                        help="Show archived sent messages (slot digests, daily reports, spike "
                             "alerts, service events) reconstructed in the exact text Telegram "
                             "received; combine with --kind/--hours/--days/--date/--from/--to")
    parser.add_argument("--kind", choices=["slot", "daily", "spike", "service", "all"], default="all",
                        help="With --messages: restrict to one message kind (default: all)")
    parser.add_argument("--hours", type=int, metavar="N",
                        help="With --messages: only messages sent in the last N hours")
    parser.add_argument("--days", type=int, metavar="N",
                        help="With --messages: only messages covering the last N calendar days")
    parser.add_argument("--date", metavar="YYYY-MM-DD",
                        help="With --messages: only messages covering this calendar date")
    parser.add_argument("--from", dest="dt_from", metavar="'YYYY-MM-DD[ HH:MM]'",
                        help="With --messages: explicit range start (sent-at timestamp)")
    parser.add_argument("--to", dest="dt_to", metavar="'YYYY-MM-DD[ HH:MM]'",
                        help="With --messages: explicit range end (sent-at timestamp)")
    args = parser.parse_args()
    if args.list_out and not args.list:
        args.list = True

    conn = connect_db()
    if conn is None:
        sys.exit(1)

    out_fh = None
    try:
        if args.list_out:
            out_fh = open(args.list_out, "w")
            print(f"Full address lists also being written to {args.list_out}")

        did_something = False
        if args.day:
            cmd_day(conn, args.day, show_list=args.list, out_fh=out_fh)
            did_something = True
        if args.spikes:
            cmd_spikes(conn)
            did_something = True
        if args.top:
            cmd_top(conn, args.top)
            did_something = True
        if args.geo:
            cmd_geo(conn)
            did_something = True
        if args.sync_mikrotik:
            subnets = aggregate_seen_subnets(conn, min_ips=args.min_ips)
            sync_subnets_to_mikrotik(conn, subnets)
            did_something = True
        if args.merge_adjacent:
            merge_adjacent_subnets()
            did_something = True
        if args.verify_blocks:
            cmd_verify_blocks(conn, fix=args.fix)
            did_something = True
        if args.messages:
            cmd_messages(conn, args.kind, args.hours, args.days, args.date, args.dt_from, args.dt_to)
            did_something = True
        if args.sum or not did_something:
            cmd_sum(conn, show_list=args.list, out_fh=out_fh)
    finally:
        conn.close()
        if out_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
