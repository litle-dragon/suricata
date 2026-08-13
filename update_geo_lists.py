#!/usr/bin/env python3
"""Fetch iwik.org GeoIP country ranges and the Spamhaus DROP list, write them
as Suricata IP Reputation (iprep) source files, and trigger a live reload --
no Suricata restart (docs/adr/0003-ip-reputation-not-datasets-for-geo-spamhaus-cidr-matching.md).

Suricata `dataset type: ip` is exact-match only and rejects CIDR entries
(confirmed on a live 7.0.3 box -- see ADR-0003, which supersedes ADR-0001's
original "load as a dataset" design). IP Reputation's reputation-file format
natively supports CIDR, so that's what Suricata now loads:

  /etc/suricata/iprep/categories.txt              -- <id>,<short name>,<description>
  /etc/suricata/iprep/geo-spamhaus-reputation.list -- <cidr>,<category id>,<score>

Separately, this script keeps writing the same plain per-source `.lst` files
as before (one CIDR per line) under `local_lists_dir` -- these are NOT read
by Suricata anymore; they're alert-bridge.py's own private copy for its local
"covering range" lookup (geo_lists.py), since iprep -- like the dataset
approach before it -- only tells the demon THAT an IP matched a category, not
WHICH CIDR.

Same style as parse_rules_ips.py / sync_rules_to_mikrotik.py: argparse,
syslog logging via _jlog, config read from alert-bridge.cfg, atomic write
(tmp file + os.replace).

Sources:
  https://www.iwik.org/ipcountry/geoip.txt   -- "<CIDR> <CC>" per line, IPv4+IPv6 mixed
  https://www.spamhaus.org/drop/drop.txt     -- "<CIDR> ; SBLxxxxx" per line, IPv4 only

On a fetch/parse failure for either source, the existing on-disk `.lst` for
that source is left untouched (keep-old-on-failure) and a warning goes to
both syslog and Telegram -- a transient outage must never wipe out
yesterday's working block-list. categories.txt + geo-spamhaus-reputation.list
are always rebuilt from whatever is CURRENTLY on disk under local_lists_dir
after that -- so a partial fetch failure still produces a complete,
internally-consistent reputation file (yesterday's data for the failed
source, today's for the rest).

Usage:
  python3 update_geo_lists.py                 # fetch, write, reload, notify
  python3 update_geo_lists.py --dry-run        # fetch + parse only, no writes/reload/notify
"""

import argparse
import configparser
import ipaddress
import os
import subprocess
import sys
import syslog
import tempfile
import urllib.error
import urllib.request
from collections import defaultdict

syslog.openlog(ident="update_geo_lists", logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

CFG_FILE = os.environ.get("CFG_FILE", "/opt/alert-bridge/alert-bridge.cfg")
ENV_FILE = os.environ.get("ENV_FILE", "/opt/alert-bridge/env")

_cfg = configparser.ConfigParser()
if os.path.exists(CFG_FILE):
    _cfg.read(CFG_FILE)

COUNTRIES = [
    cc.strip().upper()
    for cc in _cfg.get("geo_spamhaus", "countries", fallback="RU,BY,CN,KP,IR").split(",")
    if cc.strip()
]
LOCAL_LISTS_DIR = _cfg.get("geo_spamhaus", "local_lists_dir", fallback="/var/lib/suricata/datasets")
IPREP_DIR = _cfg.get("geo_spamhaus", "iprep_dir", fallback="/etc/suricata/iprep")

IWIK_URL = "https://www.iwik.org/ipcountry/geoip.txt"
SPAMHAUS_URL = "https://www.spamhaus.org/drop/drop.txt"
FETCH_TIMEOUT = 30


def _jlog(msg: str, level: int = syslog.LOG_INFO) -> None:
    """Mirror to the journal — run via cron, not a systemd service, so stdout
    is not captured by journald automatically."""
    try:
        syslog.syslog(level, msg)
    except Exception:
        pass


def _load_tg_env() -> tuple[str, str, str]:
    """Reads TG_TOKEN/TG_CHAT/TG_THREAD_ID from ENV_FILE. Independent, tiny
    duplicate of the same 5 lines every helper script in this repo has —
    these scripts deliberately don't import alert-bridge.py (see plan)."""
    values = {"TG_TOKEN": "", "TG_CHAT": "", "TG_THREAD_ID": ""}
    if not os.path.exists(ENV_FILE):
        return values["TG_TOKEN"], values["TG_CHAT"], values["TG_THREAD_ID"]
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                if key.strip() in values:
                    values[key.strip()] = val.strip()
    except OSError as e:
        print(f"Warning: failed to read {ENV_FILE}: {e}", file=sys.stderr)
    return values["TG_TOKEN"], values["TG_CHAT"], values["TG_THREAD_ID"]


def telegram_send(text: str) -> bool:
    tg_token, tg_chat, tg_thread_id = _load_tg_env()
    if not tg_token or not tg_chat:
        return False
    try:
        import json as _json

        payload = {"chat_id": tg_chat, "text": text}
        if tg_thread_id:
            try:
                payload["message_thread_id"] = int(tg_thread_id)
            except ValueError:
                pass
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{tg_token}/sendMessage",
            data=_json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception as e:
        print(f"telegram send failed: {e}", file=sys.stderr)
        return False


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "update_geo_lists/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return r.read().decode("utf-8", errors="replace")


def parse_iwik(text: str, countries: list[str]) -> dict[str, list[str]]:
    """Filters iwik.org geoip.txt ("<CIDR> <CC>" per line) down to `countries`.
    Returns {country_code: [cidr, ...]}. IPv6 lines and comment lines (#...)
    are skipped -- geo/Spamhaus blocking is IPv4-only (CONTEXT.md "Діапазон")."""
    wanted = set(countries)
    result: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        cidr, cc = parts
        if cc not in wanted:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        result[cc].append(str(net))
    return result


def parse_spamhaus(text: str) -> list[str]:
    """Parses spamhaus.org/drop/drop.txt ("<CIDR> ; SBLxxxxx" per line) into a
    flat CIDR list. Comment lines (;...) are skipped."""
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";", 1)[0].strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        result.append(str(net))
    return result


def atomic_write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _read_lst(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def build_category_map(countries: list[str]) -> dict[str, int]:
    """Category short name -> numeric id (1..60, iprep's hard-coded ceiling).
    Stable ordering: countries in configured order, SPAMHAUS always last --
    used by both categories.txt and geo-spamhaus-reputation.list, so the two
    files are generated from the same mapping and can never drift apart."""
    mapping = {f"GEO-{cc}": i + 1 for i, cc in enumerate(countries)}
    mapping["SPAMHAUS"] = len(countries) + 1
    return mapping


def write_iprep_files(countries: list[str]) -> tuple[int, int]:
    """Rebuilds categories.txt + the merged reputation list from whatever is
    CURRENTLY on disk under local_lists_dir (per-source .lst files) -- so a
    partial fetch failure (keep-old-on-failure above) still produces a
    complete, internally-consistent reputation file, using yesterday's data
    for the failed source(s) and today's for the rest.
    Returns (category_count, reputation_entry_count)."""
    cat_map = build_category_map(countries)
    cat_lines = [
        f"{cid},{name},Geo/Spamhaus block category {name}"
        for name, cid in sorted(cat_map.items(), key=lambda kv: kv[1])
    ]
    atomic_write_lines(os.path.join(IPREP_DIR, "categories.txt"), cat_lines)

    rep_lines = []
    for cc in countries:
        cid = cat_map[f"GEO-{cc}"]
        for cidr in _read_lst(os.path.join(LOCAL_LISTS_DIR, f"geo_{cc.lower()}.lst")):
            rep_lines.append(f"{cidr},{cid},127")
    sh_id = cat_map["SPAMHAUS"]
    for cidr in _read_lst(os.path.join(LOCAL_LISTS_DIR, "spamhaus.lst")):
        rep_lines.append(f"{cidr},{sh_id},127")
    atomic_write_lines(os.path.join(IPREP_DIR, "geo-spamhaus-reputation.list"), rep_lines)

    _jlog(f"wrote iprep categories.txt ({len(cat_lines)} categories) + "
          f"geo-spamhaus-reputation.list ({len(rep_lines)} entries)")
    return len(cat_lines), len(rep_lines)


def reload_suricata() -> bool:
    """Live reload via suricatasc -- reloads both rules and IP Reputation data
    (categories.txt is the one exception: per Suricata docs it requires a
    restart if its content changes, which it only does when `countries`
    itself changes in alert-bridge.cfg, a rare manual edit). No Suricata
    restart needed for the day-to-day CIDR list refresh."""
    try:
        r = subprocess.run(
            ["suricatasc", "-c", "reload-rules"],
            capture_output=True, text=True, timeout=30,
        )
        ok = r.returncode == 0
        _jlog(f"suricatasc reload-rules: rc={r.returncode} out={r.stdout.strip()!r}")
        return ok
    except (OSError, subprocess.SubprocessError) as e:
        _jlog(f"suricatasc reload-rules failed: {e}", level=syslog.LOG_WARNING)
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                     help="Fetch and parse only -- print counts, write nothing, "
                          "trigger no reload, send no Telegram message")
    args = ap.parse_args()

    failures: list[str] = []
    geo_by_cc: dict[str, list[str]] = {}
    spamhaus_cidrs: list[str] = []

    try:
        iwik_text = _fetch(IWIK_URL)
        geo_by_cc = parse_iwik(iwik_text, COUNTRIES)
        for cc in COUNTRIES:
            if not geo_by_cc.get(cc):
                _jlog(f"iwik fetch: 0 CIDRs parsed for {cc} -- suspicious, treating as fetch failure",
                      level=syslog.LOG_WARNING)
                failures.append(f"geoip({cc})")
    except (urllib.error.URLError, OSError) as e:
        _jlog(f"iwik fetch failed: {e}", level=syslog.LOG_WARNING)
        failures.append("geoip(fetch)")

    try:
        spamhaus_text = _fetch(SPAMHAUS_URL)
        spamhaus_cidrs = parse_spamhaus(spamhaus_text)
        if not spamhaus_cidrs:
            _jlog("spamhaus fetch: 0 CIDRs parsed -- suspicious, treating as fetch failure",
                  level=syslog.LOG_WARNING)
            failures.append("spamhaus")
    except (urllib.error.URLError, OSError) as e:
        _jlog(f"spamhaus fetch failed: {e}", level=syslog.LOG_WARNING)
        failures.append("spamhaus")

    print(f"iwik: {sum(len(v) for v in geo_by_cc.values())} CIDRs across {len(geo_by_cc)}/{len(COUNTRIES)} "
          f"countries; spamhaus: {len(spamhaus_cidrs)} CIDRs; failures={failures or 'none'}")
    for cc in COUNTRIES:
        print(f"  {cc}: {len(geo_by_cc.get(cc, []))} CIDRs")

    if args.dry_run:
        print("--dry-run: no files written, no reload triggered, no Telegram sent")
        return 1 if failures else 0

    if failures:
        msg = f"⚠️ update_geo_lists: {', '.join(failures)} fetch failed, keeping yesterday's list(s)"
        telegram_send(msg)
        _jlog(msg, level=syslog.LOG_WARNING)
        # Partial success still writes whatever sources succeeded -- a Spamhaus
        # outage must not also block today's geo update, and vice versa.

    wrote_any = False
    for cc in COUNTRIES:
        if cc not in geo_by_cc or not geo_by_cc[cc]:
            continue  # this source failed above -- leave existing file untouched
        path = os.path.join(LOCAL_LISTS_DIR, f"geo_{cc.lower()}.lst")
        atomic_write_lines(path, sorted(geo_by_cc[cc]))
        wrote_any = True
        _jlog(f"wrote {path}: {len(geo_by_cc[cc])} CIDRs")

    if spamhaus_cidrs:
        path = os.path.join(LOCAL_LISTS_DIR, "spamhaus.lst")
        atomic_write_lines(path, sorted(spamhaus_cidrs))
        wrote_any = True
        _jlog(f"wrote {path}: {len(spamhaus_cidrs)} CIDRs")

    # Always rebuild the iprep files from current on-disk .lst state, even on
    # a total fetch failure (e.g. first-ever run failing) -- reproduces
    # whatever categories.txt/reputation.list existed before, or an empty-but-
    # valid pair on a truly first run, rather than leaving Suricata's iprep
    # config pointing at files that don't exist yet.
    cat_count, rep_count = write_iprep_files(COUNTRIES)

    if wrote_any:
        reload_ok = reload_suricata()
        summary_parts = [f"{cc}={len(geo_by_cc.get(cc, []))}" for cc in COUNTRIES]
        summary = (
            f"✅ update_geo_lists: geo[{', '.join(summary_parts)}], spamhaus={len(spamhaus_cidrs)} CIDRs, "
            f"iprep {cat_count} categories / {rep_count} entries"
            f"{'' if reload_ok else ' (reload-rules FAILED, restart suricata manually)'}"
        )
        telegram_send(summary)
        _jlog(summary)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
