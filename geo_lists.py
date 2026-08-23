#!/usr/bin/env python3
"""Local "covering range" lookup for the geo/Spamhaus block-lists — imported by
alert-bridge.py, not run standalone in production.

Suricata's IP Reputation (iprep) is a category+score check: an alert tells us
the attacker IP matched *some* entry in a category (e.g. GEO-RU), but not
which CIDR (see PROJECT_HISTORY.md, ADR-0003,
which supersedes ADR-0001's original dataset-based design — Suricata
`dataset type: ip` turned out to be exact-match only, rejecting CIDR entries).
This module reads the same flat `.lst` files update_geo_lists.py writes (one
CIDR per line, IPv4-only per CONTEXT.md "Діапазон") — Suricata itself no
longer reads these directly, they're this module's own private copy — and
does its own O(log n) bisect lookup to find the exact covering CIDR before
the demon blocks it on MikroTik.

Files are re-parsed only when their mtime changes (update_geo_lists.py
replaces them atomically once a day) — not on every alert.

Run standalone (`python3 geo_lists.py`) for a self-test against a synthetic
list.
"""

import bisect
import configparser
import ipaddress
import os

CFG_FILE = os.environ.get("CFG_FILE", "/opt/alert-bridge/alert-bridge.cfg")

_cfg = configparser.ConfigParser()
if os.path.exists(CFG_FILE):
    _cfg.read(CFG_FILE)

GEO_ENABLED = _cfg.getboolean("geo_spamhaus", "enabled", fallback=True)
COUNTRIES = [
    cc.strip().lower()
    for cc in _cfg.get("geo_spamhaus", "countries", fallback="RU,BY,CN,KP,IR").split(",")
    if cc.strip()
]
LOCAL_LISTS_DIR = _cfg.get("geo_spamhaus", "local_lists_dir", fallback="/var/lib/suricata/datasets")
MIKROTIK_GEO_LIST = _cfg.get("geo_spamhaus", "mikrotik_geo_list", fallback="suricata-geo-block")
MIKROTIK_SPAMHAUS_LIST = _cfg.get("geo_spamhaus", "mikrotik_spamhaus_list", fallback="suricata-spamhaus-block")

# list_name -> (mtime, sorted [(start_int, end_int, cidr_str), ...] by start_int)
_cache: dict[str, tuple[float, list[tuple[int, int, str]]]] = {}


def list_path(list_name: str) -> str:
    return os.path.join(LOCAL_LISTS_DIR, f"{list_name}.lst")


def _parse_lst(path: str) -> list[tuple[int, int, str]]:
    ranges = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.version != 4:  # IPv4-only for geo/Spamhaus blocking (CONTEXT.md)
                continue
            ranges.append((int(net.network_address), int(net.broadcast_address), str(net)))
    ranges.sort(key=lambda r: r[0])
    return ranges


def _load_ranges(list_name: str) -> list[tuple[int, int, str]]:
    path = list_path(list_name)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return []
    cached = _cache.get(list_name)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        ranges = _parse_lst(path)
    except OSError:
        return cached[1] if cached else []
    _cache[list_name] = (mtime, ranges)
    return ranges


def covering_range(list_name: str, ip: str) -> str | None:
    """Returns the exact CIDR from `<LOCAL_LISTS_DIR>/<list_name>.lst` that covers
    `ip`, or None if the list is missing/empty or genuinely doesn't cover it
    (local copy drifted from what Suricata's IP Reputation data matched
    against — caller falls back to blocking the bare IP)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if ip_obj.version != 4:
        return None
    ranges = _load_ranges(list_name)
    if not ranges:
        return None
    starts = [r[0] for r in ranges]
    idx = bisect.bisect_right(starts, int(ip_obj)) - 1
    if idx < 0:
        return None
    start, end, cidr = ranges[idx]
    return cidr if start <= int(ip_obj) <= end else None


def _self_test() -> bool:
    """Synthetic .lst, no filesystem/network dependency beyond a tmp dir."""
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        global LOCAL_LISTS_DIR
        LOCAL_LISTS_DIR = tmp
        _cache.clear()
        with open(list_path("geo_test"), "w") as f:
            f.write("# comment line, must be skipped\n")
            f.write("203.0.113.0/24\n")
            f.write("198.51.100.128/26\n")
            f.write("2001:db8::/32\n")  # IPv6 — must be filtered out

        cases = [
            ("203.0.113.42", "203.0.113.0/24"),      # inside first range
            ("203.0.113.255", "203.0.113.0/24"),     # last address of range
            ("198.51.100.130", "198.51.100.128/26"), # inside second, narrower range
            ("198.51.100.64", None),                 # outside both ranges
            ("8.8.8.8", None),                        # far outside
            ("2001:db8::1", None),                    # IPv6 — never matched
        ]
        for ip, expected in cases:
            got = covering_range("geo_test", ip)
            status = "ok" if got == expected else "FAIL"
            if got != expected:
                ok = False
            print(f"[{status}] covering_range('geo_test', {ip!r}) = {got!r} (expected {expected!r})")

        # mtime-triggered reload: append a new range, refresh the file's mtime,
        # and confirm the previously-uncovered IP is now found.
        with open(list_path("geo_test"), "a") as f:
            f.write("198.51.100.0/25\n")
        os.utime(list_path("geo_test"), None)
        got = covering_range("geo_test", "198.51.100.64")
        expected = "198.51.100.0/25"
        status = "ok" if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"[{status}] reload-after-mtime-change covering_range('geo_test', '198.51.100.64') = "
              f"{got!r} (expected {expected!r})")

        missing = covering_range("geo_does_not_exist", "1.2.3.4")
        status = "ok" if missing is None else "FAIL"
        if missing is not None:
            ok = False
        print(f"[{status}] covering_range on missing list file = {missing!r} (expected None)")

    return ok


if __name__ == "__main__":
    print(f"geo_lists self-test — COUNTRIES={COUNTRIES}, LOCAL_LISTS_DIR={LOCAL_LISTS_DIR}")
    passed = _self_test()
    print("SELF-TEST PASSED" if passed else "SELF-TEST FAILED")
    raise SystemExit(0 if passed else 1)
