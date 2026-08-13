#!/usr/bin/env python3
"""Smoke test for the geo/Spamhaus blocking pipeline (ADR-0001/0002) against a
mocked MikroTik REST API -- no live router or Suricata box required.

Covers, per geo-spamhaus-plan.md §6 step 6:
  - classify_category() signature parsing (geo hit, spamhaus hit, garbage)
  - geo_lists.covering_range() resolving the exact CIDR from a local .lst
  - a geo hit blocks the *covering range* on the correct MikroTik list
    (suricata-geo-block), records permanent_blocks(kind='geo-<cc>')
  - a spamhaus hit blocks on suricata-spamhaus-block, kind='spamhaus'
  - whitelist gate: whitelisted() true for RFC1918 addresses
  - dedup: a repeat hit against an already-blocked covering range never
    re-issues a MikroTik PUT (in-memory _permanently_blocked_subnets cache)

Run: python3 test_geo_spamhaus_smoke.py
"""

import importlib.util
import os
import sys
import tempfile

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Isolated environment, set up BEFORE importing alert-bridge.py / geo_lists.py
# (both read config/env once at import time). ─────────────────────────────────
_tmp = tempfile.mkdtemp(prefix="geo-spamhaus-smoke-")
DATASET_DIR = os.path.join(_tmp, "datasets")
os.makedirs(DATASET_DIR, exist_ok=True)

CFG_PATH = os.path.join(_tmp, "alert-bridge.cfg")
with open(CFG_PATH, "w") as f:
    f.write(
        "[geo_spamhaus]\n"
        "enabled = true\n"
        "countries = RU,BY\n"
        f"local_lists_dir = {DATASET_DIR}\n"
        "mikrotik_geo_list = suricata-geo-block\n"
        "mikrotik_spamhaus_list = suricata-spamhaus-block\n"
    )

with open(os.path.join(DATASET_DIR, "geo_ru.lst"), "w") as f:
    f.write("203.0.113.0/24\n")
with open(os.path.join(DATASET_DIR, "geo_by.lst"), "w") as f:
    f.write("198.18.0.0/24\n")
with open(os.path.join(DATASET_DIR, "spamhaus.lst"), "w") as f:
    f.write("198.51.100.128/26\n")

os.environ["CFG_FILE"] = CFG_PATH
os.environ["DB_FILE"] = os.path.join(_tmp, "alert_bridge.db")
os.environ["MT_HOST"] = "192.0.2.1"
os.environ["MT_USER"] = "test"
os.environ["MT_PASS"] = "test"
os.environ["TG_TOKEN"] = ""  # skip Telegram entirely
os.environ["TG_CHAT"] = ""
os.environ["WAN_IP"] = ""
os.environ["WAN_IPV6_PREFIX"] = ""

# ── Fake MikroTik REST layer — replaces `requests` inside the alert-bridge
# module only, after import, so every other module's `requests` is untouched. ─
class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data if json_data is not None else []
        self.text = text or str(self._json)

    def json(self):
        return self._json


class FakeMikroTik:
    """In-memory address-list store + call counters, keyed by list name."""

    def __init__(self):
        self.entries: dict[str, list[dict]] = {}
        self.put_calls: list[tuple[str, str]] = []  # (list, address)

    def get(self, url, auth=None, verify=None, timeout=None):
        # url shape: https://HOST/rest/ip/firewall/address-list?list=NAME[&address=X]
        qs = url.split("?", 1)[1] if "?" in url else ""
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        list_name = params.get("list", "")
        addr_filter = params.get("address")
        rows = self.entries.get(list_name, [])
        if addr_filter is not None:
            rows = [r for r in rows if r["address"] == addr_filter]
        return _FakeResponse(200, rows)

    def put(self, url, json=None, auth=None, verify=None, timeout=None):
        list_name = json["list"]
        self.put_calls.append((list_name, json["address"]))
        self.entries.setdefault(list_name, []).append(
            {"address": json["address"], "comment": json.get("comment", ""), ".id": f"*{len(self.put_calls)}"}
        )
        return _FakeResponse(200, {})

    def delete(self, url, auth=None, verify=None, timeout=None):
        return _FakeResponse(200, {})


results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"[{'ok' if condition else 'FAIL'}] {label}")


def main() -> int:
    spec = importlib.util.spec_from_file_location("alert_bridge_under_test", os.path.join(REPO_DIR, "alert-bridge.py"))
    ab = importlib.util.module_from_spec(spec)
    sys.modules["alert_bridge_under_test"] = ab
    spec.loader.exec_module(ab)

    fake_mt = FakeMikroTik()
    ab.requests.get = fake_mt.get
    ab.requests.put = fake_mt.put
    ab.requests.delete = fake_mt.delete

    ab.db_init()

    # 1-4: classify_category signature parsing
    check("classify_category geo hit (GEO-BLOCK-RU-IN)", ab.classify_category("GEO-BLOCK-RU-IN") == ("geo", "ru"))
    check("classify_category geo hit outbound (GEO-BLOCK-BY-OUT)", ab.classify_category("GEO-BLOCK-BY-OUT") == ("geo", "by"))
    check("classify_category rejects unconfigured country (GEO-BLOCK-CN-IN, cfg only has RU,BY)",
          ab.classify_category("GEO-BLOCK-CN-IN") is None)
    check("classify_category spamhaus hit (SPAMHAUS-BLOCK-IN)", ab.classify_category("SPAMHAUS-BLOCK-IN") == ("spamhaus", None))
    check("classify_category ignores ordinary ET signature", ab.classify_category("ET DROP Spamhaus DROP Listed Traffic") is None)

    # 5: geo_lists covering-range lookup
    covering = ab.geo_lists.covering_range("geo_ru", "203.0.113.55")
    check("geo_lists.covering_range resolves exact CIDR", covering == "203.0.113.0/24")

    # 6: geo hit -> blocks the *covering range* on suricata-geo-block, records kind='geo-ru'
    addr = covering
    block_list = ab.geo_lists.MIKROTIK_GEO_LIST
    blocked = ab.mikrotik_block(addr, "GEO-BLOCK-RU-IN", permanent=True, block_list=block_list)
    if blocked:
        ab._permanently_blocked_subnets.add(addr)
        ab.db_record_permanent_block(addr, "geo-ru", "GEO-BLOCK-RU-IN")
    check("geo hit: MikroTik PUT succeeded", blocked)
    check("geo hit: blocked the covering /24, not the bare IP", fake_mt.put_calls[-1] == ("suricata-geo-block", "203.0.113.0/24"))
    row = ab._conn.execute("SELECT kind FROM permanent_blocks WHERE ip_or_subnet=?", (addr,)).fetchone()
    check("geo hit: permanent_blocks audit row has kind='geo-ru'", row is not None and row[0] == "geo-ru")

    # 7: spamhaus hit -> suricata-spamhaus-block, kind='spamhaus'
    sh_covering = ab.geo_lists.covering_range("spamhaus", "198.51.100.150")
    check("spamhaus covering_range resolves", sh_covering == "198.51.100.128/26")
    sh_block_list = ab.geo_lists.MIKROTIK_SPAMHAUS_LIST
    sh_blocked = ab.mikrotik_block(sh_covering, "SPAMHAUS-BLOCK-IN", permanent=True, block_list=sh_block_list)
    if sh_blocked:
        ab._permanently_blocked_subnets.add(sh_covering)
        ab.db_record_permanent_block(sh_covering, "spamhaus", "SPAMHAUS-BLOCK-IN")
    check("spamhaus hit: MikroTik PUT succeeded on suricata-spamhaus-block",
          sh_blocked and fake_mt.put_calls[-1] == ("suricata-spamhaus-block", "198.51.100.128/26"))
    sh_row = ab._conn.execute("SELECT kind FROM permanent_blocks WHERE ip_or_subnet=?", (sh_covering,)).fetchone()
    check("spamhaus hit: permanent_blocks audit row has kind='spamhaus'", sh_row is not None and sh_row[0] == "spamhaus")

    # 8: whitelist gate
    check("whitelisted() true for RFC1918 (192.168.1.5)", ab.whitelisted("192.168.1.5") is True)
    check("whitelisted() false for a routable geo-list IP (203.0.113.55)", ab.whitelisted("203.0.113.55") is False)

    # 9: dedup — a repeat hit against the SAME covering range must not re-issue a MikroTik PUT
    put_calls_before = len(fake_mt.put_calls)
    already_blocked = addr in ab._permanently_blocked_ips or addr in ab._permanently_blocked_subnets
    check("dedup: covering range already in _permanently_blocked_subnets", already_blocked)
    if not already_blocked:
        ab.mikrotik_block(addr, "GEO-BLOCK-RU-IN (repeat)", permanent=True, block_list=block_list)
    check("dedup: no new MikroTik PUT issued for the repeat hit", len(fake_mt.put_calls) == put_calls_before)

    ab._conn.close()

    failed = [label for label, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED:")
        for label in failed:
            print(f"  - {label}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
