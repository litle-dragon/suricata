#!/usr/bin/env python3
"""Independent health watchdog for the Suricata/MikroTik IDS pipeline.

Runs standalone on a systemd timer (every 5 min, see
`suricata-healthcheck.timer`) and deliberately does **not** import
alert-bridge.py: a bug or crash in the main bridge must not also disable the
thing that's supposed to notice. `geo_lists.py` is imported for its config
parsing only (pure, side-effect-free at import time).

Checks, in order:

  1. systemd units `suricata`, `tzsp-receiver`, `tzsp0-iface`, `alert-bridge`
     are all `active`.
  2. MikroTik REST API reachable, and `/tool/sniffer` reports
     `running=true`.
  3. `tzsp0` interface packet counter is actually increasing. Catches a
     sniffer that reports `running=true` but isn't really streaming — wrong
     `streaming-server`, a mid-path firewall/routing change, etc. This is
     the failure mode behind the 2026-10-12 00:34-19:03 blackout: the
     MikroTik sniffer silently stopped sending with no service crash on
     either side and no log line to explain why; it only recovered because
     a router reboot at 19:03 re-ran the `start-sniffer` scheduler. Requires
     two consecutive zero-growth samples (~10 min of total silence) before
     alerting, and skips the verdict for one cycle right after a counter
     reset (router/interface reboot) instead of false-alarming.
  4. `eve.json` freshness — Suricata must have logged *some* event (not
     just alerts; flow/http/tls counts too) in the last 10 minutes. Catches
     Suricata itself wedging even while packets keep arriving.
  5. geo/Spamhaus list freshness — `update_geo_lists.py`'s daily cron
     actually ran within the last 48h.

State persisted in `healthcheck_state.json` next to this script, for
debounce: alert immediately on OK->FAIL, remind every `REMIND_INTERVAL_S`
while still failing, send exactly one recovery message on FAIL->OK.
"""

import json
import os
import subprocess
import sys
import time

import requests
from requests.auth import HTTPBasicAuth

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import geo_lists  # noqa: E402  (path insert must come first)

requests.packages.urllib3.disable_warnings()  # self-signed router cert, same as alert-bridge.py

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "healthcheck_state.json")
EVE_JSON = "/var/log/suricata/eve.json"
TZSP_IFACE = "tzsp0"
UNITS = ["suricata.service", "tzsp-receiver.service", "tzsp0-iface.service", "alert-bridge.service"]

EVE_STALE_S = 10 * 60
LIST_STALE_S = 48 * 3600
REMIND_INTERVAL_S = 30 * 60

TG_TOKEN = os.environ.get("TG_TOKEN", "")
TG_CHAT = os.environ.get("TG_CHAT", "")
TG_THREAD_ID = os.environ.get("TG_THREAD_ID", "")
MT_HOST = os.environ.get("MT_HOST", "")
MT_USER = os.environ.get("MT_USER", "")
MT_PASS = os.environ.get("MT_PASS", "")


def telegram_send(text: str) -> bool:
    """Same contract as alert-bridge.py's telegram_send(): True only on a
    confirmed HTTP 200."""
    if not TG_TOKEN or not TG_CHAT:
        print("telegram not configured, skipping send", flush=True)
        return False
    payload = {"chat_id": TG_CHAT, "text": text}
    if TG_THREAD_ID:
        try:
            payload["message_thread_id"] = int(TG_THREAD_ID)
        except ValueError:
            pass
    try:
        r = requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json=payload, timeout=10)
        if r.status_code != 200:
            print(f"telegram send failed: HTTP {r.status_code} {r.text}", flush=True)
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"telegram failed: {e}", flush=True)
        return False


def check_units() -> list[str]:
    failures = []
    for unit in UNITS:
        r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        state = r.stdout.strip()
        if state != "active":
            failures.append(f"systemd: {unit} is {state or 'unknown'} (expected active)")
    return failures


def check_mikrotik() -> list[str]:
    if not MT_HOST or not MT_USER:
        return ["mikrotik: MT_HOST/MT_USER not configured"]
    auth = HTTPBasicAuth(MT_USER, MT_PASS)
    try:
        r = requests.get(f"https://{MT_HOST}/rest/tool/sniffer", auth=auth, verify=False, timeout=(5, 10))
    except requests.RequestException as e:
        return [f"mikrotik: REST API unreachable ({e})"]
    if r.status_code != 200:
        return [f"mikrotik: REST API HTTP {r.status_code}"]
    running = r.json().get("running")
    if running != "true":
        return [f"mikrotik: /tool sniffer running={running!r} (expected 'true')"]
    return []


def check_tzsp0_traffic(state: dict) -> list[str]:
    path = f"/sys/class/net/{TZSP_IFACE}/statistics/tx_packets"
    try:
        with open(path) as f:
            current = int(f.read().strip())
    except OSError as e:
        return [f"tzsp0: cannot read counters ({e})"]

    now = time.time()
    prev = state.get("tzsp0_tx_packets")
    prev_ts = state.get("tzsp0_tx_ts")
    streak = state.get("tzsp0_zero_streak", 0)

    state["tzsp0_tx_packets"] = current
    state["tzsp0_tx_ts"] = now

    if prev is None or current < prev:
        # First run, or counter reset (interface/router reboot) — can't
        # judge a delta yet, don't false-alarm.
        state["tzsp0_zero_streak"] = 0
        return []

    delta = current - prev
    if delta > 0:
        state["tzsp0_zero_streak"] = 0
        return []

    streak += 1
    state["tzsp0_zero_streak"] = streak
    if streak >= 2:
        elapsed_min = int((now - prev_ts) / 60) if prev_ts else 0
        return [f"tzsp0: zero packets received for ~{elapsed_min} min — MikroTik stream likely dead "
                f"(router sniffer may report running=true but isn't actually sending)"]
    return []


def _tail_last_json_line(path: str, chunk: int = 16384) -> dict | None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    with open(path, "rb") as f:
        f.seek(max(0, size - chunk))
        data = f.read()
    for line in reversed(data.split(b"\n")):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def check_eve_json() -> list[str]:
    if not os.path.exists(EVE_JSON):
        return [f"eve.json: {EVE_JSON} does not exist"]
    last = _tail_last_json_line(EVE_JSON)
    if last is None:
        return ["eve.json: could not parse a trailing JSON line"]
    # mtime is tz-agnostic and simpler than parsing the timestamp field's
    # "+0300"-style offset; just as accurate for "did anything get written
    # recently".
    mtime_age_s = time.time() - os.path.getmtime(EVE_JSON)
    if mtime_age_s > EVE_STALE_S:
        return [f"eve.json: no new events written in {int(mtime_age_s / 60)} min "
                f"(last line timestamp={last.get('timestamp', '?')!r})"]
    return []


def check_geo_lists() -> list[str]:
    if not geo_lists.GEO_ENABLED:
        return []
    failures = []
    now = time.time()
    names = [f"geo_{cc}" for cc in geo_lists.COUNTRIES] + ["spamhaus"]
    for name in names:
        path = geo_lists.list_path(name)
        if not os.path.exists(path):
            failures.append(f"geo-lists: {path} missing")
            continue
        age_s = now - os.path.getmtime(path)
        if age_s > LIST_STALE_S:
            failures.append(f"geo-lists: {path} is {int(age_s / 3600)}h old "
                             f"(update_geo_lists.py cron may be broken)")
    return failures


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def main() -> int:
    state = load_state()

    failures: list[str] = []
    failures += check_units()
    failures += check_mikrotik()
    failures += check_tzsp0_traffic(state)
    failures += check_eve_json()
    failures += check_geo_lists()

    now = time.time()
    was_failing = state.get("status") == "fail"

    if failures:
        print("HEALTH CHECK FAILED:\n  " + "\n  ".join(failures), flush=True)
        should_notify = (not was_failing) or (now - state.get("last_alert", 0) >= REMIND_INTERVAL_S)
        if should_notify:
            since = state.get("since", now) if was_failing else now
            duration_min = int((now - since) / 60)
            header = "🔴 Suricata pipeline: NOT OK" if not was_failing else \
                f"🔴 Suricata pipeline: still NOT OK ({duration_min} min)"
            text = header + "\n\n" + "\n".join(f"• {f}" for f in failures)
            if telegram_send(text):
                state["last_alert"] = now
        if not was_failing:
            state["since"] = now
        state["status"] = "fail"
    else:
        print("health check OK", flush=True)
        if was_failing:
            since = state.get("since", now)
            duration_min = int((now - since) / 60)
            telegram_send(f"✅ Suricata pipeline: back to OK (was down ~{duration_min} min)")
        state["status"] = "ok"
        state.pop("since", None)
        state.pop("last_alert", None)

    save_state(state)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
