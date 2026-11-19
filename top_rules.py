#!/usr/bin/env python3
"""Top alert signatures from Suricata's eve.json (read-only tuning aid).

Scans the live `eve.json` plus its rotated `.gz` siblings, keeps only
`event_type == "alert"` lines and counts `alert.signature`. Answers the two
tuning questions the DB cannot: which few signatures produce most of the
noise, and which never fire at all.

Lines are matched with one compiled regex pass instead of a `json.loads` per
line: eve.json reaches ~1.5 GB/day here and a full parse takes minutes, while
the regex pass over the same file takes seconds. The signature string is
still JSON-unescaped (`json.loads` on the matched token only).

Deliberately does not touch `alert_bridge.db` (its `hit_log` has no signature
column), the MikroTik router or Telegram: it is a report, not an event.

Usage:
  top_rules.py                      # all lines in eve.json + all rotations
  top_rules.py --day 2026-11-18     # only that day (by timestamp field)
  top_rules.py --top 25 --files '/var/log/suricata/eve.json*'
"""

import argparse
import glob
import gzip
import json
import os
import re
import sys
from collections import Counter

LOG_DIR = "/var/log/suricata"
SIG_MAX = 110

ALERT_MARK = b'"event_type":"alert"'
SIG_RE = re.compile(rb'"signature":"((?:[^"\\]|\\.)*)"')


def default_files() -> list[str]:
    pattern = os.path.join(LOG_DIR, "eve.json")
    files = [pattern] + sorted(glob.glob(pattern + ".*.gz"))
    return [f for f in files if os.path.exists(f)]


def expand(patterns: list[str]) -> list[str]:
    files: list[str] = []
    for p in patterns:
        if any(ch in p for ch in "*?["):
            files.extend(sorted(glob.glob(p)))
        elif os.path.exists(p):
            files.append(p)
        else:
            print(f"warning: no such file: {p}", file=sys.stderr)
    return files


def iter_lines(path: str):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rb") as fh:
            for line in fh:
                yield line
    except OSError as exc:
        print(f"warning: {path}: {exc}", file=sys.stderr)


def count_signatures(files: list[str], day: str | None) -> tuple[Counter, int, int]:
    counts: Counter = Counter()
    alerts = 0
    no_sig = 0
    day_mark = f'"timestamp":"{day}'.encode() if day else None
    for path in files:
        for line in iter_lines(path):
            if ALERT_MARK not in line:
                continue
            if day_mark is not None and day_mark not in line[:64]:
                continue
            m = SIG_RE.search(line)
            if m is None:
                no_sig += 1
                continue
            try:
                sig = json.loads(b'"' + m.group(1) + b'"')
            except json.JSONDecodeError:
                sig = m.group(1).decode("utf-8", "replace")
            counts[sig] += 1
            alerts += 1
    return counts, alerts, no_sig


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--day", metavar="YYYY-MM-DD", help="only events of that day")
    ap.add_argument("--top", type=int, default=10, help="how many rows to print (default 10)")
    ap.add_argument("--files", nargs="+", metavar="PATH", help="explicit files/globs")
    args = ap.parse_args()

    files = expand(args.files) if args.files else default_files()
    if not files:
        print("no eve.json files found", file=sys.stderr)
        return 2

    counts, alerts, no_sig = count_signatures(files, args.day)
    if not alerts:
        print(f"no alerts found in {len(files)} file(s)"
              + (f" for {args.day}" if args.day else ""))
        return 0

    width = len(str(counts.most_common(1)[0][1]))
    for sig, n in counts.most_common(max(1, args.top)):
        shown = sig if len(sig) <= SIG_MAX else sig[: SIG_MAX - 1] + "…"
        print(f"{n:>{width}}  {shown}")
    print(f"\n{alerts} alerts, {len(counts)} distinct signatures, "
          f"{len(files)} file(s) scanned"
          + (f", day={args.day}" if args.day else ""))
    if no_sig:
        print(f"({no_sig} alert lines without a signature skipped)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
