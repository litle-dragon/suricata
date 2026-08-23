> ⚠️ **Історичний документ, застарілий станом на 2026-08-23.** Це первісна
> проєктна специфікація (написана до впровадження geo/Spamhaus-конвеєра,
> `service_events`, `hit_log`/`restore_period_state`, `--messages`,
> `SIGUSR1`/`SIGUSR2`). Схема БД і формати повідомлень нижче більше **не**
> відповідають коду один в один — залишено як запис первісного дизайну, не
> як джерело правди. **Актуальний опис функціоналу** — `FUNCTIONALITY.md`
> (по коду) і `ARCHITECTURE.md` (загальна архітектура); актуальна
> термінологія — `CONTEXT.md`.

# Specification: Suricata Alert Reporting & SQLite Architecture (`spec.md`)

## 1. Overview & Context

This document defines the architecture and implementation specification for the Suricata `alert-bridge.py` reporting, notification, and persistence subsystem.

### Key Objectives
1. **Per-Alert Telegram Silence**: Disable per-alert Telegram notifications. Introduce an **Anomaly / Spike Alert** that triggers ONLY when the alert rate in a 5-minute sliding window exceeds a configurable threshold $N$.
2. **Fixed 6-Hour Slot Digests**: Align digests to 4 fixed clock windows starting at midnight (`00:00-05:59`, `06:00-11:59`, `12:00-17:59`, `18:00-23:59`).
3. **Exact User-Specified Formatting**:
   - Integer rounding for all average metrics (`round(total_alerts / count)`).
   - All-time historical uniqueness checks for "new IPs" and "new subnets".
   - Structured breakdown: Total alerts, unique new IPs, unique new subnets, average attacks per IP/subnet, permanent block counts, Top 10 `/24` subnets (with $\ge 2$ IPs), and unaggregated single IPs.
4. **SQLite Persistence Engine (`sqlite3`)**:
   - Replace JSON state files with SQLite (`/var/log/suricata/alert_bridge.db`) for zero-dependency, crash-resilient (WAL mode), high-performance, and queryable historical storage across all days indefinitely.

---

## 2. SQLite Database Schema (`/var/log/suricata/alert_bridge.db`)

SQLite is embedded via the Python standard library (`import sqlite3`). On initialization, the database enables Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) and creates the following tables:

### 2.1 Table: `seen_ips` (All-Time Uniqueness Tracker)
Tracks every IP ever observed by Suricata to calculate "new IPs" (never seen before in history).
```sql
CREATE TABLE IF NOT EXISTS seen_ips (
    ip TEXT PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_hits INTEGER DEFAULT 1
);
```

### 2.2 Table: `seen_subnets` (All-Time Uniqueness Tracker for `/24`)
Tracks every `/24` (or `/64` IPv6) subnet ever observed by Suricata.
```sql
CREATE TABLE IF NOT EXISTS seen_subnets (
    subnet TEXT PRIMARY KEY,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_hits INTEGER DEFAULT 1
);
```

### 2.3 Table: `daily_stats` (Full Historical Daily Archive)
Stores complete daily summary snapshots captured at midnight rollover (00:00). Preserves full history indefinitely.
```sql
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,               -- e.g. '2026-08-05'
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
    top_subnets_json TEXT NOT NULL,       -- JSON array of top 10 subnets
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 2.4 Table: `slot_digests` (6-Hour Slot Archive)
Archives every 6-hour digest generated at slot boundaries.
```sql
CREATE TABLE IF NOT EXISTS slot_digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    slot_index INTEGER NOT NULL,          -- 0, 1, 2, or 3
    start_time TEXT NOT NULL,             -- '00:00'
    end_time TEXT NOT NULL,               -- '05:59'
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
```

### 2.5 Table: `spike_events` (Anomaly Spike Log)
Logs every anomaly alert triggered by the 5-minute sliding window.
```sql
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
```

---

## 3. In-Memory Hot State & Processing Logic (`alert-bridge.py`)

To ensure ultra-fast processing ($<0.1\text{ ms}$ per alert event), event classification and threshold checks run in-memory, while persistent states flush to SQLite on events, slot boundaries, and midnight.

### 3.1 Hot Memory Data Structures
- **5-Minute Sliding Window**:
  - `_sliding_window_alerts`: `list[dict]` containing `{"time": float, "ip": str, "sig": str, "direction": str}`.
  - `_last_spike_alert_time`: `float` (cooldown enforcement: 15 minutes / 900s).
  - `SPIKE_THRESHOLD_N`: `int` (configurable via env `SPIKE_THRESHOLD_N`, default `500`).
- **Slot Counters (6h)**:
  - `_slot_index`: `int` (0, 1, 2, 3).
  - `_slot_alerts_count`: `int`.
  - `_slot_inbound_counts`: `dict[str, int]`.
  - `_slot_inbound_subnets`: `dict[str, dict]`.
  - `_slot_new_ips`: `set[str]`.
  - `_slot_new_subnets`: `set[str]`.
  - `_slot_perm_ips_count`: `int`.
  - `_slot_perm_subnets_count`: `int`.
- **Daily Counters (Resets at 00:00)**:
  - `_digest_day`: `str` (`YYYY-MM-DD`).
  - `_daily_inbound_counts`: `dict[str, int]`.
  - `_daily_inbound_subnets`: `dict[str, dict]`.
  - `_daily_new_ips`: `set[str]`.
  - `_daily_new_subnets`: `set[str]`.
  - `_daily_permanent_ips_count`: `int`.
  - `_daily_permanent_subnets_count`: `int`.

### 3.2 Uniqueness Determination (All-Time History)
When an inbound alert arrives for IP `target_ip`:
1. Check `seen_ips` table in SQLite (or local set `_all_time_seen_ips` cached at startup).
2. If `target_ip` is not in history:
   - Add `target_ip` to `_slot_new_ips` and `_daily_new_ips`.
   - Insert `target_ip` into `seen_ips` table.
3. Check `seen_subnets` table in SQLite for `subnet_str`.
4. If `subnet_str` is not in history:
   - Add `subnet_str` to `_slot_new_subnets` and `_daily_new_subnets`.
   - Insert `subnet_str` into `seen_subnets` table.

---

## 4. Telegram Notification Templates & Triggers

### 4.1 Anomaly / Spike Alert (Sliding 5-Min Window)
- **Trigger**: `len(_sliding_window_alerts) >= SPIKE_THRESHOLD_N` and `(now - _last_spike_alert_time) >= 900`.
- **Layout & Concrete Example**:
```text
🚨 АНОМАЛЬНИЙ СПЛЕСК АТАК (Spike Alert) ⚠️
Період: 14:10 - 14:15 (останні 5 хвилин)

• Всього алертів за 5 хв: 1,420 (поріг: N = 500)
• Середня інтенсивність: 284 алертів/хв
• Унікальних IP-атакуючих: 45

ТОП10 підмереж по алертам (/24, від 2+ IP):
• 69.5.169.0/24 — 18 IP | 413 алертів (сер. 23 алерти/IP)
• 66.132.186.0/24 — 12 IP | 228 алертів (сер. 19 алерти/IP)

Поодинокі нові IP: 15 IP (всього 42 алертів)
```

### 4.2 Fixed 6-Hour Slot Digest
- **Schedule**:
  - Slot 0: `00:00 - 05:59` (sent at 06:00)
  - Slot 1: `06:00 - 11:59` (sent at 12:00)
  - Slot 2: `12:00 - 17:59` (sent at 18:00)
  - Slot 3: `18:00 - 23:59` (sent at 00:00)
- **Layout & Concrete Example**:
```text
📊 6-годинний дайджест нових загроз
Період: 12:00 - 17:59 (2026-08-05)

• Всього алертів за 6 годин: 5,211
• Унікальних нових IP (раніше не бачили): 2,271
• Унікальних нових підмереж (раніше не бачили): 1,271
• Середня кількість алертів на 1 IP: 2
• Середня кількість алертів на 1 підмережу: 4
• Додано в постійний блок ІР за 6 годин: 32
• Додано в постійний блок підмереж за 6 годин: 2

ТОП10 підмереж по алертам (/24, від 2+ IP):
• 69.5.169.0/24 — 168 IP | 413 алертів (сер. 2 алерти/IP)
• 66.132.186.0/24 — 56 IP | 228 алертів (сер. 4 алерти/IP)
• 66.132.172.0/24 — 52 IP | 217 алертів (сер. 4 алерти/IP)

Поодинокі нові IP (адреси які не агрегувалися в підмережі): 144 IP (всього 144 алертів)
```

### 4.3 07:00 AM Daily Report (Yesterday's Full Day)
- **Trigger**: `current_hour >= "07"` and `last_7am_report_date != today`. Reads yesterday's record from SQLite `daily_stats`.
- **Layout & Concrete Example**:
```text
🌅 Звіт за попередній день (2026-08-05) 📊

• Всього алертів за добу: 24,180
• Унікальних нових IP (раніше не бачили): 8,420
• Унікальних нових підмереж (раніше не бачили): 3,110
• Середня кількість алертів на 1 IP: 3
• Середня кількість алертів на 1 підмережу: 8
• Додано в постійний блок ІР за добу: 124
• Додано в постійний блок підмереж за добу: 8

ТОП10 підмереж по алертам (/24, від 2+ IP):
• 69.5.169.0/24 — 340 IP | 1,820 алертів (сер. 5 алертів/IP)
• 66.132.186.0/24 — 180 IP | 1,140 алертів (сер. 6 алертів/IP)

Поодинокі нові IP (адреси які не агрегувалися в підмережі): 610 IP (всього 610 алертів)
```

---

## 5. Analytics CLI Tool (`analyze_stats.py`)

`analyze_stats.py` queries `/var/log/suricata/alert_bridge.db` directly to deliver instant reports without parsing raw logs:
- `python3 analyze_stats.py --sum`: Displays summary across all recorded days in SQLite `daily_stats`.
- `python3 analyze_stats.py --day YYYY-MM-DD`: Displays full report breakdown for any historical day.
- `python3 analyze_stats.py --spikes`: Displays historical log of all anomaly spike alerts from `spike_events`.
- `python3 analyze_stats.py --top N`: Displays top N attacker subnets/IPs all-time from `seen_subnets` and `seen_ips`.

---

## 6. Implementation Steps

1. **Database Module**: Implement SQLite connection, table migrations, and helper CRUD functions in `alert-bridge.py`.
2. **In-Memory Event Pipeline**: Refactor `record_hit()` and `check_periodic_tasks()` in `alert-bridge.py` to use SQLite for uniqueness tracking and history saving.
3. **Notification System**: Wire Telegram messaging for 5-min spikes, 6-h slots, and 07:00 AM daily reports with integer rounding. Remove per-alert Telegram calls.
4. **Analytics Tool**: Update `analyze_stats.py` to read directly from `/var/log/suricata/alert_bridge.db`.
5. **Verification**:
   - Run `python3 -m py_compile alert-bridge.py analyze_stats.py`.
   - Run synthetic alert test suite to confirm database tables populate correctly and notification formats match specification.
