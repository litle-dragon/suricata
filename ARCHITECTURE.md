# Загальна архітектура проєкту

> Високорівневий огляд системи: компоненти, потоки даних, схема БД,
> деплой-топологія. Деталі "що саме робить кожна функція" — `FUNCTIONALITY.md`
> (по коду). Термінологія — `CONTEXT.md`. Покрокова інструкція розгортання —
> `README.md`. Історія проєктних рішень — `docs/adr/*.md`, `geo-spamhaus-plan.md`.
>
> Останнє оновлення: 2026-08-23 (після сесії: message archive/search,
> on-demand звіти, GEO/Spamhaus TOP10, restart-safe стан, фікс кешу
> постійних блоків).

## 1. Що це

Домашня IDS на базі MikroTik-роутера (дзеркалить WAN-трафік) + Suricata
(інспектує копію) + Python-демон (`alert-bridge.py`), який реагує на алерти:
блокує атакуючих на MikroTik і звітує в Telegram. Пасивна система — трафік
ніколи не проходить крізь Suricata inline, перший пакет атаки завжди
проходить до блокування.

## 2. Компоненти й потік даних

```
MikroTik router                              external services
  │ /tool sniffer (TZSP over UDP 37008)         │ iwik.org (geoip.txt)
  ▼                                              │ spamhaus.org (drop.txt)
Linux box:                                       │ api.telegram.org (Bot API)
  tzsp2pcap → tcpreplay → tzsp0 (dummy iface)     │
       │                                          │
   Suricata (IDS + IP Reputation engine) ◀── update_geo_lists.py (cron.daily)
       │ eve.json (alerts only)                   │ writes geo-spamhaus-
       ▼                                          │ reputation.list + .lst
  alert-bridge.py (systemd, singleton) ───────────┘
       │            │              │
       ▼            ▼              ▼
  MikroTik REST   SQLite         Telegram Bot API
  (block/unblock) alert_bridge.db (spike/digest/report/
                       │           lifecycle/on-demand)
                       ▼
              analyze_stats.py (CLI, read-only за замовчуванням,
                                 read-write лише для --sync-mikrotik/
                                 --merge-adjacent/--verify-blocks --fix/
                                 --messages)
```

Допоміжний, незалежний ланцюжок (не залежить від БД чи живого демона):
`parse_rules_ips.py` → `malicious_subnets.txt` → `sync_rules_to_mikrotik.py`
— масове batch-завантаження репутаційних IP з наявних Suricata-правил.
`migrate_json_to_sqlite.py` і `sync-state-from-journal.py` — легасі,
одноразові/незатребувані відтоді, як стан переїхав у SQLite.

## 3. Три конвеєри блокування

| | Regular (inbound) | GEO | Spamhaus |
|---|---|---|---|
| Джерело рішення | Suricata ET-сигнатури | geo-spamhaus.rules (IP Reputation) | те саме |
| Ескалація | 1-2 спроби → temp (1h), 3+ → permanent | немає — permanent з 1-ї спроби | те саме |
| Агрегація | `/24`/`/64` (`get_subnet`) | `covering_range` (довільний CIDR з geo-списку) | те саме |
| Uniqueness-трекінг | `seen_ips`/`seen_subnets` (all-time) | немає (ADR-0002) | немає |
| MikroTik-список | `suricata-block` | `suricata-geo-block` | `suricata-spamhaus-block` |
| Аудит | `permanent_blocks` (`kind='ip'/'subnet'`) | `permanent_blocks` (`kind='geo-<cc>'`) | `permanent_blocks` (`kind='spamhaus'`) |
| ТОП10 у звіті | `_slot_inbound_subnets` (фільтр "вже заблоковано") | `_slot_geo_spamhaus_subnets` (без фільтра — див. чому нижче) | те саме |

**Чому GEO/Spamhaus ТОП10 без фільтра "вже заблоковано":** регулярний
pipeline ескалює поступово, є вікно часу до permanent-блоку, коли підмережа
ще кандидат на ТОП. GEO/Spamhaus блокує миттєво з 1-ї спроби — фільтр
залишив би ТОП майже завжди пустим.

**Спільна точка:** усі три пишуть у `permanent_blocks` і читають/пишуть той
самий in-memory кеш `_permanently_blocked_ips`/`_permanently_blocked_subnets`
(завантажений при старті з **усіх** `kind`, не тільки `'ip'`/`'subnet'` —
див. §6 "Відомий технічний борг" щодо історії цього багу).

## 4. Схема БД (`/var/log/suricata/alert_bridge.db`, WAL mode)

| Таблиця | Призначення | Час життя |
|---|---|---|
| `seen_ips` / `seen_subnets` | All-time "чи бачили колись" + `first_seen` | назавжди |
| `permanent_blocks` | Аудит кожного permanent-блоку (обидва пайплайни) | назавжди |
| `subnet_active_days` | Multi-day override — дні активності підмережі | назавжди |
| `subnet_daily_ips` | Restart-safe унікальні IP на підмережу за сьогодні | до півночі |
| `daily_stats` / `slot_digests` | Повний архів звітів (структуровані + JSON-колонки для адрес-листів/ТОП) | назавжди |
| `spike_events` | Лог аномальних сплесків | назавжди |
| `service_events` | Повідомлення без іншого структурного сховища (старт/стоп, reconcile-summary, on-demand) | назавжди |
| `hit_log` | Restart-safe обсяг алертів (не блоків), `day+slot_index+pipeline+bucket+ip` | до півночі |

Нові колонки — `_SCHEMA_MIGRATIONS` (ідемпотентний `ALTER TABLE`, ловить
"duplicate column"). Нові таблиці — просто `CREATE TABLE IF NOT EXISTS`,
без міграції.

## 5. Життєвий цикл звіту

```
Алерт (eve.json)
  → record_hit() / geo-spamhaus гілка в main()
      → in-memory _slot_*/_daily_* лічильники (гарячий шлях)
      → record_hit_log() UPSERT у hit_log (restart-safe backing store)
  → MikroTik REST (якщо перетнутий поріг/geo-spamhaus hit)
  → таймерний тригер (check_periodic_tasks(), кожен тік follow()-циклу):
      - межа слоту (6г) → send_6h_slot_digest() → INSERT slot_digests
                        → reconcile_slot_blocks() → archive_send(service_events)
      - північ → snapshot_daily_stats() → INSERT daily_stats
      - 07:00 → send_7am_daily_report() (читає daily_stats, не пам'ять)
      - SIGUSR1/SIGUSR2 → send_*_ondemand() → archive_send(service_events)
  → telegram_send() → sent=1/0 у рядку звіту
  → (при наступному старті) resend_missed_reports() досилає sent=0
```

**При старті процесу** (`main()`, одразу після `db_init()`):
`restore_period_state()` відновлює `_slot_*`/`_daily_*` з трьох джерел
(`hit_log`, `seen_ips`/`seen_subnets.first_seen`, `permanent_blocks.blocked_at`)
— рестарт мід-слот/мід-доба більше не губить частковий прогрес.

**Пошук/показ будь-якого надісланого повідомлення** — `analyze_stats.py
--messages`, рендерить тим самим форматером (`_build_periodic_report_lines`),
що й оригінал, лениво імпортуючи `alert-bridge.py` через `importlib`.

## 6. Відомий технічний борг

Детальний план виправлень — `TODO.md`. Коротко, найважливіше:

- **Stringly-typed `kind`** (`"ip"`/`"subnet"`/`"geo-<cc>"`/`"spamhaus"`) —
  джерело реального бага 2026-08-23 (кеш постійних блоків фільтрував лише
  `'ip'`/`'subnet'`, губив geo/spamhaus після кожного рестарту). Немає
  механізму, що ловить неповний `WHERE kind IN (...)` автоматично.
- **Дублікація трьох "паралельних" пайплайнів** — кожна нова властивість
  (new-block list, TOP-агрегація, hit_log) дописується вручну symmetric
  у 4 місця (`_slot_*`/`_daily_*` × geo/spamhaus).
- **Схема БД синхронізується вручну в 3+ місцях** (CREATE TABLE,
  `_SCHEMA_MIGRATIONS`, кожен SELECT/INSERT column list) — один рядок
  міграції вже губився в правці сьогодні, знайдено випадково.
- **Деплой без CI** — `curl` з GitHub raw CDN кешує старий вміст ~1 хв
  після push; ловиться лише ручною звіркою checksums.
- **`alert-bridge.py`** — hyphenated filename, не імпортується напряму
  (`analyze_stats.py`/тести змушені юзати `importlib.util.spec_from_file_location`).

## 7. Деплой-топологія

- **Suricata-бокс** (`suricata-ids`, SSH-alias) — Debian/Ubuntu, Suricata +
  `tzsp2pcap`/`tcpreplay` (systemd units `tzsp0-iface`/`tzsp-receiver`) +
  `alert-bridge.service` (`/opt/alert-bridge/{alert-bridge.py,
  analyze_stats.py,env,alert-bridge.cfg}`) + `cron.daily/update-geo-lists`.
- **MikroTik router** — `/tool sniffer` (TZSP mirror), REST API (`www-ssl`,
  Basic Auth, IP-обмежений на Suricata-бокс), RAW-правила
  (`suricata-block`/`suricata-geo-block`/`suricata-spamhaus-block`).
- **Секрети** — `/opt/alert-bridge/env` (Telegram token, MikroTik
  креденшели, WAN IP), права `600`, ніколи в git (`.gitignore`: `.env`,
  `.env.*`, `.envrc`, `*.env`).
- **Деплой** — `git push` → на боксі `sudo curl -o ... raw.githubusercontent.com/...`
  (або напряму `sudo tee` по SSH, коли CDN кешує старе) → `py_compile` →
  `systemctl restart alert-bridge`.
