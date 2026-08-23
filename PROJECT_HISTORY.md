> Історичні проєктні документи — первісна специфікація, план реалізації
> geo/Spamhaus-фічі, і три ADR — злиті сюди 2026-08-23 з окремих файлів
> (`spec.md`, `geo-spamhaus-plan.md`, `docs/adr/000{1,2,3}-*.md`). Ніщо
> нижче не редагувалось під поточний стан коду — це запис того, що
> вирішувалось і чому, в момент прийняття рішення. **Актуальний опис
> функціоналу** — `FUNCTIONALITY.md` (по коду) і `ARCHITECTURE.md`
> (загальна архітектура); актуальна термінологія — `CONTEXT.md`; план
> подальших змін — `TODO.md`.
>
> ADR-посилання в коді/коментарях (`ADR-0001`/`ADR-0002`/`ADR-0003`)
> вказують на секції нижче.

---

# ADR-0001 — Suricata dataset matching замість прямого завантаження geo/Spamhaus списків у MikroTik

**Статус:** superseded by ADR-0003 (нижче).

Geo-блокування (RU, BY, CN, KP, IR) і Spamhaus DROP — великі списки CIDR-діапазонів (geoip.txt: ~26k рядків усі країни; Spamhaus DROP: ~1.7k). Замість завантаження цих списків цілком у MikroTik firewall address-lists (постійне навантаження на пам'ять роутера), списки завантажуються як Suricata `dataset` (IPv4-only, окремий dataset-файл на країну + окремий на Spamhaus, окреме правило на кожен напрямок), а на MikroTik пушаться лише **фактичні хіти** — той самий патерн, що вже працює для ET-сигнатур через `alert-bridge.py`.

Compromise: Suricata `dataset:isset` — бінарна перевірка, алерт не несе інформації про те, який саме діапазон (яка довжина префікса) збігся; демон визначає "охоплюючий діапазон" власним lookup'ом по локальній копії списку перед блокуванням на MikroTik.

---

# ADR-0002 — Geo/Spamhaus-блоки: паралельний конвеєр, не розширення ескалації

**Статус:** accepted.

Geo/Spamhaus-алерти блокуються негайно й постійно на першому ж хіті (джерело — вже курований зовнішній список, ескалація тут безглузда). Свідомо **не** проходять через `record_hit()`/`seen_ips`/`seen_subnets` uniqueness-трекінг і не рахуються у `_daily_inbound_counts`/"нова IP" — інакше вони б плуталися зі звичайними ET-атакуючими в наявних дайджестах (IP, яка ніколи не бачила ескалацію 1→2→3, з'являлася б як "нова атакуюча IP").

Наслідок: власні лічильники в дайджестах, з розбивкою по країні (RU/BY/CN/KP/IR) і окремо Spamhaus; audit reuse `permanent_blocks` (новий `kind`), MikroTik address-list — 2 нових списки за категорією (`suricata-geo-block`, `suricata-spamhaus-block`), не по країні.

---

# ADR-0003 — IP Reputation (iprep), не datasets, для CIDR-матчингу geo/Spamhaus

**Статус:** accepted. Supersedes ADR-0001.

## Що трапилось

ADR-0001 припускав, що Suricata `dataset type: ip` може зберігати CIDR-записи. Це виявилося хибним при першому реальному розгортанні на живому Suricata 7.0.3:

```
E: datasets: dataset data parse failed geo-ru//var/lib/suricata/datasets/geo_ru.lst: 101.79.213.0/24
```

`101.79.213.0/24` — валідний CIDR, але парсер його відхилив. Офіційна документація Suricata 7.0.3 підтверджує: формат файлу для `type: ip` — "in the file as string, it can be IPv6 or IPv4 address" (голий IP, без CIDR). Suricata datasets — це exact-match хеш-таблиця, не призначена для мережевих діапазонів. Розкладання ~26k підмереж (деякі /8-/9, мільйони адрес на країну) в exact-match список знецінює саму ціль ADR-0001 — уникнути роздування пам'яті.

## Рішення

**IP Reputation (iprep)** — вбудований у Suricata механізм, чий формат reputation-файлу нативно підтримує CIDR: `<ip-or-cidr>,<category>,<score>`, напр. `1.1.1.0/24,6,88` (документація, розділ IP Reputation Format).

- **`categories.txt`** (`reputation-categories-file` у `suricata.yaml`) — статичний CSV `<id>,<short-name>,<опис>`, по одній категорії на країну (`GEO-RU`, `GEO-BY`, ...) + `SPAMHAUS`. Генерується `update_geo_lists.py`, детермінований мапінг (порядок `countries` з cfg + Spamhaus останнім).
- **`geo-spamhaus-reputation.list`** (`reputation-files`) — об'єднаний CSV `<cidr>,<category-id>,127` для всіх джерел разом. Score завжди 127 (максимальна впевненість) — списки бінарні, немає градації довіри.
- Правила `geo-spamhaus.rules` тепер використовують `iprep:<src|dst>,<CATEGORY>,>,0;` замість `dataset:isset,...,type ip;`. `msg:`/`sid` — без змін.
- `categories.txt` **не** перечитується на живому reload (потребує рестарту Suricata, якщо змінюється `countries` — рідкісна ручна дія); `geo-spamhaus-reputation.list` перечитується разом зі звичайним rules-reload (`suricatasc -c reload-rules` / `USR2`), без рестарту — це підтверджено документацією IP Reputation Config.

## Що НЕ змінюється

- **`geo_lists.py`** (локальний lookup "охоплюючий діапазон") лишається потрібним і незмінним по суті: `iprep` теж не каже, який саме CIDR збігся — лише категорію і score, той самий compromise, що й ADR-0001 описував для datasets. Демон, як і раніше, сам визначає точний діапазон по локальній копії `.lst`-файлів (тепер це приватна копія лише для алерт-бріджа — Suricata їх більше не читає напряму, читає натомість `geo-spamhaus-reputation.list`).
- **`alert-bridge.py`** — жодних змін: `classify_category()` парсить ту саму `msg:`-конвенцію, паралельний конвеєр блокування (ADR-0002) не зачеплений.
- **MikroTik-сторона** (`suricata-geo-block`/`suricata-spamhaus-block`) — не зачеплена, вона ніколи не залежала від того, як саме Suricata матчить CIDR всередині.

## Наслідок для конфігурації

`[geo_spamhaus] dataset_dir` перейменовано на `local_lists_dir` (та сама директорія, змінилося лише її призначення — це більше не шлях, який читає Suricata) + новий ключ `iprep_dir` (де `update_geo_lists.py` пише `categories.txt`/`geo-spamhaus-reputation.list`, і звідки їх реально завантажує Suricata).

---

# План реалізації geo/Spamhaus-блокування (2026-08-12…13)

> **Статус (2026-08-12, кінець сесії):** Grilling+domain-modeling завершено, дизайн-дерево закрите, план погоджений користувачем. Код ще НЕ писався.
>
> **Апдейт (2026-08-13):** Усі 6 кроків реалізовані й запушені (`8cf417c`). На реальному деплої Suricata 7.0.3 виявлено, що `dataset type: ip` (§1, ADR-0001) — exact-match, CIDR не приймає; замінено на IP Reputation (iprep) — ADR-0003, коміт `f4e2e05` (+ doc-фікси `7becff3`, `ebdaa43`). §1 і §3 нижче описують оригінальний datasets-дизайн — фактична реалізація на iprep, деталі в ADR-0003 і README Step 4b. **Перевірено наживо на Suricata-боксі під навантаженням** — 6-годинний дайджест 12:00–17:59 підтвердив спрацювання (`Geo-block: RU=94, BY=1, CN=194, KP=0, IR=5`, `Spamhaus-block: 60`).

Ґрунтується на `CONTEXT.md` і ADR-0001/0002 (вище) — рішення там уже прийняті, цей документ лише розкладає їх на файли й кроки.

## 1. Suricata-side: датасети + правила (оригінальний, superseded ADR-0001-дизайн)

**Нові файли** (на Suricata-боксі, поза git-репо, як і наявний `/etc/suricata/threshold.config`):
```
/var/lib/suricata/datasets/geo_ru.lst
/var/lib/suricata/datasets/geo_by.lst
/var/lib/suricata/datasets/geo_cn.lst
/var/lib/suricata/datasets/geo_kp.lst
/var/lib/suricata/datasets/geo_ir.lst
/var/lib/suricata/datasets/spamhaus.lst
```
Кожен — простий текстовий список CIDR, один на рядок.

**Rule-файл** `geo-spamhaus.rules`, `msg`-конвенція, яку парсить `alert-bridge.py`:
```
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GEO-BLOCK-RU-IN"; ip.src; dataset:isset,geo_ru,type ip; classtype:policy-violation; sid:9000001; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GEO-BLOCK-RU-OUT"; ip.dst; dataset:isset,geo_ru,type ip; classtype:policy-violation; sid:9000002; rev:1;)
... (аналогічно для BY/CN/KP/IR, SPAMHAUS-BLOCK-IN/OUT)
```
sid-діапазон `9000001-9000012` зарезервований під цю фічу. Фактична реалізація замінила `dataset:isset,...,type ip` на `iprep:<src|dst>,<CATEGORY>,>,0` — ADR-0003.

## 2. Скрипт `update_geo_lists.py`

Стиль `argparse` + `syslog`-логування (`_jlog`), читає `env`/`alert-bridge.cfg`, atomic write (`tmp` + `os.replace`):
1. Фетчить `iwik.org/ipcountry/geoip.txt`, фільтрує за суфіксом країни (з cfg), пише `geo_<cc-lower>.lst`.
2. Фетчить `spamhaus.org/drop/drop.txt`, парсить `CIDR ; SBLxxxxx` → `spamhaus.lst`.
3. На мережевій помилці — не чіпає наявний файл, Telegram-warning.
4. На успіху — атомарна заміна + `suricatasc -c reload-rules` (без рестарту) + Telegram-підсумок.
5. Cron: `/etc/cron.daily/update-geo-lists`.

## 3. Зміни в `alert-bridge.py`

- `classify_category(sig)` — парсить `GEO-BLOCK-<CC>-IN/OUT`/`SPAMHAUS-BLOCK-IN/OUT`.
- `geo_lists.py` — локальний lookup "охоплюючий діапазон" (bisect по `.lst`-файлах).
- Новий блок у `main()`, ДО inbound/outbound-гілки (інший конвеєр, ADR-0002): класифікація → whitelist-гейт → `covering_range` → `already_blocked`-перевірка (спільний кеш з regular pipeline) → `mikrotik_block()` + `db_record_permanent_block()` → лічильники по країнах.
- `mikrotik_block()`/`mikrotik_lookup_covered()` — параметр `block_list`.
- Дайджести — нові рядки `🌍 Geo-block:`/`🚫 Spamhaus-block:` (тільки коли > 0).

## 4. `analyze_stats.py`

`--geo` — `permanent_blocks WHERE kind LIKE 'geo-%' OR kind='spamhaus'`, розбивка по країні.

## 5. README

"Step 4b — Geo/Spamhaus dataset blocking" між Step 4 і Step 5.

## 6. Порядок реалізації (виконано)

1. `geo_lists.py` + юніт-тест.
2. `update_geo_lists.py`, dry-run на реальних URL.
3. Зміни в `alert-bridge.py`.
4. `alert-bridge.cfg.example` + `analyze_stats.py --geo`.
5. Suricata rule-файл + README-розділ.
6. Верифікація: `py_compile` + smoke-тест на замоканому MikroTik REST.

## Явно поза обсягом цього плану

- Рефакторинг формату/структури звітів — реалізовано пізніше, сесія 2026-08-23.
- Альтернативні канали сповіщень (ntfy тощо) — не реалізовано.
- Ребрендинг репо — не реалізовано.

---

# Первісна специфікація: Suricata Alert Reporting & SQLite Architecture (2026-08-05, до geo/Spamhaus)

> Схема БД і формати повідомлень нижче описують стан **до** geo/Spamhaus-
> конвеєра, `service_events`, `hit_log`/`restore_period_state`,
> `--messages`, `SIGUSR1`/`SIGUSR2` — історичний знімок первісного дизайну,
> не поточний код.

## 1. Overview & Context

Ця специфікація визначала архітектуру reporting/notification/persistence-підсистеми `alert-bridge.py`.

### Key Objectives
1. **Per-Alert Telegram Silence**: вимкнути повідомлення на кожен алерт. Ввести **Anomaly / Spike Alert**, що спрацьовує лише коли частота алертів у ковзному 5-хвилинному вікні перевищує поріг $N$.
2. **Fixed 6-Hour Slot Digests**: дайджести прив'язані до 4 фіксованих вікон від півночі (`00:00-05:59`, `06:00-11:59`, `12:00-17:59`, `18:00-23:59`).
3. **Exact User-Specified Formatting**: цілочисельне округлення середніх; all-time historical uniqueness для "нових IP/підмереж"; структурована розбивка (Total alerts, unique new IPs/subnets, avg attacks per IP/subnet, permanent block counts, Top 10 `/24` з 2+ IP, unaggregated single IPs).
4. **SQLite Persistence Engine**: заміна JSON-стану на SQLite (`/var/log/suricata/alert_bridge.db`, WAL mode) — crash-resilient, queryable, без обмеження історії.

## 2. Первісна схема SQLite

П'ять таблиць (WAL mode): `seen_ips`/`seen_subnets` (all-time уникальність, `first_seen`/`last_seen`/`total_hits`), `daily_stats`/`slot_digests` (архів звітів — на момент написання **без** `sent`/`*_json`/geo-колонок, лише базові числові поля + `top_subnets_json`), `spike_events` (лог аномалій).

## 3. In-Memory Hot State (первісний набір)

- 5-хвилинне ковзне вікно: `_sliding_window_alerts`, `_last_spike_alert_time`, `SPIKE_THRESHOLD_N`.
- Слотові лічильники (6г): `_slot_index`, `_slot_alerts_count`, `_slot_inbound_counts`, `_slot_inbound_subnets`, `_slot_new_ips`/`_slot_new_subnets`, `_slot_perm_ips_count`/`_slot_perm_subnets_count`.
- Добові лічильники (ресет опівночі): `_digest_day`, `_daily_inbound_counts`, `_daily_inbound_subnets`, `_daily_new_ips`/`_daily_new_subnets`, `_daily_permanent_ips_count`/`_daily_permanent_subnets_count`.

Ці структури з тих пір розширились (geo/spamhaus-лічильники, `hit_log`-backing, restart-safety) — актуальний перелік у `FUNCTIONALITY.md`.

## 4. Telegram-шаблони (первісні, без geo/spamhaus-розбивки)

### 4.1 Anomaly / Spike Alert
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
Розклад: Slot 0 `00:00-05:59` (шле о 06:00), Slot 1 `06:00-11:59` (12:00), Slot 2 `12:00-17:59` (18:00), Slot 3 `18:00-23:59` (00:00).
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

### 4.3 07:00 AM Daily Report
Тригер: `current_hour >= "07"` і `last_7am_report_date != today`, читає вчорашній рядок з `daily_stats`.
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

## 5. Analytics CLI (первісний набір)

`analyze_stats.py --sum`/`--day YYYY-MM-DD`/`--spikes`/`--top N` — з тих пір розширено `--list`/`--list-out`/`--geo`/`--sync-mikrotik`/`--merge-adjacent`/`--verify-blocks`/`--fix`/`--messages` (`FUNCTIONALITY.md`).

## 6. Кроки реалізації (виконано)

1. SQLite-модуль: з'єднання, міграції, CRUD.
2. In-memory event pipeline: `record_hit()`/`check_periodic_tasks()`.
3. Notification system: spike/6h/07:00, без per-alert.
4. Analytics tool: пряме читання з SQLite.
5. Верифікація: `py_compile` + синтетичний alert test suite.
