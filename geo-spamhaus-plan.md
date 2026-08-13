> **Статус (2026-08-12, кінець сесії):** Grilling+domain-modeling завершено, дизайн-дерево закрите, план погоджений користувачем. Код ще НЕ писався — жодного файлу з розділів 1-5 не створено/змінено. Наступний крок при продовженні: розділ 6, крок 1 — `geo_lists.py` (lookup-модуль). Контекст для продовження: `CONTEXT.md`, `docs/adr/0001-...md`, `docs/adr/0002-...md`, цей файл. Читати їх — і НЕ повторювати grilling-раунди, рішення вже прийняті й зафіксовані.

# Plan: Geo (RU/BY/CN/KP/IR) + Spamhaus DROP blocking via Suricata datasets

Ґрунтується на `CONTEXT.md` і `docs/adr/0001-...`/`0002-...` — рішення там уже прийняті, цей документ лише розкладає їх на файли й кроки.

## 1. Suricata-side: датасети + правила

**Нові файли** (на Suricata-боксі, поза git-репо, як і наявний `/etc/suricata/threshold.config`):
```
/var/lib/suricata/datasets/geo_ru.lst
/var/lib/suricata/datasets/geo_by.lst
/var/lib/suricata/datasets/geo_cn.lst
/var/lib/suricata/datasets/geo_kp.lst
/var/lib/suricata/datasets/geo_ir.lst
/var/lib/suricata/datasets/spamhaus.lst
```
Кожен — простий текстовий список CIDR, один на рядок (IPv4-only, формат, який Suricata `dataset type: ip` розуміє напряму).

**`suricata.yaml`** — новий блок `datasets:` (README, крок 4b):
```yaml
datasets:
  geo_ru: {type: ip, load: /var/lib/suricata/datasets/geo_ru.lst}
  geo_by: {type: ip, load: /var/lib/suricata/datasets/geo_by.lst}
  geo_cn: {type: ip, load: /var/lib/suricata/datasets/geo_cn.lst}
  geo_kp: {type: ip, load: /var/lib/suricata/datasets/geo_kp.lst}
  geo_ir: {type: ip, load: /var/lib/suricata/datasets/geo_ir.lst}
  spamhaus: {type: ip, load: /var/lib/suricata/datasets/spamhaus.lst}
```

**Новий rule-файл** `/etc/suricata/rules/geo-spamhaus.rules`, доданий до `rule-files:` у `suricata.yaml`. `msg` — точний контракт, який парсить `alert-bridge.py` (префікс, не `classtype` — `classtype` заскладний для 1:1 category-match):

```
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GEO-BLOCK-RU-IN"; ip.src; dataset:isset,geo_ru,type ip; classtype:policy-violation; sid:9000001; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GEO-BLOCK-RU-OUT"; ip.dst; dataset:isset,geo_ru,type ip; classtype:policy-violation; sid:9000002; rev:1;)
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GEO-BLOCK-BY-IN"; ip.src; dataset:isset,geo_by,type ip; classtype:policy-violation; sid:9000003; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GEO-BLOCK-BY-OUT"; ip.dst; dataset:isset,geo_by,type ip; classtype:policy-violation; sid:9000004; rev:1;)
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GEO-BLOCK-CN-IN"; ip.src; dataset:isset,geo_cn,type ip; classtype:policy-violation; sid:9000005; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GEO-BLOCK-CN-OUT"; ip.dst; dataset:isset,geo_cn,type ip; classtype:policy-violation; sid:9000006; rev:1;)
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GEO-BLOCK-KP-IN"; ip.src; dataset:isset,geo_kp,type ip; classtype:policy-violation; sid:9000007; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GEO-BLOCK-KP-OUT"; ip.dst; dataset:isset,geo_kp,type ip; classtype:policy-violation; sid:9000008; rev:1;)
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"GEO-BLOCK-IR-IN"; ip.src; dataset:isset,geo_ir,type ip; classtype:policy-violation; sid:9000009; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"GEO-BLOCK-IR-OUT"; ip.dst; dataset:isset,geo_ir,type ip; classtype:policy-violation; sid:9000010; rev:1;)
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"SPAMHAUS-BLOCK-IN"; ip.src; dataset:isset,spamhaus,type ip; classtype:policy-violation; sid:9000011; rev:1;)
alert ip $HOME_NET any -> $EXTERNAL_NET any (msg:"SPAMHAUS-BLOCK-OUT"; ip.dst; dataset:isset,spamhaus,type ip; classtype:policy-violation; sid:9000012; rev:1;)
```
sid-діапазон `9000001-9000012` зарезервований під цю фічу (поза ET-діапазоном, не конфліктує з `suricata-update`-керованими сигнатурами).

## 2. Новий скрипт: `update_geo_lists.py`

Той самий стиль, що `parse_rules_ips.py`/`sync_rules_to_mikrotik.py`: `argparse`, `syslog`-логування через `_jlog`, читає `env`/`alert-bridge.cfg`, atomic write (`tmp` + `os.replace`).

**Що робить:**
1. Фетчить `https://www.iwik.org/ipcountry/geoip.txt`, фільтрує рядки за суфіксом країни (`RU`/`BY`/`CN`/`KP`/`IR`, з `[geo_spamhaus] countries` у cfg), пропускає IPv6-рядки (захисно, хоч у вибірці їх не було), пише `geo_<cc-lower>.lst` (по одному CIDR на рядок, без коментарів/country-суфікса).
2. Фетчить `https://www.spamhaus.org/drop/drop.txt`, парсить `CIDR ; SBLxxxxx` → лишає лише CIDR, пише `spamhaus.lst`.
3. На мережевій помилці (фетч не вдався) для будь-якого джерела — **не чіпає** наявний файл на диску, логує warning у journal, шле Telegram-повідомлення "⚠️ update_geo_lists: RU/Spamhaus fetch failed, keeping yesterday's list" (per Q4).
4. На успіху — атомарно замінює файли, тригерить `suricatasc -c reload-rules` (без рестарту), шле коротке Telegram-повідомлення з підсумком (кількість CIDR на країну + spamhaus).
5. Cron: `/etc/cron.daily/update-geo-lists` (окремо від існуючого щотижневого `suricata-update`), запускається під root (потрібен доступ до `/var/lib/suricata/datasets/` і суфікс-сокет для `suricatasc`).

Telegram-надсилання — окрема маленька функція (не імпортує `alert-bridge.py`, дублює ті самі 5 рядків `requests.post`, як і решта допоміжних скриптів зараз незалежні один від одного).

## 3. Зміни в `alert-bridge.py`

**Класифікація категорії** — нова функція `classify_category(sig: str) -> tuple[str, str] | None`:
```python
_GEO_PREFIX = "GEO-BLOCK-"      # GEO-BLOCK-RU-IN / GEO-BLOCK-RU-OUT / ...
_SPAMHAUS_PREFIX = "SPAMHAUS-BLOCK-"
```
Парсить `msg` за конвенцією з розділу 1: повертає `("geo", "ru")`/`("spamhaus", None)`/`None`.

**Локальний lookup "охоплюючий діапазон"** — новий модуль `geo_lists.py` (імпортується `alert-bridge.py`), читає ті самі `.lst`-файли, що й Suricata dataset, будує на кожен файл відсортований масив `(network_start_int, network_end_int, str(network))` і робить `bisect`-пошук О(log n) — Suricata `dataset:isset` не каже, який саме CIDR збігся (ADR-0001), тож демон шукає сам. Перечитує файли при зміні mtime (не на кожен алерт).

**Новий блок обробки в `main()`**, ДО існуючої inbound/outbound-гілки (бо це інший конвеєр, ADR-0002):
1. `classify_category(sig)` — якщо не geo/spamhaus, іде у звичайний шлях без змін.
2. Якщо так: `whitelisted(ip)` — як і завжди, gate.
3. `geo_lists.covering_range(list_name, ip)` — знаходить точний CIDR.
4. Якщо вже в `_permanently_blocked_ips`/`_permanently_blocked_subnets` (спільний кеш з ADR-0002) — no-op, лише лічильник.
5. Інакше — `mikrotik_block(covering_range, sig, permanent=True, block_list=CATEGORY_LIST[category])` (нова опція `block_list`, MIKROTIK_GEO_LIST/MIKROTIK_SPAMHAUS_LIST з cfg), `db_record_permanent_block(covering_range, kind=f"geo-{cc}"/"spamhaus", sig)`.
6. Інкремент нових лічільників `_slot_geo_counts[cc]`, `_daily_geo_counts[cc]`, `_slot_spamhaus_count`, `_daily_spamhaus_count` — окремо від `_daily_inbound_counts`/`seen_ips` (не проходять `record_hit()`).

**`mikrotik_block()`/`mikrotik_lookup_covered()`** — додати параметр `block_list: str = BLOCK_LIST`, щоб працювати з `suricata-geo-block`/`suricata-spamhaus-block` окремо від дефолтного `suricata-block`.

**Дайджести** (`_build_periodic_report_lines`, `send_6h_slot_digest`, `send_7am_daily_report`) — нові рядки з розбивкою по країні:
```
🌍 Geo-block: RU=12, BY=0, CN=3, KP=0, IR=1
🚫 Spamhaus-block: 4
```
Тільки коли лічильник > 0 для відповідного рядка (не захаращувати нулями).

**`alert-bridge.cfg.example`** — новий розділ:
```ini
[geo_spamhaus]
enabled = true
countries = RU,BY,CN,KP,IR
dataset_dir = /var/lib/suricata/datasets
mikrotik_geo_list = suricata-geo-block
mikrotik_spamhaus_list = suricata-spamhaus-block
```

**`SCHEMA_MIGRATIONS`** — без змін: `permanent_blocks.kind` уже `TEXT`, нові значення (`geo-ru` тощо) не потребують ALTER TABLE.

## 4. `analyze_stats.py`

Новий прапорець `--geo` — читає `permanent_blocks WHERE kind LIKE 'geo-%' OR kind='spamhaus'`, групує по `kind`, друкує розбивку по країні + Spamhaus (не входить у `--sum`/`--top`, окрема команда per Q3).

## 5. README

Новий розділ "Step 4b — Geo/Spamhaus dataset blocking" між існуючим Step 4 (Suricata config) і Step 5 (rules install): `datasets:` блок, custom rule file, cron для `update_geo_lists.py`, і нові MikroTik firewall drop-правила на `suricata-geo-block`/`suricata-spamhaus-block` (аналогічно наявному `suricata-block`).

## 6. Порядок реалізації

1. `geo_lists.py` (lookup-модуль) + юніт-перевірка на синтетичному `.lst`.
2. `update_geo_lists.py` (фетч+парсинг+atomic write+Telegram), тест на реальних URL (dry-run, без запису).
3. Зміни в `alert-bridge.py` (класифікація, блок, лічильники, дайджести, cfg).
4. `alert-bridge.cfg.example` + `analyze_stats.py --geo`.
5. Suricata rule-файл + README-розділ (документація, без доступу до живого роутера/Suricata-боксу — не перевіряється тут наживо).
6. Верифікація: `python3 -m py_compile` на всіх змінених/нових `.py`; smoke-тест на замоканому MikroTik REST (розширення наявного 9/9-набору новими кейсами: geo-хіт → правильний список+діапазон, spamhaus-хіт, whitelist-гейт, дедуп через `_permanently_blocked_ips`).

## Явно поза обсягом цього плану (за твоїми відповідями)

- Рефакторинг формату/структури звітів — 2-а черга.
- Альтернативні канали сповіщень (ntfy тощо) — 2-а черга, окреме дослідження.
- Ребрендинг репо — після завершення фічі.
</content>
