# IP Reputation (iprep), не datasets, для CIDR-матчингу geo/Spamhaus

**Статус:** accepted

Supersedes [0001-suricata-dataset-offload-for-geo-spamhaus-blocking.md](0001-suricata-dataset-offload-for-geo-spamhaus-blocking.md).

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
