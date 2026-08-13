# Suricata dataset matching замість прямого завантаження geo/Spamhaus списків у MikroTik

**Статус:** accepted

Geo-блокування (RU, BY, CN, KP, IR) і Spamhaus DROP — великі списки CIDR-діапазонів (geoip.txt: ~26k рядків усі країни; Spamhaus DROP: ~1.7k). Замість завантаження цих списків цілком у MikroTik firewall address-lists (постійне навантаження на пам'ять роутера), списки завантажуються як Suricata `dataset` (IPv4-only, окремий dataset-файл на країну + окремий на Spamhaus, окреме правило на кожен напрямок), а на MikroTik пушаться лише **фактичні хіти** — той самий патерн, що вже працює для ET-сигнатур через `alert-bridge.py`.

Compromise: Suricata `dataset:isset` — бінарна перевірка, алерт не несе інформації про те, який саме діапазон (яка довжина префікса) збігся; демон визначає "охоплюючий діапазон" власним lookup'ом по локальній копії списку перед блокуванням на MikroTik.
