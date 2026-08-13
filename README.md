# Build Your Own Home IDS — Suricata + MikroTik

Turn a MikroTik router and any Linux box on your LAN into a home Intrusion
Detection System that:

- inspects a **live mirror of your WAN traffic** with [Suricata](https://suricata.io/) and ~50k free Emerging Threats Open signatures,
- **automatically blocks attackers** on the router's firewall (with a self-expiring timeout),
- surfaces **anomaly spikes** to your phone via **Telegram** the moment attack volume crosses a threshold — no per-alert spam,
- and rolls the rest into **fixed 6-hour digests** and a **07:00 daily report**, backed by a queryable **SQLite** history.

This README is the step-by-step companion to the video tutorial. The three
files in this repo — [`alert-bridge.py`](alert-bridge.py),
[`alert-bridge.service`](alert-bridge.service), [`env.example`](env.example) —
are the alert bridge you'll install in Step 8.

## How it works

```
Internet ──▶ MikroTik router ──▶ your LAN (traffic flows normally)
                  │
                  │  /tool sniffer streams a COPY of every WAN packet
                  │  (TZSP over UDP 37008)
                  ▼
            Linux box:  tzsp2pcap ──▶ tcpreplay ──▶ tzsp0 (dummy iface)
                                                        │
                                                    Suricata (IDS)
                                                        │  eve.json alerts
                                                    alert-bridge.py
                                                   ┌────┴────────┐
                                                   ▼             ▼
                                     MikroTik REST API      Telegram
                                     (block attacker IP)   (spikes + digests)
```

Key design decisions:

- **Passive, not inline.** Suricata only ever sees a *copy* of the traffic. If
  the Linux box crashes, your internet doesn't even blink. The trade-off: an
  attacker's first few packets always get through before the block lands.
- **Mirror the WAN, stream over the LAN.** Never mirror the interface that
  carries the mirror itself, or every packet spawns a copy of a copy of a
  copy — a packet fusion reactor. `filter-stream=yes` on the sniffer is the
  second layer of protection against this.
- **Block everything, page rarely.** Every severity 1–2 hit is blocked, but
  the bridge never sends a message per alert. It pages you only on an
  **anomaly spike** (inbound alert rate over a 5-minute window crossing a
  threshold), then summarizes the rest in scheduled digests — a handful of
  messages a day instead of hundreds.

## Prerequisites

| What | Notes |
|---|---|
| MikroTik router, RouterOS **v7** | RB5009, hEX, or similar — anything with the built-in packet sniffer |
| Linux machine or VM on the LAN | Debian/Ubuntu assumed below. A few GB of free disk (logs + rules). **Wired** gigabit connection — the mirror duplicates your WAN bandwidth onto the LAN, so don't do this over Wi-Fi |
| ~30 minutes | All software is free and open source |

Values you'll substitute for your own throughout (examples used below):

| Placeholder | Example below | Yours |
|---|---|---|
| Suricata box LAN IP | `192.168.12.232` | `ip -br addr` |
| Router LAN IP | `192.168.12.200` | — |
| WAN interface name on the router | `WAN2` | `/interface print` (often `ether1` or a PPPoE interface) |
| Your public IPv4 | `203.0.113.1` | `curl -4 ifconfig.me` |
| Your public IPv6 prefix (if any) | `2001:db8:aaaa:1::/64` | `curl -6 ifconfig.me` |

> **Why the public IP matters:** the router mirrors traffic *after* NAT, so
> every packet Suricata sees carries your public address, not `192.168.x.x`.
> If your public IP isn't in `HOME_NET`, many inbound attack rules simply
> won't match.
>
> This is a property of the `/tool sniffer` method in Step 6, not of the
> project. [Step 6b](#step-6b-alternative--mirror-with-firewall-mangle-instead)
> describes a mangle-based alternative that preserves the original private
> addresses — so alerts name the actual device rather than your whole
> household. Read its FastTrack caveat before switching.

## Step 1 — Install packages on the Linux box

```bash
sudo apt update
sudo apt install -y suricata suricata-update tcpreplay build-essential libpcap-dev git jq python3-requests
```

What each piece does: `suricata` is the IDS itself; `suricata-update`
downloads the detection rules; `tcpreplay` injects packets onto an interface;
`build-essential` + `libpcap-dev` compile the small helper we build next;
`jq` makes Suricata's JSON logs readable; `python3-requests` is needed by the
alert bridge later.

Sanity check:

```bash
suricata -V
```

## Step 2 — Build tzsp2pcap

The MikroTik sniffer streams packets wrapped in **TZSP** (TaZmen Sniffer
Protocol). Wireshark understands it natively; Suricata doesn't. The tiny
adapter [`tzsp2pcap`](https://github.com/thefloweringash/tzsp2pcap) listens on
UDP 37008, strips the TZSP header, and recovers the original Ethernet frames.
It isn't packaged for Debian, so build it:

```bash
git clone https://github.com/thefloweringash/tzsp2pcap.git
cd tzsp2pcap
make
sudo make install
```

Verify:

```bash
tzsp2pcap -h
```

## Step 3 — Create the capture interface (tzsp0)

Suricata needs a network interface to listen on. We create a **dummy**
interface — connected to no hardware — and replay the mirrored packets onto
it. As far as Suricata is concerned, it's plugged straight into your WAN.

```bash
sudo ip link add tzsp0 type dummy
sudo ip link set tzsp0 mtu 9000      # jumbo MTU so oversized packets aren't truncated
sudo ip link set tzsp0 up
```

Dummy interfaces disappear on reboot, so make it permanent with two systemd
units.

`/etc/systemd/system/tzsp0-iface.service` — recreates the interface at boot:

```ini
[Unit]
Description=Dummy interface for TZSP capture
Before=tzsp-receiver.service suricata.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link show tzsp0 2>/dev/null || ip link add tzsp0 type dummy'
ExecStart=/usr/sbin/ip link set tzsp0 mtu 9000
ExecStart=/usr/sbin/ip link set tzsp0 up
ExecStop=-/usr/sbin/ip link del tzsp0

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/tzsp-receiver.service` — the decode pipeline.
`tzsp2pcap -f` listens on UDP 37008 and writes pcap to stdout (flushing after
every packet); `tcpreplay` injects those packets onto `tzsp0` immediately:

```ini
[Unit]
Description=TZSP receiver - decapsulate MikroTik stream onto tzsp0
After=tzsp0-iface.service network.target
Requires=tzsp0-iface.service

[Service]
ExecStart=/bin/sh -c '/usr/local/bin/tzsp2pcap -f | /usr/bin/tcpreplay --topspeed -i tzsp0 -'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable both (starts them now *and* on every boot):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tzsp0-iface tzsp-receiver
```

## Step 4 — Configure Suricata

```bash
sudo vi /etc/suricata/suricata.yaml
```

It's a huge file; only a handful of changes are needed.

**1. `HOME_NET`** — add your **public** IPv4 (and IPv6 prefix, if you have
one) alongside your LAN networks. If you have **2 ISPs (Dual WAN)**, you **must include both public WAN IPs** in `HOME_NET`.

> **Why both IPs are needed in `HOME_NET`:** Most Suricata rules look for attacks coming from `$EXTERNAL_NET` to `$HOME_NET`. If your second WAN IP isn't in `HOME_NET`, attacks coming in through WAN2 won't match inbound attack rules.

Find your public IP(s):

```bash
curl -4 ifconfig.me && echo
curl -6 ifconfig.me && echo
```

```yaml
# Single WAN example:
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,203.0.113.1/32,2001:db8:aaaa:1::/64]"

# Dual/Multi-WAN example (include both public WAN IPs):
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,203.0.113.1/32,198.51.100.2/32]"
```

> **Note on capture interface for Dual WAN:** You do **NOT** need multiple interfaces in Suricata. MikroTik streams TZSP traffic from both WANs over LAN to UDP 37008, where `tzsp2pcap` decapsulates both streams onto the single dummy interface `tzsp0`. Suricata listens on `tzsp0` and inspects traffic for both WANs simultaneously.

**2. Capture interface** — in the `af-packet:` section, point Suricata at the
dummy interface:

```yaml
af-packet:
  - interface: tzsp0
```

**3. Disable checksum validation** — replayed packets often carry checksums
that were never finalized by a real NIC; without this Suricata silently drops
perfectly valid packets:

```yaml
af-packet:
  - interface: tzsp0
    checksum-checks: no
```

**4. Trim the logging** — by default `eve.json` records every flow, DNS
lookup, and TLS handshake: hundreds of MB per day. Under `outputs:` →
`eve-log:` → `types:`, remove everything except `- alert`. (Keep more if you
plan to feed EveBox/Grafana/a SIEM later.)

**5. Disable the stats dump** — Suricata writes a full statistics block to
`stats.log` every 8 seconds. In the `stats:` section set `enabled: no`.

**6. Uncomment the threshold file** (used in Step 7 to silence noisy rules):

```yaml
threshold-file: /etc/suricata/threshold.config
```

The result: just two logs. `fast.log` (one alert per line, human-readable)
and `eve.json` (the same alerts as structured JSON — the bridge needs it).

## Step 4b — Geo/Spamhaus IP Reputation blocking (optional)

Blocks entire countries (RU/BY/CN/KP/IR by default) and the
[Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) list of hijacked/
spam-hosting networks — tens of thousands of CIDR ranges, too many to push
into MikroTik's address-lists directly without eating router memory.
Instead they're loaded into Suricata's **IP Reputation (iprep)** engine (a
CIDR-aware lookup structure built for exactly this — Suricata `dataset`
cannot hold CIDR entries, it's exact-match only, see
`docs/adr/0003-ip-reputation-not-datasets-for-geo-spamhaus-cidr-matching.md`),
and only actual **hits** get pushed to MikroTik — the same offload pattern
the alert bridge already uses for ET signatures. See also
`docs/adr/0002-geo-spamhaus-parallel-pipeline.md`.

> ⚠️ **If you already added `geo_ru`/`geo_by`/... entries under `datasets:`
> in `suricata.yaml`** (an earlier version of this doc got this wrong):
> remove those 6 lines. Suricata datasets reject CIDR notation outright —
> `suricata -T` will fail with `dataset data parse failed ...: <cidr>`.
> The `defaults:`/`rules:` sub-sections already in your `datasets:` block
> are unrelated and should stay.

**1. Create the directories and rule file:**

```bash
sudo mkdir -p /var/lib/suricata/datasets /etc/suricata/iprep
sudo curl -o /etc/suricata/rules/geo-spamhaus.rules \
  https://raw.githubusercontent.com/litle-dragon/suricata/main/geo-spamhaus.rules
```

**2. Enable IP Reputation in `suricata.yaml`** — these are top-level keys,
siblings of `datasets:`/`vars:`/`rule-files:`, not nested inside any of
them (they're commented out by default in stock `suricata.yaml`, search for
`# IP Reputation`):

```yaml
reputation-categories-file: /etc/suricata/iprep/categories.txt
default-reputation-path: /etc/suricata/iprep
reputation-files:
  - geo-spamhaus-reputation.list
```

And add the new rule file to `rule-files:` alongside the ET ruleset:

```yaml
rule-files:
  - suricata.rules
  - geo-spamhaus.rules
```

**3. Install and schedule `update_geo_lists.py`** — fetches
[iwik.org](https://www.iwik.org/ipcountry/geoip.txt) (filtered to the
configured countries) and the Spamhaus DROP list, then writes **two kinds
of file**:

- `local_lists_dir` (default `/var/lib/suricata/datasets`) — plain
  `geo_<cc>.lst` / `spamhaus.lst`, one CIDR per line. Suricata does **not**
  read these; they're alert-bridge.py's own private copy for its local
  "covering range" lookup (`geo_lists.py`) — `iprep`, like the dataset
  approach it replaced, tells the demon *that* an IP matched a category,
  never *which* CIDR.
- `iprep_dir` (default `/etc/suricata/iprep`) — `categories.txt` (one row
  per country + Spamhaus) and `geo-spamhaus-reputation.list` (every CIDR
  above, tagged with its category), the files Suricata actually loads.

On a fetch failure for either source it leaves yesterday's `.lst` file
untouched, rebuilds `geo-spamhaus-reputation.list` from whatever is
currently on disk (so a partial outage never blanks the list), and sends a
Telegram warning. It then triggers a live `suricatasc -c reload-rules` —
covers both the rule reload and the IP Reputation data reload, no Suricata
restart:

```bash
sudo curl -o /opt/alert-bridge/update_geo_lists.py \
  https://raw.githubusercontent.com/litle-dragon/suricata/main/update_geo_lists.py
sudo curl -o /opt/alert-bridge/geo_lists.py \
  https://raw.githubusercontent.com/litle-dragon/suricata/main/geo_lists.py
sudo python3 /opt/alert-bridge/update_geo_lists.py   # first run — populates every file above
```

```bash
echo -e '#!/bin/sh\nCFG_FILE=/opt/alert-bridge/alert-bridge.cfg ENV_FILE=/opt/alert-bridge/env python3 /opt/alert-bridge/update_geo_lists.py' | sudo tee /etc/cron.daily/update-geo-lists
sudo chmod +x /etc/cron.daily/update-geo-lists
```

**4. Add the `[geo_spamhaus]` section** to `/opt/alert-bridge/alert-bridge.cfg`
(see `alert-bridge.cfg.example` for every key + default), validate, then
restart both services — `categories.txt` is only read at Suricata startup
(unlike the reputation list, it does **not** hot-reload):

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl restart alert-bridge
```

**5. MikroTik firewall rules** — two more permanent, no-timeout RAW drop
rules, one per category list (`suricata-geo-block` / `suricata-spamhaus-block`),
analogous to the `suricata-block` rule from Step 8c. IPv4 only — geo/Spamhaus
blocking deliberately doesn't cover IPv6 (see CONTEXT.md "Діапазон"):

```routeros
# For Single WAN (e.g. WAN2):
/ip firewall raw add chain=prerouting in-interface=WAN2 \
    src-address-list=suricata-geo-block action=drop comment="Suricata geo-block"
/ip firewall raw add chain=prerouting in-interface=WAN2 \
    src-address-list=suricata-spamhaus-block action=drop comment="Suricata Spamhaus-block"

# For Dual WAN (reuse the WAN-LIST interface list from Step 8c):
/ip firewall raw add chain=prerouting in-interface-list=WAN-LIST \
    src-address-list=suricata-geo-block action=drop comment="Suricata geo-block"
/ip firewall raw add chain=prerouting in-interface-list=WAN-LIST \
    src-address-list=suricata-spamhaus-block action=drop comment="Suricata Spamhaus-block"
```

From here, a GEO-BLOCK-\*/SPAMHAUS-BLOCK-\* alert is blocked on MikroTik
immediately and permanently on its first hit — no escalation, no cooldown
(see `docs/adr/0002-...`). Country/Spamhaus breakdowns show up in the 6-hour
digest, the 07:00 report, and `analyze_stats.py --geo`.

## Step 5 — Install the rules and verify

Download the free Emerging Threats Open ruleset (~50k signatures, refreshed
daily upstream):

```bash
sudo suricata-update
```

Validate the config — parses the YAML and loads every rule, the easiest way
to catch mistakes before restarting:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Then restart:

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

Check the capture interface:

```bash
sudo tcpdump -ni tzsp0 -c 5
```

**Nothing appears — that's expected.** The router isn't streaming yet.
Remember this command though: `tcpdump -ni tzsp0` is the single most useful
diagnostic in this entire project (see [Troubleshooting](#troubleshooting)).

Keep signatures fresh — schedule a weekly (or daily) update:

```bash
echo -e '#!/bin/sh\nsuricata-update && systemctl restart suricata' | sudo tee /etc/cron.weekly/suricata-rules
sudo chmod +x /etc/cron.weekly/suricata-rules
```

## Step 6 — Turn on the MikroTik sniffer

On the router (substitute your Suricata box IP and your WAN interface name):

```routeros
# For Single WAN (e.g. WAN2):
/tool sniffer set streaming-enabled=yes streaming-server=192.168.12.232:37008 \
    filter-stream=yes filter-interface=WAN2
/tool sniffer start

# For Dual WAN (e.g. WAN1, WAN2):
/tool sniffer set streaming-enabled=yes streaming-server=192.168.12.232:37008 \
    filter-stream=yes filter-interface=WAN1,WAN2
/tool sniffer start
```

- `streaming-enabled=yes` — stream packets over the network instead of
  writing them to a file.
- `streaming-server` — your Suricata box, UDP port 37008.
- `filter-interface` — mirror **only WAN interfaces** (`WAN2` or `WAN1,WAN2`). Never mirror the LAN
  interface the TZSP stream leaves through (packet loop).
- `filter-stream=yes` — tells the sniffer never to capture its own TZSP
  stream. Sniffing only the WAN is the seatbelt; this is the airbag.

Verify:

```routeros
/tool sniffer print
```

The sniffer does **not** survive a reboot, so add a scheduler that waits for
the WAN interface(s) to come up and then (re)starts it.

**Single WAN Scheduler:**
```routeros
/system scheduler add name=start-sniffer on-event=":local up 0; :local i 0; :while (\$i < 180) do={ :do { :if ([/interface get [find name=\"WAN2\"] running]) do={ :set up 1 } } on-error={}; :if (\$up = 1) do={ :set i 181 } else={ :delay 1s; :set i (\$i + 1) } }; :if (\$up = 1) do={ /tool sniffer stop; :delay 1s; /tool sniffer start }" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-time=startup
```

**Dual WAN Scheduler** (starts for both if both are ready, or only for the active WAN if only one is ready):
```routeros
/system scheduler add name=start-sniffer on-event=":local i 0; :local w1 false; :local w2 false; :while (\$i < 180 and (\$w1 = false and \$w2 = false)) do={ :do { :set w1 [/interface get [find name=\"WAN1\"] running] } on-error={}; :do { :set w2 [/interface get [find name=\"WAN2\"] running] } on-error={}; :if (\$w1 = false and \$w2 = false) do={ :delay 1s; :set i (\$i + 1) } }; :delay 3s; :do { :set w1 [/interface get [find name=\"WAN1\"] running] } on-error={}; :do { :set w2 [/interface get [find name=\"WAN2\"] running] } on-error={}; :local ifaces \"\"; :if (\$w1 and \$w2) do={ :set ifaces \"WAN1,WAN2\" } else={ :if (\$w1) do={ :set ifaces \"WAN1\" }; :if (\$w2) do={ :set ifaces \"WAN2\" } }; :if (\$ifaces != \"\") do={ /tool sniffer stop; :delay 1s; /tool sniffer set filter-interface=\$ifaces; /tool sniffer start }" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-time=startup
```

Back on the Linux box, packets should now be flowing:

```bash
sudo tcpdump -ni tzsp0 -c 10
```

**End-to-end test.** [testmynids.org](http://testmynids.org) returns a fake
`uid=0(root)` response designed to trigger a classic IDS signature. Watch the
log in one terminal:

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {sig: .alert.signature, src: .src_ip, dest: .dest_ip}'
```

…and trigger it from another:

```bash
curl -s http://testmynids.org/uid/index.html
```

You should see `GPL ATTACK_RESPONSE id check returned root` within seconds.
Note the *source* IP is the web server, not you: this rule matches the
**response** coming back, not your request. Suricata cares about packet
direction — some signatures fire on requests, others on responses.

## Step 6b (alternative) — Mirror with firewall mangle instead

`/tool sniffer` taps the WAN interface itself, which means it sees traffic
**after** source NAT: every LAN host shows up as your single public IP. That's
why Step 6 makes you put your public address in `HOME_NET`, and it's why an
alert only ever tells you "something behind your router did this" — never
*which* device.

An alternative is to mirror from the **firewall mangle** `forward` chain
instead. Mangle `forward` runs *after* dstnat but *before* srcnat, so both
rules see the **private** LAN address:

```routeros
/ip firewall mangle

add chain=forward in-interface-list=LAN out-interface=WAN2 \
    action=sniff-tzsp \
    sniff-target=192.168.12.232 sniff-target-port=37008 \
    comment="Suricata: LAN -> WAN, pre-srcnat"

add chain=forward in-interface=WAN2 out-interface-list=LAN \
    action=sniff-tzsp \
    sniff-target=192.168.12.232 sniff-target-port=37008 \
    comment="Suricata: WAN -> LAN, post-dstnat"
```

The difference is immediate once packets start flowing: a capture on `tzsp0`
shows individual `192.168.x.x` hosts as sources and destinations, and your
public IP appears nowhere. Under Step 6, that same traffic collapses to a
single public address. (Confirmed on RouterOS 7.x; `sniff-tzsp` has been
available since RouterOS 6.)

### What this changes

**Populate the `LAN` interface list first.** RouterOS ships this list
*empty*. If you skip this, both rules match nothing and you'll see zero
packets with no error anywhere. Add every LAN-side interface — your bridge,
or each VLAN individually if your LAN is segmented:

```routeros
/interface list member
add list=LAN interface=bridge
# …or, on a VLAN-segmented network, one line per VLAN:
# add list=LAN interface=vlan10
# add list=LAN interface=vlan20
```

Check what you actually have with `/interface print`. Whatever you leave out
is simply invisible to Suricata.

**Use `out-interface-list=LAN`, not `out-interface=LAN`,** in the return
rule — `out-interface` expects an interface *name*, and a list name silently
won't resolve.

**`HOME_NET` gets simpler.** Since Suricata now sees pre-NAT addresses, your
public IP is no longer required — the RFC1918 ranges already in the Step 4
`HOME_NET` cover your hosts. Leaving the public IP in place does no harm, so
if you're switching between the two methods, keep it.

**One rule pair per WAN.** These rules are scoped to a single interface
(`WAN2`). On a multi-WAN or failover router, traffic over the other uplink is
not mirrored — add a matching pair for each WAN you care about.

**`forward` only sees *forwarded* traffic.** This is the biggest blind spot,
and it's easy to miss. Packets addressed to the router *itself* — an inbound
port scan against your public IP, SSH/WebFig brute-forcing, anything not
port-forwarded to a LAN host — traverse `chain=input`, never `chain=forward`.
The two rules above will not mirror any of it.

That matters immediately: the `nmap` test in
[Step 9](#step-9--prove-the-whole-loop) targets your public IP, so with only
the `forward` pair it produces **nothing**. `/tool sniffer` catches this
traffic for free, because it taps the interface rather than a chain.

If you want that coverage back, add the router's own traffic too:

```routeros
/ip firewall mangle

add chain=input in-interface=WAN2 \
    action=sniff-tzsp \
    sniff-target=192.168.12.232 sniff-target-port=37008 \
    comment="Suricata: WAN -> router"

add chain=output out-interface=WAN2 \
    action=sniff-tzsp \
    sniff-target=192.168.12.232 sniff-target-port=37008 \
    comment="Suricata: router -> WAN"
```

Still no loop: the TZSP stream leaves via your LAN interface, not `WAN2`, so
the `output` rule doesn't match it. But keep `out-interface=WAN2` narrow — an
`output` rule scoped to the LAN interface *would* mirror the mirror.

**Loops are structurally impossible in `forward`.** The TZSP stream is
generated by the router itself, so it travels `output` — a `chain=forward`
rule can never mirror its own mirror. Mangle has no `filter-stream=yes`
equivalent, and for the `forward` pair none is needed; the `output` rule
above is the only one that needs care.

**A newly added rule may briefly show the `I` (invalid) flag** while RouterOS
resolves interface-list membership. It clears on its own within a few
seconds; re-run `/ip firewall mangle print` before assuming something's wrong.

### The FastTrack caveat — read this before choosing

This method does not *require* you to delete your FastTrack rule. But be
clear about what you get if you keep it: **FastTracked connections bypass the
mangle chains entirely.** Once a connection is fasttracked, its packets skip
`chain=forward` and are never mirrored.

In practice that means you still see connection setup — TCP handshakes, DNS,
TLS `ClientHello` (so SNI and JA3 survive), ICMP, and anything the FastTrack
rule doesn't cover — but not the bulk of an established session. Plenty of
signatures still fire; payload-inspection rules mostly won't.

So check your own router before choosing — this one command decides which row
you're in:

```routeros
/ip firewall filter print where action=fasttrack-connection
```

| Result | What to expect |
|---|---|
| **No rule** (empty output) — common on routers doing policy routing or mark-based multi-WAN, which are incompatible with FastTrack anyway | Full mirror of forwarded traffic, pre-NAT addresses |
| **A rule exists**, and you leave it alone | Partial mirror: connection setup and metadata only |
| **A rule exists**, and you want full coverage | You must exclude the traffic from FastTrack — at which point you're paying the CPU cost you were trying to avoid |

RouterOS's default firewall *does* ship a FastTrack rule, so unless you've
built your own ruleset, assume you're in the second row until you've checked.
If the output is empty, every packet crossing the chains you hooked will be
mirrored.

### Verifying

Rule counters are the fastest confirmation that the router side works:

```routeros
/ip firewall mangle print stats where action=sniff-tzsp
```

Every rule you added should show packets climbing. Then, on the Linux box,
confirm the addresses really are pre-NAT:

```bash
sudo tcpdump -ni tzsp0 -c 20 -nn
```

Sources and destinations should be `192.168.x.x`, not your public IP.

To remove the mirror later:

```routeros
/ip firewall mangle remove [find action=sniff-tzsp]
```

## Step 7 — Tune noisy rules

Every IDS grows a few noisy rules. Don't guess — measure. After a day or two,
rank alerts by signature:

```bash
sudo cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | "\(.alert.signature_id) \(.alert.signature)"' | sort | uniq -c | sort -rn | head
```

Typical offenders: STUN keepalives from Tailscale/Zoom/WebRTC. Suppress the
specific **signature IDs** (not the whole protocol) in
`/etc/suricata/threshold.config`:

```
suppress gen_id 1, sig_id 2016150
suppress gen_id 1, sig_id 2016149
```

```bash
sudo systemctl restart suricata
```

Rule of thumb: look at the source and destination first. STUN to Zoom or
Tailscale infrastructure is normal; STUN to a residential IP in a country
you've never communicated with might be the alert that matters. **Suppress
traffic you can explain — never traffic you're just tired of seeing.**

## Step 8 — The alert bridge: Telegram + auto-block

One Python script closes the loop: it tails `eve.json`, and for every
severity 1–2 alert it pushes the attacker's IP into a MikroTik firewall
address list via the REST API. It never messages per alert — instead it
records everything to a local SQLite database and pages Telegram only on an
anomaly spike, a fixed 6-hour digest, or the 07:00 daily report (see
[Step 8e](#8e-reports--analytics)).

Install it from this repo:

```bash
sudo mkdir /opt/alert-bridge/
sudo curl -o /opt/alert-bridge/alert-bridge.py https://raw.githubusercontent.com/litle-dragon/suricata/main/alert-bridge.py
sudo curl -o /opt/alert-bridge/analyze_stats.py https://raw.githubusercontent.com/litle-dragon/suricata/main/analyze_stats.py
sudo curl -o /opt/alert-bridge/env https://raw.githubusercontent.com/litle-dragon/suricata/main/env.example
sudo curl -o /opt/alert-bridge/alert-bridge.cfg https://raw.githubusercontent.com/litle-dragon/suricata/main/alert-bridge.cfg.example
sudo curl -o /etc/systemd/system/alert-bridge.service https://raw.githubusercontent.com/litle-dragon/suricata/main/alert-bridge.service
sudo chmod 600 /opt/alert-bridge/env
sudo systemctl daemon-reload
```

Secrets and per-deployment values (Telegram token, MikroTik credentials, WAN
IPs) live in `/opt/alert-bridge/env`. The template contains **no real
addresses** — every value is a placeholder (or empty) that you fill in
during the steps below, so the bridge does nothing until it's configured
for *your* network.

Blocking thresholds and other tunable behavior live separately in
`/opt/alert-bridge/alert-bridge.cfg` (INI format, every key commented with
its default and rationale in `alert-bridge.cfg.example`). It's optional —
delete it or leave any key out and the script falls back to the hardcoded
default — but the file is what you edit to tune sensitivity without
touching code. Two defaults worth knowing out of the box:
- `subnet_threshold = 5` — unique all-time attacker IPs in a `/24` before
  the whole subnet is blocked permanently (lowered from the original 10).
- `[subnet_multiday]` — a subnet active (≥2 unique IPs) on 2 or more
  distinct days is blocked permanently regardless of `subnet_threshold`,
  since a small crew coming back day after day is itself the threat
  signal, even if it never grows past a handful of IPs.

Restart after editing either file:
```bash
sudo systemctl restart alert-bridge
```

### 8a. Telegram bot

1. In Telegram, message **@BotFather** → `/newbot` → pick a name and a
   username ending in `bot` → copy the API token into `TG_TOKEN=`.
2. Send your new bot any message (this creates the chat).
3. Get the chat ID and put it into `TG_CHAT=`:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[-1].message.chat.id'
```

(Leave both empty if you want blocking without notifications.)

### 8b. RouterOS REST API

On the router, create a self-signed certificate so the API traffic is
encrypted:

```routeros
/certificate add name=rest-api common-name=192.168.12.200 days-valid=3650 \
    key-usage=digital-signature,key-encipherment,tls-server,key-cert-sign,crl-sign
/certificate sign rest-api
/certificate set rest-api trusted=yes
```

Create a dedicated API user, locked to the Suricata box's IP, with the
minimum permissions (generate your own strong password):

```routeros
/user group add name=suricata-api policy=read,write,api,rest-api
/user add name=suricata group=suricata-api password=<STRONG_PASSWORD> address=192.168.12.232/32
```

Enable the REST API (rides on `www-ssl`), restricted to the Suricata box:

```routeros
/ip service set www-ssl certificate=rest-api disabled=no address=127.0.0.1/32,192.168.12.232/32
```

> ⚠️ `www-ssl` is shared between WebFig and the REST API. If you use WebFig
> over HTTPS from other machines, include your LAN subnet in that address
> list **before** pressing Enter.

Put the router's LAN IP, user, and password into `/opt/alert-bridge/env` —
replace the `MT_HOST=YOUR_ROUTER_LAN_IP` placeholder with your router's
address (`192.168.12.200` in the examples above) and fill in `MT_USER=` and
`MT_PASS=`.

### 8c. Firewall drop rules

Two **RAW** rules — RAW runs before connection tracking, so blocked packets
are dropped with minimal CPU. Both are scoped to the WAN interface, so they
can never block your own LAN:

```routeros
# For Single WAN (e.g. WAN2):
/ip firewall raw add chain=prerouting in-interface=WAN2 \
    src-address-list=suricata-block action=drop comment="Suricata auto-block"
/ipv6 firewall raw add chain=prerouting in-interface=WAN2 \
    src-address-list=suricata-block action=drop comment="Suricata auto-block (v6)"

# For Dual WAN (create an Interface List containing both WANs):
/interface list add name=WAN-LIST
/interface list member add interface=WAN1 list=WAN-LIST
/interface list member add interface=WAN2 list=WAN-LIST

/ip firewall raw add chain=prerouting in-interface-list=WAN-LIST \
    src-address-list=suricata-block action=drop comment="Suricata auto-block"
/ipv6 firewall raw add chain=prerouting in-interface-list=WAN-LIST \
    src-address-list=suricata-block action=drop comment="Suricata auto-block (v6)"
```

### 8d. Start the bridge

Finish `/opt/alert-bridge/env` with your own public addresses so the bridge
can never block *you*. These ship **empty** in the template — set them to
your own values in CIDR notation (from the Prerequisites table), e.g.:

```
WAN_IP=203.0.113.1/32
WAN_IPV6_PREFIX=2001:db8:aaaa:1::/64
```

Leave `WAN_IPV6_PREFIX=` empty if you have no IPv6.

```bash
sudo systemctl enable --now alert-bridge
journalctl -u alert-bridge -f
```

Built-in safeguards:

- **Never blocks trusted addresses** — RFC1918, CGNAT, loopback, public DNS
  resolvers (1.1.1.1 / 8.8.8.8 / 9.9.9.9), and your own public IPs.
- **Every block expires** — 1-hour timeout; false positives self-heal.
- **Severity 1–2 only** — informational (severity 3) alerts are ignored.
- **Blocks are rate-limited** — a 5-minute cooldown per attacker+signature
  keeps an nmap scan from hammering the router with duplicate REST calls.
- **No per-alert paging** — Telegram fires only on an anomaly spike, a 6-hour
  digest, or the 07:00 daily report; reputation hits (`ET DROP` / `ET CINS` /
  `ET TOR`) are blocked but never page.
- **Subnet blocks use all-time uniqueness, not a daily window** — a `/24`
  reaching 10 distinct attacker IPs gets permanently blocked, even if those
  hits are spread across several days (not reset at midnight).
- **Every permanent block is audited** — a `permanent_blocks` table records
  every IP/subnet that ever got a permanent block and when, so
  `analyze_stats.py --list` can show the real addresses, not just a count.
- **State reconciled against the router, not just assumed** — once an IP's
  attempt count passes the permanent threshold, the bridge verifies against
  MikroTik's real block list before treating it as already-handled; a
  6-hour, end-of-slot pass catches anything a failed REST call missed.

> **If your LAN uses a different DNS resolver** (the router itself, an ISP
> resolver, a local Pi-hole), add it to the `WHITELIST` in `alert-bridge.py`.
> DNS-based malware rules fire on the *query*, so the "attacker" side of the
> flow resolves to your resolver — without the whitelist entry, a single
> severity-1 DNS alert would block your DNS for an hour.

### 8e. Reports & analytics

The bridge no longer sends a message per alert. Everything lands in a local
SQLite database at `/var/log/suricata/alert_bridge.db` (WAL mode, created
automatically on first run), and Telegram fires for only three things:

| Notification | Trigger |
|---|---|
| 🚨 **Anomaly spike** | Inbound alert rate over a sliding 5-minute window crosses `SPIKE_THRESHOLD_N` (default 500). 15-minute cooldown between spikes. |
| 📊 **6-hour digest** | Sent at each fixed clock slot — `00:00`, `06:00`, `12:00`, `18:00` — summarizing the slot that just ended. |
| 🌅 **Daily report** | Sent once at 07:00 for the previous full day. |

Tune the spike threshold in `/opt/alert-bridge/env`. To find a sensible `N`
for your network, watch your own background rate first:

```bash
# inbound alerts in the last 24h (divide by minutes to estimate the peak rate)
journalctl -u alert-bridge --since "24 hours ago" | grep -c "inbound-alert"
```

Set it above your normal background so only real floods page you:

```
SPIKE_THRESHOLD_N=500
```

Query the history any time with `analyze_stats.py` — it reads the SQLite
database directly, no log parsing:

```bash
sudo python3 /opt/alert-bridge/analyze_stats.py --sum              # every recorded day
sudo python3 /opt/alert-bridge/analyze_stats.py --day 2026-08-05   # one day, full breakdown
sudo python3 /opt/alert-bridge/analyze_stats.py --spikes           # anomaly spike log
sudo python3 /opt/alert-bridge/analyze_stats.py --top 20           # top attacker subnets + IPs all-time
```

Add `--list` to `--sum`/`--day` to print the actual addresses (new IPs, new
subnets, and anything permanently blocked that day) instead of just counts.
Large days get a 50-per-group terminal preview — pass `--list-out FILE` to
write the full, untruncated lists to a file instead:

```bash
sudo python3 /opt/alert-bridge/analyze_stats.py --day 2026-08-05 --list
sudo python3 /opt/alert-bridge/analyze_stats.py --day 2026-08-05 --list --list-out /tmp/2026-08-05.txt
```

`--sync-mikrotik` still works, now sourced from the all-time attacker history:
it permanently blocks any `/24` with `--min-ips` (default 10) unique attackers.

Once several adjacent `/24`s have been blocked, collapse them into wider
CIDRs directly on the router (e.g. two neighboring `/24`s become one `/23`):

```bash
sudo python3 /opt/alert-bridge/analyze_stats.py --merge-adjacent
```

## Step 9 — Prove the whole loop

From an **external** host (a VPS, or a phone hotspot — a scan from inside the
LAN never crosses the WAN, so the sniffer won't see it):

```bash
nmap -sS -sV -Pn <YOUR_PUBLIC_IP>
```

Within a couple of seconds: a Telegram message on your phone, and the
scanner's IP in the router's block list with the timeout counting down:

```routeros
/ip firewall address-list print where list=suricata-block
```

Every subsequent probe from that IP hits the RAW drop rule before conntrack
even sees it.

## Troubleshooting

`sudo tcpdump -ni tzsp0` is the dividing line:

**No packets on tzsp0?** The problem is *upstream* of Suricata:

```bash
systemctl status tzsp-receiver      # is the decode pipeline running?
```

…and check the router — `/tool sniffer print` should show `running: yes`
(it does not survive reboots without the scheduler from Step 6). If you used
Step 6b instead, check the rule counters: `/ip firewall mangle print stats
where action=sniff-tzsp`.

Work along the chain — each step rules out the one before it:

```bash
# 1. Is TZSP even arriving from the router?
sudo tcpdump -ni any udp port 37008 -c 10

# 2. Is tzsp2pcap listening?
sudo ss -ulnp | grep 37008
```

**TZSP arrives, but tzsp0 stays silent — and `tcpreplay` claims success.**
This one is nasty, because nothing reports an error. `tcpreplay` prints a
healthy-looking `Successful packets: N / Failed packets: 0` while *zero*
packets actually reach the interface. The giveaway is in the journal
(`journalctl -u tzsp-receiver`), repeating on a loop:

```
TP_STATUS_WRONG_FORMAT occures O_o. Frame 1660, pkt len 70
```

`tcpreplay` (4.5.x, as packaged by Debian/Ubuntu) is built with AF_PACKET
`TX_RING` support, and on recent kernels that path fails against the `dummy`
driver: it wedges in a retry loop, discards the frames, and still reports
them as sent. Confirm the interface itself is fine — this injects 25 frames
with a plain `sendto()` and they *will* show up in a concurrent
`tcpdump -ni tzsp0`:

```bash
sudo python3 -c "
import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind(('tzsp0', 0))
for _ in range(25): s.send(b'\xde\xad\xbe\xef\x00\x01\xde\xad\xbe\xef\x00\x02\x08\x00' + b'A'*50)
"
```

If those 25 arrive but `tcpreplay` output doesn't, the TX ring is the culprit.
There is no runtime flag to disable it — rebuild `tcpreplay` without
`--enable-tx-ring`, or replace it in `tzsp-receiver.service` with any injector
that uses plain `sendto()`. Lowering the `tzsp0` MTU does **not** help.

**Packets arriving but no alerts?** The problem is *inside* Suricata:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml   # config still valid?
```

- Is your **current** public IP still in `HOME_NET`? (If your ISP address
  changed, update `suricata.yaml` and `/opt/alert-bridge/env`.)
- Is `checksum-checks: no` set on the af-packet interface?

**Blocks not landing on the router?** `journalctl -u alert-bridge -f` shows
every REST call and error.

Useful one-liners:

```bash
# Live alerts, human-readable
sudo tail -f /var/log/suricata/fast.log

# Live alerts, structured
sudo tail -f /var/log/suricata/eve.json | jq -c 'select(.event_type=="alert") | {sig:.alert.signature, sev:.alert.severity, src:.src_ip, dst:.dest_ip}'

# Unblock an IP immediately (on the router)
/ip firewall address-list remove [find list=suricata-block address=1.2.3.4]

# Pause everything (on the router — IDS goes idle, internet unaffected)
/tool sniffer stop
```

## Honest caveats

1. **Reactive, not inline.** The first packets always get through; detection
   comes first, then the block. For a home network that's the right
   trade-off — an inline IPS that crashes takes your internet with it.
2. **Signature-based.** It catches what somebody has written a rule for:
   known C2 servers, reputation-listed IPs, scanner fingerprints, cleartext
   credential leaks. A brand-new zero-day with no signature won't alert.
   You still need patches, backups, and sensible practices.
3. **It does not decrypt HTTPS.** It works from metadata — DNS, TLS SNI, JA3
   fingerprints, certificates, traffic patterns. That's usually enough, and
   your payloads stay private. LAN-to-LAN traffic is also invisible (only
   WAN crossings are mirrored).
4. **Watch router CPU on small devices.** Mirroring is cheap (an RB5009 sits
   around 3%), but on a hEX pushing close to line rate, check the headroom.
5. **Automation deserves supervision.** Review your alerts occasionally,
   tune false positives, investigate surprises. The goal isn't to replace
   you — it's to make sure you only look at the interesting events.

## Files in this repo

| File | Purpose |
|---|---|
| [`alert-bridge.py`](alert-bridge.py) | Tails `eve.json`, blocks attackers via the MikroTik REST API, records to SQLite, and pages Telegram on spikes/digests |
| [`alert-bridge.service`](alert-bridge.service) | systemd unit for the bridge |
| [`analyze_stats.py`](analyze_stats.py) | Queries the SQLite database — daily summaries, spike log, top attackers, real addresses, subnet cleanup (`--sum` / `--day` / `--spikes` / `--top` / `--list` / `--list-out` / `--sync-mikrotik` / `--merge-adjacent` / `--verify-blocks` / `--fix`) |
| [`sync-state-from-journal.py`](sync-state-from-journal.py) | Legacy — rebuilt the old JSON state from `journalctl`; unused since the SQLite migration |
| [`migrate_json_to_sqlite.py`](migrate_json_to_sqlite.py) | One-time — seeds SQLite `seen_ips`/`seen_subnets` from the legacy JSON state so day one isn't all "new" |
| [`env.example`](env.example) | Secrets/deployment template (Telegram, MikroTik, WAN IPs) → copy to `/opt/alert-bridge/env` |
| [`alert-bridge.cfg.example`](alert-bridge.cfg.example) | Blocking/anomaly threshold template → copy to `/opt/alert-bridge/alert-bridge.cfg` |
