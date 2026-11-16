# C3Hole - a DNS ad-blocker for the ESP32-C3 (no PSRAM, ~$2)

C3Hole answers your network's DNS queries and sinks ads/trackers/malware domains.
Hash-in-flash + Bloom filter instead of a string table in RAM, so a 250K-domain list
fits on a bare ESP32-C3 SuperMini.

| | string-in-RAM approach | C3Hole |
|---|---|---|
| Hardware | ESP32 + PSRAM (~$8) | ESP32-C3, no PSRAM (~$2) |
| Storage | ~2.5 MB RAM for 141K domains | 5 bytes/domain in flash: 0.67 MiB for 141K, 1.21 MiB for 253K |
| RAM | most of it | ~57 KB static + Bloom filter (default 128 KB, adjustable) |
| Lookup | string compare | Bloom filter first; flash only on a possible hit (binary search, memory-mapped) |
| Collisions | n/a | 40-bit hashes; expected < 0.03 collisions at 253K (0 in the test list) |
| Upstream | blocking, 1 query at a time | async, 32 concurrent; failover to a secondary, or ask both at once; your own server (`ip:port`) works |
| Updates | - | blocklist **and** firmware over the air (HTTPS or upload) |

Domains block their subdomains automatically (`ads.example.com` is blocked when `example.com` is listed).

## Measured on the host test suite (`sh tests/run_tests.sh`, 139 checks)

* 253,000-domain list: every listed domain found, 0 false blocks in 200,000 random lookups.
* Share of non-blocked lookups settled by the Bloom filter alone (0 flash reads) at 253K domains:
  **64 KB: 38 %, 128 KB: 74 %, 256 KB: 96 %.** The 93 % figure in the comparison above needs a
  bigger filter than 128 KB once the list grows past ~141K domains; this is why the size is a
  dashboard setting (0 = automatic from free heap). The result is always correct either way;
  a bigger filter only saves flash reads.
* 32 simultaneous queries to a 250 ms upstream finish in ~252 ms (sequential: 8,000 ms).
* Firmware links against the real Arduino-ESP32 2.0.17 / ESP-IDF 4.4 SDK with the Espressif
  RISC-V GCC 8.4 toolchain: **1,101,840 bytes in a 1,310,720-byte OTA slot (84 %)**.

## Flash layout (4 MB)

    0x009000 nvs        16 KB     Wi-Fi calibration
    0x00d000 otadata     8 KB
    0x00f000 cfg         4 KB     your settings (key=value text)
    0x010000 app0      1280 KB    firmware slot A   } firmware OTA
    0x150000 app1      1280 KB    firmware slot B   }
    0x290000 blocklist 1472 KB    raw sorted hashes, up to 301,456 domains

No filesystem: the blocklist partition is read directly (memory-mapped).
A new list is downloaded twice: pass 1 only verifies its SHA-256, pass 2 writes it,
and the header is written last, so an interrupted update never leaves a half-valid list.

## Quick start (no software to install)

1. Create a **public** GitHub repository and upload this whole folder (keep `.github`).
2. **Actions > Build C3Hole > Run workflow.** About 15 minutes.
3. Download `C3HoleFlasher.exe` from the repo's **Releases** page (tag `latest`).
4. Run it, plug in the board, enter Wi-Fi name/password, click **FLASH**.
   Leave the dashboard password blank to get a strong generated one.
5. Open the dashboard it shows (`http://c3hole.local`, user `admin`) and point your router's DNS at the device IP.

Auto-update: put this in the flasher's *Auto-update URL* (or later in the dashboard) and the device
re-downloads the weekly list by itself:

    https://github.com/suf1/c3hole/releases/download/latest/blocklist.bin

Firmware OTA works the same way with `.../firmware.bin` (dashboard > Settings > Firmware URL,
then **Update firmware from URL**) or by uploading `firmware.bin` in the dashboard.

## Build by hand (PlatformIO)

    pip install platformio cryptography
    python tools/make_ca_bundle.py                  # Mozilla CA list for HTTPS updates
    python tools/build_blocklist.py build/blocklist.bin \
        https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
        https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt
    pio run -e c3

Flash with the flasher .exe or `esptool` using the offsets above. Without the flasher the device
starts a setup Wi-Fi `C3Hole-Setup` (http://192.168.4.1) where you enter your Wi-Fi and dashboard password.

## Getting more blocked, and why ads sometimes still appear

Blocked share is not a quality score (15-35 % is normal; it depends on what your devices do). What matters is ads that
get through. The usual reasons, most likely first:

1. **A device is not really using C3Hole.** The dashboard's *Clients* list shows every device that asked; a phone or PC
   that is missing, or has tiny counts, is using another resolver. Typical culprits: a second DNS server in the router/DHCP
   settings (devices switch to it when C3Hole is briefly unreachable and stay for minutes), browser "Secure DNS"/DoH,
   Android "Private DNS", iCloud Private Relay, apps and TVs with built-in DNS, and an **IPv6 DNS server advertised by the
   router** (C3Hole is IPv4-only; turn off IPv6 DNS advertisement or IPv6 in the router).
2. **Cached answers.** `ipconfig /flushdns` and restart the browser after changing anything.
3. **First-party ads.** YouTube video ads, sponsored posts in Facebook/Instagram feeds and similar come from the same
   domains as the content. No DNS blocker can remove them.
4. **CNAME cloaking** - a harmless-looking name that secretly points to a tracker. Handled: every upstream reply's CNAME
   chain is checked against the list (*Cloaked trackers caught* on the dashboard).
5. **Encrypted-DNS bypass.** C3Hole answers NXDOMAIN for `use-application-dns.net` (Firefox) and `mask.icloud.com` /
   `mask-h2.icloud.com` (iCloud Private Relay), which is the standard signal to turn those features off on a network
   (iOS will say Private Relay is unavailable here). Chrome/Edge "Secure DNS" and Android "Private DNS" must be switched off by hand.
6. **The domain is not on the list.** Add your own in `custom/block.txt`, or add a bigger source in the workflow
   (for example Hagezi `pro.plus`); the builder refuses a list larger than the device holds (301,456 domains).
   More lists block more but also break more sites; keep `custom/allow.txt` for exceptions.
7. **No TCP:53.** If an upstream reply is too big, a client retries over TCP and C3Hole does not answer it. The dashboard
   counts these as *Truncated replies (need TCP)*; if that number grows, TCP support is worth adding.
8. **Outages.** While the device is offline (see *Wi-Fi drops*), clients with another DNS server use it. Use only C3Hole
   in DHCP, give it a DHCP reservation, and for redundancy run **two** C3Holes as primary and secondary DNS.

Quick checks from a PC: `nslookup doubleclick.net <C3Hole IP>` must answer 0.0.0.0 every time, and
`Get-DnsClientServerAddress` must list only the C3Hole address for IPv4 *and* IPv6.

## Upstream DNS (including your own server)

Pick a provider preset or type any IPv4 address, optionally with a port: `192.168.0.5` or `192.168.0.5:5353`
(AdGuard Home, Unbound, Pi-hole, dnsmasq...). Two modes: *primary, then secondary after the failover timeout*
(default 800 ms) or *ask both at once, first answer wins* (best against a flaky resolver, double the upstream traffic).
Replies are accepted only from the configured IP **and** port. An upstream cannot be the device itself.
Default: 8.8.8.8 + 9.9.9.9 (two providers).

## Radio and cooling

* **Wi-Fi transmit power**, 2 to 19.5 dBm (default 11). Lower runs cooler; on SuperMini boards with weak antennas,
  8.5 dBm often makes Wi-Fi *more* stable.
* **Wi-Fi power save**: off (fastest, default), minimum or maximum modem sleep (cooler, but adds latency to replies).
* **CPU speed**: 160 MHz (default) or 80 MHz (cooler; applies after reboot).
* The dashboard shows chip temperature.

## Dashboard and safety

* Password login (HTTP Basic): salted SHA-256 hash stored, never the password; 5 failed logins = 30 s lockout.
* **Open dashboard (no password)** is optional: choose "none" in the flasher, tick it on the setup page, or use
  *Remove password* in the dashboard. Anyone on your Wi-Fi can then change settings and install firmware. In this mode
  requests are only accepted when addressed to an IP or `<hostname>.local` (blocks DNS-rebinding from web pages).
* All state-changing requests need an `X-C3H` header (blocks cross-site form posts).
* The dashboard is plain HTTP on your LAN: do not port-forward it.
* Hold the BOOT button for 5 s while running to erase all settings.
* Names shown in "recently blocked" come from network clients and are sanitised.

## If the dashboard disappears after a while

Version 1.0.0 had a bug: after any Wi-Fi drop it called `WiFi.reconnect()` every second, which restarts the connection
attempt each time, so a brief glitch could become a permanent outage until power-cycled. Fixed: the stack now reconnects by
itself, the firmware only steps in after 45 s, and reboots after 5 min offline. Also fixed: mDNS (`c3hole.local`)
stopped answering after a reconnect; the memory reserve was too small (Bloom filter now leaves 64 KB); a low-memory guard
gives the Bloom filter back if the heap runs short.

If it ever happens again, open the dashboard when it is back and read **System health**:

| Shows | Means |
|---|---|
| Last restart reason: BROWNOUT | weak USB power - use a better charger/cable |
| CRASH (panic) / watchdog | firmware fault - please report with the serial log |
| Wi-Fi drops, reason 200 / 201 | beacon timeout / AP not found: weak signal, or TX power too high/low for the antenna |
| Wi-Fi drops, reason 2, 4, 15 | authentication/handshake expired: router or roaming problem |
| Low-memory events > 0 | heap ran short: lower the Bloom filter size |

With a USB serial monitor attached it also logs a status line every minute and every Wi-Fi loss with its reason code.
Give the device a DHCP reservation in your router so its IP never changes.

## Limits you should know

* DNS over UDP only (no TCP:53 fallback, no DoH/DoT). Clients that insist on DoH bypass any DNS blocker.
* No DNS cache; every non-blocked query goes upstream.
* No TCP:53 (see the truncated-replies counter).
* Manual blocklist upload erases the old list first (a failed upload leaves the device with no list until retried);
  the HTTPS update path is safe because it verifies before erasing.
* Not run on hardware by the author of this package: see "Verification status".

## Verification status

Done: 139 automated host checks (also run under AddressSanitizer/UBSan) (hashing, Bloom, matcher, config, DNS packets, real UDP async tests,
Python-built lists/config read by the C++ code); full compile + link of the firmware with the real toolchain
and SDK; partition table validated with Espressif's `gen_esp32part.py`; flasher logic, validation and GUI
exercised with a simulated esptool.

Not done (needs your hardware / GitHub): running on a real ESP32-C3 (Wi-Fi, flash mapping, TLS, heap numbers),
the PlatformIO build itself, and building the Windows `.exe`. The workflow runs a self-test of the finished
`.exe`, so a broken build fails visibly instead of shipping.

## Layout

    src/main.cpp         Arduino glue: Wi-Fi, web dashboard, updates, tasks
    src/core/            portable engine (SHA-256, hash, Bloom, matcher, config, DNS) - unit tested on a PC
    src/web_ui.h         embedded dashboard
    tools/               blocklist builder, CA bundle tool, settings-blob writer
    flasher/             the Windows GUI flasher (Python/tkinter + esptool)
    custom/              your own block.txt / allow.txt, merged into the weekly build
    ci/, .github/        build scripts and workflow
    tests/               host tests (`sh tests/run_tests.sh`)

MIT license. `tools/gen_crt_bundle.py` is from Espressif's arduino-esp32 (Apache-2.0).
