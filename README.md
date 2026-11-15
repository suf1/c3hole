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
| Upstream | blocking, 1 query at a time | async, 32 concurrent, retry on secondary, per-query timeout |
| Updates | - | blocklist **and** firmware over the air (HTTPS or upload) |

Domains block their subdomains automatically (`ads.example.com` is blocked when `example.com` is listed).

## Measured on the host test suite (`sh tests/run_tests.sh`, 109 checks)

* 253,000-domain list: every listed domain found, 0 false blocks in 200,000 random lookups.
* Share of non-blocked lookups settled by the Bloom filter alone (0 flash reads) at 253K domains:
  **64 KB: 38 %, 128 KB: 74 %, 256 KB: 96 %.** The 93 % figure in the comparison above needs a
  bigger filter than 128 KB once the list grows past ~141K domains; this is why the size is a
  dashboard setting (0 = automatic from free heap). The result is always correct either way;
  a bigger filter only saves flash reads.
* 32 simultaneous queries to a 250 ms upstream finish in ~252 ms (sequential: 8,000 ms).
* Firmware links against the real Arduino-ESP32 2.0.17 / ESP-IDF 4.4 SDK with the Espressif
  RISC-V GCC 8.4 toolchain: **1,088,864 bytes in a 1,310,720-byte OTA slot (83 %)**.

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

    https://github.com/<you>/<repo>/releases/download/latest/blocklist.bin

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

## Dashboard and safety

* HTTP Basic auth, salted SHA-256 password hash stored (never the password), 5 failed logins = 30 s lockout.
* All state-changing requests need an `X-C3H` header (blocks cross-site form posts).
* The dashboard is plain HTTP on your LAN: do not port-forward it.
* Hold the BOOT button for 5 s while running to erase all settings.
* Names shown in "recently blocked" come from network clients and are sanitised.

## Limits you should know

* DNS over UDP only (no TCP:53 fallback, no DoH/DoT). Clients that insist on DoH bypass any DNS blocker.
* No DNS cache; every non-blocked query goes upstream.
* Manual blocklist upload erases the old list first (a failed upload leaves the device with no list until retried);
  the HTTPS update path is safe because it verifies before erasing.
* Not run on hardware by the author of this package: see "Verification status".

## Verification status

Done: 109 automated host checks (hashing, Bloom, matcher, config, DNS packets, real UDP async tests,
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
    ci/, .github/        build scripts and workflow
    tests/               host tests (`sh tests/run_tests.sh`)

MIT license. `tools/gen_crt_bundle.py` is from Espressif's arduino-esp32 (Apache-2.0).
