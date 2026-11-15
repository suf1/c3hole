"""Collect firmware, blocklist and boot files into flasher/assets and write manifest.json.

usage: python ci/collect_assets.py <blocklist.bin> <assets_dir>     (run from the project root, after `pio run`)
"""
import glob
import json
import os
import re
import shutil
import struct
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def parse_partitions(path):
    parts = {}
    for line in open(path, encoding="utf-8"):
        line = line.split("#")[0].strip()
        cols = [c.strip() for c in line.split(",")]
        if len(cols) >= 5 and cols[0]:
            parts[cols[0]] = (int(cols[3], 0), int(cols[4], 0))
    return parts


def main(blocklist, assets):
    os.makedirs(assets, exist_ok=True)
    build = os.path.join(ROOT, ".pio", "build", "c3")
    for name in ("bootloader.bin", "partitions.bin", "firmware.bin"):
        shutil.copy(os.path.join(build, name), os.path.join(assets, name))
    hits = glob.glob(os.path.expanduser("~/.platformio/packages/framework-arduinoespressif32*/tools/partitions/boot_app0.bin"))
    if not hits:
        raise SystemExit("boot_app0.bin not found in the PlatformIO framework package")
    shutil.copy(hits[0], os.path.join(assets, "boot_app0.bin"))
    shutil.copy(blocklist, os.path.join(assets, "blocklist.bin"))

    parts = parse_partitions(os.path.join(ROOT, "partitions.csv"))
    for need in ("otadata", "cfg", "app0", "blocklist"):
        if need not in parts:
            raise SystemExit("partitions.csv has no '%s' partition" % need)
    fw_size = os.path.getsize(os.path.join(assets, "firmware.bin"))
    if fw_size > parts["app0"][1]:
        raise SystemExit("firmware (%d bytes) does not fit the app slot (%d bytes)" % (fw_size, parts["app0"][1]))
    with open(blocklist, "rb") as f:
        head = f.read(48)
    if head[:4] != b"C3HL":
        raise SystemExit("blocklist.bin has no C3HL header")
    domains = struct.unpack_from("<I", head, 8)[0]
    bl_size = os.path.getsize(blocklist)
    if bl_size > parts["blocklist"][1]:
        raise SystemExit("blocklist (%d bytes) does not fit its partition (%d bytes)" % (bl_size, parts["blocklist"][1]))
    ini = open(os.path.join(ROOT, "platformio.ini"), encoding="utf-8").read()
    m = re.search(r'C3HOLE_VERSION=\\"([^"\\]+)\\"', ini)
    man = {
        "built_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "version": m.group(1) if m else "?",
        "app_offset": parts["app0"][0],
        "otadata_offset": parts["otadata"][0],
        "cfg_offset": parts["cfg"][0],
        "blocklist_offset": parts["blocklist"][0],
        "blocklist_size": parts["blocklist"][1],
        "blocklist_domains": domains,
        "blocklist_bytes": bl_size,
        "firmware_bytes": fw_size,
        "app_slot_bytes": parts["app0"][1],
    }
    json.dump(man, open(os.path.join(assets, "manifest.json"), "w"), indent=2)
    print(json.dumps(man, indent=2))
    print("firmware uses %.0f%% of its OTA slot" % (100.0 * fw_size / parts["app0"][1]))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
