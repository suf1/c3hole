"""C3Hole Flasher 2.0 - non-UI logic: validation, flashing job, self-test.

Everything needed (firmware, bootloader, partition table, blocklist, esptool) is bundled into the executable by the
CI workflow. Settings are written to the device's `cfg` partition, the blocklist to its raw `blocklist` partition.
The interface is a small Material-style toolkit drawn with the standard library (see mdui.py).
"""
import base64
import io
import json
import os
import queue
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import webbrowser

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import serial
from serial.tools import list_ports

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import cfgblob  # noqa: E402

APP_NAME = "C3Hole Flasher"
APP_VERSION = "2.0"
ESPRESSIF_VID = 0x303A


# --------------------------------------------------------------------- assets
def base_dir():
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def asset(name):
    return os.path.join(base_dir(), "assets", name)


def load_manifest():
    with open(asset("manifest.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def settings_path():
    root = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(root, "C3HoleFlasher", "settings.json")


def load_settings():
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(d):
    try:
        os.makedirs(os.path.dirname(settings_path()), exist_ok=True)
        with open(settings_path(), "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass


# --------------------------------------------------------------------- validation
UPSTREAM = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?$")

PRESETS = [  # name, upstream 1, upstream 2
    ("Google + Quad9 (two providers)", "8.8.8.8", "9.9.9.9"),
    ("Google (8.8.8.8)", "8.8.8.8", "8.8.4.4"),
    ("Quad9 (9.9.9.9)", "9.9.9.9", "149.112.112.112"),
    ("Cloudflare (1.1.1.1)", "1.1.1.1", "1.0.0.1"),
    ("AdGuard DNS", "94.140.14.14", "94.140.15.15"),
    ("OpenDNS", "208.67.222.222", "208.67.220.220"),
    ("My own server...", "", ""),
]


def valid_upstream(s):
    """'1.2.3.4' or '1.2.3.4:5353' (your own resolver)."""
    m = UPSTREAM.match(s)
    if not m:
        return False
    if not all(0 <= int(g) <= 255 for g in m.groups()[:4]):
        return False
    if m.group(5) is not None and not 1 <= int(m.group(5)) <= 65535:
        return False
    return s.split(":")[0] != "0.0.0.0"


FIELD_ORDER = ["ssid", "wifi_pass", "dash_pass", "up1", "up2", "bl_url", "fw_url", "bl_hours", "bloom_kb", "up_timeout", "bl_file"]
FIELD_PAGE = {"ssid": 0, "wifi_pass": 0, "dash_pass": 0, "bl_url": 0, "bl_hours": 0, "bl_file": 0,
              "up1": 1, "up2": 1, "up_timeout": 1, "bloom_kb": 1, "fw_url": 2}


def _num(v, key, lo, hi, msg):
    try:
        n = int(v[key])
    except ValueError:
        return "Hours, Bloom KB and failover timeout must be numbers."
    return None if lo <= n <= hi else msg


def field_errors(v, blocklist_size_limit, blocklist_path=None):
    """Returns {field: message} for every field that is currently invalid (first problem per field)."""
    e = {}
    ssid = v["ssid"]
    if not ssid:
        e["ssid"] = "Enter your Wi-Fi network name."
    elif len(ssid.encode()) > 32:
        e["ssid"] = "SSID is too long (max 32 bytes)."
    elif re.search(r"[\r\n\x00]", ssid):
        e["ssid"] = "Wi-Fi settings must not contain line breaks."
    wp = v["wifi_pass"]
    if wp and len(wp) < 8:
        e["wifi_pass"] = "Wi-Fi password must be at least 8 characters (or empty for an open network)."
    elif len(wp.encode()) > 63:
        e["wifi_pass"] = "Wi-Fi password is too long (max 63 bytes)."
    elif re.search(r"[\r\n\x00]", wp):
        e["wifi_pass"] = "Wi-Fi settings must not contain line breaks."
    dp = v["dash_pass"]
    if dp and not v.get("no_auth"):
        if not 8 <= len(dp) <= 60:
            e["dash_pass"] = "Dashboard password must be 8-60 characters."
        elif not re.fullmatch(r"[\x20-\x7E]+", dp):
            e["dash_pass"] = "Dashboard password: plain ASCII characters only."
    if not valid_upstream(v["up1"]):
        e["up1"] = "Upstream DNS 1 must be an IPv4 address, optionally with :port (e.g. 192.168.0.5:5353)."
    if v["up2"] and not valid_upstream(v["up2"]):
        e["up2"] = "Upstream DNS 2 must be an IPv4 address, optionally with :port."
    for key, label in (("bl_url", "Blocklist URL"), ("fw_url", "Firmware URL")):
        u = v[key]
        if u and (len(u) > 159 or not re.match(r"^https?://\S+$", u)):
            e[key] = "%s must start with http:// or https:// (max 159 characters)." % label
    for key, lo, hi, msg in (("bl_hours", 0, 8760, "Update interval must be 0-8760 hours."),
                             ("bloom_kb", 0, 400, "Bloom filter must be 0-400 KB (0 = automatic)."),
                             ("up_timeout", 100, 5000, "Failover timeout must be 100-5000 ms.")):
        m = _num(v, key, lo, hi, msg)
        if m:
            e[key] = m
    if blocklist_path:
        try:
            with open(blocklist_path, "rb") as f:
                head = f.read(48)
            size = os.path.getsize(blocklist_path)
        except OSError as ex:
            e["bl_file"] = "Cannot read blocklist file: %s" % ex
        else:
            if head[:4] != b"C3HL":
                e["bl_file"] = "That file is not a C3Hole blocklist (missing C3HL header)."
            elif size > blocklist_size_limit:
                e["bl_file"] = "That blocklist is too large for this firmware's partition."
    return e


def validate(v, blocklist_size_limit, blocklist_path=None):
    """Returns the first error message (in form order) or None."""
    e = field_errors(v, blocklist_size_limit, blocklist_path)
    for k in FIELD_ORDER:
        if k in e:
            return e[k]
    return None


# --------------------------------------------------------------------- helpers
class LineWriter(io.TextIOBase):
    """File-like object that forwards complete lines (\\n or \\r separated)."""

    def __init__(self, cb):
        self.cb, self.buf, self._in = cb, "", False

    def writable(self):
        return True

    def write(self, s):
        if self._in:
            return len(s)
        self._in = True
        try:
            self.buf += s
            while True:
                m = re.search(r"[\r\n]", self.buf)
                if not m:
                    break
                line, self.buf = self.buf[:m.start()], self.buf[m.end():]
                if line.strip():
                    self.cb(line)
        finally:
            self._in = False
        return len(s)

    def flush(self):
        pass

    def isatty(self):
        return False


def run_esptool(argv, on_line):
    import esptool
    old = (sys.stdout, sys.stderr)
    sys.stdout = sys.stderr = LineWriter(on_line)
    try:
        esptool.main(argv)
    except SystemExit as e:
        if e.code not in (0, None):
            raise RuntimeError("esptool exited with code %s" % e.code)
    finally:
        sys.stdout, sys.stderr = old


def list_ports_info():
    out = []
    for p in list_ports.comports():
        is_esp = p.vid == ESPRESSIF_VID
        out.append((0 if is_esp else 1, p.device, "%s - %s" % (p.device, p.description or "serial port"), is_esp))
    out.sort()
    return [(dev, label, esp) for _, dev, label, esp in out]


def capture_boot(port, seconds, on_line, stop):
    """Read the device's serial log; return its IP address once it has joined Wi-Fi."""
    ip, t0, ser, buf, ip_at = None, time.time(), None, "", None
    while time.time() - t0 < seconds and not stop.is_set():
        if ser is None:
            try:
                ser = serial.Serial()
                ser.port, ser.baudrate, ser.timeout = port, 115200, 0.5
                ser.dtr = False
                ser.rts = False
                ser.open()
            except Exception:
                ser = None
                time.sleep(0.5)
                continue
        try:
            chunk = ser.read(256)
        except Exception:
            try:
                ser.close()
            except Exception:
                pass
            ser = None
            time.sleep(0.5)
            continue
        if chunk:
            buf += chunk.decode("utf-8", "replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if line:
                    on_line("device: " + line)
                m = re.search(r"ip=(\d+\.\d+\.\d+\.\d+)", line)
                if m and not m.group(1).startswith("0."):
                    ip, ip_at = m.group(1), time.time()
        if ip and time.time() - ip_at > 2:
            break
    if ser:
        try:
            ser.close()
        except Exception:
            pass
    return ip


def check_login(host, password):
    """True/False if the dashboard accepts the password (None if open or unreachable)."""
    headers = {}
    if password:
        headers["Authorization"] = "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
    req = urllib.request.Request("http://%s/api/status" % host, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        return False if e.code in (401, 403) else None
    except Exception:
        return None


# --------------------------------------------------------------------- worker
FILE_NAMES = ["bootloader", "partition table", "boot data", "firmware", "settings", "blocklist"]


def flash_job(cfg, q, stop):
    log = lambda s: q.put(("log", s))
    prog = lambda v: q.put(("progress", v))
    stage = lambda i, st: q.put(("stage", i, st))
    status = lambda t: q.put(("status", t))
    result = {"ip": None, "password": None if cfg["no_auth"] else cfg["dash_pass"], "login": None,
              "generated": cfg["generated"], "no_auth": cfg["no_auth"]}
    try:
        man = load_manifest()
        stage(0, "active")
        status("Preparing settings...")
        prog(2)
        blob = cfgblob.build_cfg(cfg["ssid"], cfg["wifi_pass"], cfg["dash_pass"], bloom_kb=int(cfg["bloom_kb"]),
                                 up1=cfg["up1"], up2=cfg["up2"] or "", bl_url=cfg["bl_url"], fw_url=cfg["fw_url"],
                                 bl_hours=int(cfg["bl_hours"]), no_auth=cfg["no_auth"], tx_power=int(cfg["tx_power"]),
                                 ps_mode=int(cfg["ps_mode"]), cpu_mhz=int(cfg["cpu_mhz"]), up_mode=int(cfg["up_mode"]),
                                 up_timeout=int(cfg["up_timeout"]))
        tmp = tempfile.mkdtemp(prefix="c3hole_")
        cfg_path = os.path.join(tmp, "cfg.bin")
        with open(cfg_path, "wb") as f:
            f.write(blob)
        bl_path = cfg["blocklist_path"] or asset("blocklist.bin")

        files = [(0x0, asset("bootloader.bin")), (0x8000, asset("partitions.bin")),
                 (man["otadata_offset"], asset("boot_app0.bin")), (man["app_offset"], asset("firmware.bin")),
                 (man["cfg_offset"], cfg_path), (man["blocklist_offset"], bl_path)]
        sizes = [os.path.getsize(p) for _, p in files]
        total = float(sum(sizes))
        state = {"idx": -1}
        stage(0, "done")

        def on_es(line):
            log(line)
            if line.startswith("Compressed"):
                state["idx"] += 1
                if 0 <= state["idx"] < len(FILE_NAMES):
                    status("Writing %s..." % FILE_NAMES[state["idx"]])
            m = re.search(r"Writing at 0x[0-9a-fA-F]+\.\.\. \((\d+) %\)", line)
            if m and 0 <= state["idx"] < len(files):
                done = sum(sizes[:state["idx"]]) + sizes[state["idx"]] * int(m.group(1)) / 100.0
                prog(12 + 80 * done / total)

        base = ["--chip", "esp32c3", "--port", cfg["port"], "--baud", str(cfg["baud"])]
        if cfg["erase"]:
            stage(1, "active")
            status("Erasing flash...")
            log("Erasing flash...")
            run_esptool(base + ["erase_flash"], on_es)
            stage(1, "done")
        else:
            stage(1, "skip")
        prog(12)
        stage(2, "active")
        status("Writing firmware, settings and blocklist...")
        args = base + ["--after", "hard_reset", "write_flash", "--flash_mode", "keep", "--flash_freq", "keep",
                       "--flash_size", "keep"]
        for off, path in files:
            args += [hex(off), path]
        run_esptool(args, on_es)
        stage(2, "done")
        prog(93)

        stage(3, "active")
        status("Waiting for the board to start and join Wi-Fi (up to 60 s)...")
        log("Flash complete. Waiting for the device to boot and join Wi-Fi (up to 60 s)...")
        ip = capture_boot(cfg["port"], 60, log, stop)
        if not ip:
            try:
                ip = socket.gethostbyname("c3hole.local")
            except Exception:
                ip = None
        result["ip"] = ip
        stage(3, "done" if ip else "warn")
        prog(97)
        stage(4, "active")
        status("Checking the dashboard...")
        if ip:
            result["login"] = check_login(ip, None if cfg["no_auth"] else cfg["dash_pass"])
        stage(4, "done" if ip else "warn")
        prog(100)
        q.put(("done", result))
    except Exception as e:
        log(traceback.format_exc())
        q.put(("error", str(e)))


# --------------------------------------------------------------------- self-test
def selftest():
    lines, ok = [], True

    def check(name, cond, extra=""):
        nonlocal ok
        ok = ok and bool(cond)
        lines.append("%s %s %s" % ("PASS" if cond else "FAIL", name, extra))

    try:
        man = load_manifest()
        for n in ("bootloader.bin", "partitions.bin", "boot_app0.bin", "firmware.bin", "blocklist.bin"):
            p = asset(n)
            check("asset " + n, os.path.exists(p), "%d bytes" % (os.path.getsize(p) if os.path.exists(p) else 0))
        with open(asset("firmware.bin"), "rb") as f:
            check("firmware image magic 0xE9", f.read(1) == b"\xe9")
        bl = os.path.getsize(asset("blocklist.bin"))
        check("blocklist fits partition", bl <= man["blocklist_size"], "%d of %d bytes" % (bl, man["blocklist_size"]))
        with open(asset("blocklist.bin"), "rb") as f:
            check("blocklist header", f.read(4) == b"C3HL")
        blob = cfgblob.build_cfg("Net", "password1", "Dash-pass-1")
        check("cfg blob", len(blob) == 4096 and blob.startswith(b"C3CFG1\n"))
        blob = cfgblob.build_cfg("Net", "", "", no_auth=True)
        check("cfg blob (no password)", b"noauth=1" in blob and b"dhash=\n" in blob)
        import esptool  # noqa: F401
        check("esptool import", True, esptool.__version__)
        check("serial ports api", isinstance(list_ports_info(), list))
        import mdui
        import tkinter
        check("ui toolkit", hasattr(mdui, "Card") and tkinter.TkVersion >= 8.5, "Tk %s" % tkinter.TkVersion)
    except Exception:
        ok = False
        lines.append("FAIL exception\n" + traceback.format_exc())
    out = os.environ.get("C3F_SELFTEST_OUT") or os.path.join(tempfile.gettempdir(), "c3hole_selftest.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\nRESULT: %s\n" % ("OK" if ok else "FAILED"))
    print("\n".join(lines))
    return 0 if ok else 1
