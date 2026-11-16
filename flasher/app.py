"""C3Hole Flasher - plug in an ESP32-C3, fill in the fields, click Flash.

Everything needed (firmware, bootloader, partition table, blocklist, esptool) is
bundled into the executable by the CI workflow.  Settings are written to the
device's `cfg` partition, the blocklist to its raw `blocklist` partition.
"""
import base64
import io
import json
import os
import queue
import re
import socket
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
    ("Google (8.8.8.8)", "8.8.8.8", "8.8.4.4"),
    ("Quad9 (9.9.9.9)", "9.9.9.9", "149.112.112.112"),
    ("Cloudflare (1.1.1.1)", "1.1.1.1", "1.0.0.1"),
    ("AdGuard DNS", "94.140.14.14", "94.140.15.15"),
    ("OpenDNS", "208.67.222.222", "208.67.220.220"),
    ("Google + Quad9", "8.8.8.8", "9.9.9.9"),
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


def validate(v, blocklist_size_limit, blocklist_path=None):
    """Returns an error string or None. v is a dict of the form values."""
    if not v["ssid"]:
        return "Enter your Wi-Fi network name."
    if len(v["ssid"].encode()) > 32:
        return "SSID is too long (max 32 bytes)."
    if v["wifi_pass"] and len(v["wifi_pass"]) < 8:
        return "Wi-Fi password must be at least 8 characters (or empty for an open network)."
    if len(v["wifi_pass"].encode()) > 63:
        return "Wi-Fi password is too long (max 63 bytes)."
    for name in ("ssid", "wifi_pass"):
        if re.search(r"[\r\n\x00]", v[name]):
            return "Wi-Fi settings must not contain line breaks."
    dp = v["dash_pass"]
    if dp and not v.get("no_auth"):
        if not 8 <= len(dp) <= 60:
            return "Dashboard password must be 8-60 characters."
        if not re.fullmatch(r"[\x20-\x7E]+", dp):
            return "Dashboard password: plain ASCII characters only."
    if not valid_upstream(v["up1"]):
        return "Upstream DNS 1 must be an IPv4 address, optionally with :port (e.g. 192.168.0.5:5353)."
    if v["up2"] and not valid_upstream(v["up2"]):
        return "Upstream DNS 2 must be an IPv4 address, optionally with :port."
    for key, label in (("bl_url", "Blocklist URL"), ("fw_url", "Firmware URL")):
        u = v[key]
        if u and (len(u) > 159 or not re.match(r"^https?://\S+$", u)):
            return "%s must start with http:// or https:// (max 159 characters)." % label
    try:
        h = int(v["bl_hours"])
        k = int(v["bloom_kb"])
        t = int(v["up_timeout"])
    except ValueError:
        return "Hours, Bloom KB and failover timeout must be numbers."
    if not 0 <= h <= 8760:
        return "Update interval must be 0-8760 hours."
    if not 0 <= k <= 400:
        return "Bloom filter must be 0-400 KB (0 = automatic)."
    if not 100 <= t <= 5000:
        return "Failover timeout must be 100-5000 ms."
    if blocklist_path:
        try:
            with open(blocklist_path, "rb") as f:
                head = f.read(48)
            size = os.path.getsize(blocklist_path)
        except OSError as e:
            return "Cannot read blocklist file: %s" % e
        if head[:4] != b"C3HL":
            return "That file is not a C3Hole blocklist (missing C3HL header)."
        if size > blocklist_size_limit:
            return "That blocklist is too large for this firmware's partition."
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
        out.append((0 if is_esp else 1, p.device, "%s - %s%s" % (p.device, p.description or "serial port",
                                                                  "  [ESP32-C3]" if is_esp else "")))
    out.sort()
    return [(dev, label) for _, dev, label in out]


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
    """True/False if the dashboard accepts the password (None = open dashboard), or None if unreachable."""
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
def flash_job(cfg, q, stop):
    log = lambda s: q.put(("log", s))
    prog = lambda v: q.put(("progress", v))
    result = {"ip": None, "password": None if cfg["no_auth"] else cfg["dash_pass"], "login": None,
              "generated": cfg["generated"], "no_auth": cfg["no_auth"]}
    try:
        man = load_manifest()
        prog(2)
        log("Building settings partition...")
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

        def on_es(line):
            log(line)
            if line.startswith("Compressed"):
                state["idx"] += 1
            m = re.search(r"Writing at 0x[0-9a-fA-F]+\.\.\. \((\d+) %\)", line)
            if m and 0 <= state["idx"] < len(files):
                done = sum(sizes[:state["idx"]]) + sizes[state["idx"]] * int(m.group(1)) / 100.0
                prog(12 + 80 * done / total)

        base = ["--chip", "esp32c3", "--port", cfg["port"], "--baud", str(cfg["baud"])]
        if cfg["erase"]:
            log("Erasing flash...")
            run_esptool(base + ["erase_flash"], on_es)
        prog(12)
        log("Writing firmware, settings and blocklist...")
        args = base + ["--after", "hard_reset", "write_flash", "--flash_mode", "keep", "--flash_freq", "keep",
                       "--flash_size", "keep"]
        for off, path in files:
            args += [hex(off), path]
        run_esptool(args, on_es)
        prog(93)

        log("Flash complete. Waiting for the device to boot and join Wi-Fi (up to 60 s)...")
        ip = capture_boot(cfg["port"], 60, log, stop)
        if not ip:
            try:
                ip = socket.gethostbyname("c3hole.local")
            except Exception:
                ip = None
        result["ip"] = ip
        prog(97)
        if ip:
            result["login"] = check_login(ip, None if cfg["no_auth"] else cfg["dash_pass"])
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
    except Exception:
        ok = False
        lines.append("FAIL exception\n" + traceback.format_exc())
    out = os.environ.get("C3F_SELFTEST_OUT") or os.path.join(tempfile.gettempdir(), "c3hole_selftest.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\nRESULT: %s\n" % ("OK" if ok else "FAILED"))
    print("\n".join(lines))
    return 0 if ok else 1


# --------------------------------------------------------------------- GUI
def main_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    man = None
    try:
        man = load_manifest()
    except Exception:
        pass

    root = tk.Tk()
    root.title(APP_NAME)
    root.resizable(False, False)   # window sizes itself to its content
    style = ttk.Style()
    try:
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")
    except Exception:
        pass
    style.configure("Big.TButton", font=("Segoe UI", 10, "bold"), padding=(10, 3))
    style.configure("Small.TLabel", foreground="#666", font=("Segoe UI", 8))

    q = queue.Queue()
    stop = threading.Event()
    busy = {"v": False, "ports": []}
    saved = load_settings()
    sv = lambda k, d: tk.StringVar(value=str(saved.get(k, d)))
    V = {"ssid": sv("ssid", ""), "bl_url": sv("bl_url", ""), "bl_hours": sv("bl_hours", "24"), "fw_url": sv("fw_url", ""),
         "up1": sv("up1", "8.8.8.8"), "up2": sv("up2", "9.9.9.9"), "bloom_kb": sv("bloom_kb", "128"),
         "up_timeout": sv("up_timeout", "800")}
    v_wpass, v_dpass = tk.StringVar(), tk.StringVar()
    v_noauth, v_erase = tk.BooleanVar(value=False), tk.BooleanVar(value=True)
    v_bl, v_blpath = tk.StringVar(value="Bundled list"), tk.StringVar()
    v_port, v_baud, v_log = tk.StringVar(), tk.StringVar(value="460800"), tk.BooleanVar(value=False)
    tx_labels = ["%s" % lab for _, lab in sorted(cfgblob.TX_POWERS.items())]
    tx_by_label = {lab: val for val, lab in cfgblob.TX_POWERS.items()}
    v_tx = tk.StringVar(value=cfgblob.TX_POWERS.get(int(saved.get("tx_power", 44)), "11 dBm"))
    ps_opts = ["Off (fastest)", "Minimum sleep", "Maximum sleep"]
    v_ps = tk.StringVar(value=ps_opts[int(saved.get("ps_mode", 0))])
    v_cpu = tk.StringVar(value="%s MHz" % saved.get("cpu_mhz", 160))
    mode_opts = ["Primary, then 2nd", "Ask both at once"]
    v_mode = tk.StringVar(value=mode_opts[int(saved.get("up_mode", 0))])
    v_preset = tk.StringVar()

    outer = ttk.Frame(root, padding=(10, 8))
    outer.pack(fill="both", expand=True)
    if man:
        info = "%s domains bundled  |  firmware v%s  |  %s" % (format(man["blocklist_domains"], ","), man.get("version", "?"), man["built_at"])
    else:
        info = "WARNING: bundled assets not found - use the .exe built by the workflow"
    ttk.Label(outer, text=info, style="Small.TLabel").pack(anchor="w")

    nb = ttk.Notebook(outer)
    nb.pack(fill="x", pady=(4, 6))
    t1, t2 = ttk.Frame(nb, padding=8), ttk.Frame(nb, padding=8)
    nb.add(t1, text=" Setup ")
    nb.add(t2, text=" Advanced ")

    def lab(parent, text, r, c=0):
        ttk.Label(parent, text=text).grid(row=r, column=c, sticky="w", padx=(0, 6), pady=2)

    # ---- Setup tab
    t1.columnconfigure(1, weight=1)
    lab(t1, "Wi-Fi name", 0)
    ttk.Entry(t1, textvariable=V["ssid"]).grid(row=0, column=1, columnspan=2, sticky="we", pady=2)
    lab(t1, "Wi-Fi password", 1)
    e_w = ttk.Entry(t1, textvariable=v_wpass, show="*")
    e_w.grid(row=1, column=1, sticky="we", pady=2)
    show = tk.BooleanVar(value=False)
    ttk.Checkbutton(t1, text="show", variable=show, command=lambda: [w.config(show="" if show.get() else "*") for w in (e_w, e_d)]).grid(row=1, column=2, padx=(6, 0))
    lab(t1, "Dashboard password", 2)
    e_d = ttk.Entry(t1, textvariable=v_dpass, show="*")
    e_d.grid(row=2, column=1, sticky="we", pady=2)

    def on_noauth():
        e_d.config(state="disabled" if v_noauth.get() else "normal")
    ttk.Checkbutton(t1, text="none", variable=v_noauth, command=on_noauth).grid(row=2, column=2, padx=(6, 0))
    ttk.Label(t1, text="Blank = a strong password is generated and shown after flashing. 'none' = open dashboard.", style="Small.TLabel", wraplength=470, justify="left").grid(row=3, column=0, columnspan=3, sticky="w")
    lab(t1, "Blocklist", 4)
    cbl = ttk.Combobox(t1, textvariable=v_bl, state="readonly", values=["Bundled list", "My own file..."])
    cbl.grid(row=4, column=1, columnspan=2, sticky="we", pady=2)

    def on_bl(_=None):
        if v_bl.get() == "My own file...":
            p = filedialog.askopenfilename(filetypes=[("Blocklist", "*.bin"), ("All", "*.*")])
            if p:
                v_blpath.set(p)
                v_bl.set("File: " + os.path.basename(p))
                cbl["values"] = ["Bundled list", "My own file...", v_bl.get()]
            else:
                v_bl.set("Bundled list")
        elif v_bl.get() == "Bundled list":
            v_blpath.set("")
    cbl.bind("<<ComboboxSelected>>", on_bl)
    lab(t1, "Auto-update URL", 5)
    ttk.Entry(t1, textvariable=V["bl_url"]).grid(row=5, column=1, sticky="we", pady=2)
    hf = ttk.Frame(t1)
    hf.grid(row=5, column=2, padx=(6, 0))
    ttk.Entry(hf, textvariable=V["bl_hours"], width=4).pack(side="left")
    ttk.Label(hf, text=" h").pack(side="left")

    # ---- Advanced tab
    for c in (1, 3):
        t2.columnconfigure(c, weight=1)

    def pair(r, c, text, widget):
        lab(t2, text, r, c)
        widget.grid(row=r, column=c + 1, sticky="we", pady=2, padx=(0, 8))
    cpre = ttk.Combobox(t2, textvariable=v_preset, state="readonly", values=[p[0] for p in PRESETS], width=17)
    pair(0, 0, "Upstream DNS", cpre)
    pair(0, 2, "Mode", ttk.Combobox(t2, textvariable=v_mode, state="readonly", values=mode_opts, width=17))
    e_u1 = ttk.Entry(t2, textvariable=V["up1"], width=14)
    e_u2 = ttk.Entry(t2, textvariable=V["up2"], width=14)
    pair(1, 0, "Server 1", e_u1)
    pair(1, 2, "Server 2", e_u2)
    ttk.Label(t2, text="IPv4, optional :port - e.g. 192.168.0.5:5353 for your own resolver", style="Small.TLabel", wraplength=470, justify="left").grid(row=2, column=0, columnspan=4, sticky="w")

    def on_preset(_=None):
        for name, a, b in PRESETS:
            if name == v_preset.get() and a:
                V["up1"].set(a)
                V["up2"].set(b)
    cpre.bind("<<ComboboxSelected>>", on_preset)

    def sync_preset(*_):
        for name, a, b in PRESETS:
            if a and a == V["up1"].get() and b == V["up2"].get():
                v_preset.set(name)
                return
        v_preset.set("My own server...")
    V["up1"].trace_add("write", sync_preset)
    V["up2"].trace_add("write", sync_preset)
    sync_preset()
    pair(3, 0, "Failover ms", ttk.Entry(t2, textvariable=V["up_timeout"], width=8))
    pair(3, 2, "Bloom KB (0=auto)", ttk.Entry(t2, textvariable=V["bloom_kb"], width=8))
    pair(4, 0, "Wi-Fi TX power", ttk.Combobox(t2, textvariable=v_tx, state="readonly", values=tx_labels, width=10))
    pair(4, 2, "Wi-Fi power save", ttk.Combobox(t2, textvariable=v_ps, state="readonly", values=ps_opts, width=17))
    pair(5, 0, "CPU speed", ttk.Combobox(t2, textvariable=v_cpu, state="readonly", values=["160 MHz", "80 MHz"], width=10))
    pair(5, 2, "Flash speed", ttk.Combobox(t2, textvariable=v_baud, state="readonly", values=["115200", "230400", "460800", "921600"], width=10))
    lab(t2, "Firmware URL", 6)
    ttk.Entry(t2, textvariable=V["fw_url"]).grid(row=6, column=1, columnspan=3, sticky="we", pady=2)
    ttk.Checkbutton(t2, text="Erase all flash first (recommended)", variable=v_erase).grid(row=7, column=0, columnspan=4, sticky="w")
    ttk.Label(t2, text="Cooler/more stable Wi-Fi: lower TX power (try 8.5 dBm), 80 MHz CPU, power save on.", style="Small.TLabel", wraplength=470, justify="left").grid(row=8, column=0, columnspan=4, sticky="w")

    # ---- bottom bar
    bar = ttk.Frame(outer)
    bar.pack(fill="x")
    bar.columnconfigure(0, weight=1)
    cb = ttk.Combobox(bar, textvariable=v_port, state="readonly")
    cb.grid(row=0, column=0, sticky="we", padx=(0, 8))
    btn = ttk.Button(bar, text="FLASH", style="Big.TButton")
    btn.grid(row=0, column=1)
    pb = ttk.Progressbar(outer, maximum=100)
    pb.pack(fill="x", pady=(6, 2))
    status = tk.StringVar(value="Plug in the board, then click FLASH. (Stuck? hold BOOT, tap RESET, release BOOT.)")
    ttk.Label(outer, textvariable=status, style="Small.TLabel", wraplength=510).pack(anchor="w")
    v_res = tk.StringVar(value="")
    ttk.Label(outer, textvariable=v_res, wraplength=510, justify="left").pack(anchor="w", pady=(2, 0))
    rb = ttk.Frame(outer)
    rb.pack(anchor="w", pady=(2, 0))
    b_open = ttk.Button(rb, text="Open dashboard", state="disabled")
    b_open.pack(side="left")
    b_copy = ttk.Button(rb, text="Copy password", state="disabled")
    b_copy.pack(side="left", padx=6)
    logf = ttk.Frame(outer)
    logt = tk.Text(logf, height=7, wrap="word", font=("Consolas", 8), state="disabled", background="#111", foreground="#ddd")
    sb = ttk.Scrollbar(logf, command=logt.yview)
    logt.config(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    logt.pack(side="left", fill="both", expand=True)

    def toggle_log():
        if v_log.get():
            logf.pack(fill="both", expand=True, pady=(4, 0))
        else:
            logf.pack_forget()
    ttk.Checkbutton(rb, text="Show details", variable=v_log, command=toggle_log).pack(side="left", padx=10)

    def log(s):
        logt.config(state="normal")
        logt.insert("end", s + "\n")
        logt.see("end")
        logt.config(state="disabled")

    def refresh_ports():
        if busy["v"]:
            return
        ports = list_ports_info()
        if ports != busy["ports"]:
            busy["ports"] = ports
            labels = [lab_ for _, lab_ in ports]
            cb["values"] = labels
            if v_port.get() not in labels:
                v_port.set(labels[0] if labels else "")
        root.after(2000, refresh_ports)

    def selected_port():
        for dev, lab_ in busy["ports"]:
            if lab_ == v_port.get():
                return dev
        return None

    def form():
        d = {k: V[k].get().strip() for k in V}
        d["wifi_pass"] = v_wpass.get()
        d["dash_pass"] = v_dpass.get()
        d["no_auth"] = v_noauth.get()
        return d

    def set_busy(b):
        busy["v"] = b
        btn.config(state="disabled" if b else "normal", text="Flashing..." if b else "FLASH")
        if not b:
            refresh_ports()

    def start():
        d = form()
        limit = man["blocklist_size"] if man else 0
        err = validate(d, limit, v_blpath.get() or None)
        if not err and not selected_port():
            err = "No board found. Plug in the ESP32-C3 (use a data cable)."
        if not err and not man:
            err = "Bundled firmware is missing. Use the .exe built by the workflow."
        if err:
            messagebox.showwarning(APP_NAME, err)
            return
        if d["no_auth"] and not messagebox.askyesno(APP_NAME, "No dashboard password: anyone on your network can open the dashboard, "
                                                    "change settings and install firmware.\n\nContinue without a password?"):
            return
        generated = False
        if not d["no_auth"] and not d["dash_pass"]:
            d["dash_pass"] = cfgblob.random_password(12)
            generated = True
        if v_erase.get() and not messagebox.askyesno(APP_NAME, "This erases everything on the board and installs C3Hole.\n\nContinue?"):
            return
        d.update(tx_power=tx_by_label[v_tx.get()], ps_mode=ps_opts.index(v_ps.get()), cpu_mhz=int(v_cpu.get().split()[0]),
                 up_mode=mode_opts.index(v_mode.get()))
        save_settings({k: d[k] for k in ("ssid", "bl_url", "bl_hours", "fw_url", "up1", "up2", "bloom_kb", "up_timeout",
                                         "tx_power", "ps_mode", "cpu_mhz", "up_mode")})
        d.update(port=selected_port(), baud=int(v_baud.get()), erase=v_erase.get(), generated=generated,
                 blocklist_path=v_blpath.get() or None)
        stop.clear()
        pb["value"] = 0
        v_res.set("")
        b_open.config(state="disabled")
        b_copy.config(state="disabled")
        set_busy(True)
        status.set("Flashing - do not unplug...")
        threading.Thread(target=flash_job, args=(d, q, stop), daemon=True).start()

    btn.config(command=start)

    def show_done(r):
        set_busy(False)
        status.set("Done.")
        ip, pw, login = r["ip"], r["password"], r["login"]
        lines = []
        if ip:
            url = "http://%s" % ip
            lines.append("Dashboard: %s  (or http://c3hole.local)" % url)
            b_open.config(state="normal", command=lambda: webbrowser.open(url))
        else:
            lines.append("Flashed, but no IP reported within 60 s. Check the Wi-Fi name/password and press RESET; "
                         "hold BOOT 5 s to wipe settings and use the 'C3Hole-Setup' Wi-Fi.")
        if r["no_auth"]:
            lines.append("No password: the dashboard is open to your network.")
        else:
            lines.append("User: admin   Password: %s%s" % (pw, "  (generated - save it now)" if r["generated"] else ""))
        if login is True and not r["no_auth"]:
            lines.append("Login check passed.")
        elif login is False:
            lines.append("Login check FAILED - the device rejected the password.")
        lines.append("Next: set your router's DNS to this IP and reserve it in DHCP.")
        v_res.set("\n".join(lines))
        if pw:
            def cp():
                root.clipboard_clear()
                root.clipboard_append(pw)
            b_copy.config(state="normal", command=cp)

    def show_error(msg):
        set_busy(False)
        status.set("Failed.")
        hint = ""
        if re.search(r"Failed to connect|No serial data|Could not open|PermissionError|timed out", msg, re.I):
            hint = "\n\nTry another USB cable/port, close any serial monitor, then hold BOOT, tap RESET, release BOOT and click FLASH again."
        v_res.set("Flashing failed: " + msg + hint)
        messagebox.showerror(APP_NAME, "Flashing failed:\n\n" + msg + hint)

    def poll():
        try:
            while True:
                kind, val = q.get_nowait()
                if kind == "log":
                    log(val)
                elif kind == "progress":
                    pb["value"] = val
                elif kind == "done":
                    show_done(val)
                elif kind == "error":
                    show_error(val)
        except queue.Empty:
            pass
        root.after(100, poll)

    def on_close():
        if busy["v"] and not messagebox.askyesno(APP_NAME, "Flashing is in progress. Quit anyway?"):
            return
        stop.set()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh_ports()
    poll()
    root.mainloop()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    main_gui()
