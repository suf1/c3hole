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
IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def valid_ip(s):
    m = IPV4.match(s)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


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
    if dp:
        if not 8 <= len(dp) <= 60:
            return "Dashboard password must be 8-60 characters."
        if not re.fullmatch(r"[\x20-\x7E]+", dp):
            return "Dashboard password: plain ASCII characters only."
    if not valid_ip(v["up1"]):
        return "Upstream DNS 1 is not a valid IPv4 address."
    if v["up2"] and not valid_ip(v["up2"]):
        return "Upstream DNS 2 is not a valid IPv4 address."
    for key, label in (("bl_url", "Blocklist URL"), ("fw_url", "Firmware URL")):
        u = v[key]
        if u and (len(u) > 159 or not re.match(r"^https?://\S+$", u)):
            return "%s must start with http:// or https:// (max 159 characters)." % label
    try:
        h = int(v["bl_hours"])
        k = int(v["bloom_kb"])
    except ValueError:
        return "Update hours and Bloom KB must be numbers."
    if not 0 <= h <= 8760:
        return "Update interval must be 0-8760 hours."
    if not 0 <= k <= 400:
        return "Bloom filter must be 0-400 KB (0 = automatic)."
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
    """True/False if the dashboard accepts the password, None if unreachable."""
    token = base64.b64encode(("admin:" + password).encode()).decode()
    req = urllib.request.Request("http://%s/api/status" % host, headers={"Authorization": "Basic " + token})
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
    result = {"ip": None, "password": cfg["dash_pass"], "login": None, "generated": cfg["generated"]}
    try:
        man = load_manifest()
        prog(2)
        log("Building settings partition...")
        blob = cfgblob.build_cfg(cfg["ssid"], cfg["wifi_pass"], cfg["dash_pass"], bloom_kb=int(cfg["bloom_kb"]),
                                 up1=cfg["up1"], up2=cfg["up2"] or "", bl_url=cfg["bl_url"], fw_url=cfg["fw_url"],
                                 bl_hours=int(cfg["bl_hours"]))
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
            result["login"] = check_login(ip, cfg["dash_pass"])
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
    root.geometry("780x940")
    root.minsize(720, 720)
    style = ttk.Style()
    try:
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")
    except Exception:
        pass
    style.configure("Big.TButton", font=("Segoe UI", 12, "bold"), padding=8)
    style.configure("H.TLabel", font=("Segoe UI", 15, "bold"))

    q = queue.Queue()
    stop = threading.Event()
    busy = {"v": False, "ports": []}
    saved = load_settings()

    V = {k: tk.StringVar(value=saved.get(k, d)) for k, d in
         (("ssid", ""), ("bl_url", ""), ("bl_hours", "24"), ("fw_url", ""), ("up1", "1.1.1.1"), ("up2", "9.9.9.9"),
          ("bloom_kb", "128"))}
    v_wpass, v_dpass = tk.StringVar(), tk.StringVar()
    v_show, v_adv = tk.BooleanVar(value=False), tk.BooleanVar(value=False)
    v_blmode, v_blpath = tk.StringVar(value="bundled"), tk.StringVar()
    v_port, v_erase, v_baud = tk.StringVar(), tk.BooleanVar(value=True), tk.StringVar(value="460800")

    outer = ttk.Frame(root, padding=14)
    outer.pack(fill="both", expand=True)
    ttk.Label(outer, text="C3Hole - DNS ad-blocker flasher", style="H.TLabel").pack(anchor="w")
    if man:
        info = "Bundled: %s domains | firmware v%s | built %s" % (format(man["blocklist_domains"], ","), man.get("version", "?"), man["built_at"])
    else:
        info = "WARNING: bundled assets not found (run the .exe built by the workflow)"
    ttk.Label(outer, text=info, foreground="#555").pack(anchor="w", pady=(0, 6))

    def entry(parent, label, var, row, show=None, width=40):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3, padx=(0, 10))
        e = ttk.Entry(parent, textvariable=var, width=width, show=show or "")
        e.grid(row=row, column=1, sticky="we", pady=3)
        return e

    f1 = ttk.LabelFrame(outer, text=" 1. Wi-Fi (2.4 GHz) ", padding=8)
    f1.pack(fill="x", pady=3)
    f1.columnconfigure(1, weight=1)
    entry(f1, "Network name (SSID)", V["ssid"], 0)
    e_w = entry(f1, "Wi-Fi password", v_wpass, 1, show="*")

    f2 = ttk.LabelFrame(outer, text=" 2. Dashboard password ", padding=8)
    f2.pack(fill="x", pady=3)
    f2.columnconfigure(1, weight=1)
    e_d = entry(f2, "Password (8+ chars)", v_dpass, 0, show="*")
    ttk.Label(f2, text="Leave blank and a strong password is generated for you and shown after flashing.",
              foreground="#555").grid(row=1, column=0, columnspan=2, sticky="w")
    ttk.Checkbutton(outer, text="Show passwords", variable=v_show,
                    command=lambda: [w.config(show="" if v_show.get() else "*") for w in (e_w, e_d)]).pack(anchor="w")

    f3 = ttk.LabelFrame(outer, text=" 3. Blocklist ", padding=8)
    f3.pack(fill="x", pady=3)
    f3.columnconfigure(1, weight=1)
    ttk.Radiobutton(f3, text="Bundled list (StevenBlack + Hagezi Multi PRO)", variable=v_blmode, value="bundled").grid(row=0, column=0, columnspan=3, sticky="w")
    ttk.Radiobutton(f3, text="My own blocklist.bin:", variable=v_blmode, value="custom").grid(row=1, column=0, sticky="w")
    ttk.Entry(f3, textvariable=v_blpath).grid(row=1, column=1, sticky="we", padx=6)

    def browse():
        p = filedialog.askopenfilename(filetypes=[("Blocklist", "*.bin"), ("All", "*.*")])
        if p:
            v_blpath.set(p)
            v_blmode.set("custom")
    ttk.Button(f3, text="Browse...", command=browse).grid(row=1, column=2)
    ttk.Label(f3, text="Auto-update URL").grid(row=2, column=0, sticky="w", pady=(6, 0))
    ttk.Entry(f3, textvariable=V["bl_url"]).grid(row=2, column=1, columnspan=2, sticky="we", padx=6, pady=(6, 0))
    ttk.Label(f3, text="Check every (hours, 0 = off)").grid(row=3, column=0, sticky="w")
    ttk.Entry(f3, textvariable=V["bl_hours"], width=8).grid(row=3, column=1, sticky="w", padx=6)

    ttk.Checkbutton(outer, text="Show advanced settings", variable=v_adv,
                    command=lambda: fadv.pack(fill="x", pady=3, after=advmark) if v_adv.get() else fadv.pack_forget()).pack(anchor="w")
    advmark = ttk.Frame(outer)
    advmark.pack()
    fadv = ttk.LabelFrame(outer, text=" Advanced ", padding=8)
    fadv.columnconfigure(1, weight=1)
    entry(fadv, "Upstream DNS 1", V["up1"], 0, width=20)
    entry(fadv, "Upstream DNS 2 (optional)", V["up2"], 1, width=20)
    entry(fadv, "Bloom filter KB (0 = auto)", V["bloom_kb"], 2, width=10)
    entry(fadv, "Firmware update URL", V["fw_url"], 3)

    f4 = ttk.LabelFrame(outer, text=" 4. Board ", padding=8)
    f4.pack(fill="x", pady=3)
    f4.columnconfigure(1, weight=1)
    ttk.Label(f4, text="COM port").grid(row=0, column=0, sticky="w", padx=(0, 10))
    cb = ttk.Combobox(f4, textvariable=v_port, state="readonly", width=50)
    cb.grid(row=0, column=1, sticky="we")
    ttk.Checkbutton(f4, text="Erase all flash first (recommended)", variable=v_erase).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
    rb = ttk.Frame(f4)
    rb.grid(row=2, column=0, columnspan=2, sticky="w")
    ttk.Label(rb, text="Speed").pack(side="left")
    ttk.Combobox(rb, textvariable=v_baud, values=["115200", "230400", "460800", "921600"], width=8, state="readonly").pack(side="left", padx=6)
    ttk.Label(f4, text="Use a data-capable USB cable. If the board is not found or cannot connect: hold BOOT, tap RESET, release BOOT.",
              foreground="#555", wraplength=680).grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

    btn = ttk.Button(outer, text="FLASH", style="Big.TButton")
    btn.pack(fill="x", pady=(8, 4))
    pb = ttk.Progressbar(outer, maximum=100)
    pb.pack(fill="x")
    status = tk.StringVar(value="Ready.")
    ttk.Label(outer, textvariable=status).pack(anchor="w", pady=(2, 2))

    res = ttk.LabelFrame(outer, text=" Result ", padding=8)
    res.pack(fill="x", pady=3)
    v_res = tk.StringVar(value="Dashboard details will appear here after flashing.")
    ttk.Label(res, textvariable=v_res, wraplength=700, justify="left").pack(anchor="w")
    rbtn = ttk.Frame(res)
    rbtn.pack(anchor="w", pady=(4, 0))
    b_open = ttk.Button(rbtn, text="Open dashboard", state="disabled")
    b_open.pack(side="left")
    b_copy = ttk.Button(rbtn, text="Copy password", state="disabled")
    b_copy.pack(side="left", padx=6)

    logf = ttk.Frame(outer)
    logf.pack(fill="both", expand=True, pady=(4, 0))
    logt = tk.Text(logf, height=6, wrap="word", font=("Consolas", 9), state="disabled", background="#111", foreground="#ddd")
    sb = ttk.Scrollbar(logf, command=logt.yview)
    logt.config(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    logt.pack(side="left", fill="both", expand=True)

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
            labels = [lab for _, lab in ports]
            cb["values"] = labels
            if v_port.get() not in labels:
                v_port.set(labels[0] if labels else "")
        root.after(2000, refresh_ports)

    def selected_port():
        for dev, lab in busy["ports"]:
            if lab == v_port.get():
                return dev
        return None

    def form():
        d = {k: V[k].get().strip() for k in V}
        d["wifi_pass"] = v_wpass.get()
        d["dash_pass"] = v_dpass.get()
        return d

    def set_busy(b):
        busy["v"] = b
        btn.config(state="disabled" if b else "normal", text="Flashing... do not unplug" if b else "FLASH")
        if not b:
            refresh_ports()

    def start():
        d = form()
        limit = man["blocklist_size"] if man else 0
        err = validate(d, limit, v_blpath.get() if v_blmode.get() == "custom" else None)
        if not err and not selected_port():
            err = "No board found. Plug in the ESP32-C3 (use a data cable)."
        if not err and not man:
            err = "Bundled firmware is missing. Use the .exe built by the workflow."
        if err:
            messagebox.showwarning(APP_NAME, err)
            return
        generated = False
        if not d["dash_pass"]:
            d["dash_pass"] = cfgblob.random_password(12)
            generated = True
        if v_erase.get() and not messagebox.askyesno(APP_NAME, "This erases everything on the board and installs C3Hole.\n\nContinue?"):
            return
        save_settings({k: d[k] for k in ("ssid", "bl_url", "bl_hours", "fw_url", "up1", "up2", "bloom_kb")})
        d.update(port=selected_port(), baud=int(v_baud.get()), erase=v_erase.get(), generated=generated,
                 blocklist_path=v_blpath.get() if v_blmode.get() == "custom" else None)
        stop.clear()
        pb["value"] = 0
        v_res.set("Working...")
        b_open.config(state="disabled")
        b_copy.config(state="disabled")
        set_busy(True)
        status.set("Flashing...")
        threading.Thread(target=flash_job, args=(d, q, stop), daemon=True).start()

    btn.config(command=start)

    def show_done(r):
        set_busy(False)
        status.set("Done.")
        ip, pw, login = r["ip"], r["password"], r["login"]
        lines = []
        if ip:
            url = "http://%s" % ip
            lines.append("Dashboard: %s   (also http://c3hole.local)" % url)
            b_open.config(state="normal", command=lambda: webbrowser.open(url))
        else:
            lines.append("Flashed OK, but the device did not report an IP within 60 s. Check the Wi-Fi name/password and press RESET. "
                         "If it cannot join, it keeps retrying; hold BOOT for 5 s to wipe settings and use the 'C3Hole-Setup' Wi-Fi.")
        lines.append("Username: admin     Password: %s%s" % (pw, "   (generated for you - save it now)" if r["generated"] else ""))
        if login is True:
            lines.append("Login check: password accepted by the device.")
        elif login is False:
            lines.append("Login check: the device rejected the password - please report this.")
        elif ip:
            lines.append("Login check: dashboard not reachable from this PC yet (try the link above).")
        lines.append("Next: set your router's DNS to the device IP and give it a DHCP reservation.")
        v_res.set("\n".join(lines))

        def cp():
            root.clipboard_clear()
            root.clipboard_append(pw)
        b_copy.config(state="normal", command=cp)

    def show_error(msg):
        set_busy(False)
        status.set("Failed.")
        hint = ""
        if re.search(r"Failed to connect|No serial data|Could not open|PermissionError|timed out", msg, re.I):
            hint = "\n\nTry: another USB cable/port, close any serial monitor, then hold BOOT, tap RESET, release BOOT and click FLASH again."
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
