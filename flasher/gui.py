"""The C3Hole Flasher 2.0 window (Material style, see mdui.py for the widgets)."""
import os
import queue
import struct
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog

import core
import mdui
from mdui import px

cfgblob = core.cfgblob
BUNDLED = "Bundled list"
OWN_FILE = "My own file..."


class App:
    PAGES = [("Setup", "wifi"), ("Network", "globe"), ("Device", "chip"), ("Log", "terminal")]
    STEPS = ["Prepare", "Erase", "Write", "Boot", "Verify"]

    def __init__(self, root):
        self.root = root
        mdui.init(root)
        self.man = None
        try:
            self.man = core.load_manifest()
        except Exception:
            pass
        self.saved = core.load_settings()
        self.q = queue.Queue()
        self.stop = threading.Event()
        self.busy = False
        self.touched = set()
        self.errs = {}
        self.log_lines = []
        self.ports_raw = []
        self.port_map = {}
        self.page_idx = 0
        self.cur_stage = 0
        self.overlay = None
        self.dark = {"dark": True, "light": False}.get(self.saved.get("theme"), mdui.system_prefers_dark())
        self._init_vars()
        root.title("%s %s" % (core.APP_NAME, core.APP_VERSION))
        root.geometry("980x700")
        root.minsize(900, 660)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<Control-Return>", lambda e: self.start())
        self.build()
        self.refresh_ports()
        self.poll()

    # ------------------------------------------------------------------ state
    def _init_vars(self):
        s = self.saved
        d = {"ssid": "", "bl_url": "", "bl_hours": "24", "fw_url": "", "up1": "8.8.8.8", "up2": "9.9.9.9",
             "bloom_kb": "128", "up_timeout": "500", "wifi_pass": "", "dash_pass": ""}
        self.sv = {k: tk.StringVar(value=str(s.get(k, v)) if k not in ("wifi_pass", "dash_pass") else "") for k, v in d.items()}
        self.v_noauth = tk.BooleanVar(value=False)
        self.v_erase = tk.BooleanVar(value=True)
        self.v_bl = tk.StringVar(value=BUNDLED)
        self.v_blpath = tk.StringVar(value="")
        self.prev_bl = BUNDLED
        self.v_port = tk.StringVar(value="")
        self.v_baud = tk.StringVar(value="460800")
        self.v_preset = tk.StringVar(value="")
        self.tx_labels = [lab for _, lab in sorted(cfgblob.TX_POWERS.items())]
        self.tx_by_label = {lab: val for val, lab in cfgblob.TX_POWERS.items()}
        self.v_tx = tk.StringVar(value=cfgblob.TX_POWERS.get(int(s.get("tx_power", 44)), "11 dBm"))
        self.ps_opts = ["Off (fastest, recommended)", "Minimum modem sleep", "Maximum modem sleep"]
        self.v_ps = tk.StringVar(value=self.ps_opts[int(s.get("ps_mode", 0))])
        self.cpu_opts = ["160 MHz", "80 MHz"]
        self.v_cpu = tk.StringVar(value="%s MHz" % s.get("cpu_mhz", 160))
        self.mode_opts = ["Primary, then secondary", "Ask both at once (recommended)"]
        self.v_mode = tk.StringVar(value=self.mode_opts[int(s.get("up_mode", 1))])
        for k in ("up1", "up2"):
            self.sv[k].trace_add("write", lambda *a: self._sync_preset())
        self._sync_preset()

    def _sync_preset(self):
        for name, a, b in core.PRESETS:
            if a and a == self.sv["up1"].get() and b == self.sv["up2"].get():
                self.v_preset.set(name)
                return
        self.v_preset.set(core.PRESETS[-1][0])

    def form(self):
        d = {k: self.sv[k].get().strip() for k in ("ssid", "bl_url", "bl_hours", "fw_url", "up1", "up2", "bloom_kb", "up_timeout")}
        d["wifi_pass"] = self.sv["wifi_pass"].get()
        d["dash_pass"] = self.sv["dash_pass"].get()
        d["no_auth"] = self.v_noauth.get()
        return d

    # ------------------------------------------------------------------ building
    def build(self):
        r = self.root
        for w in r.winfo_children():
            w.destroy()
        th = self.th = mdui.Theme(self.dark)
        F = mdui.FONTS
        r.configure(bg=th.bg)
        self.fields = {}
        self.overlay = None

        # ---- app bar
        bar = tk.Frame(r, bg=th.card, height=px(64))
        bar.pack(fill="x")
        bar.pack_propagate(False)
        logo = tk.Canvas(bar, width=px(40), height=px(40), bg=th.card, highlightthickness=0)
        logo.pack(side="left", padx=(px(22), px(12)), pady=px(12))
        mdui.rr(logo, 1, 1, px(40) - 1, px(40) - 1, px(12), fill=th.primary, outline="")
        mdui.icon(logo, "bolt", px(20), px(20), px(24), th.on_primary, bg=th.primary)
        tk.Label(bar, text="C3Hole Flasher", font=F.h1, bg=th.card, fg=th.text).pack(side="left")
        mdui.Chip(bar, th, "v" + core.APP_VERSION, tonal=True, bg=th.card).pack(side="left", padx=px(12))
        mdui.IconButton(bar, th, "sun" if self.dark else "moon", self.toggle_theme, bg=th.card).pack(side="right", padx=px(18))
        tk.Frame(r, bg=th.outline, height=1).pack(fill="x")

        # ---- bottom bar (packed before the body so the body takes the rest)
        bot = tk.Frame(r, bg=th.card, height=px(88))
        bot.pack(side="bottom", fill="x")
        bot.pack_propagate(False)
        tk.Frame(r, bg=th.outline, height=1).pack(side="bottom", fill="x")
        left = tk.Frame(bot, bg=th.card)
        left.pack(side="left", padx=(px(20), 0))
        self.chip = mdui.Chip(left, th, "No board detected", dot=th.outline_hi, bg=th.card)
        self.chip.pack(side="left")
        mdui.IconButton(left, th, "refresh", lambda: self.refresh_ports(once=True), bg=th.card, size=36).pack(side="left", padx=(px(4), 0))
        self.fab = mdui.Button(bot, th, "Flash", self.start, kind="filled", icon_name="bolt", fab=True, min_w=150, bg=th.card)
        self.fab.pack(side="right", padx=px(22))
        mid = tk.Frame(bot, bg=th.card)
        mid.pack(side="left", fill="x", expand=True, padx=px(18))
        self.status_icon = tk.Canvas(mid, width=px(24), height=px(24), bg=th.card, highlightthickness=0)
        self.status_icon.pack(side="left", padx=(0, px(8)))
        self.status_lbl = tk.Label(mid, text="", font=F.small, bg=th.card, fg=th.text2, anchor="w", justify="left", wraplength=px(380))
        self.status_lbl.pack(side="left", fill="x", expand=True)

        # ---- body: rail + pages
        body = tk.Frame(r, bg=th.bg)
        body.pack(fill="both", expand=True)
        self.rail = mdui.Rail(body, th, self.PAGES, self.show_page)
        self.rail.pack(side="left", fill="y")
        self.pages = mdui.Pages(body, th)
        self.pages.pack(side="left", fill="both", expand=True, padx=(0, px(18)), pady=px(16))
        for builder in (self.page_setup, self.page_network, self.page_device, self.page_log):
            builder(self.pages.add())
        if self.page_idx:
            self.pages.pages[0].place_forget()
            self.pages.pages[self.page_idx].place(x=0, y=0, width=0, relwidth=1, relheight=1)
            self.pages.cur = self.page_idx
            self.rail.select(self.page_idx)

        self.toast = mdui.Toast(r, th)
        for line in self.log_lines[-400:]:
            self._log_insert(line)
        self.on_noauth(refresh=False)
        self.update_bl_info()
        self.update_port_ui()
        self.refresh_errors()

    # ---- helpers to build content
    def columns(self, page):
        th = self.th
        page.columnconfigure(0, weight=1, uniform="c")
        page.columnconfigure(1, weight=1, uniform="c")
        a, b = tk.Frame(page, bg=th.bg), tk.Frame(page, bg=th.bg)
        a.grid(row=0, column=0, sticky="new", padx=(0, px(8)))
        b.grid(row=0, column=1, sticky="new", padx=(px(8), 0))
        return a, b

    def card(self, parent, title, subtitle, icon_name):
        c = mdui.Card(parent, self.th, title, subtitle, icon_name)
        c.pack(fill="x", pady=(0, px(14)))
        return c.body

    def field(self, parent, name, label, helper="", show=None, trailing=None, pady=(0, px(8))):
        tf = mdui.TextField(parent, self.th, label, self.sv[name], show=show, helper=helper, trailing=trailing,
                            on_change=self.refresh_errors)
        tf.entry.bind("<FocusOut>", lambda e, n=name: self.touch(n), add="+")
        tf.pack(fill="x", pady=pady)
        self.fields[name] = tf
        return tf

    def dropdown(self, parent, label, var, values, command=None, helper="", pady=(0, px(8))):
        dd = mdui.Dropdown(parent, self.th, label, var, values, command=command, helper=helper)
        dd.pack(fill="x", pady=pady)
        return dd

    # ---- pages
    def page_setup(self, page):
        th = self.th
        a, b = self.columns(page)
        c = self.card(a, "Wi-Fi", "The network the board will join", "wifi")
        self.field(c, "ssid", "Network name (SSID)", "2.4 GHz networks only")
        self.field(c, "wifi_pass", "Wi-Fi password", "Leave empty for an open network", show=True, trailing="eye", pady=(0, 0))
        c = self.card(a, "Blocklist", "What gets blocked", "shield")
        self.bl_dd = self.dropdown(c, "Source", self.v_bl, [BUNDLED, OWN_FILE], command=self.on_bl_source)
        self.bl_info = tk.Label(c, text="", font=mdui.FONTS.small, bg=th.card, fg=th.text2, anchor="w", justify="left", wraplength=px(340))
        self.bl_info.pack(fill="x", padx=px(2))
        c = self.card(b, "Dashboard", "Where you manage the device", "lock")
        self.field(c, "dash_pass", "Dashboard password", "Leave empty and a strong one is generated for you")
        sw = mdui.Switch(c, th, "No password (open dashboard)", self.v_noauth, command=self.on_noauth)
        sw.pack(fill="x", pady=(px(4), px(6)))
        self.noauth_warn = mdui.Callout(c, th, "Anyone on your network can open the dashboard, change settings and install firmware.", "warn")
        c = self.card(b, "Automatic updates", "Keep the blocklist fresh", "refresh")
        self.field(c, "bl_url", "Blocklist URL", "Direct link to blocklist.bin (https://...)")
        self.field(c, "bl_hours", "Check every (hours)", "0 = never", pady=(0, 0))

    def page_network(self, page):
        th = self.th
        a, b = self.columns(page)
        c = self.card(a, "Upstream DNS", "Who answers what C3Hole doesn't block", "globe")
        self.dropdown(c, "Provider", self.v_preset, [p[0] for p in core.PRESETS], command=self.on_preset,
                      helper="Two different providers means one outage can't stop DNS.")
        row = tk.Frame(c, bg=th.card)
        row.pack(fill="x", pady=(0, px(8)))
        row.columnconfigure(0, weight=1, uniform="u")
        row.columnconfigure(1, weight=1, uniform="u")
        t1 = mdui.TextField(row, th, "Server 1", self.sv["up1"], on_change=self.refresh_errors)
        t2 = mdui.TextField(row, th, "Server 2 (optional)", self.sv["up2"], on_change=self.refresh_errors)
        t1.grid(row=0, column=0, sticky="ew", padx=(0, px(6)))
        t2.grid(row=0, column=1, sticky="ew", padx=(px(6), 0))
        for n, t in (("up1", t1), ("up2", t2)):
            t.entry.bind("<FocusOut>", lambda e, n=n: self.touch(n), add="+")
            self.fields[n] = t
        tk.Label(c, text="Your own resolver works too: 192.168.0.5 or 192.168.0.5:5353", font=mdui.FONTS.tiny, bg=th.card,
                 fg=th.text2, anchor="w").pack(fill="x", padx=px(2), pady=(0, px(8)))
        self.dropdown(c, "When asking upstream", self.v_mode, self.mode_opts)
        self.field(c, "up_timeout", "Failover timeout (ms)", "How long to wait before asking again", pady=(0, 0))
        c = self.card(b, "Radio & power", "Cooler, steadier Wi-Fi", "tune")
        self.dropdown(c, "Wi-Fi transmit power", self.v_tx, self.tx_labels, helper="Lower runs cooler. Try 8.5 dBm if Wi-Fi is unstable.")
        self.dropdown(c, "Wi-Fi power save", self.v_ps, self.ps_opts, helper="For a DNS server keep this Off: sleeping delays replies.")
        self.dropdown(c, "CPU speed", self.v_cpu, self.cpu_opts, helper="80 MHz runs cooler.")
        self.field(c, "bloom_kb", "Bloom filter (KB)", "0 = automatic. Smaller saves memory, never causes wrong blocks.", pady=(0, 0))

    def page_device(self, page):
        th = self.th
        a, b = self.columns(page)
        c = self.card(a, "Board", "The ESP32-C3 you plugged in", "chip")
        self.port_dd = self.dropdown(c, "Serial port", self.v_port, [], helper="Not listed? Use a data cable, then hold BOOT, tap RESET, release BOOT.")
        self.dropdown(c, "Flash speed", self.v_baud, ["115200", "230400", "460800", "921600"], helper="Lower it if flashing fails.")
        mdui.Switch(c, th, "Erase all flash first", self.v_erase, helper="Recommended: clears old firmware and settings").pack(fill="x", pady=(px(2), 0))
        c = self.card(b, "Firmware updates", "Optional: update from the dashboard", "bolt")
        self.field(c, "fw_url", "Firmware URL", "Direct link to firmware.bin (https://...)", pady=(0, px(6)))
        about = "Bundled with this flasher"
        if self.man:
            about = "Bundled: %s domains, firmware v%s, built %s" % (format(self.man["blocklist_domains"], ","), self.man.get("version", "?"), self.man["built_at"])
        mdui.Callout(c, th, about, "info").pack(fill="x", pady=(px(4), 0))

    def page_log(self, page):
        th = self.th
        card = mdui.Card(page, th, "Details", "Everything the flasher and the board reported", "terminal")
        card.pack(fill="both", expand=True)
        # the card sizes itself to its content; give the text a fixed comfortable height
        self.log_text = tk.Text(card.body, height=14, wrap="word", font=mdui.FONTS.mono, bg=th.card2, fg=th.text2, relief="flat", bd=0,
                                padx=px(10), pady=px(8), state="disabled", insertbackground=th.text, highlightthickness=0)
        self.log_text.pack(fill="both", expand=True)
        row = tk.Frame(card.body, bg=th.card)
        row.pack(fill="x", pady=(px(10), 0))
        mdui.Button(row, th, "Copy log", self.copy_log, kind="tonal", icon_name="copy", min_w=0).pack(side="left")

    # ------------------------------------------------------------------ interaction
    def show_page(self, i):
        self.page_idx = i
        self.rail.select(i)
        self.pages.show(i)

    def toggle_theme(self):
        if self.busy:
            self.toast.show("Finish flashing first")
            return
        self.dark = not self.dark
        s = dict(self.saved)
        s["theme"] = "dark" if self.dark else "light"
        self.saved = s
        core.save_settings(s)
        self.build()

    def touch(self, name):
        self.touched.add(name)
        self.refresh_errors()

    def on_preset(self, name):
        for n, a, b in core.PRESETS:
            if n == name and a:
                self.sv["up1"].set(a)
                self.sv["up2"].set(b)

    def on_noauth(self, refresh=True):
        on = self.v_noauth.get()
        tf = self.fields.get("dash_pass")
        if tf:
            tf.set_enabled(not on)
        if on:
            self.noauth_warn.pack(fill="x", pady=(0, px(6)))
        elif self.noauth_warn.winfo_manager():
            self.noauth_warn.pack_forget()
        if refresh:
            self.refresh_errors()

    def on_bl_source(self, v):
        if v == OWN_FILE:
            p = filedialog.askopenfilename(filetypes=[("C3Hole blocklist", "*.bin"), ("All files", "*.*")])
            if p:
                label = "File: " + os.path.basename(p)
                self.v_blpath.set(p)
                self.bl_dd.set_values([BUNDLED, OWN_FILE, label])
                self.v_bl.set(label)
            else:
                self.v_bl.set(self.prev_bl)
        elif v == BUNDLED:
            self.v_blpath.set("")
        self.prev_bl = self.v_bl.get()
        self.update_bl_info()
        self.refresh_errors()

    def update_bl_info(self):
        th = self.th
        path = self.v_blpath.get()
        err = self.errs.get("bl_file") if path else ""
        if err:
            self.bl_info.config(text=err, fg=th.error)
            return
        if path:
            try:
                with open(path, "rb") as f:
                    head = f.read(48)
                n = struct.unpack_from("<I", head, 8)[0]
                self.bl_info.config(text="%s domains, %.2f MB" % (format(n, ","), os.path.getsize(path) / 1048576.0), fg=th.text2)
            except Exception:
                self.bl_info.config(text="", fg=th.text2)
        elif self.man:
            self.bl_info.config(text="StevenBlack + Hagezi Multi PRO: %s domains, %.2f MB, built %s" % (
                format(self.man["blocklist_domains"], ","), self.man["blocklist_bytes"] / 1048576.0, self.man["built_at"]), fg=th.text2)
        else:
            self.bl_info.config(text="Bundled list missing: use the .exe built by the workflow.", fg=th.error)

    def copy_text(self, text, what):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.toast.show("%s copied" % what)

    def copy_log(self):
        self.copy_text("\n".join(self.log_lines), "Log")

    # ---- validation + status bar
    def blocklist_limit(self):
        return self.man["blocklist_size"] if self.man else 0

    def first_problem(self):
        """(field, message, page) of whatever blocks flashing, or None."""
        e = self.errs
        for k in core.FIELD_ORDER:
            if k in e:
                return k, e[k], core.FIELD_PAGE.get(k, 0)
        if not self.man:
            return None, "Bundled firmware is missing: use the .exe built by the workflow.", 2
        if not self.selected_port():
            return None, "No board found. Plug in the ESP32-C3 with a data cable.", 2
        return None

    def refresh_errors(self):
        try:
            self.errs = core.field_errors(self.form(), self.blocklist_limit(), self.v_blpath.get() or None)
            for name, tf in self.fields.items():
                tf.set_error(self.errs.get(name) if name in self.touched else "")
            self.update_bl_info()
            self.update_status()
        except tk.TclError:
            pass

    def set_status(self, text, kind):
        th = self.th
        col = {"ok": th.ok, "warn": th.warn, "err": th.error}.get(kind, th.text2)
        self.status_icon.delete("all")
        mdui.icon(self.status_icon, "check" if kind == "ok" else "warn", px(12), px(12), px(20), col, bg=th.card)
        self.status_lbl.config(text=text, fg=th.text if kind != "ok" else th.text2)

    def update_status(self):
        p = self.first_problem()
        if p:
            self.set_status(p[1], "warn")
        else:
            self.set_status("Ready. Press Flash (Ctrl+Enter).", "ok")

    # ---- serial ports
    def selected_port(self):
        return self.port_map.get(self.v_port.get())

    def refresh_ports(self, once=False):
        if not self.busy:
            try:
                ports = core.list_ports_info()
                if ports != self.ports_raw:
                    had_esp = any(p[2] for p in self.ports_raw)
                    first = self.ports_raw == [] and not hasattr(self, "_ports_seen")
                    self._ports_seen = True
                    self.ports_raw = ports
                    self.port_map = {}
                    labels = []
                    for dev, label, esp in ports:
                        lab = label + ("   (ESP32-C3)" if esp else "")
                        self.port_map[lab] = dev
                        labels.append(lab)
                    if self.v_port.get() not in self.port_map:
                        self.v_port.set(labels[0] if labels else "")
                    self.update_port_ui()
                    self.refresh_errors()
                    new_esp = [p for p in ports if p[2]]
                    if new_esp and not had_esp and not first:
                        self.toast.show("ESP32-C3 detected on %s" % new_esp[0][0])
            except tk.TclError:
                pass
        if not once:
            self.root.after(2000, self.refresh_ports)

    def update_port_ui(self):
        th = self.th
        try:
            self.port_dd.set_values(list(self.port_map))
        except Exception:
            pass
        dev = self.selected_port()
        if dev:
            esp = any(p[0] == dev and p[2] for p in self.ports_raw)
            self.chip.update_chip("%s  ESP32-C3" % dev if esp else dev, th.ok if esp else th.warn)
        else:
            self.chip.update_chip("No board detected", th.outline_hi)

    # ------------------------------------------------------------------ flashing
    def ask(self, title, lines, ok, cancel="Cancel"):
        return mdui.confirm(self.root, self.th, title, lines, ok=ok, cancel=cancel)

    def start(self):
        if self.busy:
            return
        self.touched |= set(self.fields)
        self.refresh_errors()
        p = self.first_problem()
        if p:
            field, msg, page = p
            self.show_page(page)
            self.toast.show(msg, 4800)
            if field in self.fields:
                self.fields[field].entry.focus_set()
            return
        d = self.form()
        dev = self.selected_port()
        lines = [("info", "Board: %s" % self.v_port.get().strip())]
        if self.v_erase.get():
            lines.append(("info", "The board is erased first: old firmware and settings are removed."))
        if d["no_auth"]:
            lines.append(("warn", "No dashboard password: anyone on your network can open the dashboard, change settings and install firmware."))
        if not self.ask("Ready to flash?", lines, "Flash"):
            return
        generated = False
        if not d["no_auth"] and not d["dash_pass"]:
            d["dash_pass"] = cfgblob.random_password(12)
            generated = True
        mode = self.mode_opts.index(self.v_mode.get())
        d.update(tx_power=self.tx_by_label[self.v_tx.get()], ps_mode=self.ps_opts.index(self.v_ps.get()),
                 cpu_mhz=int(self.v_cpu.get().split()[0]), up_mode=mode)
        keep = {k: d[k] for k in ("ssid", "bl_url", "bl_hours", "fw_url", "up1", "up2", "bloom_kb", "up_timeout", "tx_power", "ps_mode", "cpu_mhz", "up_mode")}
        s = dict(self.saved)
        s.update(keep)
        self.saved = s
        core.save_settings(s)
        d.update(port=dev, baud=int(self.v_baud.get()), erase=self.v_erase.get(), generated=generated,
                 blocklist_path=self.v_blpath.get() or None)
        self.stop.clear()
        self.busy = True
        self.cur_stage = 0
        self.show_progress()
        threading.Thread(target=core.flash_job, args=(d, self.q, self.stop), daemon=True).start()

    # ---- overlay
    def open_overlay(self):
        th = self.th
        if self.overlay is not None:
            self.overlay.destroy()
        ov = tk.Frame(self.root, bg=th.scrim)
        ov.place(x=0, y=px(65), relwidth=1, relheight=1)
        ov.lift()
        card = mdui.Card(ov, th, pad=26, bg=th.scrim)
        card.place(relx=0.5, rely=0.46, anchor="center", width=px(640))
        self.overlay = ov
        self.ov_body = card.body
        return card.body

    def close_overlay(self):
        if self.overlay is not None:
            self.overlay.destroy()
            self.overlay = None
        self.busy = False
        self.update_status()

    def clear(self, w):
        for c in w.winfo_children():
            c.destroy()

    def show_progress(self):
        th, F = self.th, mdui.FONTS
        b = self.open_overlay()
        tk.Label(b, text="Flashing C3Hole", font=F.h1, bg=th.card, fg=th.text, anchor="w").pack(fill="x")
        tk.Label(b, text="Please keep the board plugged in", font=F.small, bg=th.card, fg=th.text2, anchor="w").pack(fill="x", pady=(0, px(14)))
        self.stepper = mdui.Stepper(b, th, self.STEPS)
        self.stepper.pack(fill="x")
        self.prog = mdui.LinearProgress(b, th)
        self.prog.pack(fill="x", pady=(px(10), px(8)))
        self.prog.set_indeterminate(True)
        row = tk.Frame(b, bg=th.card)
        row.pack(fill="x")
        self.stage_lbl = tk.Label(row, text="Starting...", font=F.body, bg=th.card, fg=th.text, anchor="w")
        self.stage_lbl.pack(side="left")
        self.pct_lbl = tk.Label(row, text="", font=F.bold, bg=th.card, fg=th.primary)
        self.pct_lbl.pack(side="right")
        self.last_lbl = tk.Label(b, text="", font=F.mono, bg=th.card, fg=th.text2, anchor="w")
        self.last_lbl.pack(fill="x", pady=(px(10), 0))

    def kv(self, parent, key, value, actions=(), mono=False):
        th = self.th
        row = tk.Frame(parent, bg=th.card)
        row.pack(fill="x", pady=px(3))
        tk.Label(row, text=key, font=mdui.FONTS.small, bg=th.card, fg=th.text2, width=11, anchor="w").pack(side="left")
        tk.Label(row, text=value, font=mdui.FONTS.mono if mono else mdui.FONTS.bold, bg=th.card, fg=th.text, anchor="w").pack(side="left")
        for name, cmd in reversed(actions):
            mdui.IconButton(row, th, name, cmd, bg=th.card, size=34).pack(side="right")
        return row

    def result_badge(self, parent, ok):
        th = self.th
        s = px(96)
        cv = tk.Canvas(parent, width=s, height=s, bg=th.card, highlightthickness=0)
        cv.pack(pady=(0, px(6)))
        col = th.ok if ok else th.error

        def step(t):
            cv.delete("all")
            r = s * 0.42 * t
            cv.create_oval(s / 2 - r, s / 2 - r, s / 2 + r, s / 2 + r, fill=col, outline="")
            if t > 0.7:
                mdui.icon(cv, "check" if ok else "close", s / 2, s / 2, s * 0.5 * t, "#FFFFFF" if not th.dark else "#0B1F12", bg=col)
        mdui.animate(cv, 14, step)

    def show_success(self, r):
        th, F = self.th, mdui.FONTS
        self.busy = False
        b = self.open_overlay()
        self.busy = True
        self.result_badge(b, True)
        tk.Label(b, text="All set!" if r["ip"] else "Flashed", font=F.h1, bg=th.card, fg=th.text).pack()
        tk.Label(b, text="C3Hole is installed and starting." if not r["ip"] else "C3Hole is running and ready to block.",
                 font=F.small, bg=th.card, fg=th.text2).pack(pady=(0, px(12)))
        info = tk.Frame(b, bg=th.card)
        info.pack(fill="x")
        url = None
        if r["ip"]:
            url = "http://%s" % r["ip"]
            self.kv(info, "Dashboard", url, actions=[("open", lambda: webbrowser.open(url))])
        if r["no_auth"]:
            self.kv(info, "Password", "none (open dashboard)")
        else:
            self.kv(info, "Username", "admin")
            self.kv(info, "Password", r["password"], actions=[("copy", lambda: self.copy_text(r["password"], "Password"))], mono=True)
            if r["generated"]:
                tk.Label(info, text="Generated for you. Save it now.", font=F.tiny, bg=th.card, fg=th.warn).pack(anchor="w", padx=px(2))
        notes = tk.Frame(b, bg=th.card)
        notes.pack(fill="x", pady=(px(14), 0))
        if r["ip"]:
            if r["login"] is True and not r["no_auth"]:
                mdui.Callout(notes, th, "Login check passed: the dashboard accepted the password.", "info").pack(fill="x", pady=(0, px(8)))
            elif r["login"] is False:
                mdui.Callout(notes, th, "The device rejected the password. Please flash again and report this.", "warn").pack(fill="x", pady=(0, px(8)))
            mdui.Callout(notes, th, "Next: set your router's DNS to %s and reserve that address in DHCP." % r["ip"], "info").pack(fill="x")
        else:
            mdui.Callout(notes, th, "The board did not report an IP within 60 s. Check the Wi-Fi name and password, then press RESET. "
                         "Hold BOOT for 5 s to wipe settings and use the 'C3Hole-Setup' Wi-Fi.", "warn").pack(fill="x")
        btns = tk.Frame(b, bg=th.card)
        btns.pack(fill="x", pady=(px(18), 0))
        mdui.Button(btns, th, "Done", self.close_overlay, kind="filled").pack(side="right")
        if url:
            mdui.Button(btns, th, "Open dashboard", lambda: webbrowser.open(url), kind="tonal", icon_name="open").pack(side="right", padx=(0, px(8)))

    def show_failure(self, msg):
        th, F = self.th, mdui.FONTS
        b = self.open_overlay()
        self.busy = True
        self.result_badge(b, False)
        tk.Label(b, text="Flashing failed", font=F.h1, bg=th.card, fg=th.text).pack()
        tk.Label(b, text="Stopped during: %s" % self.STEPS[min(self.cur_stage, len(self.STEPS) - 1)], font=F.small, bg=th.card, fg=th.text2).pack(pady=(0, px(10)))
        tk.Label(b, text=msg, font=F.small, bg=th.card, fg=th.error, wraplength=px(560), justify="left", anchor="w").pack(fill="x")
        hint = None
        low = msg.lower()
        if any(k in low for k in ("failed to connect", "no serial data", "could not open", "permissionerror", "timed out")):
            hint = ("Try another USB cable or port and close any serial monitor. Then hold BOOT, tap RESET, release BOOT and press Flash again.")
        if hint:
            mdui.Callout(b, th, hint, "warn").pack(fill="x", pady=(px(12), 0))
        btns = tk.Frame(b, bg=th.card)
        btns.pack(fill="x", pady=(px(18), 0))
        mdui.Button(btns, th, "Close", self.close_overlay, kind="filled").pack(side="right")
        mdui.Button(btns, th, "Show details", lambda: (self.close_overlay(), self.show_page(3)), kind="outlined", icon_name="terminal").pack(side="right", padx=(0, px(8)))

    # ------------------------------------------------------------------ queue + log
    def _log_insert(self, line):
        try:
            self.log_text.config(state="normal")
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        except (tk.TclError, AttributeError):
            pass

    def poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self.log_lines.append(msg[1])
                    self._log_insert(msg[1])
                    if self.overlay is not None and hasattr(self, "last_lbl") and self.last_lbl.winfo_exists():
                        self.last_lbl.config(text=msg[1][:70])
                elif kind == "progress" and self.overlay is not None and self.prog.winfo_exists():
                    self.prog.set_indeterminate(False)
                    self.prog.set(msg[1] / 100.0)
                    self.pct_lbl.config(text="%d%%" % int(msg[1]))
                elif kind == "stage" and self.overlay is not None and self.stepper.winfo_exists():
                    self.stepper.set(msg[1], msg[2])
                    if msg[2] == "active":
                        self.cur_stage = msg[1]
                elif kind == "status" and self.overlay is not None and self.stage_lbl.winfo_exists():
                    self.stage_lbl.config(text=msg[1])
                elif kind == "done":
                    self.show_success(msg[1])
                elif kind == "error":
                    self.show_failure(msg[1])
        except queue.Empty:
            pass
        except tk.TclError:
            pass
        self.root.after(70, self.poll)

    def on_close(self):
        if self.busy and not self.ask("Quit while flashing?", [("warn", "The board may be left half-flashed. You can flash it again afterwards.")], "Quit", "Keep flashing"):
            return
        self.stop.set()
        self.root.destroy()
