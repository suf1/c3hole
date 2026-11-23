"""A small Material-style widget kit for tkinter (pure standard library, drawn on Canvas).

Everything that takes a size goes through px() so the UI stays crisp and correctly sized on high-DPI displays.
"""
import math
import sys
import tkinter as tk
from tkinter import font as tkfont

SCALE = 1.0
FONTS = None


def px(n):
    return int(round(n * SCALE))


def init(root):
    """Call once after creating the Tk root."""
    global SCALE, FONTS
    try:
        SCALE = max(1.0, root.winfo_fpixels("1i") / 96.0)
    except Exception:
        SCALE = 1.0
    fams = set(tkfont.families(root))

    def pick(*names):
        for n in names:
            if n in fams:
                return n
        return "Helvetica"

    sans = pick("Segoe UI", "Roboto", "Noto Sans", "DejaVu Sans", "Helvetica", "Arial")
    mono = pick("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New")

    class F:
        pass

    f = F()
    mk = lambda fam, size, w="normal": tkfont.Font(root=root, family=fam, size=size, weight=w)
    f.body, f.small, f.tiny = mk(sans, 10), mk(sans, 9), mk(sans, 8)
    f.btn, f.bold = mk(sans, 10, "bold"), mk(sans, 10, "bold")
    f.h2, f.h1, f.big = mk(sans, 12, "bold"), mk(sans, 17, "bold"), mk(sans, 21, "bold")
    f.mono = mk(mono, 9)
    FONTS = f
    return f


# ------------------------------------------------------------------ colour + theme
def _rgb(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def mix(a, b, t):
    ra, rb = _rgb(a), _rgb(b)
    return "#%02x%02x%02x" % tuple(int(round(x + (y - x) * t)) for x, y in zip(ra, rb))


def ease(t):
    return 1 - (1 - t) ** 3


class Theme:
    def __init__(self, dark):
        self.dark = dark
        if dark:
            self.bg, self.card, self.card2 = "#111318", "#1C1F27", "#252934"
            self.outline, self.outline_hi = "#3A3F4D", "#8C91A0"
            self.text, self.text2 = "#E3E5EE", "#B3B8C6"
            self.primary, self.on_primary = "#A8C7FF", "#002F68"
            self.primary_c, self.on_primary_c = "#1D4A91", "#D6E3FF"
            self.error, self.ok, self.warn = "#F2B8B5", "#7EDB98", "#F5B761"
            self.shadow, self.snack, self.on_snack = "#0A0C10", "#E3E5EE", "#1B1E26"
        else:
            self.bg, self.card, self.card2 = "#EEF1F8", "#FFFFFF", "#F4F6FB"
            self.outline, self.outline_hi = "#C3C8D4", "#747A89"
            self.text, self.text2 = "#1B1E26", "#4A5060"
            self.primary, self.on_primary = "#0B57D0", "#FFFFFF"
            self.primary_c, self.on_primary_c = "#D6E3FF", "#00204F"
            self.error, self.ok, self.warn = "#B3261E", "#146C2E", "#8C5000"
            self.shadow, self.snack, self.on_snack = "#D5DAE6", "#2E3138", "#F1F0F7"
        self.scrim = mix(self.bg, "#000000", 0.55 if not dark else 0.6)


def system_prefers_dark():
    if sys.platform.startswith("win"):
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
        except Exception:
            return False
    return False


# ------------------------------------------------------------------ drawing helpers
def rr(c, x1, y1, x2, y2, r, **kw):
    r = max(0, min(r, (x2 - x1) / 2.0, (y2 - y1) / 2.0))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


def icon(c, name, cx, cy, s, col, bg="", tag="ic"):
    """Draw a simple line icon centred on (cx, cy) with size s (already scaled)."""
    lw = max(2, int(round(s / 11.0)))
    k = dict(tags=tag)
    def ln(pts, **o):
        opts = dict(fill=col, width=lw, capstyle="round", joinstyle="round", tags=tag)
        opts.update(o)
        return c.create_line(*pts, **opts)
    if name == "wifi":
        y0 = cy + s * 0.30
        for r in (0.58, 0.38, 0.18):
            R = s * r
            c.create_arc(cx - R, y0 - R, cx + R, y0 + R, start=45, extent=90, style="arc", outline=col, width=lw, **k)
        c.create_oval(cx - lw, y0 - lw, cx + lw, y0 + lw, fill=col, outline=col, **k)
    elif name == "lock":
        c.create_arc(cx - s * .2, cy - s * .44, cx + s * .2, cy + s * .02, start=0, extent=180, style="arc", outline=col, width=lw, **k)
        rr(c, cx - s * .32, cy - s * .08, cx + s * .32, cy + s * .42, s * .08, fill=col, outline=col, **k)
        c.create_oval(cx - lw, cy + s * .08 - lw, cx + lw, cy + s * .08 + lw, fill=bg or "#fff", outline=bg or "#fff", **k)
    elif name == "shield":
        pts = [cx, cy - s * .46, cx + s * .38, cy - s * .3, cx + s * .34, cy + s * .1, cx, cy + s * .46, cx - s * .34, cy + s * .1, cx - s * .38, cy - s * .3]
        c.create_polygon(pts, outline=col, fill="", width=lw, joinstyle="round", **k)
        ln([cx - s * .14, cy, cx - s * .02, cy + s * .13, cx + s * .18, cy - s * .12])
    elif name == "tune":
        for dy, kx in ((-.28, -.15), (0, .2), (.28, -.05)):
            ln([cx - s * .42, cy + dy * s, cx + s * .42, cy + dy * s])
            c.create_oval(cx + kx * s - s * .11, cy + dy * s - s * .11, cx + kx * s + s * .11, cy + dy * s + s * .11, fill=bg or col, outline=col, width=lw, **k)
    elif name == "chip":
        rr(c, cx - s * .26, cy - s * .26, cx + s * .26, cy + s * .26, s * .05, outline=col, fill="", width=lw, **k)
        for d in (-.14, .14):
            for sx in (-1, 1):
                ln([cx + sx * s * .26, cy + d * s, cx + sx * s * .42, cy + d * s])
                ln([cx + d * s, cy + sx * s * .26, cx + d * s, cy + sx * s * .42])
    elif name == "terminal":
        rr(c, cx - s * .45, cy - s * .34, cx + s * .45, cy + s * .34, s * .07, outline=col, fill="", width=lw, **k)
        ln([cx - s * .26, cy - s * .12, cx - s * .06, cy, cx - s * .26, cy + s * .12])
        ln([cx + s * .04, cy + s * .14, cx + s * .26, cy + s * .14])
    elif name == "sun":
        c.create_oval(cx - s * .2, cy - s * .2, cx + s * .2, cy + s * .2, outline=col, width=lw, **k)
        for i in range(8):
            a = i * math.pi / 4
            ln([cx + math.cos(a) * s * .32, cy + math.sin(a) * s * .32, cx + math.cos(a) * s * .46, cy + math.sin(a) * s * .46])
    elif name == "moon":
        c.create_oval(cx - s * .34, cy - s * .34, cx + s * .34, cy + s * .34, fill=col, outline=col, **k)
        c.create_oval(cx - s * .12, cy - s * .46, cx + s * .5, cy + s * .16, fill=bg, outline=bg, **k)
    elif name == "check":
        ln([cx - s * .3, cy + s * .02, cx - s * .08, cy + s * .24, cx + s * .32, cy - s * .22], width=lw + 1)
    elif name == "close":
        ln([cx - s * .26, cy - s * .26, cx + s * .26, cy + s * .26])
        ln([cx - s * .26, cy + s * .26, cx + s * .26, cy - s * .26])
    elif name == "refresh":
        c.create_arc(cx - s * .32, cy - s * .32, cx + s * .32, cy + s * .32, start=50, extent=280, style="arc", outline=col, width=lw, **k)
        ex, ey = cx + s * .32 * math.cos(math.radians(50)), cy - s * .32 * math.sin(math.radians(50))
        c.create_polygon(ex - s * .06, ey - s * .2, ex + s * .2, ey - s * .02, ex - s * .08, ey + s * .1, fill=col, outline=col, **k)
    elif name in ("eye", "eyeoff"):
        c.create_oval(cx - s * .46, cy - s * .24, cx + s * .46, cy + s * .24, outline=col, width=lw, **k)
        c.create_oval(cx - s * .12, cy - s * .12, cx + s * .12, cy + s * .12, fill=col, outline=col, **k)
        if name == "eyeoff":
            ln([cx - s * .4, cy + s * .34, cx + s * .4, cy - s * .34])
    elif name == "chevron":
        ln([cx - s * .2, cy - s * .08, cx, cy + s * .12, cx + s * .2, cy - s * .08])
    elif name == "info":
        c.create_oval(cx - s * .42, cy - s * .42, cx + s * .42, cy + s * .42, outline=col, width=lw, **k)
        ln([cx, cy - s * .04, cx, cy + s * .22])
        c.create_oval(cx - lw * .7, cy - s * .22 - lw * .7, cx + lw * .7, cy - s * .22 + lw * .7, fill=col, outline=col, **k)
    elif name == "warn":
        c.create_polygon(cx, cy - s * .42, cx + s * .46, cy + s * .34, cx - s * .46, cy + s * .34, outline=col, fill="", width=lw, joinstyle="round", **k)
        ln([cx, cy - s * .12, cx, cy + s * .1])
        c.create_oval(cx - lw * .7, cy + s * .2 - lw * .7, cx + lw * .7, cy + s * .2 + lw * .7, fill=col, outline=col, **k)
    elif name == "copy":
        rr(c, cx - s * .1, cy - s * .36, cx + s * .36, cy + s * .14, s * .05, outline=col, fill="", width=lw, **k)
        rr(c, cx - s * .36, cy - s * .12, cx + s * .1, cy + s * .38, s * .05, outline=col, fill=bg or "", width=lw, **k)
    elif name == "open":
        ln([cx - s * .08, cy + s * .08, cx + s * .34, cy - s * .34])
        ln([cx + s * .1, cy - s * .34, cx + s * .34, cy - s * .34, cx + s * .34, cy - s * .1])
        ln([cx + s * .2, cy + s * .02, cx + s * .2, cy + s * .34, cx - s * .34, cy + s * .34, cx - s * .34, cy - s * .2, cx - s * .08, cy - s * .2])
    elif name == "bolt":
        c.create_polygon(cx + s * .06, cy - s * .46, cx - s * .26, cy + s * .06, cx - s * .02, cy + s * .06, cx - s * .08, cy + s * .46,
                         cx + s * .26, cy - s * .08, cx + s * .02, cy - s * .08, fill=col, outline=col, joinstyle="round", **k)
    elif name == "globe":
        c.create_oval(cx - s * .4, cy - s * .4, cx + s * .4, cy + s * .4, outline=col, width=lw, **k)
        c.create_oval(cx - s * .16, cy - s * .4, cx + s * .16, cy + s * .4, outline=col, width=lw, **k)
        ln([cx - s * .4, cy, cx + s * .4, cy])
    elif name == "plug":
        rr(c, cx - s * .24, cy - s * .08, cx + s * .24, cy + s * .26, s * .06, outline=col, fill="", width=lw, **k)
        ln([cx - s * .12, cy - s * .08, cx - s * .12, cy - s * .34])
        ln([cx + s * .12, cy - s * .08, cx + s * .12, cy - s * .34])
        ln([cx, cy + s * .26, cx, cy + s * .44])
    elif name == "list":
        for dy in (-.26, 0, .26):
            c.create_oval(cx - s * .4, cy + dy * s - lw * .8, cx - s * .4 + lw * 1.6, cy + dy * s + lw * .8, fill=col, outline=col, **k)
            ln([cx - s * .22, cy + dy * s, cx + s * .42, cy + dy * s])


# ------------------------------------------------------------------ animation helper
def _after(w, ms, fn):
    """Schedule on the app root (not the widget) so timers survive widget rebuilds without 'invalid command' errors."""
    try:
        return w._root().after(ms, fn)
    except Exception:
        return None


def animate(widget, frames, step, done=None, interval=14):
    """Call step(t) with t easing 0..1 over `frames` frames, then done()."""
    state = {"i": 0}

    def tick():
        try:
            if not widget.winfo_exists():
                return
        except tk.TclError:
            return
        state["i"] += 1
        t = min(1.0, state["i"] / float(frames))
        step(ease(t))
        if t < 1.0:
            _after(widget, interval, tick)
        elif done:
            done()
    _after(widget, interval, tick)


# ------------------------------------------------------------------ Card
class Card(tk.Canvas):
    def __init__(self, parent, th, title="", subtitle="", icon_name=None, pad=18, bg=None):
        tk.Canvas.__init__(self, parent, highlightthickness=0, bd=0, bg=bg or th.bg, height=px(60))
        self.th, self.pad = th, px(pad)
        self.body = tk.Frame(self, bg=th.card)
        self._win = self.create_window(self.pad, self.pad, window=self.body, anchor="nw")
        self.bind("<Configure>", self._on_cfg)
        self.body.bind("<Configure>", self._on_body)
        if title:
            head = tk.Frame(self.body, bg=th.card)
            head.pack(fill="x", pady=(0, px(10)))
            if icon_name:
                ic = tk.Canvas(head, width=px(40), height=px(40), bg=th.card, highlightthickness=0)
                ic.pack(side="left", padx=(0, px(12)))
                ic.create_oval(1, 1, px(40) - 1, px(40) - 1, fill=th.primary_c, outline="")
                icon(ic, icon_name, px(20), px(20), px(22), th.on_primary_c, bg=th.primary_c)
            col = tk.Frame(head, bg=th.card)
            col.pack(side="left", fill="x")
            tk.Label(col, text=title, font=FONTS.h2, bg=th.card, fg=th.text, anchor="w").pack(anchor="w")
            if subtitle:
                tk.Label(col, text=subtitle, font=FONTS.small, bg=th.card, fg=th.text2, anchor="w").pack(anchor="w")

    def _on_cfg(self, e):
        self.itemconfigure(self._win, width=max(10, e.width - 2 * self.pad))
        self.delete("bg")
        rr(self, 1, 2, e.width - 2, e.height - 1, px(16), fill=self.th.shadow, outline="", tags="bg")
        rr(self, 1, 0, e.width - 2, e.height - 3, px(16), fill=self.th.card, outline=self.th.outline, tags="bg")
        self.tag_lower("bg")

    def _on_body(self, e):
        h = self.body.winfo_reqheight() + 2 * self.pad + px(3)
        if int(float(self.cget("height"))) != h:
            self.configure(height=h)


# ------------------------------------------------------------------ Callout (tinted info / warning box)
class Callout(tk.Canvas):
    def __init__(self, parent, th, text, kind="info", bg=None):
        tk.Canvas.__init__(self, parent, highlightthickness=0, bd=0, bg=bg or th.card, height=px(40))
        self.th = th
        warn = kind == "warn"
        self.fill = mix(th.card, th.warn, 0.14) if warn else th.primary_c
        fg = th.text if warn else th.on_primary_c
        self.pad = px(12)
        self.body = tk.Frame(self, bg=self.fill)
        ic = tk.Canvas(self.body, width=px(22), height=px(22), bg=self.fill, highlightthickness=0)
        ic.pack(side="left", padx=(0, px(10)), anchor="n")
        icon(ic, "warn" if warn else "info", px(11), px(11), px(20), th.warn if warn else th.on_primary_c, bg=self.fill)
        self.lbl = tk.Label(self.body, text=text, font=FONTS.small, bg=self.fill, fg=fg, justify="left", anchor="w", wraplength=px(300))
        self.lbl.pack(side="left", fill="x", expand=True)
        self._win = self.create_window(self.pad, px(10), window=self.body, anchor="nw")
        self.bind("<Configure>", self._on_cfg)
        self.body.bind("<Configure>", self._on_body)

    def _on_cfg(self, e):
        self.itemconfigure(self._win, width=max(10, e.width - 2 * self.pad))
        self.lbl.config(wraplength=max(80, e.width - 2 * self.pad - px(40)))
        self.delete("bg")
        rr(self, 0, 0, e.width - 1, e.height - 1, px(12), fill=self.fill, outline="", tags="bg")
        self.tag_lower("bg")

    def _on_body(self, e):
        h = self.body.winfo_reqheight() + px(20)
        if int(float(self.cget("height"))) != h:
            self.configure(height=h)


# ------------------------------------------------------------------ Button
class Button(tk.Canvas):
    def __init__(self, parent, th, text="", command=None, kind="filled", icon_name=None, bg=None, height=40, fab=False, min_w=0):
        self.th, self.kind, self.text, self.command, self.icon_name, self.fab = th, kind, text, command, icon_name, fab
        h = px(56 if fab else height)
        iw = px(26) if icon_name else 0
        w = max(px(min_w), FONTS.btn.measure(text) + iw + px(56 if fab else 40))
        tk.Canvas.__init__(self, parent, width=w, height=h + px(4), highlightthickness=0, bd=0, bg=bg or th.card, cursor="hand2", takefocus=1)
        self.h, self.w, self._bgc = h, w, bg or th.card
        self.enabled, self._hover, self._press, self._focus = True, False, False, False
        self._fill = self._target_fill()
        self.bind("<Enter>", lambda e: self._set(hover=True))
        self.bind("<Leave>", lambda e: self._set(hover=False, press=False))
        self.bind("<ButtonPress-1>", lambda e: self._set(press=True))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<FocusIn>", lambda e: self._set(focus=True))
        self.bind("<FocusOut>", lambda e: self._set(focus=False))
        self.bind("<space>", lambda e: self.invoke())
        self.bind("<Return>", lambda e: self.invoke())
        self._draw()

    def _target_fill(self):
        th, k = self.th, self.kind
        if not self.enabled:
            return mix(th.card, th.text, 0.12) if k in ("filled", "tonal") else self._bgc
        lvl = 0.16 if self._press else (0.08 if self._hover else 0.0)
        if k == "filled":
            return mix(th.primary, th.on_primary, lvl)
        if k == "tonal":
            return mix(th.primary_c, th.on_primary_c, lvl)
        return mix(self._bgc, th.primary, lvl) if lvl else self._bgc

    def _text_color(self):
        th = self.th
        if not self.enabled:
            return mix(th.card, th.text, 0.4)
        return {"filled": th.on_primary, "tonal": th.on_primary_c}.get(self.kind, th.primary)

    def _set(self, **kw):
        self._hover = kw.get("hover", self._hover)
        self._press = kw.get("press", self._press)
        self._focus = kw.get("focus", self._focus)
        old, new = self._fill, self._target_fill()
        animate(self, 5, lambda t: self._set_fill(mix(old, new, t)), interval=12)

    def _set_fill(self, col):
        self._fill = col
        self._draw()

    def _release(self, e):
        was = self._press
        self._set(press=False)
        if was and self.enabled and 0 <= e.x <= self.w and 0 <= e.y <= self.h:
            self.invoke()

    def invoke(self):
        if self.enabled and self.command:
            self.command()

    def configure_state(self, enabled=None, text=None, kind=None):
        if enabled is not None:
            self.enabled = enabled
            self.configure(cursor="hand2" if enabled else "arrow")
        if text is not None:
            self.text = text
        if kind is not None:
            self.kind = kind
        self._fill = self._target_fill()
        self._draw()

    def _draw(self):
        self.delete("all")
        th, h, w = self.th, self.h, self.w
        r = h / 2.0
        if self.kind in ("filled",) and self.enabled:
            rr(self, 1, px(3), w - 1, h + px(2), r, fill=mix(th.shadow, "#000000", 0.1 if th.dark else 0.0) if not th.dark else "#0A0C10", outline="")
        rr(self, 1, 1, w - 1, h, r, fill=self._fill, outline=th.outline_hi if self.kind == "outlined" else "")
        if self._focus:
            rr(self, 0, 0, w, h + 1, r, fill="", outline=th.primary, width=2)
        col = self._text_color()
        tw = FONTS.btn.measure(self.text)
        iw = px(26) if self.icon_name else 0
        x0 = (w - tw - iw) / 2.0
        if self.icon_name:
            icon(self, self.icon_name, x0 + px(10), h / 2.0 + 1, px(22 if self.fab else 20), col, bg=self._fill)
        self.create_text(x0 + iw, h / 2.0 + 1, text=self.text, font=FONTS.btn, fill=col, anchor="w")


class IconButton(tk.Canvas):
    def __init__(self, parent, th, name, command=None, bg=None, size=40, color=None):
        self.th, self.name, self.command, self.color = th, name, command, color
        self.s = px(size)
        self._bgc = bg or th.card
        tk.Canvas.__init__(self, parent, width=self.s, height=self.s, highlightthickness=0, bd=0, bg=self._bgc, cursor="hand2", takefocus=1)
        self._lvl = 0.0
        self.bind("<Enter>", lambda e: self._to(0.10))
        self.bind("<Leave>", lambda e: self._to(0.0))
        self.bind("<ButtonRelease-1>", lambda e: self.command and self.command())
        self.bind("<space>", lambda e: self.command and self.command())
        self._draw()

    def _to(self, target):
        start = self._lvl
        animate(self, 5, lambda t: self._set(start + (target - start) * t), interval=12)

    def _set(self, v):
        self._lvl = v
        self._draw()

    def set_icon(self, name):
        self.name = name
        self._draw()

    def _draw(self):
        self.delete("all")
        s, th = self.s, self.th
        fill = mix(self._bgc, self.color or th.text, self._lvl) if self._lvl else self._bgc
        self.create_oval(1, 1, s - 1, s - 1, fill=fill, outline="")
        icon(self, self.name, s / 2.0, s / 2.0, int(s * .55), self.color or th.text2, bg=fill)


# ------------------------------------------------------------------ Text field (outlined, floating label)
class TextField(tk.Frame):
    def __init__(self, parent, th, label, var, show=None, helper="", trailing=None, bg=None, width=None, on_change=None):
        bgc = bg or th.card
        tk.Frame.__init__(self, parent, bg=bgc)
        self.th, self.var, self.label, self.helper, self.bgc = th, var, label, helper, bgc
        self.h = px(58)
        self.show_pw = show is not None
        self.trailing = trailing
        self.on_change = on_change
        self._err, self._focus, self._hover, self._enabled = "", False, False, True
        self._t = 1.0 if var.get() else 0.0
        self.cv = tk.Canvas(self, height=self.h, width=px(width) if width else px(220), highlightthickness=0, bd=0, bg=bgc, cursor="xterm", takefocus=1)
        self.cv.pack(fill="x")
        self.msg = tk.Label(self, text=helper, anchor="w", justify="left", font=FONTS.tiny, bg=bgc, fg=th.text2, wraplength=px(330))
        if helper:
            self.msg.pack(fill="x", padx=px(14), pady=(px(2), 0))
        self.entry = tk.Entry(self.cv, textvariable=var, show="*" if show else "", bd=0, highlightthickness=0, relief="flat", font=FONTS.body,
                              bg=bgc, fg=th.text, insertbackground=th.primary, disabledbackground=bgc, disabledforeground=th.text2,
                              selectbackground=th.primary_c, selectforeground=th.on_primary_c)
        self._ew = self.cv.create_window(px(14), self.h // 2 + px(5), window=self.entry, anchor="w", width=px(150))
        self.cv.bind("<Configure>", self._on_cfg)
        self.cv.bind("<Button-1>", self._click)
        self.cv.bind("<FocusIn>", lambda e: self._reveal())       # reached with Tab while the entry is hidden
        self.cv.bind("<Enter>", lambda e: self._setf(hover=True))
        self.cv.bind("<Leave>", lambda e: self._setf(hover=False))
        self.entry.bind("<FocusIn>", lambda e: self._setf(focus=True))
        self.entry.bind("<FocusOut>", lambda e: self._setf(focus=False))
        self._tid = var.trace_add("write", self._on_var)
        self.bind("<Destroy>", self._cleanup)
        self._draw()

    def _cleanup(self, e):
        if e.widget is self:
            try:
                self.var.trace_remove("write", self._tid)
            except Exception:
                pass

    def _on_cfg(self, e):
        trail = px(44) if self.trailing else 0
        self.cv.itemconfigure(self._ew, width=max(20, e.width - px(28) - trail))
        self._draw()

    def _click(self, e):
        if self.trailing == "eye" and e.x > self.cv.winfo_width() - px(46):
            self.show_pw = not self.show_pw
            self.entry.config(show="*" if self.show_pw else "")
            self._draw()
        else:
            self._reveal()

    def _reveal(self):
        if self._enabled:
            self.cv.itemconfigure(self._ew, state="normal")
            self.entry.focus_set()

    def _on_var(self, *a):
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        self._goal()
        if self.on_change:
            self.on_change()

    def _setf(self, focus=None, hover=None):
        if focus is not None:
            self._focus = focus
        if hover is not None:
            self._hover = hover
        self._goal()

    def _goal(self):
        want = 1.0 if (self._focus or self.var.get() != "") else 0.0
        if abs(want - self._t) < 0.01:
            self._draw()
            return
        start = self._t
        animate(self, 7, lambda t: self._step(start + (want - start) * t), interval=13)

    def _step(self, v):
        self._t = v
        self._draw()

    def set_error(self, msg):
        self._err = msg or ""
        text = self._err or self.helper
        self.msg.config(text=text, fg=self.th.error if self._err else self.th.text2)
        if text and not self.msg.winfo_manager():
            self.msg.pack(fill="x", padx=px(14), pady=(px(2), 0))
        elif not text and self.msg.winfo_manager():
            self.msg.pack_forget()
        self._draw()

    def set_enabled(self, on):
        self._enabled = on
        self.entry.config(state="normal" if on else "disabled")
        self._draw()

    def _draw(self):
        c, th = self.cv, self.th
        c.delete("ol")
        w = c.winfo_width() if c.winfo_width() > 1 else int(float(c.cget("width")))
        y0 = px(9)
        if not self._enabled:
            ocol, lw, lcol = mix(th.outline, th.card, .4), 1, mix(th.text2, th.card, .45)
        elif self._err:
            ocol, lw, lcol = th.error, 2, th.error
        elif self._focus:
            ocol, lw, lcol = th.primary, 2, th.primary
        else:
            ocol, lw, lcol = (th.text if self._hover else th.outline_hi), 1, th.text2
        rr(c, 1, y0, w - 2, self.h - px(2), px(10), fill="", outline=ocol, width=lw, tags="ol")
        t = self._t
        ly = (self.h + y0) / 2.0 - px(2) + (y0 - ((self.h + y0) / 2.0 - px(2))) * t
        font = FONTS.tiny if t > 0.5 else FONTS.body
        lx = px(14) if t <= 0.5 else px(12)
        if t > 0.5:
            c.create_rectangle(lx - px(3), ly - px(7), lx + font.measure(self.label) + px(3), ly + px(7), fill=self.bgc, outline="", tags="ol")
        c.create_text(lx, ly, text=self.label, font=font, fill=lcol, anchor="w", tags="ol")
        c.tag_raise("ol")
        if self.trailing == "eye":
            icon(c, "eye" if self.show_pw else "eyeoff", w - px(24), self.h / 2.0 + px(3), px(20), th.text2, bg=self.bgc, tag="ol")
        self.entry.configure(fg=th.text if self._enabled else th.text2)
        # the label sits where the entry is: keep the entry out of the way until it is needed
        self.cv.itemconfigure(self._ew, state="normal" if (t > 0.3 or self._focus or self.var.get()) else "hidden")


# ------------------------------------------------------------------ Dropdown
class Dropdown(tk.Frame):
    def __init__(self, parent, th, label, var, values, command=None, bg=None, helper=""):
        bgc = bg or th.card
        tk.Frame.__init__(self, parent, bg=bgc)
        self.th, self.var, self.label, self.values, self.command, self.bgc = th, var, label, list(values), command, bgc
        self.h = px(58)
        self._hover, self._focus, self._pop, self._outside_id = False, False, None, None
        self.cv = tk.Canvas(self, height=self.h, width=px(220), highlightthickness=0, bd=0, bg=bgc, cursor="hand2", takefocus=1)
        self.cv.pack(fill="x")
        self.msg = tk.Label(self, text=helper, anchor="w", justify="left", font=FONTS.tiny, bg=bgc, fg=th.text2, wraplength=px(330))
        if helper:
            self.msg.pack(fill="x", padx=px(14), pady=(px(2), 0))
        self.cv.bind("<Configure>", lambda e: self._draw())
        self.cv.bind("<Button-1>", lambda e: self.toggle())
        self.cv.bind("<Enter>", lambda e: self._f(hover=True))
        self.cv.bind("<Leave>", lambda e: self._f(hover=False))
        self.cv.bind("<FocusIn>", lambda e: self._f(focus=True))
        self.cv.bind("<FocusOut>", lambda e: self._f(focus=False))
        self.cv.bind("<space>", lambda e: self.toggle())
        self.cv.bind("<Return>", lambda e: self.toggle())
        self.cv.bind("<Down>", lambda e: self._move(1))
        self.cv.bind("<Up>", lambda e: self._move(-1))
        self._tid = var.trace_add("write", lambda *a: self._safe_draw())
        self.bind("<Destroy>", self._cleanup)
        self._draw()

    def _cleanup(self, e):
        if e.widget is self:
            self.close()
            try:
                self.var.trace_remove("write", self._tid)
            except Exception:
                pass

    def _safe_draw(self):
        try:
            if self.winfo_exists():
                self._draw()
        except tk.TclError:
            pass

    def _f(self, hover=None, focus=None):
        if hover is not None:
            self._hover = hover
        if focus is not None:
            self._focus = focus
        self._draw()

    def set_values(self, values):
        self.values = list(values)
        self._draw()

    def _move(self, d):
        if self.values and self.var.get() in self.values:
            i = max(0, min(len(self.values) - 1, self.values.index(self.var.get()) + d))
            self._choose(self.values[i])

    def _draw(self):
        c, th = self.cv, self.th
        c.delete("all")
        w = c.winfo_width() if c.winfo_width() > 1 else int(float(c.cget("width")))
        y0 = px(9)
        open_ = self._pop is not None
        ocol, lw, lcol = (th.primary, 2, th.primary) if (self._focus or open_) else ((th.text if self._hover else th.outline_hi), 1, th.text2)
        rr(c, 1, y0, w - 2, self.h - px(2), px(10), fill="", outline=ocol, width=lw)
        c.create_rectangle(px(9), 0, px(15) + FONTS.tiny.measure(self.label), px(16), fill=self.bgc, outline="")
        c.create_text(px(12), y0, text=self.label, font=FONTS.tiny, fill=lcol, anchor="w")
        c.create_text(px(14), (self.h + y0) / 2.0 - px(1), text=self.var.get(), font=FONTS.body, fill=th.text, anchor="w", width=max(10, w - px(60)))
        icon(c, "chevron", w - px(24), (self.h + y0) / 2.0 - px(1), px(20), th.text2, bg=self.bgc)

    def toggle(self):
        if self._pop:
            self.close()
        else:
            self.open()

    def open(self):
        th = self.th
        self.cv.focus_set()
        top = tk.Toplevel(self)
        top.overrideredirect(True)
        top.configure(bg=th.outline)
        inner = tk.Frame(top, bg=th.card)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        ih = px(34)
        cur = self.var.get()
        for v in self.values:
            row = tk.Label(inner, text=v, anchor="w", font=FONTS.body, bg=th.primary_c if v == cur else th.card,
                           fg=th.on_primary_c if v == cur else th.text, padx=px(14), height=1, cursor="hand2")
            row.pack(fill="x", ipady=px(6))
            hov = th.card2 if v != cur else th.primary_c
            row.bind("<Enter>", lambda e, r=row, h=hov: r.config(bg=h))
            row.bind("<Leave>", lambda e, r=row, v=v: r.config(bg=th.primary_c if v == cur else th.card))
            row.bind("<Button-1>", lambda e, v=v: self._choose(v))
        w = self.cv.winfo_width()
        total = len(self.values) * ih + 2
        x, y = self.cv.winfo_rootx(), self.cv.winfo_rooty() + self.h - px(4)
        sh = self.winfo_screenheight()
        if y + total > sh - px(8):
            y = max(px(8), self.cv.winfo_rooty() - total + px(14))
        top.geometry("%dx%d+%d+%d" % (w, total, x, y))
        top.bind("<Escape>", lambda e: self.close())
        self._pop = top
        self._outside_id = self.winfo_toplevel().bind("<Button-1>", self._outside, add="+")
        self._draw()

    def _outside(self, e):
        if self._pop and not str(e.widget).startswith(str(self._pop)) and e.widget is not self.cv:
            self.close()

    def close(self):
        if self._pop:
            try:
                self._pop.destroy()
            except tk.TclError:
                pass
            self._pop = None
            try:
                self.winfo_toplevel().unbind("<Button-1>", self._outside_id)
            except Exception:
                pass
            self._outside_id = None
            self._safe_draw()

    def _choose(self, v):
        self.close()
        self.var.set(v)
        if self.command:
            self.command(v)


# ------------------------------------------------------------------ Switch
class Switch(tk.Frame):
    def __init__(self, parent, th, text, var, command=None, bg=None, helper=""):
        bgc = bg or th.card
        tk.Frame.__init__(self, parent, bg=bgc)
        self.th, self.var, self.command, self.bgc = th, var, command, bgc
        self.cv = tk.Canvas(self, width=px(52), height=px(32), highlightthickness=0, bd=0, bg=bgc, cursor="hand2", takefocus=1)
        self.cv.pack(side="left")
        col = tk.Frame(self, bg=bgc)
        col.pack(side="left", padx=(px(12), 0), fill="x", expand=True)
        self.lbl = tk.Label(col, text=text, font=FONTS.body, bg=bgc, fg=th.text, anchor="w", cursor="hand2", justify="left", wraplength=px(300))
        self.lbl.pack(anchor="w")
        if helper:
            tk.Label(col, text=helper, font=FONTS.tiny, bg=bgc, fg=th.text2, anchor="w", justify="left", wraplength=px(300)).pack(anchor="w")
        self._p = 1.0 if var.get() else 0.0
        for w in (self.cv, self.lbl):
            w.bind("<Button-1>", lambda e: self.toggle())
        self.cv.bind("<space>", lambda e: self.toggle())
        self._tid = var.trace_add("write", lambda *a: self._sync())
        self.bind("<Destroy>", self._cleanup)
        self._draw()

    def _cleanup(self, e):
        if e.widget is self:
            try:
                self.var.trace_remove("write", self._tid)
            except Exception:
                pass

    def toggle(self):
        self.var.set(not self.var.get())
        if self.command:
            self.command()

    def _sync(self):
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        want = 1.0 if self.var.get() else 0.0
        start = self._p
        animate(self, 7, lambda t: self._step(start + (want - start) * t), interval=13)

    def _step(self, v):
        self._p = v
        self._draw()

    def _draw(self):
        c, th, p = self.cv, self.th, self._p
        c.delete("all")
        track = mix(th.card2 if not th.dark else th.card2, th.primary, p)
        out = mix(th.outline_hi, th.primary, p)
        x1, y1, x2, y2 = px(2), px(4), px(50), px(28)
        rad = (y2 - y1) / 2.0
        fillc = track if p > 0 else th.card2
        c.create_oval(x1, y1, x1 + 2 * rad, y2, fill=fillc, outline=out, width=2)
        c.create_oval(x2 - 2 * rad, y1, x2, y2, fill=fillc, outline=out, width=2)
        c.create_rectangle(x1 + rad, y1, x2 - rad, y2, fill=fillc, outline=fillc)
        c.create_line(x1 + rad, y1, x2 - rad, y1, fill=out, width=2)
        c.create_line(x1 + rad, y2, x2 - rad, y2, fill=out, width=2)
        r = px(7) + px(3) * p
        cx = px(14) + (px(38) - px(14)) * p
        c.create_oval(cx - r, px(16) - r, cx + r, px(16) + r, fill=mix(th.outline_hi, th.on_primary, p), outline="")
        if p > 0.6:
            icon(c, "check", cx, px(16), px(12), th.primary, bg=th.on_primary)


# ------------------------------------------------------------------ Progress, stepper, chip
class LinearProgress(tk.Canvas):
    def __init__(self, parent, th, bg=None, height=6):
        self.th = th
        tk.Canvas.__init__(self, parent, height=px(height), highlightthickness=0, bd=0, bg=bg or th.card)
        self.value, self.target, self.indet, self._ph = 0.0, 0.0, False, 0.0
        self._running = False
        self.bind("<Configure>", lambda e: self._draw())

    def set(self, v):
        self.target = max(0.0, min(1.0, v))
        self._kick()

    def set_indeterminate(self, on):
        self.indet = on
        self._kick()

    def _kick(self):
        if not self._running:
            self._running = True
            _after(self, 16, self._tick)

    def _tick(self):
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        self.value += (self.target - self.value) * 0.18
        if abs(self.target - self.value) < 0.002:
            self.value = self.target
        self._ph = (self._ph + 0.018) % 1.0
        self._draw()
        if self.indet or self.value != self.target:
            _after(self, 16, self._tick)
        else:
            self._running = False

    def _draw(self):
        self.delete("all")
        w, h, th = self.winfo_width(), self.winfo_height(), self.th
        if w < 4:
            return
        rr(self, 0, 0, w, h, h / 2.0, fill=th.primary_c if not th.dark else th.card2, outline="")
        if self.indet:
            seg = w * 0.3
            x = -seg + (w + seg) * self._ph
            rr(self, max(0, x), 0, min(w, x + seg), h, h / 2.0, fill=th.primary, outline="")
        elif self.value > 0.005:
            rr(self, 0, 0, max(h, w * self.value), h, h / 2.0, fill=th.primary, outline="")


class Stepper(tk.Canvas):
    """Horizontal stepper: states per step are 'pending' | 'active' | 'done' | 'skip' | 'error' | 'warn'."""

    def __init__(self, parent, th, steps, bg=None):
        self.th, self.steps = th, steps
        self.states = ["pending"] * len(steps)
        tk.Canvas.__init__(self, parent, height=px(74), highlightthickness=0, bd=0, bg=bg or th.card)
        self._pulse = 0.0
        self._bgc = bg or th.card
        self.bind("<Configure>", lambda e: self._draw())
        _after(self, 40, self._tick)

    def set(self, i, state):
        self.states[i] = state
        self._draw()

    def _tick(self):
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        self._pulse = (self._pulse + 0.05) % 1.0
        if "active" in self.states:
            self._draw()
        _after(self, 40, self._tick)

    def _draw(self):
        self.delete("all")
        th, n = self.th, len(self.steps)
        w = self.winfo_width()
        if w < 50:
            return
        r = px(14)
        left, right = px(44), w - px(44)
        xs = [left + (right - left) * i / float(n - 1) for i in range(n)]
        cy = px(24)
        for i in range(n - 1):
            done = self.states[i] in ("done", "skip", "warn")
            self.create_line(xs[i] + r, cy, xs[i + 1] - r, cy, fill=th.ok if done else th.outline, width=px(3), capstyle="round")
        for i, x in enumerate(xs):
            st = self.states[i]
            if st == "active":
                pr = r + px(6) * self._pulse
                self.create_oval(x - pr, cy - pr, x + pr, cy + pr, outline=mix(th.primary, self._bgc, 0.35 + 0.65 * self._pulse), width=2)
                self.create_oval(x - r, cy - r, x + r, cy + r, fill=th.primary, outline="")
                self.create_oval(x - px(4), cy - px(4), x + px(4), cy + px(4), fill=th.on_primary, outline="")
            elif st in ("done", "skip"):
                self.create_oval(x - r, cy - r, x + r, cy + r, fill=th.ok if st == "done" else th.outline_hi, outline="")
                icon(self, "check" if st == "done" else "close", x, cy, px(16), th.on_primary if not th.dark else "#0B1F12", bg="")
            elif st == "warn":
                self.create_oval(x - r, cy - r, x + r, cy + r, fill=th.warn, outline="")
            elif st == "error":
                self.create_oval(x - r, cy - r, x + r, cy + r, fill=th.error, outline="")
                icon(self, "close", x, cy, px(14), "#FFFFFF" if not th.dark else "#3B0A07")
            else:
                self.create_oval(x - r, cy - r, x + r, cy + r, outline=th.outline_hi, width=2, fill="")
            self.create_text(x, cy + px(30), text=self.steps[i], font=FONTS.small, fill=th.text if st in ("active", "done") else th.text2)


class Chip(tk.Canvas):
    def __init__(self, parent, th, text="", dot=None, bg=None, icon_name=None, tonal=False):
        self.th, self.text, self.dot, self.bgc, self.icon_name, self.tonal = th, text, dot, bg or th.card, icon_name, tonal
        tk.Canvas.__init__(self, parent, height=px(32), highlightthickness=0, bd=0, bg=self.bgc)
        self.update_chip(text, dot)

    def update_chip(self, text, dot=None):
        self.text, self.dot = text, dot
        th = self.th
        lead = px(30) if (dot or self.icon_name) else px(14)
        w = lead + FONTS.small.measure(text) + px(14)
        self.configure(width=w)
        self.delete("all")
        rr(self, 1, 1, w - 1, px(31), px(16), fill=th.primary_c if self.tonal else "", outline="" if self.tonal else th.outline_hi)
        if dot:
            self.create_oval(px(11), px(11), px(21), px(21), fill=dot, outline="")
        elif self.icon_name:
            icon(self, self.icon_name, px(18), px(16), px(16), th.on_primary_c if self.tonal else th.text2, bg=th.primary_c if self.tonal else self.bgc)
        self.create_text(lead, px(16), text=text, font=FONTS.small, fill=th.on_primary_c if self.tonal else th.text, anchor="w")


# ------------------------------------------------------------------ Navigation rail, pages, toast, dialog
class Rail(tk.Canvas):
    def __init__(self, parent, th, items, command):
        self.th, self.items, self.command = th, items, command
        self.sel, self.hov = 0, -1
        self.iw = px(92)
        self.ih = px(78)
        tk.Canvas.__init__(self, parent, width=self.iw, highlightthickness=0, bd=0, bg=th.bg, cursor="hand2")
        self.bind("<Motion>", self._motion)
        self.bind("<Leave>", lambda e: self._hover(-1))
        self.bind("<Button-1>", self._click)
        self.bind("<Configure>", lambda e: self._draw())

    def _idx(self, y):
        i = int((y - px(10)) // self.ih)
        return i if 0 <= i < len(self.items) else -1

    def _motion(self, e):
        self._hover(self._idx(e.y))

    def _hover(self, i):
        if i != self.hov:
            self.hov = i
            self._draw()

    def _click(self, e):
        i = self._idx(e.y)
        if i >= 0:
            self.select(i)
            self.command(i)

    def select(self, i):
        self.sel = i
        self._draw()

    def _draw(self):
        self.delete("all")
        th = self.th
        for i, (name, ic) in enumerate(self.items):
            top = px(10) + i * self.ih
            cx = self.iw / 2.0
            on = i == self.sel
            pill = th.primary_c if on else (th.card2 if i == self.hov else th.bg)
            rr(self, cx - px(30), top + px(4), cx + px(30), top + px(36), px(16), fill=pill, outline="")
            icon(self, ic, cx, top + px(20), px(22), th.on_primary_c if on else th.text2, bg=pill)
            self.create_text(cx, top + px(52), text=name, font=FONTS.bold if on else FONTS.small, fill=th.text if on else th.text2)


class Pages(tk.Frame):
    def __init__(self, parent, th):
        tk.Frame.__init__(self, parent, bg=th.bg)
        self.pages, self.cur, self.busy = [], 0, False

    def add(self):
        f = tk.Frame(self, bg=self["bg"])
        self.pages.append(f)
        if len(self.pages) == 1:
            f.place(x=0, y=0, width=0, relwidth=1, relheight=1)
        return f

    def show(self, i):
        if i == self.cur or self.busy:
            return
        w = max(self.winfo_width(), 200)
        d = 1 if i > self.cur else -1
        old, new = self.pages[self.cur], self.pages[i]
        self.busy = True
        new.place(x=d * w, y=0, width=w, relwidth=0, relheight=1)    # place() ADDS width and relwidth: never mix them
        new.lift()

        def step(t):
            old.place(x=int(-d * w * t * 0.35), y=0, width=w, relwidth=0, relheight=1)
            new.place(x=int(d * w * (1 - t)), y=0, width=w, relwidth=0, relheight=1)

        def done():
            old.place_forget()
            new.place(x=0, y=0, width=0, relwidth=1, relheight=1)
            self.cur, self.busy = i, False
        animate(self, 10, step, done)


class Toast(tk.Frame):
    def __init__(self, parent, th):
        tk.Frame.__init__(self, parent, bg=th.snack)
        self.th = th
        self.lbl = tk.Label(self, text="", font=FONTS.body, bg=th.snack, fg=th.on_snack, padx=px(18), pady=px(12))
        self.lbl.pack()
        self._job = None

    def show(self, text, ms=3600):
        if self._job:
            try:
                self._root().after_cancel(self._job)
            except Exception:
                pass
        self.lbl.config(text=text)
        self.update_idletasks()
        self.place(relx=0.5, rely=1.0, anchor="s", y=px(40))
        self.lift()
        animate(self, 8, lambda t: self.place(relx=0.5, rely=1.0, anchor="s", y=int(px(40) - px(140) * t)))
        self._job = _after(self, ms, self.hide)

    def hide(self):
        self._job = None
        self.place_forget()


def confirm(root, th, title, lines, ok="OK", cancel="Cancel", danger=False):
    """Modal Material-style dialog. Returns True/False."""
    result = [False]
    top = tk.Toplevel(root)
    top.title(title)
    top.configure(bg=th.card)
    top.resizable(False, False)
    top.transient(root)
    body = tk.Frame(top, bg=th.card, padx=px(26), pady=px(22))
    body.pack()
    tk.Label(body, text=title, font=FONTS.h1, bg=th.card, fg=th.text, anchor="w").pack(anchor="w", pady=(0, px(10)))
    for kind, text in lines:
        row = tk.Frame(body, bg=th.card)
        row.pack(anchor="w", fill="x", pady=px(3))
        if kind in ("warn", "info"):
            ic = tk.Canvas(row, width=px(24), height=px(24), bg=th.card, highlightthickness=0)
            ic.pack(side="left", padx=(0, px(8)))
            icon(ic, kind, px(12), px(12), px(20), th.warn if kind == "warn" else th.primary, bg=th.card)
        tk.Label(row, text=text, font=FONTS.body, bg=th.card, fg=th.text, justify="left", anchor="w", wraplength=px(420)).pack(side="left")
    btns = tk.Frame(body, bg=th.card)
    btns.pack(anchor="e", pady=(px(20), 0))

    def done(v):
        result[0] = v
        top.destroy()
    Button(btns, th, cancel, lambda: done(False), kind="text").pack(side="left", padx=(0, px(8)))
    b = Button(btns, th, ok, lambda: done(True), kind="filled")
    b.pack(side="left")
    top.bind("<Escape>", lambda e: done(False))
    top.protocol("WM_DELETE_WINDOW", lambda: done(False))
    top.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() - top.winfo_width()) // 2
    y = root.winfo_rooty() + (root.winfo_height() - top.winfo_height()) // 3
    top.geometry("+%d+%d" % (max(0, x), max(0, y)))
    try:
        top.wait_visibility()
        top.grab_set()
    except tk.TclError:
        pass
    b.focus_set()
    root.wait_window(top)
    return result[0]
