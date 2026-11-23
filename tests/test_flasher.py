"""Flasher logic tests (no window, no board): validation rules and the flash job with esptool simulated."""
import os, queue, sys, tempfile, threading, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "flasher"))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import core, cfgblob

# --- fake bundled assets
tmp = tempfile.mkdtemp(prefix="c3f_assets_")
for n, data in (("bootloader.bin", b"\xff" * 4096), ("partitions.bin", b"\xff" * 3072), ("boot_app0.bin", b"\xff" * 8192),
                ("firmware.bin", b"\xe9" + b"\x00" * 5000), ("blocklist.bin", b"C3HL" + b"\x00" * 60)):
    open(os.path.join(tmp, n), "wb").write(data)
MAN = {"built_at": "t", "version": "x", "app_offset": 0x10000, "otadata_offset": 0xD000, "cfg_offset": 0xF000,
       "blocklist_offset": 0x290000, "blocklist_size": 0x170000, "blocklist_domains": 1, "blocklist_bytes": 64}
core.asset = lambda name: os.path.join(tmp, name)
core.load_manifest = lambda: MAN

ok = dict(ssid="Home", wifi_pass="secret123", dash_pass="", no_auth=False, up1="8.8.8.8", up2="9.9.9.9",
          bl_url="https://x.org/b.bin", fw_url="", bl_hours="24", bloom_kb="128", up_timeout="500")
LIM = 0x170000


def chk(**kw):
    d = dict(ok); d.update(kw)
    return core.validate(d, LIM)


assert chk() is None
cases = [(dict(ssid=""), "network name"), (dict(ssid="x" * 33), "too long"), (dict(wifi_pass="short"), "8 characters"),
         (dict(dash_pass="short"), "8-60"), (dict(dash_pass="caf\u00e9-pass-1"), "ascii"), (dict(up1="300.1.1.1"), "upstream dns 1"),
         (dict(up1="1.1.1.1:0"), "upstream dns 1"), (dict(up1="1.1.1.1:70000"), "upstream dns 1"), (dict(up1="0.0.0.0"), "upstream dns 1"),
         (dict(up1="dns.example.com"), "upstream dns 1"), (dict(up2="1.2.3"), "upstream dns 2"), (dict(up_timeout="50"), "100-5000"),
         (dict(up_timeout="x"), "numbers"), (dict(bl_url="ftp://x"), "http"), (dict(bloom_kb="500"), "0-400"),
         (dict(bl_hours="9000"), "0-8760"), (dict(ssid="a\nb"), "line breaks")]
for kw, frag in cases:
    e = chk(**kw)
    assert e and frag in e.lower(), (kw, e)
for good in ("192.168.0.5", "192.168.0.5:5353", "10.0.0.2:53"):
    assert chk(up1=good) is None, good
assert chk(up2="") is None and chk(wifi_pass="") is None
assert chk(no_auth=True, dash_pass="x") is None
# per-field errors drive the inline messages in the window
fe = core.field_errors(dict(ok, ssid="", up1="nope", bl_hours="x"), LIM)
assert set(fe) == {"ssid", "up1", "bl_hours"}, fe
assert all(f in core.FIELD_PAGE for f in fe)
print("validation OK (%d cases + inline field errors)" % (len(cases) + 6))

# --- flash job with esptool and the serial/HTTP steps simulated
calls, seen, login = [], {}, {}


def fake(argv, on_line):
    calls.append(argv)
    if "write_flash" in argv:
        seen["blob"] = open(argv[argv.index("0xf000") + 1], "rb").read()
        for l in ["Compressed 4096 bytes to 100...", "Writing at 0x00000000... (100 %)"]:
            on_line(l)


core.run_esptool = fake
core.capture_boot = lambda p, s, l, st: "192.168.0.232"
core.check_login = lambda h, p: (login.__setitem__("pw", p), True if p else None)[1]


def run(**over):
    q = queue.Queue()
    cfg = dict(ok, dash_pass="Gen-Pass-123456", generated=True, port="COM3", baud=460800, erase=True, blocklist_path=None,
               tx_power=34, ps_mode=1, cpu_mhz=80, up_mode=1, up1="192.168.0.5:5353")
    cfg.update(over)
    core.flash_job(cfg, q, threading.Event())
    ev = []
    while not q.empty():
        ev.append(q.get())
    return ev


def done_of(ev):
    return [m[1] for m in ev if m[0] == "done"][0]


ev = run(); d = done_of(ev); b = seen["blob"]
for needle in (b"txpower=34\n", b"ps=1\n", b"cpu=80\n", b"upmode=1\n", b"up1=192.168.0.5:5353\n", b"noauth=0\n", b"dhash="):
    assert needle in b, needle
assert d["password"] == "Gen-Pass-123456" and d["login"] is True and login["pw"] == "Gen-Pass-123456"
st = [(m[1], m[2]) for m in ev if m[0] == "stage"]
assert st[0] == (0, "active") and st[-2:] == [(4, "active"), (4, "done")] and (1, "done") in st, st
prog = [m[1] for m in ev if m[0] == "progress"]
assert prog == sorted(prog) and prog[-1] == 100
ev = run(erase=False)
st = [(m[1], m[2]) for m in ev if m[0] == "stage"]
assert (1, "skip") in st and (1, "active") not in st and not any("erase_flash" in c for c in calls[-1:]), st
ev = run(no_auth=True, dash_pass=""); d = done_of(ev)
assert b"noauth=1\n" in seen["blob"] and b"dhash=\n" in seen["blob"] and d["password"] is None and login["pw"] is None
wf = [c for c in calls if "write_flash" in c][0]
tail = wf[wf.index("keep", wf.index("--flash_size")):]
pairs = [(tail[i], os.path.basename(tail[i + 1])) for i in range(1, len(tail), 2)]
assert pairs == [("0x0", "bootloader.bin"), ("0x8000", "partitions.bin"), ("0xd000", "boot_app0.bin"), ("0x10000", "firmware.bin"),
                 ("0xf000", "cfg.bin"), ("0x290000", "blocklist.bin")], pairs


def boom(argv, on_line):
    raise RuntimeError("Failed to connect to ESP32-C3")


core.run_esptool = boom
ev = run()
assert [m for m in ev if m[0] == "error"] and not [m for m in ev if m[0] == "done"]
print("flash job OK: settings reach the blob, stages/status stream for the stepper, errors are reported")
