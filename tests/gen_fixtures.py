"""Generates the fixtures used by test_core.cpp (cross-language checks)."""
import os, sys, random, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import build_blocklist as bb
import cfgblob

W = os.path.join(HERE, "_work")
os.makedirs(W, exist_ok=True)
BUILD = os.path.join(HERE, "..", "tools", "build_blocklist.py")

small = ["example.com", "adblock.net", "ads.tracker.io", "wild.io", "xn--80ak6aa92e.com"]
open(os.path.join(W, "small.txt"), "w").write("\n".join(small) + "\n")
subprocess.check_call([sys.executable, BUILD, os.path.join(W, "small.bin"), os.path.join(W, "small.txt")], stdout=subprocess.DEVNULL)

rnd = random.Random(42)
tlds = ["com", "net", "org", "io", "info", "xyz", "co.uk", "de", "ru", "cn"]
big = set()
while len(big) < 253000:
    big.add("%s%d.%s" % ("".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rnd.randint(4, 12))),
                         rnd.randint(0, 999), rnd.choice(tlds)))
open(os.path.join(W, "big.txt"), "w").write("\n".join(sorted(big)) + "\n")
subprocess.check_call([sys.executable, BUILD, os.path.join(W, "big.bin"), os.path.join(W, "big.txt"), "--no-prune"], stdout=subprocess.DEVNULL)

with open(os.path.join(W, "vectors.txt"), "w") as f:
    for n in ["example.com", "a.b.c.d.example.org", "xn--80ak6aa92e.com", "x", "ads.tracker.io"]:
        f.write("%s %010x\n" % (n, bb.hash40(n)))

blob = cfgblob.build_cfg("My Home WiFi", "p@ss=w0rd!", "Dash-Pass-123", bloom_kb=96,
                         bl_url="https://example.org/a.bin", fw_url="", bl_hours=12, salt="0123456789abcdef")
open(os.path.join(W, "cfg.bin"), "wb").write(blob)
print("fixtures ready")
