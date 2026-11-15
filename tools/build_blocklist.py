#!/usr/bin/env python3
"""Build a C3Hole blocklist (blocklist.bin) from hosts / domain / adblock lists.

    python build_blocklist.py OUT.bin SOURCE [SOURCE ...] [options]

SOURCE is an http(s) URL or a local file. Understood line formats:
    0.0.0.0 ads.example.com        (hosts)
    ads.example.com                (plain domain list)
    ||ads.example.com^             (adblock, simple rules only)
    *.ads.example.com              (wildcard)

Each domain is hashed to 40 bits (FNV-1a 64 folded) and the sorted hashes are
stored with a 48-byte header (see src/core/blocklist.h).  Pure standard library.
"""
import argparse
import hashlib
import os
import re
import struct
import sys
import time
import urllib.request

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF

DEFAULT_CAPACITY = (0x170000 - 48) // 5   # entries that fit the firmware's blocklist partition

LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DOMAIN_RE = re.compile(r"^(?:%s\.)+[a-z0-9-]{2,63}$" % LABEL)
IP_RE = re.compile(r"^[0-9.]+$|^[0-9a-f:]+$")
SKIP_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
              "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
              "ip6-allhosts", "0.0.0.0"}


def hash40(name):
    """Must match c3::hash40() in src/core/hash40.h."""
    h = FNV_OFFSET
    for b in name.encode("ascii"):
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return (h ^ (h >> 40)) & 0xFFFFFFFFFF


def clean(token):
    t = token.strip().lower().rstrip(".")
    if t.startswith("*."):
        t = t[2:]
    if not t or t in SKIP_NAMES or IP_RE.match(t) or len(t) > 253:
        return None
    return t if DOMAIN_RE.match(t) else None


def parse_line(line):
    """Yield domains found on one source line."""
    line = line.strip()
    if not line or line[0] in "#!;[":
        return
    line = line.split("#", 1)[0].strip()
    if line.startswith("||"):                      # adblock simple rule
        body = line[2:]
        if "^" in body:
            host, _, tail = body.partition("^")
            if tail and not tail.startswith("$"):
                return
        else:
            host = body
        if "/" in host or "*" in host.replace("*.", "", 1) or "$" in host:
            return
        d = clean(host)
        if d:
            yield d
        return
    parts = line.split()
    if not parts:
        return
    if IP_RE.match(parts[0]) and len(parts) > 1:   # hosts format
        for tok in parts[1:]:
            d = clean(tok)
            if d:
                yield d
        return
    if len(parts) == 1:
        d = clean(parts[0])
        if d:
            yield d


def fetch(src, retries=3):
    if os.path.isfile(src):
        with open(src, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(src, headers={"User-Agent": "c3hole-builder/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (attempt + 1))
    raise SystemExit("download failed for %s: %s" % (src, last))


def prune_subdomains(domains):
    """Drop entries whose parent domain is also listed (the matcher checks parents)."""
    keep, removed = set(), 0
    for d in domains:
        labels = d.split(".")
        redundant = any(".".join(labels[i:]) in domains for i in range(1, len(labels) - 1))
        if redundant:
            removed += 1
        else:
            keep.add(d)
    return keep, removed


def build(domains):
    by_hash = {}
    for d in domains:
        by_hash.setdefault(hash40(d), []).append(d)
    collisions = {h: v for h, v in by_hash.items() if len(v) > 1}
    hashes = sorted(by_hash)
    payload = b"".join(h.to_bytes(5, "big") for h in hashes)
    header = struct.pack("<4sBBHII", b"C3HL", 1, 5, 0, len(hashes), int(time.time()))
    header += hashlib.sha256(payload).digest()
    return header + payload, len(hashes), collisions


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="output file, e.g. blocklist.bin")
    ap.add_argument("sources", nargs="+", help="URLs or files")
    ap.add_argument("--allow", action="append", default=[], metavar="DOMAIN_OR_FILE",
                    help="remove this exact domain (or every domain in this file) from the list; repeatable")
    ap.add_argument("--no-prune", action="store_true", help="keep subdomains whose parent is already listed")
    ap.add_argument("--capacity", type=int, default=DEFAULT_CAPACITY,
                    help="maximum entries the firmware partition holds (default %(default)d)")
    args = ap.parse_args()

    domains, per_source = set(), []
    for src in args.sources:
        text = fetch(src)
        found = set()
        for line in text.splitlines():
            found.update(parse_line(line))
        per_source.append((src, len(found)))
        domains |= found
        print("  %-8d %s" % (len(found), src))
    raw = len(domains)

    allow = set()
    for a in args.allow:
        if os.path.isfile(a):
            for line in open(a, encoding="utf-8", errors="replace"):
                d = clean(line.split("#", 1)[0])
                if d:
                    allow.add(d)
        else:
            d = clean(a)
            if d:
                allow.add(d)
    allowed_hit = domains & allow
    domains -= allow
    pruned = 0
    if not args.no_prune:
        domains, pruned = prune_subdomains(domains)

    blob, count, collisions = build(domains)
    if count > args.capacity:
        raise SystemExit("ERROR: %d entries exceed the firmware capacity of %d" % (count, args.capacity))
    with open(args.out, "wb") as f:
        f.write(blob)

    print("\nunique domains from sources : %d" % raw)
    print("removed by allowlist        : %d" % len(allowed_hit))
    print("pruned (parent already in)  : %d" % pruned)
    print("entries written             : %d  (capacity %d, %.0f%% used)" % (count, args.capacity, 100.0 * count / args.capacity))
    print("file size                   : %d bytes (%.2f MB)" % (len(blob), len(blob) / 1048576.0))
    print("hash collisions             : %d" % len(collisions))
    for h, names in list(collisions.items())[:10]:
        print("   %010x: %s" % (h, ", ".join(names)))
    print("wrote %s" % args.out)


if __name__ == "__main__":
    main()
