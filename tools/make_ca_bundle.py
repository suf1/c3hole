#!/usr/bin/env python3
"""Creates data/cert/x509_crt_bundle.bin (Mozilla root CAs) for HTTPS updates.

    pip install cryptography
    python tools/make_ca_bundle.py            # downloads https://curl.se/ca/cacert.pem
    python tools/make_ca_bundle.py my.pem     # or use your own PEM bundle
"""
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "data", "cert", "x509_crt_bundle.bin")
URL = "https://curl.se/ca/cacert.pem"


def main():
    with tempfile.TemporaryDirectory() as tmp:
        if len(sys.argv) > 1:
            pem = os.path.join(tmp, "user.pem")      # the generator ignores files not ending in .pem
            shutil.copy(sys.argv[1], pem)
        else:
            pem = os.path.join(tmp, "cacert.pem")
            req = urllib.request.Request(URL, headers={"User-Agent": "c3hole-build"})
            with urllib.request.urlopen(req, timeout=60) as r, open(pem, "wb") as f:
                f.write(r.read())
        subprocess.check_call([sys.executable, os.path.join(HERE, "gen_crt_bundle.py"), "--input", pem, "-q"], cwd=tmp)
        built = os.path.join(tmp, "x509_crt_bundle")
        if os.path.getsize(built) < 10000:
            raise SystemExit("ERROR: CA bundle is only %d bytes - no certificates were found in the input" % os.path.getsize(built))
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        shutil.copy(built, OUT)
    print("wrote %s (%d bytes)" % (os.path.normpath(OUT), os.path.getsize(OUT)))


if __name__ == "__main__":
    main()
