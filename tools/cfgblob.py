"""Builds the 4 KB `cfg` partition image (format shared with src/core/config.h)."""
import hashlib
import secrets
import string

CFG_SIZE = 4096
_ALPHABET = string.ascii_letters + string.digits


def random_password(n=12):
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def hash_password(salt, password):
    return hashlib.sha256((salt + ":" + password).encode("utf-8")).hexdigest()


def _check(name, value):
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("%s must not contain line breaks" % name)


def build_cfg(ssid, wifi_pass, dash_password, bloom_kb=128, up1="1.1.1.1", up2="9.9.9.9",
              bl_url="", fw_url="", bl_hours=24, host="c3hole", salt=None):
    for n, v in (("ssid", ssid), ("wifi password", wifi_pass), ("dashboard password", dash_password),
                 ("blocklist url", bl_url), ("firmware url", fw_url), ("hostname", host)):
        _check(n, v)
    if not ssid or len(ssid.encode()) > 32:
        raise ValueError("SSID must be 1-32 bytes")
    if len(wifi_pass.encode()) > 63:
        raise ValueError("Wi-Fi password must be at most 63 bytes")
    salt = salt or secrets.token_hex(8)
    lines = [
        "ssid=" + ssid,
        "wpass=" + wifi_pass,
        "dsalt=" + salt,
        "dhash=" + hash_password(salt, dash_password),
        "up1=" + up1,
        "up2=" + up2,
        "blurl=" + bl_url,
        "fwurl=" + fw_url,
        "host=" + host,
        "bloomkb=%d" % bloom_kb,
        "blhours=%d" % bl_hours,
    ]
    blob = ("C3CFG1\n" + "\n".join(lines) + "\n").encode("utf-8") + b"\x00"
    if len(blob) > CFG_SIZE:
        raise ValueError("configuration too large")
    return blob + b"\xff" * (CFG_SIZE - len(blob))
