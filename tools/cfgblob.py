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


TX_POWERS = {  # quarter-dBm value used by the firmware -> dBm label
    8: "2 dBm", 20: "5 dBm", 28: "7 dBm", 34: "8.5 dBm", 44: "11 dBm", 52: "13 dBm",
    60: "15 dBm", 68: "17 dBm", 74: "18.5 dBm", 76: "19 dBm", 78: "19.5 dBm"}


def build_cfg(ssid, wifi_pass, dash_password, bloom_kb=128, up1="8.8.8.8", up2="9.9.9.9",
              bl_url="", fw_url="", bl_hours=24, host="c3hole", salt=None,
              no_auth=False, tx_power=44, ps_mode=0, cpu_mhz=160, up_mode=1, up_timeout=500):
    """dash_password is ignored when no_auth is True (the dashboard is then open to the LAN)."""
    for n, v in (("ssid", ssid), ("wifi password", wifi_pass), ("dashboard password", dash_password or ""),
                 ("blocklist url", bl_url), ("firmware url", fw_url), ("hostname", host), ("upstream 1", up1),
                 ("upstream 2", up2)):
        _check(n, v)
    if not ssid or len(ssid.encode()) > 32:
        raise ValueError("SSID must be 1-32 bytes")
    if len(wifi_pass.encode()) > 63:
        raise ValueError("Wi-Fi password must be at most 63 bytes")
    if tx_power not in TX_POWERS:
        raise ValueError("unsupported TX power %r" % (tx_power,))
    if ps_mode not in (0, 1, 2) or cpu_mhz not in (80, 160) or up_mode not in (0, 1):
        raise ValueError("bad power-save / CPU / upstream mode value")
    if no_auth:
        salt, dhash = "", ""
    else:
        if not dash_password:
            raise ValueError("a dashboard password is required unless no_auth is set")
        salt = salt or secrets.token_hex(8)
        dhash = hash_password(salt, dash_password)
    lines = [
        "ssid=" + ssid,
        "wpass=" + wifi_pass,
        "dsalt=" + salt,
        "dhash=" + dhash,
        "up1=" + up1,
        "up2=" + up2,
        "blurl=" + bl_url,
        "fwurl=" + fw_url,
        "host=" + host,
        "bloomkb=%d" % bloom_kb,
        "blhours=%d" % bl_hours,
        "txpower=%d" % tx_power,
        "ps=%d" % ps_mode,
        "cpu=%d" % cpu_mhz,
        "noauth=%d" % (1 if no_auth else 0),
        "upmode=%d" % up_mode,
        "uptmo=%d" % up_timeout,
    ]
    blob = ("C3CFG1\n" + "\n".join(lines) + "\n").encode("utf-8") + b"\x00"
    if len(blob) > CFG_SIZE:
        raise ValueError("configuration too large")
    return blob + b"\xff" * (CFG_SIZE - len(blob))
