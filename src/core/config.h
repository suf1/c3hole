// Device settings stored as plain "key=value" lines in the 4 KB `cfg` partition.
// Layout: "C3CFG1\n" + lines + NUL, rest 0xFF.  tools/cfgblob.py writes the same format.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

namespace c3 {

enum { CFG_PART_SIZE = 4096 };

struct Config {
  char ssid[33];
  char wifiPass[64];
  char dashSalt[33];
  char dashHash[65];
  char up1[24];   // "ip" or "ip:port"
  char up2[24];
  char blUrl[160];
  char fwUrl[160];
  char host[32];
  uint16_t bloomKb;
  uint16_t blHours;
  uint8_t txPower;      // wifi_power_t in quarter-dBm (8..78); lower = cooler
  uint8_t psMode;       // Wi-Fi power save: 0 off, 1 min modem, 2 max modem
  uint16_t cpuMhz;      // 80 or 160
  bool noAuth;          // dashboard open without a password
  uint8_t upMode;       // 0 = failover to the secondary, 1 = ask both, first answer wins
  uint16_t upTimeoutMs; // failover timeout

  Config() { clear(); }

  void clear() {
    memset(this, 0, sizeof(*this));
    strcpy(up1, "8.8.8.8");
    strcpy(up2, "9.9.9.9");
    strcpy(host, "c3hole");
    bloomKb = 128;
    blHours = 24;
    txPower = 44;        // 11 dBm
    psMode = 0;
    cpuMhz = 160;
    noAuth = false;
    upMode = 1;           // ask both upstreams at once: one flaky resolver cannot stall every query
    upTimeoutMs = 500;
  }

  bool configured() const { return ssid[0] != 0 && (dashHash[0] != 0 || noAuth); }

  static bool validTxPower(long v) {
    static const uint8_t ok[] = {8, 20, 28, 34, 44, 52, 60, 68, 74, 76, 78};  // 2 .. 19.5 dBm
    for (size_t i = 0; i < sizeof(ok); i++) if (ok[i] == v) return true;
    return false;
  }

  static bool validValue(const char* s) {
    for (; *s; s++)
      if (*s == '\n' || *s == '\r') return false;
    return true;
  }

  static void copy(char* dst, size_t cap, const char* src) {
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
  }

  static void hashPassword(const char* salt, const char* pw, char hexOut[65]) {
    Sha256 s;
    s.update((const uint8_t*)salt, strlen(salt));
    s.update((const uint8_t*)":", 1);
    s.update((const uint8_t*)pw, strlen(pw));
    uint8_t d[32];
    s.final(d);
    toHex(d, 32, hexOut);
  }

  void setDashPassword(const char* pw, const char* saltHex) {
    copy(dashSalt, sizeof(dashSalt), saltHex);
    hashPassword(dashSalt, pw, dashHash);
  }

  bool checkDashPassword(const char* pw) const {
    if (!dashHash[0]) return false;
    char h[65];
    hashPassword(dashSalt, pw, h);
    uint8_t diff = 0;  // constant-time compare
    for (int i = 0; i < 64; i++) diff |= (uint8_t)(h[i] ^ dashHash[i]);
    return diff == 0 && dashHash[64] == 0;
  }

  void set(const char* key, const char* val) {
    if (!strcmp(key, "ssid")) copy(ssid, sizeof(ssid), val);
    else if (!strcmp(key, "wpass")) copy(wifiPass, sizeof(wifiPass), val);
    else if (!strcmp(key, "dsalt")) copy(dashSalt, sizeof(dashSalt), val);
    else if (!strcmp(key, "dhash")) copy(dashHash, sizeof(dashHash), val);
    else if (!strcmp(key, "up1")) copy(up1, sizeof(up1), val);
    else if (!strcmp(key, "up2")) copy(up2, sizeof(up2), val);
    else if (!strcmp(key, "blurl")) copy(blUrl, sizeof(blUrl), val);
    else if (!strcmp(key, "fwurl")) copy(fwUrl, sizeof(fwUrl), val);
    else if (!strcmp(key, "host")) copy(host, sizeof(host), val);
    else if (!strcmp(key, "txpower")) { long v = atol(val); if (validTxPower(v)) txPower = (uint8_t)v; }
    else if (!strcmp(key, "ps")) { long v = atol(val); psMode = (uint8_t)(v < 0 ? 0 : v > 2 ? 2 : v); }
    else if (!strcmp(key, "cpu")) { long v = atol(val); cpuMhz = (uint16_t)(v == 80 ? 80 : 160); }
    else if (!strcmp(key, "noauth")) noAuth = atol(val) != 0;
    else if (!strcmp(key, "upmode")) upMode = atol(val) == 1 ? 1 : 0;
    else if (!strcmp(key, "uptmo")) { long v = atol(val); upTimeoutMs = (uint16_t)(v < 100 ? 100 : v > 5000 ? 5000 : v); }
    else if (!strcmp(key, "bloomkb")) { long v = atol(val); bloomKb = (uint16_t)(v < 0 ? 0 : v > 400 ? 400 : v); }
    else if (!strcmp(key, "blhours")) { long v = atol(val); blHours = (uint16_t)(v < 0 ? 0 : v > 8760 ? 8760 : v); }
  }

  // Returns false if the blob does not start with the magic line.
  bool parse(const uint8_t* blob, size_t len) {
    static const char magic[] = "C3CFG1\n";
    if (len < sizeof(magic) - 1 || memcmp(blob, magic, sizeof(magic) - 1) != 0) return false;
    clear();
    size_t i = sizeof(magic) - 1;
    char line[320];
    while (i < len && blob[i] != 0 && blob[i] != 0xFF) {
      size_t n = 0;
      while (i < len && blob[i] != '\n' && blob[i] != 0 && blob[i] != 0xFF) {
        if (n < sizeof(line) - 1) line[n++] = (char)blob[i];
        i++;
      }
      if (i < len && blob[i] == '\n') i++;
      line[n] = 0;
      char* eq = strchr(line, '=');
      if (eq) { *eq = 0; set(line, eq + 1); }
    }
    return true;
  }

  // Writes the full blob (padded with 0xFF to cap). Returns bytes used or 0 on overflow.
  size_t serialize(uint8_t* out, size_t cap) const {
    char* tmp = (char*)out;
    size_t n = 0;
    bool ok = true;
    auto put = [&](const char* k, const char* v) {
      if (!ok) return;
      int w = snprintf(tmp + n, cap - n, "%s=%s\n", k, v);
      if (w < 0 || (size_t)w >= cap - n) ok = false; else n += (size_t)w;
    };
    int w0 = snprintf(tmp, cap, "C3CFG1\n");
    if (w0 < 0 || (size_t)w0 >= cap) return 0;
    n = (size_t)w0;
    char num[12];
    put("ssid", ssid);
    put("wpass", wifiPass);
    put("dsalt", dashSalt);
    put("dhash", dashHash);
    put("up1", up1);
    put("up2", up2);
    put("blurl", blUrl);
    put("fwurl", fwUrl);
    put("host", host);
    snprintf(num, sizeof(num), "%u", (unsigned)bloomKb); put("bloomkb", num);
    snprintf(num, sizeof(num), "%u", (unsigned)blHours); put("blhours", num);
    snprintf(num, sizeof(num), "%u", (unsigned)txPower); put("txpower", num);
    snprintf(num, sizeof(num), "%u", (unsigned)psMode); put("ps", num);
    snprintf(num, sizeof(num), "%u", (unsigned)cpuMhz); put("cpu", num);
    put("noauth", noAuth ? "1" : "0");
    snprintf(num, sizeof(num), "%u", (unsigned)upMode); put("upmode", num);
    snprintf(num, sizeof(num), "%u", (unsigned)upTimeoutMs); put("uptmo", num);
    if (!ok || n + 1 > cap) return 0;
    tmp[n] = 0;
    size_t used = n + 1;
    memset(out + used, 0xFF, cap - used);
    return used;
  }
};

}  // namespace c3
