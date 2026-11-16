// C3Hole - DNS ad-blocking sinkhole for the ESP32-C3 (no PSRAM).
//
//  * Blocklist = sorted 40-bit hashes in a raw flash partition (memory-mapped),
//    with a Bloom filter in RAM so most lookups never touch flash.
//  * DNS engine = src/core/dns.cpp (async, 32 concurrent upstream queries).
//  * Settings live in the 4 KB `cfg` partition (src/core/config.h).
#include <Arduino.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_spi_flash.h>
#include <esp_system.h>
#include <lwip/dns.h>
#include <mbedtls/base64.h>
#include <time.h>

#include "core/blocklist.h"
#include "core/config.h"
#include "core/dns.h"
#include "web_ui.h"

#ifndef C3HOLE_VERSION
#define C3HOLE_VERSION "dev"
#endif

// CA bundle embedded by platformio.ini (board_build.embed_files)
extern const uint8_t rootca_crt_bundle_start[] asm("_binary_data_cert_x509_crt_bundle_bin_start");

static const uint8_t PART_SUBTYPE_CFG = 0x40;
static const uint8_t PART_SUBTYPE_BLOCKLIST = 0x41;
static const uint8_t BOOT_PIN = 9;

// ------------------------------------------------------------------ globals
static c3::Config cfg;
static c3::Matcher matcher;
static uint32_t dnsRng() { return esp_random(); }
static c3::DnsServer dnsServer(matcher, dnsRng);
static WebServer web(80);
static const esp_partition_t* partCfg = nullptr;
static const esp_partition_t* partBl = nullptr;

static bool setupMode = false;
static bool wifiUp = false;
static uint32_t rebootAtMs = 0;

// diagnostics shown on the dashboard
static uint32_t wifiDrops = 0;
static uint8_t lastDiscReason = 0;
static uint32_t lowHeapEvents = 0;
static uint32_t wifiDownSince = 0, lastWifiKick = 0;

// ------------------------------------------------------------------ small helpers
static String jsonEsc(const char* s) {
  String o;
  for (; *s; s++) {
    char c = *s;
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if ((uint8_t)c < 0x20) { o += ' '; }
    else o += c;
  }
  return o;
}

static void randomHex(char* out, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++) snprintf(out + i * 2, 3, "%02x", (unsigned)(esp_random() & 0xFF));
}

static bool validUrl(const String& u) {
  if (u.length() == 0) return true;
  if (u.length() >= 160) return false;
  if (!(u.startsWith("http://") || u.startsWith("https://"))) return false;
  return c3::Config::validValue(u.c_str());
}

static bool parseIp(const String& s, uint32_t& out) {
  IPAddress ip;
  if (!ip.fromString(s)) return false;
  out = (uint32_t)ip;  // network byte order, same layout as in_addr
  return true;
}

// "192.168.0.5" or "192.168.0.5:5353" (your own resolver, e.g. AdGuard Home / Unbound / Pi-hole).
static bool parseUpstream(const String& s, uint32_t& ip, uint16_t& port) {
  int colon = s.indexOf(':');
  String host = colon >= 0 ? s.substring(0, colon) : s;
  long p = 53;
  if (colon >= 0) {
    String ps = s.substring(colon + 1);
    if (ps.length() < 1 || ps.length() > 5) return false;
    for (size_t i = 0; i < ps.length(); i++) if (ps[i] < '0' || ps[i] > '9') return false;
    p = ps.toInt();
    if (p < 1 || p > 65535) return false;
  }
  uint32_t a;
  if (!parseIp(host, a) || a == 0) return false;
  ip = a;
  port = (uint16_t)p;
  return true;
}

static const char* resetReasonText() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "power-on";
    case ESP_RST_SW: return "software restart";
    case ESP_RST_PANIC: return "CRASH (panic)";
    case ESP_RST_INT_WDT: case ESP_RST_TASK_WDT: case ESP_RST_WDT: return "watchdog reset";
    case ESP_RST_BROWNOUT: return "BROWNOUT (weak power)";
    case ESP_RST_DEEPSLEEP: return "deep sleep";
    case ESP_RST_EXT: return "reset button";
    default: return "unknown";
  }
}

static void applyRadio();
static void applyUpstreams();
static void applyLwipDns();

// ------------------------------------------------------------------ config storage
static bool loadConfig() {
  uint8_t* b = (uint8_t*)malloc(c3::CFG_PART_SIZE);
  if (!b) return false;
  bool ok = esp_partition_read(partCfg, 0, b, c3::CFG_PART_SIZE) == ESP_OK && cfg.parse(b, c3::CFG_PART_SIZE);
  free(b);
  return ok;
}

static bool saveConfig() {
  uint8_t* b = (uint8_t*)malloc(c3::CFG_PART_SIZE);
  if (!b) return false;
  bool ok = cfg.serialize(b, c3::CFG_PART_SIZE) > 0 && esp_partition_erase_range(partCfg, 0, c3::CFG_PART_SIZE) == ESP_OK &&
            esp_partition_write(partCfg, 0, b, c3::CFG_PART_SIZE) == ESP_OK;
  free(b);
  return ok;
}

static void factoryReset() {
  esp_partition_erase_range(partCfg, 0, c3::CFG_PART_SIZE);
  delay(200);
  ESP.restart();
}

// ------------------------------------------------------------------ blocklist partition
class FlashReadStore : public c3::HashStore {
 public:
  FlashReadStore() : n(0) {}
  uint32_t n;
  uint32_t count() const override { return n; }
  uint64_t at(uint32_t i) const override {
    uint8_t b[5];
    esp_partition_read(partBl, c3::BL_HEADER_SIZE + (size_t)i * c3::BL_HASH_SIZE, b, 5);
    return c3::getBE40(b);
  }
};

static c3::BlInfo blInfo;
static bool blValid = false;
static bool blMapped = false;
static spi_flash_mmap_handle_t blHandle = 0;
static c3::MemStore memStore;
static FlashReadStore readStore;
static const char* blMode = "-";

static uint32_t blCapacity() { return partBl ? (uint32_t)((partBl->size - c3::BL_HEADER_SIZE) / c3::BL_HASH_SIZE) : 0; }

static uint32_t effectiveBloomBytes() {
  uint32_t kb = cfg.bloomKb;
  uint32_t freeKb = ESP.getFreeHeap() / 1024;
  if (kb == 0) {  // automatic: use what is left after a 100 KB runtime reserve
    kb = freeKb > 100 ? freeKb - 100 : 0;
    if (kb > 256) kb = 256;
  } else {
    uint32_t cap = freeKb > 64 ? freeKb - 64 : 0;  // keep 64 KB for Wi-Fi buffers, lwIP, web server, TLS
    if (kb > cap) kb = cap;
  }
  return kb >= 4 ? kb * 1024 : 0;
}

static void yieldBriefly() { vTaskDelay(1); }

static void unloadBlocklist() {
  matcher.unload();
  if (blMapped) { spi_flash_munmap(blHandle); blMapped = false; }
  blValid = false;
  blMode = "-";
}

static bool loadBlocklist() {
  unloadBlocklist();
  uint8_t h[c3::BL_HEADER_SIZE];
  if (esp_partition_read(partBl, 0, h, sizeof(h)) != ESP_OK) return false;
  if (!c3::blParseHeader(h, sizeof(h), blInfo)) return false;
  size_t need = c3::BL_HEADER_SIZE + (size_t)blInfo.count * c3::BL_HASH_SIZE;
  if (blInfo.count == 0 || need > partBl->size) return false;
  const void* ptr = nullptr;
  c3::HashStore* store;
  if (esp_partition_mmap(partBl, 0, need, SPI_FLASH_MMAP_DATA, &ptr, &blHandle) == ESP_OK) {
    blMapped = true;
    memStore.set((const uint8_t*)ptr + c3::BL_HEADER_SIZE, blInfo.count);
    store = &memStore;
    blMode = "memory-mapped";
  } else {
    readStore.n = blInfo.count;
    store = &readStore;
    blMode = "read on demand";
  }
  matcher.load(store, effectiveBloomBytes(), yieldBriefly);
  blValid = true;
  return true;
}

static void restoreBloom() {
  matcher.dropBloom();
  matcher.rebuildBloom(effectiveBloomBytes(), yieldBriefly);
}

// Re-reads the payload from flash and checks it against the header hash.
static bool verifyFlash(const c3::BlInfo& info) {
  c3::Sha256 sh;
  uint8_t* buf = (uint8_t*)malloc(4096);
  if (!buf) return false;
  size_t total = (size_t)info.count * c3::BL_HASH_SIZE, off = 0;
  bool ok = true;
  while (off < total && ok) {
    size_t n = total - off < 4096 ? total - off : 4096;
    ok = esp_partition_read(partBl, c3::BL_HEADER_SIZE + off, buf, n) == ESP_OK;
    sh.update(buf, n);
    off += n;
  }
  free(buf);
  uint8_t d[32];
  sh.final(d);
  return ok && memcmp(d, info.sha, 32) == 0;
}

// ------------------------------------------------------------------ update state
enum UpdKind { UPD_NONE, UPD_BLOCKLIST, UPD_FIRMWARE };
static struct {
  volatile bool busy;
  volatile uint8_t pct;
  UpdKind kind;
  char msg[96];
  char last[96];
  uint32_t lastOk;
} upd = {false, 0, UPD_NONE, "idle", "never", 0};
static uint32_t nextBlUpdateMs = 0;

static void setMsg(const char* m, int pct = -1) {
  if (m != upd.msg) {
    strncpy(upd.msg, m, sizeof(upd.msg) - 1);
    upd.msg[sizeof(upd.msg) - 1] = 0;
  }
  if (pct >= 0) upd.pct = (uint8_t)pct;
}

static void setLast(const char* m) {
  strncpy(upd.last, m, sizeof(upd.last) - 1);
  upd.last[sizeof(upd.last) - 1] = 0;
}

// Receives the blocklist byte stream (from HTTP or a browser upload).
// VERIFY mode only hashes; WRITE mode erases the partition once the header is
// accepted, stores the payload, and writes the header LAST so an interrupted
// update can never leave a half-written list that looks valid.
class BlSink : public Stream {
 public:
  enum Mode { VERIFY, WRITE };
  BlSink(Mode m, const uint8_t* expectSha, int pctBase, int pctSpan)
      : mode_(m), hdrFill_(0), hdrOk_(false), erased_(false), got_(0), expected_(0), err_(""), wbuf_(nullptr),
        wfill_(0), woff_(0), base_(pctBase), span_(pctSpan), hasExpect_(expectSha != nullptr) {
    if (expectSha) memcpy(expect_, expectSha, 32);
  }
  ~BlSink() { if (wbuf_) free(wbuf_); }

  size_t write(const uint8_t* b, size_t n) override {
    size_t total = n;
    while (n && hdrFill_ < c3::BL_HEADER_SIZE) { hdr_[hdrFill_++] = *b++; n--; }
    if (hdrFill_ == c3::BL_HEADER_SIZE && !hdrOk_) {
      if (!c3::blParseHeader(hdr_, c3::BL_HEADER_SIZE, info_)) return fail("not a C3Hole blocklist");
      if (info_.count == 0 || info_.count > blCapacity()) return fail("list does not fit this device");
      expected_ = (size_t)info_.count * c3::BL_HASH_SIZE;
      if (hasExpect_ && memcmp(expect_, info_.sha, 32) != 0) return fail("file changed during download");
      if (mode_ == WRITE) {
        wbuf_ = (uint8_t*)malloc(4096);
        if (!wbuf_) return fail("out of memory");
        unloadBlocklist();
        size_t eraseLen = (c3::BL_HEADER_SIZE + expected_ + 4095) & ~(size_t)4095;
        erased_ = true;
        if (esp_partition_erase_range(partBl, 0, eraseLen) != ESP_OK) return fail("flash erase failed");
      }
      hdrOk_ = true;
    }
    if (n) {
      if (!hdrOk_) return fail("short header");
      if (got_ + n > expected_) return fail("file longer than its header says");
      sha_.update(b, n);
      if (mode_ == WRITE && !stage(b, n)) return fail("flash write failed");
      got_ += n;
      if (expected_) setMsg(upd.msg, base_ + (int)((uint64_t)got_ * span_ / expected_));
    }
    return total;
  }
  size_t write(uint8_t c) override { return write(&c, 1); }
  int available() override { return 0; }
  int read() override { return -1; }
  int peek() override { return -1; }
  void flush() override {}

  bool finish() {
    if (!hdrOk_ || got_ != expected_) { if (!*err_) err_ = "incomplete download"; return false; }
    uint8_t d[32];
    sha_.final(d);
    if (memcmp(d, info_.sha, 32) != 0) { err_ = "checksum mismatch"; return false; }
    if (mode_ == WRITE) {
      if (wfill_ && esp_partition_write(partBl, c3::BL_HEADER_SIZE + woff_, wbuf_, wfill_) != ESP_OK) { err_ = "flash write failed"; return false; }
      wfill_ = 0;
      if (esp_partition_write(partBl, 0, hdr_, c3::BL_HEADER_SIZE) != ESP_OK) { err_ = "header write failed"; return false; }
    }
    return true;
  }

  const char* error() const { return err_; }
  const c3::BlInfo& info() const { return info_; }
  bool erased() const { return erased_; }

 private:
  size_t fail(const char* m) { err_ = m; return 0; }
  bool stage(const uint8_t* b, size_t n) {
    while (n) {
      size_t take = 4096 - wfill_;
      if (take > n) take = n;
      memcpy(wbuf_ + wfill_, b, take);
      wfill_ += take; b += take; n -= take;
      if (wfill_ == 4096) {
        if (esp_partition_write(partBl, c3::BL_HEADER_SIZE + woff_, wbuf_, 4096) != ESP_OK) return false;
        woff_ += 4096;
        wfill_ = 0;
      }
    }
    return true;
  }

  Mode mode_;
  uint8_t hdr_[c3::BL_HEADER_SIZE];
  size_t hdrFill_;
  bool hdrOk_, erased_;
  size_t got_, expected_;
  const char* err_;
  c3::BlInfo info_;
  c3::Sha256 sha_;
  uint8_t* wbuf_;
  size_t wfill_, woff_;
  int base_, span_;
  bool hasExpect_;
  uint8_t expect_[32];
};

// Receives a firmware image and feeds it to the Update library.
class FwSink : public Stream {
 public:
  FwSink() : started_(false), err_("") {}
  size_t write(const uint8_t* b, size_t n) override {
    if (!n) return 0;
    if (!started_) {
      if (b[0] != 0xE9) { err_ = "not an ESP32 firmware image"; return 0; }
      if (!Update.begin(UPDATE_SIZE_UNKNOWN)) { err_ = "no OTA slot / not enough space"; return 0; }
      started_ = true;
    }
    if (Update.write((uint8_t*)b, n) != n) { err_ = "flash write failed"; return 0; }
    return n;
  }
  size_t write(uint8_t c) override { return write(&c, 1); }
  int available() override { return 0; }
  int read() override { return -1; }
  int peek() override { return -1; }
  void flush() override {}
  bool started() const { return started_; }
  const char* error() const { return err_; }
 private:
  bool started_;
  const char* err_;
};

// ------------------------------------------------------------------ HTTP download
static bool waitForTime(uint32_t ms) {
  uint32_t t0 = millis();
  while (time(nullptr) < 1700000000 && millis() - t0 < ms) delay(200);
  return time(nullptr) >= 1700000000;
}

static bool httpStream(const char* url, Stream& sink, String& err) {
  bool https = strncmp(url, "https://", 8) == 0;
  WiFiClientSecure sc;
  WiFiClient pc;
  HTTPClient http;
  bool begun;
  if (https) {
    sc.setCACertBundle(rootca_crt_bundle_start);
    begun = http.begin(sc, String(url));
  } else {
    begun = http.begin(pc, String(url));
  }
  if (!begun) { err = "bad URL"; return false; }
  http.setConnectTimeout(10000);
  http.setTimeout(20000);
  http.setReuse(false);
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setUserAgent("C3Hole/" C3HOLE_VERSION);
  int code = http.GET();
  if (code != 200) {
    err = code < 0 ? HTTPClient::errorToString(code) : String("HTTP ") + code;
    http.end();
    return false;
  }
  int r = http.writeToStream(&sink);
  http.end();
  if (r < 0) { err = HTTPClient::errorToString(r); return false; }
  return true;
}

static void finishUpdate(bool ok, const String& detail) {
  String s = ok ? String("OK: ") + detail : String("FAILED: ") + detail;
  setLast(s.c_str());
  setMsg(s.c_str(), ok ? 100 : 0);
  if (ok) upd.lastOk = (uint32_t)time(nullptr);
}

static void doBlocklistUpdate() {
  String err;
  const char* url = cfg.blUrl;
  if (!url[0]) { finishUpdate(false, "no blocklist URL set"); return; }
  bool https = strncmp(url, "https://", 8) == 0;
  matcher.dropBloom();  // free ~128 KB of RAM for the TLS session
  if (https) {
    setMsg("Waiting for clock (NTP)...", 1);
    if (!waitForTime(20000)) { restoreBloom(); finishUpdate(false, "clock not set (NTP unreachable)"); return; }
  }
  setMsg("Downloading (pass 1: verify)...", 2);
  BlSink verify(BlSink::VERIFY, nullptr, 2, 43);
  if (!httpStream(url, verify, err) || !verify.finish()) {
    restoreBloom();
    finishUpdate(false, verify.error()[0] ? String(verify.error()) : err);
    return;
  }
  uint8_t sha[32];
  memcpy(sha, verify.info().sha, 32);
  setMsg("Installing (pass 2)...", 46);
  BlSink install(BlSink::WRITE, sha, 46, 50);
  bool ok = httpStream(url, install, err) && install.finish() && verifyFlash(install.info());
  if (!ok) {
    String why = install.error()[0] ? String(install.error()) : (err.length() ? err : String("verification failed"));
    if (install.erased()) { loadBlocklist(); nextBlUpdateMs = millis() + 5 * 60 * 1000UL; }
    else restoreBloom();
    finishUpdate(false, why);
    return;
  }
  loadBlocklist();
  char d[64];
  snprintf(d, sizeof(d), "%u domains installed", (unsigned)blInfo.count);
  finishUpdate(true, d);
}

static void doFirmwareUpdate() {
  String err;
  const char* url = cfg.fwUrl;
  if (!url[0]) { finishUpdate(false, "no firmware URL set"); return; }
  matcher.dropBloom();
  if (strncmp(url, "https://", 8) == 0) {
    setMsg("Waiting for clock (NTP)...", 1);
    if (!waitForTime(20000)) { restoreBloom(); finishUpdate(false, "clock not set (NTP unreachable)"); return; }
  }
  setMsg("Downloading firmware...", 5);
  FwSink sink;
  bool ok = httpStream(url, sink, err);
  if (ok && sink.started() && Update.end(true)) {
    finishUpdate(true, "firmware installed, rebooting");
    rebootAtMs = millis() + 1500;
    return;
  }
  String why = sink.error()[0] ? String(sink.error()) : (err.length() ? err : String(Update.errorString()));
  if (sink.started()) Update.abort();
  restoreBloom();
  finishUpdate(false, why);
}

static void updateTask(void*) {
  if (upd.kind == UPD_BLOCKLIST) doBlocklistUpdate();
  else if (upd.kind == UPD_FIRMWARE) doFirmwareUpdate();
  upd.busy = false;
  vTaskDelete(nullptr);
}

static bool startUpdate(UpdKind k) {
  if (upd.busy || !wifiUp) return false;
  upd.busy = true;
  upd.kind = k;
  upd.pct = 0;
  setMsg("Starting...", 0);
  if (xTaskCreate(updateTask, "upd", 12288, nullptr, 2, nullptr) != pdPASS) { upd.busy = false; return false; }
  return true;
}

// ------------------------------------------------------------------ web: auth
static uint32_t lockUntilMs = 0;
static uint8_t authFails = 0;

// With no password set, only accept requests addressed to an IP or to <hostname>.local
// (blocks DNS-rebinding attacks from web pages that resolve an attacker name to this device).
static bool hostAllowed() {
  String h = web.header("Host");
  int colon = h.indexOf(':');
  if (colon >= 0) h = h.substring(0, colon);
  h.toLowerCase();
  IPAddress ip;
  if (ip.fromString(h)) return true;
  String mine = String(cfg.host);
  mine.toLowerCase();
  return h == mine + ".local" || h == mine;
}

static bool authorized() {
  if (cfg.noAuth) return hostAllowed();
  if (!cfg.dashHash[0]) return false;
  if (lockUntilMs != 0 && (int32_t)(millis() - lockUntilMs) < 0) return false;
  String h = web.header("Authorization");
  if (!h.startsWith("Basic ")) return false;
  String b64 = h.substring(6);
  unsigned char out[96];
  size_t olen = 0;
  if (mbedtls_base64_decode(out, sizeof(out) - 1, &olen, (const unsigned char*)b64.c_str(), b64.length()) != 0) return false;
  out[olen] = 0;
  char* colon = strchr((char*)out, ':');
  if (!colon) return false;
  bool ok = cfg.checkDashPassword(colon + 1);
  if (ok) { authFails = 0; return true; }
  if (++authFails >= 5) { authFails = 0; lockUntilMs = millis() + 30000; if (lockUntilMs == 0) lockUntilMs = 1; }
  return false;
}

static void securityHeaders() {
  web.sendHeader("Cache-Control", "no-store");
  web.sendHeader("X-Frame-Options", "DENY");
  web.sendHeader("X-Content-Type-Options", "nosniff");
}

static void sendChallenge() {
  securityHeaders();
  web.sendHeader("WWW-Authenticate", "Basic realm=\"C3Hole\"");
  web.send(401, "text/plain", "Unauthorized");
}

// GET: password only.  POST: password + custom header (blocks cross-site form posts).
static bool guard(bool post) {
  if (!authorized()) { sendChallenge(); return false; }
  if (post && web.header("X-C3H") != "1") { web.send(403, "text/plain", "Missing X-C3H header"); return false; }
  return true;
}

// ------------------------------------------------------------------ web: handlers
static String statusJson() {
  c3::DnsStats d = dnsServer.stats();
  c3::MatchStats m = matcher.stats();
  String j;
  j.reserve(2200);
  j += "{\"ver\":\"" C3HOLE_VERSION "\",\"slot\":\"";
  const esp_partition_t* run = esp_ota_get_running_partition();
  j += run ? run->label : "?";
  j += "\",\"uptime\":" + String((uint32_t)(millis() / 1000));
  j += ",\"heap\":{\"free\":" + String(ESP.getFreeHeap()) + ",\"min\":" + String(ESP.getMinFreeHeap()) + ",\"maxblk\":" +
       String(ESP.getMaxAllocHeap()) + "}";
  j += ",\"sys\":{\"reset\":\"" + String(resetReasonText()) + "\",\"temp\":" + String(temperatureRead(), 1) + ",\"cpu\":" +
       String(getCpuFrequencyMhz()) + ",\"drops\":" + String(wifiDrops) + ",\"disc\":" + String((unsigned)lastDiscReason) +
       ",\"lowheap\":" + String(lowHeapEvents) + "}";
  j += ",\"wifi\":{\"ssid\":\"" + jsonEsc(WiFi.SSID().c_str()) + "\",\"rssi\":" + String(WiFi.RSSI()) + ",\"ip\":\"" +
       WiFi.localIP().toString() + "\"}";
  j += ",\"dns\":{\"total\":" + String(d.total) + ",\"blocked\":" + String(d.blocked) + ",\"forwarded\":" + String(d.forwarded) +
       ",\"answered\":" + String(d.answered) + ",\"timeouts\":" + String(d.timeouts) + ",\"retried\":" + String(d.retried) +
       ",\"overflow\":" + String(d.overflow) + ",\"pending\":" + String(dnsServer.pending()) + ",\"cname\":" + String(d.cnameBlocked) +
       ",\"trunc\":" + String(d.truncated) + ",\"canary\":" + String(d.canary) + "}";
  j += ",\"match\":{\"queries\":" + String(m.queries) + ",\"misses\":" + String(m.misses) + ",\"noflash\":" + String(m.missesNoFlash) +
       ",\"searches\":" + String(m.flashSearches) + "}";
  j += ",\"bloom\":{\"on\":" + String(matcher.hasBloom() ? "true" : "false") + ",\"kb\":" + String(matcher.bloomBytes() / 1024) +
       ",\"k\":" + String(matcher.bloomK()) + ",\"fill\":" + String(matcher.bloomFill(), 3) + ",\"fpr\":" + String(matcher.bloomFpr(), 4) + "}";
  j += ",\"bl\":{\"valid\":" + String(blValid ? "true" : "false") + ",\"count\":" + String(blValid ? blInfo.count : 0) +
       ",\"created\":" + String(blValid ? blInfo.created : 0) + ",\"max\":" + String(blCapacity()) + ",\"mode\":\"" + blMode +
       "\",\"last\":\"" + jsonEsc(upd.last) + "\",\"lastOk\":" + String(upd.lastOk) + "}";
  j += ",\"upd\":{\"busy\":" + String(upd.busy ? "true" : "false") + ",\"pct\":" + String((unsigned)upd.pct) + ",\"msg\":\"" +
       jsonEsc(upd.msg) + "\"}";
  j += ",\"cfg\":{\"up1\":\"" + jsonEsc(cfg.up1) + "\",\"up2\":\"" + jsonEsc(cfg.up2) + "\",\"bloomkb\":" + String(cfg.bloomKb) +
       ",\"blurl\":\"" + jsonEsc(cfg.blUrl) + "\",\"blhours\":" + String(cfg.blHours) + ",\"fwurl\":\"" + jsonEsc(cfg.fwUrl) + "\"" +
       ",\"txpower\":" + String((unsigned)cfg.txPower) + ",\"ps\":" + String((unsigned)cfg.psMode) + ",\"cpu\":" + String(cfg.cpuMhz) +
       ",\"upmode\":" + String((unsigned)cfg.upMode) + ",\"uptmo\":" + String(cfg.upTimeoutMs) + ",\"noauth\":" + String(cfg.noAuth ? "true" : "false") + "}";
  char recent[c3::DnsServer::kRecent][c3::DnsServer::kRecentLen];
  size_t rn = dnsServer.recentBlocked(recent, c3::DnsServer::kRecent);
  j += ",\"recent\":[";
  for (size_t i = 0; i < rn; i++) { if (i) j += ','; j += '"'; j += jsonEsc(recent[i]); j += '"'; }
  c3::ClientStat cs[c3::DnsServer::kClients];
  size_t cn = dnsServer.clients(cs, 8);
  j += "],\"clients\":[";
  for (size_t i = 0; i < cn; i++) {
    if (i) j += ',';
    IPAddress ip(cs[i].ip);
    j += "{\"ip\":\"" + ip.toString() + "\",\"total\":" + String(cs[i].total) + ",\"blocked\":" + String(cs[i].blocked) + "}";
  }
  j += "]}";
  return j;
}

static void handleRoot() {
  if (!guard(false)) return;
  securityHeaders();
  web.send_P(200, "text/html", DASH_PAGE);
}

static void handleStatus() {
  if (!guard(false)) return;
  securityHeaders();
  web.send(200, "application/json", statusJson());
}

static void handleConfig() {
  if (!guard(true)) return;
  String up1 = web.arg("up1"), up2 = web.arg("up2"), blurl = web.arg("blurl"), fwurl = web.arg("fwurl");
  up1.trim(); up2.trim();
  uint32_t ip1 = 0, ip2 = 0;
  uint16_t port1 = 53, port2 = 53;
  if (!parseUpstream(up1, ip1, port1)) { web.send(400, "text/plain", "Upstream 1 must be an IPv4 address, optionally with :port (e.g. 192.168.0.5:5353)"); return; }
  if (up2.length() && !parseUpstream(up2, ip2, port2)) { web.send(400, "text/plain", "Upstream 2 must be an IPv4 address, optionally with :port"); return; }
  uint32_t me = (uint32_t)WiFi.localIP();
  if ((ip1 == me && port1 == 53) || (ip2 == me && port2 == 53)) { web.send(400, "text/plain", "An upstream cannot be this device itself (that would loop)"); return; }
  if (!validUrl(blurl) || !validUrl(fwurl)) { web.send(400, "text/plain", "URLs must start with http:// or https:// (max 159 chars)"); return; }
  long kb = web.arg("bloomkb").toInt(), hrs = web.arg("blhours").toInt();
  long txp = web.arg("txpower").toInt(), ps = web.arg("ps").toInt(), cpu = web.arg("cpu").toInt();
  long upm = web.arg("upmode").toInt(), tmo = web.arg("uptmo").toInt();
  if (kb < 0 || kb > 400 || hrs < 0 || hrs > 8760) { web.send(400, "text/plain", "Bloom KB 0-400, hours 0-8760"); return; }
  if (!c3::Config::validTxPower(txp)) { web.send(400, "text/plain", "Unsupported TX power value"); return; }
  if (ps < 0 || ps > 2 || (cpu != 80 && cpu != 160) || (upm != 0 && upm != 1) || tmo < 100 || tmo > 5000) {
    web.send(400, "text/plain", "Invalid power-save, CPU or upstream-mode value (timeout 100-5000 ms)");
    return;
  }
  bool bloomChanged = (uint16_t)kb != cfg.bloomKb;
  c3::Config::copy(cfg.up1, sizeof(cfg.up1), up1.c_str());
  c3::Config::copy(cfg.up2, sizeof(cfg.up2), up2.c_str());
  c3::Config::copy(cfg.blUrl, sizeof(cfg.blUrl), blurl.c_str());
  c3::Config::copy(cfg.fwUrl, sizeof(cfg.fwUrl), fwurl.c_str());
  cfg.bloomKb = (uint16_t)kb;
  cfg.blHours = (uint16_t)hrs;
  cfg.txPower = (uint8_t)txp;
  cfg.psMode = (uint8_t)ps;
  cfg.cpuMhz = (uint16_t)cpu;  // takes effect after the next reboot
  cfg.upMode = (uint8_t)upm;
  cfg.upTimeoutMs = (uint16_t)tmo;
  if (!saveConfig()) { web.send(500, "text/plain", "Could not save settings"); return; }
  applyUpstreams();
  applyLwipDns();
  applyRadio();
  nextBlUpdateMs = millis() + 5000;
  if (bloomChanged && blValid && !upd.busy) restoreBloom();
  web.send(200, "application/json", "{}");
}

static void handlePassword() {
  if (!guard(true)) return;
  if (web.arg("nopw") == "1") {  // open dashboard: anyone on the LAN can use it
    cfg.noAuth = true;
    cfg.dashHash[0] = 0;
    cfg.dashSalt[0] = 0;
    if (!saveConfig()) { web.send(500, "text/plain", "Could not save"); return; }
    web.send(200, "application/json", "{}");
    return;
  }
  String pw = web.arg("pw");
  if (pw.length() < 8 || pw.length() > 60 || !c3::Config::validValue(pw.c_str())) { web.send(400, "text/plain", "Password must be 8-60 characters"); return; }
  char salt[17];
  randomHex(salt, 8);
  cfg.setDashPassword(pw.c_str(), salt);
  cfg.noAuth = false;
  if (!saveConfig()) { web.send(500, "text/plain", "Could not save"); return; }
  web.send(200, "application/json", "{}");
}

static void handleWifi() {
  if (!guard(true)) return;
  String ssid = web.arg("ssid"), pass = web.arg("pass");
  if (ssid.length() < 1 || ssid.length() > 32 || pass.length() > 63 || !c3::Config::validValue(ssid.c_str()) || !c3::Config::validValue(pass.c_str())) {
    web.send(400, "text/plain", "SSID 1-32 chars, password up to 63 chars");
    return;
  }
  c3::Config::copy(cfg.ssid, sizeof(cfg.ssid), ssid.c_str());
  c3::Config::copy(cfg.wifiPass, sizeof(cfg.wifiPass), pass.c_str());
  if (!saveConfig()) { web.send(500, "text/plain", "Could not save"); return; }
  web.send(200, "application/json", "{}");
  rebootAtMs = millis() + 1500;
}

static void handleFetch() {
  if (!guard(true)) return;
  if (!cfg.blUrl[0]) { web.send(400, "text/plain", "Set a blocklist URL first"); return; }
  if (!startUpdate(UPD_BLOCKLIST)) { web.send(409, "text/plain", "Busy or Wi-Fi down"); return; }
  web.send(200, "application/json", "{}");
}

static void handleFwFetch() {
  if (!guard(true)) return;
  if (!cfg.fwUrl[0]) { web.send(400, "text/plain", "Set a firmware URL first"); return; }
  if (!startUpdate(UPD_FIRMWARE)) { web.send(409, "text/plain", "Busy or Wi-Fi down"); return; }
  web.send(200, "application/json", "{}");
}

static void handleReboot() {
  if (!guard(true)) return;
  web.send(200, "application/json", "{}");
  rebootAtMs = millis() + 800;
}

static void handleFactory() {
  if (!guard(true)) return;
  web.send(200, "application/json", "{}");
  delay(300);
  factoryReset();
}

// ---- manual blocklist upload (multipart) ----
static BlSink* upBl = nullptr;
static bool upDenied = false;
static String upErr;

static void upCleanup() {
  delete upBl;
  upBl = nullptr;
  upd.busy = false;
}

static void onBlUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    upErr = "";
    upDenied = !authorized() || web.header("X-C3H") != "1";
    if (upDenied) return;
    if (upd.busy) { upErr = "device is busy with another update"; return; }
    upd.busy = true;
    upd.kind = UPD_BLOCKLIST;
    setMsg("Receiving upload...", 0);
    matcher.dropBloom();
    delete upBl;
    upBl = new BlSink(BlSink::WRITE, nullptr, 0, 100);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (upDenied || !upBl || upErr.length()) return;
    if (upBl->write(u.buf, u.currentSize) != u.currentSize) upErr = upBl->error();
  } else if (u.status == UPLOAD_FILE_END) {
    if (upDenied || !upBl || upErr.length()) return;
    if (!upBl->finish() || !verifyFlash(upBl->info())) upErr = upBl->error()[0] ? upBl->error() : "verification failed";
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    upErr = "upload aborted";
  }
}

static void onBlUploadDone() {
  if (upDenied) { sendChallenge(); upCleanup(); return; }
  bool erased = upBl && upBl->erased();
  if (upErr.length()) {
    if (erased) loadBlocklist(); else restoreBloom();
    setLast((String("FAILED: ") + upErr).c_str());
    web.send(400, "text/plain", upErr);
    upCleanup();
    return;
  }
  bool ok = loadBlocklist();
  upd.lastOk = (uint32_t)time(nullptr);
  setLast(ok ? "OK: uploaded manually" : "FAILED: list invalid after upload");
  web.send(ok ? 200 : 400, "text/plain", ok ? "OK" : "list invalid");
  upCleanup();
}

// ---- manual firmware upload ----
static bool fwStarted = false;
static bool fwDone = false;

static void onFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    upErr = "";
    fwStarted = fwDone = false;
    upDenied = !authorized() || web.header("X-C3H") != "1";
    if (upDenied) return;
    if (upd.busy) { upErr = "device is busy with another update"; return; }
    upd.busy = true;
    matcher.dropBloom();
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (upDenied || upErr.length()) return;
    if (!fwStarted) {
      if (u.buf[0] != 0xE9) { upErr = "not an ESP32 firmware image"; return; }
      if (!Update.begin(UPDATE_SIZE_UNKNOWN)) { upErr = "no OTA slot / not enough space"; return; }
      fwStarted = true;
    }
    if (Update.write(u.buf, u.currentSize) != u.currentSize) upErr = Update.errorString();
  } else if (u.status == UPLOAD_FILE_END) {
    if (upDenied || upErr.length() || !fwStarted) return;
    if (Update.end(true)) fwDone = true; else upErr = Update.errorString();
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    upErr = "upload aborted";
    if (fwStarted) Update.abort();
  }
}

static void onFwUploadDone() {
  if (upDenied) { sendChallenge(); upd.busy = false; return; }
  if (fwDone && !upErr.length()) {
    web.send(200, "text/plain", "Firmware installed, rebooting");
    rebootAtMs = millis() + 1500;
    return;
  }
  if (fwStarted) Update.abort();
  restoreBloom();
  upd.busy = false;
  web.send(400, "text/plain", upErr.length() ? upErr : String("upload incomplete"));
}

// ---- first-run setup (open AP, only while unconfigured) ----
static void handleSetupPage() {
  securityHeaders();
  web.send_P(200, "text/html", SETUP_PAGE);
}

static void handleSetupSave() {
  String ssid = web.arg("ssid"), wpass = web.arg("wpass"), dpass = web.arg("dpass");
  bool nopw = web.arg("nopw") == "1";
  if (ssid.length() < 1 || ssid.length() > 32 || wpass.length() > 63 || dpass.length() > 60 ||
      !c3::Config::validValue(ssid.c_str()) || !c3::Config::validValue(wpass.c_str()) || !c3::Config::validValue(dpass.c_str()) ||
      (!nopw && dpass.length() < 8)) {
    web.send(400, "text/plain", "Check the fields: SSID 1-32 characters; dashboard password 8-60 characters, or tick 'no password'.");
    return;
  }
  cfg.clear();
  c3::Config::copy(cfg.ssid, sizeof(cfg.ssid), ssid.c_str());
  c3::Config::copy(cfg.wifiPass, sizeof(cfg.wifiPass), wpass.c_str());
  if (nopw) {
    cfg.noAuth = true;
  } else {
    char salt[17];
    randomHex(salt, 8);
    cfg.setDashPassword(dpass.c_str(), salt);
  }
  if (!saveConfig()) { web.send(500, "text/plain", "Could not save settings"); return; }
  web.send(200, "text/html", "<meta name=viewport content='width=device-width'><h3>Saved.</h3><p>Restarting and joining your Wi-Fi...</p>");
  rebootAtMs = millis() + 1500;
}

// ------------------------------------------------------------------ networking
static void applyLwipDns() {
  // The device itself (NTP, update downloads) must not depend on its own DNS sinkhole, and lwIP can only
  // use port 53: take the first configured upstream on port 53, else a public resolver.
  uint32_t ip = 0;
  uint16_t port = 53;
  if (!(parseUpstream(cfg.up1, ip, port) && port == 53) && !(cfg.up2[0] && parseUpstream(cfg.up2, ip, port) && port == 53))
    ip = IPAddress(8, 8, 8, 8);
  IPAddress a(ip);
  ip_addr_t d;
  IP_ADDR4(&d, a[0], a[1], a[2], a[3]);
  dns_setserver(0, &d);
}

static void applyRadio() {
  WiFi.setTxPower((wifi_power_t)cfg.txPower);
  WiFi.setSleep(cfg.psMode == 0 ? WIFI_PS_NONE : cfg.psMode == 1 ? WIFI_PS_MIN_MODEM : WIFI_PS_MAX_MODEM);
}

static void applyUpstreams() {
  uint32_t i1 = 0, i2 = 0;
  uint16_t p1 = 53, p2 = 53;
  parseUpstream(cfg.up1, i1, p1);
  if (cfg.up2[0]) parseUpstream(cfg.up2, i2, p2);
  dnsServer.setUpstreamEndpoints(i1, p1, i2, p2);
  dnsServer.setParallel(cfg.upMode == 1);
  dnsServer.setTimeoutMs(cfg.upTimeoutMs);
}

static void dnsTask(void*) {
  for (;;) dnsServer.step(20);
}

static void startDns() {
  uint32_t ip1 = 0;
  uint16_t p1 = 53;
  parseUpstream(cfg.up1, ip1, p1);
  if (dnsServer.begin(53, ip1, 0)) {
    applyUpstreams();
    xTaskCreate(dnsTask, "dns", 6144, nullptr, 5, nullptr);
    Serial.println("[c3hole] DNS server listening on :53");
  } else {
    Serial.println("[c3hole] ERROR: could not bind UDP :53");
  }
}

static void onWifiUp() {
  Serial.printf("[c3hole] ip=%s\n", WiFi.localIP().toString().c_str());
  applyRadio();
  applyLwipDns();
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  MDNS.end();  // the responder stops answering after a reconnect unless it is restarted
  MDNS.begin(cfg.host);
  MDNS.addService("http", "tcp", 80);
  if (!dnsServer.running()) startDns();
}

static void onWifiEvent(arduino_event_id_t ev, arduino_event_info_t info) {
  if (ev == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) lastDiscReason = info.wifi_sta_disconnected.reason;
}

static void startStation() {
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(cfg.host);
  WiFi.setAutoReconnect(true);
  WiFi.onEvent(onWifiEvent);
  WiFi.begin(cfg.ssid, cfg.wifiPass);
  applyRadio();
}

static void registerRoutes() {
  static const char* hdrs[] = {"Authorization", "X-C3H", "Host"};
  web.collectHeaders(hdrs, 3);
  if (setupMode) {
    web.on("/", HTTP_GET, handleSetupPage);
    web.on("/setup", HTTP_POST, handleSetupSave);
    web.onNotFound(handleSetupPage);
    return;
  }
  web.on("/", HTTP_GET, handleRoot);
  web.on("/api/status", HTTP_GET, handleStatus);
  web.on("/api/config", HTTP_POST, handleConfig);
  web.on("/api/password", HTTP_POST, handlePassword);
  web.on("/api/wifi", HTTP_POST, handleWifi);
  web.on("/api/fetch", HTTP_POST, handleFetch);
  web.on("/api/fwfetch", HTTP_POST, handleFwFetch);
  web.on("/api/reboot", HTTP_POST, handleReboot);
  web.on("/api/factory", HTTP_POST, handleFactory);
  web.on("/api/upload/blocklist", HTTP_POST, onBlUploadDone, onBlUpload);
  web.on("/api/upload/firmware", HTTP_POST, onFwUploadDone, onFwUpload);
  web.onNotFound([]() { web.send(404, "text/plain", "Not found"); });
}

// ------------------------------------------------------------------ Arduino entry points
void setup() {
  Serial.begin(115200);
  Serial.setTxTimeoutMs(0);  // never block when no USB host is listening
  Serial.printf("\n[c3hole] v%s starting, free heap %u\n", C3HOLE_VERSION, (unsigned)ESP.getFreeHeap());
  pinMode(BOOT_PIN, INPUT_PULLUP);

  partCfg = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)PART_SUBTYPE_CFG, nullptr);
  partBl = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)PART_SUBTYPE_BLOCKLIST, nullptr);
  if (!partCfg || !partBl) {
    Serial.println("[c3hole] FATAL: partition table is wrong (flash with the C3Hole flasher or partitions.csv)");
    for (;;) delay(1000);
  }

  bool haveCfg = loadConfig();
  setupMode = !(haveCfg && cfg.configured());
  if (haveCfg && cfg.cpuMhz == 80) setCpuFrequencyMhz(80);  // cooler; 160 MHz is the boot default

  if (setupMode) {
    Serial.println("[c3hole] not configured: starting setup access point 'C3Hole-Setup' (http://192.168.4.1)");
    WiFi.mode(WIFI_AP);
    WiFi.softAP("C3Hole-Setup");
    registerRoutes();
    web.begin();
    return;
  }

  startStation();
  registerRoutes();
  web.begin();

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 15000) delay(250);

  if (loadBlocklist())
    Serial.printf("[c3hole] blocklist: %u domains (%s), bloom %u KB k=%u\n", (unsigned)blInfo.count, blMode,
                  (unsigned)(matcher.bloomBytes() / 1024), (unsigned)matcher.bloomK());
  else
    Serial.println("[c3hole] no valid blocklist installed yet (everything is forwarded)");

  nextBlUpdateMs = millis() + (blValid ? (uint32_t)(cfg.blHours > 1000 ? 1000 : cfg.blHours) * 3600000UL : 20000UL);
}

void loop() {
  if (setupMode) {
    web.handleClient();
    if (rebootAtMs && (int32_t)(millis() - rebootAtMs) >= 0) ESP.restart();
    delay(2);
    return;
  }
  web.handleClient();

  static uint32_t lastTick = 0;
  uint32_t now = millis();
  if (now - lastTick >= 1000) {
    lastTick = now;
    bool up = WiFi.status() == WL_CONNECTED;
    if (up && !wifiUp) onWifiUp();
    if (!up && wifiUp) {
      wifiDrops++;
      Serial.printf("[c3hole] Wi-Fi lost (reason %u), waiting for automatic reconnect\n", (unsigned)lastDiscReason);
    }
    wifiUp = up;
    // The stack reconnects by itself (setAutoReconnect). Never call WiFi.reconnect() in a tight loop: that restarts the
    // attempt every time and a brief outage becomes permanent. Only step in after a long outage, then restart.
    if (up) {
      wifiDownSince = 0;
    } else {
      if (!wifiDownSince) wifiDownSince = now ? now : 1;
      uint32_t down = now - wifiDownSince;
      if (down > 45000UL && now - lastWifiKick > 45000UL) {
        lastWifiKick = now;
        Serial.println("[c3hole] Wi-Fi down for 45 s: restarting the connection attempt");
        WiFi.disconnect(false, false);
        WiFi.begin(cfg.ssid, cfg.wifiPass);
        applyRadio();
      }
      if (down > 300000UL) { Serial.println("[c3hole] Wi-Fi down for 5 min: rebooting"); delay(100); ESP.restart(); }
    }

    // Memory guard: if the heap runs low, give the Bloom filter back so the network stack keeps working.
    uint32_t freeHeap = ESP.getFreeHeap();
    static uint8_t lowCount = 0;
    if (freeHeap < 30 * 1024UL && !upd.busy) {
      if (++lowCount >= 5 && matcher.hasBloom()) {
        matcher.dropBloom();
        lowHeapEvents++;
        Serial.printf("[c3hole] low heap (%u B): Bloom filter released\n", (unsigned)freeHeap);
      }
    } else {
      lowCount = 0;
    }
    if ((now / 1000) % 60 == 0)
      Serial.printf("[c3hole] up=%us heap=%u min=%u maxblk=%u rssi=%d drops=%u\n", (unsigned)(now / 1000), (unsigned)freeHeap,
                    (unsigned)ESP.getMinFreeHeap(), (unsigned)ESP.getMaxAllocHeap(), (int)WiFi.RSSI(), (unsigned)wifiDrops);
    if (now < 120000UL && up && (now / 1000) % 5 == 0) Serial.printf("[c3hole] ip=%s\n", WiFi.localIP().toString().c_str());

    if (up && cfg.blUrl[0] && cfg.blHours > 0 && !upd.busy && (int32_t)(now - nextBlUpdateMs) >= 0) {
      uint32_t hrs = cfg.blHours > 1000 ? 1000 : cfg.blHours;
      nextBlUpdateMs = now + hrs * 3600000UL;
      if (!startUpdate(UPD_BLOCKLIST)) nextBlUpdateMs = now + 60000UL;
    }
  }

  // Hold the BOOT button for 5 s while running to erase all settings.
  static uint32_t lowSince = 0;
  if (digitalRead(BOOT_PIN) == LOW) {
    if (!lowSince) lowSince = now ? now : 1;
    else if (now - lowSince > 5000) factoryReset();
  } else {
    lowSince = 0;
  }

  if (rebootAtMs && (int32_t)(now - rebootAtMs) >= 0) ESP.restart();
  delay(2);
}
