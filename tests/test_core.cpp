// Host-side tests for the portable core (hashing, bloom, matcher, config, DNS engine).
// Build: see tests/run_tests.sh   (compiled with -std=gnu++11 like the firmware)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../src/core/blocklist.h"
#include "../src/core/config.h"
#include "../src/core/dns.h"

using namespace c3;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, ...)                                              \
  do {                                                                \
    if (cond) { g_pass++; }                                           \
    else { g_fail++; printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
  } while (0)

static std::string W = "tests/_work/";

static std::vector<uint8_t> readFile(const std::string& path) {
  std::vector<uint8_t> v;
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) { printf("cannot open %s\n", path.c_str()); exit(2); }
  uint8_t b[65536];
  size_t n;
  while ((n = fread(b, 1, sizeof(b), f)) > 0) v.insert(v.end(), b, b + n);
  fclose(f);
  return v;
}

static uint32_t rngState = 88172645u;
static uint32_t rng32() { rngState ^= rngState << 13; rngState ^= rngState >> 17; rngState ^= rngState << 5; return rngState; }

static uint64_t nowUs() {
  return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}

// ------------------------------------------------------------------ helpers
static std::string sha256hex(const std::string& s) {
  Sha256 h; h.update((const uint8_t*)s.data(), s.size());
  uint8_t d[32]; h.final(d); char hex[65]; toHex(d, 32, hex); return hex;
}

static size_t buildQuery(uint8_t* out, uint16_t id, const char* name, uint16_t qtype, bool edns) {
  size_t p = 0;
  out[p++] = id >> 8; out[p++] = id & 0xFF;
  out[p++] = 0x01; out[p++] = 0x00;             // RD
  out[p++] = 0; out[p++] = 1;                   // QDCOUNT
  out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 0;
  out[p++] = 0; out[p++] = edns ? 1 : 0;        // ARCOUNT
  const char* s = name;
  while (*s) {
    const char* dot = strchr(s, '.');
    size_t l = dot ? (size_t)(dot - s) : strlen(s);
    out[p++] = (uint8_t)l;
    memcpy(out + p, s, l); p += l;
    s += l; if (*s == '.') s++;
  }
  out[p++] = 0;
  out[p++] = qtype >> 8; out[p++] = qtype & 0xFF;
  out[p++] = 0; out[p++] = 1;                   // IN
  if (edns) { const uint8_t opt[] = {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0}; memcpy(out + p, opt, sizeof(opt)); p += sizeof(opt); }
  return p;
}

// ------------------------------------------------------------------ tests
static void testSha() {
  printf("[sha256]\n");
  CHECK(sha256hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
  CHECK(sha256hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty");
  CHECK(sha256hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "two-block");
  std::string million(1000000, 'a');
  CHECK(sha256hex(million) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "1M a");
}

static void testHash() {
  printf("[hash40 vs python]\n");
  FILE* f = fopen((W + "vectors.txt").c_str(), "r");
  char name[256], hex[32];
  int n = 0;
  while (f && fscanf(f, "%255s %31s", name, hex) == 2) {
    uint64_t want = strtoull(hex, nullptr, 16);
    CHECK(hash40(name, strlen(name)) == want, "%s: got %010llx want %s", name, (unsigned long long)hash40(name, strlen(name)), hex);
    n++;
  }
  if (f) fclose(f);
  CHECK(n == 5, "vectors read: %d", n);
}

static void testMatcherSmall() {
  printf("[matcher, python-built list]\n");
  std::vector<uint8_t> file = readFile(W + "small.bin");
  BlInfo info;
  CHECK(blParseHeader(file.data(), file.size(), info), "header parse");
  CHECK(info.count == 5, "count=%u", info.count);
  Sha256 sh; sh.update(file.data() + BL_HEADER_SIZE, file.size() - BL_HEADER_SIZE);
  uint8_t d[32]; sh.final(d);
  CHECK(memcmp(d, info.sha, 32) == 0, "payload sha256 matches header");
  MemStore store; store.set(file.data() + BL_HEADER_SIZE, info.count);
  Matcher m;
  CHECK(m.load(&store, 4096), "load");
  struct { const char* n; bool blocked; } cases[] = {
      {"example.com", true}, {"www.example.com", true}, {"a.b.c.example.com", true},
      {"notexample.com", false}, {"example.org", false}, {"com", false}, {"adblock.net", true},
      {"cdn.adblock.net", true}, {"tracker.io", false}, {"ads.tracker.io", true}, {"x.ads.tracker.io", true},
      {"wild.io", true}, {"io", false}, {"xn--80ak6aa92e.com", true}, {"mail.google.com", false}};
  for (auto& c : cases) CHECK(m.isBlocked(c.n, strlen(c.n)) == c.blocked, "%s expected %d", c.n, c.blocked);
  m.dropBloom();
  for (auto& c : cases) CHECK(m.isBlocked(c.n, strlen(c.n)) == c.blocked, "no-bloom %s", c.n);
  CHECK(m.rebuildBloom(4096), "rebuild");
  m.unload();
  CHECK(!m.isBlocked("example.com", 11), "unloaded matcher blocks nothing");
}

static void testMatcherBig() {
  printf("[matcher, 253,000 domains]\n");
  std::vector<uint8_t> file = readFile(W + "big.bin");
  BlInfo info;
  CHECK(blParseHeader(file.data(), file.size(), info) && info.count == 253000, "header count=%u", info.count);
  MemStore store; store.set(file.data() + BL_HEADER_SIZE, info.count);
  bool sorted = true;
  for (uint32_t i = 1; i < info.count; i++) if (store.at(i - 1) >= store.at(i)) { sorted = false; break; }
  CHECK(sorted, "payload strictly ascending (no duplicate hashes)");

  FILE* f = fopen((W + "big.txt").c_str(), "r");
  std::vector<std::string> doms;
  char line[256];
  while (f && fgets(line, sizeof(line), f)) { line[strcspn(line, "\r\n")] = 0; doms.push_back(line); }
  if (f) fclose(f);
  CHECK(doms.size() == 253000, "domains read %zu", doms.size());

  uint32_t sizes[] = {128, 64, 256};
  for (uint32_t kb : sizes) {
    Matcher m;
    uint64_t t0 = nowUs();
    CHECK(m.load(&store, kb * 1024), "load %u KB", kb);
    uint64_t buildMs = (nowUs() - t0) / 1000;
    size_t miss = 0;
    for (size_t i = 0; i < doms.size(); i += 7) miss += m.isBlocked(doms[i].c_str(), doms[i].size()) ? 0 : 1;
    CHECK(miss == 0, "listed domains not found: %zu", miss);
    std::string sub = "cdn.edge." + doms[123];
    CHECK(m.isBlocked(sub.c_str(), sub.size()), "subdomain of listed");
    size_t fp = 0;
    MatchStats s0 = m.stats();
    for (int i = 0; i < 200000; i++) {
      char nm[64];
      snprintf(nm, sizeof(nm), "host%u.unlisted-%u.example-test.com", rng32() % 100000, rng32());
      fp += m.isBlocked(nm, strlen(nm)) ? 1 : 0;
    }
    MatchStats s1 = m.stats();
    uint32_t misses = s1.misses - s0.misses, noflash = s1.missesNoFlash - s0.missesNoFlash;
    printf("  bloom %3u KB: k=%u fill=%.2f est.FPR=%.1f%% | build %llu ms | misses settled with 0 flash reads: %.1f%% | false blocks %zu/200000\n",
           kb, m.bloomK(), m.bloomFill(), 100.0 * m.bloomFpr(), (unsigned long long)buildMs, 100.0 * noflash / misses, fp);
    CHECK(fp <= 2, "false blocks %zu", fp);
  }
}

static void testConfig() {
  printf("[config, python-built blob]\n");
  std::vector<uint8_t> blob = readFile(W + "cfg.bin");
  Config c;
  CHECK(blob.size() == CFG_PART_SIZE, "blob size");
  CHECK(c.parse(blob.data(), blob.size()), "parse");
  CHECK(!strcmp(c.ssid, "My Home WiFi"), "ssid '%s'", c.ssid);
  CHECK(!strcmp(c.wifiPass, "p@ss=w0rd!"), "wifi pass with '=' '%s'", c.wifiPass);
  CHECK(c.bloomKb == 96 && c.blHours == 12, "numbers");
  CHECK(!strcmp(c.blUrl, "https://example.org/a.bin") && c.fwUrl[0] == 0, "urls");
  CHECK(c.configured(), "configured");
  CHECK(c.checkDashPassword("Dash-Pass-123"), "python-hashed password verifies in C++");
  CHECK(!c.checkDashPassword("Dash-Pass-124") && !c.checkDashPassword(""), "wrong passwords rejected");
  uint8_t out[CFG_PART_SIZE];
  size_t used = c.serialize(out, sizeof(out));
  CHECK(used > 0 && out[CFG_PART_SIZE - 1] == 0xFF, "serialize");
  Config d;
  CHECK(d.parse(out, sizeof(out)) && !strcmp(d.ssid, c.ssid) && !strcmp(d.dashHash, c.dashHash) && d.bloomKb == 96, "roundtrip");
  c.setDashPassword("new-password-9", "feedfacecafebeef");
  CHECK(c.checkDashPassword("new-password-9") && !c.checkDashPassword("Dash-Pass-123"), "password change");
  uint8_t blank[64]; memset(blank, 0xFF, sizeof(blank));
  CHECK(!d.parse(blank, sizeof(blank)), "erased flash is not a config");
  Config e; CHECK(!e.configured(), "default config is unconfigured");
  uint8_t tiny[40];
  CHECK(c.serialize(tiny, sizeof(tiny)) == 0, "serialize reports overflow instead of corrupting memory");
}

static void testDnsPacket() {
  printf("[dns packets]\n");
  uint8_t q[512], r[512];
  size_t n = buildQuery(q, 0xBEEF, "Www.Example.COM", 1, true);
  DnsQuestion dq;
  CHECK(dnsParseQuestion(q, n, dq), "parse");
  CHECK(!strcmp(dq.name, "www.example.com") && dq.qtype == 1 && dq.qclass == 1, "name lowercased '%s'", dq.name);
  size_t rn = dnsBuildBlockedReply(q, n, dq, r, sizeof(r));
  CHECK(rn == (size_t)dq.qend + 16, "A reply size %zu", rn);
  CHECK(r[0] == 0xBE && r[1] == 0xEF && (r[2] & 0x80) && (r[2] & 0x01) && (r[3] & 0x0F) == 0, "header id/flags");
  CHECK(r[7] == 1 && r[11] == 0, "ANCOUNT=1 ARCOUNT=0 (EDNS dropped)");
  CHECK(memcmp(r + rn - 4, "\0\0\0\0", 4) == 0 && r[rn - 5] == 4, "A rdata 0.0.0.0");
  n = buildQuery(q, 1, "ads.example.com", 28, false);
  dnsParseQuestion(q, n, dq);
  rn = dnsBuildBlockedReply(q, n, dq, r, sizeof(r));
  CHECK(rn == (size_t)dq.qend + 28 && r[rn - 17] == 16, "AAAA reply (:: 16 bytes)");
  n = buildQuery(q, 1, "ads.example.com", 16, false);
  dnsParseQuestion(q, n, dq);
  rn = dnsBuildBlockedReply(q, n, dq, r, sizeof(r));
  CHECK(rn == dq.qend && r[7] == 0 && (r[3] & 0x0F) == 0, "TXT -> NODATA (NOERROR, no answer)");
  n = buildQuery(q, 1, "a.example.com", 1, false);
  uint8_t bad[512]; memcpy(bad, q, n);
  bad[2] |= 0x80; CHECK(!dnsParseQuestion(bad, n, dq), "response packet rejected");
  memcpy(bad, q, n); bad[5] = 2; CHECK(!dnsParseQuestion(bad, n, dq), "QDCOUNT=2 rejected");
  memcpy(bad, q, n); bad[12] = 0xC0; CHECK(!dnsParseQuestion(bad, n, dq), "compression pointer rejected");
  memcpy(bad, q, n); bad[2] |= 0x10; CHECK(!dnsParseQuestion(bad, n, dq), "non-QUERY opcode rejected");
  CHECK(!dnsParseQuestion(q, 10, dq) && !dnsParseQuestion(q, n - 3, dq), "truncated rejected");
}

// ------------------------------------------------------------------ UDP integration
struct FakeUpstream {
  int fd = -1;
  uint16_t port = 0;
  int delayMs;
  std::atomic<bool> stop;
  std::atomic<int> received;
  std::thread th;
  struct Item { uint64_t due; std::vector<uint8_t> pkt; sockaddr_in to; };

  FakeUpstream(const char* ip, uint16_t bindPort, int delay) : delayMs(delay), stop(false), received(0) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = inet_addr(ip); a.sin_port = htons(bindPort);
    if (bind(fd, (sockaddr*)&a, sizeof(a)) != 0) { perror("bind upstream"); exit(2); }
    socklen_t l = sizeof(a); getsockname(fd, (sockaddr*)&a, &l); port = ntohs(a.sin_port);
    th = std::thread([this] { run(); });
  }
  ~FakeUpstream() { stop = true; th.join(); close(fd); }

  void run() {
    std::vector<Item> q;
    while (!stop) {
      fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
      timeval tv = {0, 2000};
      if (select(fd + 1, &rf, nullptr, nullptr, &tv) > 0) {
        uint8_t b[1500]; sockaddr_in from; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, b, sizeof(b), 0, (sockaddr*)&from, &fl);
        if (n > 0) { received++; Item it; it.due = nowUs() + (uint64_t)delayMs * 1000; it.pkt.assign(b, b + n); it.to = from; q.push_back(it); }
      }
      uint64_t now = nowUs();
      for (size_t i = 0; i < q.size();) {
        if (q[i].due <= now) {
          q[i].pkt[2] |= 0x80;                       // QR=1  (echo as a "response")
          q[i].pkt[7] = 1;                           // pretend ANCOUNT=1 so tests can tell it came from here
          sendto(fd, q[i].pkt.data(), q[i].pkt.size(), 0, (sockaddr*)&q[i].to, sizeof(q[i].to));
          q.erase(q.begin() + (long)i);
        } else i++;
      }
    }
  }
};

struct ServerRunner {
  DnsServer srv;
  std::thread th;
  std::atomic<bool> stop;
  std::atomic<int> peak;
  uint16_t port;
  ServerRunner(Matcher& m, uint32_t up1, uint32_t up2, uint16_t upPort, uint32_t timeoutMs)
      : srv(m, rng32), stop(false), peak(0), port(0) {
    srv.setUpstreamPort(upPort);
    srv.setTimeoutMs(timeoutMs);
    for (uint16_t p = 35300; p < 35400; p++) {   // find a free port
      if (srv.begin(p, up1, up2)) { port = p; break; }
    }
    if (!port) { printf("no free port\n"); exit(2); }
    th = std::thread([this] { while (!stop) { srv.step(5); int p = srv.pending(); if (p > peak) peak = p; } });
  }
  ~ServerRunner() { stop = true; th.join(); }
};

struct Client {
  int fd;
  sockaddr_in to;
  explicit Client(uint16_t port) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&to, 0, sizeof(to)); to.sin_family = AF_INET; to.sin_addr.s_addr = inet_addr("127.0.0.1"); to.sin_port = htons(port);
  }
  ~Client() { close(fd); }
  void send(const uint8_t* p, size_t n) { sendto(fd, p, n, 0, (sockaddr*)&to, sizeof(to)); }
  int recv(uint8_t* b, size_t cap, int ms) {
    fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
    timeval tv = {ms / 1000, (ms % 1000) * 1000};
    if (select(fd + 1, &rf, nullptr, nullptr, &tv) <= 0) return -1;
    return (int)recvfrom(fd, b, cap, 0, nullptr, nullptr);
  }
};

static std::vector<uint8_t> g_smallFile;
static MemStore g_store;
static Matcher g_matcher;

static void testServerConcurrency() {
  printf("[dns server: 32 concurrent upstream queries]\n");
  FakeUpstream up("127.0.0.1", 0, 250);   // every reply takes 250 ms
  ServerRunner sr(g_matcher, inet_addr("127.0.0.1"), 0, up.port, 2000);
  Client c(sr.port);
  uint8_t q[512];
  uint64_t t0 = nowUs();
  for (int i = 0; i < 32; i++) {
    char nm[64]; snprintf(nm, sizeof(nm), "host%d.concurrent.test", i);
    size_t n = buildQuery(q, (uint16_t)(0x1000 + i), nm, 1, false);
    c.send(q, n);
  }
  bool seen[32] = {false};
  int got = 0;
  uint8_t r[1500];
  for (int k = 0; k < 32; k++) {
    int n = c.recv(r, sizeof(r), 1500);
    if (n < 12) break;
    int id = (r[0] << 8) | r[1];
    if (id >= 0x1000 && id < 0x1020 && !seen[id - 0x1000] && (r[2] & 0x80) && r[7] == 1) { seen[id - 0x1000] = true; got++; }
  }
  double ms = (nowUs() - t0) / 1000.0;
  printf("  32 queries x 250 ms upstream latency finished in %.0f ms (sequential would take 8000 ms); peak in flight: %d\n", ms, (int)sr.peak);
  CHECK(got == 32, "got %d/32 replies with the correct client IDs", got);
  CHECK(ms < 1000, "took %.0f ms - not concurrent", ms);
  CHECK(sr.peak >= 30, "peak pending %d", (int)sr.peak);
  CHECK(up.received == 32, "upstream saw %d", up.received.load());
  DnsStats s = sr.srv.stats();
  CHECK(s.forwarded == 32 && s.answered == 32 && s.timeouts == 0, "stats fwd=%u ans=%u to=%u", s.forwarded, s.answered, s.timeouts);
  CHECK(sr.srv.pending() == 0, "all slots released");
}

static void testServerBlocking() {
  printf("[dns server: blocking without touching upstream]\n");
  FakeUpstream up("127.0.0.1", 0, 10);
  ServerRunner sr(g_matcher, inet_addr("127.0.0.1"), 0, up.port, 1000);
  Client c(sr.port);
  uint8_t q[512], r[1500];
  size_t n = buildQuery(q, 0x2222, "Metrics.Ads.Tracker.IO", 1, true);
  c.send(q, n);
  int rn = c.recv(r, sizeof(r), 500);
  CHECK(rn > 12 && r[0] == 0x22 && r[1] == 0x22 && (r[2] & 0x80), "blocked reply received");
  CHECK(rn > 4 && memcmp(r + rn - 4, "\0\0\0\0", 4) == 0, "answer is 0.0.0.0");
  n = buildQuery(q, 0x3333, "tracker.io", 1, false);   // parent of a listed name: NOT blocked
  c.send(q, n);
  rn = c.recv(r, sizeof(r), 500);
  CHECK(rn > 0 && r[0] == 0x33 && r[7] == 1, "unlisted parent forwarded and answered by upstream");
  DnsStats s = sr.srv.stats();
  CHECK(s.blocked == 1 && s.forwarded == 1, "blocked=%u forwarded=%u", s.blocked, s.forwarded);
  CHECK(up.received == 1, "upstream only saw the non-blocked query (saw %d)", up.received.load());
  char recent[DnsServer::kRecent][DnsServer::kRecentLen];
  size_t rc = sr.srv.recentBlocked(recent, DnsServer::kRecent);
  CHECK(rc == 1 && !strcmp(recent[0], "metrics.ads.tracker.io"), "recent list");
  n = buildQuery(q, 0x7777, "a\"b<script>.ads.tracker.io", 1, false);   // hostile label bytes
  c.send(q, n);
  rn = c.recv(r, sizeof(r), 500);
  rc = sr.srv.recentBlocked(recent, DnsServer::kRecent);
  CHECK(rc == 2 && !strchr(recent[0], '"') && !strchr(recent[0], '<') && !strchr(recent[0], '>'), "hostile name sanitised: %s", recent[0]);
  ClientStat cs[4];
  size_t nc = sr.srv.clients(cs, 4);
  CHECK(nc == 1 && cs[0].total == 3 && cs[0].blocked == 2, "client stats total=%u blocked=%u", cs[0].total, cs[0].blocked);
}

static void testServerRetryTimeoutOverflow() {
  printf("[dns server: secondary retry, timeout, overflow]\n");
  {
    FakeUpstream up2("127.0.0.2", 0, 5);                     // secondary is alive
    ServerRunner sr(g_matcher, inet_addr("127.0.0.1"), inet_addr("127.0.0.2"), up2.port, 150);  // primary: nothing listens
    Client c(sr.port);
    uint8_t q[512], r[1500];
    size_t n = buildQuery(q, 0x4444, "retry.example-test.org", 1, false);
    c.send(q, n);
    int rn = c.recv(r, sizeof(r), 1500);
    CHECK(rn > 0 && r[0] == 0x44 && r[1] == 0x44 && r[7] == 1, "answer arrived via secondary");
    CHECK(sr.srv.stats().retried == 1 && sr.srv.stats().timeouts == 0, "retried=%u", sr.srv.stats().retried);
  }
  {
    FakeUpstream dead("127.0.0.1", 0, 5);
    uint16_t p = dead.port;
    ServerRunner sr(g_matcher, inet_addr("127.0.0.3"), inet_addr("127.0.0.4"), p, 100);  // both upstreams dead
    Client c(sr.port);
    uint8_t q[512];
    size_t n = buildQuery(q, 0x5555, "nobody.example-test.org", 1, false);
    c.send(q, n);
    std::this_thread::sleep_for(std::chrono::milliseconds(450));
    DnsStats s = sr.srv.stats();
    CHECK(s.timeouts == 1 && s.retried == 1 && sr.srv.pending() == 0, "timeouts=%u retried=%u pending=%d", s.timeouts, s.retried, sr.srv.pending());
  }
  {
    FakeUpstream silent("127.0.0.1", 0, 60000);              // never answers within the test
    ServerRunner sr(g_matcher, inet_addr("127.0.0.1"), 0, silent.port, 30000);
    Client c(sr.port);
    uint8_t q[512];
    for (int i = 0; i < 40; i++) {
      char nm[48]; snprintf(nm, sizeof(nm), "o%d.overflow.test", i);
      c.send(q, buildQuery(q, (uint16_t)(0x6000 + i), nm, 1, false));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DnsStats s = sr.srv.stats();
    CHECK(s.forwarded == 40 && s.overflow == 8 && sr.srv.pending() == 32, "fwd=%u overflow=%u pending=%d", s.forwarded, s.overflow, sr.srv.pending());
  }
  {
    FakeUpstream up("127.0.0.1", 0, 5);
    ServerRunner sr(g_matcher, inet_addr("127.0.0.1"), 0, up.port, 500);
    Client c(sr.port);
    uint8_t junk[7] = {1, 2, 3, 4, 5, 6, 7};
    c.send(junk, sizeof(junk));
    uint8_t r[64];
    CHECK(c.recv(r, sizeof(r), 200) < 0, "short garbage is dropped silently");
    CHECK(sr.srv.stats().malformed == 1, "malformed counted");
  }
}

int main() {
  testSha();
  testHash();
  testMatcherSmall();
  testMatcherBig();
  testConfig();
  testDnsPacket();
  g_smallFile = readFile(W + "small.bin");
  BlInfo bi; blParseHeader(g_smallFile.data(), g_smallFile.size(), bi);
  g_store.set(g_smallFile.data() + BL_HEADER_SIZE, bi.count);
  g_matcher.load(&g_store, 4096);
  testServerConcurrency();
  testServerBlocking();
  testServerRetryTimeoutOverflow();
  printf("\n%d checks passed, %d failed\n", g_pass, g_fail);
  return g_fail ? 1 : 0;
}
