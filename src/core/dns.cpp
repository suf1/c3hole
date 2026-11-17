#include "dns.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <chrono>

#ifdef ARDUINO
#include <lwip/sockets.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

namespace c3 {

static inline uint16_t be16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void putBe16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline uint32_t be32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static inline void putBe32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

bool dnsParseQuestion(const uint8_t* pkt, size_t len, DnsQuestion& q) {
  if (len < 12 + 5) return false;
  uint8_t flags1 = pkt[2];
  if (flags1 & 0x80) return false;               // QR must be 0 (query)
  if (((flags1 >> 3) & 0x0F) != 0) return false; // opcode must be QUERY
  if (be16(pkt + 4) != 1) return false;          // exactly one question
  size_t pos = 12, n = 0;
  for (;;) {
    if (pos >= len) return false;
    uint8_t l = pkt[pos++];
    if (l == 0) break;
    if (l & 0xC0) return false;                  // no compression in a question
    if (pos + l > len) return false;
    if (n + l + 1 >= sizeof(q.name)) return false;
    if (n) q.name[n++] = '.';
    for (uint8_t i = 0; i < l; i++) {
      char c = (char)pkt[pos + i];
      if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
      q.name[n++] = c;
    }
    pos += l;
  }
  if (pos + 4 > len) return false;
  q.name[n] = 0;
  q.nameLen = (uint16_t)n;
  q.qtype = be16(pkt + pos);
  q.qclass = be16(pkt + pos + 2);
  q.qend = (uint16_t)(pos + 4);
  return n > 0;
}

size_t dnsBuildBlockedReply(const uint8_t* query, size_t qlen, const DnsQuestion& q, uint8_t* out, size_t cap) {
  (void)qlen;
  size_t need = q.qend + 16 + 12;
  if (cap < need) return 0;
  memcpy(out, query, q.qend);                       // header + question
  out[2] = (uint8_t)(0x80 | (query[2] & 0x01));     // QR=1, keep RD
  out[3] = 0x80;                                    // RA=1, RCODE=0
  putBe16(out + 6, 0);                              // ANCOUNT (set below)
  putBe16(out + 8, 0);                              // NSCOUNT
  putBe16(out + 10, 0);                             // ARCOUNT (drop EDNS OPT)
  size_t pos = q.qend;
  uint16_t an = 0;
  if (q.qclass == 1 && (q.qtype == 1 || q.qtype == 28)) {
    uint16_t rl = (q.qtype == 1) ? 4 : 16;
    out[pos++] = 0xC0; out[pos++] = 0x0C;           // name pointer to question
    putBe16(out + pos, q.qtype); pos += 2;
    putBe16(out + pos, 1); pos += 2;                // class IN
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 60;  // TTL 60 s
    putBe16(out + pos, rl); pos += 2;
    memset(out + pos, 0, rl); pos += rl;
    an = 1;
  }
  putBe16(out + 6, an);
  return pos;
}

// Decodes a (possibly compressed) name at `pos` into lower-case dotted text (out may be null).
// Returns the offset just past the name as stored at `pos`, or 0 on any malformation.
static size_t readName(const uint8_t* p, size_t len, size_t pos, char* out, size_t cap) {
  size_t n = 0, end = 0;
  int jumps = 0;
  for (;;) {
    if (pos >= len) return 0;
    uint8_t l = p[pos];
    if (l == 0) { if (!end) end = pos + 1; break; }
    if ((l & 0xC0) == 0xC0) {
      if (pos + 1 >= len) return 0;
      if (!end) end = pos + 2;
      if (++jumps > 8) return 0;                       // pointer loops
      size_t ptr = ((size_t)(l & 0x3F) << 8) | p[pos + 1];
      if (ptr >= len) return 0;
      pos = ptr;
      continue;
    }
    if (l & 0xC0) return 0;
    if (pos + 1 + l > len) return 0;
    if (out) {
      if (n + l + 2 > cap) return 0;
      if (n) out[n++] = '.';
      for (uint8_t i = 0; i < l; i++) {
        char c = (char)p[pos + 1 + i];
        out[n++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
      }
    }
    pos += 1 + l;
  }
  if (out) out[n] = 0;
  return end;
}

bool dnsCnameTargetBlocked(const uint8_t* p, size_t len, Matcher& m) {
  if (len < 12 || (p[3] & 0x0F) != 0) return false;
  uint16_t qd = be16(p + 4), an = be16(p + 6);
  if (an == 0 || qd > 4) return false;
  size_t pos = 12;
  for (uint16_t i = 0; i < qd; i++) {
    pos = readName(p, len, pos, nullptr, 0);
    if (!pos || pos + 4 > len) return false;
    pos += 4;
  }
  char name[254];
  for (uint16_t i = 0; i < an && i < 24; i++) {
    pos = readName(p, len, pos, nullptr, 0);
    if (!pos || pos + 10 > len) return false;
    uint16_t type = be16(p + pos), cls = be16(p + pos + 2), rdl = be16(p + pos + 8);
    pos += 10;
    if (pos + rdl > len) return false;
    if (type == 5 && cls == 1 && readName(p, len, pos, name, sizeof(name)) && name[0] && m.isBlocked(name, strlen(name)))
      return true;
    pos += rdl;
  }
  return false;
}

bool dnsIsDohCanary(const char* name) {
  return !strcmp(name, "use-application-dns.net") ||   // Firefox
         !strcmp(name, "mask.icloud.com") ||           // Apple iCloud Private Relay
         !strcmp(name, "mask-h2.icloud.com");
}

size_t dnsBuildNxdomain(const uint8_t* query, const DnsQuestion& q, uint8_t* out, size_t cap) {
  if (cap < q.qend) return 0;
  memcpy(out, query, q.qend);
  out[2] = (uint8_t)(0x80 | (query[2] & 0x01));      // QR=1, keep RD
  out[3] = 0x83;                                     // RA=1, RCODE=3 (NXDOMAIN)
  putBe16(out + 6, 0);
  putBe16(out + 8, 0);
  putBe16(out + 10, 0);
  return q.qend;
}

struct RrScan {
  uint32_t minTtl;
  size_t endAuth;
  size_t ttlPos[32];
  int nTtl;
  uint16_t an, ns;
};

// Walks the answer + authority records of a single-question message.
static bool scanRecords(const uint8_t* p, size_t len, RrScan& r) {
  if (len < 12 || be16(p + 4) != 1) return false;
  uint16_t an = be16(p + 6), ns = be16(p + 8);
  if ((uint32_t)an + ns > 32) return false;
  size_t pos = readName(p, len, 12, nullptr, 0);
  if (!pos || pos + 4 > len) return false;
  pos += 4;
  r.minTtl = 0xFFFFFFFFu; r.nTtl = 0; r.an = an; r.ns = ns;
  for (uint32_t i = 0; i < (uint32_t)an + ns; i++) {
    pos = readName(p, len, pos, nullptr, 0);
    if (!pos || pos + 10 > len) return false;
    uint16_t type = be16(p + pos), rdl = be16(p + pos + 8);
    uint32_t ttl = be32(p + pos + 4);
    if (pos + 10 + rdl > len) return false;
    if (type != 41) { if (ttl < r.minTtl) r.minTtl = ttl; r.ttlPos[r.nTtl++] = pos + 4; }
    pos += 10 + rdl;
  }
  r.endAuth = pos;
  return true;
}

// Copies a reply for caching: no additional section (so no OPT), TC clear, NOERROR/NXDOMAIN only.
static size_t dnsMakeCacheable(const uint8_t* reply, size_t len, uint8_t* out, size_t cap, uint32_t& ttl) {
  if (len < 12 || !(reply[2] & 0x80) || (reply[2] & 0x02) || ((reply[2] >> 3) & 0x0F) != 0) return 0;
  uint8_t rc = reply[3] & 0x0F;
  if (rc != 0 && rc != 3) return 0;
  RrScan r;
  if (!scanRecords(reply, len, r) || r.endAuth > cap) return 0;
  memcpy(out, reply, r.endAuth);
  putBe16(out + 10, 0);                                   // ARCOUNT = 0
  ttl = r.nTtl ? r.minTtl : 30;
  return r.endAuth;
}

static void dnsPatchTtls(uint8_t* p, size_t len, uint32_t ttl) {
  RrScan r;
  if (!scanRecords(p, len, r)) return;
  for (int i = 0; i < r.nTtl; i++) putBe32(p + r.ttlPos[i], ttl);
}

// True if the query carries an EDNS OPT record with the DNSSEC-OK bit (such answers are never cached).
static bool queryWantsDnssec(const uint8_t* p, size_t len, size_t qend) {
  if (len < 12 || be16(p + 10) == 0) return false;
  size_t pos = qend;
  uint32_t total = (uint32_t)be16(p + 6) + be16(p + 8) + be16(p + 10);
  for (uint32_t i = 0; i < total && i < 16; i++) {
    pos = readName(p, len, pos, nullptr, 0);
    if (!pos || pos + 10 > len) return false;
    if (be16(p + pos) == 41 && (be16(p + pos + 6) & 0x8000)) return true;
    pos += 10 + be16(p + pos + 8);
  }
  return false;
}

static uint64_t cacheKeyFor(const DnsQuestion& q) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (uint16_t i = 0; i < q.nameLen; i++) { h ^= (uint8_t)q.name[i]; h *= 0x100000001b3ULL; }
  h ^= ((uint64_t)q.qtype << 32) | ((uint64_t)q.qclass << 16) | 1u;
  h *= 0x100000001b3ULL;
  return h;
}

static inline uint8_t lc(uint8_t c) { return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c; }

uint32_t DnsServer::nowMs() {
  return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}

DnsServer::DnsServer(Matcher& matcher, uint32_t (*rng)())
    : matcher_(matcher), rng_(rng), srv_(-1), up_(-1), up1_(0), up2_(0), timeoutMs_(1500), up1Port_(53), up2Port_(53), parallel_(false),
      tcp_(-1), probeMs_(0), lastProbeMs_(0), lastOkMs_(0), cMin_(20), cMax_(600), cStale_(600), cacheBytes_(0),
      recentHead_(0), recentCount_(0) {
  lastRead_ = false;
  memset(cache_, 0, sizeof(cache_));
  memset(slots_, 0, sizeof(slots_));
  memset(recent_, 0, sizeof(recent_));
  memset(clients_, 0, sizeof(clients_));
}

DnsServer::~DnsServer() { end(); }

static bool setNonBlocking(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  return fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

bool DnsServer::begin(uint16_t port, uint32_t up1, uint32_t up2) {
  end();
  up1_ = up1;
  up2_ = up2;
  srv_ = socket(AF_INET, SOCK_DGRAM, 0);
  up_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (srv_ < 0 || up_ < 0) { end(); return false; }
  int one = 1;
  setsockopt(srv_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  a.sin_port = htons(port);
  if (bind(srv_, (sockaddr*)&a, sizeof(a)) != 0) { end(); return false; }
  sockaddr_in b;
  memset(&b, 0, sizeof(b));
  b.sin_family = AF_INET;
  b.sin_addr.s_addr = htonl(INADDR_ANY);
  b.sin_port = 0;
  if (bind(up_, (sockaddr*)&b, sizeof(b)) != 0) { end(); return false; }
  if (!setNonBlocking(srv_) || !setNonBlocking(up_)) { end(); return false; }
  lastOkMs_ = nowMs();
  lastProbeMs_ = lastOkMs_;
  return true;
}

void DnsServer::end() {
  if (srv_ >= 0) close(srv_);
  if (up_ >= 0) close(up_);
  if (tcp_ >= 0) close(tcp_);
  srv_ = up_ = tcp_ = -1;
  memset(slots_, 0, sizeof(slots_));
  cacheClear();
}

void DnsServer::cacheClear() {
  std::lock_guard<std::mutex> g(cacheMu_);
  for (int i = 0; i < kCache; i++) { free(cache_[i].data); cache_[i].data = nullptr; }
  cacheBytes_ = 0;
}

void DnsServer::sendTo(int fd, const uint8_t* p, size_t n, uint32_t ip, uint16_t port) {
  sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = ip;
  to.sin_port = port;               // already in network byte order (as received)
  sendto(fd, p, n, 0, (sockaddr*)&to, sizeof(to));
}

void DnsServer::noteRtt(uint32_t rtt) {
  if (rtt > 400) st_.slow++;
  if (rtt > st_.rttMax) st_.rttMax = rtt;
  st_.rttAvg = st_.rttAvg ? (st_.rttAvg * 7 + rtt) / 8 : rtt;
}

void DnsServer::setUpstreams(uint32_t up1, uint32_t up2) { up1_ = up1; up2_ = up2; }

void DnsServer::setUpstreamEndpoints(uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2) {
  up1_ = ip1; up1Port_ = port1 ? port1 : 53;
  up2_ = ip2; up2Port_ = port2 ? port2 : 53;
}

int DnsServer::pending() const {
  int n = 0;
  for (int i = 0; i < kSlots; i++) n += slots_[i].used ? 1 : 0;
  return n;
}

void DnsServer::step(int waitMs) {
  if (srv_ < 0) return;
  fd_set rf;
  FD_ZERO(&rf);
  FD_SET(srv_, &rf);
  FD_SET(up_, &rf);
  int maxfd = (srv_ > up_ ? srv_ : up_) + 1;
  timeval tv;
  tv.tv_sec = waitMs / 1000;
  tv.tv_usec = (waitMs % 1000) * 1000;
  int r = select(maxfd, &rf, nullptr, nullptr, &tv);
  if (r > 0) {
    if (FD_ISSET(up_, &rf))
      for (int i = 0; i < 32; i++) { onUpstream(); if (!lastRead_) break; }
    if (FD_ISSET(srv_, &rf))
      for (int i = 0; i < 32; i++) { onClient(); if (!lastRead_) break; }
  }
  sweep();
  if (probeMs_ && nowMs() - lastProbeMs_ >= probeMs_) { lastProbeMs_ = nowMs(); sendProbe(); }
}

void DnsServer::noteBlocked(const char* name) {
  std::lock_guard<std::mutex> g(mu_);
  // Names come from network clients: keep only hostname characters so the
  // dashboard can never be fed markup or JSON-breaking bytes.
  char* dst = recent_[recentHead_];
  size_t i = 0;
  for (; name[i] && i < kRecentLen - 1; i++) {
    char c = name[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
    dst[i] = ok ? c : '?';
  }
  dst[i] = 0;
  recentHead_ = (uint8_t)((recentHead_ + 1) % kRecent);
  if (recentCount_ < kRecent) recentCount_++;
}

void DnsServer::noteClient(uint32_t ip, bool blocked) {
  std::lock_guard<std::mutex> g(mu_);
  int idx = -1, minIdx = 0;
  for (int i = 0; i < kClients; i++) {
    if (clients_[i].ip == ip) { idx = i; break; }
    if (clients_[i].total < clients_[minIdx].total) minIdx = i;
  }
  if (idx < 0) {
    idx = minIdx;
    clients_[idx].ip = ip;
    clients_[idx].total = 0;
    clients_[idx].blocked = 0;
  }
  clients_[idx].total++;
  if (blocked) clients_[idx].blocked++;
}

size_t DnsServer::recentBlocked(char out[][kRecentLen], size_t max) const {
  std::lock_guard<std::mutex> g(mu_);
  size_t n = recentCount_ < max ? recentCount_ : max;
  for (size_t i = 0; i < n; i++) {
    int idx = ((int)recentHead_ - 1 - (int)i + 2 * kRecent) % kRecent;  // newest first
    memcpy(out[i], recent_[idx], kRecentLen);
  }
  return n;
}

void DnsServer::markClientBlocked(uint32_t ip) {
  std::lock_guard<std::mutex> g(mu_);
  for (int i = 0; i < kClients; i++)
    if (clients_[i].ip == ip) { clients_[i].blocked++; return; }
}

size_t DnsServer::clients(ClientStat* out, size_t max) const {
  std::lock_guard<std::mutex> g(mu_);
  size_t n = 0;
  for (int i = 0; i < kClients && n < max; i++)
    if (clients_[i].total) out[n++] = clients_[i];
  for (size_t i = 0; i < n; i++)           // sort by total, descending
    for (size_t j = i + 1; j < n; j++)
      if (out[j].total > out[i].total) { ClientStat t = out[i]; out[i] = out[j]; out[j] = t; }
  return n;
}

void DnsServer::onClient() {
  sockaddr_in from;
  socklen_t fl = sizeof(from);
  ssize_t n = recvfrom(srv_, buf_, sizeof(buf_), 0, (sockaddr*)&from, &fl);
  lastRead_ = n > 0;
  if (n <= 0) return;
  st_.total++;
  uint32_t ip = from.sin_addr.s_addr;
  uint16_t port = from.sin_port;
  DnsQuestion q;
  if (!dnsParseQuestion(buf_, (size_t)n, q)) {
    if (n < 12) { st_.malformed++; return; }
    noteClient(ip, false);
    forward(buf_, (size_t)n, ip, port);
    return;
  }
  if (q.qclass == 1 && dnsIsDohCanary(q.name)) {     // tell browsers/OSes not to bypass us with encrypted DNS
    size_t rn = dnsBuildNxdomain(buf_, q, out_, sizeof(out_));
    if (rn) {
      sockaddr_in to;
      memset(&to, 0, sizeof(to));
      to.sin_family = AF_INET;
      to.sin_addr.s_addr = ip;
      to.sin_port = port;
      noteClient(ip, false);
      st_.canary++;
      sendto(srv_, out_, rn, 0, (sockaddr*)&to, sizeof(to));
      return;
    }
  }
  bool blocked = q.qclass == 1 && matcher_.isBlocked(q.name, q.nameLen);
  noteClient(ip, blocked);
  if (blocked) {
    size_t rn = dnsBuildBlockedReply(buf_, (size_t)n, q, out_, sizeof(out_));
    if (rn) {
      sockaddr_in to;
      memset(&to, 0, sizeof(to));
      to.sin_family = AF_INET;
      to.sin_addr.s_addr = ip;
      to.sin_port = port;
      st_.blocked++;                 // record first: a client that gets the reply may read the stats at once
      noteBlocked(q.name);
      sendto(srv_, out_, rn, 0, (sockaddr*)&to, sizeof(to));
      return;
    }
  }
  if (q.qclass == 1 && !queryWantsDnssec(buf_, (size_t)n, q.qend)) {
    size_t cl = 0;
    if (cacheGet(q, buf_, false, out_, sizeof(out_), cl)) {
      st_.cacheHits++;
      if (matcher_.ready() && dnsCnameTargetBlocked(out_, cl, matcher_)) {      // list may have changed since caching
        size_t rn = dnsBuildBlockedReply(buf_, (size_t)n, q, out_, sizeof(out_));
        if (rn) {
          st_.blocked++; st_.cnameBlocked++;
          noteBlocked(q.name);
          markClientBlocked(ip);
          sendTo(srv_, out_, rn, ip, port);
          return;
        }
      }
      sendTo(srv_, out_, cl, ip, port);
      return;
    }
    st_.cacheMisses++;
  }
  forward(buf_, (size_t)n, ip, port);
}

void DnsServer::forward(uint8_t* pkt, size_t n, uint32_t ip, uint16_t port) {
  if (!up1_) return;
  int slot = -1;
  uint32_t oldest = 0;
  int oldestIdx = 0;
  uint32_t now = nowMs();
  for (int i = 0; i < kSlots; i++) {
    if (!slots_[i].used) { slot = i; break; }
    uint32_t age = now - slots_[i].tsMs;
    if (age >= oldest) { oldest = age; oldestIdx = i; }
  }
  if (slot < 0) { slot = oldestIdx; st_.overflow++; }   // all 32 busy: evict the oldest
  Slot& s = slots_[slot];
  s.used = true;
  s.clientId = be16(pkt);
  s.clientIp = ip;
  s.clientPort = port;
  s.tsMs = now;
  s.firstMs = now;
  s.tries = 0;
  s.upId = (uint16_t)((rng_() & 0xFFE0u) | (uint32_t)slot);
  putBe16(pkt, s.upId);
  if (n <= kStoredQuery) { memcpy(s.q, pkt, n); s.qlen = (uint16_t)n; } else { s.qlen = 0; }
  sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = up1_;
  to.sin_port = htons(up1Port_);
  sendto(up_, pkt, n, 0, (sockaddr*)&to, sizeof(to));
  if (parallel_ && up2_) {                                  // ask the secondary at the same time
    to.sin_addr.s_addr = up2_;
    to.sin_port = htons(up2Port_);
    sendto(up_, pkt, n, 0, (sockaddr*)&to, sizeof(to));
  }
  st_.forwarded++;
}

void DnsServer::onUpstream() {
  sockaddr_in from;
  socklen_t fl = sizeof(from);
  ssize_t n = recvfrom(up_, buf_, sizeof(buf_), 0, (sockaddr*)&from, &fl);
  lastRead_ = n > 0;
  if (n < 12) return;
  bool fromUp1 = from.sin_addr.s_addr == up1_ && from.sin_port == htons(up1Port_);
  bool fromUp2 = up2_ && from.sin_addr.s_addr == up2_ && from.sin_port == htons(up2Port_);
  if (!fromUp1 && !fromUp2) return;                                           // not from our upstreams
  uint16_t id = be16(buf_);
  Slot& s = slots_[id & (kSlots - 1)];
  if (!s.used || s.upId != id) return;                                        // stale or spoofed
  uint32_t now = nowMs();
  lastOkMs_ = now;
  noteRtt(now - s.firstMs);
  if (s.clientIp == 0) { s.used = false; st_.probeOk++; return; }             // heartbeat reply
  if (buf_[2] & 0x02) st_.truncated++;
  DnsQuestion cq;
  bool haveQ = s.qlen && dnsParseQuestion(s.q, s.qlen, cq) && cq.qclass == 1;
  if (haveQ && !queryWantsDnssec(s.q, s.qlen, cq.qend)) cachePut(cq, s.q, buf_, (size_t)n);
  if (haveQ && matcher_.ready() && dnsCnameTargetBlocked(buf_, (size_t)n, matcher_)) {
    // CNAME-cloaked tracker: the name looked harmless but resolves through a blocked domain.
    size_t rn = dnsBuildBlockedReply(s.q, s.qlen, cq, out_, sizeof(out_));
    if (rn) {
      putBe16(out_, s.clientId);
      sockaddr_in cto;
      memset(&cto, 0, sizeof(cto));
      cto.sin_family = AF_INET;
      cto.sin_addr.s_addr = s.clientIp;
      cto.sin_port = s.clientPort;
      uint32_t cip = s.clientIp;
      s.used = false;
      st_.answered++;
      st_.blocked++;
      st_.cnameBlocked++;
      noteBlocked(cq.name);
      markClientBlocked(cip);
      sendto(srv_, out_, rn, 0, (sockaddr*)&cto, sizeof(cto));
      return;
    }
  }
  putBe16(buf_, s.clientId);
  sockaddr_in to;
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = s.clientIp;
  to.sin_port = s.clientPort;
  s.used = false;                // release the slot and count first: the client may read the stats the moment it gets the reply
  st_.answered++;
  sendto(srv_, buf_, (size_t)n, 0, (sockaddr*)&to, sizeof(to));
}

void DnsServer::sweep() {
  uint32_t now = nowMs();
  for (int i = 0; i < kSlots; i++) {
    Slot& s = slots_[i];
    if (!s.used || (now - s.tsMs) < timeoutMs_) continue;
    if (s.tries == 0 && s.qlen) {            // first silence: resend once (UDP gets lost), possibly to the other server
      if (parallel_ || !up2_) sendTo(up_, s.q, s.qlen, up1_, htons(up1Port_));
      if (up2_) sendTo(up_, s.q, s.qlen, up2_, htons(up2Port_));
      s.tries = 1;
      s.tsMs = now;
      st_.retried++;
      continue;
    }
    bool probe = s.clientIp == 0;
    s.used = false;
    if (probe) { st_.probeFail++; continue; }
    DnsQuestion q;
    size_t cl = 0;
    if (s.qlen && dnsParseQuestion(s.q, s.qlen, q) && cacheGet(q, s.q, true, out_, sizeof(out_), cl)) {
      putBe16(out_, s.clientId);              // upstream failed but we remember an answer: better stale than nothing
      if (matcher_.ready() && dnsCnameTargetBlocked(out_, cl, matcher_)) {
        size_t rn = dnsBuildBlockedReply(s.q, s.qlen, q, out_, sizeof(out_));
        if (rn) { putBe16(out_, s.clientId); cl = rn; st_.blocked++; st_.cnameBlocked++; }
      }
      st_.staleServed++;
      st_.answered++;
      sendTo(srv_, out_, cl, s.clientIp, s.clientPort);
      continue;
    }
    st_.timeouts++;
  }
}

void DnsServer::sendProbe() {
  if (!up1_) return;
  int slot = -1;
  for (int i = 0; i < kSlots; i++) if (!slots_[i].used) { slot = i; break; }
  if (slot < 0) return;                                   // busy: real queries are proof enough
  uint8_t pkt[17] = {0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0 /*root*/, 0, 2 /*NS*/, 0, 1 /*IN*/};
  Slot& s = slots_[slot];
  memset(&s, 0, sizeof(s));
  s.used = true;
  s.clientIp = 0;                                         // marks an internal probe
  s.tsMs = s.firstMs = nowMs();
  s.tries = 1;                                            // no resend: a probe either answers or counts as a failure
  s.upId = (uint16_t)((rng_() & 0xFFE0u) | (uint32_t)slot);
  putBe16(pkt, s.upId);
  sendTo(up_, pkt, sizeof(pkt), up1_, htons(up1Port_));
  if (parallel_ && up2_) sendTo(up_, pkt, sizeof(pkt), up2_, htons(up2Port_));
}

// ------------------------------------------------------------------ cache
bool DnsServer::cacheGet(const DnsQuestion& q, const uint8_t* query, bool stale, uint8_t* out, size_t cap, size_t& len) {
  std::lock_guard<std::mutex> g(cacheMu_);
  uint64_t key = cacheKeyFor(q);
  uint32_t now = nowMs();
  size_t ql = q.qend - 12;
  for (int i = 0; i < kCache; i++) {
    CacheEntry& e = cache_[i];
    if (!e.data || e.key != key || e.len < 12 + ql || e.len > cap) continue;
    bool same = true;
    for (size_t k = 0; k < ql; k++) if (lc(e.data[12 + k]) != lc(query[12 + k])) { same = false; break; }
    if (!same) continue;
    uint32_t age = now - e.storedMs;
    bool fresh = age < e.ttlMs;
    if (!fresh && !(stale && age < e.ttlMs + cStale_ * 1000UL)) continue;
    memcpy(out, e.data, e.len);
    putBe16(out, be16(query));
    out[2] = (uint8_t)((out[2] & 0xFE) | (query[2] & 0x01) | 0x80);
    uint32_t remain = fresh ? (e.ttlMs - age) / 1000 : 30;
    dnsPatchTtls(out, e.len, remain < 1 ? 1 : remain);
    e.lastUse = now;
    len = e.len;
    return true;
  }
  return false;
}

void DnsServer::cachePut(const DnsQuestion& q, const uint8_t* query, const uint8_t* reply, size_t rlen) {
  uint8_t tmp[kCacheMaxEntry];
  uint32_t ttl = 0;
  size_t n = dnsMakeCacheable(reply, rlen, tmp, sizeof(tmp), ttl);
  size_t ql = q.qend - 12;
  if (!n || n < 12 + ql) return;
  for (size_t k = 0; k < ql; k++) if (lc(tmp[12 + k]) != lc(query[12 + k])) return;   // reply must echo our question
  if (ttl < cMin_) ttl = cMin_;
  if (ttl > cMax_) ttl = cMax_;
  uint8_t* copy = (uint8_t*)malloc(n);
  if (!copy) return;
  memcpy(copy, tmp, n);
  uint64_t key = cacheKeyFor(q);
  uint32_t now = nowMs();
  std::lock_guard<std::mutex> g(cacheMu_);
  int slot = -1;
  for (int i = 0; i < kCache; i++)                          // same question: replace
    if (cache_[i].data && cache_[i].key == key) { slot = i; break; }
  if (slot >= 0) { cacheBytes_ -= cache_[slot].len; free(cache_[slot].data); cache_[slot].data = nullptr; }
  for (;;) {                                                // make room: free slot first, else least recently used
    if (slot < 0) for (int i = 0; i < kCache; i++) if (!cache_[i].data) { slot = i; break; }
    if (slot >= 0 && cacheBytes_ + n <= (uint32_t)kCacheBytes) break;
    int lru = -1;
    for (int i = 0; i < kCache; i++)
      if (cache_[i].data && (lru < 0 || (now - cache_[i].lastUse) > (now - cache_[lru].lastUse))) lru = i;
    if (lru < 0) { free(copy); return; }
    cacheBytes_ -= cache_[lru].len; free(cache_[lru].data); cache_[lru].data = nullptr;
    if (slot < 0) slot = lru;
  }
  CacheEntry& e = cache_[slot];
  e.key = key; e.storedMs = now; e.ttlMs = ttl * 1000UL; e.lastUse = now; e.len = (uint16_t)n; e.data = copy;
  cacheBytes_ += (uint32_t)n;
}

// ------------------------------------------------------------------ TCP
static bool recvAll(int fd, uint8_t* p, size_t n) {
  while (n) {
    ssize_t r = recv(fd, p, n, 0);
    if (r <= 0) return false;
    p += r; n -= (size_t)r;
  }
  return true;
}

static bool sendAll(int fd, const uint8_t* p, size_t n) {
  while (n) {
    ssize_t r = send(fd, p, n, 0);
    if (r <= 0) return false;
    p += r; n -= (size_t)r;
  }
  return true;
}

bool DnsServer::beginTcp(uint16_t port) {
  if (tcp_ >= 0) close(tcp_);
  tcp_ = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_ < 0) return false;
  int one = 1;
  setsockopt(tcp_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  a.sin_port = htons(port);
  if (bind(tcp_, (sockaddr*)&a, sizeof(a)) != 0 || listen(tcp_, 2) != 0) { close(tcp_); tcp_ = -1; return false; }
  return true;
}

void DnsServer::tcpStep(int waitMs) {
  if (tcp_ < 0) return;
  fd_set rf;
  FD_ZERO(&rf);
  FD_SET(tcp_, &rf);
  timeval tv;
  tv.tv_sec = waitMs / 1000;
  tv.tv_usec = (waitMs % 1000) * 1000;
  if (select(tcp_ + 1, &rf, nullptr, nullptr, &tv) <= 0) return;
  sockaddr_in from;
  socklen_t fl = sizeof(from);
  int c = accept(tcp_, (sockaddr*)&from, &fl);
  if (c < 0) return;
  handleTcpConn(c, from.sin_addr.s_addr);
  close(c);
}

void DnsServer::handleTcpConn(int fd, uint32_t clientIp) {
  timeval tv;
  tv.tv_sec = 2; tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  for (int i = 0; i < 8; i++) {                         // a client may pipeline a few queries on one connection
    uint8_t lb[2];
    if (!recvAll(fd, lb, 2)) break;
    size_t ql = ((size_t)lb[0] << 8) | lb[1];
    if (ql < 12 || ql > kTcpBuf - 2 || !recvAll(fd, tcpIn_, ql)) break;
    st_.total++;
    st_.tcpQueries++;
    size_t rl = 0;
    if (!handleTcpQuery(tcpIn_, ql, clientIp, tcpOut_ + 2, kTcpBuf - 2, rl)) break;
    tcpOut_[0] = (uint8_t)(rl >> 8);
    tcpOut_[1] = (uint8_t)rl;
    if (!sendAll(fd, tcpOut_, rl + 2)) break;
  }
}

bool DnsServer::tcpForward(const uint8_t* query, size_t qlen, uint8_t* reply, size_t cap, size_t& rlen) {
  uint32_t ips[2] = {up1_, up2_};
  uint16_t ports[2] = {up1Port_, up2Port_};
  for (int t = 0; t < 2; t++) {
    if (!ips[t]) continue;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) continue;
    sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ips[t];
    to.sin_port = htons(ports[t]);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    bool ok = false;
    int rc = connect(fd, (sockaddr*)&to, sizeof(to));
    if (rc != 0 && errno == EINPROGRESS) {
      fd_set wf;
      FD_ZERO(&wf);
      FD_SET(fd, &wf);
      timeval tv = {1, 500000};
      int err = 1;
      socklen_t el = sizeof(err);
      if (select(fd + 1, nullptr, &wf, nullptr, &tv) > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) rc = 0;
    }
    if (rc == 0) {
      fcntl(fd, F_SETFL, fl);
      timeval tv = {1, 500000};
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      uint8_t hdr[2] = {(uint8_t)(qlen >> 8), (uint8_t)qlen};
      uint8_t lb[2];
      if (sendAll(fd, hdr, 2) && sendAll(fd, query, qlen) && recvAll(fd, lb, 2)) {
        size_t rl = ((size_t)lb[0] << 8) | lb[1];
        if (rl >= 12 && rl <= cap && recvAll(fd, reply, rl) && be16(reply) == be16(query)) { rlen = rl; ok = true; }
      }
    }
    close(fd);
    if (ok) return true;
  }
  return false;
}

bool DnsServer::handleTcpQuery(const uint8_t* query, size_t qlen, uint32_t clientIp, uint8_t* out, size_t cap, size_t& rlen) {
  DnsQuestion q;
  if (!dnsParseQuestion(query, qlen, q)) return tcpForward(query, qlen, out, cap, rlen);
  if (q.qclass == 1 && dnsIsDohCanary(q.name)) {
    noteClient(clientIp, false);
    st_.canary++;
    rlen = dnsBuildNxdomain(query, q, out, cap);
    return rlen > 0;
  }
  bool blocked = q.qclass == 1 && matcher_.isBlocked(q.name, q.nameLen);
  noteClient(clientIp, blocked);
  if (blocked) {
    rlen = dnsBuildBlockedReply(query, qlen, q, out, cap);
    if (rlen) { st_.blocked++; noteBlocked(q.name); return true; }
  }
  bool dnssec = queryWantsDnssec(query, qlen, q.qend);
  if (q.qclass == 1 && !dnssec && cacheGet(q, query, false, out, cap, rlen)) {
    st_.cacheHits++;
    if (!(matcher_.ready() && dnsCnameTargetBlocked(out, rlen, matcher_))) return true;
    rlen = dnsBuildBlockedReply(query, qlen, q, out, cap);
    if (rlen) { st_.blocked++; st_.cnameBlocked++; noteBlocked(q.name); markClientBlocked(clientIp); return true; }
  }
  if (tcpForward(query, qlen, out, cap, rlen)) {
    if (q.qclass == 1 && !dnssec) cachePut(q, query, out, rlen);
    if (matcher_.ready() && dnsCnameTargetBlocked(out, rlen, matcher_)) {
      size_t rn = dnsBuildBlockedReply(query, qlen, q, out, cap);
      if (rn) { rlen = rn; st_.blocked++; st_.cnameBlocked++; noteBlocked(q.name); markClientBlocked(clientIp); }
    }
    return true;
  }
  if (q.qclass == 1 && !dnssec && cacheGet(q, query, true, out, cap, rlen)) { st_.staleServed++; return true; }
  if (cap < q.qend) return false;                       // SERVFAIL: tell the client instead of leaving it hanging
  memcpy(out, query, q.qend);
  out[2] = (uint8_t)(0x80 | (query[2] & 0x01));
  out[3] = 0x82;
  putBe16(out + 6, 0); putBe16(out + 8, 0); putBe16(out + 10, 0);
  rlen = q.qend;
  st_.timeouts++;
  return true;
}

}  // namespace c3
