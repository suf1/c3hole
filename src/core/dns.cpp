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

uint32_t DnsServer::nowMs() {
  return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}

DnsServer::DnsServer(Matcher& matcher, uint32_t (*rng)())
    : matcher_(matcher), rng_(rng), srv_(-1), up_(-1), up1_(0), up2_(0), timeoutMs_(1500), up1Port_(53), up2Port_(53), parallel_(false),
      recentHead_(0), recentCount_(0) {
  lastRead_ = false;
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
  return true;
}

void DnsServer::end() {
  if (srv_ >= 0) close(srv_);
  if (up_ >= 0) close(up_);
  srv_ = up_ = -1;
  memset(slots_, 0, sizeof(slots_));
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
    if (!parallel_ && s.tries == 0 && up2_ && s.qlen) {
      sockaddr_in to;
      memset(&to, 0, sizeof(to));
      to.sin_family = AF_INET;
      to.sin_addr.s_addr = up2_;
      to.sin_port = htons(up2Port_);
      sendto(up_, s.q, s.qlen, 0, (sockaddr*)&to, sizeof(to));
      s.tries = 1;
      s.tsMs = now;
      st_.retried++;
    } else {
      s.used = false;
      st_.timeouts++;
    }
  }
}

}  // namespace c3
