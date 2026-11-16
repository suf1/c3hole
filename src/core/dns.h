// DNS sinkhole engine: packet parsing, blocked replies and an asynchronous
// forwarder with 32 concurrent in-flight upstream queries.
// Portable: POSIX sockets on a PC (for tests), lwIP sockets on the ESP32.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include <mutex>

#include "blocklist.h"

namespace c3 {

struct DnsQuestion {
  char name[254];      // lower-case, no trailing dot
  uint16_t nameLen;
  uint16_t qtype;
  uint16_t qclass;
  uint16_t qend;       // offset just past the question section
};

// Parses a standard query with exactly one question. Returns false otherwise.
bool dnsParseQuestion(const uint8_t* pkt, size_t len, DnsQuestion& q);

// Builds the reply for a blocked name: A -> 0.0.0.0, AAAA -> ::, anything else -> NODATA.
size_t dnsBuildBlockedReply(const uint8_t* query, size_t qlen, const DnsQuestion& q, uint8_t* out, size_t cap);

struct DnsStats {
  uint32_t total, blocked, forwarded, answered, timeouts, retried, overflow, malformed;
  uint32_t cnameBlocked;  // replies discarded because a CNAME target is on the blocklist (cloaked trackers)
  uint32_t truncated;     // upstream replies with the TC bit set (clients would retry over TCP, which is not served)
  uint32_t canary;        // encrypted-DNS canary lookups answered with NXDOMAIN
  DnsStats() : total(0), blocked(0), forwarded(0), answered(0), timeouts(0), retried(0), overflow(0), malformed(0),
               cnameBlocked(0), truncated(0), canary(0) {}
};

// True if the answer section of an upstream reply holds a CNAME whose target is blocked.
bool dnsCnameTargetBlocked(const uint8_t* pkt, size_t len, Matcher& m);

// Names browsers/OSes use to decide whether they may bypass the network's DNS with DoH.
bool dnsIsDohCanary(const char* name);

// NXDOMAIN reply for a query (used for the canary names).
size_t dnsBuildNxdomain(const uint8_t* query, const DnsQuestion& q, uint8_t* out, size_t cap);

struct ClientStat {
  uint32_t ip;  // network byte order
  uint32_t total;
  uint32_t blocked;
};

class DnsServer {
 public:
  enum { kSlots = 32, kRecent = 16, kRecentLen = 64, kClients = 16, kStoredQuery = 256 };

  DnsServer(Matcher& matcher, uint32_t (*rng)());
  ~DnsServer();

  // Upstream addresses are IPv4 in network byte order (0 = unused); ports are in host byte order.
  bool begin(uint16_t port, uint32_t up1, uint32_t up2);
  void end();
  void setUpstreams(uint32_t up1, uint32_t up2);
  void setUpstreamEndpoints(uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2);
  // false: ask the primary, retry on the secondary after the timeout. true: ask both at once, first answer wins.
  void setParallel(bool on) { parallel_ = on; }
  void setTimeoutMs(uint32_t ms) { timeoutMs_ = ms; }
  void setUpstreamPort(uint16_t port) { up1Port_ = up2Port_ = port; }  // both upstreams (default 53)

  // Runs one iteration: waits up to waitMs for traffic, handles it, expires timeouts.
  void step(int waitMs);

  DnsStats stats() const { return st_; }
  int pending() const;
  size_t recentBlocked(char out[][kRecentLen], size_t max) const;
  size_t clients(ClientStat* out, size_t max) const;
  bool running() const { return srv_ >= 0; }

 private:
  struct Slot {
    bool used;
    uint16_t upId;
    uint16_t clientId;
    uint32_t clientIp;
    uint16_t clientPort;
    uint32_t tsMs;
    uint8_t tries;
    uint16_t qlen;
    uint8_t q[kStoredQuery];
  };

  void onClient();
  void onUpstream();
  void forward(uint8_t* pkt, size_t n, uint32_t ip, uint16_t port);
  void sweep();
  void noteClient(uint32_t ip, bool blocked);
  void markClientBlocked(uint32_t ip);
  void noteBlocked(const char* name);
  static uint32_t nowMs();

  Matcher& matcher_;
  uint32_t (*rng_)();
  int srv_, up_;
  uint32_t up1_, up2_, timeoutMs_;
  uint16_t up1Port_, up2Port_;
  bool parallel_;
  Slot slots_[kSlots];
  DnsStats st_;
  bool lastRead_;
  uint8_t buf_[1500];
  uint8_t out_[1500];

  mutable std::mutex mu_;  // guards recent_ and clients_ (read by the web thread)
  char recent_[kRecent][kRecentLen];
  uint8_t recentHead_;
  uint8_t recentCount_;
  ClientStat clients_[kClients];
};

}  // namespace c3
