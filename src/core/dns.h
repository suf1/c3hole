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
  uint32_t cacheHits, cacheMisses, staleServed;   // answers from the local cache / served stale because upstream failed
  uint32_t tcpQueries;                            // queries received over TCP
  uint32_t slow;                                  // upstream round trips slower than 400 ms
  uint32_t rttAvg, rttMax;                        // upstream round trip, ms (smoothed average / worst)
  uint32_t probeOk, probeFail;                    // heartbeat probes to the upstream
  DnsStats() : total(0), blocked(0), forwarded(0), answered(0), timeouts(0), retried(0), overflow(0), malformed(0),
               cnameBlocked(0), truncated(0), canary(0), cacheHits(0), cacheMisses(0), staleServed(0), tcpQueries(0),
               slow(0), rttAvg(0), rttMax(0), probeOk(0), probeFail(0) {}
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
  enum { kSlots = 32, kRecent = 16, kRecentLen = 64, kClients = 16, kStoredQuery = 256,
         kCache = 48, kCacheMaxEntry = 512, kCacheBytes = 16000, kTcpBuf = 1502 };

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

  // TCP:53 (clients retry over TCP when a UDP answer is truncated). Run tcpStep() from its own task: it may block
  // for a couple of seconds while talking to a client or to the upstream.
  bool beginTcp(uint16_t port);
  void tcpStep(int waitMs);

  // Heartbeat: every `ms` a tiny query goes to the upstream (0 = off). Keeps the Wi-Fi link busy and measures health.
  void setProbeInterval(uint32_t ms) { probeMs_ = ms; }
  uint32_t msSinceUpstreamOk() const { return nowMs() - lastOkMs_; }

  // Answer cache: TTLs are clamped to [minSec, maxSec]; an expired entry may be served for `staleSec` more seconds
  // if (and only if) the upstream does not answer.
  void setCacheLimits(uint32_t minSec, uint32_t maxSec, uint32_t staleSec) { cMin_ = minSec; cMax_ = maxSec; cStale_ = staleSec; }
  void cacheClear();

  DnsStats stats() const { return st_; }
  int pending() const;
  size_t recentBlocked(char out[][kRecentLen], size_t max) const;
  size_t clients(ClientStat* out, size_t max) const;
  bool running() const { return srv_ >= 0; }
  static uint32_t nowMs();

 private:
  struct Slot {
    bool used;
    uint16_t upId;
    uint16_t clientId;
    uint32_t clientIp;
    uint16_t clientPort;
    uint32_t tsMs;       // last send (for timeouts)
    uint32_t firstMs;    // first send (for round-trip time)
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
  void sendProbe();
  void noteRtt(uint32_t rtt);
  void sendTo(int fd, const uint8_t* p, size_t n, uint32_t ip, uint16_t port);

  struct CacheEntry {
    uint64_t key;
    uint32_t storedMs, ttlMs, lastUse;
    uint16_t len;
    uint8_t* data;
  };
  bool cacheGet(const DnsQuestion& q, const uint8_t* query, bool stale, uint8_t* out, size_t cap, size_t& len);
  void cachePut(const DnsQuestion& q, const uint8_t* query, const uint8_t* reply, size_t len);
  bool tcpForward(const uint8_t* query, size_t qlen, uint8_t* reply, size_t cap, size_t& rlen);
  bool handleTcpQuery(const uint8_t* query, size_t qlen, uint32_t clientIp, uint8_t* out, size_t cap, size_t& rlen);
  void handleTcpConn(int fd, uint32_t clientIp);

  Matcher& matcher_;
  uint32_t (*rng_)();
  int srv_, up_;
  uint32_t up1_, up2_, timeoutMs_;
  uint16_t up1Port_, up2Port_;
  bool parallel_;
  int tcp_;
  uint32_t probeMs_, lastProbeMs_, lastOkMs_;
  uint32_t cMin_, cMax_, cStale_;
  CacheEntry cache_[kCache];
  uint32_t cacheBytes_;
  std::mutex cacheMu_;
  uint8_t tcpIn_[kTcpBuf];
  uint8_t tcpOut_[kTcpBuf];
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
