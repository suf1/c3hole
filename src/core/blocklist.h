// Blocklist file format, hash store abstraction and the domain matcher.
//
// File layout ("C3HL" v1):
//   [0..3]   magic "C3HL"
//   [4]      version = 1
//   [5]      hash size in bytes = 5
//   [6..7]   flags (0)
//   [8..11]  entry count, little endian
//   [12..15] build time (unix seconds), little endian
//   [16..47] SHA-256 of the payload
//   [48..]   count x 5-byte big-endian hashes, sorted ascending
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mutex>

#include "bloom.h"
#include "hash40.h"
#include "sha256.h"

namespace c3 {

enum { BL_HEADER_SIZE = 48, BL_HASH_SIZE = 5 };

struct BlInfo {
  uint32_t count;
  uint32_t created;
  uint8_t sha[32];
  BlInfo() : count(0), created(0) { memset(sha, 0, sizeof(sha)); }
};

inline bool blParseHeader(const uint8_t* p, size_t avail, BlInfo& out) {
  if (avail < BL_HEADER_SIZE) return false;
  if (memcmp(p, "C3HL", 4) != 0) return false;
  if (p[4] != 1 || p[5] != BL_HASH_SIZE) return false;
  out.count = getLE32(p + 8);
  out.created = getLE32(p + 12);
  memcpy(out.sha, p + 16, 32);
  return true;
}

// Random access to the sorted hash table (flash-mapped or read on demand).
class HashStore {
 public:
  virtual ~HashStore() {}
  virtual uint32_t count() const = 0;
  virtual uint64_t at(uint32_t i) const = 0;
};

class MemStore : public HashStore {
 public:
  MemStore() : p_(nullptr), n_(0) {}
  void set(const uint8_t* payload, uint32_t n) { p_ = payload; n_ = n; }
  uint32_t count() const override { return n_; }
  uint64_t at(uint32_t i) const override { return getBE40(p_ + (size_t)i * BL_HASH_SIZE); }

 private:
  const uint8_t* p_;
  uint32_t n_;
};

inline bool storeContains(const HashStore& s, uint64_t h) {
  uint32_t lo = 0, hi = s.count();
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    uint64_t v = s.at(mid);
    if (v == h) return true;
    if (v < h) lo = mid + 1; else hi = mid;
  }
  return false;
}

struct MatchStats {
  uint32_t queries;       // lookups performed
  uint32_t blocked;       // lookups that matched
  uint32_t misses;        // lookups that did not match
  uint32_t missesNoFlash; // ... of which the Bloom filter alone settled it (0 flash reads)
  uint32_t flashSearches; // binary searches executed
  MatchStats() : queries(0), blocked(0), misses(0), missesNoFlash(0), flashSearches(0) {}
};

class Matcher {
 public:
  Matcher() : store_(nullptr), ready_(false) {}

  // Build the Bloom filter from `store` and start serving lookups.
  // bloomBytes == 0 (or allocation failure) -> run without a Bloom filter.
  // `yieldFn` (optional) is called every few thousand entries during the build.
  bool load(HashStore* store, uint32_t bloomBytes, void (*yieldFn)() = nullptr) {
    Bloom nb;
    bool haveBloom = false;
    if (bloomBytes && store->count() && nb.init(bloomBytes, store->count())) {
      for (uint32_t i = 0, n = store->count(); i < n; i++) {
        nb.add(store->at(i));
        if (yieldFn && (i & 0x3FFF) == 0x3FFF) yieldFn();
      }
      haveBloom = true;
    }
    std::lock_guard<std::mutex> g(mu_);
    bloom_.release();
    if (haveBloom) bloom_.swap(nb);
    store_ = store;
    ready_ = store != nullptr && store->count() > 0;
    return haveBloom || bloomBytes == 0;
  }

  // Stop matching (all queries are forwarded) and drop the store.
  void unload() {
    std::lock_guard<std::mutex> g(mu_);
    ready_ = false;
    store_ = nullptr;
    bloom_.release();
  }

  // Free the Bloom filter only (frees RAM, e.g. during a TLS download).
  // Lookups continue using binary search alone.
  void dropBloom() {
    std::lock_guard<std::mutex> g(mu_);
    bloom_.release();
  }

  // Rebuild the Bloom filter for the already-loaded store.
  bool rebuildBloom(uint32_t bloomBytes, void (*yieldFn)() = nullptr) {
    HashStore* s;
    { std::lock_guard<std::mutex> g(mu_); s = store_; }
    if (!s) return false;
    return load(s, bloomBytes, yieldFn);
  }

  // name: lower-case, no trailing dot. Blocks the name or any parent domain
  // (but never a bare single-label TLD).
  bool isBlocked(const char* name, size_t len) {
    std::lock_guard<std::mutex> g(mu_);
    if (!ready_) return false;
    st_.queries++;
    bool touchedFlash = false;
    size_t pos = 0;
    for (;;) {
      const char* suf = name + pos;
      size_t sl = len - pos;
      const char* dot = (const char*)memchr(suf, '.', sl);
      if (!dot) break;  // single label left: stop
      uint64_t h = hash40(suf, sl);
      bool maybe = bloom_.ready() ? bloom_.test(h) : true;
      if (maybe) {
        touchedFlash = true;
        st_.flashSearches++;
        if (storeContains(*store_, h)) { st_.blocked++; return true; }
      }
      pos += (size_t)(dot - suf) + 1;
    }
    st_.misses++;
    if (!touchedFlash) st_.missesNoFlash++;
    return false;
  }

  bool ready() const { return ready_; }
  bool hasBloom() const { return bloom_.ready(); }
  uint32_t bloomBytes() const { return bloom_.bytes(); }
  uint8_t bloomK() const { return bloom_.k(); }
  double bloomFill() const { return bloom_.fill(); }
  double bloomFpr() const { return bloom_.fpr(); }
  uint32_t entries() const { return store_ ? store_->count() : 0; }
  MatchStats stats() const { return st_; }

 private:
  mutable std::mutex mu_;
  Bloom bloom_;
  HashStore* store_;
  bool ready_;
  MatchStats st_;
};

}  // namespace c3
