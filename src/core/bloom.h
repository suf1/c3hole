// Bloom filter held in RAM; built at boot from the sorted hash table in flash.
// Bit positions are derived from the 40-bit domain hash (double hashing).
#pragma once
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace c3 {

class Bloom {
 public:
  Bloom() : bits_(nullptr), m_(0), k_(1), set_(0) {}
  ~Bloom() { release(); }
  Bloom(const Bloom&) = delete;
  Bloom& operator=(const Bloom&) = delete;

  void swap(Bloom& o) {
    uint8_t* b = bits_; bits_ = o.bits_; o.bits_ = b;
    uint32_t t = m_; m_ = o.m_; o.m_ = t;
    uint8_t k = k_; k_ = o.k_; o.k_ = k;
    uint32_t s = set_; set_ = o.set_; o.set_ = s;
  }

  // bytes: filter size; items: expected number of entries (to pick k).
  bool init(uint32_t bytes, uint32_t items) {
    release();
    if (bytes < 64) return false;
    bits_ = (uint8_t*)calloc(bytes, 1);
    if (!bits_) return false;
    m_ = bytes * 8;
    double ratio = (double)m_ / (double)(items ? items : 1);
    long k = lround(0.693 * ratio);
    if (k < 1) k = 1;
    if (k > 8) k = 8;
    k_ = (uint8_t)k;
    set_ = 0;
    return true;
  }

  void add(uint64_t h) {
    uint32_t a = (uint32_t)h, b = (uint32_t)(h >> 8) | 1u;
    for (uint8_t j = 0; j < k_; j++) {
      uint32_t i = (a + (uint32_t)j * b) % m_;
      uint8_t mask = (uint8_t)(1u << (i & 7));
      uint8_t& cell = bits_[i >> 3];
      if (!(cell & mask)) { cell |= mask; set_++; }
    }
  }

  bool test(uint64_t h) const {
    uint32_t a = (uint32_t)h, b = (uint32_t)(h >> 8) | 1u;
    for (uint8_t j = 0; j < k_; j++) {
      uint32_t i = (a + (uint32_t)j * b) % m_;
      if (!(bits_[i >> 3] & (1u << (i & 7)))) return false;
    }
    return true;
  }

  void release() {
    if (bits_) free(bits_);
    bits_ = nullptr; m_ = 0; set_ = 0;
  }

  bool ready() const { return bits_ != nullptr; }
  uint32_t bytes() const { return m_ / 8; }
  uint8_t k() const { return k_; }
  double fill() const { return m_ ? (double)set_ / (double)m_ : 0.0; }
  // Expected false-positive rate given the current fill.
  double fpr() const { return m_ ? pow(fill(), (double)k_) : 1.0; }

 private:
  uint8_t* bits_;
  uint32_t m_;
  uint8_t k_;
  uint32_t set_;
};

}  // namespace c3
