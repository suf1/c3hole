// 40-bit domain hash: FNV-1a (64-bit) folded to 40 bits.
// MUST stay identical to tools/build_blocklist.py::hash40().
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace c3 {

inline uint64_t hash40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint8_t)s[i];
    h *= 0x100000001b3ULL;
  }
  return (h ^ (h >> 40)) & 0xFFFFFFFFFFULL;
}

inline uint64_t getBE40(const uint8_t* p) {
  return ((uint64_t)p[0] << 32) | ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 8) |
         (uint64_t)p[4];
}

inline void putBE40(uint8_t* p, uint64_t v) {
  p[0] = (uint8_t)(v >> 32);
  p[1] = (uint8_t)(v >> 24);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 8);
  p[4] = (uint8_t)v;
}

inline uint32_t getLE32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

}  // namespace c3
