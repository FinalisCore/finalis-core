// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <limits>

namespace finalis::wide {

// 128-bit arithmetic for consensus code, in plain C++ on 64-bit limbs. There is deliberately one
// implementation for every compiler: a native __int128 path for GCC/Clang next to an intrinsic path
// for MSVC let the two disagree at the edges (wrap vs saturate, truncate vs #DE fault), and nodes on
// different platforms must derive identical results. Semantics are those of unsigned __int128:
// mul() wraps mod 2^128 and div_u64() returns the low 64 bits of the quotient.
// tests/test_wide_arith.cpp checks every function against __int128 where the compiler has it.

struct U128 {
  std::uint64_t hi{0};
  std::uint64_t lo{0};
  bool operator==(const U128&) const = default;
};

inline constexpr U128 from_u64(std::uint64_t value) { return U128{0, value}; }

inline constexpr U128 mul_u64(std::uint64_t a, std::uint64_t b) {
  constexpr std::uint64_t kMask = 0xFFFF'FFFFULL;
  const std::uint64_t a_lo = a & kMask;
  const std::uint64_t a_hi = a >> 32;
  const std::uint64_t b_lo = b & kMask;
  const std::uint64_t b_hi = b >> 32;
  const std::uint64_t p0 = a_lo * b_lo;
  const std::uint64_t p1 = a_lo * b_hi;
  const std::uint64_t p2 = a_hi * b_lo;
  const std::uint64_t p3 = a_hi * b_hi;
  const std::uint64_t mid = (p0 >> 32) + (p1 & kMask) + (p2 & kMask);
  return U128{p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32), (p0 & kMask) | (mid << 32)};
}

// value * factor mod 2^128.
inline constexpr U128 mul(U128 value, std::uint64_t factor) {
  U128 out = mul_u64(value.lo, factor);
  out.hi += value.hi * factor;
  return out;
}

inline constexpr int cmp(U128 a, U128 b) {
  if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
  if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
  return 0;
}

inline constexpr bool fits_u64(U128 value) { return value.hi == 0; }

// Low 64 bits of value / divisor. The high quotient word (value.hi / divisor) is dropped, as a
// static_cast of the __int128 quotient would. Division by zero traps like any integer division.
inline constexpr std::uint64_t div_u64(U128 value, std::uint64_t divisor) {
  std::uint64_t rem = value.hi % divisor;
  std::uint64_t quot = 0;
  for (int bit = 63; bit >= 0; --bit) {
    const bool carry = (rem >> 63) != 0;
    rem = (rem << 1) | ((value.lo >> bit) & 1U);
    quot <<= 1;
    if (carry || rem >= divisor) {
      rem -= divisor;
      quot |= 1U;
    }
  }
  return quot;
}

inline constexpr int compare_mul_u64(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d) {
  return cmp(mul_u64(a, b), mul_u64(c, d));
}

inline constexpr int compare_mul3_u64(std::uint64_t a, std::uint64_t b, std::uint64_t c,
                                      std::uint64_t x, std::uint64_t y, std::uint64_t z) {
  return cmp(mul(mul_u64(a, b), c), mul(mul_u64(x, y), z));
}

inline constexpr std::uint64_t mul_div_u64(std::uint64_t a, std::uint64_t b, std::uint64_t divisor) {
  return div_u64(mul_u64(a, b), divisor);
}

inline constexpr std::uint64_t mul_div_u64(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t divisor) {
  return div_u64(mul(mul_u64(a, b), c), divisor);
}

inline constexpr bool mul_u64_exceeds_u64(std::uint64_t a, std::uint64_t b) {
  return !fits_u64(mul_u64(a, b));
}

// Signed 128-bit accumulator (two's complement), for sums of u64 amounts that may go negative, such
// as the confidential-pool turnstile delta. Semantics are those of __int128 within its range.
struct I128 {
  std::uint64_t hi{0};
  std::uint64_t lo{0};
  bool operator==(const I128&) const = default;
};

inline constexpr I128 i128_from_u64(std::uint64_t value) { return I128{0, value}; }

inline constexpr I128 i128_from_i64(std::int64_t value) {
  return I128{value < 0 ? std::numeric_limits<std::uint64_t>::max() : 0, static_cast<std::uint64_t>(value)};
}

inline constexpr I128 add(I128 a, I128 b) {
  const std::uint64_t lo = a.lo + b.lo;
  return I128{a.hi + b.hi + (lo < a.lo ? 1U : 0U), lo};
}

inline constexpr I128 add_u64(I128 a, std::uint64_t value) { return add(a, i128_from_u64(value)); }

inline constexpr I128 sub_u64(I128 a, std::uint64_t value) {
  return I128{a.hi - (a.lo < value ? 1U : 0U), a.lo - value};
}

inline constexpr bool is_negative(I128 value) { return (value.hi >> 63) != 0; }

// 0 <= value <= UINT64_MAX.
inline constexpr bool fits_u64(I128 value) { return value.hi == 0; }

// INT64_MIN <= value <= INT64_MAX.
inline constexpr bool fits_i64(I128 value) {
  constexpr std::uint64_t kSignBit = 1ULL << 63;
  return (value.hi == 0 && value.lo < kSignBit) ||
         (value.hi == std::numeric_limits<std::uint64_t>::max() && value.lo >= kSignBit);
}

// Callers check fits_u64 / fits_i64 first.
inline constexpr std::uint64_t to_u64(I128 value) { return value.lo; }
inline constexpr std::int64_t to_i64(I128 value) { return static_cast<std::int64_t>(value.lo); }

}  // namespace finalis::wide
