#pragma once

#include <cstdint>
#include <limits>

#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
#endif

namespace finalis::wide {

#if defined(__SIZEOF_INT128__)

using U128 = unsigned __int128;

inline constexpr U128 from_u64(std::uint64_t value) { return static_cast<U128>(value); }

inline constexpr U128 mul_u64(std::uint64_t a, std::uint64_t b) {
  return static_cast<U128>(a) * static_cast<U128>(b);
}

inline constexpr U128 mul(U128 value, std::uint64_t factor) { return value * static_cast<U128>(factor); }

inline constexpr int cmp(U128 a, U128 b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

inline constexpr bool fits_u64(U128 value) { return value <= static_cast<U128>(std::numeric_limits<std::uint64_t>::max()); }

inline constexpr std::uint64_t div_u64(U128 value, std::uint64_t divisor) {
  return static_cast<std::uint64_t>(value / static_cast<U128>(divisor));
}

#elif defined(_MSC_VER) && defined(_M_X64)

struct U128 {
  std::uint64_t hi;
  std::uint64_t lo;
};

inline constexpr U128 from_u64(std::uint64_t value) { return U128{0, value}; }

inline U128 mul_u64(std::uint64_t a, std::uint64_t b) {
  U128 out{};
  out.lo = _umul128(a, b, &out.hi);
  return out;
}

inline U128 mul(U128 value, std::uint64_t factor) {
  if ((value.hi == 0 && value.lo == 0) || factor == 0) return U128{0, 0};

  std::uint64_t upper_overflow = 0;
  const std::uint64_t upper_lo = _umul128(value.hi, factor, &upper_overflow);
  std::uint64_t lower_hi = 0;
  const std::uint64_t lower_lo = _umul128(value.lo, factor, &lower_hi);

  if (upper_overflow != 0) return U128{std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max()};

  const std::uint64_t hi = lower_hi + upper_lo;
  if (hi < lower_hi) return U128{std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max()};

  return U128{hi, lower_lo};
}

inline constexpr int cmp(U128 a, U128 b) {
  if (a.hi < b.hi) return -1;
  if (a.hi > b.hi) return 1;
  if (a.lo < b.lo) return -1;
  if (a.lo > b.lo) return 1;
  return 0;
}

inline constexpr bool fits_u64(U128 value) { return value.hi == 0; }

inline std::uint64_t div_u64(U128 value, std::uint64_t divisor) {
  std::uint64_t remainder = 0;
  return _udiv128(value.hi, value.lo, divisor, &remainder);
}

#else
#error "Portable 128-bit arithmetic requires either __int128 or MSVC x64 intrinsics."
#endif

inline int compare_mul_u64(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d) {
  return cmp(mul_u64(a, b), mul_u64(c, d));
}

inline int compare_mul3_u64(std::uint64_t a, std::uint64_t b, std::uint64_t c,
                            std::uint64_t x, std::uint64_t y, std::uint64_t z) {
  return cmp(mul(mul_u64(a, b), c), mul(mul_u64(x, y), z));
}

inline std::uint64_t mul_div_u64(std::uint64_t a, std::uint64_t b, std::uint64_t divisor) {
  return div_u64(mul_u64(a, b), divisor);
}

inline std::uint64_t mul_div_u64(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t divisor) {
  return div_u64(mul(mul_u64(a, b), c), divisor);
}

inline bool mul_u64_exceeds_u64(std::uint64_t a, std::uint64_t b) {
  return !fits_u64(mul_u64(a, b));
}

}  // namespace finalis::wide
