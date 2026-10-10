// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <array>
#include <cstdint>
#include <limits>

#include "common/wide_arith.hpp"

using namespace finalis;

namespace {

constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

// Deterministic generator so every platform checks the same inputs.
std::uint64_t splitmix64(std::uint64_t* state) {
  std::uint64_t z = (*state += 0x9E37'79B9'7F4A'7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58'476D'1CE4'E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D0'49BB'1331'11EBULL;
  return z ^ (z >> 31);
}

// Mixes edge values into the random stream: products and quotients near 2^64 and 2^128 are where
// implementations used to disagree.
std::uint64_t operand(std::uint64_t* state) {
  static constexpr std::array<std::uint64_t, 8> kEdges{0, 1, 2, 0xFFFF'FFFFULL, 0x1'0000'0000ULL, kMax / 2, kMax - 1, kMax};
  const std::uint64_t r = splitmix64(state);
  switch (r % 4) {
    case 0:
      return kEdges[(r >> 8) % kEdges.size()];
    case 1:
      return r >> (r % 64);
    default:
      return splitmix64(state);
  }
}

}  // namespace

// Known answers: these run on every compiler, including MSVC, which has no __int128 to compare with.
TEST(test_wide_u128_known_answers) {
  ASSERT_TRUE((wide::mul_u64(kMax, kMax) == wide::U128{kMax - 1, 1}));
  ASSERT_TRUE((wide::mul_u64(0x1'0000'0000ULL, 0x1'0000'0000ULL) == wide::U128{1, 0}));
  ASSERT_TRUE((wide::mul_u64(0, kMax) == wide::U128{0, 0}));
  // mul wraps mod 2^128: (2^128 - 1) * 2 = 2^128 - 2.
  ASSERT_TRUE((wide::mul(wide::U128{kMax, kMax}, 2) == wide::U128{kMax, kMax - 1}));
  // div_u64 keeps the low 64 bits of the quotient: (3 * 2^64 + 5) / 2 = 2^64 + 2^63 + 2.
  ASSERT_EQ(wide::div_u64(wide::U128{3, 5}, 2), (1ULL << 63) + 2);
  ASSERT_EQ(wide::div_u64(wide::U128{kMax - 1, 1}, kMax), kMax);  // (kMax * kMax) / kMax
  ASSERT_EQ(wide::div_u64(wide::U128{0, 10}, 3), 3ULL);
  ASSERT_EQ(wide::mul_div_u64(kMax, kMax, kMax), kMax);
  ASSERT_EQ(wide::mul_div_u64(700'000'000'000'000ULL, 2'500ULL, 10'000ULL), 175'000'000'000'000ULL);
  ASSERT_EQ(wide::mul_div_u64(kMax, 3, 5, 15), kMax);
  ASSERT_EQ(wide::compare_mul_u64(kMax, kMax, kMax, kMax - 1), 1);
  ASSERT_EQ(wide::compare_mul_u64(2, 3, 3, 2), 0);
  // Wraps: kMax^2 * 2 exceeds 2^128 and compares below kMax^2. Callers must keep products in range.
  ASSERT_EQ(wide::compare_mul3_u64(kMax, kMax, 2, kMax, kMax, 1), -1);
  ASSERT_EQ(wide::compare_mul3_u64(kMax, 3, 2, kMax, 5, 1), 1);
  ASSERT_TRUE(wide::mul_u64_exceeds_u64(0x1'0000'0000ULL, 0x1'0000'0000ULL));
  ASSERT_TRUE(!wide::mul_u64_exceeds_u64(0xFFFF'FFFFULL, 0x1'0000'0001ULL));
}

TEST(test_wide_i128_known_answers) {
  wide::I128 d;
  d = wide::sub_u64(d, 1);
  ASSERT_TRUE(wide::is_negative(d));
  ASSERT_TRUE(wide::fits_i64(d));
  ASSERT_EQ(wide::to_i64(d), -1LL);
  ASSERT_TRUE(!wide::fits_u64(d));
  d = wide::add_u64(d, 1);
  ASSERT_TRUE((d == wide::I128{}));
  // Sums past 2^64 stay exact.
  d = wide::add_u64(wide::add_u64(wide::I128{}, kMax), kMax);
  ASSERT_TRUE((d == wide::I128{1, kMax - 1}));
  ASSERT_TRUE(!wide::fits_u64(d));
  d = wide::sub_u64(d, kMax);
  ASSERT_TRUE(wide::fits_u64(d));
  ASSERT_EQ(wide::to_u64(d), kMax);
  // Turnstile bounds: pool + delta must land in [0, 2^64 - 1].
  const auto at_max = wide::add(wide::i128_from_u64(kMax - 5), wide::i128_from_u64(5));
  ASSERT_TRUE(wide::fits_u64(at_max));
  ASSERT_TRUE(!wide::fits_u64(wide::add_u64(at_max, 1)));
  ASSERT_TRUE(!wide::fits_u64(wide::sub_u64(wide::i128_from_u64(5), 6)));
  // fits_i64 edges.
  constexpr auto kI64Max = std::numeric_limits<std::int64_t>::max();
  constexpr auto kI64Min = std::numeric_limits<std::int64_t>::min();
  ASSERT_TRUE(wide::fits_i64(wide::i128_from_i64(kI64Max)));
  ASSERT_TRUE(wide::fits_i64(wide::i128_from_i64(kI64Min)));
  ASSERT_TRUE(!wide::fits_i64(wide::add_u64(wide::i128_from_i64(kI64Max), 1)));
  ASSERT_TRUE(!wide::fits_i64(wide::sub_u64(wide::i128_from_i64(kI64Min), 1)));
  ASSERT_EQ(wide::to_i64(wide::i128_from_i64(kI64Min)), kI64Min);
}

#if defined(__SIZEOF_INT128__)
// The portable implementation must match native __int128 bit for bit, including wrap and truncation.
TEST(test_wide_matches_native_int128) {
  using N = unsigned __int128;
  using S = __int128;
  const auto to_native = [](wide::U128 v) { return (static_cast<N>(v.hi) << 64) | v.lo; };
  const auto to_native_s = [](wide::I128 v) { return static_cast<S>((static_cast<N>(v.hi) << 64) | v.lo); };
  std::uint64_t state = 0x5EED'F1A1'15ULL;
  for (int i = 0; i < 200'000; ++i) {
    const std::uint64_t a = operand(&state);
    const std::uint64_t b = operand(&state);
    const std::uint64_t c = operand(&state);
    std::uint64_t divisor = operand(&state);
    if (divisor == 0) divisor = 1;

    const N ab = static_cast<N>(a) * b;
    ASSERT_TRUE(to_native(wide::mul_u64(a, b)) == ab);
    ASSERT_TRUE(to_native(wide::mul(wide::mul_u64(a, b), c)) == ab * c);
    ASSERT_EQ(wide::div_u64(wide::mul_u64(a, b), divisor), static_cast<std::uint64_t>(ab / divisor));
    ASSERT_EQ(wide::mul_div_u64(a, b, c, divisor), static_cast<std::uint64_t>((ab * c) / divisor));
    const N cd = static_cast<N>(c) * divisor;
    ASSERT_EQ(wide::compare_mul_u64(a, b, c, divisor), ab < cd ? -1 : (ab > cd ? 1 : 0));
    ASSERT_EQ(wide::mul_u64_exceeds_u64(a, b), ab > kMax);

    // Signed accumulator: a - b - c + divisor, starting from a signed 64-bit value.
    const auto start = static_cast<std::int64_t>(splitmix64(&state));
    auto acc = wide::sub_u64(wide::sub_u64(wide::add_u64(wide::i128_from_i64(start), a), b), c);
    acc = wide::add(acc, wide::i128_from_u64(divisor));
    const S native = static_cast<S>(start) + a - b - c + divisor;
    ASSERT_TRUE(to_native_s(acc) == native);
    ASSERT_EQ(wide::is_negative(acc), native < 0);
    ASSERT_EQ(wide::fits_u64(acc), native >= 0 && native <= static_cast<S>(kMax));
    ASSERT_EQ(wide::fits_i64(acc), native >= std::numeric_limits<std::int64_t>::min() &&
                                       native <= std::numeric_limits<std::int64_t>::max());
  }
}
#endif
