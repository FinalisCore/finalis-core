// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include "common/address.hpp"

using namespace finalis;

TEST(test_address_encode_decode_checksum) {
  std::array<std::uint8_t, 20> pkh{};
  for (size_t i = 0; i < pkh.size(); ++i) pkh[i] = static_cast<std::uint8_t>(i);

  auto addr = address::encode_p2pkh("tsc", pkh);
  ASSERT_TRUE(addr.has_value());

  auto dec = address::decode(*addr);
  ASSERT_TRUE(dec.has_value());
  ASSERT_EQ(dec->hrp, "tsc");
  ASSERT_EQ(dec->addr_type, 0x00);
  ASSERT_EQ(dec->pubkey_hash, pkh);

  std::string bad = *addr;
  bad.back() = (bad.back() == 'a') ? 'b' : 'a';
  ASSERT_TRUE(!address::decode(bad).has_value());
}

TEST(test_address_validate_reports_specific_errors) {
  std::array<std::uint8_t, 20> pkh{};
  for (size_t i = 0; i < pkh.size(); ++i) pkh[i] = static_cast<std::uint8_t>(i);

  auto good = address::encode_p2pkh("sc", pkh);
  ASSERT_TRUE(good.has_value());

  const auto valid = address::validate(*good);
  ASSERT_TRUE(valid.valid);
  ASSERT_TRUE(valid.decoded.has_value());
  ASSERT_TRUE(valid.normalized_address.has_value());
  ASSERT_EQ(*valid.normalized_address, *good);

  const auto missing_sep = address::validate("scabcdef");
  ASSERT_TRUE(!missing_sep.valid);
  ASSERT_EQ(missing_sep.error, "missing separator");

  const auto bad_hrp = address::validate("zz1abcdef");
  ASSERT_TRUE(!bad_hrp.valid);
  ASSERT_EQ(bad_hrp.error, "unsupported hrp");

  std::string bad_checksum = *good;
  bad_checksum.back() = (bad_checksum.back() == 'a') ? 'b' : 'a';
  const auto checksum = address::validate(bad_checksum);
  ASSERT_TRUE(!checksum.valid);
  ASSERT_EQ(checksum.error, "checksum mismatch");

  const auto bad_base32 = address::validate("sc1ABC");
  ASSERT_TRUE(!bad_base32.valid);
  ASSERT_EQ(bad_base32.error, "invalid base32");
}

TEST(test_base32_encode_decode) {
  using finalis::address::base32_encode;
  using finalis::address::base32_decode;
  using finalis::Bytes;

  // Test normal encoding/decoding
  Bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
  std::string encoded = base32_encode(data);
  auto decoded_opt = base32_decode(encoded);
  ASSERT_TRUE(decoded_opt.has_value());
  ASSERT_EQ(decoded_opt.value(), data);

  // Test empty input
  Bytes empty_data;
  std::string empty_encoded = base32_encode(empty_data);
  ASSERT_EQ(empty_encoded, "");
  auto empty_decoded = base32_decode("");
  ASSERT_TRUE(empty_decoded.has_value());
  ASSERT_EQ(empty_decoded.value(), Bytes{});

  // Test invalid character
  auto invalid_decoded = base32_decode("abc$ef");
  ASSERT_TRUE(!invalid_decoded.has_value());

  // Test incomplete group (should fail if remainder is nonzero)
  // 'a' = 0, so this is valid, but 'b' = 1, so remainder is nonzero
  auto incomplete = base32_decode("b");
  ASSERT_TRUE(!incomplete.has_value());
}

void register_address_tests() {}
