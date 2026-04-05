#include "test_framework.hpp"

#include "address/address.hpp"

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

void register_address_tests() {}
