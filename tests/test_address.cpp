TEST(test_p2pkh_script_pubkey) {
  using finalis::address::p2pkh_script_pubkey;
  using finalis::Bytes;
  // Test with all zeros
  std::array<std::uint8_t, 20> zeros{};
  Bytes script = p2pkh_script_pubkey(zeros);
  ASSERT_EQ(script.size(), 25u);
  ASSERT_EQ(script[0], 0x76); // OP_DUP
  ASSERT_EQ(script[1], 0xA9); // OP_HASH160
  ASSERT_EQ(script[2], 0x14); // Push 20 bytes
  for (size_t i = 0; i < 20; ++i) ASSERT_EQ(script[3 + i], 0x00);
  ASSERT_EQ(script[23], 0x88); // OP_EQUALVERIFY
  ASSERT_EQ(script[24], 0xAC); // OP_CHECKSIG

  // Test with all ones
  std::array<std::uint8_t, 20> ones;
  ones.fill(0xFF);
  Bytes script_ones = p2pkh_script_pubkey(ones);
  ASSERT_EQ(script_ones.size(), 25u);
  for (size_t i = 0; i < 20; ++i) ASSERT_EQ(script_ones[3 + i], 0xFF);

  // Test with a known pattern
  std::array<std::uint8_t, 20> pattern = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19};
  Bytes script_pattern = p2pkh_script_pubkey(pattern);
  for (size_t i = 0; i < 20; ++i) ASSERT_EQ(script_pattern[3 + i], static_cast<std::uint8_t>(i));
}
TEST(test_decode_valid_and_invalid_addresses) {
  using finalis::address::encode_p2pkh;
  using finalis::address::decode;
  // Valid address
  std::array<std::uint8_t, 20> pkh{};
  for (size_t i = 0; i < pkh.size(); ++i) pkh[i] = static_cast<std::uint8_t>(i);
  auto addr = encode_p2pkh("sc", pkh);
  ASSERT_TRUE(addr.has_value());
  auto dec = decode(*addr);
  ASSERT_TRUE(dec.has_value());
  ASSERT_EQ(dec->hrp, "sc");
  ASSERT_EQ(dec->addr_type, 0x00);
  ASSERT_EQ(dec->pubkey_hash, pkh);

  // Invalid address (bad checksum)
  std::string bad = *addr;
  bad.back() = (bad.back() == 'a') ? 'b' : 'a';
  auto dec_bad = decode(bad);
  ASSERT_TRUE(!dec_bad.has_value());

  // Invalid address (unsupported HRP)
  auto dec_hrp = decode("xx1abcdef");
  ASSERT_TRUE(!dec_hrp.has_value());

  // Invalid address (empty string)
  auto dec_empty = decode("");
  ASSERT_TRUE(!dec_empty.has_value());
}
TEST(test_address_validate_edge_cases) {
  using finalis::address::validate;
  // Address with valid HRP but too short payload (base32 for 1 byte)
  std::string short_payload = "sc1aaaaa"; // Not enough for 25 bytes after decoding
  auto res_short = validate(short_payload);
  ASSERT_TRUE(!res_short.valid);
  ASSERT_EQ(res_short.error, "invalid payload length");

  // Address with valid HRP but too long payload (base32 for 40 bytes)
  std::string long_payload = "sc1" + std::string(40, 'a');
  auto res_long = validate(long_payload);
  ASSERT_TRUE(!res_long.valid);
  // Could be invalid payload length or invalid base32 depending on decode

  // Address with valid HRP but invalid payload (bad address type)
  // Construct a valid address, then mutate the type byte
  std::array<std::uint8_t, 20> pkh{};
  auto good = finalis::address::encode_p2pkh("sc", pkh);
  ASSERT_TRUE(good.has_value());
  std::string mutated = *good;
  // Find the separator and base32-decode, then re-encode with type byte = 0x01
  auto sep = mutated.find('1');
  ASSERT_TRUE(sep != std::string::npos);
  std::string b32 = mutated.substr(sep + 1);
  auto data_opt = finalis::address::base32_decode(b32);
  ASSERT_TRUE(data_opt.has_value());
  auto data = data_opt.value();
  data[0] = 0x01; // unsupported address type
  std::string b32_mut;
  {
    // Re-encode mutated data
    b32_mut = finalis::address::base32_encode(data);
  }
  std::string bad_type_addr = mutated.substr(0, sep + 1) + b32_mut;
  auto res_bad_type = validate(bad_type_addr);
  ASSERT_TRUE(!res_bad_type.valid);
  ASSERT_EQ(res_bad_type.error, "unsupported address type");
}
// SPDX-License-Identifier: MIT

TEST(test_encode_p2pkh_various_inputs) {
  using finalis::address::encode_p2pkh;
  std::array<std::uint8_t, 20> zeros{};
  std::array<std::uint8_t, 20> ones;
  ones.fill(0xFF);
  std::array<std::uint8_t, 20> random = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                         0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

  // Valid HRPs
  auto addr_zeros_sc = encode_p2pkh("sc", zeros);
  ASSERT_TRUE(addr_zeros_sc.has_value());
  auto addr_ones_tsc = encode_p2pkh("tsc", ones);
  ASSERT_TRUE(addr_ones_tsc.has_value());
  auto addr_random_sc = encode_p2pkh("sc", random);
  ASSERT_TRUE(addr_random_sc.has_value());

  // Invalid HRPs
  auto addr_invalid_hrp1 = encode_p2pkh("btc", zeros);
  ASSERT_TRUE(!addr_invalid_hrp1.has_value());
  auto addr_invalid_hrp2 = encode_p2pkh("", ones);
  ASSERT_TRUE(!addr_invalid_hrp2.has_value());
  auto addr_invalid_hrp3 = encode_p2pkh("scc", random);
  ASSERT_TRUE(!addr_invalid_hrp3.has_value());
}
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
