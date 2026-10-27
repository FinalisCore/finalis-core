// SPDX-License-Identifier: MIT

#include "support/test_chain_domain.hpp"
#include "test_framework.hpp"

#include "common/address.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp) throw std::runtime_error("key gen failed");
  return *kp;
}

std::array<std::uint8_t, 20> pkh_of(const crypto::KeyPair& k) {
  const auto h = crypto::h160(Bytes(k.public_key.begin(), k.public_key.end()));
  std::array<std::uint8_t, 20> out{};
  std::copy(h.begin(), h.end(), out.begin());
  return out;
}

// `spender` spends the locked output at `op` to a plain output; validated at block `height`.
TxValidationResult spend_at(const UtxoSet& view, const OutPoint& op, const crypto::KeyPair& spender, std::uint64_t height) {
  const TxOut prev = view.at(op).out;
  auto tx = build_signed_p2pkh_tx_multi_input(test::test_chain_domain(), {{op, prev}},
                                              Bytes(spender.private_key.begin(), spender.private_key.end()),
                                              {TxOut{prev.value - 1'000, address::p2pkh_script_pubkey(pkh_of(spender))}});
  if (!tx) return TxValidationResult{false, "build failed", 0};
  const auto ctx = test::with_test_chain_identity(SpecialValidationContext{.current_height = height});
  return validate_tx(*tx, 1, view, &ctx);
}

OutPoint locked_op() {
  OutPoint op{};
  op.txid.fill(0xD1);
  return op;
}

}  // namespace

TEST(test_height_lock_scripts_roundtrip_and_reject_malformed) {
  const auto a = pkh_of(key_from_byte(1));
  const auto b = pkh_of(key_from_byte(2));
  const auto locked = height_lock_script_pubkey(250'000, a);
  ASSERT_EQ(locked.size(), kHeightLockScriptBytes);
  const auto p1 = parse_height_lock_script(locked);
  ASSERT_TRUE(p1.has_value() && p1->unlock_height == 250'000 && p1->beneficiary_pkh == a && !p1->owner_pkh);
  const auto inheritance = inheritance_lock_script_pubkey(9, a, b);
  ASSERT_EQ(inheritance.size(), kInheritanceLockScriptBytes);
  const auto p2 = parse_height_lock_script(inheritance);
  ASSERT_TRUE(p2.has_value() && p2->unlock_height == 9 && p2->owner_pkh == a && p2->beneficiary_pkh == b);
  ASSERT_TRUE(is_supported_base_layer_output_script(locked) && is_supported_base_layer_output_script(inheritance));
  ASSERT_TRUE(!parse_height_lock_script(height_lock_script_pubkey(0, a)).has_value());  // height 0 is not a lock
  ASSERT_TRUE(!parse_height_lock_script(Bytes(locked.begin(), locked.end() - 1)).has_value());
  auto wrong_prefix = locked;
  wrong_prefix[7] = '9';
  ASSERT_TRUE(!parse_height_lock_script(wrong_prefix).has_value());
  // Indexed under the script itself and the P2PKH address of each key that may spend it.
  const auto keys = script_index_hashes(inheritance);
  ASSERT_EQ(keys.size(), 3u);
  ASSERT_TRUE(script_indexed_under(inheritance, crypto::sha256(address::p2pkh_script_pubkey(a))));
  ASSERT_TRUE(script_indexed_under(inheritance, crypto::sha256(address::p2pkh_script_pubkey(b))));
  ASSERT_TRUE(!script_indexed_under(locked, crypto::sha256(address::p2pkh_script_pubkey(b))));
}

// Locked form: only the beneficiary, only from the unlock height; whatever the gap.
TEST(test_height_locked_output_spends_only_from_its_height) {
  const auto owner = key_from_byte(3);
  const auto stranger = key_from_byte(4);
  UtxoSet view;
  view[locked_op()] = UtxoEntry{TxOut{5'000'000, height_lock_script_pubkey(200'200, pkh_of(owner))}};
  const auto early = spend_at(view, locked_op(), owner, 200'199);
  ASSERT_TRUE(!early.ok);
  ASSERT_EQ(early.error, std::string("height lock not reached"));
  ASSERT_TRUE(spend_at(view, locked_op(), owner, 200'200).ok);
  ASSERT_TRUE(spend_at(view, locked_op(), owner, 9'000'000).ok);
  ASSERT_TRUE(!spend_at(view, locked_op(), stranger, 9'000'000).ok);

  // Without a block height the input cannot be judged.
  const TxOut prev = view.at(locked_op()).out;
  auto tx = build_signed_p2pkh_tx_multi_input(test::test_chain_domain(), {{locked_op(), prev}},
                                              Bytes(owner.private_key.begin(), owner.private_key.end()),
                                              {TxOut{prev.value - 1'000, address::p2pkh_script_pubkey(pkh_of(owner))}});
  ASSERT_TRUE(tx.has_value());
  ASSERT_TRUE(!validate_tx(*tx, 1, view, nullptr).ok);
}

// Inheritance form: the owner at any height, the heir from the unlock height, nobody else ever.
TEST(test_inheritance_lock_owner_any_time_heir_from_height) {
  const auto owner = key_from_byte(5);
  const auto heir = key_from_byte(6);
  const auto stranger = key_from_byte(7);
  UtxoSet view;
  view[locked_op()] = UtxoEntry{TxOut{5'000'000, inheritance_lock_script_pubkey(1'000, pkh_of(owner), pkh_of(heir))}};
  ASSERT_TRUE(spend_at(view, locked_op(), owner, 2).ok);
  ASSERT_TRUE(!spend_at(view, locked_op(), heir, 999).ok);
  ASSERT_TRUE(spend_at(view, locked_op(), heir, 1'000).ok);
  ASSERT_TRUE(!spend_at(view, locked_op(), stranger, 5'000).ok);
  ASSERT_TRUE(script_spendable_by(view.at(locked_op()).out.script_pubkey, pkh_of(owner), 1));
  ASSERT_TRUE(!script_spendable_by(view.at(locked_op()).out.script_pubkey, pkh_of(heir), 999));
}

// Paying into a lock is an ordinary transaction with a height-locked output.
TEST(test_payment_into_a_height_lock_is_valid) {
  const auto payer = key_from_byte(8);
  const auto recipient = key_from_byte(9);
  OutPoint coin{};
  coin.txid.fill(0xD2);
  UtxoSet view;
  view[coin] = UtxoEntry{TxOut{3'000'000, address::p2pkh_script_pubkey(pkh_of(payer))}};
  auto tx = build_signed_p2pkh_tx_multi_input(test::test_chain_domain(), {{coin, view.at(coin).out}},
                                              Bytes(payer.private_key.begin(), payer.private_key.end()),
                                              {TxOut{2'999'000, height_lock_script_pubkey(77, pkh_of(recipient))}});
  ASSERT_TRUE(tx.has_value());
  const auto ctx = test::with_test_chain_identity(SpecialValidationContext{.current_height = 10});
  ASSERT_TRUE(validate_tx(*tx, 1, view, &ctx).ok);
}
