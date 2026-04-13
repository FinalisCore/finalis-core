#include "test_framework.hpp"

#include <ctime>

#include "address/address.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "mempool/mempool.hpp"
#include "policy/hashcash.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

TxOut p2pkh_out_for_pub(const PubKey32& pub, std::uint64_t value) {
  const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
  return TxOut{value, address::p2pkh_script_pubkey(pkh)};
}

std::optional<Tx> spend_one(const OutPoint& op, const TxOut& prev, const crypto::KeyPair& from,
                            const PubKey32& to_pub, std::uint64_t value_out) {
  std::vector<TxOut> outs;
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  outs.push_back(TxOut{value_out, address::p2pkh_script_pubkey(to_pkh)});
  return build_signed_p2pkh_tx_single_input(op, prev, from.private_key, outs);
}

Bytes make_p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig.begin(), sig.end());
  ss.push_back(0x20);
  ss.insert(ss.end(), pub.begin(), pub.end());
  return ss;
}

crypto::Commitment33 commitment33(std::uint8_t seed) {
  crypto::Commitment33 out;
  out.bytes[0] = 0x02 | (seed & 0x01);
  for (std::size_t i = 1; i < out.bytes.size(); ++i) out.bytes[i] = static_cast<std::uint8_t>(seed + i);
  return out;
}

TxV2 make_transparent_only_v2_tx(const OutPoint& op, const crypto::KeyPair& from, const PubKey32& to_pub,
                                 std::uint64_t value_in, std::uint64_t value_out) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::Transparent,
      .witness = TransparentInputWitnessV2{},
  });
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::Transparent,
      .body = TransparentTxOutV2{value_out, address::p2pkh_script_pubkey(to_pkh)},
  });
  tx.fee = value_in - value_out;
  tx.balance_proof.excess_commitment = crypto::Commitment33{};
  tx.balance_proof.excess_pubkey.fill(0);
  tx.balance_proof.excess_sig.fill(0);
  auto msg = signing_message_for_input_v2(tx, 0);
  if (!msg.has_value()) throw std::runtime_error("v2 sighash failed");
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  if (!sig.has_value()) throw std::runtime_error("v2 sign failed");
  std::get<TransparentInputWitnessV2>(tx.inputs[0].witness).script_sig = make_p2pkh_script_sig(*sig, from.public_key);
  return tx;
}

std::vector<Tx> fill_pool_to_count_limit(mempool::Mempool& mp, mempool::UtxoView& view, const crypto::KeyPair& from,
                                         const PubKey32& to_pub, std::uint64_t value_in, std::uint64_t value_out) {
  std::vector<Tx> accepted;
  accepted.reserve(mempool::Mempool::kMaxTxCount);
  std::string err;
  for (std::size_t i = 0; i < mempool::Mempool::kMaxTxCount; ++i) {
    OutPoint op{};
    for (std::size_t b = 0; b < op.txid.size(); ++b) op.txid[b] = static_cast<std::uint8_t>((i + b) & 0xFF);
    op.index = static_cast<std::uint32_t>(i);
    TxOut prev = p2pkh_out_for_pub(from.public_key, value_in);
    view[op] = UtxoEntry{prev};
    auto tx = spend_one(op, prev, from, to_pub, value_out);
    ASSERT_TRUE(tx.has_value());
    ASSERT_TRUE(mp.accept_tx(*tx, view, &err));
    accepted.push_back(*tx);
  }
  return accepted;
}

}  // namespace

TEST(test_mempool_accept_reject_rules) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(1);
  const auto k2 = key_from_byte(2);

  OutPoint op1{};
  op1.txid.fill(0x11);
  op1.index = 0;
  TxOut prev1 = p2pkh_out_for_pub(k1.public_key, 1'000'000);
  view[op1] = UtxoEntry{prev1};

  auto tx_ok = spend_one(op1, prev1, k1, k2.public_key, 999'000);
  ASSERT_TRUE(tx_ok.has_value());

  std::string err;
  ASSERT_TRUE(mp.accept_tx(*tx_ok, view, &err));
  ASSERT_EQ(mp.size(), 1u);

  ASSERT_TRUE(!mp.accept_tx(*tx_ok, view, &err));

  auto tx_conflict = spend_one(op1, prev1, k1, k2.public_key, 998'500);
  ASSERT_TRUE(tx_conflict.has_value());
  ASSERT_TRUE(!mp.accept_tx(*tx_conflict, view, &err));

  OutPoint op2{};
  op2.txid.fill(0x22);
  op2.index = 0;
  TxOut prev2 = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op2] = UtxoEntry{prev2};
  auto tx_neg_fee = spend_one(op2, prev2, k1, k2.public_key, 20'000);
  ASSERT_TRUE(tx_neg_fee.has_value());
  ASSERT_TRUE(!mp.accept_tx(*tx_neg_fee, view, &err));

  Tx big;
  big.version = 1;
  big.lock_time = 0;
  big.inputs.push_back(TxIn{zero_hash(), 0, Bytes{}, 0xFFFFFFFF});
  big.outputs.push_back(TxOut{1, Bytes(120 * 1024, 0x01)});
  ASSERT_TRUE(!mp.accept_tx(big, view, &err));
}

TEST(test_mempool_selection_order_fee_rate_then_absolute_fee_then_txid) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(10);
  const auto k2 = key_from_byte(20);

  OutPoint op_a{};
  op_a.txid.fill(0xA1);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0xB1);
  op_b.index = 0;
  OutPoint op_c{};
  op_c.txid.fill(0xC1);
  op_c.index = 0;

  TxOut prev_a = p2pkh_out_for_pub(k1.public_key, 10000);
  TxOut prev_b = p2pkh_out_for_pub(k1.public_key, 10000);
  TxOut prev_c = p2pkh_out_for_pub(k1.public_key, 10000);

  view[op_a] = UtxoEntry{prev_a};
  view[op_b] = UtxoEntry{prev_b};
  view[op_c] = UtxoEntry{prev_c};

  auto tx1 = spend_one(op_a, prev_a, k1, k2.public_key, 9800);  // fee 200
  auto tx2 = spend_one(op_b, prev_b, k1, k2.public_key, 9700);  // fee 300
  auto tx3 = spend_one(op_c, prev_c, k1, k2.public_key, 9800);  // fee 200
  ASSERT_TRUE(tx1 && tx2 && tx3);

  std::string err;
  ASSERT_TRUE(mp.accept_tx(*tx1, view, &err));
  ASSERT_TRUE(mp.accept_tx(*tx2, view, &err));
  ASSERT_TRUE(mp.accept_tx(*tx3, view, &err));

  auto selected = mp.select_for_block(10, 1024 * 1024, view);
  ASSERT_EQ(selected.size(), 3u);

  ASSERT_EQ(txid_any(selected[0]), tx2->txid());

  const Hash32 t1 = tx1->txid();
  const Hash32 t3 = tx3->txid();
  if (t1 < t3) {
    ASSERT_EQ(txid_any(selected[1]), t1);
    ASSERT_EQ(txid_any(selected[2]), t3);
  } else {
    ASSERT_EQ(txid_any(selected[1]), t3);
    ASSERT_EQ(txid_any(selected[2]), t1);
  }
}

TEST(test_mempool_full_rejects_equal_or_worse_and_evicts_one_better_tx) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(40);
  const auto k2 = key_from_byte(41);
  auto accepted = fill_pool_to_count_limit(mp, view, k1, k2.public_key, 10'000, 9'800);

  ASSERT_EQ(mp.size(), mempool::Mempool::kMaxTxCount);
  const auto before_stats = mp.policy_stats();
  ASSERT_TRUE(before_stats.min_fee_rate_to_enter_when_full.has_value());

  std::string err;

  OutPoint equal_op{};
  equal_op.txid.fill(0xEE);
  equal_op.index = 0;
  TxOut equal_prev = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[equal_op] = UtxoEntry{equal_prev};
  auto equal_tx = spend_one(equal_op, equal_prev, k1, k2.public_key, 9'800);
  ASSERT_TRUE(equal_tx.has_value());
  ASSERT_TRUE(!mp.accept_tx(*equal_tx, view, &err));
  ASSERT_TRUE(err.find("mempool full: not good enough") != std::string::npos);
  ASSERT_EQ(mp.size(), mempool::Mempool::kMaxTxCount);
  ASSERT_EQ(mp.policy_stats().rejected_full_not_good_enough, before_stats.rejected_full_not_good_enough + 1);

  OutPoint worse_op{};
  worse_op.txid.fill(0xEF);
  worse_op.index = 0;
  TxOut worse_prev = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[worse_op] = UtxoEntry{worse_prev};
  auto worse_tx = spend_one(worse_op, worse_prev, k1, k2.public_key, 9'900);
  ASSERT_TRUE(worse_tx.has_value());
  ASSERT_TRUE(!mp.accept_tx(*worse_tx, view, &err));
  ASSERT_TRUE(err.find("mempool full: not good enough") != std::string::npos);
  ASSERT_EQ(mp.size(), mempool::Mempool::kMaxTxCount);
  ASSERT_EQ(mp.policy_stats().rejected_full_not_good_enough, before_stats.rejected_full_not_good_enough + 2);

  Hash32 worst_txid = accepted.front().txid();
  std::size_t worst_size = accepted.front().serialize().size();
  for (const auto& tx : accepted) {
    if (worst_txid < tx.txid()) {
      worst_txid = tx.txid();
      worst_size = tx.serialize().size();
    }
  }

  const auto bytes_before = mp.total_bytes();
  OutPoint better_op{};
  better_op.txid.fill(0xF0);
  better_op.index = 0;
  TxOut better_prev = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[better_op] = UtxoEntry{better_prev};
  auto better_tx = spend_one(better_op, better_prev, k1, k2.public_key, 9'700);
  ASSERT_TRUE(better_tx.has_value());
  ASSERT_TRUE(mp.accept_tx(*better_tx, view, &err));
  ASSERT_EQ(mp.size(), mempool::Mempool::kMaxTxCount);
  ASSERT_TRUE(mp.contains(better_tx->txid()));
  ASSERT_TRUE(!mp.contains(worst_txid));
  ASSERT_EQ(mp.policy_stats().evicted_for_better_incoming, before_stats.evicted_for_better_incoming + 1);
  ASSERT_EQ(mp.total_bytes(), bytes_before - worst_size + better_tx->serialize().size());
}

TEST(test_mempool_block_selection_prefers_fee_rate_and_nonfitting_entries_remain) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(50);
  const auto k2 = key_from_byte(51);

  auto add_tx = [&](std::uint8_t tag, std::uint64_t value_in, const std::vector<std::uint64_t>& outputs) -> Tx {
    OutPoint op{};
    op.txid.fill(tag);
    op.index = 0;
    TxOut prev = p2pkh_out_for_pub(k1.public_key, value_in);
    view[op] = UtxoEntry{prev};
    std::vector<TxOut> outs;
    const auto to_pkh = crypto::h160(Bytes(k2.public_key.begin(), k2.public_key.end()));
    for (auto out_value : outputs) outs.push_back(TxOut{out_value, address::p2pkh_script_pubkey(to_pkh)});
    auto tx = build_signed_p2pkh_tx_single_input(op, prev, k1.private_key, outs);
    ASSERT_TRUE(tx.has_value());
    std::string err;
    ASSERT_TRUE(mp.accept_tx(*tx, view, &err));
    return *tx;
  };

  const auto high_rate = add_tx(0x10, 10'000, {9'850});                       // fee 150, smaller tx
  const auto low_rate_high_fee = add_tx(0x11, 20'000, {3'960, 3'960, 3'960, 3'960, 3'960});  // fee 200, larger tx

  auto selected = mp.select_for_block(10, 1024 * 1024, view);
  ASSERT_EQ(selected.size(), 2u);
  ASSERT_EQ(txid_any(selected[0]), high_rate.txid());
  ASSERT_EQ(txid_any(selected[1]), low_rate_high_fee.txid());

  const auto fit_one = mp.select_for_block(10, high_rate.serialize().size() + 1, view);
  ASSERT_EQ(fit_one.size(), 1u);
  ASSERT_EQ(txid_any(fit_one[0]), high_rate.txid());
  ASSERT_TRUE(mp.contains(high_rate.txid()));
  ASSERT_TRUE(mp.contains(low_rate_high_fee.txid()));
}

TEST(test_mempool_confirmed_and_pruned_removal_behaviour_remains_intact) {
  mempool::Mempool mp;
  mempool::UtxoView view;

  const auto k1 = key_from_byte(60);
  const auto k2 = key_from_byte(61);

  OutPoint op1{};
  op1.txid.fill(0x61);
  op1.index = 0;
  TxOut prev1 = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op1] = UtxoEntry{prev1};
  auto tx1 = spend_one(op1, prev1, k1, k2.public_key, 9'800);
  ASSERT_TRUE(tx1.has_value());

  OutPoint op2{};
  op2.txid.fill(0x62);
  op2.index = 0;
  TxOut prev2 = p2pkh_out_for_pub(k1.public_key, 11'000);
  view[op2] = UtxoEntry{prev2};
  auto tx2 = spend_one(op2, prev2, k1, k2.public_key, 10'700);
  ASSERT_TRUE(tx2.has_value());

  std::string err;
  ASSERT_TRUE(mp.accept_tx(*tx1, view, &err));
  ASSERT_TRUE(mp.accept_tx(*tx2, view, &err));
  ASSERT_EQ(mp.size(), 2u);

  mp.remove_confirmed({tx1->txid()});
  ASSERT_EQ(mp.size(), 1u);
  ASSERT_TRUE(!mp.contains(tx1->txid()));
  ASSERT_TRUE(mp.contains(tx2->txid()));

  view.erase(op2);
  mp.prune_against_utxo(view);
  ASSERT_EQ(mp.size(), 0u);
  ASSERT_TRUE(!mp.contains(tx2->txid()));
}

TEST(test_mempool_hashcash_policy_requires_stamp_for_low_fee_txs) {
  mempool::Mempool mp;
  mp.set_network(mainnet_network());
  mp.set_hashcash_config(policy::HashcashConfig{
      .enabled = true,
      .base_bits = 10,
      .max_bits = 10,
      .epoch_seconds = 60,
      .fee_exempt_min = 500,
      .pressure_tx_threshold = 1000,
      .pressure_step_txs = 500,
      .pressure_bits_per_step = 1,
      .large_tx_bytes = 4096,
      .large_tx_extra_bits = 1,
  });
  mempool::UtxoView view;

  const auto k1 = key_from_byte(3);
  const auto k2 = key_from_byte(4);

  OutPoint op1{};
  op1.txid.fill(0x31);
  op1.index = 0;
  TxOut prev1 = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op1] = UtxoEntry{prev1};

  auto tx = spend_one(op1, prev1, k1, k2.public_key, 9'800);  // fee 200, below exempt min
  ASSERT_TRUE(tx.has_value());

  std::string err;
  ASSERT_TRUE(!mp.accept_tx(*tx, view, &err));
  ASSERT_TRUE(err.find("hashcash stamp required") != std::string::npos);

  const auto now_unix = static_cast<std::uint64_t>(std::time(nullptr));
  ASSERT_TRUE(policy::apply_hashcash_stamp(&*tx, mainnet_network(),
                                           policy::HashcashConfig{
                                               .enabled = true,
                                               .base_bits = 10,
                                               .max_bits = 10,
                                               .epoch_seconds = 60,
                                               .fee_exempt_min = 500,
                                               .pressure_tx_threshold = 1000,
                                               .pressure_step_txs = 500,
                                               .pressure_bits_per_step = 1,
                                               .large_tx_bytes = 4096,
                                               .large_tx_extra_bits = 1,
                                           },
                                           10, now_unix, 500'000, &err));
  auto reparsed = Tx::parse(tx->serialize());
  ASSERT_TRUE(reparsed.has_value());
  ASSERT_TRUE(reparsed->hashcash.has_value());
  ASSERT_EQ(reparsed->hashcash->bits, 10u);
  ASSERT_TRUE(mp.accept_tx(*reparsed, view, &err));
}

TEST(test_mempool_rejects_txv2_before_activation_via_variant_validation) {
  mempool::Mempool mp;
  mempool::UtxoView view;
  const auto k1 = key_from_byte(70);
  const auto k2 = key_from_byte(71);

  OutPoint op{};
  op.txid.fill(0x71);
  op.index = 0;
  TxOut prev = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op] = UtxoEntry{prev};

  ConfidentialPolicy policy;
  policy.activation_height = 500;
  SpecialValidationContext ctx;
  ctx.confidential_policy = &policy;
  ctx.current_height = 100;
  mp.set_validation_context(ctx);

  const auto tx = make_transparent_only_v2_tx(op, k1, k2.public_key, 10'000, 9'800);
  std::string err;
  ASSERT_TRUE(!mp.accept_tx(AnyTx{tx}, view, &err));
  ASSERT_TRUE(err.find("tx invalid: confidential tx not active") != std::string::npos);
}

TEST(test_mempool_accepts_txv2_after_activation_when_variant_validation_succeeds) {
  mempool::Mempool mp;
  mempool::UtxoView view;
  const auto k1 = key_from_byte(72);
  const auto k2 = key_from_byte(73);

  OutPoint op{};
  op.txid.fill(0x72);
  op.index = 0;
  TxOut prev = p2pkh_out_for_pub(k1.public_key, 10'000);
  view[op] = UtxoEntry{prev};

  ConfidentialPolicy policy;
  policy.activation_height = 0;
  SpecialValidationContext ctx;
  ctx.confidential_policy = &policy;
  ctx.current_height = 100;
  mp.set_validation_context(ctx);

  const auto tx = make_transparent_only_v2_tx(op, k1, k2.public_key, 10'000, 9'800);
  std::string err;
  ASSERT_TRUE(mp.accept_tx(AnyTx{tx}, view, &err));
  ASSERT_TRUE(mp.contains(tx.txid()));
}

void register_mempool_tests() {}
