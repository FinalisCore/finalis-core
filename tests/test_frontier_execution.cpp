#include "test_framework.hpp"

#include <array>
#include <atomic>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include "address/address.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/ingress.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> seq{0};
  return prefix + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

TxOut p2pkh_out_for_pub(const PubKey32& pub, std::uint64_t value) {
  const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
  return TxOut{value, address::p2pkh_script_pubkey(pkh)};
}

Bytes raw_signed_spend(const OutPoint& op, const TxOut& prev, const crypto::KeyPair& from, const PubKey32& to_pub,
                       std::uint64_t value_out) {
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  std::vector<TxOut> outputs{TxOut{value_out, address::p2pkh_script_pubkey(to_pkh)}};
  auto tx = build_signed_p2pkh_tx_single_input(op, prev, from.private_key, outputs);
  if (!tx.has_value()) throw std::runtime_error("failed to build spend");
  return tx->serialize();
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

Bytes raw_signed_spend_v2(const OutPoint& op, const crypto::KeyPair& from, const PubKey32& to_pub, std::uint64_t value_in,
                          std::uint64_t value_out) {
  TxV2 tx;
  tx.inputs.push_back(TxInV2{
      .prev_txid = op.txid,
      .prev_index = op.index,
      .sequence = 0xFFFFFFFF,
      .kind = TxInputKind::TRANSPARENT,
      .witness = TransparentInputWitnessV2{},
  });
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  tx.outputs.push_back(TxOutV2{
      .kind = TxOutputKind::TRANSPARENT,
      .body = TransparentTxOutV2{value_out, address::p2pkh_script_pubkey(to_pkh)},
  });
  tx.fee = value_in - value_out;
  tx.balance_proof.excess_commitment = commitment33(0x61);
  tx.balance_proof.excess_sig.fill(0x62);
  auto msg = signing_message_for_input_v2(tx, 0);
  if (!msg.has_value()) throw std::runtime_error("failed to build v2 sighash");
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  if (!sig.has_value()) throw std::runtime_error("failed to sign v2 spend");
  std::get<TransparentInputWitnessV2>(tx.inputs[0].witness).script_sig = make_p2pkh_script_sig(*sig, from.public_key);
  return tx.serialize();
}

}  // namespace

TEST(test_frontier_execution_accepts_independent_valid_transactions) {
  const auto from_a = key_from_byte(1);
  const auto from_b = key_from_byte(2);
  const auto to = key_from_byte(3);

  OutPoint op_a{};
  op_a.txid.fill(0x11);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x22);
  op_b.index = 0;

  UtxoSet parent;
  parent[op_a] = UtxoEntry{p2pkh_out_for_pub(from_a.public_key, 10'000)};
  parent[op_b] = UtxoEntry{p2pkh_out_for_pub(from_b.public_key, 12'000)};

  std::vector<Bytes> ordered{
      raw_signed_spend(op_a, parent[op_a].out, from_a, to.public_key, 9'700),
      raw_signed_spend(op_b, parent[op_b].out, from_b, to.public_key, 11'500),
  };

  consensus::FrontierExecutionResult result;
  std::string err;
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 7, ordered, nullptr, &result, &err));
  ASSERT_EQ(result.transition.prev_frontier, 7u);
  ASSERT_EQ(result.transition.next_frontier, 9u);
  ASSERT_EQ(result.decisions.size(), 2u);
  ASSERT_TRUE(result.decisions[0].accepted);
  ASSERT_TRUE(result.decisions[1].accepted);
  ASSERT_TRUE(result.transition.prev_state_root != result.transition.next_state_root);
}

TEST(test_frontier_execution_first_conflicting_valid_spend_wins) {
  const auto from = key_from_byte(4);
  const auto to = key_from_byte(5);

  OutPoint op{};
  op.txid.fill(0x33);
  op.index = 0;

  UtxoSet parent;
  parent[op] = UtxoEntry{p2pkh_out_for_pub(from.public_key, 10'000)};

  std::vector<Bytes> ordered{
      raw_signed_spend(op, parent[op].out, from, to.public_key, 9'800),
      raw_signed_spend(op, parent[op].out, from, to.public_key, 9'700),
  };

  consensus::FrontierExecutionResult result;
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 0, ordered, nullptr, &result));
  ASSERT_EQ(result.decisions.size(), 2u);
  ASSERT_TRUE(result.decisions[0].accepted);
  ASSERT_TRUE(!result.decisions[1].accepted);
  ASSERT_EQ(result.decisions[1].reject_reason, FrontierRejectReason::CONFLICT_DOMAIN_USED);
}

TEST(test_frontier_execution_invalid_then_later_valid_same_domain_can_accept) {
  const auto from = key_from_byte(6);
  const auto to = key_from_byte(7);

  OutPoint op{};
  op.txid.fill(0x44);
  op.index = 0;

  UtxoSet parent;
  parent[op] = UtxoEntry{p2pkh_out_for_pub(from.public_key, 10'000)};

  Tx invalid;
  invalid.version = 1;
  invalid.lock_time = 0;
  invalid.inputs.push_back(TxIn{op.txid, op.index, Bytes{}, 0xFFFFFFFF});
  invalid.outputs.push_back(TxOut{9'500, address::p2pkh_script_pubkey(crypto::h160(Bytes(to.public_key.begin(), to.public_key.end())))});

  std::vector<Bytes> ordered{
      invalid.serialize(),
      raw_signed_spend(op, parent[op].out, from, to.public_key, 9'800),
  };

  consensus::FrontierExecutionResult result;
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 10, ordered, nullptr, &result));
  ASSERT_EQ(result.decisions.size(), 2u);
  ASSERT_TRUE(!result.decisions[0].accepted);
  ASSERT_EQ(result.decisions[0].reject_reason, FrontierRejectReason::TX_INVALID);
  ASSERT_TRUE(result.decisions[1].accepted);
}

TEST(test_frontier_execution_is_deterministic_for_same_parent_and_slice) {
  const auto from_a = key_from_byte(8);
  const auto from_b = key_from_byte(9);
  const auto to = key_from_byte(10);

  OutPoint op_a{};
  op_a.txid.fill(0x55);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x66);
  op_b.index = 0;

  UtxoSet parent;
  parent[op_a] = UtxoEntry{p2pkh_out_for_pub(from_a.public_key, 10'000)};
  parent[op_b] = UtxoEntry{p2pkh_out_for_pub(from_b.public_key, 10'000)};

  std::vector<Bytes> ordered{
      raw_signed_spend(op_a, parent[op_a].out, from_a, to.public_key, 9'900),
      raw_signed_spend(op_b, parent[op_b].out, from_b, to.public_key, 9'850),
  };

  consensus::FrontierExecutionResult a;
  consensus::FrontierExecutionResult b;
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 3, ordered, nullptr, &a));
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 3, ordered, nullptr, &b));
  ASSERT_EQ(a.transition.serialize(), b.transition.serialize());
  ASSERT_EQ(a.result_id(), b.result_id());
  ASSERT_EQ(a.decisions.size(), b.decisions.size());
  for (std::size_t i = 0; i < a.decisions.size(); ++i) {
    ASSERT_EQ(a.decisions[i].serialize(), b.decisions[i].serialize());
  }
}

TEST(test_frontier_transition_hash_is_stable_and_order_sensitive) {
  const auto from_a = key_from_byte(11);
  const auto from_b = key_from_byte(12);
  const auto to = key_from_byte(13);

  OutPoint op_a{};
  op_a.txid.fill(0x77);
  op_a.index = 0;
  OutPoint op_b{};
  op_b.txid.fill(0x88);
  op_b.index = 0;

  UtxoSet parent;
  parent[op_a] = UtxoEntry{p2pkh_out_for_pub(from_a.public_key, 10'000)};
  parent[op_b] = UtxoEntry{p2pkh_out_for_pub(from_b.public_key, 10'000)};

  const Bytes tx_a = raw_signed_spend(op_a, parent[op_a].out, from_a, to.public_key, 9'900);
  const Bytes tx_b = raw_signed_spend(op_b, parent[op_b].out, from_b, to.public_key, 9'900);

  consensus::FrontierExecutionResult ab;
  consensus::FrontierExecutionResult ba;
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 0, {tx_a, tx_b}, nullptr, &ab));
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 0, {tx_b, tx_a}, nullptr, &ba));

  ASSERT_EQ(ab.transition.transition_id(), ab.transition.transition_id());
  ASSERT_TRUE(ab.transition.transition_id() != ba.transition.transition_id());
  ASSERT_TRUE(ab.result_id() != ba.result_id());
}

TEST(test_frontier_execution_rejects_txv2_ordered_record_until_supported) {
  const auto from = key_from_byte(14);
  const auto to = key_from_byte(15);

  OutPoint op{};
  op.txid.fill(0x91);
  op.index = 0;

  UtxoSet parent;
  parent[op] = UtxoEntry{p2pkh_out_for_pub(from.public_key, 10'000)};

  std::vector<Bytes> ordered{raw_signed_spend_v2(op, from, to.public_key, 10'000, 9'800)};

  consensus::FrontierExecutionResult result;
  ASSERT_TRUE(consensus::execute_frontier_slice(parent, 0, ordered, nullptr, &result));
  ASSERT_EQ(result.decisions.size(), 1u);
  ASSERT_TRUE(!result.decisions[0].accepted);
  ASSERT_EQ(result.decisions[0].reject_reason, FrontierRejectReason::TX_INVALID);
  ASSERT_TRUE(result.accepted_txs.empty());
}

TEST(test_ingress_append_rejects_txv2_payload_until_supported) {
  const auto from = key_from_byte(16);
  const auto to = key_from_byte(17);

  OutPoint op{};
  op.txid.fill(0x92);
  op.index = 0;

  const auto raw = raw_signed_spend_v2(op, from, to.public_key, 10'000, 9'800);
  const auto any = parse_any_tx(raw);
  ASSERT_TRUE(any.has_value());

  IngressCertificate cert;
  cert.epoch = 1;
  cert.lane = 0;
  cert.seq = 1;
  cert.txid = txid_any(*any);
  cert.tx_hash = crypto::sha256d(raw);
  cert.prev_lane_root = zero_hash();

  const auto base = unique_test_base("frontier_ingress_txv2");
  const auto db_path = std::filesystem::temp_directory_path() / base;
  std::filesystem::remove_all(db_path);
  storage::DB db;
  ASSERT_TRUE(db.open(db_path.string()));

  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, raw, {}, &err));
  ASSERT_EQ(err, "ingress-tx-version-not-yet-supported");
}
