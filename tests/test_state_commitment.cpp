#include "test_framework.hpp"

#include "consensus/state_commitment.hpp"
#include "crypto/smt.hpp"
#include "merkle/merkle.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

}  // namespace

TEST(test_scr3_marker_parses_single_marker) {
  const Hash32 u = filled(0x11);
  const Hash32 v = filled(0x22);
  Bytes script{'c', 'b', ':', '1'};
  script = consensus::append_v3_roots_to_coinbase_script(script, u, v);

  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kNone);
  ASSERT_TRUE(parsed->utxo_root == u);
  ASSERT_TRUE(parsed->validators_root == v);
}

TEST(test_scr3_marker_multiple_markers_fails) {
  const Hash32 u = filled(0x33);
  const Hash32 v = filled(0x44);
  Bytes script = consensus::append_v3_roots_to_coinbase_script(Bytes{'x'}, u, v);
  const auto second = consensus::append_v3_roots_to_coinbase_script({}, u, v);
  script.insert(script.end(), second.begin(), second.end());

  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(!parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kMultipleMarkers);
}

TEST(test_scr3_marker_wrong_length_fails) {
  Bytes script{'c', 'b'};
  script.insert(script.end(), consensus::kSCR3Prefix.begin(), consensus::kSCR3Prefix.end());
  script.push_back(0x01);  // truncated marker payload

  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(!parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kWrongLength);
}

TEST(test_scr3_marker_missing_and_ascii_payload_is_not_marker) {
  const Bytes script{'c', 'b', ':', '0', ':', 'r', '3', '=', 'x', 'x'};
  consensus::MarkerError err = consensus::MarkerError::kNone;
  const auto parsed = consensus::find_scr3_roots_marker(script, &err);
  ASSERT_TRUE(!parsed.has_value());
  ASSERT_EQ(err, consensus::MarkerError::kMissing);
}

TEST(test_scr3_marker_bytes_affect_block_id_hash_domain) {
  const Hash32 u = filled(0x55);
  const Hash32 v = filled(0x66);

  Tx cb;
  cb.version = 1;
  cb.lock_time = 0;
  cb.inputs.push_back(TxIn{zero_hash(), 0xFFFFFFFF, Bytes{'c', 'b'}, 0xFFFFFFFF});
  cb.outputs.push_back(TxOut{1, Bytes{0x51}});
  cb.inputs[0].script_sig = consensus::append_v3_roots_to_coinbase_script(cb.inputs[0].script_sig, u, v);

  Block b;
  b.header.prev_finalized_hash = zero_hash();
  b.header.height = 1;
  b.header.timestamp = 1;
  b.header.round = 0;
  b.header.leader_pubkey.fill(0x01);
  b.txs.push_back(cb);

  std::vector<Bytes> txs1;
  txs1.push_back(b.txs[0].serialize());
  auto m1 = merkle::compute_merkle_root_from_txs(txs1);
  ASSERT_TRUE(m1.has_value());
  b.header.merkle_root = *m1;
  const Hash32 id1 = b.header.block_id();

  // Flip one byte inside SCR3 payload and recompute merkle/header.
  auto& script = b.txs[0].inputs[0].script_sig;
  ASSERT_TRUE(script.size() >= 68);
  script[4] ^= 0x01;

  std::vector<Bytes> txs2;
  txs2.push_back(b.txs[0].serialize());
  auto m2 = merkle::compute_merkle_root_from_txs(txs2);
  ASSERT_TRUE(m2.has_value());
  b.header.merkle_root = *m2;
  const Hash32 id2 = b.header.block_id();

  ASSERT_TRUE(id1 != id2);
}

TEST(test_validator_commitment_v3_ignores_v4_fields) {
  consensus::ValidatorInfo a;
  a.status = consensus::ValidatorStatus::ACTIVE;
  a.joined_height = 10;
  a.has_bond = true;
  a.bond_outpoint = OutPoint{filled(0x01), 3};
  a.unbond_height = 99;
  a.eligible_count_window = 11;
  a.participated_count_window = 7;
  a.liveness_window_start = 1000;
  a.suspended_until_height = 2000;
  a.last_join_height = 12;
  a.last_exit_height = 77;
  a.penalty_strikes = 3;

  consensus::ValidatorInfo b = a;
  b.eligible_count_window = 123456;
  b.participated_count_window = 654321;
  b.liveness_window_start = 424242;
  b.suspended_until_height = 313131;
  b.last_join_height = 999;
  b.last_exit_height = 1001;
  b.penalty_strikes = 42;

  const Bytes av3 = consensus::validator_commitment_value(a, 3);
  const Bytes bv3 = consensus::validator_commitment_value(b, 3);
  ASSERT_EQ(av3, bv3);
}

TEST(test_validator_commitment_v4_includes_v4_fields) {
  consensus::ValidatorInfo a;
  a.status = consensus::ValidatorStatus::ACTIVE;
  a.joined_height = 10;
  a.has_bond = true;
  a.bond_outpoint = OutPoint{filled(0x02), 5};
  a.unbond_height = 99;
  a.eligible_count_window = 11;
  a.participated_count_window = 7;
  a.liveness_window_start = 1000;
  a.suspended_until_height = 2000;
  a.last_join_height = 12;
  a.last_exit_height = 77;
  a.penalty_strikes = 3;

  consensus::ValidatorInfo b = a;
  b.eligible_count_window = 12;

  const Bytes av4 = consensus::validator_commitment_value(a, 4);
  const Bytes bv4 = consensus::validator_commitment_value(b, 4);
  ASSERT_TRUE(av4 != bv4);
}

TEST(test_validator_root_v3_stable_when_v4_fields_change) {
  PubKey32 pub{};
  pub.fill(0xAB);

  consensus::ValidatorInfo a;
  a.status = consensus::ValidatorStatus::ACTIVE;
  a.joined_height = 10;
  a.has_bond = true;
  a.bond_outpoint = OutPoint{filled(0x03), 7};
  a.unbond_height = 99;
  a.eligible_count_window = 5;
  a.participated_count_window = 1;

  consensus::ValidatorInfo b = a;
  b.eligible_count_window = 5000;
  b.participated_count_window = 4000;
  b.liveness_window_start = 1234;
  b.suspended_until_height = 5678;
  b.last_join_height = 777;
  b.last_exit_height = 888;
  b.penalty_strikes = 9;

  std::vector<std::pair<Hash32, Bytes>> leaves_a{
      {consensus::validator_commitment_key(pub), consensus::validator_commitment_value(a, 3)}};
  std::vector<std::pair<Hash32, Bytes>> leaves_b{
      {consensus::validator_commitment_key(pub), consensus::validator_commitment_value(b, 3)}};

  const Hash32 root_a = crypto::SparseMerkleTree::compute_root_from_leaves(leaves_a);
  const Hash32 root_b = crypto::SparseMerkleTree::compute_root_from_leaves(leaves_b);
  ASSERT_EQ(root_a, root_b);
}

void register_state_commitment_tests() {}
