// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_paths.hpp"

#include <filesystem>

#include "common/network.hpp"
#include "consensus/canonical_derivation.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "storage/db.hpp"

using namespace finalis;

namespace {

constexpr std::uint64_t kBond = 100'000ULL * 100'000'000ULL;  // above any minimum bond

PubKey32 pub_of(std::uint8_t b) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(b);
  return crypto::keypair_from_seed32(seed)->public_key;
}

// A join as a block carries it: the bond (SCVALREG) and the join request for one validator key.
AnyTx join_tx(std::uint8_t key) {
  Tx tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{Hash32{key}, 0, Bytes{}, 0xFFFFFFFF});
  Bytes reg{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  const auto pub = pub_of(key);
  reg.insert(reg.end(), pub.begin(), pub.end());
  tx.outputs.push_back(TxOut{kBond, reg});
  ValidatorJoinRequestScriptData d;
  d.validator_pubkey = pub;
  d.payout_pubkey = pub;
  d.bls_pubkey.fill(key);
  tx.outputs.push_back(TxOut{0, encode_validator_join_request_script(d)});
  return AnyTx{tx};
}

consensus::CanonicalDerivationConfig join_limited_config() {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = mainnet_network();
  cfg.validator_min_bond_override = 0;
  cfg.validator_bond_min_amount = 0;
  cfg.validator_bond_max_amount = kBond;
  cfg.validator_join_limit_window_blocks = 10;
  cfg.validator_join_limit_max_new = 1;
  return cfg;
}

std::size_t count_status(const consensus::CanonicalDerivedState& s, ValidatorJoinRequestStatus st) {
  std::size_t n = 0;
  for (const auto& [_, r] : s.validator_join_requests) n += r.status == st ? 1 : 0;
  return n;
}

}  // namespace

// More joins than the window admits used to be finalized with their bond locked but no validator
// registered, stranding the bond for good. They are now queued and admitted oldest first.
TEST(test_joins_over_the_window_limit_are_queued_not_stranded) {
  const auto cfg = join_limited_config();
  consensus::CanonicalDerivedState state;
  const UtxoSetV2 no_inputs;
  const auto apply = [&](std::uint64_t height, std::vector<AnyTx> txs) {
    consensus::apply_validator_state_changes_from_txs(cfg, &state, txs, 0, no_inputs, height);
  };
  const auto registered = [&](std::uint8_t key) { return state.validators.get(pub_of(key)).has_value(); };

  const auto empty_root = consensus::queued_join_commitment_root(state.validator_join_requests);
  apply(1, {join_tx(1), join_tx(2), join_tx(3)});
  ASSERT_TRUE(registered(1) && !registered(2) && !registered(3));
  ASSERT_EQ(count_status(state, ValidatorJoinRequestStatus::APPROVED), 1u);
  ASSERT_EQ(count_status(state, ValidatorJoinRequestStatus::REQUESTED), 2u);
  for (const auto& [_, r] : state.validator_join_requests) {
    if (r.status == ValidatorJoinRequestStatus::REQUESTED) ASSERT_TRUE(r.bls_pubkey != crypto::BlsPublicKey{});
  }
  const auto queued_root = consensus::queued_join_commitment_root(state.validator_join_requests);
  ASSERT_TRUE(queued_root != empty_root);  // the queue is committed

  // Same window: full, nothing moves; a newcomer queues behind the others.
  apply(5, {join_tx(4)});
  ASSERT_TRUE(!registered(2) && !registered(3) && !registered(4));
  ASSERT_EQ(count_status(state, ValidatorJoinRequestStatus::REQUESTED), 3u);

  // Each new window admits one, oldest first (2 and 3 from height 1, then 4 from height 5), ahead of
  // that block's own join.
  apply(11, {join_tx(5)});
  ASSERT_EQ(count_status(state, ValidatorJoinRequestStatus::REQUESTED), 3u);
  ASSERT_TRUE(registered(1) && (registered(2) != registered(3)) && !registered(4) && !registered(5));
  apply(21, {});
  ASSERT_TRUE(registered(2) && registered(3) && !registered(4));
  apply(31, {});
  ASSERT_TRUE(registered(4) && !registered(5));
  apply(41, {});
  ASSERT_TRUE(registered(5));
  ASSERT_EQ(count_status(state, ValidatorJoinRequestStatus::REQUESTED), 0u);
  ASSERT_TRUE(consensus::queued_join_commitment_root(state.validator_join_requests) == empty_root);
  for (std::uint8_t k = 2; k <= 5; ++k) {
    const auto info = state.validators.get(pub_of(k));
    ASSERT_TRUE(info->has_bond && info->bonded_amount == kBond);
    ASSERT_TRUE(info->bls_pubkey[0] == k);  // the BLS key survived the wait
  }
}

TEST(test_queued_join_request_round_trips_with_its_bls_key) {
  const auto base = finalis::test::unique_test_base("/tmp/finalis_test_join_queue_db");
  std::filesystem::remove_all(base);
  storage::DB db;
  ASSERT_TRUE(db.open(base));
  ValidatorJoinRequest req;
  req.request_txid.fill(0x31);
  req.validator_pubkey = pub_of(7);
  req.payout_pubkey = pub_of(8);
  req.bond_outpoint = OutPoint{req.request_txid, 0};
  req.bond_amount = kBond;
  req.requested_height = 42;
  req.status = ValidatorJoinRequestStatus::REQUESTED;
  req.bls_pubkey.fill(0x5a);
  ASSERT_TRUE(db.put_validator_join_request(req.request_txid, req));
  const auto loaded = db.load_validator_join_requests();
  ASSERT_EQ(loaded.size(), 1u);
  const auto& got = loaded.begin()->second;
  ASSERT_TRUE(got.status == ValidatorJoinRequestStatus::REQUESTED && got.bls_pubkey == req.bls_pubkey &&
              got.requested_height == 42);
}
