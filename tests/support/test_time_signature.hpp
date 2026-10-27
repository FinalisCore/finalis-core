// SPDX-License-Identifier: MIT

#pragma once

// The parent height's time signature for a hand-built transition, as the proposer gathers it: each
// committee member among `keys` signs time_signature_message(parent height) with its seed-derived BLS
// key, and the lowest-index threshold are aggregated (consensus::aggregate_time_signatures).

#include <map>
#include <optional>
#include <vector>

#include "consensus/canonical_derivation.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/ed25519.hpp"
#include "utxo/tx.hpp"
#include "utxo/validate.hpp"

namespace finalis::test {

// Empty for the genesis parent; nullopt if the keys in `keys` do not reach the threshold.
inline std::optional<TimeSignatureAggregate> test_prev_time_signature(const consensus::CanonicalDerivationConfig& cfg,
                                                                      const consensus::CanonicalDerivedState& parent,
                                                                      const std::vector<crypto::KeyPair>& keys) {
  const auto height = parent.finalized_height;
  if (height == 0) return TimeSignatureAggregate{};
  const auto committee_keys = consensus::time_signature_committee_keys(cfg, parent, height);
  if (!committee_keys.has_value()) return std::nullopt;
  const auto msg = time_signature_message(consensus_chain_domain(cfg.network, cfg.chain_id), height);
  std::map<std::uint32_t, crypto::BlsSignature> sigs;
  for (const auto& kp : keys) {
    const auto sk = crypto::bls_key_from_validator_seed(kp.private_key);
    if (!sk) continue;
    const auto pk = crypto::bls_public_key(*sk);
    for (std::uint32_t i = 0; i < committee_keys->size(); ++i) {
      if (pk != (*committee_keys)[i]) continue;
      if (auto sig = crypto::bls_sign(*sk, msg, crypto::kBlsTimeSignatureDst)) sigs[i] = *sig;
    }
  }
  return consensus::aggregate_time_signatures(*committee_keys, sigs,
                                              consensus::time_signature_threshold(committee_keys->size()));
}

// The aggregate on `height` by the key set `key_set` (a long lock's named committee): each key in
// `keys` that is in the set signs, the lowest-index threshold are aggregated; nullopt below it.
inline std::optional<TimeSignatureAggregate> test_time_signature_by(const consensus::CanonicalDerivationConfig& cfg,
                                                                    const std::vector<crypto::BlsPublicKey>& key_set,
                                                                    std::uint64_t height,
                                                                    const std::vector<crypto::KeyPair>& keys) {
  const auto msg = time_signature_message(consensus_chain_domain(cfg.network, cfg.chain_id), height);
  std::map<std::uint32_t, crypto::BlsSignature> sigs;
  for (const auto& kp : keys) {
    const auto sk = crypto::bls_key_from_validator_seed(kp.private_key);
    if (!sk) continue;
    const auto pk = crypto::bls_public_key(*sk);
    for (std::uint32_t i = 0; i < key_set.size(); ++i) {
      if (pk != key_set[i]) continue;
      if (auto sig = crypto::bls_sign(*sk, msg, crypto::kBlsTimeSignatureDst)) sigs[i] = *sig;
    }
  }
  return consensus::aggregate_time_signatures(key_set, sigs, consensus::time_signature_threshold(key_set.size()));
}

}  // namespace finalis::test
