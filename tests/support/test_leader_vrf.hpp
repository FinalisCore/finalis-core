// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <vector>

#include "consensus/canonical_derivation.hpp"
#include "consensus/randomness.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/vrf.hpp"
#include "utxo/tx.hpp"

namespace finalis::test {

// Gives a hand-built transition its leader's VRF proof, as the proposer does after
// populate_frontier_transition_metadata. False if no key in `keys` is the leader's.
inline bool attach_test_leader_vrf(FrontierTransition* transition, const Hash32& parent_randomness,
                                   const std::vector<crypto::KeyPair>& keys) {
  const auto it = std::find_if(keys.begin(), keys.end(),
                               [&](const crypto::KeyPair& kp) { return kp.public_key == transition->leader_pubkey; });
  if (it == keys.end()) return false;
  const auto proof =
      crypto::vrf_prove(it->private_key, consensus::leader_vrf_alpha(parent_randomness, transition->height));
  if (!proof) return false;
  transition->leader_vrf_proof = *proof;
  return true;
}

// Sets record->transition.next_state_commitment as the proposer does, after the VRF proof (the
// post-state depends on it). False if the record does not apply to `parent`.
inline bool attach_test_next_state_commitment(const consensus::CanonicalDerivationConfig& cfg,
                                              const consensus::CanonicalDerivedState& parent,
                                              consensus::CanonicalFrontierRecord* record) {
  std::string error;
  return consensus::derive_frontier_next_state_commitment(cfg, parent, *record,
                                                          &record->transition.next_state_commitment, &error);
}

}  // namespace finalis::test
