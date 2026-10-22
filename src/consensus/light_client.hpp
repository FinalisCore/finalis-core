// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "consensus/canonical_derivation.hpp"
#include "crypto/smt.hpp"
#include "genesis/genesis.hpp"
#include "storage/db.hpp"
#include "utxo/tx.hpp"

// Checking finalized state without trusting the server that reports it. A client that knows an epoch's
// committee accepts a transition carrying a quorum of that committee's precommits, and learns the next
// epoch's committee from a CommitteeHandoff. Starting from the genesis committee, it can follow the
// chain epoch by epoch, then check UTXOs against the finalized tip's signed next_state_root.

namespace finalis::consensus {

inline constexpr std::uint32_t kValidationRulesVersion = 7;

// The derivation parameters every node on `network` runs with: the network's values and the NodeConfig
// defaults, without the test-only overrides. The genesis committee is derived from these.
CanonicalDerivationConfig network_canonical_derivation_config(const NetworkConfig& network, const ChainId& chain_id);

// Chain identity of the embedded genesis: what a node's ChainId holds once its DB matches it.
ChainId chain_id_for_genesis(const NetworkConfig& network, const Hash32& genesis_bin_hash);

// The epoch-1 committee checkpoint, as every node derives it from the genesis document.
std::optional<storage::FinalizedCommitteeCheckpoint> genesis_committee_checkpoint(const NetworkConfig& network,
                                                                                  const genesis::Document& doc,
                                                                                  const Hash32& genesis_bin_hash,
                                                                                  std::string* error = nullptr);

// Proof of the committee checkpoint for epoch `next_epoch_start` (= transition height + 1), checkable
// with the committee of the epoch that transition ends: its finality certificate signs the transition,
// the transition signs next_state_commitment = sha256d(post_state_preimage), and the preimage's
// checkpoint root holds next_checkpoint.
struct CommitteeHandoff {
  Bytes transition;
  FinalityCertificate certificate;
  Bytes post_state_preimage;
  Bytes next_checkpoint;  // checkpoint_commitment_value
  crypto::SmtProof next_checkpoint_proof;

  Bytes serialize() const;
  static std::optional<CommitteeHandoff> parse(const Bytes& bytes);
};

// For a node that has just finalized `transition` (its epoch's last height) with `certificate`;
// `state_after` is the state that transition produced. nullopt when the height ends no epoch.
std::optional<CommitteeHandoff> build_committee_handoff(const CanonicalDerivationConfig& cfg,
                                                        const CanonicalDerivedState& state_after,
                                                        const FrontierTransition& transition,
                                                        const FinalityCertificate& certificate,
                                                        std::string* error = nullptr);

struct LightClientParams {
  Hash32 chain_domain{};
  std::uint64_t epoch_blocks{0};
};
LightClientParams light_client_params(const NetworkConfig& network, const ChainId& chain_id);

// `transition` is final when `certificate` carries a quorum of precommits from the committee of
// `epoch_checkpoint`, which must be the checkpoint of the transition's epoch.
bool verify_light_finality(const LightClientParams& params, const storage::FinalizedCommitteeCheckpoint& epoch_checkpoint,
                           const FrontierTransition& transition, const FinalityCertificate& certificate,
                           std::string* error = nullptr);

// The next epoch's checkpoint, proven by `handoff` from `current` (the checkpoint of the epoch it ends).
std::optional<storage::FinalizedCommitteeCheckpoint> verify_committee_handoff(
    const LightClientParams& params, const storage::FinalizedCommitteeCheckpoint& current, const CommitteeHandoff& handoff,
    std::string* error = nullptr);

}  // namespace finalis::consensus
