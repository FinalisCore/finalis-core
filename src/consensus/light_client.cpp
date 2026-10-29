// SPDX-License-Identifier: MIT

#include "consensus/light_client.hpp"

#include <set>

#include "codec/bytes.hpp"
#include "consensus/randomness.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"

namespace finalis::consensus {
namespace {

constexpr std::uint8_t kCommitteeHandoffVersion = 1;

bool fail(std::string* error, const std::string& reason) {
  if (error) *error = reason;
  return false;
}

std::optional<Hash32> hash_at(const Bytes& bytes, std::size_t offset) {
  if (bytes.size() < offset + 32) return std::nullopt;
  Hash32 out{};
  std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.begin() + static_cast<std::ptrdiff_t>(offset + 32),
            out.begin());
  return out;
}

}  // namespace

CanonicalDerivationConfig network_canonical_derivation_config(const NetworkConfig& network, const ChainId& chain_id) {
  CanonicalDerivationConfig cfg;
  cfg.network = network;
  cfg.chain_id = chain_id;
  cfg.max_committee = network.max_committee;
  cfg.validator_min_bond_override = network.validator_min_bond;
  cfg.validator_bond_min_amount = network.validator_bond_min_amount;
  cfg.validator_bond_max_amount = std::max(network.validator_bond_max_amount, network.validator_bond_min_amount);
  cfg.validator_warmup_blocks = network.validator_warmup_blocks;
  cfg.validator_cooldown_blocks = network.validator_cooldown_blocks;
  cfg.validator_join_limit_window_blocks = network.validator_join_limit_window_blocks;
  cfg.validator_join_limit_max_new = network.validator_join_limit_max_new;
  cfg.validator_liveness_window_blocks = network.liveness_window_blocks;
  cfg.validator_miss_rate_suspend_threshold_percent = network.miss_rate_suspend_threshold_percent;
  cfg.validator_miss_rate_exit_threshold_percent = network.miss_rate_exit_threshold_percent;
  cfg.validator_suspend_duration_blocks = network.suspend_duration_blocks;
  cfg.validation_rules_version = kValidationRulesVersion;
  return cfg;
}

ChainId chain_id_for_genesis(const NetworkConfig& network, const Hash32& genesis_bin_hash) {
  ChainId id;
  id.network_name = network.name;
  id.magic = network.magic;
  id.network_id_hex = hex_encode(Bytes(network.network_id.begin(), network.network_id.end()));
  id.protocol_version = network.protocol_version;
  id.genesis_hash_hex = hex_encode32(genesis_bin_hash);
  id.expected_genesis_hash_hex = id.genesis_hash_hex;
  id.db_genesis_hash_hex = id.genesis_hash_hex;
  return id;
}

std::optional<storage::FinalizedCommitteeCheckpoint> genesis_committee_checkpoint(const NetworkConfig& network,
                                                                                  const genesis::Document& doc,
                                                                                  const Hash32& genesis_bin_hash,
                                                                                  std::string* error) {
  const auto cfg = network_canonical_derivation_config(network, chain_id_for_genesis(network, genesis_bin_hash));
  const CanonicalGenesisState genesis_state = canonical_genesis_state_from_document(doc);
  CanonicalDerivedState state;
  if (!build_genesis_canonical_state(cfg, genesis_state, &state, error)) return std::nullopt;
  const auto it = state.finalized_committee_checkpoints.find(1);
  if (it == state.finalized_committee_checkpoints.end() || it->second.ordered_members.empty()) {
    if (error) *error = "genesis-checkpoint-missing";
    return std::nullopt;
  }
  return it->second;
}

Bytes CommitteeHandoff::serialize() const {
  codec::ByteWriter w;
  w.u8(kCommitteeHandoffVersion);
  w.varbytes(transition);
  w.varbytes(certificate.serialize());
  w.varbytes(post_state_preimage);
  w.varbytes(next_checkpoint);
  w.varbytes(crypto::SparseMerkleTree::encode_compact_proof(next_checkpoint_proof));
  return w.take();
}

std::optional<CommitteeHandoff> CommitteeHandoff::parse(const Bytes& bytes) {
  CommitteeHandoff out;
  const bool ok = codec::parse_exact(bytes, [&](codec::ByteReader& r) {
    auto version = r.u8();
    if (!version || *version != kCommitteeHandoffVersion) return false;
    auto transition = r.varbytes();
    auto cert = r.varbytes();
    auto preimage = r.varbytes();
    auto checkpoint = r.varbytes();
    auto proof = r.varbytes();
    if (!transition || !cert || !preimage || !checkpoint || !proof) return false;
    auto parsed_cert = FinalityCertificate::parse(*cert);
    auto parsed_proof = crypto::SparseMerkleTree::decode_compact_proof(*proof);
    if (!parsed_cert || !parsed_proof) return false;
    out.transition = std::move(*transition);
    out.certificate = std::move(*parsed_cert);
    out.post_state_preimage = std::move(*preimage);
    out.next_checkpoint = std::move(*checkpoint);
    out.next_checkpoint_proof = std::move(*parsed_proof);
    return true;
  });
  if (!ok) return std::nullopt;
  return out;
}

std::optional<CommitteeHandoff> build_committee_handoff(const CanonicalDerivationConfig& cfg,
                                                        const CanonicalDerivedState& state_after,
                                                        const FrontierTransition& transition,
                                                        const FinalityCertificate& certificate,
                                                        std::string* error) {
  const std::uint64_t next_epoch_start = transition.height + 1;
  if (committee_epoch_start(next_epoch_start, cfg.network.committee_epoch_blocks) != next_epoch_start) return std::nullopt;
  if (state_after.finalized_height != transition.height) {
    if (error) *error = "handoff-state-height-mismatch";
    return std::nullopt;
  }
  CommitteeHandoff handoff;
  handoff.transition = transition.serialize();
  handoff.certificate = certificate;
  handoff.post_state_preimage = consensus_post_state_preimage(cfg, state_after, &transition.next_state_root);
  if (crypto::sha256d(handoff.post_state_preimage) != transition.next_state_commitment) {
    if (error) *error = "handoff-post-state-commitment-mismatch";
    return std::nullopt;
  }
  const auto it = state_after.finalized_committee_checkpoints.find(next_epoch_start);
  if (it == state_after.finalized_committee_checkpoints.end()) {
    if (error) *error = "handoff-next-checkpoint-missing";
    return std::nullopt;
  }
  handoff.next_checkpoint = checkpoint_commitment_value(it->second);
  auto [root, proof] = crypto::SparseMerkleTree::prove_from_leaves(
      checkpoint_commitment_leaves(state_after.finalized_committee_checkpoints), checkpoint_commitment_key(next_epoch_start));
  if (hash_at(handoff.post_state_preimage, kPostStatePreimageCheckpointRootOffset) != root) {
    if (error) *error = "handoff-checkpoint-root-mismatch";
    return std::nullopt;
  }
  handoff.next_checkpoint_proof = std::move(proof);
  return handoff;
}

LightClientParams light_client_params(const NetworkConfig& network, const ChainId& chain_id) {
  return LightClientParams{consensus_chain_domain(network, chain_id), network.committee_epoch_blocks};
}

bool verify_light_finality(const LightClientParams& params, const storage::FinalizedCommitteeCheckpoint& epoch_checkpoint,
                           const FrontierTransition& transition, const FinalityCertificate& certificate,
                           std::string* error) {
  if (transition.height == 0 ||
      committee_epoch_start(transition.height, params.epoch_blocks) != epoch_checkpoint.epoch_start_height) {
    return fail(error, "light-finality-wrong-epoch");
  }
  if (certificate.height != transition.height) return fail(error, "light-finality-height-mismatch");
  if (certificate.round < transition.round) return fail(error, "light-finality-round-mismatch");
  if (certificate.frontier_transition_id != transition.transition_id()) {
    return fail(error, "light-finality-transition-id-mismatch");
  }
  // The committee comes from the trusted checkpoint, never from the certificate.
  const auto committee = checkpoint_committee_for_round(epoch_checkpoint, certificate.round);
  const std::set<PubKey32> members(committee.begin(), committee.end());
  if (committee.empty() || members.size() != committee.size()) return fail(error, "light-finality-bad-committee");
  const auto msg = vote_signing_message(params.chain_domain, certificate.height, certificate.round,
                                        certificate.frontier_transition_id);
  std::set<PubKey32> signed_by;
  for (const auto& sig : certificate.signatures) {
    if (!members.contains(sig.validator_pubkey) || signed_by.contains(sig.validator_pubkey)) continue;
    if (crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) signed_by.insert(sig.validator_pubkey);
  }
  if (signed_by.size() < quorum_threshold(committee.size())) return fail(error, "light-finality-no-quorum");
  return true;
}

std::optional<storage::FinalizedCommitteeCheckpoint> verify_committee_handoff(
    const LightClientParams& params, const storage::FinalizedCommitteeCheckpoint& current, const CommitteeHandoff& handoff,
    std::string* error) {
  const auto transition = FrontierTransition::parse(handoff.transition);
  if (!transition.has_value()) {
    fail(error, "handoff-transition-unparseable");
    return std::nullopt;
  }
  const std::uint64_t next_epoch_start = transition->height + 1;
  if (committee_epoch_start(next_epoch_start, params.epoch_blocks) != next_epoch_start) {
    fail(error, "handoff-not-epoch-end");
    return std::nullopt;
  }
  if (!verify_light_finality(params, current, *transition, handoff.certificate, error)) return std::nullopt;
  if (crypto::sha256d(handoff.post_state_preimage) != transition->next_state_commitment) {
    fail(error, "handoff-post-state-commitment-mismatch");
    return std::nullopt;
  }
  const auto checkpoint_root = hash_at(handoff.post_state_preimage, kPostStatePreimageCheckpointRootOffset);
  if (!checkpoint_root.has_value()) {
    fail(error, "handoff-preimage-short");
    return std::nullopt;
  }
  if (!crypto::SparseMerkleTree::verify_proof(*checkpoint_root, checkpoint_commitment_key(next_epoch_start),
                                              handoff.next_checkpoint, handoff.next_checkpoint_proof)) {
    fail(error, "handoff-checkpoint-proof-invalid");
    return std::nullopt;
  }
  auto next = parse_checkpoint_commitment_value(handoff.next_checkpoint);
  if (!next.has_value() || next->epoch_start_height != next_epoch_start || next->ordered_members.empty()) {
    fail(error, "handoff-checkpoint-invalid");
    return std::nullopt;
  }
  return next;
}

}  // namespace finalis::consensus
