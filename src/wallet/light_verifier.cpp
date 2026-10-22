// SPDX-License-Identifier: MIT

#include "wallet/light_verifier.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "consensus/randomness.hpp"
#include "consensus/state_commitment.hpp"
#include "crypto/smt.hpp"
#include "genesis/embedded.hpp"
#include "lightserver/client.hpp"
#include "utxo/confidential_tx.hpp"

namespace finalis::wallet {
namespace {

constexpr std::uint8_t kSavedStateVersion = 1;
// Enough to check servers a few epochs behind; older ones are of no use to a wallet.
constexpr std::size_t kKeptCheckpoints = 16;
constexpr std::size_t kMaxOutpointsPerRequest = 256;
constexpr std::uint64_t kHandoffsPerRequest = 64;

bool fail(std::string* error, std::string reason) {
  if (error) *error = std::move(reason);
  return false;
}

// A failure caused by what the server sent, not by reaching it.
bool fault(std::string* error, bool* server_fault, std::string reason) {
  if (server_fault) *server_fault = true;
  return fail(error, std::move(reason));
}

}  // namespace

Bytes transparent_utxo_leaf(std::uint64_t value, const Bytes& script_pubkey) {
  TxOut out;
  out.value = value;
  out.script_pubkey = script_pubkey;
  return consensus::utxo_commitment_value(UtxoEntryV2(out));
}

std::optional<Bytes> utxo_leaf_for_output(const Bytes& tx_bytes, std::uint32_t vout) {
  const auto tx = parse_any_tx(tx_bytes);
  if (!tx.has_value()) return std::nullopt;
  if (const auto* legacy = std::get_if<Tx>(&*tx)) {
    if (vout >= legacy->outputs.size()) return std::nullopt;
    return transparent_utxo_leaf(legacy->outputs[vout].value, legacy->outputs[vout].script_pubkey);
  }
  const auto& v2 = std::get<TxV2>(*tx);
  if (vout >= v2.outputs.size()) return std::nullopt;
  const auto& out = v2.outputs[vout];
  if (out.kind == TxOutputKind::Transparent) {
    const auto& transparent = std::get<TransparentTxOutV2>(out.body);
    return transparent_utxo_leaf(transparent.value, transparent.script_pubkey);
  }
  // As validation records a confidential output in the UTXO set.
  const auto& confidential = std::get<ConfidentialTxOutV2>(out.body);
  UtxoEntryV2 entry;
  entry.kind = UtxoOutputKind::Confidential;
  entry.body = UtxoConfidentialData{
      .value_commitment = confidential.value_commitment,
      .one_time_pubkey = confidential.one_time_pubkey,
      .ephemeral_pubkey = confidential.ephemeral_pubkey,
      .scan_tag = confidential.scan_tag,
      .memo = confidential.memo,
  };
  return consensus::utxo_commitment_value(entry);
}

std::optional<LightVerifier> LightVerifier::for_network(const NetworkConfig& network, std::string* error) {
  const auto embedded = genesis::embedded_genesis_for(network.name);
  if (!embedded.has_value()) {
    fail(error, "no genesis embedded for " + network.name);
    return std::nullopt;
  }
  const Bytes bin(embedded->data, embedded->data + embedded->len);
  const auto doc = genesis::decode_bin(bin, error);
  if (!doc.has_value()) return std::nullopt;
  return from_genesis(network, *doc, genesis::hash_bin(bin), error);
}

std::optional<LightVerifier> LightVerifier::from_genesis(const NetworkConfig& network, const genesis::Document& doc,
                                                         const Hash32& genesis_bin_hash, std::string* error) {
  if (doc.initial_validators.empty()) {
    fail(error, "genesis names no validators");
    return std::nullopt;
  }
  auto checkpoint = consensus::genesis_committee_checkpoint(network, doc, genesis_bin_hash, error);
  if (!checkpoint.has_value()) return std::nullopt;
  LightVerifier v;
  v.params_ = consensus::light_client_params(network, consensus::chain_id_for_genesis(network, genesis_bin_hash));
  v.genesis_hash_ = genesis_bin_hash;
  v.remember(std::move(*checkpoint));
  return v;
}

void LightVerifier::remember(storage::FinalizedCommitteeCheckpoint checkpoint) {
  const auto epoch = checkpoint.epoch_start_height;
  checkpoints_[epoch] = std::move(checkpoint);
  while (checkpoints_.size() > kKeptCheckpoints) checkpoints_.erase(checkpoints_.begin());
}

Bytes LightVerifier::save() const {
  codec::ByteWriter w;
  w.u8(kSavedStateVersion);
  w.bytes_fixed(genesis_hash_);
  w.u64le(params_.epoch_blocks);
  w.varint(checkpoints_.size());
  for (const auto& [epoch, checkpoint] : checkpoints_) w.varbytes(consensus::checkpoint_commitment_value(checkpoint));
  return w.take();
}

bool LightVerifier::load(const Bytes& saved) {
  std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint> loaded;
  const bool ok = codec::parse_exact(saved, [&](codec::ByteReader& r) {
    const auto version = r.u8();
    const auto genesis = r.bytes_fixed<32>();
    const auto epoch_blocks = r.u64le();
    const auto count = r.varint();
    if (!version || *version != kSavedStateVersion || !genesis || *genesis != genesis_hash_ || !epoch_blocks ||
        *epoch_blocks != params_.epoch_blocks || !count || *count == 0 || *count > kKeptCheckpoints) {
      return false;
    }
    for (std::uint64_t i = 0; i < *count; ++i) {
      const auto bytes = r.varbytes();
      auto checkpoint = bytes ? consensus::parse_checkpoint_commitment_value(*bytes) : std::nullopt;
      if (!checkpoint || checkpoint->ordered_members.empty() ||
          consensus::committee_epoch_start(checkpoint->epoch_start_height, params_.epoch_blocks) !=
              checkpoint->epoch_start_height) {
        return false;
      }
      loaded[checkpoint->epoch_start_height] = std::move(*checkpoint);
    }
    return true;
  });
  if (!ok) return false;
  // Never step back: a saved state older than what this verifier already proved adds nothing.
  if (loaded.rbegin()->first < trusted_epoch_start()) return false;
  checkpoints_ = std::move(loaded);
  return true;
}

bool LightVerifier::sync_to(const std::string& rpc_url, std::uint64_t height, std::string* error, bool* server_fault) {
  const std::uint64_t target = consensus::committee_epoch_start(height, params_.epoch_blocks);
  while (trusted_epoch_start() < target) {
    const std::uint64_t from = trusted_epoch_start();
    std::string rpc_error;
    const auto page = lightserver::rpc_get_committee_handoffs(rpc_url, from, kHandoffsPerRequest, &rpc_error);
    if (!page.has_value()) return fail(error, "get_committee_handoffs: " + rpc_error);
    if (page->epoch_blocks != params_.epoch_blocks) return fault(error, server_fault, "server reports a different epoch length");
    if (page->handoffs.empty()) {
      return fail(error, "server has no committee handoff after epoch " + std::to_string(from));
    }
    for (const auto& [next, bytes] : page->handoffs) {
      if (next != trusted_epoch_start() + params_.epoch_blocks) {
        return fault(error, server_fault, "committee handoffs out of order");
      }
      const auto handoff = consensus::CommitteeHandoff::parse(bytes);
      if (!handoff.has_value()) return fault(error, server_fault, "committee handoff unparseable");
      std::string verify_error;
      auto proven = consensus::verify_committee_handoff(params_, checkpoints_.rbegin()->second, *handoff, &verify_error);
      if (!proven.has_value()) {
        return fault(error, server_fault,
                     "committee handoff for epoch " + std::to_string(next) + " rejected: " + verify_error);
      }
      remember(std::move(*proven));
      if (trusted_epoch_start() >= target) break;
    }
  }
  return true;
}

std::optional<VerifiedUtxos> LightVerifier::verify_utxos(const std::string& rpc_url,
                                                         const std::vector<std::pair<OutPoint, Bytes>>& expected,
                                                         std::string* error, bool* server_fault) {
  VerifiedUtxos out;
  out.statuses.reserve(expected.size());
  for (std::size_t start = 0; start < expected.size(); start += kMaxOutpointsPerRequest) {
    const std::size_t end = std::min(expected.size(), start + kMaxOutpointsPerRequest);
    std::vector<OutPoint> outpoints;
    for (std::size_t i = start; i < end; ++i) outpoints.push_back(expected[i].first);
    std::string rpc_error;
    const auto page = lightserver::rpc_get_utxo_proofs(rpc_url, outpoints, &rpc_error);
    if (!page.has_value()) {
      fail(error, "get_utxo_proofs: " + rpc_error);
      return std::nullopt;
    }
    const auto transition = FrontierTransition::parse(page->transition);
    const auto certificate = FinalityCertificate::parse(page->certificate);
    if (!transition || !certificate || transition->height != page->height || page->proofs.size() != outpoints.size()) {
      fault(error, server_fault, "malformed utxo proof response");
      return std::nullopt;
    }
    if (!sync_to(rpc_url, page->height, error, server_fault)) return std::nullopt;
    const auto epoch = consensus::committee_epoch_start(page->height, params_.epoch_blocks);
    const auto checkpoint = checkpoints_.find(epoch);
    if (checkpoint == checkpoints_.end()) {
      fail(error, "server is too far behind (height " + std::to_string(page->height) + ")");
      return std::nullopt;
    }
    std::string verify_error;
    if (!consensus::verify_light_finality(params_, checkpoint->second, *transition, *certificate, &verify_error)) {
      fault(error, server_fault, "finality certificate rejected: " + verify_error);
      return std::nullopt;
    }
    for (std::size_t i = 0; i < outpoints.size(); ++i) {
      const auto& item = page->proofs[i];
      const auto proof = crypto::SparseMerkleTree::decode_compact_proof(item.compact_proof);
      if (item.outpoint.txid != outpoints[i].txid || item.outpoint.index != outpoints[i].index || !proof.has_value() ||
          !crypto::SparseMerkleTree::verify_proof(transition->next_state_root,
                                                  consensus::utxo_commitment_key(outpoints[i]), item.value, *proof)) {
        fault(error, server_fault, "invalid utxo proof");
        return std::nullopt;
      }
      if (!item.value.has_value()) {
        out.statuses.push_back(UtxoProofStatus::Spent);
      } else {
        out.statuses.push_back(*item.value == expected[start + i].second ? UtxoProofStatus::Unspent
                                                                         : UtxoProofStatus::Different);
      }
    }
    out.height = std::max(out.height, page->height);
  }
  return out;
}

}  // namespace finalis::wallet
