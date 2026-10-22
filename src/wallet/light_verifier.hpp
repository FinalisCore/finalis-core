// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common/network.hpp"
#include "consensus/light_client.hpp"
#include "genesis/genesis.hpp"
#include "utxo/tx.hpp"

namespace finalis::wallet {

// What a finalized height says about an outpoint the client was told about.
enum class UtxoProofStatus : std::uint8_t {
  Unspent = 1,    // in the UTXO set, with exactly the expected contents
  Spent = 2,      // provably absent
  Different = 3,  // present, but not what the client was told (the reporting server misdescribed it)
};

struct VerifiedUtxos {
  std::uint64_t height{0};  // highest finalized height the statuses were proven at
  std::vector<UtxoProofStatus> statuses;  // one per requested outpoint, in order
};

// Leaf of a transparent output in the UTXO commitment tree.
Bytes transparent_utxo_leaf(std::uint64_t value, const Bytes& script_pubkey);
// The UTXO-tree leaf of output `vout` of a serialized transaction; nullopt if unparseable or out of range.
std::optional<Bytes> utxo_leaf_for_output(const Bytes& tx_bytes, std::uint32_t vout);

// Checks lightserver answers against validator signatures instead of trusting the server. Trust
// starts at the genesis compiled into the binary; each epoch's committee is learned from the previous
// one through CommitteeHandoffs (consensus/light_client.hpp), so no server can introduce a committee.
class LightVerifier {
 public:
  // From the genesis this binary embeds for `network`; nullopt when it embeds none or it names no validators.
  static std::optional<LightVerifier> for_network(const NetworkConfig& network, std::string* error = nullptr);
  static std::optional<LightVerifier> from_genesis(const NetworkConfig& network, const genesis::Document& doc,
                                                   const Hash32& genesis_bin_hash, std::string* error = nullptr);

  // Proven checkpoints, so a restart resumes instead of walking from genesis. load() accepts only state
  // saved for this chain and keeps the current state on any failure. The saved bytes are trusted: keep
  // them with the wallet's own data, never take them from a server.
  Bytes save() const;
  bool load(const Bytes& saved);

  std::uint64_t trusted_epoch_start() const { return checkpoints_.rbegin()->first; }

  // Proves committees through the epoch of `height` with handoffs from `rpc_url`. Progress made before a
  // failure is kept. *server_fault is set when the server sent something that does not verify (as
  // opposed to being unreachable or lacking data): it is lying or broken.
  bool sync_to(const std::string& rpc_url, std::uint64_t height, std::string* error = nullptr,
               bool* server_fault = nullptr);

  // Checks, at a finalized height whose certificate this verifier accepts, that each outpoint holds
  // `expected` (its UTXO-tree leaf). nullopt on transport failure or any invalid proof; a server that
  // sends an invalid proof is lying or broken.
  std::optional<VerifiedUtxos> verify_utxos(const std::string& rpc_url,
                                            const std::vector<std::pair<OutPoint, Bytes>>& expected,
                                            std::string* error = nullptr, bool* server_fault = nullptr);

 private:
  LightVerifier() = default;
  void remember(storage::FinalizedCommitteeCheckpoint checkpoint);

  consensus::LightClientParams params_;
  Hash32 genesis_hash_{};
  std::map<std::uint64_t, storage::FinalizedCommitteeCheckpoint> checkpoints_;  // latest few, by epoch start
};

}  // namespace finalis::wallet
