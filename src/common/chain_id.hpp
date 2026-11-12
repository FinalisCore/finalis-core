// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "network.hpp"
#include "common/types.hpp"
#include "genesis/genesis.hpp"
#include "storage/db.hpp"

namespace finalis {

struct ChainId {
  std::string network_name;
  std::uint32_t magic{0};
  std::string network_id_hex;
  std::uint32_t protocol_version{0};
  std::string genesis_hash_hex;
  std::string genesis_source;
  bool chain_id_ok{true};
  std::string expected_genesis_hash_hex;
  std::string db_genesis_hash_hex;

  static ChainId from_config_and_db(const NetworkConfig& cfg, const storage::DB& db,
                                    const std::optional<genesis::Document>& genesis_used = std::nullopt,
                                    const std::string& genesis_source_hint = "",
                                    const std::optional<Hash32>& expected_genesis_hash_override = std::nullopt);
};

struct ChainIdMismatch {
  bool match{true};
  bool network_id_differs{false};
  bool genesis_hash_differs{false};
  bool protocol_version_differs{false};
  bool magic_differs{false};
};

ChainIdMismatch compare_chain_identity(const ChainId& a, const ChainId& b);

// Fingerprint of the rules two peers must share (advertised as crh= in VERSION; a mismatch is
// disconnected). One implementation for the node and the lightserver relay, so they cannot drift.
// The rules at `next_height` (SIGNALED_ACTIVATION §3.5). `cv` is the validation rules version.
// From `upgrade_signal_activation_height` on it covers the signal rules (that height and
// `upgrade_signal_window_blocks`); `active_upgrades` are the ids of the signaled upgrades active at
// `next_height` that this binary implements, in any order. Below the signal activation height and with
// no active upgrade it is the fingerprint from before signaled activation existed, so old and new
// binaries connect until then and disconnect from then on.
std::string consensus_rules_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv,
                                        std::uint64_t next_height, std::vector<Hash32> active_upgrades = {});

// Every fingerprint this binary can have at a height >= `next_height`: the upgrades active now stay
// active, any of `known_upgrades` may activate, and signal rules switch on at their height. A peer
// ahead of the local tip legitimately advertises one of these (at most 2^8 upgrade subsets are listed).
std::vector<std::string> reachable_consensus_rules_fingerprints(const NetworkConfig& cfg, const ChainId& chain_id,
                                                                std::uint32_t cv, std::uint64_t next_height,
                                                                const std::vector<Hash32>& active_upgrades,
                                                                const std::vector<Hash32>& known_upgrades);

// Handshake rule: a peer's fingerprint is accepted if it is the one its own tip calls for. A peer at or
// below the local tip is checked exactly against `fingerprint_at(peer_next_height)`; a peer ahead is
// checked against the fingerprints this binary can reach (`reachable`), since the local node cannot
// know what activated above its tip. A fingerprint is a peer filter: blocks are validated regardless.
bool peer_consensus_rules_fingerprint_acceptable(const std::string& peer_crh, std::uint64_t peer_next_height,
                                                 std::uint64_t local_next_height, const std::string& local_crh,
                                                 const std::function<std::string(std::uint64_t)>& fingerprint_at,
                                                 const std::function<std::vector<std::string>()>& reachable);

}  // namespace finalis
