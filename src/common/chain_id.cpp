// SPDX-License-Identifier: MIT

#include "common/chain_id.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "common/types.hpp"
#include "crypto/hash.hpp"
#include "genesis/embedded.hpp"

namespace finalis {
namespace {

std::optional<Hash32> expected_genesis_hash(const NetworkConfig& cfg, const std::optional<genesis::Document>& doc) {
  if (doc.has_value()) return genesis::hash_doc(*doc);
  if (auto embedded = genesis::embedded_genesis_for(cfg.name)) return embedded->hash;
  return std::nullopt;
}

std::string default_genesis_source(const NetworkConfig& cfg, const std::optional<genesis::Document>& doc) {
  if (doc.has_value()) return "file";
  if (genesis::embedded_genesis_for(cfg.name).has_value()) return "embedded";
  return "file";
}

}  // namespace

ChainId ChainId::from_config_and_db(const NetworkConfig& cfg, const storage::DB& db,
                                    const std::optional<genesis::Document>& genesis_used,
                                    const std::string& genesis_source_hint,
                                    const std::optional<Hash32>& expected_genesis_hash_override) {
  ChainId out;
  out.network_name = cfg.name;
  out.magic = cfg.magic;
  out.protocol_version = cfg.protocol_version;
  out.network_id_hex = hex_encode(Bytes(cfg.network_id.begin(), cfg.network_id.end()));

  const auto expected =
      expected_genesis_hash_override.has_value() ? expected_genesis_hash_override : expected_genesis_hash(cfg, genesis_used);
  const std::string expected_source =
      genesis_source_hint.empty() ? default_genesis_source(cfg, genesis_used) : genesis_source_hint;

  if (expected.has_value()) {
    out.expected_genesis_hash_hex = hex_encode32(*expected);
  }

  const auto db_marker = db.get(storage::key_genesis_hash());
  if (db_marker.has_value() && db_marker->size() == 32) {
    Hash32 db_hash{};
    std::copy(db_marker->begin(), db_marker->end(), db_hash.begin());
    out.db_genesis_hash_hex = hex_encode32(db_hash);
    out.genesis_hash_hex = out.db_genesis_hash_hex;
    out.genesis_source = "db";
  } else if (expected.has_value()) {
    out.genesis_hash_hex = hex_encode32(*expected);
    out.genesis_source = expected_source;
  } else {
    out.genesis_hash_hex = hex_encode32(zero_hash());
    out.genesis_source = expected_source;
  }

  if (!out.db_genesis_hash_hex.empty() && !out.expected_genesis_hash_hex.empty()) {
    out.chain_id_ok = (out.db_genesis_hash_hex == out.expected_genesis_hash_hex);
  } else {
    out.chain_id_ok = true;
  }

  return out;
}

ChainIdMismatch compare_chain_identity(const ChainId& a, const ChainId& b) {
  ChainIdMismatch out;
  out.network_id_differs = (a.network_id_hex != b.network_id_hex);
  out.genesis_hash_differs = (a.genesis_hash_hex != b.genesis_hash_hex);
  out.protocol_version_differs = (a.protocol_version != b.protocol_version);
  out.magic_differs = (a.magic != b.magic);
  out.match =
      !(out.network_id_differs || out.genesis_hash_differs || out.protocol_version_differs || out.magic_differs);
  return out;
}

std::string consensus_rules_fingerprint(const NetworkConfig& cfg, const ChainId& chain_id, std::uint32_t cv,
                                        std::uint64_t next_height, std::vector<Hash32> active_upgrades) {
  codec::ByteWriter w;
  w.bytes_fixed(cfg.network_id);
  w.u32le(cfg.protocol_version);
  w.u64le(cfg.feature_flags);
  w.u64le(cfg.magic);
  w.u64le(cfg.committee_epoch_blocks);
  w.u32le(cfg.max_committee);
  w.u32le(cv);
  const auto genesis = hex_decode(chain_id.genesis_hash_hex);
  if (genesis.has_value() && genesis->size() == 32) {
    Hash32 g{};
    std::copy(genesis->begin(), genesis->end(), g.begin());
    w.bytes_fixed(g);
  } else {
    w.bytes_fixed(zero_hash());
  }
  // Ingress certifier rules (C1): nodes that disagree on terms reject each other's certificates.
  w.u64le(cfg.ingress_certifier_term_blocks);
  w.u64le(cfg.ingress_certifier_liveness_blocks);
  if (next_height >= cfg.upgrade_signal_activation_height) {
    const std::string tag = "signals";
    w.varbytes(Bytes(tag.begin(), tag.end()));
    w.u64le(cfg.upgrade_signal_activation_height);
    w.u64le(cfg.upgrade_signal_window_blocks);
  }
  if (!active_upgrades.empty()) {
    std::sort(active_upgrades.begin(), active_upgrades.end());
    active_upgrades.erase(std::unique(active_upgrades.begin(), active_upgrades.end()), active_upgrades.end());
    const std::string tag = "upgrades";
    w.varbytes(Bytes(tag.begin(), tag.end()));
    w.varint(active_upgrades.size());
    for (const auto& id : active_upgrades) w.bytes_fixed(id);
  }
  return hex_encode32(crypto::sha256d(w.data()));
}

std::vector<std::string> reachable_consensus_rules_fingerprints(const NetworkConfig& cfg, const ChainId& chain_id,
                                                                std::uint32_t cv, std::uint64_t next_height,
                                                                const std::vector<Hash32>& active_upgrades,
                                                                const std::vector<Hash32>& known_upgrades) {
  std::vector<Hash32> pending;
  for (const auto& id : known_upgrades) {
    if (std::find(active_upgrades.begin(), active_upgrades.end(), id) == active_upgrades.end() &&
        std::find(pending.begin(), pending.end(), id) == pending.end()) {
      pending.push_back(id);
    }
  }
  if (pending.size() > 8) pending.resize(8);
  std::vector<std::uint64_t> heights{next_height};
  if (cfg.upgrade_signal_activation_height > next_height) heights.push_back(cfg.upgrade_signal_activation_height);
  std::vector<std::string> out;
  for (const auto h : heights) {
    for (std::size_t mask = 0; mask < (std::size_t{1} << pending.size()); ++mask) {
      auto active = active_upgrades;
      for (std::size_t i = 0; i < pending.size(); ++i) {
        if (mask & (std::size_t{1} << i)) active.push_back(pending[i]);
      }
      out.push_back(consensus_rules_fingerprint(cfg, chain_id, cv, h, std::move(active)));
    }
  }
  return out;
}

bool peer_consensus_rules_fingerprint_acceptable(const std::string& peer_crh, std::uint64_t peer_next_height,
                                                 std::uint64_t local_next_height, const std::string& local_crh,
                                                 const std::function<std::string(std::uint64_t)>& fingerprint_at,
                                                 const std::function<std::vector<std::string>()>& reachable) {
  if (peer_crh == local_crh) return true;
  if (peer_next_height < local_next_height) return peer_crh == fingerprint_at(peer_next_height);
  if (peer_next_height > local_next_height) {
    const auto all = reachable();
    return std::find(all.begin(), all.end(), peer_crh) != all.end();
  }
  return false;
}

}  // namespace finalis
