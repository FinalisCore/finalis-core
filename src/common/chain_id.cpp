#include "common/chain_id.hpp"

#include <algorithm>

#include "genesis/embedded_mainnet.hpp"

namespace finalis {
namespace {

std::optional<Hash32> expected_genesis_hash(const NetworkConfig& cfg, const std::optional<genesis::Document>& doc) {
  if (doc.has_value()) return genesis::hash_doc(*doc);
  if (cfg.name == "mainnet") return genesis::MAINNET_GENESIS_HASH;
  return std::nullopt;
}

std::string default_genesis_source(const NetworkConfig& cfg, const std::optional<genesis::Document>& doc) {
  if (doc.has_value()) return "file";
  if (cfg.name == "mainnet") return "embedded";
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

}  // namespace finalis
