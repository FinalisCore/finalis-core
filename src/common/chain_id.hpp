#pragma once

#include <optional>
#include <string>

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

}  // namespace finalis
