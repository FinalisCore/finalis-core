#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "storage/db.hpp"

namespace finalis::storage {

struct SnapshotManifest {
  std::uint32_t format_version{1};
  Hash32 genesis_hash{};
  Hash32 genesis_artifact_id{};
  std::uint64_t finalized_height{0};
  Hash32 finalized_hash{};
  Hash32 utxo_root{};
  Hash32 validators_root{};
  // Namespace-specific counts make the first implementation-first snapshot
  // format self-checking without claiming protocol-grade checkpoint semantics.
  std::uint64_t entry_count{0};
  std::uint64_t metadata_count{0};
  std::uint64_t height_index_count{0};
  std::uint64_t certificate_count{0};
  std::uint64_t utxo_count{0};
  std::uint64_t validator_count{0};
  std::uint64_t tx_index_count{0};
  std::uint64_t script_utxo_count{0};
  std::uint64_t script_history_count{0};
  std::uint64_t root_index_count{0};
  std::uint64_t smt_leaf_count{0};
  std::uint64_t smt_root_count{0};
  std::uint64_t liveness_metadata_count{0};

  Bytes serialize() const;
  static std::optional<SnapshotManifest> parse(const Bytes& b);
};

struct SnapshotEntry {
  std::string key;
  Bytes value;
};

struct SnapshotBundle {
  SnapshotManifest manifest;
  std::vector<SnapshotEntry> entries;

  Bytes serialize() const;
  static std::optional<SnapshotBundle> parse(const Bytes& b);
};

bool export_snapshot_bundle(const DB& db, const std::string& path, SnapshotManifest* manifest_out = nullptr,
                            std::string* err = nullptr);
// The first import slice is intentionally conservative: import into an empty DB
// only and let existing startup paths consume the resulting keyspace.
bool import_snapshot_bundle(DB& db, const std::string& path, SnapshotManifest* manifest_out = nullptr,
                            std::string* err = nullptr);

}  // namespace finalis::storage
