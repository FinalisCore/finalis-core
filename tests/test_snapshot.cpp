// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_paths.hpp"

#include <algorithm>
#include <filesystem>
#include <optional>

#include "codec/bytes.hpp"
#include "storage/db.hpp"
#include "storage/snapshot.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

std::string unique_snapshot_path(const std::string& stem) {
  return finalis::test::unique_test_base("/tmp/" + stem);
}

// Minimal DB that passes export and validate_bundle: genesis markers, tip, roots and
// the finalized height/frontier/certificate records at height 0.
void populate_minimal_finalized_db(storage::DB* db, const Hash32& genesis_hash) {
  Hash32 genesis_artifact_id{};
  genesis_artifact_id.fill(0x02);
  Hash32 tip_hash{};
  tip_hash.fill(0x03);
  Hash32 root{};
  root.fill(0x04);
  ASSERT_TRUE(db->put(storage::key_genesis_hash(), Bytes(genesis_hash.begin(), genesis_hash.end())));
  ASSERT_TRUE(db->put(storage::key_genesis_artifact(), Bytes(genesis_artifact_id.begin(), genesis_artifact_id.end())));
  ASSERT_TRUE(db->set_tip(storage::TipState{0, tip_hash}));
  ASSERT_TRUE(db->put(storage::key_root_index("UTXO", 0), Bytes(root.begin(), root.end())));
  ASSERT_TRUE(db->put(storage::key_root_index("VAL", 0), Bytes(root.begin(), root.end())));
  ASSERT_TRUE(db->set_height_hash(0, tip_hash));
  ASSERT_TRUE(db->put(storage::key_frontier_height(0), Bytes(tip_hash.begin(), tip_hash.end())));
  ASSERT_TRUE(db->put(storage::key_frontier_transition(tip_hash), Bytes{0x01}));
  ASSERT_TRUE(db->put(storage::key_finality_certificate_height(0), Bytes{0x01}));
  ASSERT_TRUE(db->flush());
}

// Exports a minimal snapshot bound to genesis_hash; returns the snapshot path.
std::string export_minimal_snapshot(const std::string& stem, const Hash32& genesis_hash) {
  const std::string src_db_path = unique_snapshot_path(stem + "_src_db");
  const std::string snapshot_path = unique_snapshot_path(stem + ".bin");
  std::filesystem::remove_all(src_db_path);
  std::filesystem::remove(snapshot_path);
  storage::DB src;
  if (!src.open(src_db_path)) return {};
  populate_minimal_finalized_db(&src, genesis_hash);
  std::string err;
  if (!storage::export_snapshot_bundle(src, snapshot_path, nullptr, &err)) return {};
  return snapshot_path;
}

}  // namespace

TEST(test_snapshot_manifest_serialize_roundtrip) {
  storage::SnapshotManifest manifest;
  manifest.format_version = 2;
  manifest.genesis_hash.fill(0x11);
  manifest.genesis_artifact_id.fill(0x22);
  manifest.finalized_height = 42;
  manifest.finalized_hash.fill(0x33);
  manifest.utxo_root.fill(0x44);
  manifest.validators_root.fill(0x55);
  manifest.entry_count = 12;
  manifest.metadata_count = 4;
  manifest.height_index_count = 2;
  manifest.certificate_count = 1;
  manifest.utxo_count = 8;
  manifest.validator_count = 2;
  manifest.tx_index_count = 5;
  manifest.script_utxo_count = 6;
  manifest.script_history_count = 7;
  manifest.root_index_count = 8;
  manifest.smt_leaf_count = 9;
  manifest.smt_root_count = 10;
  manifest.liveness_metadata_count = 11;

  const auto bytes = manifest.serialize();
  auto parsed = storage::SnapshotManifest::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->format_version, manifest.format_version);
  ASSERT_EQ(parsed->genesis_hash, manifest.genesis_hash);
  ASSERT_EQ(parsed->genesis_artifact_id, manifest.genesis_artifact_id);
  ASSERT_EQ(parsed->finalized_height, manifest.finalized_height);
  ASSERT_EQ(parsed->finalized_hash, manifest.finalized_hash);
  ASSERT_EQ(parsed->utxo_root, manifest.utxo_root);
  ASSERT_EQ(parsed->validators_root, manifest.validators_root);
  ASSERT_EQ(parsed->entry_count, manifest.entry_count);
  ASSERT_EQ(parsed->metadata_count, manifest.metadata_count);
  ASSERT_EQ(parsed->height_index_count, manifest.height_index_count);
  ASSERT_EQ(parsed->certificate_count, manifest.certificate_count);
  ASSERT_EQ(parsed->utxo_count, manifest.utxo_count);
  ASSERT_EQ(parsed->validator_count, manifest.validator_count);
  ASSERT_EQ(parsed->tx_index_count, manifest.tx_index_count);
  ASSERT_EQ(parsed->script_utxo_count, manifest.script_utxo_count);
  ASSERT_EQ(parsed->script_history_count, manifest.script_history_count);
  ASSERT_EQ(parsed->root_index_count, manifest.root_index_count);
  ASSERT_EQ(parsed->smt_leaf_count, manifest.smt_leaf_count);
  ASSERT_EQ(parsed->smt_root_count, manifest.smt_root_count);
  ASSERT_EQ(parsed->liveness_metadata_count, manifest.liveness_metadata_count);
}

TEST(test_snapshot_import_rejects_nonempty_db) {
  const std::string src_db_path = unique_snapshot_path("finalis_snapshot_src_db");
  const std::string dst_db_path = unique_snapshot_path("finalis_snapshot_dst_nonempty_db");
  const std::string snapshot_path = unique_snapshot_path("finalis_snapshot_nonempty.bin");
  std::filesystem::remove_all(src_db_path);
  std::filesystem::remove_all(dst_db_path);
  std::filesystem::remove(snapshot_path);

  storage::DB src;
  ASSERT_TRUE(src.open(src_db_path));
  Hash32 genesis_hash{};
  genesis_hash.fill(0x01);
  Hash32 genesis_artifact_id{};
  genesis_artifact_id.fill(0x02);
  Hash32 tip_hash{};
  tip_hash.fill(0x03);
  Hash32 root{};
  root.fill(0x04);
  ASSERT_TRUE(src.put(storage::key_genesis_hash(), Bytes(genesis_hash.begin(), genesis_hash.end())));
  ASSERT_TRUE(src.put(storage::key_genesis_artifact(), Bytes(genesis_artifact_id.begin(), genesis_artifact_id.end())));
  ASSERT_TRUE(src.set_tip(storage::TipState{0, tip_hash}));
  ASSERT_TRUE(src.put(storage::key_root_index("UTXO", 0), Bytes(root.begin(), root.end())));
  ASSERT_TRUE(src.put(storage::key_root_index("VAL", 0), Bytes(root.begin(), root.end())));
  ASSERT_TRUE(src.set_height_hash(0, tip_hash));
  ASSERT_TRUE(src.flush());

  storage::SnapshotManifest manifest;
  std::string err;
  ASSERT_TRUE(storage::export_snapshot_bundle(src, snapshot_path, &manifest, &err));

  storage::DB dst;
  ASSERT_TRUE(dst.open(dst_db_path));
  ASSERT_TRUE(dst.put("occupied", Bytes{0x01}));
  ASSERT_TRUE(dst.flush());

  storage::SnapshotManifest imported;
  ASSERT_TRUE(!storage::import_snapshot_bundle(dst, snapshot_path, std::nullopt, &imported, &err));
  ASSERT_TRUE(err.find("empty db") != std::string::npos);
}

TEST(test_snapshot_import_accepts_matching_genesis) {
  Hash32 genesis_hash{};
  genesis_hash.fill(0x01);
  const auto snapshot_path = export_minimal_snapshot("finalis_snapshot_genesis_match", genesis_hash);
  ASSERT_TRUE(!snapshot_path.empty());

  const std::string dst_db_path = unique_snapshot_path("finalis_snapshot_genesis_match_dst_db");
  std::filesystem::remove_all(dst_db_path);
  storage::DB dst;
  ASSERT_TRUE(dst.open(dst_db_path));

  storage::SnapshotManifest imported;
  std::string err;
  ASSERT_TRUE(storage::import_snapshot_bundle(dst, snapshot_path, genesis_hash, &imported, &err));
  ASSERT_EQ(imported.genesis_hash, genesis_hash);
  const auto stored = dst.get(storage::key_genesis_hash());
  ASSERT_TRUE(stored.has_value());
  ASSERT_TRUE(std::equal(stored->begin(), stored->end(), genesis_hash.begin()));
}

TEST(test_snapshot_import_rejects_genesis_mismatch_without_writing) {
  Hash32 snapshot_genesis{};
  snapshot_genesis.fill(0x01);
  Hash32 node_genesis{};
  node_genesis.fill(0x7e);
  const auto snapshot_path = export_minimal_snapshot("finalis_snapshot_genesis_mismatch", snapshot_genesis);
  ASSERT_TRUE(!snapshot_path.empty());

  std::string err;
  ASSERT_TRUE(!storage::inspect_snapshot_bundle(snapshot_path, node_genesis, nullptr, &err));
  ASSERT_TRUE(err.find("snapshot genesis mismatch; reject import") != std::string::npos);

  const std::string dst_db_path = unique_snapshot_path("finalis_snapshot_genesis_mismatch_dst_db");
  std::filesystem::remove_all(dst_db_path);
  storage::DB dst;
  ASSERT_TRUE(dst.open(dst_db_path));

  storage::SnapshotManifest imported;
  err.clear();
  ASSERT_TRUE(!storage::import_snapshot_bundle(dst, snapshot_path, node_genesis, &imported, &err));
  ASSERT_TRUE(err.find("snapshot genesis mismatch; reject import") != std::string::npos);
  ASSERT_TRUE(dst.scan_prefix("").empty());
}
