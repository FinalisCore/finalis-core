#include "storage/snapshot.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <set>

#include "codec/bytes.hpp"

namespace finalis::storage {
namespace {

constexpr std::uint32_t kSnapshotFormatVersion = 2;
const Bytes kSnapshotMagic{'S', 'C', 'S', 'N', 'A', 'P', '0', '1'};

std::optional<TipState> parse_tip_bytes(const Bytes& b) {
  TipState tip;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!h || !hash) return false;
        tip.height = *h;
        tip.hash = *hash;
        return true;
      })) {
    return std::nullopt;
  }
  return tip;
}

void add_exact_key(const DB& db, std::map<std::string, Bytes>* out, const std::string& key) {
  if (auto value = db.get(key); value.has_value()) (*out)[key] = *value;
}

void add_prefix(const DB& db, std::map<std::string, Bytes>* out, const std::string& prefix, bool skip_empty_values = false) {
  for (const auto& [key, value] : db.scan_prefix(prefix)) {
    if (skip_empty_values && value.empty()) continue;
    (*out)[key] = value;
  }
}

struct SnapshotCounts {
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
};

SnapshotCounts classify_entries(const std::vector<SnapshotEntry>& entries) {
  SnapshotCounts counts;
  for (const auto& entry : entries) {
    const auto& key = entry.key;
    if (key == key_genesis_hash() || key == key_genesis_artifact() || key == key_genesis_json() || key == key_tip() ||
        key == key_finalized_frontier_height()) {
      ++counts.metadata_count;
    } else if (key.rfind(key_frontier_transition_prefix(), 0) == 0) {
      ++counts.metadata_count;
    } else if (key.rfind("H:", 0) == 0) {
      ++counts.height_index_count;
    } else if (key.rfind(key_frontier_height_prefix(), 0) == 0) {
      ++counts.height_index_count;
    } else if (key.rfind(key_finality_certificate_height_prefix(), 0) == 0) {
      ++counts.certificate_count;
    } else if (key.rfind(key_utxo_prefix(), 0) == 0) {
      ++counts.utxo_count;
    } else if (key.rfind(key_validator_prefix(), 0) == 0) {
      ++counts.validator_count;
    } else if (key.rfind(key_txidx_prefix(), 0) == 0) {
      ++counts.tx_index_count;
    } else if (key.rfind(key_script_utxo_prefix(Hash32{}).substr(0, 3), 0) == 0) {
      ++counts.script_utxo_count;
    } else if (key.rfind(key_script_history_prefix(Hash32{}).substr(0, 3), 0) == 0) {
      ++counts.script_history_count;
    } else if (key.rfind(key_root_index_prefix(), 0) == 0) {
      ++counts.root_index_count;
    } else if (key.rfind(key_smt_leaf_prefix(""), 0) == 0) {
      ++counts.smt_leaf_count;
    } else if (key.rfind(key_smt_root_prefix(""), 0) == 0) {
      ++counts.smt_root_count;
    } else if (key.rfind(key_adaptive_epoch_telemetry_prefix(), 0) == 0) {
      ++counts.liveness_metadata_count;
    }
  }
  return counts;
}

bool read_file_bytes(const std::string& path, Bytes* out, std::string* err) {
  std::ifstream f(path, std::ios::binary);
  if (!f.good()) {
    if (err) *err = "failed to open snapshot file";
    return false;
  }
  f.seekg(0, std::ios::end);
  const auto size = f.tellg();
  if (size < 0) {
    if (err) *err = "failed to read snapshot size";
    return false;
  }
  out->resize(static_cast<std::size_t>(size));
  f.seekg(0, std::ios::beg);
  if (!out->empty()) f.read(reinterpret_cast<char*>(out->data()), static_cast<std::streamsize>(out->size()));
  if (!f.good() && !f.eof()) {
    if (err) *err = "failed to read snapshot bytes";
    return false;
  }
  return true;
}

bool write_file_bytes(const std::string& path, const Bytes& bytes, std::string* err) {
  const auto parent = std::filesystem::path(path).parent_path();
  if (!parent.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
  }
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f.good()) {
    if (err) *err = "failed to create snapshot file";
    return false;
  }
  if (!bytes.empty()) f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!f.good()) {
    if (err) *err = "failed to write snapshot file";
    return false;
  }
  return true;
}

std::optional<SnapshotBundle> build_snapshot_bundle(const DB& db, std::string* err) {
  const auto tip = db.get_tip();
  if (!tip.has_value()) {
    if (err) *err = "snapshot export requires a tip";
    return std::nullopt;
  }
  const auto genesis_hash = db.get(key_genesis_hash());
  const auto genesis_artifact_id = db.get(key_genesis_artifact());
  const auto utxo_root = db.get(key_root_index("UTXO", tip->height));
  const auto validators_root = db.get(key_root_index("VAL", tip->height));
  if (!genesis_hash.has_value() || genesis_hash->size() != 32) {
    if (err) *err = "snapshot export requires genesis hash marker";
    return std::nullopt;
  }
  if (!genesis_artifact_id.has_value() || genesis_artifact_id->size() != 32) {
    if (err) *err = "snapshot export requires genesis artifact marker";
    return std::nullopt;
  }
  if (!utxo_root.has_value() || utxo_root->size() != 32 || !validators_root.has_value() || validators_root->size() != 32) {
    if (err) *err = "snapshot export requires finalized state roots";
    return std::nullopt;
  }

  std::map<std::string, Bytes> kvs;
  add_exact_key(db, &kvs, key_genesis_hash());
  add_exact_key(db, &kvs, key_genesis_artifact());
  add_exact_key(db, &kvs, key_genesis_json());
  add_exact_key(db, &kvs, key_tip());
  add_exact_key(db, &kvs, key_finalized_frontier_height());
  add_prefix(db, &kvs, "H:");
  add_prefix(db, &kvs, key_frontier_height_prefix());
  add_prefix(db, &kvs, key_frontier_transition_prefix());
  add_prefix(db, &kvs, key_finality_certificate_height_prefix());
  add_prefix(db, &kvs, key_utxo_prefix());
  add_prefix(db, &kvs, key_validator_prefix());
  add_prefix(db, &kvs, key_txidx_prefix());
  add_prefix(db, &kvs, key_script_utxo_prefix(Hash32{}).substr(0, 3));
  add_prefix(db, &kvs, key_script_history_prefix(Hash32{}).substr(0, 3));
  add_prefix(db, &kvs, key_root_index_prefix());
  add_prefix(db, &kvs, key_smt_leaf_prefix("utxo"), true);
  add_prefix(db, &kvs, key_smt_leaf_prefix("validators"), true);
  add_prefix(db, &kvs, key_smt_root_prefix("utxo"));
  add_prefix(db, &kvs, key_smt_root_prefix("validators"));
  add_prefix(db, &kvs, key_adaptive_epoch_telemetry_prefix());

  SnapshotBundle bundle;
  bundle.entries.reserve(kvs.size());
  for (const auto& [key, value] : kvs) bundle.entries.push_back(SnapshotEntry{key, value});

  bundle.manifest.format_version = kSnapshotFormatVersion;
  std::copy(genesis_hash->begin(), genesis_hash->end(), bundle.manifest.genesis_hash.begin());
  std::copy(genesis_artifact_id->begin(), genesis_artifact_id->end(), bundle.manifest.genesis_artifact_id.begin());
  bundle.manifest.finalized_height = tip->height;
  bundle.manifest.finalized_hash = tip->hash;
  std::copy(utxo_root->begin(), utxo_root->end(), bundle.manifest.utxo_root.begin());
  std::copy(validators_root->begin(), validators_root->end(), bundle.manifest.validators_root.begin());
  bundle.manifest.entry_count = static_cast<std::uint64_t>(bundle.entries.size());
  const auto counts = classify_entries(bundle.entries);
  bundle.manifest.metadata_count = counts.metadata_count;
  bundle.manifest.height_index_count = counts.height_index_count;
  bundle.manifest.certificate_count = counts.certificate_count;
  bundle.manifest.utxo_count = counts.utxo_count;
  bundle.manifest.validator_count = counts.validator_count;
  bundle.manifest.tx_index_count = counts.tx_index_count;
  bundle.manifest.script_utxo_count = counts.script_utxo_count;
  bundle.manifest.script_history_count = counts.script_history_count;
  bundle.manifest.root_index_count = counts.root_index_count;
  bundle.manifest.smt_leaf_count = counts.smt_leaf_count;
  bundle.manifest.smt_root_count = counts.smt_root_count;
  bundle.manifest.liveness_metadata_count = counts.liveness_metadata_count;
  return bundle;
}

bool validate_bundle(const SnapshotBundle& bundle, std::string* err) {
  if (bundle.manifest.format_version != kSnapshotFormatVersion) {
    if (err) *err = "unsupported snapshot format version";
    return false;
  }
  if (bundle.manifest.entry_count != bundle.entries.size()) {
    if (err) *err = "snapshot entry count mismatch";
    return false;
  }

  std::map<std::string, Bytes> by_key;
  std::string previous_key;
  for (std::size_t i = 0; i < bundle.entries.size(); ++i) {
    const auto& entry = bundle.entries[i];
    if (entry.key.empty()) {
      if (err) *err = "snapshot entry has empty key";
      return false;
    }
    if (i != 0 && !(previous_key < entry.key)) {
      if (err) *err = "snapshot entries are not strictly sorted";
      return false;
    }
    previous_key = entry.key;
    by_key[entry.key] = entry.value;
  }

  const auto counts = classify_entries(bundle.entries);
  if (counts.metadata_count != bundle.manifest.metadata_count ||
      counts.height_index_count != bundle.manifest.height_index_count ||
      counts.certificate_count != bundle.manifest.certificate_count ||
      counts.utxo_count != bundle.manifest.utxo_count ||
      counts.validator_count != bundle.manifest.validator_count ||
      counts.tx_index_count != bundle.manifest.tx_index_count ||
      counts.script_utxo_count != bundle.manifest.script_utxo_count ||
      counts.script_history_count != bundle.manifest.script_history_count ||
      counts.root_index_count != bundle.manifest.root_index_count ||
      counts.smt_leaf_count != bundle.manifest.smt_leaf_count ||
      counts.smt_root_count != bundle.manifest.smt_root_count ||
      counts.liveness_metadata_count != bundle.manifest.liveness_metadata_count) {
    if (err) *err = "snapshot namespace counts mismatch";
    return false;
  }

  const auto tip_it = by_key.find(key_tip());
  const auto genesis_hash_it = by_key.find(key_genesis_hash());
  const auto genesis_artifact_it = by_key.find(key_genesis_artifact());
  if (tip_it == by_key.end() || genesis_hash_it == by_key.end() || genesis_artifact_it == by_key.end()) {
    if (err) *err = "snapshot is missing required metadata keys";
    return false;
  }
  const auto tip = parse_tip_bytes(tip_it->second);
  if (!tip.has_value()) {
    if (err) *err = "snapshot tip record is malformed";
    return false;
  }
  if (tip->height != bundle.manifest.finalized_height || tip->hash != bundle.manifest.finalized_hash) {
    if (err) *err = "snapshot tip does not match manifest";
    return false;
  }
  if (genesis_hash_it->second.size() != 32 || genesis_artifact_it->second.size() != 32) {
    if (err) *err = "snapshot genesis markers are malformed";
    return false;
  }
  if (!std::equal(genesis_hash_it->second.begin(), genesis_hash_it->second.end(), bundle.manifest.genesis_hash.begin()) ||
      !std::equal(genesis_artifact_it->second.begin(), genesis_artifact_it->second.end(),
                  bundle.manifest.genesis_artifact_id.begin())) {
    if (err) *err = "snapshot genesis markers do not match manifest";
    return false;
  }

  const auto height_it = by_key.find(key_height(bundle.manifest.finalized_height));
  const auto frontier_height_it = by_key.find(key_frontier_height(bundle.manifest.finalized_height));
  const auto frontier_it = by_key.find(key_frontier_transition(bundle.manifest.finalized_hash));
  const auto cert_it = by_key.find(key_finality_certificate_height(bundle.manifest.finalized_height));
  const auto utxo_root_it = by_key.find(key_root_index("UTXO", bundle.manifest.finalized_height));
  const auto validators_root_it = by_key.find(key_root_index("VAL", bundle.manifest.finalized_height));
  if (height_it == by_key.end() || frontier_height_it == by_key.end() || frontier_it == by_key.end() ||
      cert_it == by_key.end() || utxo_root_it == by_key.end() || validators_root_it == by_key.end()) {
    if (err) *err = "snapshot is missing finalized tip state";
    return false;
  }
  if (height_it->second.size() != 32 || utxo_root_it->second.size() != 32 || validators_root_it->second.size() != 32) {
    if (err) *err = "snapshot finalized records are malformed";
    return false;
  }
  if (!std::equal(height_it->second.begin(), height_it->second.end(), bundle.manifest.finalized_hash.begin()) ||
      !std::equal(utxo_root_it->second.begin(), utxo_root_it->second.end(), bundle.manifest.utxo_root.begin()) ||
      !std::equal(validators_root_it->second.begin(), validators_root_it->second.end(),
                  bundle.manifest.validators_root.begin())) {
    if (err) *err = "snapshot finalized records do not match manifest";
    return false;
  }
  if (frontier_height_it->second.size() != 32) {
    if (err) *err = "snapshot frontier height mapping is malformed";
    return false;
  }
  if (!std::equal(frontier_height_it->second.begin(), frontier_height_it->second.end(), bundle.manifest.finalized_hash.begin())) {
    if (err) *err = "snapshot frontier height mapping does not match manifest";
    return false;
  }
  return true;
}

}  // namespace

Bytes SnapshotManifest::serialize() const {
  codec::ByteWriter w;
  w.u32le(format_version);
  w.bytes_fixed(genesis_hash);
  w.bytes_fixed(genesis_artifact_id);
  w.u64le(finalized_height);
  w.bytes_fixed(finalized_hash);
  w.bytes_fixed(utxo_root);
  w.bytes_fixed(validators_root);
  w.u64le(entry_count);
  w.u64le(metadata_count);
  w.u64le(height_index_count);
  w.u64le(certificate_count);
  w.u64le(utxo_count);
  w.u64le(validator_count);
  w.u64le(tx_index_count);
  w.u64le(script_utxo_count);
  w.u64le(script_history_count);
  w.u64le(root_index_count);
  w.u64le(smt_leaf_count);
  w.u64le(smt_root_count);
  w.u64le(liveness_metadata_count);
  return w.take();
}

std::optional<SnapshotManifest> SnapshotManifest::parse(const Bytes& b) {
  SnapshotManifest manifest;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto version = r.u32le();
        auto genesis_hash = r.bytes_fixed<32>();
        auto genesis_artifact_id = r.bytes_fixed<32>();
        auto finalized_height = r.u64le();
        auto finalized_hash = r.bytes_fixed<32>();
        auto utxo_root = r.bytes_fixed<32>();
        auto validators_root = r.bytes_fixed<32>();
        auto entry_count = r.u64le();
        auto metadata_count = r.u64le();
        auto height_index_count = r.u64le();
        auto certificate_count = r.u64le();
        auto utxo_count = r.u64le();
        auto validator_count = r.u64le();
        auto tx_index_count = r.u64le();
        auto script_utxo_count = r.u64le();
        auto script_history_count = r.u64le();
        auto root_index_count = r.u64le();
        auto smt_leaf_count = r.u64le();
        auto smt_root_count = r.u64le();
        auto liveness_metadata_count = r.u64le();
        if (!version || !genesis_hash || !genesis_artifact_id || !finalized_height || !finalized_hash || !utxo_root ||
            !validators_root || !entry_count || !metadata_count || !height_index_count ||
            !certificate_count || !utxo_count || !validator_count || !tx_index_count || !script_utxo_count ||
            !script_history_count || !root_index_count || !smt_leaf_count || !smt_root_count ||
            !liveness_metadata_count) {
          return false;
        }
        if (*version != kSnapshotFormatVersion) return false;
        manifest.format_version = *version;
        manifest.genesis_hash = *genesis_hash;
        manifest.genesis_artifact_id = *genesis_artifact_id;
        manifest.finalized_height = *finalized_height;
        manifest.finalized_hash = *finalized_hash;
        manifest.utxo_root = *utxo_root;
        manifest.validators_root = *validators_root;
        manifest.entry_count = *entry_count;
        manifest.metadata_count = *metadata_count;
        manifest.height_index_count = *height_index_count;
        manifest.certificate_count = *certificate_count;
        manifest.utxo_count = *utxo_count;
        manifest.validator_count = *validator_count;
        manifest.tx_index_count = *tx_index_count;
        manifest.script_utxo_count = *script_utxo_count;
        manifest.script_history_count = *script_history_count;
        manifest.root_index_count = *root_index_count;
        manifest.smt_leaf_count = *smt_leaf_count;
        manifest.smt_root_count = *smt_root_count;
        manifest.liveness_metadata_count = *liveness_metadata_count;
        return true;
      })) {
    return std::nullopt;
  }
  return manifest;
}

Bytes SnapshotBundle::serialize() const {
  codec::ByteWriter w;
  w.bytes(kSnapshotMagic);
  w.bytes(manifest.serialize());
  for (const auto& entry : entries) {
    w.varbytes(Bytes(entry.key.begin(), entry.key.end()));
    w.varbytes(entry.value);
  }
  return w.take();
}

std::optional<SnapshotBundle> SnapshotBundle::parse(const Bytes& b) {
  SnapshotBundle bundle;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto magic = r.bytes(kSnapshotMagic.size());
        if (!magic || *magic != kSnapshotMagic) return false;

        Bytes manifest_bytes;
        manifest_bytes.reserve(4 + 32 + 32 + 8 + 32 + 32 + 32 + 13 * 8);
        auto append_fixed = [&](const std::optional<Bytes>& part) {
          if (!part.has_value()) return false;
          manifest_bytes.insert(manifest_bytes.end(), part->begin(), part->end());
          return true;
        };

        if (!append_fixed(r.bytes(4))) return false;
        if (!append_fixed(r.bytes(32))) return false;
        if (!append_fixed(r.bytes(32))) return false;
        if (!append_fixed(r.bytes(8))) return false;
        if (!append_fixed(r.bytes(32))) return false;
        if (!append_fixed(r.bytes(32))) return false;
        if (!append_fixed(r.bytes(32))) return false;
        for (int i = 0; i < 13; ++i) {
          if (!append_fixed(r.bytes(8))) return false;
        }

        auto manifest = SnapshotManifest::parse(manifest_bytes);
        if (!manifest.has_value()) return false;
        bundle.manifest = *manifest;

        bundle.entries.clear();
        bundle.entries.reserve(static_cast<std::size_t>(bundle.manifest.entry_count));
        for (std::uint64_t i = 0; i < bundle.manifest.entry_count; ++i) {
          auto key = r.varbytes();
          auto value = r.varbytes();
          if (!key || !value) return false;
          bundle.entries.push_back(SnapshotEntry{std::string(key->begin(), key->end()), *value});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return bundle;
}

bool export_snapshot_bundle(const DB& db, const std::string& path, SnapshotManifest* manifest_out, std::string* err) {
  auto bundle = build_snapshot_bundle(db, err);
  if (!bundle.has_value()) return false;
  if (!write_file_bytes(path, bundle->serialize(), err)) return false;
  if (manifest_out) *manifest_out = bundle->manifest;
  return true;
}

bool import_snapshot_bundle(DB& db, const std::string& path, SnapshotManifest* manifest_out, std::string* err) {
  if (!db.scan_prefix("").empty()) {
    if (err) *err = "snapshot import requires an empty db";
    return false;
  }

  Bytes bytes;
  if (!read_file_bytes(path, &bytes, err)) return false;
  auto bundle = SnapshotBundle::parse(bytes);
  if (!bundle.has_value()) {
    if (err) *err = "failed to parse snapshot bundle";
    return false;
  }
  if (!validate_bundle(*bundle, err)) return false;

  for (const auto& entry : bundle->entries) {
    if (!db.put(entry.key, entry.value)) {
      if (err) *err = "failed to write snapshot entry";
      return false;
    }
  }
  if (!db.flush()) {
    if (err) *err = "failed to flush imported snapshot";
    return false;
  }
  if (manifest_out) *manifest_out = bundle->manifest;
  return true;
}

}  // namespace finalis::storage
