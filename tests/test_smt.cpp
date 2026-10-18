// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_paths.hpp"

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include <array>
#include <atomic>
#include <algorithm>
#include <map>
#include <chrono>

#include <filesystem>
#include <fstream>

#include "crypto/hash.hpp"
#include "crypto/smt.hpp"
#include "storage/db.hpp"

using namespace finalis;

namespace {

using finalis::test::unique_test_base;

Hash32 h(std::uint8_t b) {
  Hash32 out{};
  out.fill(b);
  return out;
}

Bytes v(std::uint8_t b, std::size_t n = 4) {
  return Bytes(n, b);
}

std::optional<std::filesystem::path> find_repo_fixture(const std::filesystem::path& relative) {
  auto cur = std::filesystem::current_path();
  for (int i = 0; i < 8; ++i) {
    const auto candidate = cur / relative;
    if (std::filesystem::exists(candidate)) return candidate;
    if (!cur.has_parent_path()) break;
    cur = cur.parent_path();
  }
  return std::nullopt;
}

}  // namespace

TEST(test_smt_insert_and_prove_membership) {
  const std::string dir = unique_test_base("/tmp/finalis_test_smt_insert");
  std::filesystem::remove_all(dir);
  storage::DB db;
  ASSERT_TRUE(db.open(dir));
  crypto::SparseMerkleTree smt(db, "utxo");

  crypto::SmtUpdate u;
  u.key = h(0x11);
  u.value = v(0xAA);
  smt.apply_updates({u});

  const Hash32 root = smt.root();
  const auto proof = smt.get_proof(u.key);
  ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, u.key, u.value, proof));
}

TEST(test_smt_delete_and_prove_nonmembership) {
  const std::string dir = unique_test_base("/tmp/finalis_test_smt_delete");
  std::filesystem::remove_all(dir);
  storage::DB db;
  ASSERT_TRUE(db.open(dir));
  crypto::SparseMerkleTree smt(db, "utxo");

  crypto::SmtUpdate add;
  add.key = h(0x22);
  add.value = v(0xBB);
  smt.apply_updates({add});

  crypto::SmtUpdate del;
  del.key = add.key;
  del.value = std::nullopt;
  smt.apply_updates({del});

  const Hash32 root = smt.root();
  const auto proof = smt.get_proof(add.key);
  ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, add.key, std::nullopt, proof));
}

TEST(test_smt_proof_verification_matches_root) {
  const std::string dir = unique_test_base("/tmp/finalis_test_smt_verify");
  std::filesystem::remove_all(dir);
  storage::DB db;
  ASSERT_TRUE(db.open(dir));
  crypto::SparseMerkleTree smt(db, "validators");

  crypto::SmtUpdate a{h(0x01), v(0x10)};
  crypto::SmtUpdate b{h(0x02), v(0x20)};
  smt.apply_updates({a, b});
  const Hash32 root = smt.root();

  auto proof = smt.get_proof(a.key);
  ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, a.key, a.value, proof));

  auto bad_value = v(0xFF);
  ASSERT_TRUE(!crypto::SparseMerkleTree::verify_proof(root, a.key, bad_value, proof));
}

TEST(test_smt_determinism_across_replay) {
  const std::string d1 = unique_test_base("/tmp/finalis_test_smt_replay1");
  const std::string d2 = unique_test_base("/tmp/finalis_test_smt_replay2");
  std::filesystem::remove_all(d1);
  std::filesystem::remove_all(d2);

  std::vector<crypto::SmtUpdate> ops;
  ops.push_back(crypto::SmtUpdate{h(0x31), v(0xA1)});
  ops.push_back(crypto::SmtUpdate{h(0x32), v(0xA2)});
  ops.push_back(crypto::SmtUpdate{h(0x33), v(0xA3)});
  ops.push_back(crypto::SmtUpdate{h(0x32), std::nullopt});
  ops.push_back(crypto::SmtUpdate{h(0x34), v(0xA4)});

  storage::DB db1;
  ASSERT_TRUE(db1.open(d1));
  crypto::SparseMerkleTree s1(db1, "utxo");
  for (const auto& op : ops) s1.apply_updates({op});
  const Hash32 r1 = s1.root();

  storage::DB db2;
  ASSERT_TRUE(db2.open(d2));
  crypto::SparseMerkleTree s2(db2, "utxo");
  for (const auto& op : ops) s2.apply_updates({op});
  const Hash32 r2 = s2.root();

  ASSERT_EQ(r1, r2);
}

TEST(test_smt_shared_vectors_match_ts) {
  std::ifstream in;
  auto vectors_path = find_repo_fixture("sdk/finalis-wallet-js/test-vectors/smt_vectors.json");
  if (vectors_path.has_value()) in.open(*vectors_path);
  ASSERT_TRUE(in.good());
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  ASSERT_TRUE(!s.empty());

  std::size_t pos = 0;
  int parsed = 0;
  while (true) {
    const auto npos = s.find("\"name\":\"", pos);
    if (npos == std::string::npos) break;
    const auto nend = s.find('"', npos + 8);
    ASSERT_TRUE(nend != std::string::npos);
    const auto rpos = s.find("\"root_hex\":\"", nend);
    const auto rend = s.find('"', rpos + 12);
    const auto kpos = s.find("\"key_hex\":\"", rend);
    const auto kend = s.find('"', kpos + 11);
    const auto vpos = s.find("\"value_hex\":", kend);
    const auto spos = s.find("\"siblings\":[", vpos);
    ASSERT_TRUE(rpos != std::string::npos && rend != std::string::npos);
    ASSERT_TRUE(kpos != std::string::npos && kend != std::string::npos);
    ASSERT_TRUE(vpos != std::string::npos && spos != std::string::npos);

    const std::string root_hex = s.substr(rpos + 12, rend - (rpos + 12));
    const std::string key_hex = s.substr(kpos + 11, kend - (kpos + 11));

    std::optional<Bytes> value;
    std::size_t cur = vpos + 12;
    if (s.compare(cur, 4, "null") == 0) {
      value = std::nullopt;
      cur += 4;
    } else {
      ASSERT_TRUE(s[cur] == '"');
      const auto vend = s.find('"', cur + 1);
      ASSERT_TRUE(vend != std::string::npos);
      auto vb = hex_decode(s.substr(cur + 1, vend - (cur + 1)));
      ASSERT_TRUE(vb.has_value());
      value = *vb;
      cur = vend + 1;
    }

    const auto arr_beg = s.find('[', spos);
    const auto arr_end = s.find(']', arr_beg);
    ASSERT_TRUE(arr_beg != std::string::npos && arr_end != std::string::npos);
    std::vector<Hash32> siblings;
    std::size_t p = arr_beg + 1;
    while (p < arr_end) {
      while (p < arr_end && (s[p] == ',')) ++p;
      if (p >= arr_end) break;
      ASSERT_TRUE(s[p] == '"');
      const auto q = s.find('"', p + 1);
      ASSERT_TRUE(q != std::string::npos && q <= arr_end);
      auto hb = hex_decode(s.substr(p + 1, q - (p + 1)));
      ASSERT_TRUE(hb.has_value() && hb->size() == 32);
      Hash32 h{};
      std::copy(hb->begin(), hb->end(), h.begin());
      siblings.push_back(h);
      p = q + 1;
      if (p < arr_end && s[p] == ',') ++p;
    }

    auto rb = hex_decode(root_hex);
    auto kb = hex_decode(key_hex);
    ASSERT_TRUE(rb.has_value() && rb->size() == 32);
    ASSERT_TRUE(kb.has_value() && kb->size() == 32);
    Hash32 root{};
    Hash32 key{};
    std::copy(rb->begin(), rb->end(), root.begin());
    std::copy(kb->begin(), kb->end(), key.begin());
    crypto::SmtProof proof{siblings};
    ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, key, value, proof));

    pos = arr_end + 1;
    ++parsed;
  }
  ASSERT_TRUE(parsed >= 3);
}

namespace {

// The original level-by-level construction (every level of all 256 materialized), kept as the
// reference for the fast recursive root.
Hash32 reference_smt_root(const std::vector<std::pair<Hash32, Bytes>>& leaves_in) {
  const auto tagged = [](const std::string& tag, const Bytes& payload) {
    Bytes in(tag.begin(), tag.end());
    in.insert(in.end(), payload.begin(), payload.end());
    return crypto::sha256(in);
  };
  const auto node = [&](const Hash32& l, const Hash32& r) {
    Bytes p(l.begin(), l.end());
    p.insert(p.end(), r.begin(), r.end());
    return tagged("SC-SMT-NODE-V0", p);
  };
  const auto bits = [](const Hash32& k, std::size_t n) {
    std::string out;
    for (std::size_t i = 0; i < n; ++i) out.push_back(((k[i / 8] >> (7 - i % 8)) & 1) ? '1' : '0');
    return out;
  };
  std::array<Hash32, 257> empties{};
  empties[256] = tagged("SC-SMT-EMPTY-V0", {});
  for (int d = 255; d >= 0; --d) empties[d] = node(empties[d + 1], empties[d + 1]);
  std::map<std::string, Hash32> level;
  for (const auto& [k, val] : leaves_in) {
    Bytes p(k.begin(), k.end());
    const auto vh = crypto::sha256(val);
    p.insert(p.end(), vh.begin(), vh.end());
    level.emplace(bits(k, 256), tagged("SC-SMT-LEAF-V0", p));
  }
  if (level.empty()) return empties[0];
  for (int depth = 256; depth > 0; --depth) {
    std::map<std::string, Hash32> parents;
    for (const auto& [prefix, _] : level) {
      const auto parent = prefix.substr(0, depth - 1);
      if (parents.count(parent)) continue;
      const auto li = level.find(parent + "0");
      const auto ri = level.find(parent + "1");
      parents[parent] = node(li == level.end() ? empties[depth] : li->second,
                             ri == level.end() ? empties[depth] : ri->second);
    }
    level = std::move(parents);
  }
  return level.begin()->second;
}

}  // namespace

TEST(test_smt_fast_root_matches_reference_as_set_changes) {
  // Keys sharing long prefixes force the leaf-path memo to move a leaf deeper and back up.
  const auto key = [](std::uint32_t i, std::size_t shared_prefix_bytes) {
    Hash32 k = crypto::sha256(Bytes{static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(i >> 8), 0x5a});
    for (std::size_t b = 0; b < shared_prefix_bytes; ++b) k[b] = 0xC3;
    return k;
  };
  std::vector<std::pair<Hash32, Bytes>> leaves;
  ASSERT_EQ(crypto::SparseMerkleTree::compute_root_from_leaves(leaves), reference_smt_root(leaves));
  for (std::uint32_t i = 0; i < 40; ++i) {
    leaves.push_back({key(i, i % 4 == 0 ? 31 : (i % 3 == 0 ? 3 : 0)), v(static_cast<std::uint8_t>(i), 1 + i % 7)});
    ASSERT_EQ(crypto::SparseMerkleTree::compute_root_from_leaves(leaves), reference_smt_root(leaves));
  }
  // Removals raise remaining leaves' branching depth; value changes give new leaf hashes.
  for (std::size_t i = 0; i < 20; ++i) {
    leaves.erase(leaves.begin() + static_cast<std::ptrdiff_t>((i * 7) % leaves.size()));
    if (i % 2 == 0 && !leaves.empty()) leaves[i % leaves.size()].second.push_back(0xEE);
    ASSERT_EQ(crypto::SparseMerkleTree::compute_root_from_leaves(leaves), reference_smt_root(leaves));
  }
  // A single leaf, then a pair differing only in the last bit.
  Hash32 a = key(1000, 0);
  Hash32 b = a;
  b[31] ^= 0x01;
  ASSERT_EQ(crypto::SparseMerkleTree::compute_root_from_leaves({{a, v(1)}}), reference_smt_root({{a, v(1)}}));
  ASSERT_EQ(crypto::SparseMerkleTree::compute_root_from_leaves({{a, v(1)}, {b, v(2)}}),
            reference_smt_root({{a, v(1)}, {b, v(2)}}));
  ASSERT_EQ(crypto::SparseMerkleTree::compute_root_from_leaves({{b, v(2)}, {a, v(1)}}),
            reference_smt_root({{a, v(1)}, {b, v(2)}}));
}

TEST(test_smt_fast_proofs_verify_for_members_and_non_members) {
  const std::string dir = unique_test_base("/tmp/finalis_test_smt_fast_proofs");
  std::filesystem::remove_all(dir);
  storage::DB db;
  ASSERT_TRUE(db.open(dir));
  crypto::SparseMerkleTree smt(db, "utxo");
  std::vector<std::pair<Hash32, Bytes>> leaves;
  for (std::uint32_t i = 0; i < 64; ++i) {
    Hash32 k = crypto::sha256(Bytes{static_cast<std::uint8_t>(i), 0x33});
    if (i % 5 == 0) for (std::size_t b = 0; b < 30; ++b) k[b] = 0x5A;  // long shared prefixes
    leaves.push_back({k, v(static_cast<std::uint8_t>(i), 1 + i % 4)});
  }
  std::vector<crypto::SmtUpdate> updates;
  for (const auto& [k, val] : leaves) updates.push_back(crypto::SmtUpdate{k, val});
  smt.apply_updates(updates);
  const auto root = smt.root();
  ASSERT_EQ(root, reference_smt_root(leaves));
  for (const auto& [k, val] : leaves) {
    ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, k, val, smt.get_proof(k)));
  }
  for (std::uint8_t i = 0; i < 8; ++i) {
    Hash32 absent = crypto::sha256(Bytes{i, 0x44});
    if (i % 2 == 0) for (std::size_t b = 0; b < 30; ++b) absent[b] = 0x5A;
    ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, absent, std::nullopt, smt.get_proof(absent)));
  }
}

TEST(test_persistent_smt_matches_reference_and_keeps_old_versions) {
  std::map<Hash32, Bytes> model;
  const auto leaves_of = [&]() {
    std::vector<std::pair<Hash32, Bytes>> out(model.begin(), model.end());
    return out;
  };
  crypto::PersistentSmt tree;
  ASSERT_EQ(tree.root(), reference_smt_root({}));
  std::uint64_t rng = 0x9e3779b97f4a7c15ULL;
  const auto next = [&]() {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
  };
  std::vector<std::pair<crypto::PersistentSmt, Hash32>> versions;
  for (int step = 0; step < 300; ++step) {
    std::vector<std::pair<Hash32, std::optional<Hash32>>> changes;
    const int n = 1 + static_cast<int>(next() % 4);
    for (int i = 0; i < n; ++i) {
      Hash32 k = crypto::sha256(Bytes{static_cast<std::uint8_t>(next() % 97), 0x21});
      if (next() % 3 == 0) for (std::size_t b = 0; b < 31; ++b) k[b] = 0xA5;  // long shared prefixes
      if (!model.empty() && next() % 3 == 0) {
        model.erase(k);
        changes.push_back({k, std::nullopt});
      } else {
        const Bytes val = v(static_cast<std::uint8_t>(next()), 1 + next() % 5);
        model[k] = val;
        changes.push_back({k, crypto::SparseMerkleTree::leaf_hash(k, val)});
      }
    }
    tree = tree.updated(changes);
    const auto expected = reference_smt_root(leaves_of());
    ASSERT_EQ(tree.root(), expected);
    ASSERT_EQ(tree.size(), model.size());
    if (step % 50 == 0) versions.push_back({tree, expected});
  }
  for (const auto& [old, root] : versions) ASSERT_EQ(old.root(), root);  // structure sharing kept them intact

  std::vector<std::pair<Hash32, Hash32>> hashes;
  for (const auto& [k, val] : model) hashes.push_back({k, crypto::SparseMerkleTree::leaf_hash(k, val)});
  ASSERT_EQ(crypto::PersistentSmt::from_leaf_hashes(hashes).root(), tree.root());
}

TEST(test_persistent_smt_proofs_verify_and_delta_codec_round_trips) {
  std::vector<std::pair<Hash32, Hash32>> leaves;
  std::vector<std::pair<Hash32, Bytes>> values;
  for (std::uint32_t i = 0; i < 80; ++i) {
    Hash32 k = crypto::sha256(Bytes{static_cast<std::uint8_t>(i), 0x55});
    if (i % 4 == 0) for (std::size_t b = 0; b < 31; ++b) k[b] = 0x3C;
    if (std::any_of(values.begin(), values.end(), [&](const auto& e) { return e.first == k; })) continue;
    const Bytes val = v(static_cast<std::uint8_t>(i), 2);
    values.push_back({k, val});
    leaves.push_back({k, crypto::SparseMerkleTree::leaf_hash(k, val)});
  }
  const auto tree = crypto::PersistentSmt::from_leaf_hashes(leaves);
  const auto root = tree.root();
  ASSERT_EQ(root, reference_smt_root(values));
  for (const auto& [k, val] : values) {
    ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, k, val, tree.proof(k)));
  }
  // A repeated key keeps its last value.
  auto repeated = leaves;
  repeated.push_back({leaves[0].first, crypto::SparseMerkleTree::leaf_hash(leaves[0].first, values[1].second)});
  std::vector<std::pair<Hash32, Bytes>> repeated_values = values;
  repeated_values[0].second = values[1].second;
  ASSERT_EQ(crypto::PersistentSmt::from_leaf_hashes(repeated).root(), reference_smt_root(repeated_values));
  for (std::uint8_t i = 0; i < 12; ++i) {
    Hash32 absent = crypto::sha256(Bytes{i, 0x66});
    if (i % 2 == 0) for (std::size_t b = 0; b < 31; ++b) absent[b] = 0x3C;
    ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(root, absent, std::nullopt, tree.proof(absent)));
  }
  ASSERT_TRUE(crypto::SparseMerkleTree::verify_proof(crypto::PersistentSmt{}.root(), leaves[0].first, std::nullopt,
                                                     crypto::PersistentSmt{}.proof(leaves[0].first)));

  const std::vector<crypto::SmtChange> changes{{leaves[0].first, leaves[1].second}, {leaves[2].first, std::nullopt}};
  const auto decoded = crypto::decode_smt_delta(crypto::encode_smt_delta(changes));
  ASSERT_TRUE(decoded.has_value() && *decoded == changes);
  ASSERT_TRUE(!crypto::decode_smt_delta(Bytes{0x05, 0x01}).has_value());
}
