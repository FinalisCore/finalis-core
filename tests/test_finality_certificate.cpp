// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_paths.hpp"

#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif

#include <atomic>
#include <chrono>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "consensus/canonical_derivation.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/validate.hpp"
#include "storage/db.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

using finalis::test::unique_test_base;

std::optional<std::filesystem::path> find_repo_dir(const std::filesystem::path& relative) {
  auto cur = std::filesystem::current_path();
  for (int i = 0; i < 8; ++i) {
    if (std::filesystem::is_directory(cur / relative)) return cur / relative;
    if (!cur.has_parent_path()) break;
    cur = cur.parent_path();
  }
  return std::nullopt;
}

// Shared core <-> TS SDK finality vectors (sdk/finalis-wallet-js/test-vectors/finality_vectors.json).
// Built only from core primitives, so a change to vote_signing_message or signing breaks the
// byte comparison below until the fixture (and the SDK verifier) are updated.
// Regenerate: FINALIS_WRITE_FINALITY_VECTORS=1 ./build/finalis-tests --run test_finality_shared_vectors_match_ts
std::string build_finality_vectors_json() {
  std::vector<crypto::KeyPair> keys;
  for (int n = 1; n <= 5; ++n) {
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>((n * 17 + static_cast<int>(i)) & 0xff);
    keys.push_back(*crypto::keypair_from_seed32(seed));
  }
  const std::vector<std::size_t> committee_idx{0, 1, 2, 3};  // key 4 is an outsider
  auto pub_hex = [&](std::size_t k) { return hex_encode(Bytes(keys[k].public_key.begin(), keys[k].public_key.end())); };
  auto tag_hash = [](const std::string& tag) { return crypto::sha256d(Bytes(tag.begin(), tag.end())); };

  struct Sig {
    std::size_t key;
    Bytes msg;
  };
  struct Case {
    std::string name;
    std::uint64_t height;
    std::uint32_t round;
    Hash32 transition;
    std::vector<Sig> sigs;
  };
  const Hash32 t1 = tag_hash("finality-vector-transition-1");
  const Hash32 t2 = tag_hash("finality-vector-transition-2");
  const std::uint64_t h1 = 12345;
  const std::uint64_t h_big = (1ULL << 53) + 11;  // beyond JS Number.MAX_SAFE_INTEGER
  const Bytes m1 = vote_signing_message(h1, 2, t1);
  const Bytes m_big = vote_signing_message(h_big, 0, t2);
  const Bytes raw_t1(t1.begin(), t1.end());
  const std::vector<Case> cases{
      {"quorum_3_of_4", h1, 2, t1, {{0, m1}, {1, m1}, {2, m1}}},
      {"all_4_of_4", h1, 2, t1, {{0, m1}, {1, m1}, {2, m1}, {3, m1}}},
      {"below_quorum_2_of_4", h1, 2, t1, {{0, m1}, {1, m1}}},
      {"wrong_round", h1, 3, t1, {{0, m1}, {1, m1}, {2, m1}}},
      {"wrong_height", h1 + 1, 2, t1, {{0, m1}, {1, m1}, {2, m1}}},
      {"raw_transition_hash_signatures", h1, 2, t1, {{0, raw_t1}, {1, raw_t1}, {2, raw_t1}}},
      {"duplicate_signer", h1, 2, t1, {{0, m1}, {0, m1}, {1, m1}}},
      {"non_committee_signer", h1, 2, t1, {{0, m1}, {1, m1}, {4, m1}}},
      {"height_above_2_pow_53", h_big, 0, t2, {{0, m_big}, {1, m_big}, {2, m_big}}},
  };

  std::ostringstream oss;
  oss << "{\n  \"message_format\": \"sha256d('SC-VOTE-V1' || u64le(height) || u32le(round) || transition_hash)\",\n";
  oss << "  \"committee\": [";
  for (std::size_t i = 0; i < committee_idx.size(); ++i) oss << (i ? ", " : "") << "\"" << pub_hex(committee_idx[i]) << "\"";
  oss << "],\n  \"cases\": [\n";
  const auto quorum = consensus::quorum_threshold(committee_idx.size());
  for (std::size_t c = 0; c < cases.size(); ++c) {
    const auto& tc = cases[c];
    const Bytes expected_msg = vote_signing_message(tc.height, tc.round, tc.transition);
    std::set<std::size_t> valid_signers;
    oss << "    {\"name\": \"" << tc.name << "\", \"height\": \"" << tc.height << "\", \"round\": " << tc.round
        << ", \"transition_hash\": \"" << hex_encode(Bytes(tc.transition.begin(), tc.transition.end()))
        << "\", \"message_hex\": \"" << hex_encode(expected_msg) << "\", \"signatures\": [";
    for (std::size_t i = 0; i < tc.sigs.size(); ++i) {
      const auto& sg = tc.sigs[i];
      const auto sig = *crypto::ed25519_sign(sg.msg, keys[sg.key].private_key);
      const bool in_committee = std::find(committee_idx.begin(), committee_idx.end(), sg.key) != committee_idx.end();
      if (in_committee && crypto::ed25519_verify(expected_msg, sig, keys[sg.key].public_key)) valid_signers.insert(sg.key);
      oss << (i ? ", " : "") << "{\"pubkey_hex\": \"" << pub_hex(sg.key) << "\", \"sig_hex\": \""
          << hex_encode(Bytes(sig.begin(), sig.end())) << "\"}";
    }
    oss << "], \"expected\": " << (valid_signers.size() >= quorum ? "true" : "false") << "}"
        << (c + 1 < cases.size() ? "," : "") << "\n";
  }
  oss << "  ]\n}\n";
  return oss.str();
}

}  // namespace

TEST(test_finality_certificate_serialize_roundtrip) {
  FinalityCertificate cert;
  cert.height = 77;
  cert.round = 3;
  cert.block_id.fill(0x42);
  cert.quorum_threshold = 5;
  PubKey32 a{};
  PubKey32 b{};
  a.fill(0x11);
  b.fill(0x22);
  cert.committee_members = {a, b};
  Sig64 sa{};
  Sig64 sb{};
  sa.fill(0xA1);
  sb.fill(0xB2);
  cert.signatures = {{a, sa}, {b, sb}};

  const auto bytes = cert.serialize();
  auto parsed = FinalityCertificate::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->height, cert.height);
  ASSERT_EQ(parsed->round, cert.round);
  ASSERT_EQ(parsed->block_id, cert.block_id);
  ASSERT_EQ(parsed->quorum_threshold, cert.quorum_threshold);
  ASSERT_EQ(parsed->committee_members, cert.committee_members);
  ASSERT_EQ(parsed->signatures.size(), cert.signatures.size());
  ASSERT_EQ(parsed->signatures[0].validator_pubkey, cert.signatures[0].validator_pubkey);
  ASSERT_EQ(parsed->signatures[0].signature, cert.signatures[0].signature);
  ASSERT_EQ(parsed->signatures[1].validator_pubkey, cert.signatures[1].validator_pubkey);
  ASSERT_EQ(parsed->signatures[1].signature, cert.signatures[1].signature);
}

TEST(test_finality_certificate_db_roundtrip) {
  const std::string path = unique_test_base("/tmp/finalis_test_finality_certificate_db");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  FinalityCertificate cert;
  cert.height = 12;
  cert.round = 0;
  cert.block_id.fill(0x5C);
  cert.quorum_threshold = 3;
  PubKey32 member{};
  member.fill(0x77);
  cert.committee_members = {member};
  Sig64 sig{};
  sig.fill(0x88);
  cert.signatures = {{member, sig}};

  ASSERT_TRUE(db.put_finality_certificate(cert));
  ASSERT_TRUE(db.flush());
  db.close();

  storage::DB ro;
  ASSERT_TRUE(ro.open_readonly(path));
  auto by_height = ro.get_finality_certificate_by_height(cert.height);
  ASSERT_TRUE(by_height.has_value());
  ASSERT_EQ(by_height->height, cert.height);
  ASSERT_EQ(by_height->block_id, cert.block_id);
  ASSERT_EQ(by_height->quorum_threshold, cert.quorum_threshold);
  ASSERT_EQ(by_height->committee_members, cert.committee_members);
  ASSERT_EQ(by_height->signatures.size(), cert.signatures.size());
}

TEST(test_canonical_finality_certificate_hash_is_deterministic_under_signature_reordering) {
  FinalityCertificate cert;
  cert.height = 19;
  cert.round = 4;
  cert.block_id.fill(0x31);
  cert.quorum_threshold = 2;
  PubKey32 a{};
  PubKey32 b{};
  PubKey32 c{};
  a.fill(0x11);
  b.fill(0x22);
  c.fill(0x33);
  cert.committee_members = {b, a, c};
  Sig64 sa{};
  Sig64 sb{};
  Sig64 sc{};
  sa.fill(0xA1);
  sb.fill(0xB2);
  sc.fill(0xC3);
  cert.signatures = {{b, sb}, {a, sa}, {b, sc}};

  const auto hash1 = consensus::canonical_finality_certificate_hash(cert);
  std::swap(cert.signatures[0], cert.signatures[1]);
  const auto hash2 = consensus::canonical_finality_certificate_hash(cert);
  ASSERT_EQ(hash1, hash2);

  cert.round += 1;
  const auto hash3 = consensus::canonical_finality_certificate_hash(cert);
  ASSERT_TRUE(hash3 != hash1);
}

TEST(test_finality_shared_vectors_match_ts) {
  const auto dir = find_repo_dir("sdk/finalis-wallet-js/test-vectors");
  ASSERT_TRUE(dir.has_value());
  const auto path = *dir / "finality_vectors.json";
  const std::string expected = build_finality_vectors_json();
  if (const char* w = std::getenv("FINALIS_WRITE_FINALITY_VECTORS"); w != nullptr && std::string(w) == "1") {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.good());
    out << expected;
  }
  std::ifstream in(path, std::ios::binary);
  ASSERT_TRUE(in.good());
  const std::string actual((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  // Mismatch: core's vote signing changed. Regenerate the fixture and update the SDK verifier.
  ASSERT_TRUE(actual == expected);
  ASSERT_TRUE(expected.find("\"name\": \"quorum_3_of_4\"") != std::string::npos);
  ASSERT_TRUE(expected.find("\"expected\": true") != std::string::npos);
  ASSERT_TRUE(expected.find("\"expected\": false") != std::string::npos);
}
