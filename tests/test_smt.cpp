#include "test_framework.hpp"

#include <filesystem>
#include <fstream>

#include "crypto/smt.hpp"

using namespace finalis;

namespace {

Hash32 h(std::uint8_t b) {
  Hash32 out{};
  out.fill(b);
  return out;
}

Bytes v(std::uint8_t b, std::size_t n = 4) {
  return Bytes(n, b);
}

}  // namespace

TEST(test_smt_insert_and_prove_membership) {
  const std::string dir = "/tmp/finalis_test_smt_insert";
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
  const std::string dir = "/tmp/finalis_test_smt_delete";
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
  const std::string dir = "/tmp/finalis_test_smt_verify";
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
  const std::string d1 = "/tmp/finalis_test_smt_replay1";
  const std::string d2 = "/tmp/finalis_test_smt_replay2";
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
  const auto cwd = std::filesystem::current_path();
  const std::vector<std::filesystem::path> candidates = {
      cwd / "sdk/finalis-wallet-js/test-vectors/smt_vectors.json",
      cwd.parent_path() / "sdk/finalis-wallet-js/test-vectors/smt_vectors.json",
  };
  std::ifstream in;
  for (const auto& p : candidates) {
    in.open(p);
    if (in.good()) break;
    in.clear();
  }
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

void register_smt_tests() {}
