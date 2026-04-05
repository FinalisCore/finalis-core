#include "test_framework.hpp"

#include <filesystem>

#include "consensus/canonical_derivation.hpp"
#include "storage/db.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

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
  const std::string path = "/tmp/finalis_test_finality_certificate_db";
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

void register_finality_certificate_tests() {}
