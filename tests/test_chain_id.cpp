#include "test_framework.hpp"

#include "common/chain_id.hpp"

using namespace finalis;

TEST(test_compare_chain_identity_detects_mismatch_fields) {
  ChainId a;
  a.network_id_hex = "aa";
  a.genesis_hash_hex = "bb";
  a.protocol_version = 1;
  a.magic = 10;

  ChainId b = a;
  auto same = compare_chain_identity(a, b);
  ASSERT_TRUE(same.match);

  b.network_id_hex = "cc";
  auto nid = compare_chain_identity(a, b);
  ASSERT_TRUE(!nid.match);
  ASSERT_TRUE(nid.network_id_differs);

  b = a;
  b.genesis_hash_hex = "dd";
  auto gh = compare_chain_identity(a, b);
  ASSERT_TRUE(!gh.match);
  ASSERT_TRUE(gh.genesis_hash_differs);

  b = a;
  b.protocol_version = 2;
  auto pv = compare_chain_identity(a, b);
  ASSERT_TRUE(!pv.match);
  ASSERT_TRUE(pv.protocol_version_differs);

  b = a;
  b.magic = 11;
  auto mg = compare_chain_identity(a, b);
  ASSERT_TRUE(!mg.match);
  ASSERT_TRUE(mg.magic_differs);
}

void register_chain_id_tests() {}
