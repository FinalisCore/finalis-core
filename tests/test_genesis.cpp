// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_genesis.hpp"

#include <algorithm>

#include "common/network.hpp"
#include "genesis/genesis.hpp"
#include "node/node.hpp"

using namespace finalis;

namespace {

std::string make_mainnet_genesis_json(bool duplicate = false, bool bad_pub = false) {
  const auto keys = node::Node::deterministic_test_keypairs();
  std::vector<std::string> pubs;
  for (int i = 0; i < 4; ++i) {
    pubs.push_back(hex_encode(Bytes(keys[i].public_key.begin(), keys[i].public_key.end())));
  }
  if (duplicate) pubs[3] = pubs[0];
  if (bad_pub) pubs[0] = "abcd";

  genesis::Document d;
  d.version = genesis::kGenesisVersion;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1'730'000'000ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 4;
  d.initial_committee_params.min_committee = 4;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.seeds = mainnet_network().default_seeds;
  d.note = "unit-test";

  d.initial_validators.clear();
  for (const auto& p : pubs) {
    auto b = hex_decode(p);
    if (b && b->size() == 32) {
      PubKey32 pk{};
      std::copy(b->begin(), b->end(), pk.begin());
      d.initial_validators.push_back(pk);
    } else {
      // For bad pubkey test we force raw JSON mutation below.
      d.initial_validators.push_back(PubKey32{});
    }
  }

  if (!bad_pub) finalis::test::fill_test_genesis_bls(d);
  auto json = genesis::to_json(d);
  if (bad_pub) {
    const std::string good = "\"" + hex_encode(Bytes(d.initial_validators[0].begin(), d.initial_validators[0].end())) + "\"";
    const auto pos = json.find(good);
    if (pos != std::string::npos) json.replace(pos, good.size(), "\"abcd\"");
  }
  return json;
}

std::string make_empty_mainnet_genesis_json() {
  genesis::Document d;
  d.version = genesis::kGenesisVersion;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1'730'000'000ULL;
  d.initial_height = 0;
  d.initial_active_set_size = 0;
  d.initial_committee_params.min_committee = 1;
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 1;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.seeds = mainnet_network().default_seeds;
  d.note = "single-node-bootstrap-template";
  return genesis::to_json(d);
}

}  // namespace

TEST(test_genesis_json_bin_hash_stable) {
  const auto json = make_mainnet_genesis_json();
  std::string err;
  auto doc = genesis::parse_json(json, &err);
  ASSERT_TRUE(doc.has_value());
  ASSERT_TRUE(genesis::validate_document(*doc, mainnet_network(), &err, 4));

  const auto b1 = genesis::encode_bin(*doc);
  const auto h1 = genesis::hash_bin(b1);
  const auto d2 = genesis::decode_bin(b1, &err);
  ASSERT_TRUE(d2.has_value());
  const auto b2 = genesis::encode_bin(*d2);
  const auto h2 = genesis::hash_bin(b2);

  ASSERT_EQ(b1, b2);
  ASSERT_EQ(h1, h2);
}

TEST(test_genesis_reject_duplicate_validators) {
  std::string err;
  auto doc = genesis::parse_json(make_mainnet_genesis_json(true, false), &err);
  ASSERT_TRUE(doc.has_value());
  ASSERT_TRUE(!genesis::validate_document(*doc, mainnet_network(), &err, 4));
}

TEST(test_genesis_reject_invalid_pubkey_hex) {
  std::string err;
  auto doc = genesis::parse_json(make_mainnet_genesis_json(false, true), &err);
  ASSERT_TRUE(!doc.has_value());
}

TEST(test_genesis_empty_validator_template_allowed_only_when_requested) {
  std::string err;
  auto doc = genesis::parse_json(make_empty_mainnet_genesis_json(), &err);
  ASSERT_TRUE(doc.has_value());
  ASSERT_TRUE(genesis::validate_document(*doc, mainnet_network(), &err, 0));
  ASSERT_TRUE(!genesis::validate_document(*doc, mainnet_network(), &err, 1));
}

// Version 2: every initial validator carries a BLS time-signature key with a valid proof of
// possession, keys unique; the entries survive JSON and binary encoding.
TEST(test_genesis_requires_a_proven_unique_bls_key_per_validator) {
  std::string err;
  const auto base = genesis::parse_json(make_mainnet_genesis_json(), &err);
  ASSERT_TRUE(base.has_value());
  ASSERT_EQ(base->initial_validator_bls.size(), 4u);
  ASSERT_TRUE(genesis::validate_document(*base, mainnet_network(), &err, 4));
  const auto bin = genesis::decode_bin(genesis::encode_bin(*base), &err);
  ASSERT_TRUE(bin.has_value());
  ASSERT_EQ(bin->initial_validator_bls.size(), 4u);
  for (std::size_t i = 0; i < 4; ++i) {
    ASSERT_TRUE(bin->initial_validator_bls[i].pubkey == base->initial_validator_bls[i].pubkey);
    ASSERT_TRUE(bin->initial_validator_bls[i].pop == base->initial_validator_bls[i].pop);
  }
  ASSERT_TRUE(genesis::bls_keys_for(*base, {base->initial_validators[2]}).front() == base->initial_validator_bls[2].pubkey);

  auto missing = *base;
  missing.initial_validator_bls.pop_back();
  ASSERT_TRUE(!genesis::validate_document(missing, mainnet_network(), &err, 4));
  ASSERT_EQ(err, std::string("initial_validator_bls must have one entry per validator"));
  auto bad_pop = *base;
  std::swap(bad_pop.initial_validator_bls[0].pop, bad_pop.initial_validator_bls[1].pop);
  ASSERT_TRUE(!genesis::validate_document(bad_pop, mainnet_network(), &err, 4));
  ASSERT_EQ(err, std::string("invalid initial validator bls proof"));
  auto dup = *base;
  dup.initial_validator_bls[3] = dup.initial_validator_bls[0];
  ASSERT_TRUE(!genesis::validate_document(dup, mainnet_network(), &err, 4));
  ASSERT_EQ(err, std::string("duplicate initial validator bls key"));
  auto v1 = *base;
  v1.version = 1;  // the pre-BLS format
  ASSERT_TRUE(!genesis::validate_document(v1, mainnet_network(), &err, 4));
  // The keys are part of the genesis hash.
  ASSERT_TRUE(genesis::hash_doc(bad_pop) != genesis::hash_doc(*base));
}
