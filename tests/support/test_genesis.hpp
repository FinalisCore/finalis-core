// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <vector>
#include <filesystem>
#include <fstream>
#include <string>

#include "common/network.hpp"
#include "genesis/genesis.hpp"
#include "node/node.hpp"
#include "utxo/signing.hpp"

namespace finalis::test {

// Fills d.initial_validator_bls for d.initial_validators from their private keys (the deterministic
// test keys by default), as finalis-cli validator_bls would for a real genesis. Throws if a
// validator's key is not among them.
inline void fill_test_genesis_bls(genesis::Document& d, const std::vector<crypto::KeyPair>& extra_keys = {}) {
  auto keys = node::Node::deterministic_test_keypairs();
  keys.insert(keys.end(), extra_keys.begin(), extra_keys.end());
  d.initial_validator_bls.clear();
  for (const auto& pub : d.initial_validators) {
    const auto it = std::find_if(keys.begin(), keys.end(), [&](const crypto::KeyPair& k) { return k.public_key == pub; });
    if (it == keys.end()) throw std::runtime_error("fill_test_genesis_bls: no private key for a genesis validator");
    const auto reg = validator_bls_registration(it->private_key);
    if (!reg) throw std::runtime_error("fill_test_genesis_bls: derivation failed");
    d.initial_validator_bls.push_back(genesis::ValidatorBls{reg->pubkey, reg->pop});
  }
}

// A mainnet-parameter genesis.json with the first `n_validators` deterministic test keys. Mainnet
// embeds no genesis before launch, so a test node needs one of these.
inline bool write_test_genesis_file(const std::string& path, std::size_t n_validators = 1) {
  const auto keys = node::Node::deterministic_test_keypairs();
  if (keys.size() < n_validators) return false;
  const auto& net = mainnet_network();
  genesis::Document d;
  d.version = genesis::kGenesisVersion;
  d.network_name = net.name;
  d.protocol_version = net.protocol_version;
  d.network_id = net.network_id;
  d.magic = net.magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = static_cast<std::uint32_t>(n_validators);
  d.initial_committee_params.min_committee = static_cast<std::uint32_t>(n_validators);
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(net.max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.note = "test";
  for (std::size_t i = 0; i < n_validators; ++i) d.initial_validators.push_back(keys[i].public_key);
  fill_test_genesis_bls(d);
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  out << genesis::to_json(d);
  return out.good();
}

}  // namespace finalis::test
