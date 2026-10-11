// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>

#include "common/network.hpp"
#include "genesis/genesis.hpp"
#include "node/node.hpp"

namespace finalis::test {

// A mainnet-parameter genesis.json with the first `n_validators` deterministic test keys. Mainnet
// embeds no genesis before launch, so a test node needs one of these.
inline bool write_test_genesis_file(const std::string& path, std::size_t n_validators = 1) {
  const auto keys = node::Node::deterministic_test_keypairs();
  if (keys.size() < n_validators) return false;
  const auto& net = mainnet_network();
  genesis::Document d;
  d.version = 1;
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
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::trunc);
  out << genesis::to_json(d);
  return out.good();
}

}  // namespace finalis::test
