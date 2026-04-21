// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>

std::vector<std::pair<std::string, TestFn>>& tests() {
  static std::vector<std::pair<std::string, TestFn>> t;
  return t;
}

Reg::Reg(const std::string& n, TestFn fn) { tests().push_back({n, std::move(fn)}); }

void register_codec_tests();
void register_chain_id_tests();
void register_crypto_tests();
void register_address_tests();
void register_p2p_tests();
void register_addrman_tests();
void register_monetary_tests();
void register_committee_schedule_tests();
void register_state_commitment_tests();
void register_smt_tests();
void register_bonding_tests();
void register_finality_certificate_tests();
void register_snapshot_tests();
void register_mempool_tests();
void register_hardening_tests();
void register_protocol_scope_tests();
void register_genesis_tests();
void register_paths_tests();
void register_keystore_tests();
void register_wallet_send_policy_tests();
void register_validator_onboarding_tests();
void register_integration_tests();
void register_lightserver_tests();

int main() {
#ifdef _WIN32
  if (std::getenv("FINALIS_TEST_QUIET_LOGS") == nullptr) {
    _putenv_s("FINALIS_TEST_QUIET_LOGS", "1");
  }
#else
  if (std::getenv("FINALIS_TEST_QUIET_LOGS") == nullptr) {
    setenv("FINALIS_TEST_QUIET_LOGS", "1", 1);
  }
#endif
  // Default test runner: current live epoch-ticket runtime.
  register_codec_tests();
  register_chain_id_tests();
  register_crypto_tests();
  register_address_tests();
  register_p2p_tests();
  register_addrman_tests();
  register_monetary_tests();
  register_committee_schedule_tests();
  register_state_commitment_tests();
  register_smt_tests();
  register_bonding_tests();
  register_finality_certificate_tests();
  register_snapshot_tests();
  register_mempool_tests();
  register_hardening_tests();
  register_protocol_scope_tests();
  register_genesis_tests();
  register_paths_tests();
  register_keystore_tests();
  register_wallet_send_policy_tests();
  register_validator_onboarding_tests();
  register_integration_tests();
  register_lightserver_tests();

  int failed = 0;
  std::vector<std::string> failed_names;
  const char* filter = std::getenv("FINALIS_TEST_FILTER");
  const char* shard_index_env = std::getenv("FINALIS_TEST_SHARD_INDEX");
  const char* shard_count_env = std::getenv("FINALIS_TEST_SHARD_COUNT");
  const std::size_t shard_count = shard_count_env ? static_cast<std::size_t>(std::atoi(shard_count_env)) : 1;
  const std::size_t shard_index = shard_index_env ? static_cast<std::size_t>(std::atoi(shard_index_env)) : 0;

  std::vector<std::pair<std::string, TestFn>> selected;
  selected.reserve(tests().size());
  std::size_t shard_counter = 0;
  for (const auto& [name, fn] : tests()) {
    if (filter && std::string(name).find(filter) == std::string::npos) continue;
    if (shard_count > 1 && (shard_counter++ % shard_count) != shard_index) continue;
    selected.push_back({name, fn});
  }

  const std::size_t total = selected.size();
  std::cout << "[tests] total=" << total;
  if (filter) std::cout << " filter=\"" << filter << "\"";
  if (shard_count > 1) std::cout << " shard=" << shard_index << "/" << shard_count;
  std::cout << std::endl;

  std::size_t index = 0;
  for (const auto& [name, fn] : selected) {
    ++index;
    std::cout << "[run " << index << "/" << total << "] " << name << std::endl;
    try {
      fn();
      std::cout << "[ok " << index << "/" << total << "] " << name << "\n";
    } catch (const std::exception& e) {
      ++failed;
      failed_names.push_back(name);
      std::cout << "[fail " << index << "/" << total << "] " << name << ": " << e.what() << "\n";
    }
  }
  if (failed) {
    std::cerr << "[failed-summary] count=" << failed << "\n";
    for (const auto& name : failed_names) {
      std::cerr << "[failed-summary] " << name << "\n";
    }
    std::cerr << failed << " tests failed\n";
    return 1;
  }
  std::cout << "all tests passed\n";
  return 0;
}
