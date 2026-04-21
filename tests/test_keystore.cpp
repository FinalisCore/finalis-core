#include "test_framework.hpp"

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
#include <string>
#include <vector>

#include "common/keystore.hpp"
#include "node/node.hpp"

using namespace finalis;

namespace {

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> seq{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return prefix + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

std::vector<char*> make_argv(std::vector<std::string>& args) {
  std::vector<char*> out;
  out.reserve(args.size());
  for (auto& a : args) out.push_back(a.data());
  return out;
}

}  // namespace

TEST(test_keystore_create_and_load_roundtrip) {
  const std::string root = unique_test_base("/tmp/finalis_test_keystore");
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
  const std::string ks = root + "/validator.json";

  std::array<std::uint8_t, 32> seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i + 1);

  keystore::ValidatorKey created;
  std::string err;
  ASSERT_TRUE(keystore::create_validator_keystore(ks, "pass123", "mainnet", "sc", seed, &created, &err));
  ASSERT_TRUE(keystore::keystore_exists(ks));
  ASSERT_EQ(created.network_name, "mainnet");

  keystore::ValidatorKey loaded;
  ASSERT_TRUE(keystore::load_validator_keystore(ks, "pass123", &loaded, &err));
  ASSERT_EQ(created.privkey, loaded.privkey);
  ASSERT_EQ(created.pubkey, loaded.pubkey);
  ASSERT_EQ(created.address, loaded.address);
  ASSERT_EQ(created.network_name, loaded.network_name);
}

TEST(test_keystore_rejects_wrong_passphrase) {
  const std::string root = unique_test_base("/tmp/finalis_test_keystore_badpass");
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
  const std::string ks = root + "/validator.json";

  keystore::ValidatorKey created;
  std::string err;
  ASSERT_TRUE(keystore::create_validator_keystore(ks, "correct", "mainnet", "sc", std::nullopt, &created, &err));

  keystore::ValidatorKey loaded;
  ASSERT_TRUE(!keystore::load_validator_keystore(ks, "wrong", &loaded, &err));
}

TEST(test_keystore_create_and_load_without_passphrase) {
  const std::string root = unique_test_base("/tmp/finalis_test_keystore_nopass");
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);
  const std::string ks = root + "/validator.json";

  keystore::ValidatorKey created;
  std::string err;
  ASSERT_TRUE(keystore::create_validator_keystore(ks, "", "mainnet", "sc", std::nullopt, &created, &err));

  keystore::ValidatorKey loaded;
  ASSERT_TRUE(keystore::load_validator_keystore(ks, "", &loaded, &err));
  ASSERT_EQ(created.privkey, loaded.privkey);
  ASSERT_EQ(created.pubkey, loaded.pubkey);
  ASSERT_EQ(created.address, loaded.address);
}

TEST(test_keystore_distinct_seeds_produce_distinct_addresses) {
  const std::string root = unique_test_base("/tmp/finalis_test_keystore_distinct_addresses");
  std::filesystem::remove_all(root);
  std::filesystem::create_directories(root);

  std::array<std::uint8_t, 32> seed_a{};
  std::array<std::uint8_t, 32> seed_b{};
  for (std::size_t i = 0; i < seed_a.size(); ++i) {
    seed_a[i] = static_cast<std::uint8_t>(i + 1);
    seed_b[i] = static_cast<std::uint8_t>(0x80 + i);
  }

  keystore::ValidatorKey key_a;
  keystore::ValidatorKey key_b;
  std::string err;
  ASSERT_TRUE(
      keystore::create_validator_keystore(root + "/a.json", "", "mainnet", "sc", seed_a, &key_a, &err));
  ASSERT_TRUE(
      keystore::create_validator_keystore(root + "/b.json", "", "mainnet", "sc", seed_b, &key_b, &err));

  ASSERT_TRUE(key_a.pubkey != key_b.pubkey);
  ASSERT_TRUE(key_a.address != key_b.address);
  ASSERT_TRUE(key_a.address != "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy");
  ASSERT_TRUE(key_b.address != "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy");
}

TEST(test_node_parse_args_validator_passphrase_env) {
#ifdef _WIN32
  _putenv_s("FINALIS_TEST_VALIDATOR_PASS", "env-secret");
#else
  ::setenv("FINALIS_TEST_VALIDATOR_PASS", "env-secret", 1);
#endif
  std::vector<std::string> args = {"finalis-node", "--node-id", "0",
                                   "--validator-passphrase-env", "FINALIS_TEST_VALIDATOR_PASS"};
  auto argv = make_argv(args);
  auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
  ASSERT_TRUE(cfg.has_value());
  ASSERT_EQ(cfg->validator_passphrase, "env-secret");
}

void register_keystore_tests() {}
