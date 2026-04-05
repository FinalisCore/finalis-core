#include "test_framework.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "keystore/validator_keystore.hpp"
#include "node/node.hpp"

using namespace finalis;

namespace {

std::vector<char*> make_argv(std::vector<std::string>& args) {
  std::vector<char*> out;
  out.reserve(args.size());
  for (auto& a : args) out.push_back(a.data());
  return out;
}

}  // namespace

TEST(test_keystore_create_and_load_roundtrip) {
  const std::string root = "/tmp/finalis_test_keystore";
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
  const std::string root = "/tmp/finalis_test_keystore_badpass";
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
  const std::string root = "/tmp/finalis_test_keystore_nopass";
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

TEST(test_node_parse_args_validator_passphrase_env) {
  ::setenv("FINALIS_TEST_VALIDATOR_PASS", "env-secret", 1);
  std::vector<std::string> args = {"finalis-node", "--node-id", "0",
                                   "--validator-passphrase-env", "FINALIS_TEST_VALIDATOR_PASS"};
  auto argv = make_argv(args);
  auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
  ASSERT_TRUE(cfg.has_value());
  ASSERT_EQ(cfg->validator_passphrase, "env-secret");
}

void register_keystore_tests() {}
