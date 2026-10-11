// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_genesis.hpp"
#include "support/test_paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "common/paths.hpp"
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

TEST(test_paths_default_db_dir_and_expand_home) {
  ASSERT_EQ(default_db_dir_for_network("mainnet"), "~/.finalis/mainnet");

  const std::string fake_home = finalis::test::unique_test_base("/tmp/finalis_test_home_paths");
#ifdef _WIN32
  _putenv_s("HOME", fake_home.c_str());
#else
  ::setenv("HOME", fake_home.c_str(), 1);
#endif
  ASSERT_EQ(expand_user_home("~/.finalis/mainnet"), fake_home + "/.finalis/mainnet");
}

TEST(test_node_default_db_path_uses_home_by_network) {
  const std::string home = finalis::test::unique_test_base("/tmp/finalis_test_home_default_db");
  std::filesystem::remove_all(home);
  std::filesystem::create_directories(home);
#ifdef _WIN32
  _putenv_s("HOME", home.c_str());
#else
  ::setenv("HOME", home.c_str(), 1);
#endif

  const std::string genesis_path = home + "/genesis.json";
  ASSERT_TRUE(finalis::test::write_test_genesis_file(genesis_path));
  std::vector<std::string> args = {"finalis-node", "--node-id", "0", "--disable-p2p", "--validator-passphrase",
                                   "test-passphrase", "--genesis", genesis_path};
  auto argv = make_argv(args);
  auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
  ASSERT_TRUE(cfg.has_value());

  node::Node n(*cfg);
  ASSERT_TRUE(n.init());
  const auto st = n.status();
  const std::string expected = home + "/.finalis/mainnet";
  ASSERT_EQ(st.db_dir, expected);
  ASSERT_TRUE(std::filesystem::exists(expected));
  n.stop();
}

TEST(test_parse_args_unescapes_comma_separated_peers_and_seeds) {
  std::vector<std::string> args = {
      "finalis-node",
      "--node-id",
      "0",
      "--disable-p2p",
      "--validator-passphrase",
      "test-passphrase",
      "--peers",
      "203.0.113.10:19440\\,198.51.100.20:19440",
      "--seeds",
      "1.2.3.4:19440\\,5.6.7.8:19440",
  };
  auto argv = make_argv(args);
  auto cfg = node::parse_args(static_cast<int>(argv.size()), argv.data());
  ASSERT_TRUE(cfg.has_value());
  ASSERT_EQ(cfg->peers.size(), 1u);
  ASSERT_EQ(cfg->peers[0], "203.0.113.10:19440,198.51.100.20:19440");
  ASSERT_EQ(cfg->seeds.size(), 1u);
  ASSERT_EQ(cfg->seeds[0], "1.2.3.4:19440,5.6.7.8:19440");
}
