// SPDX-License-Identifier: MIT

#include "test_framework.hpp"
#include "support/test_genesis.hpp"
#include "support/test_paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "common/paths.hpp"
#include "lightserver/client.hpp"
#include "lightserver/server.hpp"
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

TEST(test_admin_socket_default_is_per_network) {
  ASSERT_EQ(default_admin_socket_path("mainnet"), "/var/run/finalis/mainnet/admin.sock");
  ASSERT_EQ(default_admin_socket_path("testnet"), "/var/run/finalis/testnet/admin.sock");
  ASSERT_EQ(lightserver::default_admin_rpc_url("testnet"), "unix:///var/run/finalis/testnet/admin.sock");

  std::vector<std::string> node_args = {"finalis-node", "--testnet", "--disable-p2p"};
  auto node_argv = make_argv(node_args);
  auto node_cfg = node::parse_args(static_cast<int>(node_argv.size()), node_argv.data());
  ASSERT_TRUE(node_cfg.has_value());
  ASSERT_EQ(node_cfg->lightserver_admin_socket, "/var/run/finalis/testnet/admin.sock");

  std::vector<std::string> ls_args = {"finalis-lightserver", "--testnet"};
  auto ls_argv = make_argv(ls_args);
  auto ls_cfg = lightserver::parse_args(static_cast<int>(ls_argv.size()), ls_argv.data());
  ASSERT_TRUE(ls_cfg.has_value());
  ASSERT_EQ(ls_cfg->admin_socket_path, "/var/run/finalis/testnet/admin.sock");

  std::vector<std::string> ls_main_args = {"finalis-lightserver"};
  auto ls_main_argv = make_argv(ls_main_args);
  auto ls_main_cfg = lightserver::parse_args(static_cast<int>(ls_main_argv.size()), ls_main_argv.data());
  ASSERT_TRUE(ls_main_cfg.has_value());
  ASSERT_EQ(ls_main_cfg->admin_socket_path, "/var/run/finalis/mainnet/admin.sock");
}

TEST(test_node_lightserver_trusted_proxy_arg) {
  std::vector<std::string> ok_args = {"finalis-node", "--testnet", "--disable-p2p", "--lightserver-trusted-proxy", "127.0.0.1/32"};
  auto ok_argv = make_argv(ok_args);
  auto ok_cfg = node::parse_args(static_cast<int>(ok_argv.size()), ok_argv.data());
  ASSERT_TRUE(ok_cfg.has_value());
  ASSERT_EQ(ok_cfg->lightserver_trusted_proxy, "127.0.0.1/32");
  ASSERT_TRUE(ok_cfg->lightserver_client_ip_header.empty());
  std::vector<std::string> cf_args = {"finalis-node", "--testnet", "--disable-p2p", "--lightserver-client-ip-header", "CF-Connecting-IP"};
  auto cf_argv = make_argv(cf_args);
  auto cf_cfg = node::parse_args(static_cast<int>(cf_argv.size()), cf_argv.data());
  ASSERT_TRUE(cf_cfg.has_value());
  ASSERT_EQ(cf_cfg->lightserver_client_ip_header, "CF-Connecting-IP");
  std::vector<std::string> bad_hdr = {"finalis-node", "--testnet", "--disable-p2p", "--lightserver-client-ip-header", "a b"};
  auto bad_hdr_argv = make_argv(bad_hdr);
  ASSERT_TRUE(!node::parse_args(static_cast<int>(bad_hdr_argv.size()), bad_hdr_argv.data()).has_value());

  // Rejected here, not later in the lightserver child where the failure is only a log line.
  std::vector<std::string> bad_args = {"finalis-node", "--testnet", "--disable-p2p", "--lightserver-trusted-proxy", "localhost"};
  auto bad_argv = make_argv(bad_args);
  ASSERT_TRUE(!node::parse_args(static_cast<int>(bad_argv.size()), bad_argv.data()).has_value());
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
