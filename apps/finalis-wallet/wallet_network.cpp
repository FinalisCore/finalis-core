// SPDX-License-Identifier: MIT

#include "wallet_network.hpp"

#include "common/address.hpp"
#include "common/keystore.hpp"
#include "common/network.hpp"
#include "common/types.hpp"
#include "crypto/hash.hpp"

namespace finalis::wallet {

const std::vector<std::string>& wallet_network_names() {
  static const std::vector<std::string> names = {"mainnet", "testnet"};
  return names;
}

std::string normalize_wallet_network(const std::string& name) {
  return is_testnet_name(name) ? "testnet" : "mainnet";
}

std::string wallet_network_display_name(const std::string& network) {
  return wallet_network_is_testnet(network) ? "Testnet" : "Mainnet";
}

bool wallet_network_is_testnet(const std::string& network) { return normalize_wallet_network(network) == "testnet"; }

std::string wallet_settings_key(const std::string& network, const std::string& key) {
  const std::string net = normalize_wallet_network(network);
  return net == "mainnet" ? key : net + "/" + key;
}

std::vector<std::string> default_lightserver_endpoints(const std::string& network) {
  // Mirrors testnet/SEEDS.json lightservers_rpc. Mainnet publishes none before launch: use a local node.
  if (wallet_network_is_testnet(network)) return {"http://130.61.126.39:19544/rpc"};
  return {default_local_rpc_url(network)};
}

std::string default_local_rpc_url(const std::string& network) {
  const auto& net = network_by_name(normalize_wallet_network(network));
  return "http://127.0.0.1:" + std::to_string(net.lightserver_default_port) + "/rpc";
}

std::string default_node_db_dir_name(const std::string& network) { return normalize_wallet_network(network); }

std::optional<std::string> address_for_network(const std::string& pubkey_hex, const std::string& network) {
  const auto pubkey = hex_decode(pubkey_hex);
  if (!pubkey.has_value() || pubkey->size() != 32) return std::nullopt;
  return address::encode_p2pkh(keystore::hrp_for_network(normalize_wallet_network(network)), crypto::h160(*pubkey));
}

bool address_matches_network(const std::string& address, const std::string& network) {
  const auto decoded = address::decode(address);
  return decoded.has_value() && decoded->hrp == keystore::hrp_for_network(normalize_wallet_network(network));
}

std::string wallet_store_path(const std::string& wallet_file_path, const std::string& network) {
  const std::string net = normalize_wallet_network(network);
  return net == "mainnet" ? wallet_file_path + ".walletdb" : wallet_file_path + "." + net + ".walletdb";
}

}  // namespace finalis::wallet
