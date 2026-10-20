// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>
#include <vector>

namespace finalis::wallet {

// The networks the desktop wallet can switch between. Any other name maps to mainnet.
const std::vector<std::string>& wallet_network_names();
std::string normalize_wallet_network(const std::string& name);
std::string wallet_network_display_name(const std::string& network);
bool wallet_network_is_testnet(const std::string& network);

// Mainnet keeps the original settings keys; other networks keep theirs under "<network>/".
std::string wallet_settings_key(const std::string& network, const std::string& key);

std::vector<std::string> default_lightserver_endpoints(const std::string& network);
std::string default_local_rpc_url(const std::string& network);
std::string default_node_db_dir_name(const std::string& network);

// The same key on another network: its P2PKH address with that network's prefix.
std::optional<std::string> address_for_network(const std::string& pubkey_hex, const std::string& network);
bool address_matches_network(const std::string& address, const std::string& network);

// Local wallet state (history, coins, confidential accounts) is kept apart per network.
std::string wallet_store_path(const std::string& wallet_file_path, const std::string& network);

}  // namespace finalis::wallet
