// SPDX-License-Identifier: MIT

#pragma once

#include <string>

namespace finalis {

std::string expand_user_home(const std::string& path);
std::string default_db_dir_for_network(const std::string& network_name);
// Lightserver admin RPC Unix socket of a network. Its directory is that network's own systemd
// RuntimeDirectory (finalis/<network>), so mainnet and testnet services never share or remove it.
std::string default_admin_socket_path(const std::string& network_name);
bool ensure_private_dir(const std::string& path);

}  // namespace finalis

