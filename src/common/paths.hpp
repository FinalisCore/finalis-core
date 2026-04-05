#pragma once

#include <string>

namespace finalis {

std::string expand_user_home(const std::string& path);
std::string default_db_dir_for_network(const std::string& network_name);
bool ensure_private_dir(const std::string& path);

}  // namespace finalis

