#include "common/paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <system_error>

namespace finalis {

std::string expand_user_home(const std::string& path) {
  if (path.empty() || path[0] != '~') return path;
  const char* home = std::getenv("HOME");
  if (!home || std::string(home).empty()) return path;
  if (path == "~") return std::string(home);
  if (path.size() > 1 && path[1] == '/') return std::string(home) + path.substr(1);
  return path;
}

std::string default_db_dir_for_network(const std::string& network_name) {
  return "~/.finalis/" + network_name;
}

bool ensure_private_dir(const std::string& path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    if (!std::filesystem::create_directories(path, ec)) return false;
  }
  std::filesystem::permissions(path, std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace, ec);
  return true;
}

}  // namespace finalis
