// SPDX-License-Identifier: MIT

#include "common/paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

namespace finalis {
namespace {

std::string getenv_string(const char* name) {
  if (!name) return {};
  const char* value = std::getenv(name);
  if (!value) return {};
  return value;
}

std::string preferred_user_root() {
  std::string home = getenv_string("HOME");
  if (!home.empty()) return home;
#ifdef _WIN32
  std::string appdata = getenv_string("APPDATA");
  if (!appdata.empty()) return appdata;

  std::string userprofile = getenv_string("USERPROFILE");
  if (!userprofile.empty()) return userprofile;

  std::string homedrive = getenv_string("HOMEDRIVE");
  std::string homepath = getenv_string("HOMEPATH");
  if (!homedrive.empty() && !homepath.empty()) return homedrive + homepath;
#endif
  return {};
}

}  // namespace

std::string expand_user_home(const std::string& path) {
  if (path.empty() || path[0] != '~') return path;
  const std::string home = preferred_user_root();
  if (home.empty()) return path;
  if (path == "~") return home;
  if (path.size() > 1 && (path[1] == '/' || path[1] == '\\')) return home + path.substr(1);
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
