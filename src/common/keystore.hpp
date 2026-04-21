// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <optional>
#include <string>

#include "common/types.hpp"

namespace finalis::keystore {

struct ValidatorKey {
  std::array<std::uint8_t, 32> privkey{};
  PubKey32 pubkey{};
  std::string address;
  std::string network_name;
};

bool create_validator_keystore(const std::string& path, const std::string& passphrase, const std::string& network_name,
                               const std::string& hrp, const std::optional<std::array<std::uint8_t, 32>>& seed_override,
                               ValidatorKey* out, std::string* err);

bool load_validator_keystore(const std::string& path, const std::string& passphrase, ValidatorKey* out, std::string* err);

bool keystore_exists(const std::string& path);

std::string default_validator_keystore_path(const std::string& db_dir);

std::string hrp_for_network(const std::string& network_name);

}  // namespace finalis::keystore

