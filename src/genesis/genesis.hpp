// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "common/network.hpp"
#include "common/types.hpp"

namespace finalis::genesis {

struct CommitteeParams {
  std::uint32_t min_committee{0};
  std::uint32_t max_committee{0};
  std::string sizing_rule{"min(MAX_COMMITTEE,ACTIVE_SIZE)"};
  std::uint32_t c{0};
};

struct Document {
  std::uint32_t version{1};
  std::string network_name{"mainnet"};
  std::uint32_t protocol_version{PROTOCOL_VERSION};
  std::array<std::uint8_t, 16> network_id{};
  std::uint32_t magic{0};
  std::uint64_t genesis_time_unix{0};
  std::uint64_t initial_height{0};
  std::vector<PubKey32> initial_validators;
  std::uint32_t initial_active_set_size{0};
  CommitteeParams initial_committee_params;
  std::string monetary_params_ref{"README.md#monetary-policy-7m-hard-cap"};
  std::vector<std::string> seeds;
  std::string note;
};

std::optional<Document> parse_json(const std::string& json_text, std::string* err = nullptr);
std::string to_json(const Document& doc);

Bytes encode_bin(const Document& doc);
std::optional<Document> decode_bin(const Bytes& bin, std::string* err = nullptr);

Hash32 hash_bin(const Bytes& bin);
Hash32 hash_doc(const Document& doc);
Hash32 block_id(const Document& doc);

bool validate_document(const Document& doc, const NetworkConfig& cfg, std::string* err = nullptr,
                       std::size_t min_validators = 1);

std::optional<Document> load_from_path(const std::string& path, std::string* err = nullptr);
std::optional<Bytes> load_bin_from_path(const std::string& path, std::string* err = nullptr);
bool write_bin_to_path(const std::string& path, const Bytes& bin, std::string* err = nullptr);

}  // namespace finalis::genesis
