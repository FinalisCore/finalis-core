// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace finalis {

using Bytes = std::vector<std::uint8_t>;
using Hash32 = std::array<std::uint8_t, 32>;
using PubKey32 = std::array<std::uint8_t, 32>;
using PubKey33 = std::array<std::uint8_t, 33>;
using Sig64 = std::array<std::uint8_t, 64>;

constexpr std::uint32_t MAGIC = 0x53434F49;
constexpr std::uint16_t PROTOCOL_VERSION = 1;
constexpr std::uint64_t BLOCK_REWARD = 50'0000'0000ULL;
constexpr std::uint64_t BOND_AMOUNT = 50'0000'0000ULL;
constexpr std::uint64_t WARMUP_BLOCKS = 100;
constexpr std::uint64_t UNBOND_DELAY_BLOCKS = 100;
constexpr std::uint32_t ROUND_TIMEOUT_MS = 5000;
constexpr std::uint64_t MAX_FUTURE_DRIFT_SECONDS = 120;
constexpr std::size_t MAX_COMMITTEE = 128;

std::string hex_encode(const Bytes& data);
std::string hex_encode32(const Hash32& h);
std::optional<Bytes> hex_decode(const std::string& s);
Hash32 zero_hash();

}  // namespace finalis
