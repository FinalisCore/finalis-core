#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "common/network.hpp"
#include "utxo/tx.hpp"

namespace finalis::policy {

struct HashcashConfig {
  bool enabled{false};
  std::uint32_t base_bits{18};
  std::uint32_t max_bits{30};
  std::uint64_t epoch_seconds{60};
  std::uint64_t fee_exempt_min{1'000};
  std::size_t pressure_tx_threshold{1'000};
  std::size_t pressure_step_txs{500};
  std::uint32_t pressure_bits_per_step{1};
  std::size_t large_tx_bytes{2'048};
  std::uint32_t large_tx_extra_bits{1};
};

std::uint64_t hashcash_epoch_bucket(std::uint64_t unix_seconds, std::uint64_t epoch_seconds);
std::uint32_t required_hashcash_bits(const HashcashConfig& cfg, const Tx& tx, std::uint64_t fee,
                                     std::size_t mempool_size);
bool verify_hashcash_stamp(const Tx& tx, const NetworkConfig& network, const TxHashcashStamp& stamp,
                           const HashcashConfig& cfg, std::uint32_t required_bits, std::uint64_t now_unix_seconds,
                           std::string* err = nullptr);
bool apply_hashcash_stamp(Tx* tx, const NetworkConfig& network, const HashcashConfig& cfg, std::uint32_t bits,
                          std::uint64_t now_unix_seconds, std::uint64_t max_nonce = 0, std::string* err = nullptr);

}  // namespace finalis::policy
