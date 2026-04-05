#include "policy/hashcash.hpp"

#include <algorithm>
#include <limits>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::policy {

namespace {

std::uint32_t leading_zero_bits(const Hash32& h) {
  std::uint32_t count = 0;
  for (std::uint8_t byte : h) {
    if (byte == 0) {
      count += 8;
      continue;
    }
    for (int bit = 7; bit >= 0; --bit) {
      if ((byte & (1u << bit)) == 0) {
        ++count;
      } else {
        return count;
      }
    }
  }
  return count;
}

Hash32 hashcash_digest(const NetworkConfig& network, const Tx& tx, const TxHashcashStamp& stamp) {
  codec::ByteWriter w;
  const auto txh = crypto::sha256d(tx.serialize_without_hashcash());
  const Bytes domain{'S', 'C', '-', 'H', 'C', '-', 'v', '1'};
  w.bytes(domain);
  w.bytes_fixed(network.network_id);
  w.bytes_fixed(txh);
  w.u64le(stamp.epoch_bucket);
  w.u64le(stamp.nonce);
  return crypto::sha256d(w.take());
}

}  // namespace

std::uint64_t hashcash_epoch_bucket(std::uint64_t unix_seconds, std::uint64_t epoch_seconds) {
  if (epoch_seconds == 0) return 0;
  return unix_seconds / epoch_seconds;
}

std::uint32_t required_hashcash_bits(const HashcashConfig& cfg, const Tx& tx, std::uint64_t fee,
                                     std::size_t mempool_size) {
  if (!cfg.enabled) return 0;
  if (fee >= cfg.fee_exempt_min) return 0;

  std::uint32_t bits = cfg.base_bits;
  const auto raw_size = tx.serialize_without_hashcash().size();
  if (raw_size >= cfg.large_tx_bytes) bits += cfg.large_tx_extra_bits;
  if (mempool_size > cfg.pressure_tx_threshold && cfg.pressure_step_txs > 0) {
    const auto extra = (mempool_size - cfg.pressure_tx_threshold) / cfg.pressure_step_txs;
    bits += static_cast<std::uint32_t>(extra) * cfg.pressure_bits_per_step;
  }
  return std::min(bits, cfg.max_bits);
}

bool verify_hashcash_stamp(const Tx& tx, const NetworkConfig& network, const TxHashcashStamp& stamp,
                           const HashcashConfig& cfg, std::uint32_t required_bits, std::uint64_t now_unix_seconds,
                           std::string* err) {
  if (stamp.version != 1) {
    if (err) *err = "hashcash version unsupported";
    return false;
  }
  if (stamp.bits < required_bits) {
    if (err) *err = "hashcash bits below required";
    return false;
  }

  const auto now_bucket = hashcash_epoch_bucket(now_unix_seconds, cfg.epoch_seconds);
  if (stamp.epoch_bucket + 1 < now_bucket || stamp.epoch_bucket > now_bucket + 1) {
    if (err) *err = "hashcash epoch expired";
    return false;
  }

  const auto digest = hashcash_digest(network, tx, stamp);
  if (leading_zero_bits(digest) < stamp.bits) {
    if (err) *err = "hashcash proof invalid";
    return false;
  }
  return true;
}

bool apply_hashcash_stamp(Tx* tx, const NetworkConfig& network, const HashcashConfig& cfg, std::uint32_t bits,
                          std::uint64_t now_unix_seconds, std::uint64_t max_nonce, std::string* err) {
  if (!tx) {
    if (err) *err = "tx missing";
    return false;
  }
  if (bits == 0) {
    tx->hashcash.reset();
    return true;
  }
  if (max_nonce == 0) max_nonce = std::numeric_limits<std::uint64_t>::max();

  TxHashcashStamp stamp;
  stamp.version = 1;
  stamp.epoch_bucket = hashcash_epoch_bucket(now_unix_seconds, cfg.epoch_seconds);
  stamp.bits = bits;

  for (std::uint64_t nonce = 0; nonce < max_nonce; ++nonce) {
    stamp.nonce = nonce;
    tx->hashcash = stamp;
    if (verify_hashcash_stamp(*tx, network, stamp, cfg, bits, now_unix_seconds, nullptr)) return true;
  }
  tx->hashcash.reset();
  if (err) *err = "hashcash search exhausted";
  return false;
}

}  // namespace finalis::policy
