// SPDX-License-Identifier: MIT

#include "common/network.hpp"

#include <algorithm>
#include <limits>

#include "crypto/hash.hpp"

namespace finalis {
namespace {

constexpr std::uint64_t kEconomicsV2ActivationHeight = 0;
constexpr std::uint64_t kCoin = 100'000'000ULL;

constexpr std::uint64_t kTargetValidators = 16;
constexpr std::uint64_t kBaseMinBond = 1'000ULL * kCoin;
constexpr std::uint64_t kMinBondFloor = 1'000ULL * kCoin;
constexpr std::uint64_t kValidatorBondMaxAmount = BOND_AMOUNT * 100;
// The adaptive minimum bond must never exceed the structural bond cap.
constexpr std::uint64_t kMinBondCeiling = kValidatorBondMaxAmount;

constexpr std::uint64_t constexpr_isqrt(std::uint64_t v) {
  std::uint64_t r = 0;
  while ((r + 1) * (r + 1) <= v) ++r;
  return r;
}
// Peak of consensus::validator_min_bond_units (one active operator, before clamping).
constexpr std::uint64_t kAdaptiveMinBondPeak = kBaseMinBond * constexpr_isqrt(kTargetValidators * 100'000'000ULL) / 10'000ULL;

static_assert(kMinBondFloor <= kMinBondCeiling, "min bond floor exceeds ceiling");
static_assert(kMinBondCeiling <= kValidatorBondMaxAmount, "adaptive min bond ceiling exceeds bond max");
static_assert(kAdaptiveMinBondPeak <= kMinBondCeiling, "adaptive min bond can be clamped by the ceiling");

std::array<std::uint8_t, 16> network_id_for_name(const std::string& name) {
  const std::string s = "finalis:" + name;
  const Hash32 h = crypto::sha256(Bytes(s.begin(), s.end()));
  std::array<std::uint8_t, 16> out{};
  std::copy(h.begin(), h.begin() + 16, out.begin());
  return out;
}

const NetworkConfig kMainnet{
    .name = "mainnet",
    .network_id =
        std::array<std::uint8_t, 16>{0xfe, 0x56, 0x19, 0x11, 0x73, 0x09, 0x12, 0xcc, 0xed, 0x1e, 0x83, 0xbc, 0x27, 0x3f, 0xab, 0x13},
    .magic = MAGIC,
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,  // bit0: strict-version-handshake-v0.7
    .p2p_default_port = 19440,
    .lightserver_default_port = 19444,
    .max_committee = MAX_COMMITTEE,
    .committee_epoch_blocks = 32,
    .round_timeout_ms = 30'000,
    .max_round_timeout_ms = 300'000,
    .round_timeout_backoff_num = 3,
    .round_timeout_backoff_den = 2,
    .min_block_interval_ms = 180'000,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .validator_min_bond = BOND_AMOUNT,
    .validator_bond_min_amount = BOND_AMOUNT,
    .validator_bond_max_amount = kValidatorBondMaxAmount,
    .validator_warmup_blocks = WARMUP_BLOCKS,
    .validator_cooldown_blocks = 100,
    .validator_join_limit_window_blocks = 1'000,
    .validator_join_limit_max_new = 64,
    .liveness_window_blocks = 10'000,
    .miss_rate_suspend_threshold_percent = 30,
    .miss_rate_exit_threshold_percent = 60,
    .suspend_duration_blocks = 1'000,
    .onboarding_admission_pow_difficulty_bits = 20,
    .validator_join_admission_pow_difficulty_bits = 22,
    // CLEANSLATE: These finalized-state protections are enabled at restart genesis.
    .finality_binding_activation_height = 0,
    .availability_recovery_activation_height = 0,
    .confidential_utxo_activation_height = std::numeric_limits<std::uint64_t>::max(),
    // CLEANSLATE: Fresh genesis; these protections are active from genesis.
    .deferred_exit_activation_height = 0,
    .bootstrap_penalty_exit_protection_activation_height = 0,
    .empty_active_set_epoch_escape_activation_height = 0,
    .default_seeds = {"85.217.171.168:19440", "64.23.244.126:19440"},
    .economics_policies =
        {
            EconomicsConfig{
                .activation_height = kEconomicsV2ActivationHeight,
                .target_validators = kTargetValidators,
                // CLEANSLATE: Adaptive min bond ranges 1,000-4,000 FLS; the ceiling
                // is pinned to validator_bond_max_amount (see static_asserts above).
                .base_min_bond = kBaseMinBond,
                .min_bond_floor = kMinBondFloor,
                .min_bond_ceiling = kMinBondCeiling,
                .max_effective_bond_multiple = 10,
                .participation_threshold_bps = 8'000,
                .ticket_bonus_cap_bps = 1'000,
            },
        },
};

}  // namespace

const NetworkConfig& mainnet_network() { return kMainnet; }

std::uint64_t round_timeout_ms_for_round(const NetworkConfig& network, std::uint32_t round) {
  const std::uint64_t base = std::max<std::uint64_t>(1, network.round_timeout_ms);
  const std::uint64_t cap = std::max<std::uint64_t>(base, network.max_round_timeout_ms);
  const std::uint64_t num = network.round_timeout_backoff_num;
  const std::uint64_t den = std::max<std::uint64_t>(1, network.round_timeout_backoff_den);
  if (num <= den) return base;
  std::uint64_t timeout = base;
  // timeout <= cap < 2^32 and num < 2^32, so timeout * num cannot overflow.
  // Growing by at least 1 per step bounds the loop by ~log(cap), never by round.
  for (std::uint32_t r = 0; r < round && timeout < cap; ++r) {
    timeout = std::max(timeout + 1, timeout * num / den);
  }
  return std::min(timeout, cap);
}

const NetworkConfig& network_by_name(const std::string&) { return kMainnet; }

const std::vector<EconomicsConfig>& economics_policies(const NetworkConfig& network) { return network.economics_policies; }

const EconomicsConfig& active_economics_policy(const NetworkConfig& network, std::uint64_t height) {
  const auto& policies = economics_policies(network);
  const EconomicsConfig* active = policies.empty() ? nullptr : &policies.front();
  for (const auto& cfg : policies) {
    if (cfg.activation_height > height) break;
    active = &cfg;
  }
  return *active;
}

bool finality_binding_active_at_height(const NetworkConfig& network, std::uint64_t height) {
  return height > network.finality_binding_activation_height;
}

bool availability_recovery_active_at_height(const NetworkConfig& network, std::uint64_t height) {
  return height >= network.availability_recovery_activation_height;
}

bool confidential_utxo_active_at_height(const NetworkConfig& network, std::uint64_t height) {
  return height >= network.confidential_utxo_activation_height;
}

bool bootstrap_penalty_exit_protection_active_at_height(const NetworkConfig& network, std::uint64_t height) {
  return height >= network.bootstrap_penalty_exit_protection_activation_height;
}

bool empty_active_set_epoch_escape_active_at_height(const NetworkConfig& network, std::uint64_t height) {
  return height >= network.empty_active_set_epoch_escape_activation_height;
}

bool onboarding_admission_pow_enabled(const NetworkConfig& network) {
  return network.onboarding_admission_pow_difficulty_bits != 0;
}

bool validator_join_admission_pow_enabled(const NetworkConfig& network) {
  return network.validator_join_admission_pow_difficulty_bits != 0;
}

}  // namespace finalis
