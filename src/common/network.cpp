#include "common/network.hpp"

#include <algorithm>
#include <limits>

#include "crypto/hash.hpp"

namespace finalis {
namespace {

constexpr std::uint64_t kEconomicsV2ActivationHeight = 0;
constexpr std::uint64_t kCoin = 100'000'000ULL;

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
        std::array<std::uint8_t, 16>{0xbb, 0x70, 0x48, 0xf8, 0xdb, 0xe7, 0xb7, 0xd7,
                                     0x53, 0xd6, 0x2a, 0xb3, 0x22, 0x81, 0x3f, 0x1b},
    .magic = 2038198198,
    .protocol_version = PROTOCOL_VERSION,
    .feature_flags = 1ULL,  // bit0: strict-version-handshake-v0.7
    .p2p_default_port = 19440,
    .lightserver_default_port = 19444,
    .max_committee = MAX_COMMITTEE,
    .committee_epoch_blocks = 32,
    .round_timeout_ms = 30'000,
    .min_block_interval_ms = 180'000,
    .max_payload_len = 8 * 1024 * 1024,
    .bond_amount = BOND_AMOUNT,
    .warmup_blocks = WARMUP_BLOCKS,
    .unbond_delay_blocks = UNBOND_DELAY_BLOCKS,
    .validator_min_bond = BOND_AMOUNT,
    .validator_bond_min_amount = BOND_AMOUNT,
    .validator_bond_max_amount = BOND_AMOUNT * 100,
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
    .finality_binding_activation_height = std::numeric_limits<std::uint64_t>::max(),
    .availability_recovery_activation_height = std::numeric_limits<std::uint64_t>::max(),
    .confidential_utxo_activation_height = std::numeric_limits<std::uint64_t>::max(),
    .default_seeds = {},
    .economics_policies =
        {
            EconomicsConfig{
                .activation_height = kEconomicsV2ActivationHeight,
                .target_validators = 16,
                .base_min_bond = 100ULL * kCoin,
                .min_bond_floor = BOND_AMOUNT,
                .min_bond_ceiling = BOND_AMOUNT * 10,
                .max_effective_bond_multiple = 10,
                .participation_threshold_bps = 8'000,
                .ticket_bonus_cap_bps = 1'000,
            },
        },
};

}  // namespace

const NetworkConfig& mainnet_network() { return kMainnet; }

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

bool onboarding_admission_pow_enabled(const NetworkConfig& network) {
  return network.onboarding_admission_pow_difficulty_bits != 0;
}

bool validator_join_admission_pow_enabled(const NetworkConfig& network) {
  return network.validator_join_admission_pow_difficulty_bits != 0;
}

}  // namespace finalis
