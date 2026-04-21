// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/chain_id.hpp"
#include "common/types.hpp"
#include "onboarding/validator_onboarding.hpp"

namespace finalis::lightserver {

struct RpcStatusView {
  finalis::ChainId chain;
  std::uint64_t tip_height{0};
  std::string transition_hash;
  std::string version;
  std::string binary_version;
  std::string wallet_api_version;
  std::optional<std::uint64_t> healthy_peer_count;
  std::optional<std::uint64_t> established_peer_count;
  std::optional<std::uint64_t> observed_network_finalized_height;
  std::optional<std::uint64_t> finalized_lag;
  bool chain_id_ok{true};
  bool observed_network_height_known{false};
  bool peer_height_disagreement{false};
  bool bootstrap_sync_incomplete{false};
  std::optional<std::string> checkpoint_derivation_mode;
  std::optional<std::string> checkpoint_fallback_reason;
  std::optional<bool> fallback_sticky;
  std::optional<std::uint64_t> qualified_depth;
  std::optional<std::uint64_t> adaptive_target_committee_size;
  std::optional<std::uint64_t> adaptive_min_eligible;
  std::optional<std::uint64_t> adaptive_min_bond;
  std::optional<std::int64_t> adaptive_slack;
  std::optional<std::uint64_t> target_expand_streak;
  std::optional<std::uint64_t> target_contract_streak;
  std::optional<std::uint64_t> fallback_rate_bps;
  std::optional<std::uint64_t> sticky_fallback_rate_bps;
  std::optional<std::uint64_t> fallback_rate_window_epochs;
  std::optional<bool> near_threshold_operation;
  std::optional<bool> prolonged_expand_buildup;
  std::optional<bool> prolonged_contract_buildup;
  std::optional<bool> repeated_sticky_fallback;
  std::optional<bool> depth_collapse_after_bond_increase;
};

struct UtxoView {
  Hash32 txid{};
  std::uint32_t vout{0};
  std::uint64_t value{0};
  std::uint64_t height{0};
  Bytes script_pubkey;
};

struct AddressValidationView {
  bool valid{false};
  bool server_network_match{false};
  std::string normalized_address;
  std::string network_hint;
  std::string server_network_hrp;
  std::string addr_type;
  std::string pubkey_hash_hex;
  std::string script_pubkey_hex;
  Hash32 scripthash{};
  bool has_scripthash{false};
  std::string error;
};

struct HistoryEntry {
  Hash32 txid{};
  std::uint64_t height{0};
};

struct HistoryCursor {
  std::uint64_t height{0};
  Hash32 txid{};
};

struct HistoryPageView {
  std::vector<HistoryEntry> items;
  bool has_more{false};
  std::optional<HistoryCursor> next_start_after;
};

struct DetailedHistoryEntry {
  Hash32 txid{};
  std::uint64_t height{0};
  std::string direction;
  std::int64_t net_amount{0};
  std::string detail;
};

struct DetailedHistoryPageView {
  std::vector<DetailedHistoryEntry> items;
  bool has_more{false};
  std::optional<HistoryCursor> next_start_after;
};

struct TxView {
  std::uint64_t height{0};
  Bytes tx_bytes;
};

struct TxStatusView {
  std::string txid_hex;
  std::string status;
  bool finalized{false};
  std::uint64_t height{0};
  std::uint64_t finalized_depth{0};
  bool credit_safe{false};
  std::string transition_hash;
};

enum class BroadcastOutcome : std::uint8_t {
  // Lightserver reported accepted-for-relay. This is not proof of inclusion or
  // finalization.
  Sent = 1,
  // Lightserver returned an explicit rejection result.
  Rejected = 2,
  // Caller could not trust the RPC result path itself. This is transport or
  // response ambiguity, not a chain-level verdict.
  Ambiguous = 3,
};

struct BroadcastResult {
  BroadcastOutcome outcome{BroadcastOutcome::Ambiguous};
  std::string txid_hex;
  std::string error;
  std::string error_code;
  std::string error_message;
  std::string message;
  bool retryable{false};
  std::string retry_class{"none"};
  bool mempool_full{false};
  std::optional<std::uint64_t> min_fee_rate_to_enter_when_full;
};

std::optional<RpcStatusView> rpc_get_status(const std::string& rpc_url, std::string* err);
std::optional<AddressValidationView> rpc_validate_address(const std::string& rpc_url, const std::string& address, std::string* err);
std::optional<std::vector<UtxoView>> rpc_get_utxos(const std::string& rpc_url, const Hash32& scripthash, std::string* err);
std::optional<std::vector<HistoryEntry>> rpc_get_history(const std::string& rpc_url, const Hash32& scripthash,
                                                         std::string* err);
std::optional<HistoryPageView> rpc_get_history_page(const std::string& rpc_url, const Hash32& scripthash, std::uint64_t limit,
                                                    const std::optional<HistoryCursor>& start_after, std::string* err);
std::optional<DetailedHistoryPageView> rpc_get_history_page_detailed(const std::string& rpc_url, const Hash32& scripthash,
                                                                     std::uint64_t limit,
                                                                     const std::optional<HistoryCursor>& start_after,
                                                                     std::string* err);
std::optional<TxView> rpc_get_tx(const std::string& rpc_url, const Hash32& txid, std::string* err);
std::optional<TxStatusView> rpc_get_tx_status(const std::string& rpc_url, const Hash32& txid, std::string* err);
BroadcastResult rpc_broadcast_tx(const std::string& rpc_url, const Bytes& tx_bytes, std::string* err);
std::optional<onboarding::ValidatorOnboardingRecord> rpc_validator_onboarding_status(
    const std::string& rpc_url, const onboarding::ValidatorOnboardingOptions& options, const std::string& tracked_txid_hex,
    std::string* err);
std::optional<onboarding::ValidatorOnboardingRecord> rpc_validator_onboarding_start(
    const std::string& rpc_url, const onboarding::ValidatorOnboardingOptions& options, std::string* err);
std::optional<std::string> http_post_json_raw(const std::string& url, const std::string& body, std::string* err);

}  // namespace finalis::lightserver
