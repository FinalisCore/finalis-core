// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <map>
#include <deque>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <regex>

#include <openssl/hmac.h>

#include "common/address.hpp"
#include "codec/bytes.hpp"
#include "common/minijson.hpp"
#include "common/paths.hpp"
#include "common/socket_compat.hpp"
#include "crypto/hash.hpp"
#include "lightserver/client.hpp"
#include "utxo/tx.hpp"

namespace {

using finalis::Bytes;
using finalis::Hash32;

struct Config {
  std::string bind_ip{"127.0.0.1"};
  std::uint16_t port{18080};
  std::string rpc_url{"http://127.0.0.1:19444/rpc"};
  std::string cache_path;
  bool partner_auth_required{false};
  std::string partner_api_key;
  std::string partner_api_secret;
  std::string partner_registry_path;
  std::uint64_t partner_auth_max_skew_seconds{300};
  std::uint64_t partner_rate_limit_per_minute{600};
  std::uint64_t partner_webhook_max_attempts{5};
  std::uint64_t partner_webhook_initial_backoff_ms{1000};
  std::uint64_t partner_webhook_max_backoff_ms{60000};
  std::uint64_t partner_idempotency_ttl_seconds{7 * 24 * 60 * 60};
  std::uint64_t partner_events_ttl_seconds{30 * 24 * 60 * 60};
  std::uint64_t partner_webhook_queue_ttl_seconds{7 * 24 * 60 * 60};
  bool partner_mtls_required{false};
  std::vector<std::string> partner_allowed_ipv4_cidrs_raw;
  std::string partner_webhook_audit_log_path;
};

template <typename T>
struct LookupResult;

struct TxSummaryBatchItem;
struct TxResult;
struct TransitionResult;
LookupResult<TxResult> fetch_tx_result(const Config& cfg, const std::string& txid_hex);
std::map<std::string, TxSummaryBatchItem> fetch_tx_summary_batch(const Config& cfg, const std::vector<std::string>& txids);

struct ApiError {
  int http_status{500};
  std::string code;
  std::string message;
};

struct HttpRequest {
  std::string method;
  std::string target;
  std::map<std::string, std::string> headers;
  std::string body;
};

struct PartnerEvent {
  std::uint64_t sequence{0};
  std::string partner_id;
  std::string event_type;
  std::string object_id;
  std::string state;
  std::uint64_t emitted_unix_ms{0};
};

struct PartnerAuthRecord {
  std::string partner_id;
  std::string api_key;
  std::string active_secret;
  std::optional<std::string> next_secret;
  std::string lifecycle_state{"active"};
  std::optional<std::uint64_t> rate_limit_per_minute;
  std::optional<std::string> webhook_url;
  std::optional<std::string> webhook_secret;
  std::set<std::string> scopes;
  std::vector<std::string> allowed_ipv4_cidrs_raw;
  bool enabled{true};
};

struct PartnerPrincipal {
  std::string partner_id;
  std::string api_key;
  std::uint64_t rate_limit_per_minute{0};
  std::set<std::string> scopes;
  std::vector<std::string> allowed_ipv4_cidrs_raw;
  bool authenticated{false};
};

struct PartnerWebhookDelivery {
  std::string partner_id;
  std::uint64_t sequence{0};
  std::string url;
  std::string payload_json;
  std::uint64_t attempt{0};
  std::uint64_t enqueued_unix_ms{0};
  std::uint64_t next_attempt_unix_ms{0};
};

struct PartnerWebhookDlqEntry {
  std::string partner_id;
  std::uint64_t sequence{0};
  std::string url;
  std::string payload_json;
  std::uint64_t enqueued_unix_ms{0};
  std::uint64_t failed_unix_ms{0};
  std::uint64_t attempts{0};
  std::string last_error;
};

struct PartnerWithdrawal {
  std::string partner_id;
  std::string client_withdrawal_id;
  std::string txid;
  std::string state;
  bool retryable{false};
  std::string retry_class{"none"};
  std::optional<std::string> error_code;
  std::optional<std::string> error_message;
  std::optional<std::uint64_t> finalized_height;
  std::optional<std::string> transition_hash;
  std::uint64_t created_unix_ms{0};
  std::uint64_t updated_unix_ms{0};
};

template <typename T>
struct LookupResult {
  std::optional<T> value;
  std::optional<ApiError> error;
};

struct StatusResult {
  std::string network;
  std::string network_id;
  std::string genesis_hash;
  std::uint64_t finalized_height{0};
  std::string finalized_transition_hash;
  std::string backend_version;
  std::string wallet_api_version;
  std::optional<std::uint64_t> protocol_reserve_balance;
  std::uint64_t healthy_peer_count{0};
  std::uint64_t established_peer_count{0};
  std::size_t latest_finality_committee_size{0};
  std::size_t latest_finality_quorum_threshold{0};
  bool observed_network_height_known{false};
  std::optional<std::uint64_t> observed_network_finalized_height;
  std::optional<std::uint64_t> finalized_lag;
  bool bootstrap_sync_incomplete{false};
  bool peer_height_disagreement{false};
  std::optional<std::uint64_t> availability_epoch;
  std::optional<std::uint64_t> availability_retained_prefix_count;
  std::optional<std::uint64_t> availability_tracked_operator_count;
  std::optional<std::uint64_t> availability_eligible_operator_count;
  std::optional<bool> availability_below_min_eligible;
  std::optional<std::string> availability_checkpoint_derivation_mode;
  std::optional<std::string> availability_checkpoint_fallback_reason;
  std::optional<bool> availability_fallback_sticky;
  std::optional<std::uint64_t> adaptive_target_committee_size;
  std::optional<std::uint64_t> adaptive_min_eligible;
  std::optional<std::uint64_t> adaptive_min_bond;
  std::optional<std::uint64_t> qualified_depth;
  std::optional<std::int64_t> adaptive_slack;
  std::optional<std::uint64_t> target_expand_streak;
  std::optional<std::uint64_t> target_contract_streak;
  std::optional<std::uint64_t> adaptive_fallback_rate_bps;
  std::optional<std::uint64_t> adaptive_sticky_fallback_rate_bps;
  std::optional<std::uint64_t> adaptive_fallback_window_epochs;
  std::optional<bool> adaptive_near_threshold_operation;
  std::optional<bool> adaptive_prolonged_expand_buildup;
  std::optional<bool> adaptive_prolonged_contract_buildup;
  std::optional<bool> adaptive_repeated_sticky_fallback;
  std::optional<bool> adaptive_depth_collapse_after_bond_increase;
  std::optional<std::uint64_t> adaptive_telemetry_window_epochs;
  std::optional<std::uint64_t> adaptive_telemetry_sample_count;
  std::optional<std::uint64_t> adaptive_telemetry_fallback_epochs;
  std::optional<std::uint64_t> adaptive_telemetry_sticky_fallback_epochs;
  std::optional<bool> availability_local_operator_known;
  std::optional<std::string> availability_local_operator_pubkey;
  std::optional<std::string> availability_local_operator_status;
  std::optional<std::uint64_t> availability_local_operator_seat_budget;
  std::optional<std::string> availability_local_operator_validator_status;
  std::optional<bool> availability_local_operator_onboarding_reward_eligible;
  std::optional<std::uint64_t> availability_local_operator_onboarding_reward_score_units;
  std::uint32_t onboarding_reward_pool_bps{0};
  std::uint32_t onboarding_admission_pow_difficulty_bits{0};
  std::uint32_t validator_join_admission_pow_difficulty_bits{0};
  std::uint32_t ticket_pow_difficulty{0};
  std::uint32_t ticket_pow_difficulty_min{0};
  std::uint32_t ticket_pow_difficulty_max{0};
  std::string ticket_pow_epoch_health;
  std::uint64_t ticket_pow_streak_up{0};
  std::uint64_t ticket_pow_streak_down{0};
  std::uint64_t ticket_pow_nonce_search_limit{0};
  std::uint32_t ticket_pow_bonus_cap_bps{0};
  bool finalized_only{true};
};

struct CommitteeMemberResult {
  std::optional<std::string> operator_id;
  std::string resolved_operator_id;
  std::string operator_id_source;
  std::string representative_pubkey;
  std::optional<std::uint64_t> base_weight;
  std::optional<std::uint64_t> ticket_bonus_bps;
  std::optional<std::uint64_t> final_weight;
  std::optional<std::string> ticket_hash;
  std::optional<std::uint64_t> ticket_nonce;
};

struct CommitteeResult {
  std::uint64_t height{0};
  std::uint64_t epoch_start_height{0};
  std::optional<std::string> checkpoint_derivation_mode;
  std::optional<std::string> checkpoint_fallback_reason;
  std::optional<bool> fallback_sticky;
  std::optional<std::uint64_t> availability_eligible_operator_count;
  std::optional<std::uint64_t> availability_min_eligible_operators;
  std::optional<std::uint64_t> adaptive_target_committee_size;
  std::optional<std::uint64_t> adaptive_min_eligible;
  std::optional<std::uint64_t> adaptive_min_bond;
  std::optional<std::uint64_t> qualified_depth;
  std::optional<std::int64_t> adaptive_slack;
  std::optional<std::uint64_t> target_expand_streak;
  std::optional<std::uint64_t> target_contract_streak;
  std::vector<CommitteeMemberResult> members;
  bool finalized_only{true};
};

struct TxInputResult {
  std::string prev_txid;
  std::uint32_t vout{0};
  std::optional<std::string> address;
  std::optional<std::uint64_t> amount;
};

struct TxOutputResult {
  std::uint64_t amount{0};
  std::optional<std::string> address;
  std::string script_hex;
  std::optional<std::string> decoded_kind;
  std::optional<std::string> validator_pubkey_hex;
  std::optional<std::string> payout_pubkey_hex;
  bool has_admission_pow{false};
  std::optional<std::uint64_t> admission_pow_epoch;
  std::optional<std::uint64_t> admission_pow_nonce;
};

struct TxResult {
  std::string txid;
  bool found{false};
  bool finalized{false};
  std::optional<std::uint64_t> finalized_height;
  std::uint64_t finalized_depth{0};
  bool credit_safe{false};
  std::string status_label;
  std::string transition_hash;
  std::optional<std::uint64_t> timestamp;
  std::vector<TxInputResult> inputs;
  std::vector<TxOutputResult> outputs;
  std::uint64_t total_out{0};
  std::optional<std::uint64_t> fee;
  std::string flow_kind;
  std::string flow_summary;
  std::optional<std::string> primary_sender;
  std::optional<std::string> primary_recipient;
  std::optional<std::size_t> participant_count;
  std::string data_source{"rpc_live_finalized"};
  std::optional<std::uint64_t> data_refreshed_unix_ms;
  bool finalized_only{true};
};

struct TransitionResult {
  bool found{false};
  bool finalized{true};
  std::uint64_t height{0};
  std::string hash;
  std::string prev_finalized_hash;
  std::optional<std::uint64_t> timestamp;
  std::uint32_t round{0};
  std::size_t tx_count{0};
  std::vector<std::string> txids;
  bool summary_cached{false};
  std::uint64_t cached_summary_finalized_out{0};
  std::size_t cached_summary_distinct_recipient_count{0};
  std::map<std::string, std::size_t> cached_summary_flow_mix;
  std::string data_source{"rpc_live_finalized"};
  std::optional<std::uint64_t> data_refreshed_unix_ms;
  bool finalized_only{true};
};

struct AddressUtxoResult {
  std::string txid;
  std::uint32_t vout{0};
  std::uint64_t amount{0};
  std::uint64_t height{0};
};

struct AddressHistoryItemResult {
  std::string txid;
  std::uint64_t height{0};
  std::string direction;
  std::int64_t net_amount{0};
  std::string detail;
};

struct AddressHistoryResult {
  std::vector<AddressHistoryItemResult> items;
  bool has_more{false};
  std::optional<std::string> next_cursor;
  std::optional<std::uint64_t> next_cursor_height;
  std::optional<std::string> next_cursor_txid;
  std::optional<std::string> next_page_path;
  std::size_t loaded_pages{0};
};

struct AddressResult {
  std::string address;
  bool found{false};
  std::vector<AddressUtxoResult> utxos;
  AddressHistoryResult history;
  bool finalized_only{true};
};

enum class SearchClassification : std::uint8_t {
  TransitionHeight = 1,
  Txid = 2,
  TransitionHash = 3,
  Address = 4,
  NotFound = 5,
};

struct SearchResult {
  std::string query;
  SearchClassification classification{SearchClassification::Txid};
  std::optional<std::string> target;
  bool found{false};
  bool finalized_only{true};
};

struct RecentTxResult {
  std::string txid;
  std::optional<std::uint64_t> height;
  std::optional<std::uint64_t> timestamp;
  std::optional<std::uint64_t> total_out;
  std::optional<std::string> status_label;
  std::optional<bool> credit_safe;
  std::optional<std::size_t> input_count;
  std::optional<std::size_t> output_count;
  std::optional<std::uint64_t> fee;
  std::optional<std::string> primary_sender;
  std::optional<std::string> primary_recipient;
  std::optional<std::size_t> recipient_count;
  std::optional<std::string> flow_kind;
  std::optional<std::string> flow_summary;
};

template <typename T>
struct TimedCacheEntry {
  std::string key;
  std::chrono::steady_clock::time_point stored_at{};
  T value{};
  bool valid{false};
};

std::mutex g_status_cache_mu;
TimedCacheEntry<LookupResult<StatusResult>> g_status_cache;
std::mutex g_recent_tx_cache_mu;
TimedCacheEntry<std::vector<RecentTxResult>> g_recent_tx_cache;
std::mutex g_committee_cache_mu;
TimedCacheEntry<LookupResult<CommitteeResult>> g_committee_cache;
std::mutex g_persisted_snapshot_mu;
std::mutex g_log_mu;
constexpr auto kSlowRpcThreshold = std::chrono::milliseconds(200);
constexpr auto kSlowRequestThreshold = std::chrono::milliseconds(500);
constexpr std::size_t kPersistedRecentLimit = 8;
constexpr std::size_t kPersistedTxIndexLimit = 128;
constexpr std::size_t kPersistedTransitionIndexLimit = 128;
constexpr std::size_t kPersistedPartnerEventsLimit = 2048;
constexpr std::size_t kPersistedPartnerWebhookQueueLimit = 2048;
constexpr std::size_t kPersistedPartnerIdempotencyLimit = 200000;
constexpr std::size_t kMaxHttpHeaderBytes = 16 * 1024;
constexpr std::size_t kMaxHttpBodyBytes = 256 * 1024;

std::mutex g_partner_mu;
std::unordered_map<std::string, PartnerAuthRecord> g_partner_by_api_key;
std::unordered_map<std::string, PartnerAuthRecord> g_partner_by_id;
std::unordered_map<std::string, PartnerWithdrawal> g_partner_withdrawals_by_client_id;
std::unordered_map<std::string, std::string> g_partner_client_id_by_txid;
std::unordered_map<std::string, std::string> g_partner_idempotency_hash;
std::unordered_map<std::string, std::string> g_partner_idempotency_client_id;
std::unordered_map<std::string, std::uint64_t> g_partner_idempotency_unix_ms;
std::vector<PartnerEvent> g_partner_events;
std::uint64_t g_partner_next_sequence{1};
std::unordered_map<std::string, std::uint64_t> g_seen_partner_nonce_unix_ms;
std::unordered_map<std::string, std::deque<std::uint64_t>> g_partner_rate_windows_ms;
std::deque<PartnerWebhookDelivery> g_partner_webhook_queue;
std::deque<PartnerWebhookDlqEntry> g_partner_webhook_dlq;
std::condition_variable g_partner_webhook_cv;
std::thread g_partner_webhook_thread;
std::atomic<bool> g_partner_webhook_stop{false};

std::mutex g_metrics_mu;
std::unordered_map<std::string, std::uint64_t> g_metrics_http_requests_total;
std::uint64_t g_metrics_partner_auth_failures_total{0};
std::unordered_map<std::string, std::uint64_t> g_metrics_partner_auth_failures_by_reason_total;
std::uint64_t g_metrics_partner_rate_limited_total{0};
std::uint64_t g_metrics_partner_withdrawal_submissions_total{0};
std::uint64_t g_metrics_partner_webhook_deliveries_total{0};
std::uint64_t g_metrics_partner_webhook_failures_total{0};
std::uint64_t g_metrics_partner_webhook_dlq_total{0};
std::uint64_t g_metrics_partner_webhook_replays_total{0};
std::unordered_map<std::string, std::uint64_t> g_metrics_http_request_duration_bucket_ms;
std::unordered_map<std::string, std::uint64_t> g_metrics_http_request_duration_sum_ms;
std::unordered_map<std::string, std::uint64_t> g_metrics_http_request_duration_count;
std::unordered_map<std::string, std::uint64_t> g_metrics_partner_webhook_delivery_latency_bucket_seconds;
std::unordered_map<std::string, std::uint64_t> g_metrics_partner_webhook_delivery_latency_sum_seconds;
std::unordered_map<std::string, std::uint64_t> g_metrics_partner_webhook_delivery_latency_count;

struct PersistedExplorerSnapshot {
  std::uint64_t stored_unix_ms{0};
  std::optional<std::uint64_t> status_refreshed_unix_ms;
  std::optional<std::uint64_t> committee_refreshed_unix_ms;
  std::optional<std::uint64_t> recent_refreshed_unix_ms;
  std::optional<finalis::minijson::Value> status_result;
  std::optional<finalis::minijson::Value> committee_result;
  std::uint64_t committee_height{0};
  std::vector<RecentTxResult> recent;
  std::size_t recent_limit{kPersistedRecentLimit};
  bool recent_present{false};
  std::vector<finalis::minijson::Value> tx_index;
  std::vector<finalis::minijson::Value> transition_index;
  std::unordered_map<std::string, PartnerWithdrawal> partner_withdrawals_by_client_id;
  std::unordered_map<std::string, std::string> partner_client_id_by_txid;
  std::unordered_map<std::string, std::string> partner_idempotency_hash;
  std::unordered_map<std::string, std::string> partner_idempotency_client_id;
  std::unordered_map<std::string, std::uint64_t> partner_idempotency_unix_ms;
  std::vector<PartnerEvent> partner_events;
  std::uint64_t partner_next_sequence{1};
  std::unordered_map<std::string, std::uint64_t> seen_partner_nonce_unix_ms;
  std::deque<PartnerWebhookDelivery> partner_webhook_queue;
  std::deque<PartnerWebhookDlqEntry> partner_webhook_dlq;
};

PersistedExplorerSnapshot g_persisted_snapshot;

struct SurfaceRuntimeState {
  std::optional<std::string> last_error;
  bool used_cached_fallback{false};
};

std::mutex g_surface_state_mu;
SurfaceRuntimeState g_status_surface_state;
SurfaceRuntimeState g_committee_surface_state;
SurfaceRuntimeState g_recent_surface_state;
constexpr std::uint64_t kExplorerSurfaceStaleThresholdMs = 120000;

void clear_runtime_caches() {
  {
    std::lock_guard<std::mutex> guard(g_status_cache_mu);
    g_status_cache = {};
  }
  {
    std::lock_guard<std::mutex> guard(g_recent_tx_cache_mu);
    g_recent_tx_cache = {};
  }
  {
    std::lock_guard<std::mutex> guard(g_committee_cache_mu);
    g_committee_cache = {};
  }
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    g_persisted_snapshot = {};
  }
  {
    std::lock_guard<std::mutex> guard(g_surface_state_mu);
    g_status_surface_state = {};
    g_committee_surface_state = {};
    g_recent_surface_state = {};
  }
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    g_partner_by_api_key.clear();
    g_partner_by_id.clear();
    g_partner_withdrawals_by_client_id.clear();
    g_partner_client_id_by_txid.clear();
    g_partner_idempotency_hash.clear();
    g_partner_idempotency_client_id.clear();
    g_partner_idempotency_unix_ms.clear();
    g_partner_events.clear();
    g_partner_next_sequence = 1;
    g_seen_partner_nonce_unix_ms.clear();
    g_partner_rate_windows_ms.clear();
    g_partner_webhook_queue.clear();
    g_partner_webhook_dlq.clear();
  }
  {
    std::lock_guard<std::mutex> guard(g_metrics_mu);
    g_metrics_http_requests_total.clear();
    g_metrics_http_request_duration_bucket_ms.clear();
    g_metrics_http_request_duration_sum_ms.clear();
    g_metrics_http_request_duration_count.clear();
    g_metrics_partner_auth_failures_total = 0;
    g_metrics_partner_auth_failures_by_reason_total.clear();
    g_metrics_partner_rate_limited_total = 0;
    g_metrics_partner_withdrawal_submissions_total = 0;
    g_metrics_partner_webhook_deliveries_total = 0;
    g_metrics_partner_webhook_failures_total = 0;
    g_metrics_partner_webhook_dlq_total = 0;
    g_metrics_partner_webhook_replays_total = 0;
    g_metrics_partner_webhook_delivery_latency_bucket_seconds.clear();
    g_metrics_partner_webhook_delivery_latency_sum_seconds.clear();
    g_metrics_partner_webhook_delivery_latency_count.clear();
  }
}

std::string default_explorer_cache_path(const std::string& rpc_url) {
  const std::string root = finalis::expand_user_home("~/.finalis/explorer");
  const auto hash = finalis::crypto::sha256(Bytes(rpc_url.begin(), rpc_url.end()));
  return root + "/cache-" + finalis::hex_encode32(hash) + ".json";
}

std::string format_timestamp(std::uint64_t ts);
std::uint64_t now_unix_ms();

struct TxSummaryBatchItem {
  std::string txid;
  std::optional<std::uint64_t> height;
  std::optional<std::uint64_t> total_out;
  std::optional<std::uint64_t> fee;
  std::optional<std::size_t> input_count;
  std::optional<std::size_t> output_count;
  std::optional<std::string> primary_sender;
  std::optional<std::string> primary_recipient;
  std::optional<std::size_t> recipient_count;
  std::vector<std::string> recipients;
  std::optional<std::string> flow_kind;
  std::optional<std::string> flow_summary;
  std::optional<std::string> status_label;
  std::optional<bool> credit_safe;
};

struct Response {
  int status{200};
  std::string content_type{"text/html; charset=utf-8"};
  std::string body;
  std::optional<std::string> location;
  std::vector<std::pair<std::string, std::string>> headers;
};

Response handle_request(const Config& cfg, const std::string& req, const std::string& client_ip);
Response handle_request(const Config& cfg, const std::string& req);
ApiError upstream_error(const std::string& message);
void persist_explorer_snapshot(const Config& cfg);
bool prune_partner_state_locked(const Config& cfg, std::uint64_t now_ms);
LookupResult<StatusResult> parse_status_result_object(const finalis::minijson::Value& status_obj);
LookupResult<CommitteeResult> parse_committee_result_object(const finalis::minijson::Value& committee_obj,
                                                            std::uint64_t requested_height);

volatile std::sig_atomic_t g_stop = 0;
std::atomic<std::size_t> g_active_clients{0};
constexpr std::size_t kMaxConcurrentClients = 64;

void on_signal(int) { g_stop = 1; }

std::string html_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 16);
  for (char c : in) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}

std::string json_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (char c : in) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::string json_bool(bool v) { return v ? "true" : "false"; }

std::string json_u64_or_null(const std::optional<std::uint64_t>& v) {
  return v.has_value() ? std::to_string(*v) : "null";
}

std::string json_string_or_null(const std::optional<std::string>& v) {
  return v.has_value() ? ("\"" + json_escape(*v) + "\"") : "null";
}

ApiError make_error(int http_status, std::string code, std::string message) {
  return ApiError{http_status, std::move(code), std::move(message)};
}

std::string error_json(const ApiError& err) {
  return std::string("{\"error\":{\"code\":\"") + json_escape(err.code) + "\",\"message\":\"" + json_escape(err.message) + "\"}}";
}

Response html_response(int status, std::string body) {
  return Response{status, "text/html; charset=utf-8", std::move(body), std::nullopt, {}};
}

Response json_response(int status, std::string body) {
  return Response{status, "application/json; charset=utf-8", std::move(body), std::nullopt, {}};
}

Response json_error_response(const ApiError& err) { return json_response(err.http_status, error_json(err)); }

std::string append_api_v1(const std::string& json) {
  if (!json.empty() && json.back() == '}') {
    return json.substr(0, json.size() - 1) + ",\"api_version\":\"v1\"}";
  }
  return json;
}

std::string sanitize_redirect_location(const std::string& location) {
  if (location.empty() || location.front() != '/') return "/";
  std::string out;
  out.reserve(location.size());
  for (char c : location) {
    if (c == '\r' || c == '\n') return "/";
    const auto uc = static_cast<unsigned char>(c);
    if (uc < 0x20 && c != '\t') return "/";
    out.push_back(c);
  }
  return out;
}

Response redirect_response(const std::string& location) {
  Response out;
  out.status = 302;
  out.content_type = "text/plain; charset=utf-8";
  out.body = "Found";
  out.location = sanitize_redirect_location(location);
  return out;
}

std::string lowercase_ascii(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::optional<std::string> header_value(const HttpRequest& req, const std::string& key) {
  const auto it = req.headers.find(lowercase_ascii(key));
  if (it == req.headers.end()) return std::nullopt;
  return it->second;
}

bool secure_equal(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  return diff == 0;
}

std::string sha256_hex_text(const std::string& text) {
  const auto hash = finalis::crypto::sha256(Bytes(text.begin(), text.end()));
  return finalis::hex_encode32(hash);
}

std::optional<std::string> hmac_sha256_hex(const std::string& key, const std::string& message) {
  unsigned int len = EVP_MAX_MD_SIZE;
  unsigned char digest[EVP_MAX_MD_SIZE];
  auto* out = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                   reinterpret_cast<const unsigned char*>(message.data()), message.size(), digest, &len);
  if (!out) return std::nullopt;
  return finalis::hex_encode(Bytes(digest, digest + len));
}

using HttpPostJsonRawFn = std::function<std::optional<std::string>(const std::string&, const std::string&, std::string*)>;
HttpPostJsonRawFn g_partner_webhook_post_json = [](const std::string& url, const std::string& body, std::string* err) {
  return finalis::lightserver::http_post_json_raw(url, body, err);
};

std::optional<std::uint64_t> parse_u64_strict(const std::string& s) {
  if (s.empty()) return std::nullopt;
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
  }
  try {
    return static_cast<std::uint64_t>(std::stoull(s));
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<HttpRequest> parse_http_request(const std::string& req, std::string* err) {
  const auto line_end = req.find("\r\n");
  if (line_end == std::string::npos) {
    if (err) *err = "malformed request line";
    return std::nullopt;
  }
  const std::string first = req.substr(0, line_end);
  const auto sp1 = first.find(' ');
  const auto sp2 = first.rfind(' ');
  if (sp1 == std::string::npos || sp2 == std::string::npos || sp1 == sp2) {
    if (err) *err = "malformed request line";
    return std::nullopt;
  }
  HttpRequest out;
  out.method = first.substr(0, sp1);
  out.target = first.substr(sp1 + 1, sp2 - sp1 - 1);
  const auto hdr_end = req.find("\r\n\r\n");
  if (hdr_end == std::string::npos) {
    if (err) *err = "missing headers terminator";
    return std::nullopt;
  }
  std::size_t cursor = line_end + 2;
  while (cursor < hdr_end) {
    const auto next = req.find("\r\n", cursor);
    if (next == std::string::npos || next > hdr_end) break;
    const std::string line = req.substr(cursor, next - cursor);
    cursor = next + 2;
    const auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = lowercase_ascii(line.substr(0, colon));
    std::string value = line.substr(colon + 1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    out.headers[key] = value;
  }
  out.body = req.substr(hdr_end + 4);
  return out;
}

void record_http_metric(const std::string& path, int status) {
  std::lock_guard<std::mutex> guard(g_metrics_mu);
  const std::string key = path + "|" + std::to_string(status);
  ++g_metrics_http_requests_total[key];
}

void record_http_duration_metric(const std::string& path, std::uint64_t duration_ms) {
  static const std::array<std::uint64_t, 8> buckets_ms{50, 100, 250, 500, 1000, 2500, 5000, 10000};
  std::lock_guard<std::mutex> guard(g_metrics_mu);
  g_metrics_http_request_duration_sum_ms[path] += duration_ms;
  g_metrics_http_request_duration_count[path] += 1;
  for (const auto bucket : buckets_ms) {
    if (duration_ms <= bucket) {
      const std::string key = path + "|" + std::to_string(bucket);
      ++g_metrics_http_request_duration_bucket_ms[key];
    }
  }
}

void record_partner_auth_failure_metric(const std::string& reason) {
  std::lock_guard<std::mutex> guard(g_metrics_mu);
  ++g_metrics_partner_auth_failures_total;
  ++g_metrics_partner_auth_failures_by_reason_total[reason.empty() ? "unknown" : reason];
}

void record_partner_webhook_delivery_latency_metric(const std::string& outcome, std::uint64_t latency_seconds) {
  static const std::array<std::uint64_t, 10> buckets_seconds{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600};
  const std::string label = outcome.empty() ? "unknown" : outcome;
  std::lock_guard<std::mutex> guard(g_metrics_mu);
  g_metrics_partner_webhook_delivery_latency_sum_seconds[label] += latency_seconds;
  g_metrics_partner_webhook_delivery_latency_count[label] += 1;
  for (const auto bucket : buckets_seconds) {
    if (latency_seconds <= bucket) {
      const std::string key = label + "|" + std::to_string(bucket);
      ++g_metrics_partner_webhook_delivery_latency_bucket_seconds[key];
    }
  }
}

void push_partner_event(const std::string& partner_id, const std::string& event_type, const std::string& object_id,
                        const std::string& state) {
  PartnerEvent evt;
  evt.sequence = g_partner_next_sequence++;
  evt.partner_id = partner_id;
  evt.event_type = event_type;
  evt.object_id = object_id;
  evt.state = state;
  evt.emitted_unix_ms = now_unix_ms();
  g_partner_events.push_back(evt);
}

std::string partner_event_json(const PartnerEvent& evt) {
  std::ostringstream oss;
  oss << "{\"sequence\":" << evt.sequence << ",\"partner_id\":\"" << json_escape(evt.partner_id)
      << "\",\"event_type\":\"" << json_escape(evt.event_type)
      << "\",\"object_id\":\"" << json_escape(evt.object_id) << "\",\"state\":\"" << json_escape(evt.state)
      << "\",\"emitted_unix_ms\":" << evt.emitted_unix_ms << "}";
  return oss.str();
}

std::string partner_withdrawal_json(const PartnerWithdrawal& w) {
  std::ostringstream oss;
  oss << "{\"partner_id\":\"" << json_escape(w.partner_id) << "\",\"client_withdrawal_id\":\"" << json_escape(w.client_withdrawal_id)
      << "\",\"txid\":\"" << json_escape(w.txid)
      << "\",\"state\":\"" << json_escape(w.state) << "\",\"retryable\":" << json_bool(w.retryable)
      << ",\"retry_class\":\"" << json_escape(w.retry_class) << "\""
      << ",\"error_code\":" << json_string_or_null(w.error_code)
      << ",\"error_message\":" << json_string_or_null(w.error_message)
      << ",\"finalized_height\":" << json_u64_or_null(w.finalized_height)
      << ",\"transition_hash\":" << json_string_or_null(w.transition_hash)
      << ",\"created_unix_ms\":" << w.created_unix_ms
      << ",\"updated_unix_ms\":" << w.updated_unix_ms << "}";
  return oss.str();
}

std::string short_hex(const std::string& hex) {
  if (hex.size() <= 16) return hex;
  return hex.substr(0, 12) + "..." + hex.substr(hex.size() - 8);
}

std::string format_amount(std::uint64_t value) {
  const std::uint64_t whole = value / 100000000ULL;
  const std::uint64_t frac = value % 100000000ULL;
  std::ostringstream oss;
  oss << whole << "." << std::setw(8) << std::setfill('0') << frac << " FLS";
  return oss.str();
}

std::string format_signed_amount(std::int64_t value) {
  const bool negative = value < 0;
  const auto magnitude = negative ? static_cast<std::uint64_t>(-value) : static_cast<std::uint64_t>(value);
  return std::string(negative ? "-" : "+") + format_amount(magnitude);
}

std::string render_summary_metric_card(const std::string& label, const std::string& value, const std::string& sub = {}) {
  std::ostringstream oss;
  oss << "<div class=\"metric-card\"><span class=\"label\">" << html_escape(label) << "</span><span class=\"value\">"
      << html_escape(value) << "</span>";
  if (!sub.empty()) oss << "<span class=\"sub\">" << html_escape(sub) << "</span>";
  oss << "</div>";
  return oss.str();
}

struct TransitionSummary {
  std::uint64_t finalized_out{0};
  std::size_t distinct_recipient_count{0};
  std::map<std::string, std::size_t> flow_mix;
};

TransitionSummary compute_transition_summary(const Config& cfg, const TransitionResult& transition) {
  TransitionSummary summary;
  if (transition.summary_cached) {
    summary.finalized_out = transition.cached_summary_finalized_out;
    summary.distinct_recipient_count = transition.cached_summary_distinct_recipient_count;
    summary.flow_mix = transition.cached_summary_flow_mix;
    return summary;
  }
  std::set<std::string> distinct_recipients;
  const auto summaries = fetch_tx_summary_batch(cfg, transition.txids);
  for (const auto& txid : transition.txids) {
    auto it = summaries.find(txid);
    if (it != summaries.end()) {
      if (it->second.total_out.has_value()) summary.finalized_out += *it->second.total_out;
      if (it->second.flow_kind.has_value()) ++summary.flow_mix[*it->second.flow_kind];
      for (const auto& recipient : it->second.recipients) {
        if (!recipient.empty()) distinct_recipients.insert(recipient);
      }
      continue;
    }
    auto tx_lookup = fetch_tx_result(cfg, txid);
    if (!tx_lookup.value.has_value()) continue;
    summary.finalized_out += tx_lookup.value->total_out;
    ++summary.flow_mix[tx_lookup.value->flow_kind];
    for (const auto& out : tx_lookup.value->outputs) {
      if (out.address.has_value() && !out.address->empty()) distinct_recipients.insert(*out.address);
    }
  }
  summary.distinct_recipient_count = distinct_recipients.size();
  return summary;
}

std::string summarize_flow_mix(const std::map<std::string, std::size_t>& flow_mix) {
  std::ostringstream oss;
  if (flow_mix.empty()) {
    oss << "no classified finalized txs";
  } else {
    bool first = true;
    for (const auto& [kind, count] : flow_mix) {
      if (!first) oss << ", ";
      first = false;
      oss << kind << "=" << count;
    }
  }
  return oss.str();
}

std::string explorer_data_source_label(const std::string& source) {
  if (source == "cache_finalized_snapshot") return "cached finalized snapshot";
  if (source == "rpc_live_finalized") return "fresh finalized RPC";
  return source.empty() ? "unknown" : source;
}

std::string explorer_data_freshness_note(const std::string& source, const std::optional<std::uint64_t>& refreshed_unix_ms) {
  if (source != "cache_finalized_snapshot") return {};
  if (!refreshed_unix_ms.has_value()) return "Last refreshed from RPC: unknown";
  return "Last refreshed from RPC: " + format_timestamp(*refreshed_unix_ms);
}

std::string explorer_snapshot_freshness_text(const std::optional<std::uint64_t>& refreshed_unix_ms) {
  if (!refreshed_unix_ms.has_value()) return "unknown";
  return format_timestamp(*refreshed_unix_ms);
}

std::optional<std::uint64_t> persisted_status_refreshed_unix_ms() {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  return g_persisted_snapshot.status_refreshed_unix_ms;
}

std::optional<std::uint64_t> persisted_committee_refreshed_unix_ms() {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  return g_persisted_snapshot.committee_refreshed_unix_ms;
}

std::optional<std::uint64_t> persisted_recent_refreshed_unix_ms() {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  return g_persisted_snapshot.recent_refreshed_unix_ms;
}

std::optional<LookupResult<StatusResult>> persisted_status_result_lookup() {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  if (!g_persisted_snapshot.status_result.has_value()) return std::nullopt;
  return parse_status_result_object(*g_persisted_snapshot.status_result);
}

std::optional<LookupResult<CommitteeResult>> persisted_committee_result_lookup(std::uint64_t height) {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  if (!g_persisted_snapshot.committee_result.has_value()) return std::nullopt;
  if (g_persisted_snapshot.committee_height != height) return std::nullopt;
  return parse_committee_result_object(*g_persisted_snapshot.committee_result, height);
}

std::optional<std::vector<RecentTxResult>> persisted_recent_results(std::size_t limit) {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  if (!g_persisted_snapshot.recent_present) return std::nullopt;
  if (g_persisted_snapshot.recent_limit != limit) return std::nullopt;
  return g_persisted_snapshot.recent;
}

void set_surface_state(SurfaceRuntimeState& state, std::optional<std::string> error, bool used_cached_fallback) {
  state.last_error = std::move(error);
  state.used_cached_fallback = used_cached_fallback;
}

bool surface_is_stale(const std::optional<std::uint64_t>& refreshed_unix_ms) {
  if (!refreshed_unix_ms.has_value()) return true;
  const auto now_ms = now_unix_ms();
  return now_ms > *refreshed_unix_ms && (now_ms - *refreshed_unix_ms) > kExplorerSurfaceStaleThresholdMs;
}

std::string build_surface_stale_banner() {
  std::optional<std::uint64_t> status_ts = persisted_status_refreshed_unix_ms();
  std::optional<std::uint64_t> committee_ts = persisted_committee_refreshed_unix_ms();
  std::optional<std::uint64_t> recent_ts = persisted_recent_refreshed_unix_ms();
  SurfaceRuntimeState status_state;
  SurfaceRuntimeState committee_state;
  SurfaceRuntimeState recent_state;
  {
    std::lock_guard<std::mutex> guard(g_surface_state_mu);
    status_state = g_status_surface_state;
    committee_state = g_committee_surface_state;
    recent_state = g_recent_surface_state;
  }
  const bool any_stale = surface_is_stale(status_ts) || surface_is_stale(committee_ts) || surface_is_stale(recent_ts);
  const bool any_failed = status_state.last_error.has_value() || committee_state.last_error.has_value() || recent_state.last_error.has_value();
  if (!any_stale && !any_failed) return {};

  std::ostringstream oss;
  oss << "<div class=\"card\"><div class=\"note\"><strong>Snapshot Freshness Warning</strong>: ";
  if (any_failed) {
    oss << "one or more finalized explorer surfaces are being served from cached snapshot because live RPC refresh failed. ";
  } else {
    oss << "one or more finalized explorer surfaces are older than the freshness threshold. ";
  }
  oss << "Status=" << html_escape(explorer_snapshot_freshness_text(status_ts))
      << ", Committee=" << html_escape(explorer_snapshot_freshness_text(committee_ts))
      << ", Recent=" << html_escape(explorer_snapshot_freshness_text(recent_ts)) << ".";
  if (status_state.last_error.has_value()) oss << " status error=" << html_escape(*status_state.last_error) << ".";
  if (committee_state.last_error.has_value()) oss << " committee error=" << html_escape(*committee_state.last_error) << ".";
  if (recent_state.last_error.has_value()) oss << " recent error=" << html_escape(*recent_state.last_error) << ".";
  oss << "</div></div>";
  return oss.str();
}

std::string format_timestamp(std::uint64_t ts) {
  std::time_t tt = static_cast<std::time_t>(ts);
  std::tm tm{};
#ifdef _WIN32
  if (::gmtime_s(&tm, &tt) != 0) return std::to_string(ts);
#else
  if (::gmtime_r(&tt, &tm) == nullptr) return std::to_string(ts);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC") << " (" << ts << ")";
  return oss.str();
}

bool is_hex64(const std::string& s) {
  if (s.size() != 64) return false;
  for (char c : s) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!ok) return false;
  }
  return true;
}

bool is_digits(const std::string& s) {
  if (s.empty()) return false;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
  }
  return true;
}

std::optional<Hash32> parse_hex32(const std::string& s) {
  auto b = finalis::hex_decode(s);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::string hrp_for_network_name(const std::string& network_name) {
  return network_name == "mainnet" ? "sc" : "tsc";
}

std::optional<std::string> script_to_address(const Bytes& script_pubkey, const std::string& hrp) {
  if (script_pubkey.size() != 25) return std::nullopt;
  if (script_pubkey[0] != 0x76 || script_pubkey[1] != 0xA9 || script_pubkey[2] != 0x14 || script_pubkey[23] != 0x88 ||
      script_pubkey[24] != 0xAC) {
    return std::nullopt;
  }
  std::array<std::uint8_t, 20> pkh{};
  std::copy(script_pubkey.begin() + 3, script_pubkey.begin() + 23, pkh.begin());
  return finalis::address::encode_p2pkh(hrp, pkh);
}

std::string finalized_badge(bool finalized) {
  return finalized ? "<span class=\"badge badge-finalized\">FINALIZED</span>"
                   : "<span class=\"badge badge-unfinalized\">NOT FINALIZED</span>";
}

std::string credit_safe_badge(bool credit_safe) {
  return credit_safe ? "<span class=\"badge badge-finalized\">CREDIT SAFE</span>"
                     : "<span class=\"badge badge-unfinalized\">NOT CREDIT SAFE</span>";
}

std::string credit_safe_text(bool credit_safe) { return credit_safe ? "YES" : "NO"; }

std::string finalized_text(bool finalized) { return finalized ? "YES" : "NO"; }

std::string tx_status_label(bool finalized, bool credit_safe) {
  if (!finalized) return "NOT FINALIZED";
  return credit_safe ? "FINALIZED (CREDIT SAFE)" : "FINALIZED";
}

std::string credit_decision_text(bool finalized, bool credit_safe) {
  if (finalized && credit_safe) return "Safe to credit";
  return "Do not credit";
}

std::string uppercase_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return value;
}

std::string yes_no(bool value) { return value ? "YES" : "NO"; }

std::string title_case_health(const std::string& value) {
  if (value.empty()) return value;
  std::string out = value;
  out[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[0])));
  return out;
}

std::string ticket_pow_title(const StatusResult& status) {
  (void)status;
  return "Ticket PoW (Bounded)";
}

std::string ticket_pow_adjustment_text(const StatusResult& status) {
  (void)status;
  return "+1 after 2 healthy epochs / -1 after 3 unhealthy epochs";
}

std::string ticket_pow_note(const StatusResult& status) {
  (void)status;
  return "Each operator performs a fixed 4096-hash search per epoch. This produces a small bounded bonus and does not affect finality.";
}

std::string format_bonus_percent(std::uint64_t bps) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision((bps % 100 == 0) ? 0 : 2) << (static_cast<double>(bps) / 100.0);
  oss << "%";
  return oss.str();
}

std::string weight_composition(std::optional<std::uint64_t> base_weight, std::optional<std::uint64_t> ticket_bonus_bps,
                               std::optional<std::uint64_t> final_weight) {
  if (!base_weight.has_value() || !ticket_bonus_bps.has_value() || !final_weight.has_value()) {
    return "<span class=\"muted\">n/a</span>";
  }
  std::ostringstream oss;
  oss << "<span class=\"weight-flow\"><span class=\"mono\">" << *base_weight << "</span> &rarr; +"
      << html_escape(format_bonus_percent(*ticket_bonus_bps)) << " &rarr; <span class=\"mono\">" << *final_weight
      << "</span></span>";
  return oss.str();
}

std::string mono_value(const std::string& value) {
  const std::string escaped = html_escape(value);
  return "<div class=\"mono-block\"><code>" + escaped +
         "</code><button class=\"copy-button\" type=\"button\" onclick=\"copyText(this)\" data-copy=\"" + escaped +
         "\">Copy</button></div>";
}

std::string copy_action(const std::string& label, const std::string& value) {
  const std::string escaped_label = html_escape(label);
  const std::string escaped_value = html_escape(value);
  return "<button class=\"copy-button\" type=\"button\" onclick=\"copyText(this)\" data-copy=\"" + escaped_value + "\">" +
         escaped_label + "</button>";
}

std::string inline_copy_action(const std::string& label, const std::string& value) {
  const std::string escaped_label = html_escape(label);
  const std::string escaped_value = html_escape(value);
  return "<button class=\"copy-button-inline\" type=\"button\" onclick=\"copyText(this)\" data-copy=\"" + escaped_value +
         "\">" + escaped_label + "</button>";
}

std::string route_action_row(const std::string& page_path, const std::string& api_path) {
  return "<div class=\"route-actions\">" + copy_action("Copy Page Path", page_path) + copy_action("Copy API Path", api_path) + "</div>";
}

std::string amount_span(std::uint64_t value, const char* css_class) {
  return "<span class=\"" + std::string(css_class) + "\">" + html_escape(format_amount(value)) + "</span>";
}

std::string status_chip(const std::string& label, const std::string& tone) {
  return "<span class=\"status-chip status-chip-" + tone + "\">" + html_escape(label) + "</span>";
}

std::string tone_for_sync(const StatusResult& status) {
  if (status.bootstrap_sync_incomplete || status.peer_height_disagreement) return "warn";
  if (status.finalized_lag.has_value() && *status.finalized_lag > 0) return "muted";
  return "good";
}

std::string sync_summary_text(const StatusResult& status) {
  if (status.bootstrap_sync_incomplete) return "Bootstrap sync incomplete";
  if (status.peer_height_disagreement) return "Peer disagreement detected";
  if (status.finalized_lag.has_value()) return "Finalized lag " + std::to_string(*status.finalized_lag);
  return "Healthy";
}

std::string fallback_chip(const StatusResult& status) {
  if (!status.availability_checkpoint_fallback_reason.has_value() ||
      status.availability_checkpoint_fallback_reason->empty() ||
      *status.availability_checkpoint_fallback_reason == "none") {
    return status_chip("Fallback Clear", "good");
  }
  return status_chip("Fallback " + uppercase_copy(*status.availability_checkpoint_fallback_reason), "warn");
}

std::string operator_chip(const StatusResult& status) {
  if (!status.availability_local_operator_known.value_or(false)) return status_chip("Operator Unknown", "muted");
  const auto raw = status.availability_local_operator_status.value_or("unknown");
  const auto upper = uppercase_copy(raw);
  const std::string tone = (upper == "ACTIVE" || upper == "QUALIFIED") ? "good" : (upper == "PROBATION" ? "warn" : "muted");
  return status_chip("Operator " + upper, tone);
}

std::string display_identity(const std::optional<std::string>& value) {
  if (!value.has_value() || value->empty()) return "<span class=\"muted\">unknown</span>";
  if (finalis::address::decode(*value).has_value()) {
    return "<code>" + html_escape(short_hex(*value)) + "</code>";
  }
  return "<code>" + html_escape(short_hex(*value)) + "</code>";
}

struct FlowClassification {
  std::string kind;
  std::string summary;
  std::optional<std::string> primary_sender;
  std::optional<std::string> primary_recipient;
  std::optional<std::size_t> participant_count;
};

FlowClassification classify_tx_flow(const std::vector<TxInputResult>& inputs, const std::vector<TxOutputResult>& outputs) {
  std::set<std::string> input_addresses;
  std::set<std::string> output_addresses;
  for (const auto& input : inputs) {
    if (input.address.has_value() && !input.address->empty()) input_addresses.insert(*input.address);
  }
  for (const auto& output : outputs) {
    if (output.address.has_value() && !output.address->empty()) output_addresses.insert(*output.address);
  }

  FlowClassification flow;
  if (!input_addresses.empty()) flow.primary_sender = *input_addresses.begin();
  if (!output_addresses.empty()) flow.primary_recipient = *output_addresses.begin();
  flow.participant_count = input_addresses.size() + output_addresses.size();

  const bool same_party = !input_addresses.empty() && !output_addresses.empty() && input_addresses == output_addresses;
  const bool single_sender = input_addresses.size() == 1;
  const bool single_recipient = output_addresses.size() == 1;
  const bool has_change_like_overlap =
      !input_addresses.empty() && !output_addresses.empty() &&
      std::any_of(output_addresses.begin(), output_addresses.end(),
                  [&](const std::string& address) { return input_addresses.count(address) != 0; });

  if (inputs.empty()) {
    flow.kind = "issuance";
    flow.summary = outputs.size() <= 1 ? "Protocol or settlement issuance" : "Protocol or settlement issuance fanout";
  } else if (same_party) {
    flow.kind = "self-transfer";
    flow.summary = "Inputs and outputs resolve to the same finalized address set";
  } else if (single_sender && single_recipient && !has_change_like_overlap) {
    flow.kind = "direct-transfer";
    flow.summary = "Single-sender finalized transfer";
  } else if (single_sender && has_change_like_overlap && output_addresses.size() == 2) {
    flow.kind = "transfer-with-change";
    flow.summary = "Likely payment with one external recipient and one change output";
  } else if (input_addresses.size() > 1 && single_recipient) {
    flow.kind = "consolidation";
    flow.summary = "Many finalized inputs converging to one recipient";
  } else if (single_sender && output_addresses.size() > 2) {
    flow.kind = "fanout";
    flow.summary = "One sender distributing finalized outputs to multiple recipients";
  } else {
    flow.kind = "multi-party";
    flow.summary = "Multi-input or multi-recipient finalized transaction";
  }
  return flow;
}

AddressHistoryItemResult classify_address_history_item(const std::string& address, const TxResult& tx) {
  std::uint64_t credited = 0;
  std::uint64_t debited = 0;
  for (const auto& input : tx.inputs) {
    if (input.address.has_value() && *input.address == address) debited += input.amount.value_or(0);
  }
  for (const auto& output : tx.outputs) {
    if (output.address.has_value() && *output.address == address) credited += output.amount;
  }

  AddressHistoryItemResult item;
  item.txid = tx.txid;
  item.height = tx.finalized_height.value_or(0);

  if (debited == 0 && credited > 0) {
    item.direction = "received";
    item.net_amount = static_cast<std::int64_t>(credited);
    item.detail = "Finalized credit to this address";
  } else if (debited > 0 && credited == 0) {
    item.direction = "sent";
    item.net_amount = -static_cast<std::int64_t>(debited);
    item.detail = "Finalized spend from this address with no decoded return output";
  } else if (debited > 0 && credited > 0) {
    item.direction = "self-transfer";
    item.net_amount = static_cast<std::int64_t>(credited) - static_cast<std::int64_t>(debited);
    item.detail = "This address appears on both finalized inputs and outputs";
  } else {
    item.direction = "related";
    item.net_amount = 0;
    item.detail = "Address is present in finalized history but could not be classified precisely";
  }
  return item;
}

std::string global_finalized_banner() {
  return "<div class=\"global-banner\">Explorer view is finalized-state only. Only finalized activity is shown.</div>";
}

std::string top_nav(const std::string& active) {
  const auto item = [&](const std::string& label, const std::string& href, const std::string& key) {
    const std::string cls = active == key ? "top-tab top-tab-active" : "top-tab";
    return "<a class=\"" + cls + "\" href=\"" + href + "\">" + html_escape(label) + "</a>";
  };
  std::ostringstream oss;
  oss << "<div class=\"top-nav\">"
      << item("Overview", "/", "overview")
      << item("Committee", "/committee", "committee")
      << item("Tx", "/tx/", "tx")
      << item("Transition", "/transition/", "transition")
      << item("Address", "/address/", "address")
      << "</div>";
  return oss.str();
}

std::string page_layout(const std::string& title, const std::string& body, const std::string& active_nav = {}) {
  std::ostringstream oss;
  oss << "<!doctype html><html><head><meta charset=\"utf-8\">"
      << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
      << "<title>" << html_escape(title) << "</title>"
      << "<style>"
         "body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:radial-gradient(circle at top,#f8f1dc 0%,#f5f5f2 28%,#f1f1ed 100%);color:#171717;margin:0;padding:clamp(14px,2vw,26px);}"
         "main{max-width:1160px;width:min(100%,1160px);margin:0 auto;}"
         "a{color:#0f4c81;text-decoration:none;}a:hover{text-decoration:underline;}"
         "h1,h2{margin:0 0 12px 0;}h1{font-size:34px;line-height:1.05;letter-spacing:-.02em;}h2{font-size:20px;margin-top:30px;}"
         ".muted{color:#5b5b5b;line-height:1.45;}"
         ".card{background:rgba(255,255,255,.88);backdrop-filter:blur(6px);border:1px solid #ddd9cd;border-radius:18px;padding:18px 20px;margin:18px 0;box-shadow:0 12px 30px rgba(56,48,30,.06);}"
         ".hero-card{padding:22px 24px;background:linear-gradient(180deg,#fffdf5 0%,#fff 100%);}"
         ".grid{display:grid;grid-template-columns:minmax(180px,260px) minmax(0,1fr);gap:10px 16px;align-items:start;}"
         ".grid>div:nth-child(odd){color:#5b5b5b;font-size:13px;text-transform:uppercase;letter-spacing:.05em;}"
         ".grid>div:nth-child(even){font-size:15px;line-height:1.45;}"
         ".badge{display:inline-block;padding:10px 16px;border-radius:999px;font-size:16px;font-weight:800;letter-spacing:.08em;max-width:100%;white-space:normal;text-align:center;overflow-wrap:anywhere;}"
         ".badge-finalized{background:#d9f0d8;color:#124b19;border:2px solid #5ba55e;box-shadow:0 0 0 2px rgba(91,165,94,.12) inset;}"
         ".badge-unfinalized{background:#f6e2d8;color:#8a3110;border:2px solid #c56742;box-shadow:0 0 0 2px rgba(197,103,66,.12) inset;}"
         ".table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;}"
         "table{width:100%;border-collapse:collapse;font-size:14px;min-width:620px;}th,td{padding:10px 10px;border-bottom:1px solid #e7e2d8;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;}"
         "th{color:#4f4f4f;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.05em;}code{font-size:13px;overflow-wrap:anywhere;word-break:break-word;}"
         ".num{text-align:right;white-space:nowrap;}"
         ".mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}"
         ".mono-block{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;max-width:100%;padding:10px 12px;background:#faf9f3;border:1px solid #e6e0d4;border-radius:10px;overflow-wrap:anywhere;word-break:break-word;}"
         ".mono-block code{flex:1 1 auto;min-width:0;white-space:pre-wrap;}"
         ".copy-button{flex:0 0 auto;background:#f4efdf;border:1px solid #d5c8a2;border-radius:10px;padding:6px 10px;font:inherit;font-size:12px;color:#4b3b13;cursor:pointer;box-shadow:0 1px 0 rgba(255,255,255,.7) inset;}"
         ".copy-button:hover{background:#eee4c7;}"
         ".copy-button-row{display:flex;flex-wrap:wrap;gap:8px;}"
         ".amount-in{color:#137c34;font-weight:700;}"
         ".amount-out{color:#b02b2b;font-weight:700;}"
         ".value-cell{min-width:0;overflow-wrap:anywhere;word-break:break-word;}"
         "ul{padding-left:18px;} .note{padding:13px 15px;background:#f7f4eb;border-left:4px solid #8a8a80;border-radius:10px;line-height:1.45;}"
         ".nav{margin-bottom:14px;font-size:14px;}"
         ".global-banner{margin:0 0 18px 0;padding:13px 15px;background:#fff3d6;border:1px solid #d8b96a;border-radius:12px;color:#5e4300;font-weight:700;box-shadow:0 6px 18px rgba(126,93,9,.06);}"
         ".status-hero{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap;}"
         ".status-hero>div{min-width:0;}"
         ".decision-line{margin-top:14px;padding:13px 15px;border-radius:12px;font-weight:800;letter-spacing:.03em;background:#eef6ea;color:#18461f;border:1px solid #9dc69b;}"
         ".summary-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;}"
         ".inline-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;}"
         ".copy-button-inline{background:#f7f2e2;border:1px solid #ddcfab;border-radius:8px;padding:2px 7px;font:inherit;font-size:11px;color:#574310;cursor:pointer;}"
         ".copy-button-inline:hover{background:#eee5ca;}"
         ".recent-list{display:grid;gap:12px;}"
         ".recent-item{border:1px solid #e3e3de;border-radius:8px;padding:12px;background:#fbfbf8;}"
         ".recent-item-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;margin-bottom:10px;}"
         ".recent-meta{display:grid;grid-template-columns:minmax(110px,180px) minmax(0,1fr);gap:6px 12px;font-size:14px;}"
         ".route-actions{display:flex;flex-wrap:wrap;gap:8px;}"
         ".weight-flow{white-space:nowrap;}"
         ".hero-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:16px;}"
         ".metric-card{padding:14px 16px;border-radius:14px;background:linear-gradient(180deg,#fffdfa 0%,#f7f2e6 100%);border:1px solid #e7ddc6;}"
         ".metric-card .label{display:block;color:#6e644d;font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;}"
         ".metric-card .value{display:block;font-size:22px;font-weight:800;line-height:1.1;}"
         ".metric-card .sub{display:block;margin-top:6px;color:#5b5b5b;line-height:1.4;}"
         ".top-nav{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 16px 0;}"
         ".top-tab{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.72);border:1px solid #e4dbc4;color:#5d522f;text-decoration:none;font-size:13px;font-weight:700;letter-spacing:.03em;}"
         ".top-tab:hover{background:#fff7e3;text-decoration:none;}"
         ".top-tab-active{background:#f1e3b7;border-color:#caa752;color:#3f300c;box-shadow:0 6px 18px rgba(126,93,9,.08);}"
         ".status-chip{display:inline-flex;align-items:center;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;}"
         ".status-chip-good{background:#e4f5df;color:#1c5c20;border:1px solid #89c28b;}"
         ".status-chip-warn{background:#fff1d8;color:#7b4c06;border:1px solid #dfb267;}"
         ".status-chip-muted{background:#eceae3;color:#5d5b52;border:1px solid #d7d2c7;}"
         "details.disclosure{margin-top:14px;border-top:1px solid #ebe4d4;padding-top:12px;}"
         "details.disclosure summary{cursor:pointer;font-weight:700;color:#5d522f;}"
         "details.disclosure[open] summary{margin-bottom:10px;}"
         ".soft-empty{padding:16px 18px;border-radius:14px;background:linear-gradient(180deg,#fbfaf5 0%,#f4f1e7 100%);border:1px dashed #d6cdaa;color:#5a5342;}"
         "@media (max-width:780px){h1{font-size:26px;}.grid{grid-template-columns:1fr;}.card{padding:15px 16px;}.badge{font-size:14px;padding:8px 12px;}.mono-block{flex-direction:column;}.copy-button{align-self:flex-start;}}"
         "@media (max-width:560px){body{padding:12px;}table{min-width:460px;font-size:13px;}th,td{padding:7px 8px;}}"
      << "</style><script>"
         "function copyText(btn){"
         "const value=btn.getAttribute('data-copy')||'';"
         "const done=()=>{const prev=btn.textContent;btn.textContent='Copied';setTimeout(()=>btn.textContent=prev,1200);};"
         "if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(value).then(done).catch(()=>{});return;}"
         "const area=document.createElement('textarea');area.value=value;document.body.appendChild(area);area.select();"
         "try{document.execCommand('copy');done();}catch(e){}"
         "document.body.removeChild(area);"
         "}"
      << "</script></head><body><main>"
      << "<div class=\"nav\"><a href=\"/\">Finalis Explorer</a></div>"
      << top_nav(active_nav)
      << global_finalized_banner()
      << body << "</main></body></html>";
  return oss.str();
}

std::string url_decode(std::string_view in) {
  std::string out;
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i) {
    if (in[i] == '%' && i + 2 < in.size()) {
      auto hex = std::string(in.substr(i + 1, 2));
      auto b = finalis::hex_decode(hex);
      if (b.has_value() && b->size() == 1) {
        out.push_back(static_cast<char>((*b)[0]));
        i += 2;
        continue;
      }
    }
    out.push_back(in[i] == '+' ? ' ' : static_cast<char>(in[i]));
  }
  return out;
}

std::optional<Config> parse_args(int argc, char** argv) {
  Config cfg;
  if (const char* v = std::getenv("FINALIS_PARTNER_AUTH_REQUIRED")) {
    cfg.partner_auth_required = std::string(v) == "1" || lowercase_ascii(std::string(v)) == "true";
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_API_KEY")) cfg.partner_api_key = v;
  if (const char* v = std::getenv("FINALIS_PARTNER_API_SECRET")) cfg.partner_api_secret = v;
  if (const char* v = std::getenv("FINALIS_PARTNER_REGISTRY_PATH")) cfg.partner_registry_path = v;
  if (const char* v = std::getenv("FINALIS_PARTNER_AUTH_MAX_SKEW_SECONDS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value()) cfg.partner_auth_max_skew_seconds = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_RATE_LIMIT_PER_MINUTE")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value() && *parsed != 0) cfg.partner_rate_limit_per_minute = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_WEBHOOK_MAX_ATTEMPTS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value() && *parsed != 0) cfg.partner_webhook_max_attempts = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_WEBHOOK_INITIAL_BACKOFF_MS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value() && *parsed != 0) cfg.partner_webhook_initial_backoff_ms = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_WEBHOOK_MAX_BACKOFF_MS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value() && *parsed != 0) cfg.partner_webhook_max_backoff_ms = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_IDEMPOTENCY_TTL_SECONDS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value()) cfg.partner_idempotency_ttl_seconds = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_EVENTS_TTL_SECONDS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value()) cfg.partner_events_ttl_seconds = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_WEBHOOK_QUEUE_TTL_SECONDS")) {
    if (auto parsed = parse_u64_strict(v); parsed.has_value()) cfg.partner_webhook_queue_ttl_seconds = *parsed;
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_MTLS_REQUIRED")) {
    cfg.partner_mtls_required = std::string(v) == "1" || lowercase_ascii(std::string(v)) == "true";
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_ALLOWED_IPV4_CIDRS")) {
    std::stringstream ss(v);
    std::string item;
    while (std::getline(ss, item, ',')) {
      if (!item.empty()) cfg.partner_allowed_ipv4_cidrs_raw.push_back(item);
    }
  }
  if (const char* v = std::getenv("FINALIS_PARTNER_WEBHOOK_AUDIT_LOG_PATH")) cfg.partner_webhook_audit_log_path = v;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> std::optional<std::string> {
      if (i + 1 >= argc) return std::nullopt;
      return std::string(argv[++i]);
    };
    if (a == "--bind") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.bind_ip = *v;
    } else if (a == "--port") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.port = static_cast<std::uint16_t>(std::stoi(*v));
    } else if (a == "--rpc-url") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.rpc_url = *v;
    } else if (a == "--cache-path") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.cache_path = *v;
    } else if (a == "--partner-auth-required") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.partner_auth_required = (*v == "1" || lowercase_ascii(*v) == "true");
    } else if (a == "--partner-api-key") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.partner_api_key = *v;
    } else if (a == "--partner-api-secret") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.partner_api_secret = *v;
    } else if (a == "--partner-registry") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.partner_registry_path = *v;
    } else if (a == "--partner-auth-max-skew-seconds") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value()) return std::nullopt;
      cfg.partner_auth_max_skew_seconds = *parsed;
    } else if (a == "--partner-rate-limit-per-minute") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value() || *parsed == 0) return std::nullopt;
      cfg.partner_rate_limit_per_minute = *parsed;
    } else if (a == "--partner-webhook-max-attempts") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value() || *parsed == 0) return std::nullopt;
      cfg.partner_webhook_max_attempts = *parsed;
    } else if (a == "--partner-webhook-initial-backoff-ms") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value() || *parsed == 0) return std::nullopt;
      cfg.partner_webhook_initial_backoff_ms = *parsed;
    } else if (a == "--partner-webhook-max-backoff-ms") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value() || *parsed == 0) return std::nullopt;
      cfg.partner_webhook_max_backoff_ms = *parsed;
    } else if (a == "--partner-idempotency-ttl-seconds") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value()) return std::nullopt;
      cfg.partner_idempotency_ttl_seconds = *parsed;
    } else if (a == "--partner-events-ttl-seconds") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value()) return std::nullopt;
      cfg.partner_events_ttl_seconds = *parsed;
    } else if (a == "--partner-webhook-queue-ttl-seconds") {
      auto v = next();
      if (!v) return std::nullopt;
      auto parsed = parse_u64_strict(*v);
      if (!parsed.has_value()) return std::nullopt;
      cfg.partner_webhook_queue_ttl_seconds = *parsed;
    } else if (a == "--partner-mtls-required") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.partner_mtls_required = (*v == "1" || lowercase_ascii(*v) == "true");
    } else if (a == "--partner-allowed-ipv4-cidrs") {
      auto v = next();
      if (!v) return std::nullopt;
      std::stringstream ss(*v);
      std::string item;
      while (std::getline(ss, item, ',')) {
        if (!item.empty()) cfg.partner_allowed_ipv4_cidrs_raw.push_back(item);
      }
    } else if (a == "--partner-webhook-audit-log-path") {
      auto v = next();
      if (!v) return std::nullopt;
      cfg.partner_webhook_audit_log_path = *v;
    } else {
      return std::nullopt;
    }
  }
  if (cfg.partner_auth_required && cfg.partner_registry_path.empty() && (cfg.partner_api_key.empty() || cfg.partner_api_secret.empty())) {
    return std::nullopt;
  }
  return cfg;
}

struct RpcCallResult {
  std::optional<finalis::minijson::Value> result;
  std::string error;
  std::optional<std::int64_t> error_code;
};

using RpcGetUtxosFn =
    std::function<std::optional<std::vector<finalis::lightserver::UtxoView>>(const std::string&, const Hash32&, std::string*)>;

HttpPostJsonRawFn g_http_post_json_raw = [](const std::string& rpc_url, const std::string& body, std::string* err) {
  return finalis::lightserver::http_post_json_raw(rpc_url, body, err);
};

RpcGetUtxosFn g_rpc_get_utxos = [](const std::string& rpc_url, const Hash32& scripthash, std::string* err) {
  return finalis::lightserver::rpc_get_utxos(rpc_url, scripthash, err);
};

RpcCallResult rpc_call(const std::string& rpc_url, const std::string& method, const std::string& params_json) {
  const auto started = std::chrono::steady_clock::now();
  RpcCallResult out;
  const std::string body =
      std::string(R"({"jsonrpc":"2.0","id":1,"method":")") + json_escape(method) + R"(","params":)" + params_json + "}";
  std::string err;
  auto raw = g_http_post_json_raw(rpc_url, body, &err);
  if (!raw.has_value()) {
    out.error = err.empty() ? "rpc request failed" : err;
    return out;
  }
  auto root = finalis::minijson::parse(*raw);
  if (!root.has_value() || !root->is_object()) {
    out.error = "invalid rpc response";
    return out;
  }
  if (const auto* error = root->get("error"); error && error->is_object()) {
    if (const auto* code = error->get("code"); code && code->is_number()) {
      try {
        out.error_code = std::stoll(code->string_value);
      } catch (...) {
      }
    }
    if (const auto* msg = error->get("message")) {
      out.error = msg->as_string().value_or("rpc returned error");
    } else {
      out.error = "rpc returned error";
    }
    return out;
  }
  const auto* result = root->get("result");
  if (!result) {
    out.error = "missing rpc result";
  } else {
    out.result = *result;
  }

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
  if (elapsed >= kSlowRpcThreshold) {
    std::lock_guard<std::mutex> guard(g_log_mu);
    std::cerr << "[explorer] slow-rpc method=" << method << " duration_ms=" << elapsed.count();
    if (!out.error.empty()) std::cerr << " error=" << out.error;
    std::cerr << "\n";
  }
  return out;
}

std::optional<std::string> object_string(const finalis::minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_string();
}

std::optional<std::uint64_t> object_u64(const finalis::minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_u64();
}

std::optional<bool> object_bool(const finalis::minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value) return std::nullopt;
  return value->as_bool();
}

std::optional<std::int64_t> object_i64(const finalis::minijson::Value* obj, const char* key) {
  if (!obj || !obj->is_object()) return std::nullopt;
  const auto* value = obj->get(key);
  if (!value || !value->is_number()) return std::nullopt;
  try {
    return std::stoll(value->string_value);
  } catch (...) {
    return std::nullopt;
  }
}

finalis::minijson::Value json_null() { return finalis::minijson::Value{}; }

finalis::minijson::Value json_bool_value(bool v) {
  finalis::minijson::Value out;
  out.type = finalis::minijson::Value::Type::Bool;
  out.bool_value = v;
  return out;
}

finalis::minijson::Value json_number_value(std::uint64_t v) {
  finalis::minijson::Value out;
  out.type = finalis::minijson::Value::Type::Number;
  out.string_value = std::to_string(v);
  return out;
}

finalis::minijson::Value json_number_value_i64(std::int64_t v) {
  finalis::minijson::Value out;
  out.type = finalis::minijson::Value::Type::Number;
  out.string_value = std::to_string(v);
  return out;
}

finalis::minijson::Value json_string_value(const std::string& v) {
  finalis::minijson::Value out;
  out.type = finalis::minijson::Value::Type::String;
  out.string_value = v;
  return out;
}

finalis::minijson::Value json_array_value() {
  finalis::minijson::Value out;
  out.type = finalis::minijson::Value::Type::Array;
  return out;
}

finalis::minijson::Value json_object_value() {
  finalis::minijson::Value out;
  out.type = finalis::minijson::Value::Type::Object;
  return out;
}

void json_put(finalis::minijson::Value& obj, const char* key, const std::string& value) {
  obj.object_value[std::string(key)] = json_string_value(value);
}

void json_put(finalis::minijson::Value& obj, const char* key, const std::optional<std::string>& value) {
  obj.object_value[std::string(key)] = value.has_value() ? json_string_value(*value) : json_null();
}

void json_put(finalis::minijson::Value& obj, const char* key, std::uint64_t value) {
  obj.object_value[std::string(key)] = json_number_value(value);
}

void json_put(finalis::minijson::Value& obj, const char* key, const std::optional<std::uint64_t>& value) {
  obj.object_value[std::string(key)] = value.has_value() ? json_number_value(*value) : json_null();
}

void json_put(finalis::minijson::Value& obj, const char* key, const std::optional<std::int64_t>& value) {
  obj.object_value[std::string(key)] = value.has_value() ? json_number_value_i64(*value) : json_null();
}

void json_put(finalis::minijson::Value& obj, const char* key, bool value) {
  obj.object_value[std::string(key)] = json_bool_value(value);
}

void json_put(finalis::minijson::Value& obj, const char* key, const std::optional<bool>& value) {
  obj.object_value[std::string(key)] = value.has_value() ? json_bool_value(*value) : json_null();
}

finalis::minijson::Value serialize_partner_withdrawal(const PartnerWithdrawal& w) {
  auto out = json_object_value();
  json_put(out, "partner_id", w.partner_id);
  json_put(out, "client_withdrawal_id", w.client_withdrawal_id);
  json_put(out, "txid", w.txid);
  json_put(out, "state", w.state);
  json_put(out, "retryable", w.retryable);
  json_put(out, "retry_class", w.retry_class);
  json_put(out, "error_code", w.error_code);
  json_put(out, "error_message", w.error_message);
  json_put(out, "finalized_height", w.finalized_height);
  json_put(out, "transition_hash", w.transition_hash);
  json_put(out, "created_unix_ms", w.created_unix_ms);
  json_put(out, "updated_unix_ms", w.updated_unix_ms);
  return out;
}

std::optional<PartnerWithdrawal> parse_partner_withdrawal(const finalis::minijson::Value& v) {
  if (!v.is_object()) return std::nullopt;
  PartnerWithdrawal w;
  w.partner_id = object_string(&v, "partner_id").value_or("");
  w.client_withdrawal_id = object_string(&v, "client_withdrawal_id").value_or("");
  w.txid = object_string(&v, "txid").value_or("");
  w.state = object_string(&v, "state").value_or("");
  w.retryable = object_bool(&v, "retryable").value_or(false);
  w.retry_class = object_string(&v, "retry_class").value_or("none");
  w.error_code = object_string(&v, "error_code");
  w.error_message = object_string(&v, "error_message");
  w.finalized_height = object_u64(&v, "finalized_height");
  w.transition_hash = object_string(&v, "transition_hash");
  w.created_unix_ms = object_u64(&v, "created_unix_ms").value_or(0);
  w.updated_unix_ms = object_u64(&v, "updated_unix_ms").value_or(0);
  if (w.partner_id.empty() || w.client_withdrawal_id.empty() || w.txid.empty() || w.state.empty()) return std::nullopt;
  return w;
}

finalis::minijson::Value serialize_partner_event(const PartnerEvent& e) {
  auto out = json_object_value();
  json_put(out, "sequence", e.sequence);
  json_put(out, "partner_id", e.partner_id);
  json_put(out, "event_type", e.event_type);
  json_put(out, "object_id", e.object_id);
  json_put(out, "state", e.state);
  json_put(out, "emitted_unix_ms", e.emitted_unix_ms);
  return out;
}

std::optional<PartnerEvent> parse_partner_event(const finalis::minijson::Value& v) {
  if (!v.is_object()) return std::nullopt;
  PartnerEvent e;
  e.sequence = object_u64(&v, "sequence").value_or(0);
  e.partner_id = object_string(&v, "partner_id").value_or("");
  e.event_type = object_string(&v, "event_type").value_or("");
  e.object_id = object_string(&v, "object_id").value_or("");
  e.state = object_string(&v, "state").value_or("");
  e.emitted_unix_ms = object_u64(&v, "emitted_unix_ms").value_or(0);
  if (e.sequence == 0 || e.partner_id.empty() || e.event_type.empty() || e.object_id.empty() || e.state.empty()) return std::nullopt;
  return e;
}

finalis::minijson::Value serialize_partner_webhook_delivery(const PartnerWebhookDelivery& d) {
  auto out = json_object_value();
  json_put(out, "partner_id", d.partner_id);
  json_put(out, "sequence", d.sequence);
  json_put(out, "url", d.url);
  json_put(out, "payload_json", d.payload_json);
  json_put(out, "attempt", d.attempt);
  json_put(out, "enqueued_unix_ms", d.enqueued_unix_ms);
  json_put(out, "next_attempt_unix_ms", d.next_attempt_unix_ms);
  return out;
}

std::optional<PartnerWebhookDelivery> parse_partner_webhook_delivery(const finalis::minijson::Value& v) {
  if (!v.is_object()) return std::nullopt;
  PartnerWebhookDelivery d;
  d.partner_id = object_string(&v, "partner_id").value_or("");
  d.sequence = object_u64(&v, "sequence").value_or(0);
  d.url = object_string(&v, "url").value_or("");
  d.payload_json = object_string(&v, "payload_json").value_or("");
  d.attempt = object_u64(&v, "attempt").value_or(0);
  d.next_attempt_unix_ms = object_u64(&v, "next_attempt_unix_ms").value_or(0);
  d.enqueued_unix_ms = object_u64(&v, "enqueued_unix_ms").value_or(d.next_attempt_unix_ms);
  if (d.partner_id.empty() || d.sequence == 0 || d.url.empty() || d.payload_json.empty()) return std::nullopt;
  return d;
}

finalis::minijson::Value serialize_partner_webhook_dlq_entry(const PartnerWebhookDlqEntry& d) {
  auto out = json_object_value();
  json_put(out, "partner_id", d.partner_id);
  json_put(out, "sequence", d.sequence);
  json_put(out, "url", d.url);
  json_put(out, "payload_json", d.payload_json);
  json_put(out, "enqueued_unix_ms", d.enqueued_unix_ms);
  json_put(out, "failed_unix_ms", d.failed_unix_ms);
  json_put(out, "attempts", d.attempts);
  json_put(out, "last_error", d.last_error);
  return out;
}

std::optional<PartnerWebhookDlqEntry> parse_partner_webhook_dlq_entry(const finalis::minijson::Value& v) {
  if (!v.is_object()) return std::nullopt;
  PartnerWebhookDlqEntry d;
  d.partner_id = object_string(&v, "partner_id").value_or("");
  d.sequence = object_u64(&v, "sequence").value_or(0);
  d.url = object_string(&v, "url").value_or("");
  d.payload_json = object_string(&v, "payload_json").value_or("");
  d.enqueued_unix_ms = object_u64(&v, "enqueued_unix_ms").value_or(0);
  d.failed_unix_ms = object_u64(&v, "failed_unix_ms").value_or(0);
  d.attempts = object_u64(&v, "attempts").value_or(0);
  d.last_error = object_string(&v, "last_error").value_or("");
  if (d.partner_id.empty() || d.sequence == 0 || d.url.empty() || d.payload_json.empty()) return std::nullopt;
  return d;
}

finalis::minijson::Value serialize_string_map(const std::unordered_map<std::string, std::string>& values) {
  auto out = json_array_value();
  for (const auto& [k, v] : values) {
    auto item = json_object_value();
    json_put(item, "key", k);
    json_put(item, "value", v);
    out.array_value.push_back(std::move(item));
  }
  return out;
}

std::unordered_map<std::string, std::string> parse_string_map(const finalis::minijson::Value& values) {
  std::unordered_map<std::string, std::string> out;
  if (!values.is_array()) return out;
  for (const auto& item : values.array_value) {
    if (!item.is_object()) continue;
    const auto key = object_string(&item, "key");
    const auto value = object_string(&item, "value");
    if (!key.has_value() || key->empty() || !value.has_value()) continue;
    out[*key] = *value;
  }
  return out;
}

finalis::minijson::Value serialize_u64_map(const std::unordered_map<std::string, std::uint64_t>& values, const char* value_key) {
  auto out = json_array_value();
  for (const auto& [k, v] : values) {
    auto item = json_object_value();
    json_put(item, "key", k);
    json_put(item, value_key, v);
    out.array_value.push_back(std::move(item));
  }
  return out;
}

std::unordered_map<std::string, std::uint64_t> parse_u64_map(const finalis::minijson::Value& values, const char* value_key) {
  std::unordered_map<std::string, std::uint64_t> out;
  if (!values.is_array()) return out;
  for (const auto& item : values.array_value) {
    if (!item.is_object()) continue;
    const auto key = object_string(&item, "key");
    const auto value = object_u64(&item, value_key);
    if (!key.has_value() || key->empty() || !value.has_value()) continue;
    out[*key] = *value;
  }
  return out;
}

finalis::minijson::Value serialize_nonce_map(const std::unordered_map<std::string, std::uint64_t>& values) {
  return serialize_u64_map(values, "unix_sec");
}

std::unordered_map<std::string, std::uint64_t> parse_nonce_map(const finalis::minijson::Value& values) {
  return parse_u64_map(values, "unix_sec");
}

LookupResult<StatusResult> parse_status_result_object(const finalis::minijson::Value& status_obj) {
  LookupResult<StatusResult> out;
  if (!status_obj.is_object()) {
    out.error = upstream_error("status unavailable");
    return out;
  }
  StatusResult result;
  result.network = object_string(&status_obj, "network_name").value_or("unknown");
  result.network_id = object_string(&status_obj, "network_id").value_or("");
  result.genesis_hash = object_string(&status_obj, "genesis_hash").value_or("");
  result.finalized_height = object_u64(&status_obj, "finalized_height").value_or(0);
  result.finalized_transition_hash =
      object_string(&status_obj, "finalized_transition_hash").value_or(object_string(&status_obj, "transition_hash").value_or(""));
  result.backend_version = object_string(&status_obj, "version").value_or("unknown");
  result.wallet_api_version = object_string(&status_obj, "wallet_api_version").value_or("");
  result.protocol_reserve_balance = object_u64(&status_obj, "protocol_reserve_balance");
  result.healthy_peer_count = object_u64(&status_obj, "healthy_peer_count").value_or(0);
  result.established_peer_count = object_u64(&status_obj, "established_peer_count").value_or(0);
  result.latest_finality_committee_size =
      static_cast<std::size_t>(object_u64(&status_obj, "latest_finality_committee_size").value_or(0));
  result.latest_finality_quorum_threshold =
      static_cast<std::size_t>(object_u64(&status_obj, "latest_finality_quorum_threshold").value_or(0));
  if (const auto* sync = status_obj.get("sync"); sync && sync->is_object()) {
    result.observed_network_height_known = object_bool(sync, "observed_network_height_known").value_or(false);
    result.bootstrap_sync_incomplete = object_bool(sync, "bootstrap_sync_incomplete").value_or(false);
    result.peer_height_disagreement = object_bool(sync, "peer_height_disagreement").value_or(false);
    result.finalized_lag = object_u64(sync, "finalized_lag");
    if (result.observed_network_height_known) result.observed_network_finalized_height = object_u64(sync, "observed_network_finalized_height");
  }
  if (const auto* availability = status_obj.get("availability"); availability && availability->is_object()) {
    result.availability_epoch = object_u64(availability, "epoch");
    result.availability_retained_prefix_count = object_u64(availability, "retained_prefix_count");
    result.availability_tracked_operator_count = object_u64(availability, "tracked_operator_count");
    result.availability_eligible_operator_count = object_u64(availability, "eligible_operator_count");
    result.availability_below_min_eligible = object_bool(availability, "below_min_eligible");
    result.availability_checkpoint_derivation_mode = object_string(availability, "checkpoint_derivation_mode");
    result.availability_checkpoint_fallback_reason = object_string(availability, "checkpoint_fallback_reason");
    result.availability_fallback_sticky = object_bool(availability, "fallback_sticky");
    if (const auto* adaptive = availability->get("adaptive_regime"); adaptive && adaptive->is_object()) {
      result.qualified_depth = object_u64(adaptive, "qualified_depth");
      result.adaptive_target_committee_size = object_u64(adaptive, "adaptive_target_committee_size");
      result.adaptive_min_eligible = object_u64(adaptive, "adaptive_min_eligible");
      result.adaptive_min_bond = object_u64(adaptive, "adaptive_min_bond");
      result.adaptive_slack = object_i64(adaptive, "slack");
      result.target_expand_streak = object_u64(adaptive, "target_expand_streak");
      result.target_contract_streak = object_u64(adaptive, "target_contract_streak");
      result.adaptive_fallback_rate_bps = object_u64(adaptive, "fallback_rate_bps");
      result.adaptive_sticky_fallback_rate_bps = object_u64(adaptive, "sticky_fallback_rate_bps");
      result.adaptive_fallback_window_epochs = object_u64(adaptive, "fallback_rate_window_epochs");
      result.adaptive_near_threshold_operation = object_bool(adaptive, "near_threshold_operation");
      result.adaptive_prolonged_expand_buildup = object_bool(adaptive, "prolonged_expand_buildup");
      result.adaptive_prolonged_contract_buildup = object_bool(adaptive, "prolonged_contract_buildup");
      result.adaptive_repeated_sticky_fallback = object_bool(adaptive, "repeated_sticky_fallback");
      result.adaptive_depth_collapse_after_bond_increase = object_bool(adaptive, "depth_collapse_after_bond_increase");
    }
    if (const auto* local = availability->get("local_operator"); local && local->is_object()) {
      result.availability_local_operator_known = object_bool(local, "known");
      result.availability_local_operator_pubkey = object_string(local, "pubkey");
      result.availability_local_operator_status = object_string(local, "status");
      result.availability_local_operator_seat_budget = object_u64(local, "seat_budget");
      result.availability_local_operator_validator_status = object_string(local, "validator_registry_status");
      result.availability_local_operator_onboarding_reward_eligible = object_bool(local, "onboarding_reward_eligible");
      result.availability_local_operator_onboarding_reward_score_units = object_u64(local, "onboarding_reward_score_units");
    }
  }
  if (const auto* adaptive_summary = status_obj.get("adaptive_telemetry_summary"); adaptive_summary && adaptive_summary->is_object()) {
    result.adaptive_telemetry_window_epochs = object_u64(adaptive_summary, "window_epochs");
    result.adaptive_telemetry_sample_count = object_u64(adaptive_summary, "sample_count");
    result.adaptive_telemetry_fallback_epochs = object_u64(adaptive_summary, "fallback_epochs");
    result.adaptive_telemetry_sticky_fallback_epochs = object_u64(adaptive_summary, "sticky_fallback_epochs");
  }
  if (const auto* onboarding = status_obj.get("onboarding"); onboarding && onboarding->is_object()) {
    result.onboarding_reward_pool_bps = static_cast<std::uint32_t>(object_u64(onboarding, "reward_pool_bps").value_or(0));
    result.onboarding_admission_pow_difficulty_bits =
        static_cast<std::uint32_t>(object_u64(onboarding, "admission_pow_difficulty_bits").value_or(0));
    result.validator_join_admission_pow_difficulty_bits =
        static_cast<std::uint32_t>(object_u64(onboarding, "validator_join_admission_pow_difficulty_bits").value_or(0));
  }
  if (const auto* ticket_pow = status_obj.get("ticket_pow"); ticket_pow && ticket_pow->is_object()) {
    result.ticket_pow_difficulty = static_cast<std::uint32_t>(object_u64(ticket_pow, "difficulty").value_or(0));
    result.ticket_pow_difficulty_min = static_cast<std::uint32_t>(object_u64(ticket_pow, "difficulty_min").value_or(0));
    result.ticket_pow_difficulty_max = static_cast<std::uint32_t>(object_u64(ticket_pow, "difficulty_max").value_or(0));
    result.ticket_pow_epoch_health = object_string(ticket_pow, "epoch_health").value_or("unknown");
    result.ticket_pow_streak_up = object_u64(ticket_pow, "streak_up").value_or(0);
    result.ticket_pow_streak_down = object_u64(ticket_pow, "streak_down").value_or(0);
    result.ticket_pow_nonce_search_limit = object_u64(ticket_pow, "nonce_search_limit").value_or(0);
    result.ticket_pow_bonus_cap_bps = static_cast<std::uint32_t>(object_u64(ticket_pow, "bonus_cap_bps").value_or(0));
  }
  out.value = std::move(result);
  return out;
}

LookupResult<CommitteeResult> parse_committee_result_object(const finalis::minijson::Value& committee_obj,
                                                            std::uint64_t requested_height) {
  LookupResult<CommitteeResult> out;
  if (!committee_obj.is_object()) {
    out.error = upstream_error("committee unavailable");
    return out;
  }
  CommitteeResult result;
  result.height = object_u64(&committee_obj, "height").value_or(requested_height);
  result.epoch_start_height = object_u64(&committee_obj, "epoch_start_height").value_or(0);
  result.checkpoint_derivation_mode = object_string(&committee_obj, "checkpoint_derivation_mode");
  result.checkpoint_fallback_reason = object_string(&committee_obj, "checkpoint_fallback_reason");
  result.fallback_sticky = object_bool(&committee_obj, "fallback_sticky");
  result.availability_eligible_operator_count = object_u64(&committee_obj, "availability_eligible_operator_count");
  result.availability_min_eligible_operators = object_u64(&committee_obj, "availability_min_eligible_operators");
  result.adaptive_target_committee_size = object_u64(&committee_obj, "adaptive_target_committee_size");
  result.adaptive_min_eligible = object_u64(&committee_obj, "adaptive_min_eligible");
  result.adaptive_min_bond = object_u64(&committee_obj, "adaptive_min_bond");
  result.qualified_depth = object_u64(&committee_obj, "qualified_depth");
  result.adaptive_slack = object_i64(&committee_obj, "slack");
  result.target_expand_streak = object_u64(&committee_obj, "target_expand_streak");
  result.target_contract_streak = object_u64(&committee_obj, "target_contract_streak");
  const auto* members = committee_obj.get("members");
  if (!members || !members->is_array()) {
    out.error = upstream_error("committee members missing");
    return out;
  }
  for (const auto& member : members->array_value) {
    if (!member.is_object()) continue;
    CommitteeMemberResult item;
    item.operator_id = object_string(&member, "operator_id");
    item.representative_pubkey = object_string(&member, "representative_pubkey").value_or("");
    item.resolved_operator_id = item.operator_id.value_or(item.representative_pubkey);
    item.operator_id_source = item.operator_id.has_value() ? "operator_id" : "representative_pubkey";
    item.base_weight = object_u64(&member, "base_weight");
    item.ticket_bonus_bps = object_u64(&member, "ticket_bonus_bps");
    item.final_weight = object_u64(&member, "final_weight");
    item.ticket_hash = object_string(&member, "ticket_hash");
    item.ticket_nonce = object_u64(&member, "ticket_nonce");
    result.members.push_back(std::move(item));
  }
  out.value = std::move(result);
  return out;
}

std::vector<RecentTxResult> parse_recent_tx_cache_array(const finalis::minijson::Value& recent_array) {
  std::vector<RecentTxResult> out;
  if (!recent_array.is_array()) return out;
  out.reserve(recent_array.array_value.size());
  for (const auto& item_value : recent_array.array_value) {
    if (!item_value.is_object()) continue;
    auto txid = object_string(&item_value, "txid");
    if (!txid.has_value()) continue;
    RecentTxResult item;
    item.txid = *txid;
    item.height = object_u64(&item_value, "height");
    item.timestamp = object_u64(&item_value, "timestamp");
    item.total_out = object_u64(&item_value, "total_out");
    item.status_label = object_string(&item_value, "status_label");
    item.credit_safe = object_bool(&item_value, "credit_safe");
    if (auto count = object_u64(&item_value, "input_count"); count.has_value()) item.input_count = static_cast<std::size_t>(*count);
    if (auto count = object_u64(&item_value, "output_count"); count.has_value()) item.output_count = static_cast<std::size_t>(*count);
    item.fee = object_u64(&item_value, "fee");
    item.primary_sender = object_string(&item_value, "primary_sender");
    item.primary_recipient = object_string(&item_value, "primary_recipient");
    if (auto count = object_u64(&item_value, "recipient_count"); count.has_value()) item.recipient_count = static_cast<std::size_t>(*count);
    item.flow_kind = object_string(&item_value, "flow_kind");
    item.flow_summary = object_string(&item_value, "flow_summary");
    out.push_back(std::move(item));
  }
  return out;
}

finalis::minijson::Value serialize_recent_tx_cache_array(const std::vector<RecentTxResult>& rows) {
  auto array = json_array_value();
  for (const auto& row : rows) {
    auto item = json_object_value();
    json_put(item, "txid", row.txid);
    json_put(item, "height", row.height);
    json_put(item, "timestamp", row.timestamp);
    json_put(item, "total_out", row.total_out);
    json_put(item, "status_label", row.status_label);
    json_put(item, "credit_safe", row.credit_safe);
    json_put(item, "input_count",
             row.input_count.has_value() ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(*row.input_count)) : std::nullopt);
    json_put(item, "output_count",
             row.output_count.has_value() ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(*row.output_count)) : std::nullopt);
    json_put(item, "fee", row.fee);
    json_put(item, "primary_sender", row.primary_sender);
    json_put(item, "primary_recipient", row.primary_recipient);
    json_put(item, "recipient_count",
             row.recipient_count.has_value() ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(*row.recipient_count)) : std::nullopt);
    json_put(item, "flow_kind", row.flow_kind);
    json_put(item, "flow_summary", row.flow_summary);
    array.array_value.push_back(std::move(item));
  }
  return array;
}

finalis::minijson::Value serialize_tx_result_object(const TxResult& result) {
  auto obj = json_object_value();
  json_put(obj, "txid", result.txid);
  json_put(obj, "found", result.found);
  json_put(obj, "finalized", result.finalized);
  json_put(obj, "finalized_height", result.finalized_height);
  json_put(obj, "finalized_depth", result.finalized_depth);
  json_put(obj, "credit_safe", result.credit_safe);
  json_put(obj, "status_label", result.status_label);
  json_put(obj, "transition_hash", result.transition_hash);
  json_put(obj, "timestamp", result.timestamp);
  json_put(obj, "total_out", result.total_out);
  json_put(obj, "fee", result.fee);
  json_put(obj, "flow_kind", result.flow_kind);
  json_put(obj, "flow_summary", result.flow_summary);
  json_put(obj, "primary_sender", result.primary_sender);
  json_put(obj, "primary_recipient", result.primary_recipient);
  json_put(obj, "data_source", result.data_source);
  json_put(obj, "data_refreshed_unix_ms", result.data_refreshed_unix_ms);
  json_put(obj, "participant_count",
           result.participant_count.has_value() ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(*result.participant_count))
                                                : std::nullopt);
  auto inputs = json_array_value();
  for (const auto& in : result.inputs) {
    auto item = json_object_value();
    json_put(item, "prev_txid", in.prev_txid);
    json_put(item, "vout", static_cast<std::uint64_t>(in.vout));
    json_put(item, "address", in.address);
    json_put(item, "amount", in.amount);
    inputs.array_value.push_back(std::move(item));
  }
  auto outputs = json_array_value();
  for (const auto& out : result.outputs) {
    auto item = json_object_value();
    json_put(item, "amount", out.amount);
    json_put(item, "address", out.address);
    json_put(item, "script_hex", out.script_hex);
    json_put(item, "decoded_kind", out.decoded_kind);
    json_put(item, "validator_pubkey_hex", out.validator_pubkey_hex);
    json_put(item, "payout_pubkey_hex", out.payout_pubkey_hex);
    json_put(item, "has_admission_pow", out.has_admission_pow);
    json_put(item, "admission_pow_epoch", out.admission_pow_epoch);
    json_put(item, "admission_pow_nonce", out.admission_pow_nonce);
    outputs.array_value.push_back(std::move(item));
  }
  obj.object_value["inputs"] = std::move(inputs);
  obj.object_value["outputs"] = std::move(outputs);
  return obj;
}

std::optional<TxResult> parse_tx_result_object(const finalis::minijson::Value& obj) {
  if (!obj.is_object()) return std::nullopt;
  auto txid = object_string(&obj, "txid");
  if (!txid.has_value()) return std::nullopt;
  TxResult result;
  result.txid = *txid;
  result.found = object_bool(&obj, "found").value_or(true);
  result.finalized = object_bool(&obj, "finalized").value_or(true);
  result.finalized_height = object_u64(&obj, "finalized_height");
  result.finalized_depth = object_u64(&obj, "finalized_depth").value_or(0);
  result.credit_safe = object_bool(&obj, "credit_safe").value_or(false);
  result.status_label = object_string(&obj, "status_label").value_or("");
  result.transition_hash = object_string(&obj, "transition_hash").value_or("");
  result.timestamp = object_u64(&obj, "timestamp");
  result.total_out = object_u64(&obj, "total_out").value_or(0);
  result.fee = object_u64(&obj, "fee");
  result.flow_kind = object_string(&obj, "flow_kind").value_or("");
  result.flow_summary = object_string(&obj, "flow_summary").value_or("");
  result.primary_sender = object_string(&obj, "primary_sender");
  result.primary_recipient = object_string(&obj, "primary_recipient");
  result.data_source = object_string(&obj, "data_source").value_or("cache_finalized_snapshot");
  result.data_refreshed_unix_ms = object_u64(&obj, "data_refreshed_unix_ms");
  if (auto count = object_u64(&obj, "participant_count"); count.has_value()) result.participant_count = static_cast<std::size_t>(*count);
  if (const auto* inputs = obj.get("inputs"); inputs && inputs->is_array()) {
    for (const auto& input : inputs->array_value) {
      if (!input.is_object()) continue;
      auto prev_txid = object_string(&input, "prev_txid");
      auto vout = object_u64(&input, "vout");
      if (!prev_txid.has_value() || !vout.has_value()) continue;
      result.inputs.push_back(TxInputResult{
          *prev_txid,
          static_cast<std::uint32_t>(*vout),
          object_string(&input, "address"),
          object_u64(&input, "amount"),
      });
    }
  }
  if (const auto* outputs = obj.get("outputs"); outputs && outputs->is_array()) {
    for (const auto& output : outputs->array_value) {
      if (!output.is_object()) continue;
      result.outputs.push_back(TxOutputResult{
          object_u64(&output, "amount").value_or(0),
          object_string(&output, "address"),
          object_string(&output, "script_hex").value_or(""),
          object_string(&output, "decoded_kind"),
          object_string(&output, "validator_pubkey_hex"),
          object_string(&output, "payout_pubkey_hex"),
          object_bool(&output, "has_admission_pow").value_or(false),
          object_u64(&output, "admission_pow_epoch"),
          object_u64(&output, "admission_pow_nonce"),
      });
    }
  }
  return result;
}

finalis::minijson::Value serialize_transition_result_object(const TransitionResult& result) {
  auto obj = json_object_value();
  json_put(obj, "found", result.found);
  json_put(obj, "finalized", result.finalized);
  json_put(obj, "height", result.height);
  json_put(obj, "hash", result.hash);
  json_put(obj, "prev_finalized_hash", result.prev_finalized_hash);
  json_put(obj, "timestamp", result.timestamp);
  json_put(obj, "round", static_cast<std::uint64_t>(result.round));
  json_put(obj, "tx_count", static_cast<std::uint64_t>(result.tx_count));
  json_put(obj, "summary_cached", result.summary_cached);
  json_put(obj, "cached_summary_finalized_out", result.cached_summary_finalized_out);
  json_put(obj, "cached_summary_distinct_recipient_count", static_cast<std::uint64_t>(result.cached_summary_distinct_recipient_count));
  json_put(obj, "data_source", result.data_source);
  json_put(obj, "data_refreshed_unix_ms", result.data_refreshed_unix_ms);
  auto txids = json_array_value();
  for (const auto& txid : result.txids) txids.array_value.push_back(json_string_value(txid));
  obj.object_value["txids"] = std::move(txids);
  auto flow_mix = json_object_value();
  for (const auto& [kind, count] : result.cached_summary_flow_mix) {
    json_put(flow_mix, kind.c_str(), static_cast<std::uint64_t>(count));
  }
  obj.object_value["cached_summary_flow_mix"] = std::move(flow_mix);
  return obj;
}

std::optional<TransitionResult> parse_transition_result_object(const finalis::minijson::Value& obj) {
  if (!obj.is_object()) return std::nullopt;
  auto hash = object_string(&obj, "hash");
  if (!hash.has_value()) return std::nullopt;
  TransitionResult result;
  result.found = object_bool(&obj, "found").value_or(true);
  result.finalized = object_bool(&obj, "finalized").value_or(true);
  result.height = object_u64(&obj, "height").value_or(0);
  result.hash = *hash;
  result.prev_finalized_hash = object_string(&obj, "prev_finalized_hash").value_or("");
  result.timestamp = object_u64(&obj, "timestamp");
  result.round = static_cast<std::uint32_t>(object_u64(&obj, "round").value_or(0));
  result.tx_count = static_cast<std::size_t>(object_u64(&obj, "tx_count").value_or(0));
  result.summary_cached = object_bool(&obj, "summary_cached").value_or(false);
  result.cached_summary_finalized_out = object_u64(&obj, "cached_summary_finalized_out").value_or(0);
  result.cached_summary_distinct_recipient_count =
      static_cast<std::size_t>(object_u64(&obj, "cached_summary_distinct_recipient_count").value_or(0));
  result.data_source = object_string(&obj, "data_source").value_or("cache_finalized_snapshot");
  result.data_refreshed_unix_ms = object_u64(&obj, "data_refreshed_unix_ms");
  if (const auto* txids = obj.get("txids"); txids && txids->is_array()) {
    for (const auto& txid : txids->array_value) {
      if (txid.is_string()) result.txids.push_back(txid.string_value);
    }
  }
  if (const auto* flow_mix = obj.get("cached_summary_flow_mix"); flow_mix && flow_mix->is_object()) {
    for (const auto& [kind, value] : flow_mix->object_value) {
      if (auto count = value.as_u64(); count.has_value()) {
        result.cached_summary_flow_mix[kind] = static_cast<std::size_t>(*count);
      }
    }
  }
  return result;
}

std::optional<TxResult> find_persisted_tx_result(const std::string& txid) {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  for (const auto& entry : g_persisted_snapshot.tx_index) {
    auto parsed = parse_tx_result_object(entry);
    if (parsed.has_value() && parsed->txid == txid) {
      parsed->data_refreshed_unix_ms = g_persisted_snapshot.stored_unix_ms ? std::optional<std::uint64_t>(g_persisted_snapshot.stored_unix_ms)
                                                                           : parsed->data_refreshed_unix_ms;
      return parsed;
    }
  }
  return std::nullopt;
}

std::optional<TransitionResult> find_persisted_transition_result_by_hash(const std::string& hash) {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  for (const auto& entry : g_persisted_snapshot.transition_index) {
    auto parsed = parse_transition_result_object(entry);
    if (parsed.has_value() && parsed->hash == hash) {
      parsed->data_refreshed_unix_ms = g_persisted_snapshot.stored_unix_ms ? std::optional<std::uint64_t>(g_persisted_snapshot.stored_unix_ms)
                                                                           : parsed->data_refreshed_unix_ms;
      return parsed;
    }
  }
  return std::nullopt;
}

std::optional<TransitionResult> find_persisted_transition_result_by_height(std::uint64_t height) {
  std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
  for (const auto& entry : g_persisted_snapshot.transition_index) {
    auto parsed = parse_transition_result_object(entry);
    if (parsed.has_value() && parsed->height == height) {
      parsed->data_refreshed_unix_ms = g_persisted_snapshot.stored_unix_ms ? std::optional<std::uint64_t>(g_persisted_snapshot.stored_unix_ms)
                                                                           : parsed->data_refreshed_unix_ms;
      return parsed;
    }
  }
  return std::nullopt;
}

void upsert_persisted_tx_result(const Config& cfg, const TxResult& result) {
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    auto& entries = g_persisted_snapshot.tx_index;
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const auto& entry) {
                    auto parsed = parse_tx_result_object(entry);
                    return parsed.has_value() && parsed->txid == result.txid;
                  }),
                  entries.end());
    entries.insert(entries.begin(), serialize_tx_result_object(result));
    if (entries.size() > kPersistedTxIndexLimit) entries.resize(kPersistedTxIndexLimit);
  }
  persist_explorer_snapshot(cfg);
}

void upsert_persisted_transition_result(const Config& cfg, const TransitionResult& result) {
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    auto& entries = g_persisted_snapshot.transition_index;
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const auto& entry) {
                    auto parsed = parse_transition_result_object(entry);
                    return parsed.has_value() && (parsed->hash == result.hash || parsed->height == result.height);
                  }),
                  entries.end());
    entries.insert(entries.begin(), serialize_transition_result_object(result));
    if (entries.size() > kPersistedTransitionIndexLimit) entries.resize(kPersistedTransitionIndexLimit);
  }
  persist_explorer_snapshot(cfg);
}

std::uint64_t now_unix_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

void append_webhook_audit_log(const Config& cfg, const std::string& event, const std::string& partner_id, std::uint64_t sequence,
                              std::uint64_t attempt, bool success, const std::string& detail) {
  if (cfg.partner_webhook_audit_log_path.empty()) return;
  const auto path = std::filesystem::path(cfg.partner_webhook_audit_log_path);
  if (!path.parent_path().empty() && !finalis::ensure_private_dir(path.parent_path().string())) return;
  std::ofstream out(path, std::ios::binary | std::ios::app);
  if (!out) return;
  out << "{\"ts_unix_ms\":" << now_unix_ms() << ",\"event\":\"" << json_escape(event) << "\",\"partner_id\":\""
      << json_escape(partner_id) << "\",\"sequence\":" << sequence << ",\"attempt\":" << attempt
      << ",\"success\":" << json_bool(success) << ",\"detail\":\"" << json_escape(detail) << "\"}\n";
}

void persist_explorer_snapshot(const Config& cfg) {
  if (cfg.cache_path.empty()) return;
  PersistedExplorerSnapshot snapshot;
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    snapshot = g_persisted_snapshot;
  }
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    (void)prune_partner_state_locked(cfg, now_unix_ms());
    snapshot.partner_withdrawals_by_client_id = g_partner_withdrawals_by_client_id;
    snapshot.partner_client_id_by_txid = g_partner_client_id_by_txid;
    snapshot.partner_idempotency_hash = g_partner_idempotency_hash;
    snapshot.partner_idempotency_client_id = g_partner_idempotency_client_id;
    snapshot.partner_idempotency_unix_ms = g_partner_idempotency_unix_ms;
    snapshot.partner_events = g_partner_events;
    snapshot.partner_next_sequence = g_partner_next_sequence;
    snapshot.seen_partner_nonce_unix_ms = g_seen_partner_nonce_unix_ms;
    snapshot.partner_webhook_queue = g_partner_webhook_queue;
    snapshot.partner_webhook_dlq = g_partner_webhook_dlq;
  }
  snapshot.stored_unix_ms = now_unix_ms();
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    g_persisted_snapshot = snapshot;
  }
  auto root = json_object_value();
  json_put(root, "version", static_cast<std::uint64_t>(1));
  json_put(root, "rpc_url", cfg.rpc_url);
  json_put(root, "stored_unix_ms", snapshot.stored_unix_ms);
  json_put(root, "status_refreshed_unix_ms", snapshot.status_refreshed_unix_ms);
  json_put(root, "committee_refreshed_unix_ms", snapshot.committee_refreshed_unix_ms);
  json_put(root, "recent_refreshed_unix_ms", snapshot.recent_refreshed_unix_ms);
  json_put(root, "committee_height", snapshot.committee_height);
  json_put(root, "recent_limit", static_cast<std::uint64_t>(snapshot.recent_limit));
  json_put(root, "recent_present", snapshot.recent_present);
  root.object_value["status_result"] = snapshot.status_result.has_value() ? *snapshot.status_result : json_null();
  root.object_value["committee_result"] = snapshot.committee_result.has_value() ? *snapshot.committee_result : json_null();
  root.object_value["recent_items"] = serialize_recent_tx_cache_array(snapshot.recent);
  auto tx_index = json_array_value();
  for (const auto& entry : snapshot.tx_index) tx_index.array_value.push_back(entry);
  root.object_value["tx_index"] = std::move(tx_index);
  auto transition_index = json_array_value();
  for (const auto& entry : snapshot.transition_index) transition_index.array_value.push_back(entry);
  root.object_value["transition_index"] = std::move(transition_index);
  auto partner_withdrawals = json_array_value();
  for (const auto& [key, w] : snapshot.partner_withdrawals_by_client_id) {
    auto item = json_object_value();
    json_put(item, "key", key);
    item.object_value["value"] = serialize_partner_withdrawal(w);
    partner_withdrawals.array_value.push_back(std::move(item));
  }
  root.object_value["partner_withdrawals_by_client_id"] = std::move(partner_withdrawals);
  root.object_value["partner_client_id_by_txid"] = serialize_string_map(snapshot.partner_client_id_by_txid);
  root.object_value["partner_idempotency_hash"] = serialize_string_map(snapshot.partner_idempotency_hash);
  root.object_value["partner_idempotency_client_id"] = serialize_string_map(snapshot.partner_idempotency_client_id);
  root.object_value["partner_idempotency_unix_ms"] = serialize_u64_map(snapshot.partner_idempotency_unix_ms, "unix_ms");
  auto partner_events = json_array_value();
  for (const auto& evt : snapshot.partner_events) partner_events.array_value.push_back(serialize_partner_event(evt));
  root.object_value["partner_events"] = std::move(partner_events);
  json_put(root, "partner_next_sequence", snapshot.partner_next_sequence);
  root.object_value["seen_partner_nonce_unix_ms"] = serialize_nonce_map(snapshot.seen_partner_nonce_unix_ms);
  auto partner_webhook_queue = json_array_value();
  for (const auto& job : snapshot.partner_webhook_queue) {
    partner_webhook_queue.array_value.push_back(serialize_partner_webhook_delivery(job));
  }
  root.object_value["partner_webhook_queue"] = std::move(partner_webhook_queue);
  auto partner_webhook_dlq = json_array_value();
  for (const auto& entry : snapshot.partner_webhook_dlq) {
    partner_webhook_dlq.array_value.push_back(serialize_partner_webhook_dlq_entry(entry));
  }
  root.object_value["partner_webhook_dlq"] = std::move(partner_webhook_dlq);

  const auto path = std::filesystem::path(cfg.cache_path);
  if (!path.parent_path().empty() && !finalis::ensure_private_dir(path.parent_path().string())) return;
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return;
  out << finalis::minijson::stringify(root);
}

void load_persisted_explorer_snapshot(const Config& cfg) {
  if (cfg.cache_path.empty()) return;
  std::ifstream in(cfg.cache_path, std::ios::binary);
  if (!in) return;
  std::stringstream buffer;
  buffer << in.rdbuf();
  const auto parsed = finalis::minijson::parse(buffer.str());
  if (!parsed || !parsed->is_object()) return;
  auto version = object_u64(&*parsed, "version");
  if (!version.has_value() || *version != 1) return;
  auto rpc_url = object_string(&*parsed, "rpc_url");
  if (!rpc_url.has_value() || *rpc_url != cfg.rpc_url) return;

  PersistedExplorerSnapshot loaded;
  loaded.stored_unix_ms = object_u64(&*parsed, "stored_unix_ms").value_or(0);
  loaded.status_refreshed_unix_ms = object_u64(&*parsed, "status_refreshed_unix_ms");
  loaded.committee_refreshed_unix_ms = object_u64(&*parsed, "committee_refreshed_unix_ms");
  loaded.recent_refreshed_unix_ms = object_u64(&*parsed, "recent_refreshed_unix_ms");
  loaded.committee_height = object_u64(&*parsed, "committee_height").value_or(0);
  if (auto recent_limit = object_u64(&*parsed, "recent_limit"); recent_limit.has_value()) {
    loaded.recent_limit = static_cast<std::size_t>(*recent_limit);
  }
  loaded.recent_present = object_bool(&*parsed, "recent_present").value_or(false);
  if (const auto* status = parsed->get("status_result"); status && status->is_object()) loaded.status_result = *status;
  if (const auto* committee = parsed->get("committee_result"); committee && committee->is_object()) loaded.committee_result = *committee;
  if (const auto* recent = parsed->get("recent_items"); recent && recent->is_array()) loaded.recent = parse_recent_tx_cache_array(*recent);
  if (const auto* tx_index = parsed->get("tx_index"); tx_index && tx_index->is_array()) {
    for (const auto& entry : tx_index->array_value) {
      if (entry.is_object()) loaded.tx_index.push_back(entry);
    }
  }
  if (const auto* transition_index = parsed->get("transition_index"); transition_index && transition_index->is_array()) {
    for (const auto& entry : transition_index->array_value) {
      if (entry.is_object()) loaded.transition_index.push_back(entry);
    }
  }
  if (const auto* partner_withdrawals = parsed->get("partner_withdrawals_by_client_id");
      partner_withdrawals && partner_withdrawals->is_array()) {
    for (const auto& item : partner_withdrawals->array_value) {
      if (!item.is_object()) continue;
      const auto key = object_string(&item, "key");
      const auto* value = item.get("value");
      if (!key.has_value() || key->empty() || !value) continue;
      const auto parsed_withdrawal = parse_partner_withdrawal(*value);
      if (!parsed_withdrawal.has_value()) continue;
      loaded.partner_withdrawals_by_client_id[*key] = *parsed_withdrawal;
    }
  }
  if (const auto* partner_client_by_txid = parsed->get("partner_client_id_by_txid"); partner_client_by_txid) {
    loaded.partner_client_id_by_txid = parse_string_map(*partner_client_by_txid);
  }
  if (const auto* partner_idempotency_hash = parsed->get("partner_idempotency_hash"); partner_idempotency_hash) {
    loaded.partner_idempotency_hash = parse_string_map(*partner_idempotency_hash);
  }
  if (const auto* partner_idempotency_client_id = parsed->get("partner_idempotency_client_id"); partner_idempotency_client_id) {
    loaded.partner_idempotency_client_id = parse_string_map(*partner_idempotency_client_id);
  }
  if (const auto* partner_idempotency_unix_ms = parsed->get("partner_idempotency_unix_ms"); partner_idempotency_unix_ms) {
    loaded.partner_idempotency_unix_ms = parse_u64_map(*partner_idempotency_unix_ms, "unix_ms");
  }
  if (const auto* partner_events = parsed->get("partner_events"); partner_events && partner_events->is_array()) {
    for (const auto& item : partner_events->array_value) {
      const auto parsed_event = parse_partner_event(item);
      if (parsed_event.has_value()) loaded.partner_events.push_back(*parsed_event);
    }
  }
  loaded.partner_next_sequence = object_u64(&*parsed, "partner_next_sequence").value_or(1);
  if (const auto* nonces = parsed->get("seen_partner_nonce_unix_ms"); nonces) {
    loaded.seen_partner_nonce_unix_ms = parse_nonce_map(*nonces);
  }
  if (const auto* webhook_queue = parsed->get("partner_webhook_queue"); webhook_queue && webhook_queue->is_array()) {
    for (const auto& item : webhook_queue->array_value) {
      const auto parsed_job = parse_partner_webhook_delivery(item);
      if (parsed_job.has_value()) loaded.partner_webhook_queue.push_back(*parsed_job);
    }
  }
  if (const auto* webhook_dlq = parsed->get("partner_webhook_dlq"); webhook_dlq && webhook_dlq->is_array()) {
    for (const auto& item : webhook_dlq->array_value) {
      const auto parsed_entry = parse_partner_webhook_dlq_entry(item);
      if (parsed_entry.has_value()) loaded.partner_webhook_dlq.push_back(*parsed_entry);
    }
  }

  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    g_persisted_snapshot = loaded;
  }
  bool partner_pruned = false;
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    g_partner_withdrawals_by_client_id = loaded.partner_withdrawals_by_client_id;
    g_partner_client_id_by_txid = loaded.partner_client_id_by_txid;
    g_partner_idempotency_hash = loaded.partner_idempotency_hash;
    g_partner_idempotency_client_id = loaded.partner_idempotency_client_id;
    g_partner_idempotency_unix_ms = loaded.partner_idempotency_unix_ms;
    g_partner_events = loaded.partner_events;
    g_partner_next_sequence = std::max<std::uint64_t>(1, loaded.partner_next_sequence);
    g_seen_partner_nonce_unix_ms = loaded.seen_partner_nonce_unix_ms;
    g_partner_webhook_queue = loaded.partner_webhook_queue;
    g_partner_webhook_dlq = loaded.partner_webhook_dlq;
    partner_pruned = prune_partner_state_locked(cfg, now_unix_ms());
  }
  if (partner_pruned) persist_explorer_snapshot(cfg);
  if (loaded.status_result.has_value()) {
    auto parsed_status = parse_status_result_object(*loaded.status_result);
    if (parsed_status.value.has_value()) {
      std::lock_guard<std::mutex> guard(g_status_cache_mu);
      g_status_cache = TimedCacheEntry<LookupResult<StatusResult>>{
          .key = cfg.rpc_url, .stored_at = std::chrono::steady_clock::now(), .value = parsed_status, .valid = true};
    }
  }
  if (loaded.committee_result.has_value()) {
    auto parsed_committee = parse_committee_result_object(*loaded.committee_result, loaded.committee_height);
    if (parsed_committee.value.has_value()) {
      std::lock_guard<std::mutex> guard(g_committee_cache_mu);
      g_committee_cache = TimedCacheEntry<LookupResult<CommitteeResult>>{
          .key = cfg.rpc_url + "#committee#" + std::to_string(loaded.committee_height),
          .stored_at = std::chrono::steady_clock::now(),
          .value = parsed_committee,
          .valid = true};
    }
  }
  if (loaded.recent_present) {
    std::lock_guard<std::mutex> guard(g_recent_tx_cache_mu);
    g_recent_tx_cache = TimedCacheEntry<std::vector<RecentTxResult>>{
        .key = cfg.rpc_url + "#recent#" + std::to_string(loaded.recent_limit),
        .stored_at = std::chrono::steady_clock::now(),
        .value = loaded.recent,
        .valid = true};
  }
}

bool rpc_not_found(const RpcCallResult& res) {
  return res.error_code.has_value() && *res.error_code == -32001;
}

ApiError upstream_error(const std::string& message) { return make_error(502, "upstream_error", message.empty() ? "upstream request failed" : message); }

ApiError not_found_error(const std::string& message = "not found in finalized state") {
  return make_error(404, "not_found", message);
}

std::string search_classification_name(SearchClassification c) {
  switch (c) {
    case SearchClassification::TransitionHeight:
      return "transition_height";
    case SearchClassification::Txid:
      return "txid";
    case SearchClassification::TransitionHash:
      return "transition_hash";
    case SearchClassification::Address:
      return "address";
    case SearchClassification::NotFound:
      return "not_found";
  }
  return "unknown";
}

std::optional<SearchClassification> classify_query(const std::string& query, const std::optional<std::uint64_t>& /*max_height*/) {
  if (is_digits(query)) {
    return SearchClassification::TransitionHeight;
  }
  if (finalis::address::decode(query).has_value()) return SearchClassification::Address;
  return std::nullopt;
}

std::map<std::string, std::string> parse_query_params(std::string_view query) {
  std::map<std::string, std::string> out;
  std::size_t pos = 0;
  while (pos < query.size()) {
    const auto amp = query.find('&', pos);
    const auto part = query.substr(pos, amp == std::string_view::npos ? query.size() - pos : amp - pos);
    const auto eq = part.find('=');
    const auto key = url_decode(part.substr(0, eq));
    const auto value = eq == std::string_view::npos ? std::string{} : url_decode(part.substr(eq + 1));
    if (!key.empty()) out[key] = value;
    if (amp == std::string_view::npos) break;
    pos = amp + 1;
  }
  return out;
}

std::string link_tx(const std::string& txid) {
  return "<a href=\"/tx/" + txid + "\"><code>" + html_escape(short_hex(txid)) + "</code></a>";
}

std::string link_transition_height(std::uint64_t height) {
  return "<a href=\"/transition/" + std::to_string(height) + "\"><code>" + std::to_string(height) + "</code></a>";
}

LookupResult<StatusResult> fetch_status_result(const Config& cfg);
LookupResult<TxResult> fetch_tx_result(const Config& cfg, const std::string& txid_hex);
LookupResult<TransitionResult> fetch_transition_result(const Config& cfg, const std::string& ident);
LookupResult<AddressResult> fetch_address_result(const Config& cfg, const std::string& addr,
                                                 std::optional<std::uint64_t> start_after_height = std::nullopt,
                                                 std::optional<std::string> start_after_txid = std::nullopt);
LookupResult<SearchResult> fetch_search_result(const Config& cfg, const std::string& query);
std::vector<RecentTxResult> fetch_recent_tx_results(const Config& cfg, std::size_t max_items);
LookupResult<CommitteeResult> fetch_committee_result(const Config& cfg, std::uint64_t height);
std::map<std::string, TxSummaryBatchItem> fetch_tx_summary_batch(const Config& cfg, const std::vector<std::string>& txids);

std::string render_status_json(const StatusResult& result, std::optional<std::uint64_t> refreshed_unix_ms = std::nullopt);
std::string render_tx_json(const TxResult& result);
std::string render_transition_json(const Config& cfg, const TransitionResult& result);
std::string render_address_json(const AddressResult& result);
std::string render_search_json(const SearchResult& result);
std::string render_committee_json(const CommitteeResult& result, std::optional<std::uint64_t> refreshed_unix_ms = std::nullopt);
std::string render_recent_tx_json(const std::vector<RecentTxResult>& items, std::optional<std::uint64_t> refreshed_unix_ms = std::nullopt);

std::string render_root(const Config& cfg) {
  std::ostringstream body;
  auto status = fetch_status_result(cfg);
  const auto status_refreshed_unix_ms = persisted_status_refreshed_unix_ms();
  const auto recent = fetch_recent_tx_results(cfg, 8);
  const auto recent_refreshed_unix_ms = persisted_recent_refreshed_unix_ms();
  body << build_surface_stale_banner();
  body << "<div class=\"card hero-card\"><h1>Finalis Explorer</h1>"
       << "<div class=\"note\">Finalized-state explorer for operators, wallets, and exchanges. It intentionally shows only finalized chain state and hides mempool ambiguity.</div>";
  if (status.value.has_value()) {
    body << "<div class=\"hero-metrics\">"
         << "<div class=\"metric-card\"><span class=\"label\">Finalized Tip</span><span class=\"value\">" << status.value->finalized_height
         << "</span><span class=\"sub\">" << html_escape(short_hex(status.value->finalized_transition_hash)) << "</span></div>"
         << "<div class=\"metric-card\"><span class=\"label\">Protocol Reserve</span><span class=\"value\">"
         << html_escape(status.value->protocol_reserve_balance.has_value() ? format_amount(*status.value->protocol_reserve_balance) : std::string("n/a"))
         << "</span><span class=\"sub\">Reserved by protocol issuance for long-horizon monetary rules.</span></div>"
         << "<div class=\"metric-card\"><span class=\"label\">Peers</span><span class=\"value\">" << status.value->healthy_peer_count
         << "</span><span class=\"sub\">healthy, " << status.value->established_peer_count << " established</span></div>"
         << "<div class=\"metric-card\"><span class=\"label\">Sync</span><span class=\"value\">"
         << (status.value->finalized_lag.has_value() ? std::to_string(*status.value->finalized_lag) : std::string("n/a"))
         << "</span><span class=\"sub\">finalized lag</span></div>"
         << "</div>";
  }
  body << "</div>";
  body << "<div class=\"card\"><h2>Search</h2><form method=\"GET\" action=\"/search\">"
       << "<input type=\"text\" name=\"q\" placeholder=\"txid, transition height/hash, or address\" "
       << "style=\"width:min(100%,720px);padding:10px 12px;font:inherit;border:1px solid #cfcfc6;border-radius:8px;\"> "
       << "<button type=\"submit\" class=\"copy-button\">Search</button></form></div>";
  body << "<div class=\"card\"><div class=\"status-hero\"><div><h2>Backend</h2></div>";
  body << "</div><div class=\"grid\">";
  body << "<div>Lightserver RPC</div><div class=\"value-cell\">" << mono_value(cfg.rpc_url) << "</div>";
  if (status.value.has_value()) {
    body << "<div>Runtime Status</div><div>" << status_chip(sync_summary_text(*status.value), tone_for_sync(*status.value)) << " "
         << fallback_chip(*status.value) << " " << operator_chip(*status.value) << "</div>"
         << "<div>Status Snapshot Refreshed</div><div>" << html_escape(explorer_snapshot_freshness_text(status_refreshed_unix_ms)) << "</div>"
         << "<div>Network</div><div>" << html_escape(status.value->network) << "</div>"
         << "<div>Finalized Tip</div><div class=\"value-cell\">" << link_transition_height(status.value->finalized_height) << " <code>" << html_escape(short_hex(status.value->finalized_transition_hash))
         << "</code> " << finalized_badge(true) << "</div>"
         << "<div>Version</div><div>" << html_escape(status.value->backend_version) << "</div>"
         << "<div>Peers</div><div>healthy=" << status.value->healthy_peer_count << ", established=" << status.value->established_peer_count << "</div>"
         << "<div>Finality Committee</div><div>size=" << status.value->latest_finality_committee_size
         << ", quorum=" << status.value->latest_finality_quorum_threshold << "</div>";
  } else {
    body << "<div>Status</div><div class=\"muted\">Unavailable: " << html_escape(status.error->message) << "</div>";
  }
  body << "</div>";
  if (status.value.has_value()) {
    body << "<details class=\"disclosure\"><summary>Show backend internals</summary><div class=\"grid\">"
         << "<div>Network ID</div><div class=\"value-cell\">" << mono_value(status.value->network_id) << "</div>"
         << "<div>Genesis Hash</div><div class=\"value-cell\">" << mono_value(status.value->genesis_hash) << "</div>"
         << "<div>Wallet API</div><div>" << html_escape(status.value->wallet_api_version) << "</div>"
         << "<div>Sync Detail</div><div>" << html_escape(sync_summary_text(*status.value)) << "</div>"
         << "</div></details>";
  }
  body << "</div>";
  if (status.value.has_value()) {
    body << "<div class=\"card\"><h2>Operator View</h2>"
         << "<div class=\"note\">The homepage stays focused on finalized chain state and recent activity. Committee composition, Ticket PoW, and availability mechanics live on the dedicated committee page.</div>"
         << "<div class=\"summary-actions\">"
         << "<a class=\"copy-button\" href=\"/committee\">Open Committee View</a>"
         << "<a class=\"copy-button\" href=\"/api/committee\">Open Committee API</a>"
         << copy_action("Copy Status API Path", "/api/status")
         << "</div></div>";
  }
  body << "<div class=\"card\"><h2>Finalized Transactions</h2>";
  if (!recent.empty()) {
    body << "<div class=\"note\">Recent finalized on-chain activity from the latest finalized transitions. Flow labels are explorer heuristics derived from finalized inputs and outputs, not wallet ownership proofs.</div>"
         << "<div class=\"note\">Recent transactions snapshot refreshed from RPC: "
         << html_escape(explorer_snapshot_freshness_text(recent_refreshed_unix_ms)) << "</div>";
    body << "<div class=\"table-wrap\"><table><thead><tr><th>Txid</th><th>Height</th><th>When</th><th>Flow</th><th>From</th><th>To</th><th>Finalized Out</th><th>Fee</th><th>Status</th><th>Shape</th></tr></thead><tbody>";
    for (const auto& item : recent) {
      body << "<tr><td>" << link_tx(item.txid) << "</td><td>"
           << (item.height.has_value() ? link_transition_height(*item.height) : std::string("<span class=\"muted\">n/a</span>"))
           << "</td><td>"
           << (item.timestamp.has_value() ? html_escape(format_timestamp(*item.timestamp)) : std::string("<span class=\"muted\">n/a</span>"))
           << "</td><td>";
      if (item.flow_kind.has_value()) {
        body << "<strong>" << html_escape(*item.flow_kind) << "</strong>";
        if (item.flow_summary.has_value()) body << "<div class=\"muted\">" << html_escape(*item.flow_summary) << "</div>";
      } else {
        body << "<span class=\"muted\">n/a</span>";
      }
      body << "</td><td>" << display_identity(item.primary_sender) << "</td><td>";
      if (item.primary_recipient.has_value()) {
        body << display_identity(item.primary_recipient);
        if (item.recipient_count.has_value() && *item.recipient_count > 1) {
          body << " <span class=\"muted\">+" << (*item.recipient_count - 1) << " more</span>";
        }
      } else {
        body << "<span class=\"muted\">unknown</span>";
      }
      body << "</td><td class=\"num\">"
           << (item.total_out.has_value() ? html_escape(format_amount(*item.total_out)) : std::string("<span class=\"muted\">n/a</span>"))
           << "</td><td class=\"num\">"
           << (item.fee.has_value() ? html_escape(format_amount(*item.fee)) : std::string("<span class=\"muted\">n/a</span>"))
           << "</td><td>";
      if (item.status_label.has_value()) body << html_escape(*item.status_label);
      else body << "<span class=\"muted\">n/a</span>";
      if (item.credit_safe.has_value()) body << "<div class=\"muted\">credit safe: " << credit_safe_text(*item.credit_safe) << "</div>";
      body << "</td><td>";
      if (item.input_count.has_value() && item.output_count.has_value()) {
        body << *item.input_count << " in / " << *item.output_count << " out";
      } else {
        body << "<span class=\"muted\">n/a</span>";
      }
      body << "</td></tr>";
    }
    body << "</tbody></table></div>";
  } else {
    body << "<div class=\"soft-empty\">No finalized transactions were found in the recent finalized-height scan window. This usually means the latest finalized transitions carried no user transactions, not that explorer indexing is broken.</div>"
         << "<div class=\"note\">Recent transactions snapshot refreshed from RPC: "
         << html_escape(explorer_snapshot_freshness_text(recent_refreshed_unix_ms)) << "</div>";
  }
  body << "</div>";
  body << "<div class=\"card\"><h2>Routes</h2><ul>"
       << "<li><code>/tx/&lt;txid&gt;</code></li>"
       << "<li><code>/transition/&lt;height&gt;</code> or <code>/transition/&lt;hash&gt;</code></li>"
       << "<li><code>/address/&lt;address&gt;</code></li>"
       << "<li><code>/committee</code></li>"
       << "</ul></div>";
  return page_layout("Finalis Explorer", body.str(), "overview");
}

std::string render_committee(const Config& cfg) {
  std::ostringstream body;
  body << "<h1>Committee</h1>";
  auto status = fetch_status_result(cfg);
  if (!status.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Status unavailable: "
         << html_escape(status.error ? status.error->message : "unknown error") << "</div></div>";
    return page_layout("Committee", body.str(), "committee");
  }
  auto committee = fetch_committee_result(cfg, status.value->finalized_height);
  const auto committee_refreshed_unix_ms = persisted_committee_refreshed_unix_ms();
  if (!committee.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Committee unavailable: "
         << html_escape(committee.error ? committee.error->message : "unknown error") << "</div></div>";
    return page_layout("Committee", body.str(), "committee");
  }
  body << "<div class=\"card\"><div class=\"hero-metrics\">"
       << render_summary_metric_card("Committee Size", std::to_string(committee.value->members.size()), "finalized operator set")
       << render_summary_metric_card("Quorum", std::to_string(status.value->latest_finality_quorum_threshold), "votes required for finality")
       << render_summary_metric_card("Epoch Start", std::to_string(committee.value->epoch_start_height), "current finalized committee epoch")
       << render_summary_metric_card("Checkpoint Mode", committee.value->checkpoint_derivation_mode.value_or("n/a"),
                                     committee.value->checkpoint_fallback_reason.value_or("no fallback"))
       << "</div></div>";
  body << "<div class=\"card\"><div class=\"note\">Committee snapshot refreshed from RPC: "
       << html_escape(explorer_snapshot_freshness_text(committee_refreshed_unix_ms))
       << "</div></div>";
  body << "<div class=\"card\"><h2>" << html_escape(ticket_pow_title(*status.value)) << "</h2><div class=\"grid\">"
       << "<div>Difficulty</div><div>" << status.value->ticket_pow_difficulty << " <span class=\"muted\">(range "
       << status.value->ticket_pow_difficulty_min << "&ndash;" << status.value->ticket_pow_difficulty_max << ")</span></div>"
       << "<div>Epoch Health</div><div>" << html_escape(title_case_health(status.value->ticket_pow_epoch_health)) << "</div>"
       << "<div>Adjustment</div><div>" << html_escape(ticket_pow_adjustment_text(*status.value)) << "</div>"
       << "<div>Streak</div><div>up=" << status.value->ticket_pow_streak_up << ", down=" << status.value->ticket_pow_streak_down << "</div>"
       << "<div>Nonce Budget</div><div>" << status.value->ticket_pow_nonce_search_limit << "</div>"
       << "<div>Bonus Cap</div><div>" << status.value->ticket_pow_bonus_cap_bps << " bps</div>"
       << "</div><div class=\"summary-actions\">"
       << copy_action("Copy Page Path", "/committee")
       << copy_action("Copy API Path", "/api/committee")
       << "</div></div>";
  body << "<div class=\"card\"><div class=\"note\">" << html_escape(ticket_pow_note(*status.value))
       << " Finality remains BFT/quorum-based."
       << " This page is a finalized committee snapshot, not a live mempool or proposal view."
       << "</div></div>"
       << "<div class=\"card\"><div class=\"grid\">"
       << "<div>Finalized Height</div><div>" << link_transition_height(status.value->finalized_height) << "</div>"
       << "<div>Finalized Transition</div><div class=\"value-cell\">" << mono_value(status.value->finalized_transition_hash) << "</div>"
       << "<div>Epoch Start</div><div>" << committee.value->epoch_start_height << "</div>"
       << "<div>Committee Size</div><div>" << committee.value->members.size() << "</div>"
       << "<div>Finality Quorum</div><div>" << status.value->latest_finality_quorum_threshold << "</div>"
       << "<div>Checkpoint Mode</div><div>" << html_escape(committee.value->checkpoint_derivation_mode.value_or("n/a"))
       << "</div>"
       << "<div>Checkpoint Fallback Reason</div><div>" << html_escape(committee.value->checkpoint_fallback_reason.value_or("n/a"))
       << "</div>"
       << "<div>Sticky Fallback</div><div>"
       << (committee.value->fallback_sticky.has_value() ? yes_no(*committee.value->fallback_sticky) : std::string("n/a"))
       << "</div>"
       << "<div>Qualified Operator Depth</div><div>"
       << (committee.value->qualified_depth.has_value() ? std::to_string(*committee.value->qualified_depth)
                                                        : std::string("n/a"))
       << "</div>"
       << "<div>Adaptive Committee Target</div><div>"
       << (committee.value->adaptive_target_committee_size.has_value()
               ? std::to_string(*committee.value->adaptive_target_committee_size)
               : std::string("n/a"))
       << "</div>"
       << "<div>Adaptive Eligible Threshold</div><div>"
       << (committee.value->adaptive_min_eligible.has_value() ? std::to_string(*committee.value->adaptive_min_eligible)
                                                              : std::string("n/a"))
       << "</div>"
       << "<div>Adaptive Bond Floor</div><div>"
       << (committee.value->adaptive_min_bond.has_value() ? format_amount(*committee.value->adaptive_min_bond)
                                                          : std::string("n/a"))
       << "</div>"
       << "<div>Eligibility Slack</div><div>"
       << (committee.value->adaptive_slack.has_value() ? std::to_string(*committee.value->adaptive_slack)
                                                       : std::string("n/a"))
       << "</div>"
       << "</div></div>";
  body << "<div class=\"card\"><h2>Selected Operators</h2><div class=\"table-wrap\"><table><thead><tr><th>Operator</th><th>ID Source</th><th>Representative</th><th class=\"num\">Base Weight</th><th class=\"num\">Ticket Bonus</th><th class=\"num\">Bonus %</th><th class=\"num\">Final Weight</th><th>Weight Composition</th><th>Ticket</th></tr></thead><tbody>";
  for (const auto& member : committee.value->members) {
    const std::string operator_value = member.resolved_operator_id;
    body << "<tr><td class=\"value-cell\"><div class=\"inline-actions\"><code>" << html_escape(short_hex(operator_value))
         << "</code>" << inline_copy_action("Copy", operator_value) << "</div></td><td class=\"value-cell\"><div class=\"inline-actions\"><code>"
         << html_escape(member.operator_id_source) << "</code></div></td><td class=\"value-cell\"><div class=\"inline-actions\"><code>"
         << html_escape(short_hex(member.representative_pubkey)) << "</code>" << inline_copy_action("Copy", member.representative_pubkey)
         << "</div></td><td class=\"num\">";
    if (member.base_weight.has_value()) body << *member.base_weight;
    else body << "<span class=\"muted\">n/a</span>";
    body << "</td><td class=\"num\">";
    if (member.ticket_bonus_bps.has_value()) body << *member.ticket_bonus_bps << " bps";
    else body << "<span class=\"muted\">n/a</span>";
    body << "</td><td class=\"num\">";
    if (member.ticket_bonus_bps.has_value()) body << html_escape(format_bonus_percent(*member.ticket_bonus_bps));
    else body << "<span class=\"muted\">n/a</span>";
    body << "</td><td class=\"num\">";
    if (member.final_weight.has_value()) body << *member.final_weight;
    else body << "<span class=\"muted\">n/a</span>";
    body << "</td><td>" << weight_composition(member.base_weight, member.ticket_bonus_bps, member.final_weight)
         << "</td><td class=\"value-cell\">";
    if (member.ticket_hash.has_value()) {
      body << "<code>" << html_escape(short_hex(*member.ticket_hash)) << "</code>";
      if (member.ticket_nonce.has_value()) body << " <span class=\"muted\">nonce " << *member.ticket_nonce << "</span>";
    } else {
      body << "<span class=\"muted\">n/a</span>";
    }
    body << "</td></tr>";
  }
  if (committee.value->members.empty()) {
    body << "<tr><td colspan=\"9\" class=\"muted\">No finalized committee members available.</td></tr>";
  }
  body << "</tbody></table></div></div>";
  return page_layout("Committee", body.str(), "committee");
}

std::optional<finalis::FrontierTransition> fetch_transition_by_height(const Config& cfg, std::uint64_t height,
                                                                      std::string* transition_hash_hex, std::string* err) {
  auto res = rpc_call(cfg.rpc_url, "get_transition_by_height", std::string("{\"height\":") + std::to_string(height) + "}");
  if (!res.result.has_value() || !res.result->is_object()) {
    if (err) {
      if (rpc_not_found(res)) *err = "not_found";
      else *err = res.error.empty() ? "upstream_error" : res.error;
    }
    return std::nullopt;
  }
  const auto hash = object_string(&*res.result, "transition_hash").value_or("");
  const auto transition_hex = object_string(&*res.result, "transition_hex").value_or("");
  if (hash.empty() || transition_hex.empty()) {
    if (err) *err = "missing transition fields";
    return std::nullopt;
  }
  auto bytes = finalis::hex_decode(transition_hex);
  if (!bytes) {
    if (err) *err = "bad transition hex";
    return std::nullopt;
  }
  auto transition = finalis::FrontierTransition::parse(*bytes);
  if (!transition.has_value()) {
    if (err) *err = "transition parse failed";
    return std::nullopt;
  }
  if (transition_hash_hex) *transition_hash_hex = hash;
  return transition;
}

std::optional<finalis::FrontierTransition> fetch_transition_by_hash(const Config& cfg, const std::string& hash_hex, std::string* err) {
  auto res = rpc_call(cfg.rpc_url, "get_transition", std::string("{\"hash\":\"") + json_escape(hash_hex) + "\"}");
  if (!res.result.has_value() || !res.result->is_object()) {
    if (err) {
      if (rpc_not_found(res)) *err = "not_found";
      else *err = res.error.empty() ? "upstream_error" : res.error;
    }
    return std::nullopt;
  }
  const auto transition_hex = object_string(&*res.result, "transition_hex").value_or("");
  if (transition_hex.empty()) {
    if (err) *err = "missing transition_hex";
    return std::nullopt;
  }
  auto bytes = finalis::hex_decode(transition_hex);
  if (!bytes) {
    if (err) *err = "bad transition hex";
    return std::nullopt;
  }
  auto transition = finalis::FrontierTransition::parse(*bytes);
  if (!transition.has_value()) {
    if (err) *err = "transition parse failed";
    return std::nullopt;
  }
  return transition;
}

std::vector<std::string> fetch_transition_txids(const Config& cfg, const finalis::FrontierTransition& transition) {
  std::vector<std::string> txids;
  if (transition.next_frontier < transition.prev_frontier) return txids;
  txids.reserve(static_cast<std::size_t>(transition.next_frontier - transition.prev_frontier));
  for (std::uint64_t seq = transition.prev_frontier + 1; seq <= transition.next_frontier; ++seq) {
    auto rpc = rpc_call(cfg.rpc_url, "get_ingress_record", std::string("{\"seq\":") + std::to_string(seq) + "}");
    if (!rpc.result.has_value() || !rpc.result->is_object()) continue;
    const auto present = object_bool(&*rpc.result, "present").value_or(false);
    if (!present) continue;
    auto txid = object_string(&*rpc.result, "txid");
    if (!txid.has_value() || !is_hex64(*txid)) continue;
    txids.push_back(*txid);
  }
  return txids;
}

LookupResult<StatusResult> fetch_status_result(const Config& cfg) {
  {
    std::lock_guard<std::mutex> guard(g_status_cache_mu);
    if (g_status_cache.valid && g_status_cache.key == cfg.rpc_url &&
        (std::chrono::steady_clock::now() - g_status_cache.stored_at) < std::chrono::seconds(2)) {
      return g_status_cache.value;
    }
  }

  LookupResult<StatusResult> out;
  auto status = rpc_call(cfg.rpc_url, "get_status", "{}");
  if (!status.result.has_value() || !status.result->is_object()) {
    const auto err = upstream_error(status.error.empty() ? "status unavailable" : status.error);
    if (auto cached = persisted_status_result_lookup(); cached.has_value() && cached->value.has_value()) {
      out = *cached;
      {
        std::lock_guard<std::mutex> guard(g_surface_state_mu);
        set_surface_state(g_status_surface_state, err.message, true);
      }
    } else {
      out.error = err;
      {
        std::lock_guard<std::mutex> guard(g_surface_state_mu);
        set_surface_state(g_status_surface_state, err.message, false);
      }
    }
  } else {
    out = parse_status_result_object(*status.result);
    if (out.value.has_value()) {
      const auto refreshed_unix_ms = now_unix_ms();
      {
        std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
        g_persisted_snapshot.status_refreshed_unix_ms = refreshed_unix_ms;
        g_persisted_snapshot.status_result = *status.result;
      }
      persist_explorer_snapshot(cfg);
    }
    {
      std::lock_guard<std::mutex> guard(g_surface_state_mu);
      set_surface_state(g_status_surface_state, std::nullopt, false);
    }
  }
  {
    std::lock_guard<std::mutex> guard(g_status_cache_mu);
    g_status_cache = TimedCacheEntry<LookupResult<StatusResult>>{
        .key = cfg.rpc_url, .stored_at = std::chrono::steady_clock::now(), .value = out, .valid = true};
  }
  return out;
}

LookupResult<CommitteeResult> fetch_committee_result(const Config& cfg, std::uint64_t height) {
  const std::string cache_key = cfg.rpc_url + "#committee#" + std::to_string(height);
  {
    std::lock_guard<std::mutex> guard(g_committee_cache_mu);
    if (g_committee_cache.valid && g_committee_cache.key == cache_key &&
        (std::chrono::steady_clock::now() - g_committee_cache.stored_at) < std::chrono::seconds(5)) {
      return g_committee_cache.value;
    }
  }

  LookupResult<CommitteeResult> out;
  auto rpc = rpc_call(cfg.rpc_url, "get_committee",
                      std::string("{\"height\":") + std::to_string(height) + ",\"verbose\":true}");
  if (!rpc.result.has_value() || !rpc.result->is_object()) {
    const auto err = rpc_not_found(rpc) ? not_found_error("committee unavailable in finalized state")
                                        : upstream_error(rpc.error.empty() ? "committee unavailable" : rpc.error);
    if (auto cached = persisted_committee_result_lookup(height); cached.has_value() && cached->value.has_value()) {
      out = *cached;
      {
        std::lock_guard<std::mutex> guard(g_surface_state_mu);
        set_surface_state(g_committee_surface_state, err.message, true);
      }
    } else {
      out.error = err;
      {
        std::lock_guard<std::mutex> guard(g_surface_state_mu);
        set_surface_state(g_committee_surface_state, err.message, false);
      }
    }
  } else {
    out = parse_committee_result_object(*rpc.result, height);
    if (out.value.has_value()) {
      const auto refreshed_unix_ms = now_unix_ms();
      {
        std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
        g_persisted_snapshot.committee_refreshed_unix_ms = refreshed_unix_ms;
        g_persisted_snapshot.committee_height = height;
        g_persisted_snapshot.committee_result = *rpc.result;
      }
      persist_explorer_snapshot(cfg);
    }
    {
      std::lock_guard<std::mutex> guard(g_surface_state_mu);
      set_surface_state(g_committee_surface_state, std::nullopt, false);
    }
  }

  {
    std::lock_guard<std::mutex> guard(g_committee_cache_mu);
    g_committee_cache = TimedCacheEntry<LookupResult<CommitteeResult>>{
        .key = cache_key, .stored_at = std::chrono::steady_clock::now(), .value = out, .valid = true};
  }
  return out;
}

LookupResult<TransitionResult> fetch_transition_result(const Config& cfg, const std::string& ident) {
  LookupResult<TransitionResult> out;
  if (is_digits(ident)) {
    try {
      const auto height = static_cast<std::uint64_t>(std::stoull(ident));
      if (auto cached = find_persisted_transition_result_by_height(height); cached.has_value()) {
        cached->data_source = "cache_finalized_snapshot";
        out.value = std::move(*cached);
        return out;
      }
      std::string err;
      std::string transition_hash_hex;
      auto blk = fetch_transition_by_height(cfg, height, &transition_hash_hex, &err);
      if (!blk.has_value()) {
        out.error = err == "not_found" ? not_found_error() : upstream_error(err);
        return out;
      }
      TransitionResult result;
      result.found = true;
      result.height = blk->height;
      result.hash = transition_hash_hex;
      result.prev_finalized_hash = finalis::hex_encode32(blk->prev_finalized_hash);
      result.round = blk->round;
      result.tx_count = blk->next_frontier >= blk->prev_frontier
                            ? static_cast<std::size_t>(blk->next_frontier - blk->prev_frontier)
                            : 0;
      result.txids = fetch_transition_txids(cfg, *blk);
      const auto summary = compute_transition_summary(cfg, result);
      result.summary_cached = true;
      result.cached_summary_finalized_out = summary.finalized_out;
      result.cached_summary_distinct_recipient_count = summary.distinct_recipient_count;
      result.cached_summary_flow_mix = summary.flow_mix;
      result.data_source = "rpc_live_finalized";
      upsert_persisted_transition_result(cfg, result);
      out.value = std::move(result);
      return out;
    } catch (...) {
      out.error = make_error(400, "invalid_transition_id", "malformed transition id");
      return out;
    }
  } else if (is_hex64(ident)) {
    if (auto cached = find_persisted_transition_result_by_hash(ident); cached.has_value()) {
      cached->data_source = "cache_finalized_snapshot";
      out.value = std::move(*cached);
      return out;
    }
    auto rpc = rpc_call(cfg.rpc_url, "get_transition", std::string("{\"hash\":\"") + json_escape(ident) + "\"}");
    if (!rpc.result.has_value()) {
      out.error = rpc_not_found(rpc) ? not_found_error() : upstream_error(rpc.error);
      return out;
    }
    std::string err;
    auto blk = fetch_transition_by_hash(cfg, ident, &err);
    if (!blk.has_value()) {
      out.error = err == "not_found" ? not_found_error() : upstream_error(err);
      return out;
    }
    TransitionResult result;
    result.found = true;
    result.height = blk->height;
    result.hash = finalis::hex_encode32(blk->transition_id());
    result.prev_finalized_hash = finalis::hex_encode32(blk->prev_finalized_hash);
    result.round = blk->round;
    result.tx_count = blk->next_frontier >= blk->prev_frontier
                          ? static_cast<std::size_t>(blk->next_frontier - blk->prev_frontier)
                          : 0;
    result.txids = fetch_transition_txids(cfg, *blk);
    const auto summary = compute_transition_summary(cfg, result);
    result.summary_cached = true;
    result.cached_summary_finalized_out = summary.finalized_out;
    result.cached_summary_distinct_recipient_count = summary.distinct_recipient_count;
    result.cached_summary_flow_mix = summary.flow_mix;
    result.data_source = "rpc_live_finalized";
    upsert_persisted_transition_result(cfg, result);
    out.value = std::move(result);
    return out;
  } else {
      out.error = make_error(400, "invalid_transition_id", "malformed transition id");
    return out;
  }
}

LookupResult<TxResult> fetch_tx_result(const Config& cfg, const std::string& txid_hex) {
  LookupResult<TxResult> out;
  if (!is_hex64(txid_hex)) {
    out.error = make_error(400, "invalid_txid", "malformed txid");
    return out;
  }
  if (auto cached = find_persisted_tx_result(txid_hex); cached.has_value()) {
    cached->data_source = "cache_finalized_snapshot";
    out.value = std::move(*cached);
    return out;
  }

  auto status_call = rpc_call(cfg.rpc_url, "get_tx_status", std::string("{\"txid\":\"") + txid_hex + "\"}");
  if (!status_call.result.has_value() || !status_call.result->is_object()) {
    out.error = upstream_error(status_call.error.empty() ? "tx status unavailable" : status_call.error);
    return out;
  }
  const auto& status = *status_call.result;
  const auto status_text = object_string(&status, "status").value_or("unknown");
  const bool finalized = object_bool(&status, "finalized").value_or(false);
  if (!finalized) {
    out.error = not_found_error();
    return out;
  }

  TxResult result;
  result.txid = txid_hex;
  result.found = true;
  result.finalized = true;
  result.finalized_height = object_u64(&status, "height");
  result.finalized_depth = object_u64(&status, "finalized_depth").value_or(0);
  result.credit_safe = object_bool(&status, "credit_safe").value_or(false);
  result.status_label = tx_status_label(result.finalized, result.credit_safe);
  result.transition_hash = object_string(&status, "transition_hash").value_or("");

  auto tx_call = rpc_call(cfg.rpc_url, "get_tx", std::string("{\"txid\":\"") + txid_hex + "\"}");
  if (!tx_call.result.has_value() || !tx_call.result->is_object()) {
    out.error = rpc_not_found(tx_call) ? not_found_error() : upstream_error(tx_call.error.empty() ? "tx lookup unavailable" : tx_call.error);
    return out;
  }
  auto tx_hex = object_string(&*tx_call.result, "tx_hex");
  if (!tx_hex) {
    out.error = upstream_error("missing tx_hex");
    return out;
  }
  auto tx_bytes = finalis::hex_decode(*tx_hex);
  auto tx = tx_bytes ? finalis::parse_any_tx(*tx_bytes) : std::nullopt;
  if (!tx.has_value() || !std::holds_alternative<finalis::Tx>(*tx)) {
    out.error = upstream_error("tx parse failed");
    return out;
  }
  const auto& tx_v1 = std::get<finalis::Tx>(*tx);
  std::map<std::string, finalis::Tx> prev_tx_cache;
  auto fetch_prev_tx = [&](const Hash32& prev_txid) -> std::optional<std::reference_wrapper<const finalis::Tx>> {
    const std::string prev_txid_hex = finalis::hex_encode32(prev_txid);
    auto it = prev_tx_cache.find(prev_txid_hex);
    if (it != prev_tx_cache.end()) return std::cref(it->second);

    auto prev_call = rpc_call(cfg.rpc_url, "get_tx", std::string("{\"txid\":\"") + prev_txid_hex + "\"}");
    if (!prev_call.result.has_value() || !prev_call.result->is_object()) return std::nullopt;
    auto prev_hex = object_string(&*prev_call.result, "tx_hex");
    if (!prev_hex) return std::nullopt;
    auto prev_bytes = finalis::hex_decode(*prev_hex);
    auto prev_tx = prev_bytes ? finalis::parse_any_tx(*prev_bytes) : std::nullopt;
    if (!prev_tx.has_value() || !std::holds_alternative<finalis::Tx>(*prev_tx)) return std::nullopt;
    auto inserted = prev_tx_cache.emplace(prev_txid_hex, std::get<finalis::Tx>(*prev_tx));
    return std::cref(inserted.first->second);
  };

  std::string network_name = "mainnet";
  if (auto st = fetch_status_result(cfg); st.value.has_value()) network_name = st.value->network;
  const std::string hrp = hrp_for_network_name(network_name);

  std::uint64_t total_in = 0;
  bool fee_known = true;
  for (const auto& in : tx_v1.inputs) {
    TxInputResult input_view{finalis::hex_encode32(in.prev_txid), in.prev_index, std::nullopt, std::nullopt};
    auto prev_tx_opt = fetch_prev_tx(in.prev_txid);
    if (!prev_tx_opt.has_value()) {
      result.inputs.push_back(std::move(input_view));
      fee_known = false;
      continue;
    }
    const auto& prev_tx_v1 = prev_tx_opt->get();
    if (in.prev_index >= prev_tx_v1.outputs.size()) {
      result.inputs.push_back(std::move(input_view));
      fee_known = false;
      continue;
    }
    total_in += prev_tx_v1.outputs[in.prev_index].value;
    input_view.address = script_to_address(prev_tx_v1.outputs[in.prev_index].script_pubkey, hrp);
    input_view.amount = prev_tx_v1.outputs[in.prev_index].value;
    result.inputs.push_back(std::move(input_view));
  }

  for (const auto& tx_out : tx_v1.outputs) {
    result.total_out += tx_out.value;
    result.outputs.push_back(TxOutputResult{
        tx_out.value,
        script_to_address(tx_out.script_pubkey, hrp),
        finalis::hex_encode(tx_out.script_pubkey),
        std::nullopt,
        std::nullopt,
        std::nullopt,
        false,
        std::nullopt,
        std::nullopt,
    });
  }
  if (const auto* decoded_outputs = tx_call.result->get("decoded_outputs"); decoded_outputs && decoded_outputs->is_array()) {
    const auto limit = std::min(decoded_outputs->array_value.size(), result.outputs.size());
    for (std::size_t i = 0; i < limit; ++i) {
      const auto& item = decoded_outputs->array_value[i];
      if (!item.is_object()) continue;
      result.outputs[i].decoded_kind = object_string(&item, "decoded_kind");
      result.outputs[i].validator_pubkey_hex = object_string(&item, "validator_pubkey_hex");
      result.outputs[i].payout_pubkey_hex = object_string(&item, "payout_pubkey_hex");
      result.outputs[i].has_admission_pow = object_bool(&item, "has_admission_pow").value_or(false);
      result.outputs[i].admission_pow_epoch = object_u64(&item, "admission_pow_epoch");
      result.outputs[i].admission_pow_nonce = object_u64(&item, "admission_pow_nonce");
      if (auto addr = object_string(&item, "address"); addr.has_value()) result.outputs[i].address = *addr;
    }
  }
  if (fee_known && total_in >= result.total_out) result.fee = total_in - result.total_out;
  const auto flow = classify_tx_flow(result.inputs, result.outputs);
  result.flow_kind = flow.kind;
  result.flow_summary = flow.summary;
  result.primary_sender = flow.primary_sender;
  result.primary_recipient = flow.primary_recipient;
  result.participant_count = flow.participant_count;
  result.data_source = "rpc_live_finalized";
  upsert_persisted_tx_result(cfg, result);
  out.value = std::move(result);
  return out;
}

LookupResult<AddressResult> fetch_address_result(const Config& cfg, const std::string& addr,
                                                 std::optional<std::uint64_t> start_after_height,
                                                 std::optional<std::string> start_after_txid) {
  LookupResult<AddressResult> out;
  const auto decoded = finalis::address::decode(addr);
  if (!decoded.has_value()) {
    out.error = make_error(400, "invalid_address", "malformed address");
    return out;
  }
  AddressResult result;
  result.address = addr;
  const Bytes script_pubkey = finalis::address::p2pkh_script_pubkey(decoded->pubkey_hash);
  const auto scripthash = finalis::crypto::sha256(script_pubkey);

  auto utxos = g_rpc_get_utxos(cfg.rpc_url, scripthash, nullptr);
  if (!utxos.has_value()) {
    out.error = upstream_error("utxo lookup failed");
    return out;
  }
  for (const auto& u : *utxos) {
    result.utxos.push_back(AddressUtxoResult{finalis::hex_encode32(u.txid), u.vout, u.value, u.height});
  }

  std::optional<std::uint64_t> cursor_height = std::move(start_after_height);
  std::optional<std::string> cursor_txid = std::move(start_after_txid);
  for (int page = 0; page < 5; ++page) {
    std::ostringstream params;
    params << "{\"scripthash_hex\":\"" << finalis::hex_encode32(scripthash) << "\",\"limit\":100";
    if (cursor_height.has_value() && cursor_txid.has_value()) {
      params << ",\"start_after\":{\"height\":" << *cursor_height << ",\"txid\":\"" << *cursor_txid << "\"}";
    }
    params << "}";
    auto res = rpc_call(cfg.rpc_url, "get_history_page_detailed", params.str());
    bool used_legacy_history = false;
    if (!res.result.has_value() || !res.result->is_object()) {
      auto legacy = rpc_call(cfg.rpc_url, "get_history_page", params.str());
      if (!legacy.result.has_value() || !legacy.result->is_object()) {
        out.error = upstream_error(res.error.empty() ? "history lookup failed" : res.error);
        return out;
      }
      res = std::move(legacy);
      used_legacy_history = true;
    }
    const auto* items = res.result->get("items");
    if (!items || !items->is_array()) break;
    for (const auto& item : items->array_value) {
      auto txid = object_string(&item, "txid");
      auto height = object_u64(&item, "height");
      if (!txid || !height) continue;
      if (used_legacy_history) {
        auto tx_lookup = fetch_tx_result(cfg, *txid);
        if (tx_lookup.value.has_value()) {
          auto history_item = classify_address_history_item(addr, *tx_lookup.value);
          history_item.height = *height;
          result.history.items.push_back(std::move(history_item));
        } else {
          result.history.items.push_back(AddressHistoryItemResult{*txid, *height, "related", 0,
                                                                  "Explorer could not expand the finalized transaction details"});
        }
      } else {
        auto direction = object_string(&item, "direction");
        auto net_amount = object_i64(&item, "net_amount");
        auto detail = object_string(&item, "detail");
        if (!direction || !net_amount || !detail) continue;
        result.history.items.push_back(AddressHistoryItemResult{*txid, *height, *direction, *net_amount, *detail});
      }
    }
    result.history.has_more = object_bool(&*res.result, "has_more").value_or(false);
    result.history.loaded_pages = static_cast<std::size_t>(page + 1);
    result.history.next_cursor.reset();
    result.history.next_cursor_height.reset();
    result.history.next_cursor_txid.reset();
    result.history.next_page_path.reset();
    const auto* next = res.result->get("next_start_after");
    if (!result.history.has_more) break;
    if (!next || next->is_null() || !next->is_object()) {
      out.error = upstream_error("history pagination cursor missing");
      return out;
    }
    cursor_height = object_u64(next, "height");
    cursor_txid = object_string(next, "txid");
    if (!cursor_height.has_value() || !cursor_txid.has_value()) {
      out.error = upstream_error("history pagination cursor malformed");
      return out;
    }
    result.history.next_cursor = std::to_string(*cursor_height) + ":" + *cursor_txid;
    result.history.next_cursor_height = cursor_height;
    result.history.next_cursor_txid = cursor_txid;
    result.history.next_page_path =
        "/address/" + addr + "?after_height=" + std::to_string(*cursor_height) + "&after_txid=" + *cursor_txid;
  }

  result.found = !result.utxos.empty() || !result.history.items.empty();
  out.value = std::move(result);
  return out;
}

LookupResult<SearchResult> fetch_search_result(const Config& cfg, const std::string& query) {
  LookupResult<SearchResult> out;
  auto status = fetch_status_result(cfg);
  if (!status.value.has_value()) {
    out.error = status.error;
    return out;
  }
  auto classification = classify_query(query, status.value->finalized_height);
  if (!classification.has_value() && !is_hex64(query)) {
    out.error = make_error(400, "invalid_query", "query did not match a supported finalized identifier");
    return out;
  }

  SearchResult result;
  result.query = query;
  if (classification.has_value()) {
    result.classification = *classification;
  }

  if (classification.has_value()) switch (*classification) {
    case SearchClassification::TransitionHeight: {
      result.target = "/transition/" + query;
      auto transition = fetch_transition_result(cfg, query);
      result.found = transition.value.has_value();
      if (!transition.value.has_value() && transition.error.has_value() && transition.error->http_status != 404) {
        out.error = transition.error;
        return out;
      }
      if (!result.found) result.target = std::nullopt;
      break;
    }
    case SearchClassification::Address: {
      result.target = "/address/" + query;
      auto addr = fetch_address_result(cfg, query);
      result.found = addr.value.has_value() && addr.value->found;
      if (!addr.value.has_value() && addr.error.has_value() && addr.error->http_status != 404) {
        out.error = addr.error;
        return out;
      }
      if (!result.found) result.target = std::nullopt;
      break;
    }
    case SearchClassification::Txid:
    case SearchClassification::TransitionHash:
    case SearchClassification::NotFound:
      break;
  }
  else if (is_hex64(query)) {
    result.classification = SearchClassification::Txid;
    auto tx = fetch_tx_result(cfg, query);
    result.found = tx.value.has_value();
    if (tx.value.has_value()) {
      result.target = "/tx/" + query;
      out.value = std::move(result);
      return out;
    }
    if (tx.error.has_value() && tx.error->http_status != 404) {
      out.error = tx.error;
      return out;
    }
    result.classification = SearchClassification::TransitionHash;
    auto transition = fetch_transition_result(cfg, query);
    result.found = transition.value.has_value();
    if (transition.value.has_value()) result.target = "/transition/" + query;
    if (!transition.value.has_value() && transition.error.has_value() && transition.error->http_status != 404) {
      out.error = transition.error;
      return out;
    }
    if (!result.found) {
      result.classification = SearchClassification::NotFound;
      result.target = std::nullopt;
    }
  }

  out.value = std::move(result);
  return out;
}

std::vector<RecentTxResult> fetch_recent_tx_results(const Config& cfg, std::size_t max_items) {
  const std::string cache_key = cfg.rpc_url + "#recent#" + std::to_string(max_items);
  {
    std::lock_guard<std::mutex> guard(g_recent_tx_cache_mu);
    if (g_recent_tx_cache.valid && g_recent_tx_cache.key == cache_key &&
        (std::chrono::steady_clock::now() - g_recent_tx_cache.stored_at) < std::chrono::seconds(3)) {
      return g_recent_tx_cache.value;
    }
  }

  std::vector<RecentTxResult> out;
  if (max_items == 0) return out;
  const std::uint64_t depth_window = 32;
  bool live_recent_rpc_ok = false;
  {
    std::ostringstream params;
    params << "{\"limit\":" << max_items << ",\"depth_window\":" << depth_window << "}";
    auto res = rpc_call(cfg.rpc_url, "get_recent_tx_summaries", params.str());
    if (res.result.has_value() && res.result->is_object()) {
      if (const auto* items = res.result->get("items"); items && items->is_array()) {
        live_recent_rpc_ok = true;
        out.reserve(items->array_value.size());
        for (const auto& item_value : items->array_value) {
          if (!item_value.is_object()) continue;
          auto txid = object_string(&item_value, "txid");
          if (!txid.has_value()) continue;
          RecentTxResult item;
          item.txid = *txid;
          item.height = object_u64(&item_value, "height");
          item.total_out = object_u64(&item_value, "finalized_out");
          item.status_label = object_string(&item_value, "status_label");
          item.credit_safe = object_bool(&item_value, "credit_safe");
          if (auto count = object_u64(&item_value, "input_count"); count.has_value()) item.input_count = static_cast<std::size_t>(*count);
          if (auto count = object_u64(&item_value, "output_count"); count.has_value()) item.output_count = static_cast<std::size_t>(*count);
          item.fee = object_u64(&item_value, "fee");
          item.primary_sender = object_string(&item_value, "primary_sender");
          item.primary_recipient = object_string(&item_value, "primary_recipient");
          if (auto count = object_u64(&item_value, "recipient_count"); count.has_value()) item.recipient_count = static_cast<std::size_t>(*count);
          item.flow_kind = object_string(&item_value, "flow_kind");
          item.flow_summary = object_string(&item_value, "flow_summary");
          out.push_back(std::move(item));
        }
      }
    }
  }
  if (out.empty()) {
    auto status = fetch_status_result(cfg);
    if (!status.value.has_value()) {
      if (auto cached = persisted_recent_results(max_items); cached.has_value()) {
        {
          std::lock_guard<std::mutex> guard(g_surface_state_mu);
          set_surface_state(g_recent_surface_state, "recent tx refresh failed", true);
        }
        out = std::move(*cached);
      }
      return out;
    }
    const auto tip = status.value->finalized_height;
    const std::uint64_t start_height = tip > depth_window ? tip - depth_window : 0;
    std::vector<std::pair<std::string, std::uint64_t>> tx_refs;
    for (std::uint64_t h = tip + 1; h-- > start_height && out.size() < max_items;) {
      std::string err;
      std::string transition_hash_hex;
      auto transition = fetch_transition_by_height(cfg, h, &transition_hash_hex, &err);
      if (!transition.has_value()) continue;
      const auto txids = fetch_transition_txids(cfg, *transition);
      for (const auto& txid : txids) {
        if (tx_refs.size() >= max_items) break;
        tx_refs.push_back({txid, h});
      }
      if (h == 0) break;
    }
    std::vector<std::string> txids;
    txids.reserve(tx_refs.size());
    for (const auto& [txid, _] : tx_refs) txids.push_back(txid);
    const auto summaries = fetch_tx_summary_batch(cfg, txids);
    out.reserve(tx_refs.size());
    for (const auto& [txid, height] : tx_refs) {
      RecentTxResult item;
      item.txid = txid;
      item.height = height;
      auto it = summaries.find(txid);
      if (it != summaries.end()) {
        item.status_label = it->second.status_label;
        item.credit_safe = it->second.credit_safe;
        item.total_out = it->second.total_out;
        item.input_count = it->second.input_count;
        item.output_count = it->second.output_count;
        item.fee = it->second.fee;
        item.primary_sender = it->second.primary_sender;
        item.primary_recipient = it->second.primary_recipient;
        item.recipient_count = it->second.recipient_count;
        item.flow_kind = it->second.flow_kind;
        item.flow_summary = it->second.flow_summary;
      } else {
        auto tx_lookup = fetch_tx_result(cfg, txid);
        if (tx_lookup.value.has_value()) {
          item.status_label = tx_lookup.value->status_label;
          item.credit_safe = tx_lookup.value->credit_safe;
          item.timestamp = tx_lookup.value->timestamp;
          item.total_out = tx_lookup.value->total_out;
          item.input_count = tx_lookup.value->inputs.size();
          item.output_count = tx_lookup.value->outputs.size();
          item.fee = tx_lookup.value->fee;
          if (!tx_lookup.value->outputs.empty()) {
            std::set<std::string> unique_recipients;
            for (const auto& out_view : tx_lookup.value->outputs) {
              if (out_view.address.has_value() && !out_view.address->empty()) unique_recipients.insert(*out_view.address);
            }
            if (!unique_recipients.empty()) {
              item.primary_recipient = *unique_recipients.begin();
              item.recipient_count = unique_recipients.size();
            }
          }
          if (!tx_lookup.value->inputs.empty()) {
            const auto& first_input = tx_lookup.value->inputs.front();
            auto prev_lookup = fetch_tx_result(cfg, first_input.prev_txid);
            if (prev_lookup.value.has_value() && first_input.vout < prev_lookup.value->outputs.size()) {
              item.primary_sender = prev_lookup.value->outputs[first_input.vout].address;
            }
          }
          item.flow_kind = tx_lookup.value->flow_kind;
          item.flow_summary = tx_lookup.value->flow_summary;
        }
      }
      out.push_back(std::move(item));
    }
  }
  {
    std::lock_guard<std::mutex> guard(g_recent_tx_cache_mu);
    g_recent_tx_cache = TimedCacheEntry<std::vector<RecentTxResult>>{
        .key = cache_key, .stored_at = std::chrono::steady_clock::now(), .value = out, .valid = true};
  }
  if (max_items == kPersistedRecentLimit) {
    const auto refreshed_unix_ms = now_unix_ms();
    {
      std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
      g_persisted_snapshot.recent_refreshed_unix_ms = refreshed_unix_ms;
      g_persisted_snapshot.recent_limit = max_items;
      g_persisted_snapshot.recent_present = true;
      g_persisted_snapshot.recent = out;
    }
    persist_explorer_snapshot(cfg);
  }
  {
    std::lock_guard<std::mutex> guard(g_surface_state_mu);
    if (!out.empty() || live_recent_rpc_ok) {
      set_surface_state(g_recent_surface_state, std::nullopt, false);
    } else if (auto cached = persisted_recent_results(max_items); cached.has_value()) {
      out = *cached;
      set_surface_state(g_recent_surface_state, "recent tx refresh failed", true);
    }
  }
  return out;
}

std::map<std::string, TxSummaryBatchItem> fetch_tx_summary_batch(const Config& cfg, const std::vector<std::string>& txids) {
  std::map<std::string, TxSummaryBatchItem> out;
  if (txids.empty()) return out;
  std::ostringstream params;
  params << "{\"txids\":[";
  for (std::size_t i = 0; i < txids.size(); ++i) {
    if (i) params << ",";
    params << "\"" << json_escape(txids[i]) << "\"";
  }
  params << "]}";
  auto res = rpc_call(cfg.rpc_url, "get_tx_summaries", params.str());
  if (!res.result.has_value() || !res.result->is_object()) return out;
  const auto* items = res.result->get("items");
  if (!items || !items->is_array()) return out;
  for (const auto& item : items->array_value) {
    auto txid = object_string(&item, "txid");
    if (!txid) continue;
    TxSummaryBatchItem row;
    row.txid = *txid;
    row.height = object_u64(&item, "height");
    row.total_out = object_u64(&item, "finalized_out");
    row.fee = object_u64(&item, "fee");
    if (auto count = object_u64(&item, "input_count"); count.has_value()) row.input_count = static_cast<std::size_t>(*count);
    if (auto count = object_u64(&item, "output_count"); count.has_value()) row.output_count = static_cast<std::size_t>(*count);
    row.primary_sender = object_string(&item, "primary_sender");
    row.primary_recipient = object_string(&item, "primary_recipient");
    if (auto count = object_u64(&item, "recipient_count"); count.has_value()) row.recipient_count = static_cast<std::size_t>(*count);
    row.flow_kind = object_string(&item, "flow_kind");
    row.flow_summary = object_string(&item, "flow_summary");
    row.status_label = object_string(&item, "status_label");
    row.credit_safe = object_bool(&item, "credit_safe");
    if (const auto* recipients = item.get("recipients"); recipients && recipients->is_array()) {
      for (const auto& recipient : recipients->array_value) {
        if (recipient.is_string()) row.recipients.push_back(recipient.string_value);
      }
    }
    out.emplace(*txid, std::move(row));
  }
  return out;
}

std::string render_status_json(const StatusResult& result, std::optional<std::uint64_t> refreshed_unix_ms) {
  std::ostringstream oss;
  oss << "{\"network\":\"" << json_escape(result.network) << "\","
      << "\"network_id\":\"" << json_escape(result.network_id) << "\","
      << "\"genesis_hash\":\"" << json_escape(result.genesis_hash) << "\","
      << "\"finalized_height\":" << result.finalized_height << ","
      << "\"finalized_transition_hash\":\"" << json_escape(result.finalized_transition_hash) << "\","
      << "\"backend_version\":\"" << json_escape(result.backend_version) << "\","
      << "\"wallet_api_version\":\"" << json_escape(result.wallet_api_version) << "\","
      << "\"protocol_reserve_balance\":" << json_u64_or_null(result.protocol_reserve_balance) << ","
      << "\"healthy_peer_count\":" << result.healthy_peer_count << ","
      << "\"established_peer_count\":" << result.established_peer_count << ","
      << "\"latest_finality_committee_size\":" << result.latest_finality_committee_size << ","
      << "\"latest_finality_quorum_threshold\":" << result.latest_finality_quorum_threshold << ","
      << "\"committee_snapshot\":{\"finalized_height\":" << result.finalized_height
      << ",\"finalized_transition_hash\":\"" << json_escape(result.finalized_transition_hash) << "\""
      << ",\"committee_size\":" << result.latest_finality_committee_size
      << ",\"quorum_threshold\":" << result.latest_finality_quorum_threshold << "},"
      << "\"sync\":{\"observed_network_height_known\":" << json_bool(result.observed_network_height_known)
      << ",\"observed_network_finalized_height\":" << json_u64_or_null(result.observed_network_finalized_height)
      << ",\"finalized_lag\":" << json_u64_or_null(result.finalized_lag)
      << ",\"bootstrap_sync_incomplete\":" << json_bool(result.bootstrap_sync_incomplete)
      << ",\"peer_height_disagreement\":" << json_bool(result.peer_height_disagreement)
      << "},"
      << "\"availability\":{\"epoch\":" << json_u64_or_null(result.availability_epoch)
      << ",\"retained_prefix_count\":" << json_u64_or_null(result.availability_retained_prefix_count)
      << ",\"tracked_operator_count\":" << json_u64_or_null(result.availability_tracked_operator_count)
      << ",\"eligible_operator_count\":" << json_u64_or_null(result.availability_eligible_operator_count)
      << ",\"below_min_eligible\":"
      << (result.availability_below_min_eligible.has_value() ? json_bool(*result.availability_below_min_eligible) : "null")
      << ",\"checkpoint_derivation_mode\":" << json_string_or_null(result.availability_checkpoint_derivation_mode)
      << ",\"checkpoint_fallback_reason\":" << json_string_or_null(result.availability_checkpoint_fallback_reason)
      << ",\"fallback_sticky\":"
      << (result.availability_fallback_sticky.has_value() ? json_bool(*result.availability_fallback_sticky) : "null")
      << ",\"adaptive_regime\":{\"qualified_depth\":" << json_u64_or_null(result.qualified_depth)
      << ",\"adaptive_target_committee_size\":" << json_u64_or_null(result.adaptive_target_committee_size)
      << ",\"adaptive_min_eligible\":" << json_u64_or_null(result.adaptive_min_eligible)
      << ",\"adaptive_min_bond\":" << json_u64_or_null(result.adaptive_min_bond)
      << ",\"slack\":";
  if (result.adaptive_slack.has_value()) oss << *result.adaptive_slack;
  else oss << "null";
  oss << ",\"target_expand_streak\":" << json_u64_or_null(result.target_expand_streak)
      << ",\"target_contract_streak\":" << json_u64_or_null(result.target_contract_streak)
      << ",\"fallback_rate_bps\":" << json_u64_or_null(result.adaptive_fallback_rate_bps)
      << ",\"sticky_fallback_rate_bps\":" << json_u64_or_null(result.adaptive_sticky_fallback_rate_bps)
      << ",\"fallback_rate_window_epochs\":" << json_u64_or_null(result.adaptive_fallback_window_epochs)
      << ",\"near_threshold_operation\":"
      << (result.adaptive_near_threshold_operation.has_value() ? json_bool(*result.adaptive_near_threshold_operation)
                                                               : "null")
      << ",\"prolonged_expand_buildup\":"
      << (result.adaptive_prolonged_expand_buildup.has_value() ? json_bool(*result.adaptive_prolonged_expand_buildup)
                                                               : "null")
      << ",\"prolonged_contract_buildup\":"
      << (result.adaptive_prolonged_contract_buildup.has_value()
              ? json_bool(*result.adaptive_prolonged_contract_buildup)
              : "null")
      << ",\"repeated_sticky_fallback\":"
      << (result.adaptive_repeated_sticky_fallback.has_value() ? json_bool(*result.adaptive_repeated_sticky_fallback)
                                                               : "null")
      << ",\"depth_collapse_after_bond_increase\":"
      << (result.adaptive_depth_collapse_after_bond_increase.has_value()
              ? json_bool(*result.adaptive_depth_collapse_after_bond_increase)
              : "null")
      << "}"
      << ",\"adaptive_telemetry_summary\":{\"window_epochs\":"
      << json_u64_or_null(result.adaptive_telemetry_window_epochs)
      << ",\"sample_count\":" << json_u64_or_null(result.adaptive_telemetry_sample_count)
      << ",\"fallback_epochs\":" << json_u64_or_null(result.adaptive_telemetry_fallback_epochs)
      << ",\"sticky_fallback_epochs\":" << json_u64_or_null(result.adaptive_telemetry_sticky_fallback_epochs)
      << "}"
      << ",\"local_operator\":{\"known\":"
      << (result.availability_local_operator_known.has_value() ? json_bool(*result.availability_local_operator_known) : "null")
      << ",\"pubkey\":" << json_string_or_null(result.availability_local_operator_pubkey)
      << ",\"status\":" << json_string_or_null(result.availability_local_operator_status)
      << ",\"seat_budget\":" << json_u64_or_null(result.availability_local_operator_seat_budget)
      << ",\"validator_registry_status\":" << json_string_or_null(result.availability_local_operator_validator_status)
      << ",\"onboarding_reward_eligible\":"
      << (result.availability_local_operator_onboarding_reward_eligible.has_value()
              ? json_bool(*result.availability_local_operator_onboarding_reward_eligible)
              : "null")
      << ",\"onboarding_reward_score_units\":"
      << json_u64_or_null(result.availability_local_operator_onboarding_reward_score_units)
      << "}},"
      << "\"onboarding\":{\"reward_pool_bps\":" << result.onboarding_reward_pool_bps
      << ",\"admission_pow_difficulty_bits\":" << result.onboarding_admission_pow_difficulty_bits
      << ",\"validator_join_admission_pow_difficulty_bits\":" << result.validator_join_admission_pow_difficulty_bits
      << "},"
      << "\"ticket_pow\":{\"difficulty\":" << result.ticket_pow_difficulty
      << ",\"difficulty_min\":" << result.ticket_pow_difficulty_min
      << ",\"difficulty_max\":" << result.ticket_pow_difficulty_max
      << ",\"epoch_health\":\"" << json_escape(result.ticket_pow_epoch_health) << "\""
      << ",\"streak_up\":" << result.ticket_pow_streak_up
      << ",\"streak_down\":" << result.ticket_pow_streak_down
      << ",\"nonce_search_limit\":" << result.ticket_pow_nonce_search_limit
      << ",\"bonus_cap_bps\":" << result.ticket_pow_bonus_cap_bps
      << "},"
      << "\"snapshot_refreshed_unix_ms\":" << json_u64_or_null(refreshed_unix_ms) << ","
      << "\"finalized_only\":true}";
  return oss.str();
}

std::string render_tx_json(const TxResult& result) {
  std::ostringstream oss;
  oss << "{\"txid\":\"" << json_escape(result.txid) << "\","
      << "\"found\":" << json_bool(result.found) << ","
      << "\"finalized\":" << json_bool(result.finalized) << ","
      << "\"height\":" << json_u64_or_null(result.finalized_height) << ","
      << "\"finalized_height\":" << json_u64_or_null(result.finalized_height) << ","
      << "\"finalized_depth\":" << result.finalized_depth << ","
      << "\"credit_safe\":" << json_bool(result.credit_safe) << ","
      << "\"status_label\":\"" << json_escape(result.status_label) << "\","
      << "\"transition_hash\":\"" << json_escape(result.transition_hash) << "\","
      << "\"data_source\":\"" << json_escape(result.data_source) << "\","
      << "\"data_refreshed_unix_ms\":" << json_u64_or_null(result.data_refreshed_unix_ms) << ","
      << "\"timestamp\":" << json_u64_or_null(result.timestamp) << ",\"inputs\":[";
  for (std::size_t i = 0; i < result.inputs.size(); ++i) {
    if (i) oss << ",";
    oss << "{\"prev_txid\":\"" << json_escape(result.inputs[i].prev_txid) << "\",\"vout\":" << result.inputs[i].vout << "}";
  }
  oss << "],\"outputs\":[";
  for (std::size_t i = 0; i < result.outputs.size(); ++i) {
    if (i) oss << ",";
    oss << "{\"amount\":" << result.outputs[i].amount << ",\"address\":"
        << json_string_or_null(result.outputs[i].address) << ",\"script_hex\":\""
        << json_escape(result.outputs[i].script_hex) << "\",\"decoded_kind\":"
        << json_string_or_null(result.outputs[i].decoded_kind)
        << ",\"validator_pubkey_hex\":" << json_string_or_null(result.outputs[i].validator_pubkey_hex)
        << ",\"payout_pubkey_hex\":" << json_string_or_null(result.outputs[i].payout_pubkey_hex)
        << ",\"has_admission_pow\":" << json_bool(result.outputs[i].has_admission_pow)
        << ",\"admission_pow_epoch\":" << json_u64_or_null(result.outputs[i].admission_pow_epoch)
        << ",\"admission_pow_nonce\":" << json_u64_or_null(result.outputs[i].admission_pow_nonce)
        << "}";
  }
  std::size_t decoded_output_count = 0;
  std::set<std::string> decoded_recipients;
  for (const auto& output : result.outputs) {
    if (output.address.has_value()) {
      ++decoded_output_count;
      decoded_recipients.insert(*output.address);
    }
  }
  oss << "],\"finalized_out\":" << result.total_out << ",\"total_out\":" << result.total_out << ",\"fee\":"
      << (result.fee.has_value() ? std::to_string(*result.fee) : "null") << ","
      << "\"input_count\":" << result.inputs.size() << ",\"output_count\":" << result.outputs.size()
      << ",\"decoded_output_count\":" << decoded_output_count
      << ",\"flow\":{\"kind\":\"" << json_escape(result.flow_kind) << "\",\"summary\":\"" << json_escape(result.flow_summary) << "\"}"
      << ",\"primary_sender\":" << json_string_or_null(result.primary_sender)
      << ",\"primary_recipient\":" << json_string_or_null(result.primary_recipient)
      << ",\"recipient_count\":" << decoded_recipients.size()
      << ",\"participant_count\":";
  if (result.participant_count.has_value()) oss << *result.participant_count;
  else oss << "null";
  oss << ","
      << "\"finalized_only\":true}";
  return oss.str();
}

std::string render_transition_json(const Config& cfg, const TransitionResult& result) {
  const auto summary = compute_transition_summary(cfg, result);
  std::ostringstream oss;
  oss << "{\"found\":" << json_bool(result.found) << ",\"finalized\":true,"
      << "\"height\":" << result.height << ",\"hash\":\"" << json_escape(result.hash) << "\","
      << "\"prev_finalized_hash\":\"" << json_escape(result.prev_finalized_hash) << "\","
      << "\"data_source\":\"" << json_escape(result.data_source) << "\","
      << "\"data_refreshed_unix_ms\":" << json_u64_or_null(result.data_refreshed_unix_ms) << ","
      << "\"timestamp\":" << json_u64_or_null(result.timestamp) << ",\"round\":" << result.round
      << ",\"tx_count\":" << result.tx_count << ",\"txids\":[";
  for (std::size_t i = 0; i < result.txids.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << json_escape(result.txids[i]) << "\"";
  }
  oss << "],\"summary\":{\"tx_count\":" << result.tx_count
      << ",\"finalized_out\":" << summary.finalized_out
      << ",\"distinct_recipient_count\":" << summary.distinct_recipient_count
      << ",\"flow_mix\":{";
  bool first_flow = true;
  for (const auto& [kind, count] : summary.flow_mix) {
    if (!first_flow) oss << ",";
    first_flow = false;
    oss << "\"" << json_escape(kind) << "\":" << count;
  }
  oss << "}},\"finalized_only\":true,\"snapshot_kind\":\"finalized_transition\"}";
  return oss.str();
}

std::string render_address_json(const AddressResult& result) {
  std::ostringstream oss;
  std::uint64_t finalized_balance = 0;
  std::uint64_t received_total = 0;
  std::uint64_t sent_total = 0;
  std::uint64_t self_transfer_total = 0;
  for (const auto& utxo : result.utxos) finalized_balance += utxo.amount;
  for (const auto& item : result.history.items) {
    if (item.net_amount > 0 && item.direction == "received") received_total += static_cast<std::uint64_t>(item.net_amount);
    else if (item.net_amount < 0 && item.direction == "sent") sent_total += static_cast<std::uint64_t>(-item.net_amount);
    else if (item.direction == "self-transfer") {
      self_transfer_total += static_cast<std::uint64_t>(item.net_amount >= 0 ? item.net_amount : -item.net_amount);
    }
  }
  oss << "{\"address\":\"" << json_escape(result.address) << "\","
      << "\"found\":" << json_bool(result.found) << ",\"finalized_balance\":" << finalized_balance
      << ",\"history_slice_complete\":" << json_bool(!result.history.has_more)
      << ",\"summary\":{\"finalized_balance\":" << finalized_balance
      << ",\"received\":" << received_total
      << ",\"sent\":" << sent_total
      << ",\"self_transfer\":" << self_transfer_total
      << "},\"utxos\":[";
  for (std::size_t i = 0; i < result.utxos.size(); ++i) {
    if (i) oss << ",";
    oss << "{\"txid\":\"" << json_escape(result.utxos[i].txid) << "\",\"vout\":" << result.utxos[i].vout
        << ",\"amount\":" << result.utxos[i].amount << ",\"height\":" << result.utxos[i].height << "}";
  }
  oss << "],\"history\":{\"items\":[";
  for (std::size_t i = 0; i < result.history.items.size(); ++i) {
    if (i) oss << ",";
    oss << "{\"txid\":\"" << json_escape(result.history.items[i].txid) << "\",\"height\":"
        << result.history.items[i].height << ",\"direction\":\"" << json_escape(result.history.items[i].direction)
        << "\",\"net_amount\":" << result.history.items[i].net_amount
        << ",\"detail\":\"" << json_escape(result.history.items[i].detail) << "\"}";
  }
  oss << "],\"has_more\":" << json_bool(result.history.has_more) << ",\"next_cursor\":"
      << json_string_or_null(result.history.next_cursor)
      << ",\"next_page_path\":" << json_string_or_null(result.history.next_page_path)
      << ",\"loaded_pages\":" << result.history.loaded_pages << "},\"finalized_only\":true}";
  return oss.str();
}

std::string render_search_json(const SearchResult& result) {
  std::ostringstream oss;
  oss << "{\"query\":\"" << json_escape(result.query) << "\","
      << "\"classification\":\"" << json_escape(search_classification_name(result.classification)) << "\","
      << "\"target\":" << json_string_or_null(result.target) << ","
      << "\"found\":" << json_bool(result.found) << ",\"finalized_only\":true}";
  return oss.str();
}

std::string render_committee_json(const CommitteeResult& result, std::optional<std::uint64_t> refreshed_unix_ms) {
  std::ostringstream oss;
  oss << "{\"height\":" << result.height
      << ",\"epoch_start_height\":" << result.epoch_start_height
      << ",\"checkpoint_derivation_mode\":" << json_string_or_null(result.checkpoint_derivation_mode)
      << ",\"checkpoint_fallback_reason\":" << json_string_or_null(result.checkpoint_fallback_reason)
      << ",\"fallback_sticky\":"
      << (result.fallback_sticky.has_value() ? json_bool(*result.fallback_sticky) : "null")
      << ",\"availability_eligible_operator_count\":" << json_u64_or_null(result.availability_eligible_operator_count)
      << ",\"availability_min_eligible_operators\":" << json_u64_or_null(result.availability_min_eligible_operators)
      << ",\"adaptive_target_committee_size\":" << json_u64_or_null(result.adaptive_target_committee_size)
      << ",\"adaptive_min_eligible\":" << json_u64_or_null(result.adaptive_min_eligible)
      << ",\"adaptive_min_bond\":" << json_u64_or_null(result.adaptive_min_bond)
      << ",\"qualified_depth\":" << json_u64_or_null(result.qualified_depth)
      << ",\"slack\":";
  if (result.adaptive_slack.has_value()) oss << *result.adaptive_slack;
  else oss << "null";
  oss << ",\"target_expand_streak\":" << json_u64_or_null(result.target_expand_streak)
      << ",\"target_contract_streak\":" << json_u64_or_null(result.target_contract_streak)
      << ",\"member_count\":" << result.members.size()
      << ",\"snapshot_kind\":\"finalized_committee\""
      << ",\"snapshot_refreshed_unix_ms\":" << json_u64_or_null(refreshed_unix_ms)
      << ",\"members\":[";
  for (std::size_t i = 0; i < result.members.size(); ++i) {
    if (i) oss << ",";
    const auto& member = result.members[i];
    oss << "{\"operator_id\":" << json_string_or_null(member.operator_id)
        << ",\"resolved_operator_id\":\"" << json_escape(member.resolved_operator_id) << "\""
        << ",\"operator_id_source\":\"" << json_escape(member.operator_id_source) << "\""
        << ",\"representative_pubkey\":\"" << json_escape(member.representative_pubkey) << "\""
        << ",\"base_weight\":" << json_u64_or_null(member.base_weight)
        << ",\"ticket_bonus_bps\":" << json_u64_or_null(member.ticket_bonus_bps)
        << ",\"final_weight\":" << json_u64_or_null(member.final_weight)
        << ",\"ticket_hash\":" << json_string_or_null(member.ticket_hash)
        << ",\"ticket_nonce\":" << json_u64_or_null(member.ticket_nonce)
        << "}";
  }
  oss << "],\"finalized_only\":true}";
  return oss.str();
}

std::string render_recent_tx_json(const std::vector<RecentTxResult>& items, std::optional<std::uint64_t> refreshed_unix_ms) {
  std::ostringstream oss;
  std::uint64_t finalized_out_total = 0;
  oss << "{\"items\":[";
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i) oss << ",";
    const auto& item = items[i];
    if (item.total_out.has_value()) finalized_out_total += *item.total_out;
    oss << "{\"txid\":\"" << json_escape(item.txid) << "\""
        << ",\"height\":" << json_u64_or_null(item.height)
        << ",\"timestamp\":" << json_u64_or_null(item.timestamp)
        << ",\"finalized_out\":" << json_u64_or_null(item.total_out)
        << ",\"total_out\":" << json_u64_or_null(item.total_out)
        << ",\"fee\":" << json_u64_or_null(item.fee)
        << ",\"status_label\":" << json_string_or_null(item.status_label)
        << ",\"flow_kind\":" << json_string_or_null(item.flow_kind)
        << ",\"flow_summary\":" << json_string_or_null(item.flow_summary)
        << ",\"primary_sender\":" << json_string_or_null(item.primary_sender)
        << ",\"primary_recipient\":" << json_string_or_null(item.primary_recipient)
        << ",\"recipient_count\":";
    if (item.recipient_count.has_value()) oss << *item.recipient_count;
    else oss << "null";
    oss << ",\"input_count\":";
    if (item.input_count.has_value()) oss << *item.input_count;
    else oss << "null";
    oss << ",\"output_count\":";
    if (item.output_count.has_value()) oss << *item.output_count;
    else oss << "null";
    oss << ",\"credit_safe\":";
    if (item.credit_safe.has_value()) oss << json_bool(*item.credit_safe);
    else oss << "null";
    oss << "}";
  }
  oss << "],\"summary\":{\"tx_count\":" << items.size() << ",\"finalized_out\":" << finalized_out_total
      << "},\"snapshot_refreshed_unix_ms\":" << json_u64_or_null(refreshed_unix_ms)
      << ",\"finalized_only\":true,\"snapshot_kind\":\"recent_finalized_transactions\"}";
  return oss.str();
}

std::string render_health_json(bool ok, const std::optional<ApiError>& err = std::nullopt) {
  std::ostringstream oss;
  oss << "{\"ok\":" << json_bool(ok) << ",\"finalized_only\":true,\"upstream_ok\":" << json_bool(ok);
  if (err.has_value()) {
    oss << ",\"error\":{\"code\":\"" << json_escape(err->code) << "\",\"message\":\"" << json_escape(err->message) << "\"}";
  }
  oss << "}";
  return oss.str();
}

std::string render_tx(const Config& cfg, const std::string& txid_hex) {
  std::ostringstream body;
  body << "<h1>Transaction</h1>";
  auto lookup = fetch_tx_result(cfg, txid_hex);
  if (!lookup.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Lookup failed: "
         << html_escape(lookup.error ? lookup.error->message : "unknown error") << "</div></div>";
    return page_layout("Transaction", body.str(), "tx");
  }
  const auto& tx = *lookup.value;
  const std::string tx_path = "/tx/" + tx.txid;
  const std::string tx_api_path = "/api/tx/" + tx.txid;
  const std::string payer = tx.primary_sender.has_value() ? short_hex(*tx.primary_sender) : std::string("unknown");
  std::string payee = tx.primary_recipient.has_value() ? short_hex(*tx.primary_recipient) : std::string("unknown");
  if (!tx.outputs.empty() && tx.outputs.size() > 1) {
    std::size_t decoded_recipient_count = 0;
    for (const auto& out : tx.outputs) {
      if (out.address.has_value()) ++decoded_recipient_count;
    }
    if (decoded_recipient_count > 1) payee += " +" + std::to_string(decoded_recipient_count - 1) + " more";
  }

  body << "<div class=\"card\"><div class=\"hero-metrics\">"
       << render_summary_metric_card("Flow", tx.flow_kind, tx.flow_summary)
       << render_summary_metric_card("Paid By", payer, "inferred from finalized inputs")
       << render_summary_metric_card("Paid To", payee, "inferred from finalized outputs")
       << render_summary_metric_card("Finalized Out", format_amount(tx.total_out),
                                     tx.fee.has_value() ? ("fee " + format_amount(*tx.fee)) : "fee unknown")
       << "</div></div>";

  body << "<div class=\"card\"><div class=\"status-hero\">"
       << "<div>" << mono_value(tx.txid) << "</div><div>" << finalized_badge(tx.finalized) << " "
       << credit_safe_badge(tx.credit_safe) << "</div></div>"
       << "<div class=\"decision-line\">" << html_escape(credit_decision_text(tx.finalized, tx.credit_safe)) << "</div>"
       << "<div class=\"note\">Explorer data source: <strong>" << html_escape(explorer_data_source_label(tx.data_source))
       << "</strong>. Cached finalized snapshots remain valid, but may be older than a fresh RPC refresh.</div>"
       << (explorer_data_freshness_note(tx.data_source, tx.data_refreshed_unix_ms).empty()
               ? std::string()
               : "<div class=\"note\">" + html_escape(explorer_data_freshness_note(tx.data_source, tx.data_refreshed_unix_ms)) + "</div>")
       << "<div class=\"note\">Transaction view is finalized-state only. Relay acceptance, mempool state, and pre-finality observations are intentionally not shown here.</div>"
       << "<div class=\"grid\" style=\"margin-top:14px;\">"
       << "<div>Txid</div><div class=\"value-cell\">" << mono_value(tx.txid) << "</div>"
       << "<div>Flow Classification</div><div><strong>" << html_escape(tx.flow_kind) << "</strong><div class=\"muted\">"
       << html_escape(tx.flow_summary) << "</div></div>"
       << "<div>Status</div><div>" << html_escape(tx.status_label) << "</div>"
       << "<div>Finalized</div><div>" << finalized_text(tx.finalized) << "</div>"
       << "<div>Credit Safe</div><div>" << credit_safe_text(tx.credit_safe) << "</div>"
       << "<div>Data Source</div><div>" << html_escape(explorer_data_source_label(tx.data_source)) << "</div>"
       << "<div>Snapshot Refreshed</div><div>"
       << html_escape(explorer_data_freshness_note(tx.data_source, tx.data_refreshed_unix_ms).empty()
                          ? std::string("fresh live RPC")
                          : format_timestamp(*tx.data_refreshed_unix_ms))
       << "</div>"
       << "<div>Finalized Only</div><div>yes</div>";
  if (tx.finalized_height.has_value()) body << "<div>Finalized Height</div><div>" << link_transition_height(*tx.finalized_height) << "</div>";
  if (!tx.transition_hash.empty()) body << "<div>Transition Hash</div><div class=\"value-cell\">" << mono_value(tx.transition_hash) << "</div>";
  if (tx.timestamp.has_value()) body << "<div>Timestamp</div><div>" << html_escape(format_timestamp(*tx.timestamp)) << "</div>";
  body << "<div>Finalized Depth</div><div>" << tx.finalized_depth << "</div>";
  if (tx.primary_sender.has_value()) body << "<div>Primary Sender</div><div>" << display_identity(tx.primary_sender) << "</div>";
  if (tx.primary_recipient.has_value()) body << "<div>Primary Recipient</div><div>" << display_identity(tx.primary_recipient) << "</div>";
  if (tx.participant_count.has_value()) body << "<div>Distinct Participants</div><div>" << *tx.participant_count << "</div>";
  body << "<div>Input Count</div><div>" << tx.inputs.size() << "</div>";
  body << "<div>Output Count</div><div>" << tx.outputs.size() << "</div>";
  if (tx.fee.has_value()) body << "<div>Fee</div><div>" << html_escape(format_amount(*tx.fee)) << "</div>";
  body << "<div>Finalized Out</div><div>" << html_escape(format_amount(tx.total_out)) << "</div>"
       << "</div><div class=\"summary-actions\">"
       << copy_action("Copy Txid", tx.txid)
       << copy_action("Copy Page Path", tx_path)
       << copy_action("Copy API Path", tx_api_path);
  if (!tx.transition_hash.empty()) body << copy_action("Copy Transition Hash", tx.transition_hash);
  body << "</div></div>";

  body << "<div class=\"card\"><h2>Inputs</h2><div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Prev Tx</th><th>Vout</th><th>Decoded Source</th><th>Amount</th></tr></thead><tbody>";
  for (std::size_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    body << "<tr><td>" << i << "</td><td>" << link_tx(in.prev_txid) << "</td><td>" << in.vout
         << "</td><td>";
    if (in.address.has_value()) body << "<a href=\"/address/" << html_escape(*in.address) << "\"><code>" << html_escape(*in.address) << "</code></a>";
    else body << "<span class=\"muted\">not decoded by explorer</span>";
    body << "</td><td>";
    if (in.amount.has_value()) body << html_escape(format_amount(*in.amount));
    else body << "<span class=\"muted\">n/a</span>";
    body << "</td></tr>";
  }
  if (tx.inputs.empty()) body << "<tr><td colspan=\"5\" class=\"muted\">No inputs</td></tr>";
  body << "</tbody></table></div></div>";

  body << "<div class=\"card\"><h2>Outputs</h2><div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Amount</th><th>Decoded Destination</th><th>Output Form</th><th>Script</th></tr></thead><tbody>";
  for (std::size_t i = 0; i < tx.outputs.size(); ++i) {
    const auto& out = tx.outputs[i];
    body << "<tr><td>" << i << "</td><td>" << html_escape(format_amount(out.amount)) << "</td><td>";
    if (out.decoded_kind == std::optional<std::string>{"onboarding_registration"}) {
      body << "<div><strong>validator</strong> <code>" << html_escape(short_hex(out.validator_pubkey_hex.value_or(""))) << "</code></div>";
      body << "<div><strong>payout</strong> <code>" << html_escape(short_hex(out.payout_pubkey_hex.value_or(""))) << "</code></div>";
      if (out.has_admission_pow) {
        body << "<div class=\"muted\">admission PoW epoch "
             << html_escape(out.admission_pow_epoch.has_value() ? std::to_string(*out.admission_pow_epoch) : std::string("n/a"))
             << ", nonce "
             << html_escape(out.admission_pow_nonce.has_value() ? std::to_string(*out.admission_pow_nonce) : std::string("n/a"))
             << "</div>";
      }
    } else if (out.address.has_value()) {
      body << "<a href=\"/address/" << html_escape(*out.address) << "\"><code>" << html_escape(*out.address) << "</code></a>";
    } else {
      body << "<span class=\"muted\">not decoded by explorer</span>";
    }
    body << "</td><td>";
    if (out.decoded_kind == std::optional<std::string>{"onboarding_registration"}) {
      body << "SCONBREG onboarding registration";
    } else {
      body << (out.address.has_value() ? "P2PKH address" : "Raw script only");
    }
    body << "</td><td><code>" << html_escape(out.script_hex) << "</code></td></tr>";
  }
  if (tx.outputs.empty()) body << "<tr><td colspan=\"5\" class=\"muted\">No outputs</td></tr>";
  body << "</tbody></table></div></div>";

  return page_layout("Transaction " + txid_hex, body.str(), "tx");
}

std::string render_transition(const Config& cfg, const std::string& ident) {
  std::ostringstream body;
  body << "<h1>Transition</h1>";
  auto lookup = fetch_transition_result(cfg, ident);
  if (!lookup.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Lookup failed: "
         << html_escape(lookup.error ? lookup.error->message : "unknown error") << "</div></div>";
    return page_layout("Transition", body.str(), "transition");
  }
  const auto& transition = *lookup.value;
  const std::string transition_path = "/transition/" + transition.hash;
  const std::string transition_api_path = "/api/transition/" + transition.hash;
  const auto summary = compute_transition_summary(cfg, transition);
  const auto flow_mix_text = summarize_flow_mix(summary.flow_mix);

  body << "<div class=\"card\"><div class=\"hero-metrics\">"
       << render_summary_metric_card("Tx Count", std::to_string(transition.txids.size()), "finalized txids in this transition")
       << render_summary_metric_card("Total Finalized Out", format_amount(summary.finalized_out), "sum of finalized outputs in this transition")
       << render_summary_metric_card("Distinct Recipients", std::to_string(summary.distinct_recipient_count), "decoded finalized output addresses")
       << render_summary_metric_card("Activity Mix", flow_mix_text, "flow-type counts inferred from finalized tx structure")
       << "</div></div>";

  body << "<div class=\"card\"><div class=\"status-hero\">"
       << "<div>" << mono_value(transition.hash) << "</div><div>" << finalized_badge(true) << "</div></div>"
       << "<div class=\"note\">Explorer data source: <strong>" << html_escape(explorer_data_source_label(transition.data_source))
       << "</strong>. Cached finalized snapshots remain valid, but may be older than a fresh RPC refresh.</div>"
       << (explorer_data_freshness_note(transition.data_source, transition.data_refreshed_unix_ms).empty()
               ? std::string()
               : "<div class=\"note\">" +
                     html_escape(explorer_data_freshness_note(transition.data_source, transition.data_refreshed_unix_ms)) + "</div>")
       << "<div class=\"note\">Transition view is finalized-only. It shows the finalized checkpoint contents for one height, not proposal-stage or unfinalized round activity.</div>"
       << "<div class=\"grid\" style=\"margin-top:14px;\">"
       << "<div>Height</div><div>" << transition.height << "</div>"
       << "<div>Transition Hash</div><div class=\"value-cell\">" << mono_value(transition.hash) << "</div>"
       << "<div>Prev Finalized Hash</div><div class=\"value-cell\">" << mono_value(transition.prev_finalized_hash)
       << "</div>"
       << "<div>Timestamp</div><div>"
       << html_escape(transition.timestamp.has_value() ? format_timestamp(*transition.timestamp) : std::string("not carried in finalized transition record")) << "</div>"
       << "<div>Round</div><div>" << transition.round << "</div>"
       << "<div>Data Source</div><div>" << html_escape(explorer_data_source_label(transition.data_source)) << "</div>"
       << "<div>Snapshot Refreshed</div><div>"
       << html_escape(explorer_data_freshness_note(transition.data_source, transition.data_refreshed_unix_ms).empty()
                          ? std::string("fresh live RPC")
                          : format_timestamp(*transition.data_refreshed_unix_ms))
       << "</div>"
       << "<div>Tx Count</div><div>" << transition.tx_count << "</div></div>"
       << "<div class=\"summary-actions\">"
       << copy_action("Copy Transition Hash", transition.hash)
       << copy_action("Copy Page Path", transition_path)
       << copy_action("Copy API Path", transition_api_path)
       << "</div></div>";

  body << "<div class=\"card\"><h2>Transactions</h2><div class=\"note\">This list contains finalized transaction ids only. Per-output interpretation lives on the individual transaction page.</div><div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Txid</th><th>Outputs</th></tr></thead><tbody>";
  for (std::size_t i = 0; i < transition.txids.size(); ++i) {
    body << "<tr><td>" << i << "</td><td>" << link_tx(transition.txids[i]) << "</td><td class=\"muted\">see tx page</td></tr>";
  }
  if (transition.txids.empty()) body << "<tr><td colspan=\"3\" class=\"muted\">No transactions were finalized in this transition.</td></tr>";
  body << "</tbody></table></div></div>";
  return page_layout("Transition " + transition.hash, body.str(), "transition");
}

std::string render_address(const Config& cfg, const std::string& addr, const std::map<std::string, std::string>& query) {
  std::ostringstream body;
  body << "<h1>Address</h1>";
  std::optional<std::uint64_t> start_after_height;
  std::optional<std::string> start_after_txid;
  if (auto it = query.find("after_height"); it != query.end() && !it->second.empty() && is_digits(it->second)) {
    try {
      start_after_height = static_cast<std::uint64_t>(std::stoull(it->second));
    } catch (...) {
    }
  }
  if (auto it = query.find("after_txid"); it != query.end() && is_hex64(it->second)) {
    start_after_txid = it->second;
  }
  auto lookup = fetch_address_result(cfg, addr, start_after_height, start_after_txid);
  if (!lookup.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Lookup failed: "
         << html_escape(lookup.error ? lookup.error->message : "unknown error") << "</div></div>";
    return page_layout("Address", body.str(), "address");
  }
  const auto& address = *lookup.value;
  const std::string address_path = "/address/" + addr;
  const std::string address_api_path = "/api/address/" + addr;
  std::uint64_t finalized_balance = 0;
  for (const auto& u : address.utxos) finalized_balance += u.amount;
  std::uint64_t received_total = 0;
  std::uint64_t sent_total = 0;
  std::uint64_t self_transfer_total = 0;
  for (const auto& item : address.history.items) {
    if (item.net_amount > 0 && item.direction == "received") received_total += static_cast<std::uint64_t>(item.net_amount);
    else if (item.net_amount < 0 && item.direction == "sent") sent_total += static_cast<std::uint64_t>(-item.net_amount);
    else if (item.direction == "self-transfer") {
      self_transfer_total += static_cast<std::uint64_t>(item.net_amount >= 0 ? item.net_amount : -item.net_amount);
    }
  }

  body << "<div class=\"card\"><div class=\"hero-metrics\">"
       << render_summary_metric_card("Finalized Balance", format_amount(finalized_balance), "current spendable UTXO set")
       << render_summary_metric_card("Received (Visible Slice)", format_amount(received_total), "credits in the current history view")
       << render_summary_metric_card("Sent (Visible Slice)", format_amount(sent_total), "debits in the current history view")
       << render_summary_metric_card("Self-Transfer (Visible Slice)", format_amount(self_transfer_total),
                                     "value recycled back to the same address in this view")
       << "</div></div>";
  body << "<div class=\"card\"><div class=\"status-hero\">"
       << "<div>" << mono_value(addr) << "</div><div>" << finalized_badge(true) << "</div></div>"
       << "<div class=\"note\">Address view is finalized-state only. It shows current finalized UTXOs plus a paginated finalized-history slice, not live mempool activity.</div>"
       << "<div class=\"grid\" style=\"margin-top:14px;\">"
       << "<div>Address</div><div class=\"value-cell\">" << mono_value(addr) << "</div>"
       << "<div>Finalized Activity</div><div>" << (address.found ? "yes" : "no") << "</div>"
       << "<div>Finalized UTXOs</div><div>" << address.utxos.size() << "</div>"
       << "<div>Finalized Balance</div><div>" << html_escape(format_amount(finalized_balance)) << "</div>"
       << "<div>History Items (View)</div><div>" << address.history.items.size() << "</div>"
       << "<div>History Pages Loaded</div><div>" << address.history.loaded_pages << "</div>"
       << "<div>History Slice Complete</div><div>" << (address.history.has_more ? "no" : "yes") << "</div>";
  if (start_after_height.has_value() && start_after_txid.has_value()) {
    body << "<div>History Position</div><div>Showing older activity after height <code>" << *start_after_height
         << "</code> and tx <code>" << html_escape(short_hex(*start_after_txid)) << "</code></div>";
  }
  body << "</div><div class=\"summary-actions\">"
       << copy_action("Copy Address", addr)
       << copy_action("Copy Page Path", address_path)
       << copy_action("Copy API Path", address_api_path)
       << "</div></div>";

  body << "<div class=\"card\"><h2>Current UTXOs</h2><div class=\"table-wrap\"><table><thead><tr><th>Txid</th><th>Vout</th><th>Amount</th><th>Height</th></tr></thead><tbody>";
  if (!address.utxos.empty()) {
    for (const auto& u : address.utxos) {
      body << "<tr><td>" << link_tx(u.txid) << "</td><td>" << u.vout << "</td><td>"
           << amount_span(u.amount, "amount-in") << "</td><td>" << link_transition_height(u.height) << "</td></tr>";
    }
  } else {
    body << "<tr><td colspan=\"4\" class=\"muted\">No finalized UTXOs found.</td></tr>";
  }
  body << "</tbody></table></div></div>";

  body << "<div class=\"card\"><h2>Finalized History</h2><div class=\"note\">Each row is interpreted relative to this address only, using finalized inputs and outputs.</div><div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Txid</th><th>Height</th><th>Direction</th><th>Net Amount</th><th>Detail</th></tr></thead><tbody>";
  if (!address.history.items.empty()) {
    for (std::size_t i = 0; i < address.history.items.size(); ++i) {
      const auto& item = address.history.items[i];
      const char* amount_class = item.net_amount > 0 ? "amount-in" : (item.net_amount < 0 ? "amount-out" : "muted");
      body << "<tr><td>" << i << "</td><td>" << link_tx(item.txid) << "</td><td>" << link_transition_height(item.height)
           << "</td><td><strong>" << html_escape(item.direction) << "</strong></td><td class=\"" << amount_class << "\">"
           << html_escape(format_signed_amount(item.net_amount)) << "</td><td>" << html_escape(item.detail) << "</td></tr>";
    }
  } else {
    body << "<tr><td colspan=\"6\" class=\"muted\">No finalized history found.</td></tr>";
  }
  body << "</tbody></table></div></div>";
  if (address.history.has_more) {
    body << "<div class=\"card\"><div class=\"note\">Additional finalized history exists. ";
    if (address.history.next_page_path.has_value()) {
      body << "<a href=\"" << html_escape(*address.history.next_page_path) << "\">Load older finalized activity</a>";
    } else {
      body << "Load another older page from the API.";
    }
    body << "</div>";
    if (address.history.next_cursor.has_value()) {
      body << "<div style=\"margin-top:10px;\" class=\"muted\">Machine cursor: <code>" << html_escape(*address.history.next_cursor)
           << "</code></div>";
    }
    body << "</div>";
  }

  return page_layout("Address " + addr, body.str(), "address");
}

bool write_all(finalis::net::SocketHandle fd, const std::string& data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
    if (n <= 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

std::optional<std::string> read_http_request(finalis::net::SocketHandle fd) {
  std::string req;
  std::array<char, 4096> buf{};
  while (req.find("\r\n\r\n") == std::string::npos) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return std::nullopt;
    req.append(buf.data(), static_cast<std::size_t>(n));
    if (req.size() > kMaxHttpHeaderBytes) return std::nullopt;
  }
  const auto hdr_end = req.find("\r\n\r\n");
  const std::string headers = req.substr(0, hdr_end);
  std::regex cl_re("Content-Length:\\s*([0-9]+)", std::regex_constants::icase);
  std::smatch m;
  std::size_t content_len = 0;
  if (std::regex_search(headers, m, cl_re)) {
    try {
      content_len = static_cast<std::size_t>(std::stoull(m[1].str()));
    } catch (...) {
      return std::nullopt;
    }
  }
  if (content_len > kMaxHttpBodyBytes) return std::nullopt;
  while (req.size() < hdr_end + 4 + content_len) {
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) return std::nullopt;
    req.append(buf.data(), static_cast<std::size_t>(n));
  }
  return req;
}

std::string status_text_for_http(int status) {
  switch (status) {
    case 200:
      return "OK";
    case 302:
      return "Found";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 409:
      return "Conflict";
    case 429:
      return "Too Many Requests";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 500:
      return "Internal Server Error";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    default:
      return "Error";
  }
}

std::string http_response(const Response& resp) {
  std::ostringstream oss;
  oss << "HTTP/1.1 " << resp.status << " " << status_text_for_http(resp.status) << "\r\n"
      << "Content-Type: " << resp.content_type << "\r\n"
      << "Content-Length: " << resp.body.size() << "\r\n";
  if (resp.location.has_value()) oss << "Location: " << *resp.location << "\r\n";
  for (const auto& [k, v] : resp.headers) oss << k << ": " << v << "\r\n";
  oss << "Connection: close\r\n\r\n" << resp.body;
  return oss.str();
}

std::string render_not_found() {
  return page_layout("Not Found", "<h1>Not Found</h1><div class=\"card\"><div class=\"note\">Unknown route.</div></div>");
}

std::string request_target_for_log(const std::optional<std::string>& req) {
  if (!req.has_value()) return "(unparsed)";
  const auto line_end = req->find("\r\n");
  if (line_end == std::string::npos) return "(malformed)";
  const std::string first = req->substr(0, line_end);
  const auto sp1 = first.find(' ');
  const auto sp2 = first.rfind(' ');
  if (sp1 == std::string::npos || sp2 == std::string::npos || sp1 == sp2) return "(malformed)";
  return first.substr(sp1 + 1, sp2 - sp1 - 1);
}

std::string path_from_target(const std::string& target) {
  const auto q = target.find('?');
  return url_decode(q == std::string::npos ? target : target.substr(0, q));
}

bool partner_auth_needed(const std::string& path) {
  if (path.rfind("/api/v1/", 0) != 0) return false;
  if (path == "/api/v1/status" || path == "/api/v1/fees/recommendation") return false;
  return true;
}

std::optional<std::string> partner_required_scope(const std::string& method, const std::string& path) {
  if (path == "/api/v1/withdrawals" && method == "POST") return std::string("withdraw_submit");
  if (path == "/api/v1/events/finalized") return std::string("events_read");
  if (path == "/api/v1/webhooks/dlq" || path == "/api/v1/webhooks/dlq/replay") return std::string("webhook_manage");
  if (partner_auth_needed(path)) return std::string("read");
  return std::nullopt;
}

std::string normalize_partner_lifecycle_state(const std::string& value) {
  const auto lowered = lowercase_ascii(value);
  if (lowered == "active" || lowered == "draining" || lowered == "revoked") return lowered;
  return {};
}

struct ParsedIpv4Cidr {
  std::uint32_t network{0};
  std::uint32_t mask{0};
};

std::optional<ParsedIpv4Cidr> parse_ipv4_cidr(const std::string& raw) {
  const auto slash = raw.find('/');
  std::string ip = slash == std::string::npos ? raw : raw.substr(0, slash);
  std::uint32_t prefix = 32;
  if (slash != std::string::npos) {
    auto parsed_prefix = parse_u64_strict(raw.substr(slash + 1));
    if (!parsed_prefix.has_value() || *parsed_prefix > 32) return std::nullopt;
    prefix = static_cast<std::uint32_t>(*parsed_prefix);
  }
  in_addr addr{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return std::nullopt;
  const std::uint32_t host = ntohl(addr.s_addr);
  const std::uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
  ParsedIpv4Cidr out;
  out.network = host & mask;
  out.mask = mask;
  return out;
}

bool ip_in_cidrs(const std::string& ip, const std::vector<std::string>& cidrs_raw) {
  if (cidrs_raw.empty()) return true;
  in_addr addr{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
  const std::uint32_t host = ntohl(addr.s_addr);
  for (const auto& raw : cidrs_raw) {
    auto parsed = parse_ipv4_cidr(raw);
    if (!parsed.has_value()) continue;
    if ((host & parsed->mask) == parsed->network) return true;
  }
  return false;
}

bool mtls_verified(const HttpRequest& req) {
  const auto verified = header_value(req, "x-finalis-mtls-verified");
  if (!verified.has_value()) return false;
  const auto value = lowercase_ascii(*verified);
  return value == "1" || value == "true" || value == "yes";
}

bool principal_has_scope(const PartnerPrincipal& principal, const std::string& scope) {
  if (principal.scopes.empty()) return true;
  return principal.scopes.count(scope) > 0;
}

std::string partner_scoped_id(const std::string& partner_id, const std::string& id) {
  return partner_id + ":" + id;
}

std::uint64_t ttl_ms_saturated(std::uint64_t ttl_seconds) {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  if (ttl_seconds == 0) return 0;
  if (ttl_seconds > (kMax / 1000)) return kMax;
  return ttl_seconds * 1000;
}

bool prune_partner_state_locked(const Config& cfg, std::uint64_t now_ms) {
  bool changed = false;
  const std::uint64_t now_sec = now_ms / 1000;
  const std::uint64_t nonce_keep_window = std::max<std::uint64_t>(cfg.partner_auth_max_skew_seconds * 2, 60);
  const std::uint64_t nonce_keep_after = now_sec > nonce_keep_window ? (now_sec - nonce_keep_window) : 0;
  for (auto it = g_seen_partner_nonce_unix_ms.begin(); it != g_seen_partner_nonce_unix_ms.end();) {
    if (it->second < nonce_keep_after) {
      it = g_seen_partner_nonce_unix_ms.erase(it);
      changed = true;
    } else {
      ++it;
    }
  }

  const std::uint64_t idem_ttl_ms = ttl_ms_saturated(cfg.partner_idempotency_ttl_seconds);
  for (auto it = g_partner_idempotency_hash.begin(); it != g_partner_idempotency_hash.end();) {
    auto ts_it = g_partner_idempotency_unix_ms.find(it->first);
    if (ts_it == g_partner_idempotency_unix_ms.end()) {
      g_partner_idempotency_unix_ms[it->first] = now_ms;
      ts_it = g_partner_idempotency_unix_ms.find(it->first);
      changed = true;
    }
    const bool expired = idem_ttl_ms != 0 && now_ms > ts_it->second && (now_ms - ts_it->second) > idem_ttl_ms;
    if (expired) {
      g_partner_idempotency_client_id.erase(it->first);
      g_partner_idempotency_unix_ms.erase(it->first);
      it = g_partner_idempotency_hash.erase(it);
      changed = true;
    } else {
      ++it;
    }
  }
  for (auto it = g_partner_idempotency_client_id.begin(); it != g_partner_idempotency_client_id.end();) {
    if (!g_partner_idempotency_hash.count(it->first)) {
      it = g_partner_idempotency_client_id.erase(it);
      changed = true;
    } else {
      ++it;
    }
  }
  for (auto it = g_partner_idempotency_unix_ms.begin(); it != g_partner_idempotency_unix_ms.end();) {
    if (!g_partner_idempotency_hash.count(it->first)) {
      it = g_partner_idempotency_unix_ms.erase(it);
      changed = true;
    } else {
      ++it;
    }
  }
  if (g_partner_idempotency_hash.size() > kPersistedPartnerIdempotencyLimit) {
    std::vector<std::pair<std::uint64_t, std::string>> ordered;
    ordered.reserve(g_partner_idempotency_hash.size());
    for (const auto& [key, _] : g_partner_idempotency_hash) {
      auto ts_it = g_partner_idempotency_unix_ms.find(key);
      ordered.push_back({ts_it == g_partner_idempotency_unix_ms.end() ? 0 : ts_it->second, key});
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
      if (a.first != b.first) return a.first < b.first;
      return a.second < b.second;
    });
    const std::size_t trim = ordered.size() - kPersistedPartnerIdempotencyLimit;
    for (std::size_t i = 0; i < trim; ++i) {
      const auto& key = ordered[i].second;
      g_partner_idempotency_hash.erase(key);
      g_partner_idempotency_client_id.erase(key);
      g_partner_idempotency_unix_ms.erase(key);
      changed = true;
    }
  }

  const std::uint64_t event_ttl_ms = ttl_ms_saturated(cfg.partner_events_ttl_seconds);
  if (event_ttl_ms != 0) {
    while (!g_partner_events.empty()) {
      const auto emitted = g_partner_events.front().emitted_unix_ms;
      if (now_ms >= emitted && (now_ms - emitted) > event_ttl_ms) {
        g_partner_events.erase(g_partner_events.begin());
        changed = true;
      } else {
        break;
      }
    }
  }
  if (g_partner_events.size() > kPersistedPartnerEventsLimit) {
    g_partner_events.erase(g_partner_events.begin(),
                           g_partner_events.end() - static_cast<std::ptrdiff_t>(kPersistedPartnerEventsLimit));
    changed = true;
  }
  std::uint64_t max_seq = 0;
  for (const auto& evt : g_partner_events) max_seq = std::max(max_seq, evt.sequence);
  const std::uint64_t min_next_seq = max_seq + 1;
  if (g_partner_next_sequence < min_next_seq) {
    g_partner_next_sequence = min_next_seq;
    changed = true;
  } else if (g_partner_next_sequence == 0) {
    g_partner_next_sequence = 1;
    changed = true;
  }

  const std::uint64_t queue_ttl_ms = ttl_ms_saturated(cfg.partner_webhook_queue_ttl_seconds);
  std::deque<PartnerWebhookDelivery> rebuilt_queue;
  std::unordered_map<std::string, std::size_t> queue_index;
  rebuilt_queue.clear();
  for (const auto& entry : g_partner_webhook_queue) {
    PartnerWebhookDelivery job = entry;
    if (job.enqueued_unix_ms == 0) job.enqueued_unix_ms = job.next_attempt_unix_ms ? job.next_attempt_unix_ms : now_ms;
    const bool too_old = queue_ttl_ms != 0 && now_ms > job.enqueued_unix_ms && (now_ms - job.enqueued_unix_ms) > queue_ttl_ms;
    if (too_old || job.attempt >= cfg.partner_webhook_max_attempts) {
      changed = true;
      continue;
    }
    const std::string queue_key = partner_scoped_id(job.partner_id, std::to_string(job.sequence));
    auto seen = queue_index.find(queue_key);
    if (seen == queue_index.end()) {
      queue_index.emplace(queue_key, rebuilt_queue.size());
      rebuilt_queue.push_back(std::move(job));
      continue;
    }
    PartnerWebhookDelivery& prior = rebuilt_queue[seen->second];
    const bool prefer_new = (job.attempt < prior.attempt) ||
                            (job.attempt == prior.attempt && job.next_attempt_unix_ms < prior.next_attempt_unix_ms);
    if (prefer_new) prior = std::move(job);
    changed = true;
  }
  if (rebuilt_queue.size() > kPersistedPartnerWebhookQueueLimit) {
    rebuilt_queue.erase(rebuilt_queue.begin(),
                        rebuilt_queue.end() - static_cast<std::ptrdiff_t>(kPersistedPartnerWebhookQueueLimit));
    changed = true;
  }
  if (changed) g_partner_webhook_queue = std::move(rebuilt_queue);
  std::deque<PartnerWebhookDlqEntry> rebuilt_dlq;
  for (const auto& entry : g_partner_webhook_dlq) {
    const std::uint64_t ref_ts = entry.failed_unix_ms ? entry.failed_unix_ms : entry.enqueued_unix_ms;
    const bool too_old = queue_ttl_ms != 0 && ref_ts != 0 && now_ms > ref_ts && (now_ms - ref_ts) > queue_ttl_ms;
    if (too_old) {
      changed = true;
      continue;
    }
    rebuilt_dlq.push_back(entry);
  }
  if (rebuilt_dlq.size() > kPersistedPartnerWebhookQueueLimit) {
    rebuilt_dlq.erase(rebuilt_dlq.begin(),
                      rebuilt_dlq.end() - static_cast<std::ptrdiff_t>(kPersistedPartnerWebhookQueueLimit));
    changed = true;
  }
  if (changed) g_partner_webhook_dlq = std::move(rebuilt_dlq);
  return changed;
}

std::optional<PartnerAuthRecord> resolve_partner_record_for_api_key(const Config& cfg, const std::string& api_key) {
  std::lock_guard<std::mutex> guard(g_partner_mu);
  auto it = g_partner_by_api_key.find(api_key);
  if (it != g_partner_by_api_key.end()) return it->second;
  if (!cfg.partner_api_key.empty() && secure_equal(api_key, cfg.partner_api_key)) {
    PartnerAuthRecord single;
    single.partner_id = "default";
    single.api_key = cfg.partner_api_key;
    single.active_secret = cfg.partner_api_secret;
    single.lifecycle_state = "active";
    single.scopes = {"read", "withdraw_submit", "events_read", "webhook_manage"};
    single.allowed_ipv4_cidrs_raw = cfg.partner_allowed_ipv4_cidrs_raw;
    single.enabled = true;
    return single;
  }
  return std::nullopt;
}

std::optional<ApiError> verify_partner_auth(const Config& cfg, const HttpRequest& req, const std::string& path,
                                            const std::string& client_ip, PartnerPrincipal* out_principal) {
  if (out_principal) {
    out_principal->partner_id = "default";
    out_principal->api_key.clear();
    out_principal->rate_limit_per_minute = cfg.partner_rate_limit_per_minute;
    out_principal->authenticated = false;
  }
  if (!cfg.partner_auth_required || !partner_auth_needed(path)) return std::nullopt;
  if (cfg.partner_mtls_required && !mtls_verified(req)) {
    record_partner_auth_failure_metric("auth_mtls_required");
    return make_error(401, "auth_mtls_required", "mTLS verification header missing");
  }
  const auto api_key = header_value(req, "x-finalis-api-key");
  const auto timestamp = header_value(req, "x-finalis-timestamp");
  const auto nonce = header_value(req, "x-finalis-nonce");
  const auto signature = header_value(req, "x-finalis-signature");
  if (!api_key.has_value() || !timestamp.has_value() || !nonce.has_value() || !signature.has_value()) {
    record_partner_auth_failure_metric("auth_missing");
    return make_error(401, "auth_missing", "missing partner auth headers");
  }
  const auto record = resolve_partner_record_for_api_key(cfg, *api_key);
  if (!record.has_value() || !record->enabled) {
    record_partner_auth_failure_metric("auth_invalid_key");
    return make_error(403, "auth_invalid_key", "invalid partner api key");
  }
  if (record->lifecycle_state == "revoked") {
    record_partner_auth_failure_metric("auth_partner_revoked");
    return make_error(403, "auth_partner_revoked", "partner credentials are revoked");
  }
  if (record->lifecycle_state == "draining") {
    const auto needed_scope = partner_required_scope(req.method, path);
    if (needed_scope.has_value() && *needed_scope == "withdraw_submit") {
      record_partner_auth_failure_metric("auth_partner_draining");
      return make_error(403, "auth_partner_draining", "partner is in draining state; withdrawal submission disabled");
    }
  }
  const auto& allowed_cidrs = record->allowed_ipv4_cidrs_raw.empty() ? cfg.partner_allowed_ipv4_cidrs_raw : record->allowed_ipv4_cidrs_raw;
  if (!ip_in_cidrs(client_ip, allowed_cidrs)) {
    record_partner_auth_failure_metric("auth_ip_forbidden");
    return make_error(403, "auth_ip_forbidden", "source IP not in partner allowlist");
  }
  const auto ts = parse_u64_strict(*timestamp);
  if (!ts.has_value()) {
    record_partner_auth_failure_metric("auth_bad_timestamp");
    return make_error(401, "auth_bad_timestamp", "timestamp must be unix seconds");
  }
  const std::uint64_t now_sec = static_cast<std::uint64_t>(std::time(nullptr));
  const std::uint64_t skew = now_sec > *ts ? (now_sec - *ts) : (*ts - now_sec);
  if (skew > cfg.partner_auth_max_skew_seconds) {
    record_partner_auth_failure_metric("auth_timestamp_skew");
    return make_error(401, "auth_timestamp_skew", "timestamp outside allowed window");
  }
  const std::string canonical = req.method + "\n" + path + "\n" + *timestamp + "\n" + *nonce + "\n" + sha256_hex_text(req.body);
  const auto expected_active = hmac_sha256_hex(record->active_secret, canonical);
  bool valid_sig = expected_active.has_value() &&
                   secure_equal(lowercase_ascii(*signature), lowercase_ascii(*expected_active));
  if (!valid_sig && record->next_secret.has_value()) {
    const auto expected_next = hmac_sha256_hex(*record->next_secret, canonical);
    valid_sig = expected_next.has_value() && secure_equal(lowercase_ascii(*signature), lowercase_ascii(*expected_next));
  }
  if (!valid_sig) {
    record_partner_auth_failure_metric("auth_bad_signature");
    return make_error(403, "auth_bad_signature", "invalid partner signature");
  }
  bool nonce_window_updated = false;
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    const std::string nonce_key = partner_scoped_id(record->partner_id, *nonce);
    auto it = g_seen_partner_nonce_unix_ms.find(nonce_key);
    if (it != g_seen_partner_nonce_unix_ms.end() && (now_sec > it->second ? now_sec - it->second : it->second - now_sec) <=
            cfg.partner_auth_max_skew_seconds) {
      record_partner_auth_failure_metric("auth_replay");
      return make_error(409, "auth_replay", "nonce replay detected");
    }
    g_seen_partner_nonce_unix_ms[nonce_key] = now_sec;
    const std::uint64_t keep_after = now_sec > (cfg.partner_auth_max_skew_seconds * 2)
                                         ? (now_sec - cfg.partner_auth_max_skew_seconds * 2)
                                         : 0;
    for (auto iter = g_seen_partner_nonce_unix_ms.begin(); iter != g_seen_partner_nonce_unix_ms.end();) {
      if (iter->second < keep_after) iter = g_seen_partner_nonce_unix_ms.erase(iter);
      else ++iter;
    }
    nonce_window_updated = true;
  }
  if (nonce_window_updated) persist_explorer_snapshot(cfg);
  if (out_principal) {
    out_principal->partner_id = record->partner_id;
    out_principal->api_key = record->api_key;
    out_principal->rate_limit_per_minute = record->rate_limit_per_minute.value_or(cfg.partner_rate_limit_per_minute);
    out_principal->scopes = record->scopes;
    out_principal->allowed_ipv4_cidrs_raw = allowed_cidrs;
    out_principal->authenticated = true;
  }
  return std::nullopt;
}

std::optional<ApiError> enforce_partner_rate_limit(const Config& cfg, const HttpRequest& req, const PartnerPrincipal& principal,
                                                   Response* out_response) {
  if (!partner_auth_needed(path_from_target(req.target))) return std::nullopt;
  const std::string bucket = principal.partner_id.empty() ? "default" : principal.partner_id;
  const std::uint64_t now_ms = now_unix_ms();
  std::uint64_t retry_after_s = 0;
  const std::uint64_t limit = principal.rate_limit_per_minute == 0 ? cfg.partner_rate_limit_per_minute : principal.rate_limit_per_minute;
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    auto& window = g_partner_rate_windows_ms[bucket];
    while (!window.empty() && window.front() + 60'000 <= now_ms) window.pop_front();
    if (window.size() >= limit) {
      retry_after_s = window.empty() ? 1 : std::max<std::uint64_t>(1, (window.front() + 60'000 - now_ms + 999) / 1000);
    } else {
      window.push_back(now_ms);
    }
  }
  if (retry_after_s != 0) {
    std::lock_guard<std::mutex> guard(g_metrics_mu);
    ++g_metrics_partner_rate_limited_total;
    if (out_response) out_response->headers.push_back({"Retry-After", std::to_string(retry_after_s)});
    return make_error(429, "rate_limited", "partner rate limit exceeded");
  }
  return std::nullopt;
}

std::optional<PartnerWithdrawal> find_partner_withdrawal_by_any_id(const std::string& partner_id, const std::string& id) {
  std::lock_guard<std::mutex> guard(g_partner_mu);
  auto it = g_partner_withdrawals_by_client_id.find(partner_scoped_id(partner_id, id));
  if (it != g_partner_withdrawals_by_client_id.end()) return it->second;
  auto txit = g_partner_client_id_by_txid.find(partner_scoped_id(partner_id, id));
  if (txit == g_partner_client_id_by_txid.end()) return std::nullopt;
  auto wit = g_partner_withdrawals_by_client_id.find(txit->second);
  if (wit == g_partner_withdrawals_by_client_id.end()) return std::nullopt;
  return wit->second;
}

void upsert_partner_withdrawal(const Config& cfg, const PartnerWithdrawal& withdrawal) {
  bool persist_needed = false;
  bool notify_webhook = false;
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
  const auto scoped_client = partner_scoped_id(withdrawal.partner_id, withdrawal.client_withdrawal_id);
  const auto scoped_txid = partner_scoped_id(withdrawal.partner_id, withdrawal.txid);
  const auto prev = g_partner_withdrawals_by_client_id.find(scoped_client);
  const bool state_changed = prev == g_partner_withdrawals_by_client_id.end() || prev->second.state != withdrawal.state;
  g_partner_client_id_by_txid[scoped_txid] = scoped_client;
  g_partner_withdrawals_by_client_id[scoped_client] = withdrawal;
  persist_needed = true;
  if (state_changed) {
    push_partner_event(withdrawal.partner_id, "withdrawal_state_changed", withdrawal.client_withdrawal_id, withdrawal.state);
  }
  if (state_changed && withdrawal.state == "finalized") {
    auto pit = g_partner_by_id.find(withdrawal.partner_id);
    if (pit != g_partner_by_id.end() && pit->second.webhook_url.has_value() && pit->second.webhook_secret.has_value()) {
      const PartnerEvent& evt = g_partner_events.back();
      const std::string evt_json = partner_event_json(evt);
      const auto sig = hmac_sha256_hex(*pit->second.webhook_secret, evt_json);
      if (sig.has_value()) {
        std::ostringstream payload;
        payload << "{\"event\":" << evt_json << ",\"signature\":\"" << json_escape(*sig) << "\",\"signature_algorithm\":\"hmac_sha256\"}";
        PartnerWebhookDelivery d;
        d.partner_id = withdrawal.partner_id;
        d.sequence = evt.sequence;
        d.url = *pit->second.webhook_url;
        d.payload_json = payload.str();
        d.attempt = 0;
        d.enqueued_unix_ms = now_unix_ms();
        d.next_attempt_unix_ms = now_unix_ms();
        const auto duplicate = std::find_if(g_partner_webhook_queue.begin(), g_partner_webhook_queue.end(),
                                            [&](const PartnerWebhookDelivery& queued) {
                                              return queued.partner_id == d.partner_id && queued.sequence == d.sequence;
                                            });
        if (duplicate == g_partner_webhook_queue.end()) {
          g_partner_webhook_queue.push_back(std::move(d));
          notify_webhook = true;
        }
      }
    }
  }
  }
  if (notify_webhook) g_partner_webhook_cv.notify_one();
  if (persist_needed) persist_explorer_snapshot(cfg);
}

PartnerWithdrawal refresh_partner_withdrawal_state(const Config& cfg, PartnerWithdrawal withdrawal) {
  if (withdrawal.state == "finalized" || withdrawal.state == "rejected") return withdrawal;
  auto tx = fetch_tx_result(cfg, withdrawal.txid);
  if (tx.value.has_value() && tx.value->finalized && tx.value->credit_safe) {
    withdrawal.state = "finalized";
    withdrawal.finalized_height = tx.value->finalized_height;
    withdrawal.transition_hash = tx.value->transition_hash;
    withdrawal.retryable = false;
    withdrawal.retry_class = "none";
    withdrawal.updated_unix_ms = now_unix_ms();
    upsert_partner_withdrawal(cfg, withdrawal);
  }
  return withdrawal;
}

Response render_metrics_response() {
  std::ostringstream oss;
  oss << "# HELP finalis_http_requests_total HTTP requests by route and status\n"
      << "# TYPE finalis_http_requests_total counter\n"
      << "# HELP finalis_http_request_duration_milliseconds Request duration histogram in milliseconds\n"
      << "# TYPE finalis_http_request_duration_milliseconds histogram\n"
      << "# HELP finalis_partner_auth_failures_total Partner auth failures\n"
      << "# TYPE finalis_partner_auth_failures_total counter\n"
      << "# HELP finalis_partner_auth_failures_by_reason_total Partner auth failures by reason code\n"
      << "# TYPE finalis_partner_auth_failures_by_reason_total counter\n"
      << "# HELP finalis_partner_webhook_delivery_latency_seconds End-to-end webhook delivery latency histogram by outcome\n"
      << "# TYPE finalis_partner_webhook_delivery_latency_seconds histogram\n";
  std::uint64_t webhook_queue_depth = 0;
  std::uint64_t webhook_dlq_depth = 0;
  std::uint64_t webhook_oldest_age_seconds = 0;
  std::unordered_map<std::string, std::uint64_t> webhook_queue_depth_by_partner;
  std::unordered_map<std::string, std::uint64_t> webhook_dlq_depth_by_partner;
  std::unordered_map<std::string, std::uint64_t> webhook_oldest_age_seconds_by_partner;
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    webhook_queue_depth = static_cast<std::uint64_t>(g_partner_webhook_queue.size());
    webhook_dlq_depth = static_cast<std::uint64_t>(g_partner_webhook_dlq.size());
    const auto now = now_unix_ms();
    for (const auto& d : g_partner_webhook_queue) {
      ++webhook_queue_depth_by_partner[d.partner_id];
      if (d.enqueued_unix_ms == 0 || now < d.enqueued_unix_ms) continue;
      const auto age = (now - d.enqueued_unix_ms) / 1000;
      webhook_oldest_age_seconds = std::max<std::uint64_t>(webhook_oldest_age_seconds, age);
      webhook_oldest_age_seconds_by_partner[d.partner_id] =
          std::max<std::uint64_t>(webhook_oldest_age_seconds_by_partner[d.partner_id], age);
    }
    for (const auto& d : g_partner_webhook_dlq) ++webhook_dlq_depth_by_partner[d.partner_id];
  }
  {
    std::lock_guard<std::mutex> guard(g_metrics_mu);
    for (const auto& [key, count] : g_metrics_http_requests_total) {
      const auto sep = key.rfind('|');
      const std::string route = sep == std::string::npos ? key : key.substr(0, sep);
      const std::string status = sep == std::string::npos ? "0" : key.substr(sep + 1);
      oss << "finalis_http_requests_total{route=\"" << json_escape(route) << "\",status=\"" << json_escape(status) << "\"} "
          << count << "\n";
    }
    for (const auto& [key, count] : g_metrics_http_request_duration_bucket_ms) {
      const auto sep = key.rfind('|');
      const std::string route = sep == std::string::npos ? key : key.substr(0, sep);
      const std::string le = sep == std::string::npos ? "0" : key.substr(sep + 1);
      oss << "finalis_http_request_duration_milliseconds_bucket{route=\"" << json_escape(route) << "\",le=\"" << json_escape(le)
          << "\"} " << count << "\n";
    }
    for (const auto& [route, sum] : g_metrics_http_request_duration_sum_ms) {
      oss << "finalis_http_request_duration_milliseconds_sum{route=\"" << json_escape(route) << "\"} " << sum << "\n";
    }
    for (const auto& [route, cnt] : g_metrics_http_request_duration_count) {
      oss << "finalis_http_request_duration_milliseconds_count{route=\"" << json_escape(route) << "\"} " << cnt << "\n";
    }
    oss << "finalis_partner_auth_failures_total " << g_metrics_partner_auth_failures_total << "\n";
    for (const auto& [reason, count] : g_metrics_partner_auth_failures_by_reason_total) {
      oss << "finalis_partner_auth_failures_by_reason_total{reason=\"" << json_escape(reason) << "\"} " << count << "\n";
    }
    oss << "finalis_partner_rate_limited_total " << g_metrics_partner_rate_limited_total << "\n";
    oss << "finalis_partner_withdrawal_submissions_total " << g_metrics_partner_withdrawal_submissions_total << "\n";
    oss << "finalis_partner_webhook_deliveries_total " << g_metrics_partner_webhook_deliveries_total << "\n";
    oss << "finalis_partner_webhook_failures_total " << g_metrics_partner_webhook_failures_total << "\n";
    oss << "finalis_partner_webhook_dlq_total " << g_metrics_partner_webhook_dlq_total << "\n";
    oss << "finalis_partner_webhook_replays_total " << g_metrics_partner_webhook_replays_total << "\n";
    for (const auto& [key, count] : g_metrics_partner_webhook_delivery_latency_bucket_seconds) {
      const auto sep = key.rfind('|');
      const std::string outcome = sep == std::string::npos ? key : key.substr(0, sep);
      const std::string le = sep == std::string::npos ? "0" : key.substr(sep + 1);
      oss << "finalis_partner_webhook_delivery_latency_seconds_bucket{outcome=\"" << json_escape(outcome)
          << "\",le=\"" << json_escape(le) << "\"} " << count << "\n";
    }
    for (const auto& [outcome, count] : g_metrics_partner_webhook_delivery_latency_count) {
      oss << "finalis_partner_webhook_delivery_latency_seconds_bucket{outcome=\"" << json_escape(outcome)
          << "\",le=\"+Inf\"} " << count << "\n";
    }
    for (const auto& [outcome, sum] : g_metrics_partner_webhook_delivery_latency_sum_seconds) {
      oss << "finalis_partner_webhook_delivery_latency_seconds_sum{outcome=\"" << json_escape(outcome) << "\"} " << sum << "\n";
    }
    for (const auto& [outcome, count] : g_metrics_partner_webhook_delivery_latency_count) {
      oss << "finalis_partner_webhook_delivery_latency_seconds_count{outcome=\"" << json_escape(outcome) << "\"} " << count << "\n";
    }
  }
  oss << "finalis_partner_webhook_queue_depth " << webhook_queue_depth << "\n";
  oss << "finalis_partner_webhook_dlq_depth " << webhook_dlq_depth << "\n";
  oss << "finalis_partner_webhook_oldest_age_seconds " << webhook_oldest_age_seconds << "\n";
  for (const auto& [partner_id, depth] : webhook_queue_depth_by_partner) {
    oss << "finalis_partner_webhook_queue_depth_by_partner{partner_id=\"" << json_escape(partner_id) << "\"} " << depth << "\n";
  }
  for (const auto& [partner_id, depth] : webhook_dlq_depth_by_partner) {
    oss << "finalis_partner_webhook_dlq_depth_by_partner{partner_id=\"" << json_escape(partner_id) << "\"} " << depth << "\n";
  }
  for (const auto& [partner_id, age] : webhook_oldest_age_seconds_by_partner) {
    oss << "finalis_partner_webhook_oldest_age_seconds_by_partner{partner_id=\"" << json_escape(partner_id) << "\"} " << age << "\n";
  }
  Response resp;
  resp.status = 200;
  resp.content_type = "text/plain; version=0.0.4; charset=utf-8";
  resp.body = oss.str();
  return resp;
}

bool load_partner_registry(const Config& cfg, std::string* err) {
  if (cfg.partner_registry_path.empty()) return true;
  std::ifstream in(cfg.partner_registry_path);
  if (!in) {
    if (err) *err = "failed to open partner registry";
    return false;
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  auto root = finalis::minijson::parse(oss.str());
  if (!root.has_value() || !root->is_object()) {
    if (err) *err = "partner registry must be a JSON object";
    return false;
  }
  const auto* partners = root->get("partners");
  if (!partners || !partners->is_array()) {
    if (err) *err = "partner registry must contain partners array";
    return false;
  }
  std::unordered_map<std::string, PartnerAuthRecord> by_key;
  std::unordered_map<std::string, PartnerAuthRecord> by_id;
  for (const auto& p : partners->array_value) {
    if (!p.is_object()) {
      if (err) *err = "partner entry must be object";
      return false;
    }
    const auto partner_id = object_string(&p, "partner_id");
    const auto api_key = object_string(&p, "api_key");
    const auto active_secret = object_string(&p, "active_secret");
    if (!partner_id.has_value() || partner_id->empty() || !api_key.has_value() || api_key->empty() || !active_secret.has_value() ||
        active_secret->empty()) {
      if (err) *err = "partner entry missing partner_id/api_key/active_secret";
      return false;
    }
    PartnerAuthRecord rec;
    rec.partner_id = *partner_id;
    rec.api_key = *api_key;
    rec.active_secret = *active_secret;
    rec.next_secret = object_string(&p, "next_secret");
    rec.lifecycle_state = "active";
    if (const auto lifecycle = object_string(&p, "lifecycle_state"); lifecycle.has_value()) {
      const auto normalized = normalize_partner_lifecycle_state(*lifecycle);
      if (normalized.empty()) {
        if (err) *err = "invalid lifecycle_state in registry (expected active|draining|revoked)";
        return false;
      }
      rec.lifecycle_state = normalized;
    }
    rec.rate_limit_per_minute = object_u64(&p, "rate_limit_per_minute");
    rec.webhook_url = object_string(&p, "webhook_url");
    rec.webhook_secret = object_string(&p, "webhook_secret");
    if (const auto* scopes = p.get("scopes"); scopes && scopes->is_array()) {
      for (const auto& s : scopes->array_value) {
        if (s.is_string() && !s.string_value.empty()) rec.scopes.insert(s.string_value);
      }
    }
    if (const auto* cidrs = p.get("allowed_ipv4_cidrs"); cidrs && cidrs->is_array()) {
      for (const auto& c : cidrs->array_value) {
        if (c.is_string() && !c.string_value.empty()) rec.allowed_ipv4_cidrs_raw.push_back(c.string_value);
      }
    }
    rec.enabled = object_bool(&p, "enabled").value_or(true);
    if (by_key.count(rec.api_key) || by_id.count(rec.partner_id)) {
      if (err) *err = "duplicate partner_id or api_key in registry";
      return false;
    }
    by_key[rec.api_key] = rec;
    by_id[rec.partner_id] = rec;
  }
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    g_partner_by_api_key = std::move(by_key);
    g_partner_by_id = std::move(by_id);
  }
  return true;
}

void partner_webhook_worker(const Config cfg) {
  // Crash-recovery invariant for at-least-once delivery:
  // jobs are durable queue entries keyed by (partner_id, sequence), and we only
  // remove a job after a successful POST attempt. If the process crashes before
  // the snapshot flush that records removal, the job can be delivered again after
  // restart, which is intentional (at-least-once, never at-most-once).
  while (!g_partner_webhook_stop.load()) {
    PartnerWebhookDelivery job;
    bool have_job = false;
    bool pruned_state = false;
    {
      std::unique_lock<std::mutex> lock(g_partner_mu);
      g_partner_webhook_cv.wait_for(lock, std::chrono::milliseconds(250), [] {
        return g_partner_webhook_stop.load() || !g_partner_webhook_queue.empty();
      });
      if (g_partner_webhook_stop.load()) break;
      const auto now = now_unix_ms();
      pruned_state = prune_partner_state_locked(cfg, now);
      for (const auto& queued : g_partner_webhook_queue) {
        if (queued.next_attempt_unix_ms <= now) {
          job = queued;
          have_job = true;
          break;
        }
      }
    }
    if (pruned_state) persist_explorer_snapshot(cfg);
    if (!have_job) continue;
    std::string post_err;
    auto res = g_partner_webhook_post_json(job.url, job.payload_json, &post_err);
    bool persist_needed = false;
    bool moved_to_dlq = false;
    {
      std::lock_guard<std::mutex> guard(g_partner_mu);
      auto it = std::find_if(g_partner_webhook_queue.begin(), g_partner_webhook_queue.end(), [&](const PartnerWebhookDelivery& queued) {
        return queued.partner_id == job.partner_id && queued.sequence == job.sequence && queued.attempt == job.attempt &&
               queued.next_attempt_unix_ms == job.next_attempt_unix_ms;
      });
      if (it == g_partner_webhook_queue.end()) continue;
      if (res.has_value()) {
        g_partner_webhook_queue.erase(it);
        persist_needed = true;
      } else {
        ++it->attempt;
        if (it->attempt >= cfg.partner_webhook_max_attempts) {
          PartnerWebhookDlqEntry dlq;
          dlq.partner_id = it->partner_id;
          dlq.sequence = it->sequence;
          dlq.url = it->url;
          dlq.payload_json = it->payload_json;
          dlq.enqueued_unix_ms = it->enqueued_unix_ms;
          dlq.failed_unix_ms = now_unix_ms();
          dlq.attempts = it->attempt;
          dlq.last_error = post_err.empty() ? "delivery_failed" : post_err;
          g_partner_webhook_dlq.push_back(std::move(dlq));
          moved_to_dlq = true;
          g_partner_webhook_queue.erase(it);
        } else {
          const std::uint64_t shift = std::min<std::uint64_t>(it->attempt - 1, 16);
          std::uint64_t backoff = cfg.partner_webhook_initial_backoff_ms * (1ULL << shift);
          backoff = std::min<std::uint64_t>(backoff, cfg.partner_webhook_max_backoff_ms);
          it->next_attempt_unix_ms = now_unix_ms() + backoff;
        }
        persist_needed = true;
      }
    }
    if (res.has_value()) {
      const auto delivery_now_ms = now_unix_ms();
      if (delivery_now_ms >= job.enqueued_unix_ms) {
        record_partner_webhook_delivery_latency_metric("success", (delivery_now_ms - job.enqueued_unix_ms) / 1000);
      }
      {
        std::lock_guard<std::mutex> guard(g_metrics_mu);
        ++g_metrics_partner_webhook_deliveries_total;
      }
      append_webhook_audit_log(cfg, "webhook_delivery", job.partner_id, job.sequence, job.attempt + 1, true, "ok");
    } else {
      const auto delivery_now_ms = now_unix_ms();
      if (delivery_now_ms >= job.enqueued_unix_ms) {
        record_partner_webhook_delivery_latency_metric("failure", (delivery_now_ms - job.enqueued_unix_ms) / 1000);
      }
      {
        std::lock_guard<std::mutex> guard(g_metrics_mu);
        ++g_metrics_partner_webhook_failures_total;
        if (moved_to_dlq) ++g_metrics_partner_webhook_dlq_total;
      }
      append_webhook_audit_log(cfg, moved_to_dlq ? "webhook_dlq" : "webhook_retry", job.partner_id, job.sequence, job.attempt + 1, false,
                               post_err.empty() ? "delivery_failed" : post_err);
    }
    if (persist_needed) persist_explorer_snapshot(cfg);
  }
}

void handle_client_session(Config cfg, finalis::net::SocketHandle fd, const std::string client_ip) {
  struct ActiveGuard {
    ~ActiveGuard() { --g_active_clients; }
  } guard;

  const auto started = std::chrono::steady_clock::now();
  (void)finalis::net::set_socket_timeouts(fd, 15'000);
  auto req = read_http_request(fd);
  const Response resp_obj =
      req.has_value() ? handle_request(cfg, *req, client_ip)
                      : html_response(400, page_layout("Bad Request", "<h1>Bad Request</h1>"));
  record_http_metric(request_target_for_log(req), resp_obj.status);
  const std::string resp = http_response(resp_obj);
  (void)write_all(fd, resp);
  finalis::net::shutdown_socket(fd);
  finalis::net::close_socket(fd);

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
  record_http_duration_metric(request_target_for_log(req), static_cast<std::uint64_t>(elapsed.count()));
  if (elapsed >= kSlowRequestThreshold) {
    std::lock_guard<std::mutex> guard_log(g_log_mu);
    std::cerr << "[explorer] slow-request target=" << request_target_for_log(req)
              << " status=" << resp_obj.status
              << " duration_ms=" << elapsed.count() << "\n";
  }
}

Response handle_request(const Config& cfg, const std::string& req) {
  return handle_request(cfg, req, "127.0.0.1");
}

Response handle_request(const Config& cfg, const std::string& req, const std::string& client_ip) {
  std::string parse_err;
  auto parsed_req = parse_http_request(req, &parse_err);
  if (!parsed_req.has_value()) {
    return html_response(400, page_layout("Bad Request", "<h1>Bad Request</h1>"));
  }
  const std::string method = parsed_req->method;
  if (method != "GET" && method != "POST") {
    return html_response(405, page_layout("Method Not Allowed", "<h1>Method Not Allowed</h1>"));
  }
  std::string raw_target = parsed_req->target;
  std::string query_string;
  const auto query_pos = raw_target.find('?');
  if (query_pos != std::string::npos) {
    query_string = raw_target.substr(query_pos + 1);
    raw_target = raw_target.substr(0, query_pos);
  }
  std::string path = url_decode(raw_target);
  const auto query = parse_query_params(query_string);
  const bool is_api_path = path.rfind("/api/", 0) == 0;
  const bool post_allowed =
      (path == "/api/v1/withdrawals" || path == "/api/v1/transactions/status:batch" || path == "/api/v1/webhooks/dlq/replay");
  if (method == "POST" && !post_allowed) {
    if (is_api_path) return json_error_response(make_error(405, "method_not_allowed", "method not allowed"));
    return html_response(405, page_layout("Method Not Allowed", "<h1>Method Not Allowed</h1>"));
  }

  if (path == "/metrics") return render_metrics_response();

  PartnerPrincipal principal;
  if (auto auth_err = verify_partner_auth(cfg, *parsed_req, path, client_ip, &principal); auth_err.has_value()) {
    return json_error_response(*auth_err);
  }
  Response rate_limited_response;
  if (auto rl_err = enforce_partner_rate_limit(cfg, *parsed_req, principal, &rate_limited_response); rl_err.has_value()) {
    rate_limited_response.status = rl_err->http_status;
    rate_limited_response.content_type = "application/json; charset=utf-8";
    rate_limited_response.body = error_json(*rl_err);
    return rate_limited_response;
  }
  if (partner_auth_needed(path)) {
    const auto needed_scope = partner_required_scope(method, path);
    if (needed_scope.has_value() && !principal_has_scope(principal, *needed_scope)) {
      return json_error_response(make_error(403, "auth_scope_denied", "partner scope does not permit this operation"));
    }
  }

  if (path == "/" || path.empty()) return html_response(200, render_root(cfg));
  if (path == "/committee") return html_response(200, render_committee(cfg));
  if (path == "/favicon.ico") {
    return Response{404, "text/plain; charset=utf-8", "", std::nullopt, {}};
  }
  if (path == "/healthz") {
    auto result = fetch_status_result(cfg);
    if (result.value.has_value()) return json_response(200, render_health_json(true));
    const auto err = result.error.value_or(upstream_error("status unavailable"));
    return json_response(502, render_health_json(false, err));
  }
  if (path == "/api/v1/status") {
    auto result = fetch_status_result(cfg);
    return result.value.has_value() ? json_response(200, append_api_v1(render_status_json(*result.value, persisted_status_refreshed_unix_ms())))
                                    : json_error_response(*result.error);
  }
  if (path == "/api/v1/committee") {
    auto status = fetch_status_result(cfg);
    if (!status.value.has_value()) return json_error_response(*status.error);
    auto result = fetch_committee_result(cfg, status.value->finalized_height);
    return result.value.has_value()
               ? json_response(200, append_api_v1(render_committee_json(*result.value, persisted_committee_refreshed_unix_ms())))
               : json_error_response(*result.error);
  }
  if (path == "/api/v1/recent-tx") {
    return json_response(200, append_api_v1(render_recent_tx_json(fetch_recent_tx_results(cfg, 8), persisted_recent_refreshed_unix_ms())));
  }
  if (path == "/api/v1/fees/recommendation") {
    auto rpc = rpc_call(cfg.rpc_url, "get_status", "{}");
    std::optional<std::uint64_t> min_fee_rate;
    if (rpc.result.has_value() && rpc.result->is_object()) {
      const auto* mempool = rpc.result->get("mempool");
      if (mempool && mempool->is_object()) min_fee_rate = object_u64(mempool, "min_fee_rate_to_enter_when_full_milliunits_per_byte");
    }
    std::ostringstream oss;
    oss << "{\"policy\":\"dynamic_mempool_min_fee\",\"recommended_milliunits_per_byte\":";
    if (min_fee_rate.has_value()) oss << *min_fee_rate;
    else oss << "10000";
    oss << ",\"min_relay_milliunits_per_byte\":";
    if (min_fee_rate.has_value()) oss << *min_fee_rate;
    else oss << "10000";
    oss << ",\"ttl_seconds\":30,\"finalized_only\":true,\"api_version\":\"v1\"}";
    return json_response(200, oss.str());
  }
  if (path == "/api/v1/transactions/status:batch") {
    if (method != "POST") return json_error_response(make_error(405, "method_not_allowed", "POST required"));
    auto body_json = finalis::minijson::parse(parsed_req->body);
    if (!body_json.has_value() || !body_json->is_object()) {
      return json_error_response(make_error(400, "invalid_body", "expected JSON object body"));
    }
    const auto* txids = body_json->get("txids");
    if (!txids || !txids->is_array()) return json_error_response(make_error(400, "invalid_txids", "missing txids array"));
    std::ostringstream oss;
    oss << "{\"items\":[";
    bool first = true;
    for (const auto& item : txids->array_value) {
      if (!item.is_string() || !is_hex64(item.string_value)) {
        return json_error_response(make_error(400, "invalid_txids", "txids must be 64-hex strings"));
      }
      auto tx_lookup = fetch_tx_result(cfg, item.string_value);
      if (!first) oss << ",";
      first = false;
      if (!tx_lookup.value.has_value()) {
        oss << "{\"txid\":\"" << json_escape(item.string_value)
            << "\",\"status\":\"not_found\",\"finalized\":false,\"credit_safe\":false,\"finalized_depth\":0,"
            << "\"height\":null,\"transition_hash\":null}";
      } else {
        const auto& tx = *tx_lookup.value;
        oss << "{\"txid\":\"" << json_escape(tx.txid) << "\",\"status\":\"" << json_escape(tx.found ? "finalized" : "not_found")
            << "\",\"finalized\":" << json_bool(tx.finalized)
            << ",\"credit_safe\":" << json_bool(tx.credit_safe)
            << ",\"finalized_depth\":" << tx.finalized_depth
            << ",\"height\":" << json_u64_or_null(tx.finalized_height)
            << ",\"transition_hash\":" << json_string_or_null(tx.transition_hash.empty() ? std::optional<std::string>{} : std::optional<std::string>{tx.transition_hash})
            << "}";
      }
    }
    oss << "],\"finalized_only\":true,\"api_version\":\"v1\"}";
    return json_response(200, oss.str());
  }
  if (path == "/api/v1/withdrawals") {
    if (method != "POST") return json_error_response(make_error(405, "method_not_allowed", "POST required"));
    auto body_json = finalis::minijson::parse(parsed_req->body);
    if (!body_json.has_value() || !body_json->is_object()) {
      return json_error_response(make_error(400, "invalid_body", "expected JSON object body"));
    }
    const auto client_id = object_string(&*body_json, "client_withdrawal_id");
    const auto tx_hex = object_string(&*body_json, "tx_hex");
    if (!client_id.has_value() || client_id->empty()) {
      return json_error_response(make_error(400, "missing_client_withdrawal_id", "client_withdrawal_id is required"));
    }
    if (!tx_hex.has_value() || tx_hex->empty()) {
      return json_error_response(make_error(400, "missing_tx_hex", "tx_hex is required"));
    }
    const auto idem_key = header_value(*parsed_req, "idempotency-key");
    if (!idem_key.has_value() || idem_key->empty()) {
      return json_error_response(make_error(400, "missing_idempotency_key", "Idempotency-Key header is required"));
    }
    const std::string partner_id = principal.partner_id.empty() ? "default" : principal.partner_id;
    const std::string scoped_idem = partner_scoped_id(partner_id, *idem_key);
    const std::string scoped_client = partner_scoped_id(partner_id, *client_id);
    const auto tx_bytes = finalis::hex_decode(*tx_hex);
    if (!tx_bytes.has_value()) return json_error_response(make_error(400, "invalid_tx_hex", "tx_hex decode failed"));
    const auto any_tx = finalis::parse_any_tx(*tx_bytes);
    if (!any_tx.has_value()) return json_error_response(make_error(400, "invalid_tx_hex", "tx parse failed"));
    const std::string txid = finalis::hex_encode32(finalis::txid_any(*any_tx));
    const std::string body_hash = sha256_hex_text(parsed_req->body);
    const std::uint64_t now_ms = now_unix_ms();
    bool partner_state_updated = false;
    std::optional<PartnerWithdrawal> existing_withdrawal;
    {
      std::lock_guard<std::mutex> guard(g_partner_mu);
      if (prune_partner_state_locked(cfg, now_ms)) partner_state_updated = true;
      auto idh = g_partner_idempotency_hash.find(scoped_idem);
      if (idh != g_partner_idempotency_hash.end() && idh->second != body_hash) {
        return json_error_response(make_error(409, "idempotency_conflict", "idempotency key reused with different body"));
      }
      if (idh != g_partner_idempotency_hash.end()) {
        auto cid_it = g_partner_idempotency_client_id.find(scoped_idem);
        if (cid_it != g_partner_idempotency_client_id.end()) {
          auto wit = g_partner_withdrawals_by_client_id.find(cid_it->second);
          if (wit != g_partner_withdrawals_by_client_id.end()) {
            if (!g_partner_idempotency_unix_ms.count(scoped_idem)) {
              g_partner_idempotency_unix_ms[scoped_idem] = now_ms;
              partner_state_updated = true;
            }
            existing_withdrawal = wit->second;
          }
        }
      }
      if (!existing_withdrawal.has_value()) {
        auto existing = g_partner_withdrawals_by_client_id.find(scoped_client);
        if (existing != g_partner_withdrawals_by_client_id.end()) {
          if (g_partner_idempotency_hash[scoped_idem] != body_hash) {
            g_partner_idempotency_hash[scoped_idem] = body_hash;
            partner_state_updated = true;
          }
          if (g_partner_idempotency_client_id[scoped_idem] != scoped_client) {
            g_partner_idempotency_client_id[scoped_idem] = scoped_client;
            partner_state_updated = true;
          }
          if (!g_partner_idempotency_unix_ms.count(scoped_idem)) {
            g_partner_idempotency_unix_ms[scoped_idem] = now_ms;
            partner_state_updated = true;
          }
          existing_withdrawal = existing->second;
        }
      }
    }
    if (partner_state_updated) persist_explorer_snapshot(cfg);
    if (existing_withdrawal.has_value()) {
      return json_response(200, std::string("{\"withdrawal\":") + partner_withdrawal_json(*existing_withdrawal) + ",\"api_version\":\"v1\"}");
    }
    auto broadcast = rpc_call(cfg.rpc_url, "broadcast_tx", std::string("{\"tx_hex\":\"") + json_escape(*tx_hex) + "\"}");
    if (!broadcast.result.has_value() || !broadcast.result->is_object()) {
      return json_error_response(upstream_error(broadcast.error.empty() ? "broadcast failed" : broadcast.error));
    }
    const bool accepted = object_bool(&*broadcast.result, "accepted").value_or(false);
    const bool retryable = object_bool(&*broadcast.result, "retryable").value_or(false);
    const std::string retry_class = object_string(&*broadcast.result, "retry_class").value_or("none");
    const auto error_code = object_string(&*broadcast.result, "error_code");
    const auto error_message = object_string(&*broadcast.result, "error_message");
    PartnerWithdrawal w;
    w.partner_id = partner_id;
    w.client_withdrawal_id = *client_id;
    w.txid = object_string(&*broadcast.result, "txid").value_or(txid);
    w.state = accepted ? "accepted_for_relay" : (retryable ? "submitted" : "rejected");
    w.retryable = retryable;
    w.retry_class = retry_class;
    w.error_code = error_code;
    w.error_message = error_message;
    w.created_unix_ms = now_unix_ms();
    w.updated_unix_ms = w.created_unix_ms;
    {
      std::lock_guard<std::mutex> guard(g_partner_mu);
      g_partner_idempotency_hash[scoped_idem] = body_hash;
      g_partner_idempotency_client_id[scoped_idem] = scoped_client;
      g_partner_idempotency_unix_ms[scoped_idem] = now_ms;
    }
    upsert_partner_withdrawal(cfg, w);
    {
      std::lock_guard<std::mutex> guard(g_metrics_mu);
      ++g_metrics_partner_withdrawal_submissions_total;
    }
    const int status = accepted ? 201 : (retryable ? 202 : 200);
    return json_response(status, std::string("{\"withdrawal\":") + partner_withdrawal_json(w) + ",\"api_version\":\"v1\"}");
  }
  const std::string api_v1_withdrawals_prefix = "/api/v1/withdrawals/";
  if (path.rfind(api_v1_withdrawals_prefix, 0) == 0) {
    if (method != "GET") return json_error_response(make_error(405, "method_not_allowed", "GET required"));
    const std::string ident = path.substr(api_v1_withdrawals_prefix.size());
    if (ident.empty()) return json_error_response(make_error(400, "invalid_withdrawal_id", "missing withdrawal id"));
    auto lookup = find_partner_withdrawal_by_any_id(principal.partner_id.empty() ? "default" : principal.partner_id, ident);
    if (!lookup.has_value()) return json_error_response(make_error(404, "not_found", "withdrawal not found"));
    auto refreshed = refresh_partner_withdrawal_state(cfg, *lookup);
    return json_response(200, std::string("{\"withdrawal\":") + partner_withdrawal_json(refreshed) + ",\"api_version\":\"v1\"}");
  }
  if (path == "/api/v1/events/finalized") {
    if (method != "GET") return json_error_response(make_error(405, "method_not_allowed", "GET required"));
    const auto from_seq = query.count("from_sequence") ? parse_u64_strict(query.at("from_sequence")) : std::optional<std::uint64_t>(1);
    if (!from_seq.has_value()) return json_error_response(make_error(400, "invalid_from_sequence", "from_sequence must be numeric"));
    std::vector<PartnerEvent> events;
    std::uint64_t next_seq = 1;
    {
      std::lock_guard<std::mutex> guard(g_partner_mu);
      next_seq = g_partner_next_sequence;
      for (const auto& evt : g_partner_events) {
        if (evt.sequence >= *from_seq && evt.state == "finalized" &&
            evt.partner_id == (principal.partner_id.empty() ? "default" : principal.partner_id)) {
          events.push_back(evt);
        }
      }
    }
    std::ostringstream oss;
    oss << "{\"items\":[";
    for (std::size_t i = 0; i < events.size(); ++i) {
      if (i) oss << ",";
      oss << partner_event_json(events[i]);
    }
    oss << "],\"next_sequence\":" << next_seq << ",\"api_version\":\"v1\"}";
    return json_response(200, oss.str());
  }
  if (path == "/api/v1/webhooks/dlq") {
    if (method != "GET") return json_error_response(make_error(405, "method_not_allowed", "GET required"));
    std::uint64_t limit = 100;
    if (auto it = query.find("limit"); it != query.end() && !it->second.empty()) {
      auto parsed = parse_u64_strict(it->second);
      if (!parsed.has_value()) return json_error_response(make_error(400, "invalid_limit", "limit must be numeric"));
      limit = std::min<std::uint64_t>(*parsed, 1000);
    }
    std::vector<PartnerWebhookDlqEntry> items;
    {
      std::lock_guard<std::mutex> guard(g_partner_mu);
      const std::string partner_id = principal.partner_id.empty() ? "default" : principal.partner_id;
      for (const auto& item : g_partner_webhook_dlq) {
        if (item.partner_id != partner_id) continue;
        items.push_back(item);
      }
    }
    if (items.size() > limit) items.erase(items.begin(), items.end() - static_cast<std::ptrdiff_t>(limit));
    std::ostringstream oss;
    oss << "{\"items\":[";
    for (std::size_t i = 0; i < items.size(); ++i) {
      if (i) oss << ",";
      const auto& item = items[i];
      oss << "{\"partner_id\":\"" << json_escape(item.partner_id) << "\",\"sequence\":" << item.sequence << ",\"attempts\":"
          << item.attempts << ",\"failed_unix_ms\":" << item.failed_unix_ms << ",\"last_error\":\"" << json_escape(item.last_error)
          << "\"}";
    }
    oss << "],\"api_version\":\"v1\"}";
    return json_response(200, oss.str());
  }
  if (path == "/api/v1/webhooks/dlq/replay") {
    if (method != "POST") return json_error_response(make_error(405, "method_not_allowed", "POST required"));
    auto body_json = finalis::minijson::parse(parsed_req->body);
    if (!body_json.has_value() || !body_json->is_object()) {
      return json_error_response(make_error(400, "invalid_body", "expected JSON object body"));
    }
    const auto seq = object_u64(&*body_json, "sequence");
    if (!seq.has_value() || *seq == 0) return json_error_response(make_error(400, "invalid_sequence", "sequence is required"));
    bool replayed = false;
    {
      std::lock_guard<std::mutex> guard(g_partner_mu);
      const std::string partner_id = principal.partner_id.empty() ? "default" : principal.partner_id;
      auto it = std::find_if(g_partner_webhook_dlq.begin(), g_partner_webhook_dlq.end(), [&](const PartnerWebhookDlqEntry& item) {
        return item.partner_id == partner_id && item.sequence == *seq;
      });
      if (it != g_partner_webhook_dlq.end()) {
        PartnerWebhookDelivery d;
        d.partner_id = it->partner_id;
        d.sequence = it->sequence;
        d.url = it->url;
        d.payload_json = it->payload_json;
        d.attempt = 0;
        d.enqueued_unix_ms = now_unix_ms();
        d.next_attempt_unix_ms = now_unix_ms();
        g_partner_webhook_queue.push_back(std::move(d));
        g_partner_webhook_dlq.erase(it);
        replayed = true;
      }
    }
    if (!replayed) return json_error_response(make_error(404, "not_found", "dlq entry not found"));
    {
      std::lock_guard<std::mutex> guard(g_metrics_mu);
      ++g_metrics_partner_webhook_replays_total;
    }
    append_webhook_audit_log(cfg, "webhook_replay", principal.partner_id.empty() ? "default" : principal.partner_id, *seq, 0, true, "requeued");
    g_partner_webhook_cv.notify_one();
    persist_explorer_snapshot(cfg);
    return json_response(200, std::string("{\"replayed\":true,\"sequence\":") + std::to_string(*seq) + ",\"api_version\":\"v1\"}");
  }
  if (path == "/search") {
    auto it = query.find("q");
    if (it == query.end() || it->second.empty()) {
      return html_response(400, page_layout("Bad Request", "<div class=\"card\"><div class=\"note\">Missing search query.</div></div>"));
    }
    auto search = fetch_search_result(cfg, it->second);
    if (!search.value.has_value()) {
      if (search.error && search.error->http_status == 400) {
        return html_response(400, page_layout("Invalid Query", "<div class=\"card\"><div class=\"note\">" + html_escape(search.error->message) + "</div></div>"));
      }
      if (search.error && search.error->http_status == 502) {
        return html_response(502, page_layout("Upstream Error", "<div class=\"card\"><div class=\"note\">" + html_escape(search.error->message) + "</div></div>"));
      }
      return html_response(404, page_layout("Not Found", "<div class=\"card\"><div class=\"note\">Query not found in finalized state.</div></div>"));
    }
    if (!search.value->target.has_value()) {
      return html_response(404, page_layout("Not Found", "<div class=\"card\"><div class=\"note\">Query not found in finalized state.</div></div>"));
    }
    return redirect_response(*search.value->target);
  }
  if (path == "/api/status") {
    auto result = fetch_status_result(cfg);
    return result.value.has_value() ? json_response(200, render_status_json(*result.value, persisted_status_refreshed_unix_ms()))
                                    : json_error_response(*result.error);
  }
  if (path == "/api/committee") {
    auto status = fetch_status_result(cfg);
    if (!status.value.has_value()) return json_error_response(*status.error);
    auto result = fetch_committee_result(cfg, status.value->finalized_height);
    return result.value.has_value() ? json_response(200, render_committee_json(*result.value, persisted_committee_refreshed_unix_ms()))
                                    : json_error_response(*result.error);
  }
  if (path == "/api/recent-tx") {
    return json_response(200, render_recent_tx_json(fetch_recent_tx_results(cfg, 8), persisted_recent_refreshed_unix_ms()));
  }
  const std::string tx_prefix = "/tx/";
  const std::string transition_prefix = "/transition/";
  const std::string address_prefix = "/address/";
  const std::string api_tx_prefix = "/api/tx/";
  const std::string api_transition_prefix = "/api/transition/";
  const std::string api_address_prefix = "/api/address/";
  const std::string api_v1_tx_prefix = "/api/v1/tx/";
  const std::string api_v1_transition_prefix = "/api/v1/transition/";
  const std::string api_v1_address_prefix = "/api/v1/address/";
  if (path == "/api/search" || path == "/api/v1/search") {
    auto it = query.find("q");
    if (it == query.end() || it->second.empty()) return json_error_response(make_error(400, "invalid_query", "missing query"));
    auto result = fetch_search_result(cfg, it->second);
    return result.value.has_value()
               ? json_response(200, path == "/api/v1/search" ? append_api_v1(render_search_json(*result.value))
                                                             : render_search_json(*result.value))
               : json_error_response(*result.error);
  }
  if (path.rfind(api_tx_prefix, 0) == 0 || path.rfind(api_v1_tx_prefix, 0) == 0) {
    const bool v1 = path.rfind(api_v1_tx_prefix, 0) == 0;
    auto result = fetch_tx_result(cfg, path.substr(v1 ? api_v1_tx_prefix.size() : api_tx_prefix.size()));
    return result.value.has_value() ? json_response(200, v1 ? append_api_v1(render_tx_json(*result.value)) : render_tx_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path.rfind(api_transition_prefix, 0) == 0 || path.rfind(api_v1_transition_prefix, 0) == 0) {
    const bool v1 = path.rfind(api_v1_transition_prefix, 0) == 0;
    auto result = fetch_transition_result(cfg, path.substr(v1 ? api_v1_transition_prefix.size() : api_transition_prefix.size()));
    return result.value.has_value()
               ? json_response(200, v1 ? append_api_v1(render_transition_json(cfg, *result.value))
                                       : render_transition_json(cfg, *result.value))
               : json_error_response(*result.error);
  }
  if (path.rfind(api_address_prefix, 0) == 0 || path.rfind(api_v1_address_prefix, 0) == 0) {
    const bool v1 = path.rfind(api_v1_address_prefix, 0) == 0;
    std::optional<std::uint64_t> start_after_height;
    std::optional<std::string> start_after_txid;
    if (auto it = query.find("after_height"); it != query.end() && !it->second.empty() && is_digits(it->second)) {
      try {
        start_after_height = static_cast<std::uint64_t>(std::stoull(it->second));
      } catch (...) {
      }
    }
    if (auto it = query.find("after_txid"); it != query.end() && is_hex64(it->second)) start_after_txid = it->second;
    auto result = fetch_address_result(cfg, path.substr(v1 ? api_v1_address_prefix.size() : api_address_prefix.size()), start_after_height,
                                       start_after_txid);
    return result.value.has_value()
               ? json_response(200, v1 ? append_api_v1(render_address_json(*result.value)) : render_address_json(*result.value))
               : json_error_response(*result.error);
  }
  if (path.rfind(transition_prefix, 0) == 0) {
    return html_response(200, render_transition(cfg, path.substr(transition_prefix.size())));
  }
  if (path.rfind(tx_prefix, 0) == 0) return html_response(200, render_tx(cfg, path.substr(tx_prefix.size())));
  if (path.rfind(address_prefix, 0) == 0) return html_response(200, render_address(cfg, path.substr(address_prefix.size()), query));
  return html_response(404, render_not_found());
}

}  // namespace

int main(int argc, char** argv) {
  auto cfg = parse_args(argc, argv);
  if (!cfg.has_value()) {
    std::cerr << "usage: finalis-explorer [--bind 127.0.0.1] [--port 18080] [--rpc-url http://127.0.0.1:19444/rpc] "
                 "[--cache-path /path/to/cache.json] [--partner-auth-required 0|1] [--partner-api-key KEY] "
                 "[--partner-api-secret SECRET] [--partner-registry /path/partners.json] "
                 "[--partner-auth-max-skew-seconds 300] [--partner-rate-limit-per-minute 600] "
                 "[--partner-webhook-max-attempts 5] [--partner-webhook-initial-backoff-ms 1000] "
                 "[--partner-webhook-max-backoff-ms 60000] [--partner-idempotency-ttl-seconds 604800] "
                 "[--partner-events-ttl-seconds 2592000] [--partner-webhook-queue-ttl-seconds 604800] "
                 "[--partner-mtls-required 0|1] [--partner-allowed-ipv4-cidrs 10.0.0.0/8,127.0.0.1/32] "
                 "[--partner-webhook-audit-log-path /var/log/finalis/webhook_audit.jsonl]\n";
    return 1;
  }
  if (cfg->cache_path.empty()) cfg->cache_path = default_explorer_cache_path(cfg->rpc_url);
  std::string registry_err;
  if (!load_partner_registry(*cfg, &registry_err)) {
    std::cerr << "failed to load partner registry: " << registry_err << "\n";
    return 1;
  }
  {
    std::lock_guard<std::mutex> guard(g_partner_mu);
    if (!g_partner_by_api_key.empty()) cfg->partner_auth_required = true;
  }
  load_persisted_explorer_snapshot(*cfg);

  if (!finalis::net::ensure_sockets()) {
    std::cerr << "socket init failed\n";
    return 1;
  }
  auto listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!finalis::net::valid_socket(listen_fd)) {
    std::cerr << "socket failed\n";
    return 1;
  }
  (void)finalis::net::set_reuseaddr(listen_fd);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg->port);
  if (::inet_pton(AF_INET, cfg->bind_ip.c_str(), &addr.sin_addr) != 1) {
    std::cerr << "invalid bind address\n";
    finalis::net::close_socket(listen_fd);
    return 1;
  }
  if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::cerr << "bind failed\n";
    finalis::net::close_socket(listen_fd);
    return 1;
  }
  if (::listen(listen_fd, 32) != 0) {
    std::cerr << "listen failed\n";
    finalis::net::close_socket(listen_fd);
    return 1;
  }

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  g_partner_webhook_stop.store(false);
  g_partner_webhook_thread = std::thread([cfg = *cfg]() { partner_webhook_worker(cfg); });
  std::cout << "finalis-explorer listening on http://" << cfg->bind_ip << ":" << cfg->port
            << " using lightserver " << cfg->rpc_url
            << " partner_auth=" << (cfg->partner_auth_required ? "on" : "off")
            << " partner_rate_limit_per_minute=" << cfg->partner_rate_limit_per_minute
            << " partner_registry=" << (cfg->partner_registry_path.empty() ? "(none)" : cfg->partner_registry_path)
            << " webhook_max_attempts=" << cfg->partner_webhook_max_attempts
            << " idempotency_ttl_s=" << cfg->partner_idempotency_ttl_seconds
            << " events_ttl_s=" << cfg->partner_events_ttl_seconds
            << " webhook_queue_ttl_s=" << cfg->partner_webhook_queue_ttl_seconds
            << " mtls_required=" << (cfg->partner_mtls_required ? "on" : "off")
            << " allowed_ipv4_cidrs=" << cfg->partner_allowed_ipv4_cidrs_raw.size()
            << " webhook_audit_log=" << (cfg->partner_webhook_audit_log_path.empty() ? "(none)" : cfg->partner_webhook_audit_log_path)
            << "\n";

  while (!g_stop) {
    sockaddr_in client{};
    socklen_t len = sizeof(client);
    const auto fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&client), &len);
    if (!finalis::net::valid_socket(fd)) {
      if (g_stop) break;
      continue;
    }
    const std::size_t active = g_active_clients.load();
    if (active >= kMaxConcurrentClients) {
      const std::string resp = http_response(
          html_response(503, page_layout("Busy", "<div class=\"card\"><div class=\"note\">Explorer is busy. Retry shortly.</div></div>")));
      (void)write_all(fd, resp);
      finalis::net::shutdown_socket(fd);
      finalis::net::close_socket(fd);
      continue;
    }
    ++g_active_clients;
    char ipbuf[INET_ADDRSTRLEN] = {0};
    std::string client_ip = "0.0.0.0";
    if (::inet_ntop(AF_INET, &client.sin_addr, ipbuf, sizeof(ipbuf))) client_ip = ipbuf;
    std::thread(handle_client_session, *cfg, fd, client_ip).detach();
  }

  g_partner_webhook_stop.store(true);
  g_partner_webhook_cv.notify_all();
  if (g_partner_webhook_thread.joinable()) g_partner_webhook_thread.join();
  finalis::net::close_socket(listen_fd);
  return 0;
}
