#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <mutex>
#include <vector>

#include "address/address.hpp"
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
};

Response handle_request(const Config& cfg, const std::string& req);
ApiError upstream_error(const std::string& message);
void persist_explorer_snapshot(const Config& cfg);
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
  return Response{status, "text/html; charset=utf-8", std::move(body), std::nullopt};
}

Response json_response(int status, std::string body) {
  return Response{status, "application/json; charset=utf-8", std::move(body), std::nullopt};
}

Response json_error_response(const ApiError& err) { return json_response(err.http_status, error_json(err)); }

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
    } else {
      return std::nullopt;
    }
  }
  return cfg;
}

struct RpcCallResult {
  std::optional<finalis::minijson::Value> result;
  std::string error;
  std::optional<std::int64_t> error_code;
};

using HttpPostJsonRawFn = std::function<std::optional<std::string>(const std::string&, const std::string&, std::string*)>;
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
    }
  }
  if (const auto* adaptive_summary = status_obj.get("adaptive_telemetry_summary"); adaptive_summary && adaptive_summary->is_object()) {
    result.adaptive_telemetry_window_epochs = object_u64(adaptive_summary, "window_epochs");
    result.adaptive_telemetry_sample_count = object_u64(adaptive_summary, "sample_count");
    result.adaptive_telemetry_fallback_epochs = object_u64(adaptive_summary, "fallback_epochs");
    result.adaptive_telemetry_sticky_fallback_epochs = object_u64(adaptive_summary, "sticky_fallback_epochs");
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

void persist_explorer_snapshot(const Config& cfg) {
  if (cfg.cache_path.empty()) return;
  PersistedExplorerSnapshot snapshot;
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    snapshot = g_persisted_snapshot;
  }
  snapshot.stored_unix_ms = now_unix_ms();
  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    g_persisted_snapshot.stored_unix_ms = snapshot.stored_unix_ms;
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

  {
    std::lock_guard<std::mutex> guard(g_persisted_snapshot_mu);
    g_persisted_snapshot = loaded;
  }
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

  std::string network_name = "mainnet";
  if (auto st = fetch_status_result(cfg); st.value.has_value()) network_name = st.value->network;
  const std::string hrp = hrp_for_network_name(network_name);

  std::uint64_t total_in = 0;
  bool fee_known = true;
  for (const auto& in : tx_v1.inputs) {
    TxInputResult input_view{finalis::hex_encode32(in.prev_txid), in.prev_index, std::nullopt, std::nullopt};
    auto prev_call = rpc_call(cfg.rpc_url, "get_tx", std::string("{\"txid\":\"") + finalis::hex_encode32(in.prev_txid) + "\"}");
    if (!prev_call.result.has_value() || !prev_call.result->is_object()) {
      result.inputs.push_back(std::move(input_view));
      fee_known = false;
      continue;
    }
    auto prev_hex = object_string(&*prev_call.result, "tx_hex");
    if (!prev_hex) {
      result.inputs.push_back(std::move(input_view));
      fee_known = false;
      continue;
    }
    auto prev_bytes = finalis::hex_decode(*prev_hex);
    auto prev_tx = prev_bytes ? finalis::parse_any_tx(*prev_bytes) : std::nullopt;
    if (!prev_tx.has_value() || !std::holds_alternative<finalis::Tx>(*prev_tx)) {
      result.inputs.push_back(std::move(input_view));
      fee_known = false;
      continue;
    }
    const auto& prev_tx_v1 = std::get<finalis::Tx>(*prev_tx);
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
    });
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
      << "}},"
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
        << json_escape(result.outputs[i].script_hex) << "\"}";
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
    if (out.address.has_value()) body << "<a href=\"/address/" << html_escape(*out.address) << "\"><code>" << html_escape(*out.address) << "</code></a>";
    else body << "<span class=\"muted\">not decoded by explorer</span>";
    body << "</td><td>" << (out.address.has_value() ? "P2PKH address" : "Raw script only")
         << "</td><td><code>" << html_escape(out.script_hex) << "</code></td></tr>";
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
    if (req.size() > 16 * 1024) return std::nullopt;
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
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 502:
      return "Bad Gateway";
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

void handle_client_session(Config cfg, finalis::net::SocketHandle fd) {
  struct ActiveGuard {
    ~ActiveGuard() { --g_active_clients; }
  } guard;

  const auto started = std::chrono::steady_clock::now();
  (void)finalis::net::set_socket_timeouts(fd, 15'000);
  auto req = read_http_request(fd);
  const Response resp_obj =
      req.has_value() ? handle_request(cfg, *req)
                      : html_response(400, page_layout("Bad Request", "<h1>Bad Request</h1>"));
  const std::string resp = http_response(resp_obj);
  (void)write_all(fd, resp);
  finalis::net::shutdown_socket(fd);
  finalis::net::close_socket(fd);

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
  if (elapsed >= kSlowRequestThreshold) {
    std::lock_guard<std::mutex> guard_log(g_log_mu);
    std::cerr << "[explorer] slow-request target=" << request_target_for_log(req)
              << " status=" << resp_obj.status
              << " duration_ms=" << elapsed.count() << "\n";
  }
}

Response handle_request(const Config& cfg, const std::string& req) {
  const auto line_end = req.find("\r\n");
  if (line_end == std::string::npos) {
    return html_response(400, page_layout("Bad Request", "<h1>Bad Request</h1>"));
  }
  const std::string first = req.substr(0, line_end);
  const auto sp1 = first.find(' ');
  const auto sp2 = first.rfind(' ');
  if (sp1 == std::string::npos || sp2 == std::string::npos || sp1 == sp2) {
    return html_response(400, page_layout("Bad Request", "<h1>Bad Request</h1>"));
  }
  const std::string method = first.substr(0, sp1);
  if (method != "GET") {
    return html_response(405, page_layout("Method Not Allowed", "<h1>Method Not Allowed</h1>"));
  }
  std::string raw_target = first.substr(sp1 + 1, sp2 - sp1 - 1);
  std::string query_string;
  const auto query_pos = raw_target.find('?');
  if (query_pos != std::string::npos) {
    query_string = raw_target.substr(query_pos + 1);
    raw_target = raw_target.substr(0, query_pos);
  }
  std::string path = url_decode(raw_target);
  const auto query = parse_query_params(query_string);

  if (path == "/" || path.empty()) return html_response(200, render_root(cfg));
  if (path == "/committee") return html_response(200, render_committee(cfg));
  if (path == "/favicon.ico") {
    return Response{404, "text/plain; charset=utf-8", "", std::nullopt};
  }
  if (path == "/healthz") {
    auto result = fetch_status_result(cfg);
    if (result.value.has_value()) return json_response(200, render_health_json(true));
    const auto err = result.error.value_or(upstream_error("status unavailable"));
    return json_response(502, render_health_json(false, err));
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
  if (path == "/api/search") {
    auto it = query.find("q");
    if (it == query.end() || it->second.empty()) return json_error_response(make_error(400, "invalid_query", "missing query"));
    auto result = fetch_search_result(cfg, it->second);
    return result.value.has_value() ? json_response(200, render_search_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path.rfind(api_tx_prefix, 0) == 0) {
    auto result = fetch_tx_result(cfg, path.substr(api_tx_prefix.size()));
    return result.value.has_value() ? json_response(200, render_tx_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path.rfind(api_transition_prefix, 0) == 0) {
    auto result = fetch_transition_result(cfg, path.substr(api_transition_prefix.size()));
    return result.value.has_value() ? json_response(200, render_transition_json(cfg, *result.value))
                                    : json_error_response(*result.error);
  }
  if (path.rfind(api_address_prefix, 0) == 0) {
    std::optional<std::uint64_t> start_after_height;
    std::optional<std::string> start_after_txid;
    if (auto it = query.find("after_height"); it != query.end() && !it->second.empty() && is_digits(it->second)) {
      try {
        start_after_height = static_cast<std::uint64_t>(std::stoull(it->second));
      } catch (...) {
      }
    }
    if (auto it = query.find("after_txid"); it != query.end() && is_hex64(it->second)) start_after_txid = it->second;
    auto result = fetch_address_result(cfg, path.substr(api_address_prefix.size()), start_after_height, start_after_txid);
    return result.value.has_value() ? json_response(200, render_address_json(*result.value))
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
    std::cerr << "usage: finalis-explorer [--bind 127.0.0.1] [--port 18080] [--rpc-url http://127.0.0.1:19444/rpc] [--cache-path /path/to/cache.json]\n";
    return 1;
  }
  if (cfg->cache_path.empty()) cfg->cache_path = default_explorer_cache_path(cfg->rpc_url);
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
  std::cout << "finalis-explorer listening on http://" << cfg->bind_ip << ":" << cfg->port
            << " using lightserver " << cfg->rpc_url << "\n";

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
    std::thread(handle_client_session, *cfg, fd).detach();
  }

  finalis::net::close_socket(listen_fd);
  return 0;
}
