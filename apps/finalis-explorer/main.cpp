#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
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
#include <vector>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "common/minijson.hpp"
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
};

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
  bool finalized_only{true};
};

struct TransitionResult {
  bool found{false};
  bool finalized{true};
  std::uint64_t height{0};
  std::string hash;
  std::string prev_finalized_hash;
  std::uint64_t timestamp{0};
  std::uint32_t round{0};
  std::size_t tx_count{0};
  std::vector<std::string> txids;
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
};

struct AddressHistoryResult {
  std::vector<AddressHistoryItemResult> items;
  bool has_more{false};
  std::optional<std::string> next_cursor;
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
};

struct Response {
  int status{200};
  std::string content_type{"text/html; charset=utf-8"};
  std::string body;
  std::optional<std::string> location;
};

volatile std::sig_atomic_t g_stop = 0;

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

Response redirect_response(const std::string& location) {
  Response out;
  out.status = 302;
  out.content_type = "text/plain; charset=utf-8";
  out.body = "Found";
  out.location = location;
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

std::string format_timestamp(std::uint64_t ts) {
  std::time_t tt = static_cast<std::time_t>(ts);
  std::tm tm{};
  if (::gmtime_r(&tt, &tm) == nullptr) return std::to_string(ts);
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

std::string global_finalized_banner() {
  return "<div class=\"global-banner\">Explorer view is finalized-state only. Only finalized activity is shown.</div>";
}

std::string page_layout(const std::string& title, const std::string& body) {
  std::ostringstream oss;
  oss << "<!doctype html><html><head><meta charset=\"utf-8\">"
      << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
      << "<title>" << html_escape(title) << "</title>"
      << "<style>"
         "body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f5f5f2;color:#171717;margin:0;padding:clamp(12px,2vw,24px);}"
         "main{max-width:1080px;width:min(100%,1080px);margin:0 auto;}"
         "a{color:#0f4c81;text-decoration:none;}a:hover{text-decoration:underline;}"
         "h1,h2{margin:0 0 12px 0;}h1{font-size:28px;}h2{font-size:18px;margin-top:28px;}"
         ".muted{color:#5b5b5b;}.card{background:#fff;border:1px solid #d7d7d1;border-radius:10px;padding:16px 18px;margin:16px 0;}"
         ".grid{display:grid;grid-template-columns:minmax(140px,220px) minmax(0,1fr);gap:8px 14px;align-items:start;}"
         ".badge{display:inline-block;padding:10px 16px;border-radius:999px;font-size:16px;font-weight:800;letter-spacing:.08em;max-width:100%;white-space:normal;text-align:center;overflow-wrap:anywhere;}"
         ".badge-finalized{background:#d9f0d8;color:#124b19;border:2px solid #5ba55e;box-shadow:0 0 0 2px rgba(91,165,94,.12) inset;}"
         ".badge-unfinalized{background:#f6e2d8;color:#8a3110;border:2px solid #c56742;box-shadow:0 0 0 2px rgba(197,103,66,.12) inset;}"
         ".table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;}"
         "table{width:100%;border-collapse:collapse;font-size:14px;min-width:560px;}th,td{padding:8px 10px;border-bottom:1px solid #e3e3de;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;}"
         "th{color:#4f4f4f;font-weight:700;}code{font-size:13px;overflow-wrap:anywhere;word-break:break-word;}"
         ".num{text-align:right;white-space:nowrap;}"
         ".mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}"
         ".mono-block{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;max-width:100%;padding:10px 12px;background:#f7f7f4;border:1px solid #e3e3de;border-radius:8px;overflow-wrap:anywhere;word-break:break-word;}"
         ".mono-block code{flex:1 1 auto;min-width:0;white-space:pre-wrap;}"
         ".copy-button{flex:0 0 auto;background:#ecece7;border:1px solid #cfcfc6;border-radius:6px;padding:5px 9px;font:inherit;font-size:12px;color:#303030;cursor:pointer;}"
         ".copy-button:hover{background:#e2e2db;}"
         ".copy-button-row{display:flex;flex-wrap:wrap;gap:8px;}"
         ".amount-in{color:#137c34;font-weight:700;}"
         ".amount-out{color:#b02b2b;font-weight:700;}"
         ".value-cell{min-width:0;overflow-wrap:anywhere;word-break:break-word;}"
         "ul{padding-left:18px;} .note{padding:12px 14px;background:#f2f2ed;border-left:4px solid #8a8a80;border-radius:6px;}"
         ".nav{margin-bottom:12px;font-size:14px;}"
         ".global-banner{margin:0 0 18px 0;padding:12px 14px;background:#fff3d6;border:1px solid #d8b96a;border-radius:8px;color:#5e4300;font-weight:700;}"
         ".status-hero{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap;}"
         ".status-hero>div{min-width:0;}"
         ".decision-line{margin-top:14px;padding:12px 14px;border-radius:8px;font-weight:800;letter-spacing:.03em;background:#eef6ea;color:#18461f;border:1px solid #9dc69b;}"
         ".summary-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;}"
         ".inline-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;}"
         ".copy-button-inline{background:#f0f0eb;border:1px solid #d0d0c7;border-radius:6px;padding:2px 7px;font:inherit;font-size:11px;color:#404040;cursor:pointer;}"
         ".copy-button-inline:hover{background:#e6e6de;}"
         ".recent-list{display:grid;gap:12px;}"
         ".recent-item{border:1px solid #e3e3de;border-radius:8px;padding:12px;background:#fbfbf8;}"
         ".recent-item-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;margin-bottom:10px;}"
         ".recent-meta{display:grid;grid-template-columns:minmax(110px,180px) minmax(0,1fr);gap:6px 12px;font-size:14px;}"
         ".route-actions{display:flex;flex-wrap:wrap;gap:8px;}"
         ".weight-flow{white-space:nowrap;}"
         "@media (max-width:780px){h1{font-size:24px;}.grid{grid-template-columns:1fr;}.card{padding:14px 16px;}.badge{font-size:14px;padding:8px 12px;}.mono-block{flex-direction:column;}.copy-button{align-self:flex-start;}}"
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
    return out;
  }
  out.result = *result;
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
LookupResult<AddressResult> fetch_address_result(const Config& cfg, const std::string& addr);
LookupResult<SearchResult> fetch_search_result(const Config& cfg, const std::string& query);
std::vector<RecentTxResult> fetch_recent_tx_results(const Config& cfg, std::size_t max_items);
LookupResult<CommitteeResult> fetch_committee_result(const Config& cfg, std::uint64_t height);

std::string render_status_json(const StatusResult& result);
std::string render_tx_json(const TxResult& result);
std::string render_transition_json(const TransitionResult& result);
std::string render_address_json(const AddressResult& result);
std::string render_search_json(const SearchResult& result);
std::string render_committee_json(const CommitteeResult& result);
std::string render_recent_tx_json(const std::vector<RecentTxResult>& items);

std::string render_root(const Config& cfg) {
  std::ostringstream body;
  body << "<h1>Finalis Explorer</h1>"
       << "<div class=\"card\"><div class=\"note\">Thin explorer backed by lightserver for exchange and operator support."
       << " All views are finalized-state only.</div></div>";
  body << "<div class=\"card\"><h2>Search</h2><form method=\"GET\" action=\"/search\">"
       << "<input type=\"text\" name=\"q\" placeholder=\"txid, transition height/hash, or address\" "
       << "style=\"width:min(100%,720px);padding:10px 12px;font:inherit;border:1px solid #cfcfc6;border-radius:8px;\"> "
       << "<button type=\"submit\" class=\"copy-button\">Search</button></form></div>";
  auto status = fetch_status_result(cfg);
  body << "<div class=\"card\"><h2>Backend</h2><div class=\"grid\">";
  body << "<div>Lightserver RPC</div><div class=\"value-cell\">" << mono_value(cfg.rpc_url) << "</div>";
  if (status.value.has_value()) {
    body << "<div>Network</div><div>" << html_escape(status.value->network) << "</div>"
         << "<div>Network ID</div><div class=\"value-cell\">" << mono_value(status.value->network_id) << "</div>"
         << "<div>Genesis Hash</div><div class=\"value-cell\">" << mono_value(status.value->genesis_hash) << "</div>"
         << "<div>Finalized Tip</div><div class=\"value-cell\">" << link_transition_height(status.value->finalized_height) << " <code>" << html_escape(short_hex(status.value->finalized_transition_hash))
         << "</code> " << finalized_badge(true) << "</div>"
         << "<div>Version</div><div>" << html_escape(status.value->backend_version) << "</div>"
         << "<div>Wallet API</div><div>" << html_escape(status.value->wallet_api_version) << "</div>"
         << "<div>Peers</div><div>healthy=" << status.value->healthy_peer_count << ", established=" << status.value->established_peer_count << "</div>"
         << "<div>Finality Committee</div><div>size=" << status.value->latest_finality_committee_size
         << ", quorum=" << status.value->latest_finality_quorum_threshold << "</div>"
         << "<div>Sync</div><div>";
    if (status.value->bootstrap_sync_incomplete) {
      body << "bootstrap catch-up incomplete";
    } else if (status.value->peer_height_disagreement) {
      body << "peer disagreement detected";
    } else if (status.value->finalized_lag.has_value()) {
      body << "finalized lag=" << *status.value->finalized_lag;
    } else {
      body << "healthy";
    }
    body << "</div>";
  } else {
    body << "<div>Status</div><div class=\"muted\">Unavailable: " << html_escape(status.error->message) << "</div>";
  }
  body << "</div></div>";
  if (status.value.has_value()) {
    body << "<div class=\"card\"><h2>" << html_escape(ticket_pow_title(*status.value))
         << "</h2><div class=\"note\">" << html_escape(ticket_pow_note(*status.value)) << "</div>"
         << "<div class=\"grid\" style=\"margin-top:14px;\">"
         << "<div>Difficulty</div><div>" << status.value->ticket_pow_difficulty << " <span class=\"muted\">(range "
         << status.value->ticket_pow_difficulty_min << "&ndash;" << status.value->ticket_pow_difficulty_max << ")</span></div>"
         << "<div>Epoch Health</div><div>" << html_escape(title_case_health(status.value->ticket_pow_epoch_health)) << "</div>"
         << "<div>Adjustment</div><div>" << html_escape(ticket_pow_adjustment_text(*status.value)) << "</div>"
         << "<div>Streak</div><div>up=" << status.value->ticket_pow_streak_up << ", down=" << status.value->ticket_pow_streak_down << "</div>"
         << "<div>Nonce Budget</div><div>" << status.value->ticket_pow_nonce_search_limit << "</div>"
         << "<div>Bonus Cap</div><div>" << status.value->ticket_pow_bonus_cap_bps << " bps</div>"
         << "</div><div class=\"summary-actions\">"
         << copy_action("Copy Status API Path", "/api/status")
         << "<a class=\"copy-button\" href=\"/committee\">Open Committee</a>"
         << "<a class=\"copy-button\" href=\"/api/committee\">Open Committee API</a>"
         << "</div></div>";
    auto committee = fetch_committee_result(cfg, status.value->finalized_height);
    body << "<div class=\"card\"><h2>Current Committee Operators</h2>";
    if (committee.value.has_value() && !committee.value->members.empty()) {
      body << "<div class=\"table-wrap\"><table><thead><tr><th>Operator</th><th>ID Source</th><th>Representative</th><th class=\"num\">Base Weight</th><th class=\"num\">Ticket Bonus</th><th class=\"num\">Bonus %</th><th class=\"num\">Final Weight</th><th>Weight Composition</th></tr></thead><tbody>";
      for (const auto& member : committee.value->members) {
        const std::string operator_value = member.resolved_operator_id;
        body << "<tr><td><div class=\"inline-actions\"><code>" << html_escape(short_hex(operator_value))
             << "</code>" << inline_copy_action("Copy", operator_value) << "</div></td><td><code>"
             << html_escape(member.operator_id_source) << "</code></td><td><div class=\"inline-actions\"><code>"
             << html_escape(short_hex(member.representative_pubkey)) << "</code>"
             << inline_copy_action("Copy", member.representative_pubkey) << "</div></td><td class=\"num\">";
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
        body << "</td><td>" << weight_composition(member.base_weight, member.ticket_bonus_bps, member.final_weight) << "</td></tr>";
      }
      body << "</tbody></table></div>";
    } else {
      body << "<div class=\"note\">Current finalized committee operator detail is unavailable from the backend. Check the finalized committee checkpoint and lightserver verbose committee view.</div>";
    }
    body << "</div>";
    body << "<div class=\"card\"><h2>Availability Enforcement</h2><div class=\"note\">Finalized-history-derived BPoAR eligibility now gates future committee checkpoints. When eligible operator count is below the configured minimum, the node reports that fallback explicitly.</div>"
         << "<div class=\"grid\" style=\"margin-top:14px;\">"
         << "<div>Epoch</div><div>" << (status.value->availability_epoch.has_value() ? std::to_string(*status.value->availability_epoch) : std::string("n/a")) << "</div>"
         << "<div>Retained Prefixes</div><div>" << (status.value->availability_retained_prefix_count.has_value() ? std::to_string(*status.value->availability_retained_prefix_count) : std::string("n/a")) << "</div>"
         << "<div>Tracked Operators</div><div>" << (status.value->availability_tracked_operator_count.has_value() ? std::to_string(*status.value->availability_tracked_operator_count) : std::string("n/a")) << "</div>"
         << "<div>Eligible Operators</div><div>" << (status.value->availability_eligible_operator_count.has_value() ? std::to_string(*status.value->availability_eligible_operator_count) : std::string("n/a")) << "</div>"
         << "<div>Below Min Eligible</div><div>" << (status.value->availability_below_min_eligible.has_value() ? yes_no(*status.value->availability_below_min_eligible) : std::string("n/a")) << "</div>"
         << "<div>Checkpoint Mode</div><div>" << html_escape(status.value->availability_checkpoint_derivation_mode.value_or("n/a")) << "</div>"
         << "<div>Checkpoint Fallback Reason</div><div>" << html_escape(status.value->availability_checkpoint_fallback_reason.value_or("n/a")) << "</div>"
         << "<div>Sticky Fallback</div><div>"
         << (status.value->availability_fallback_sticky.has_value() ? yes_no(*status.value->availability_fallback_sticky)
                                                                   : std::string("n/a"))
         << "</div>"
         << "<div>Qualified Operator Depth</div><div>"
         << (status.value->qualified_depth.has_value() ? std::to_string(*status.value->qualified_depth) : std::string("n/a"))
         << "</div>"
         << "<div>Adaptive Committee Target</div><div>"
         << (status.value->adaptive_target_committee_size.has_value()
                 ? std::to_string(*status.value->adaptive_target_committee_size)
                 : std::string("n/a"))
         << "</div>"
         << "<div>Adaptive Eligible Threshold</div><div>"
         << (status.value->adaptive_min_eligible.has_value() ? std::to_string(*status.value->adaptive_min_eligible)
                                                             : std::string("n/a"))
         << "</div>"
         << "<div>Adaptive Bond Floor</div><div>"
         << (status.value->adaptive_min_bond.has_value() ? format_amount(*status.value->adaptive_min_bond) : std::string("n/a"))
         << "</div>"
         << "<div>Eligibility Slack</div><div>"
         << (status.value->adaptive_slack.has_value() ? std::to_string(*status.value->adaptive_slack) : std::string("n/a"))
         << "</div>"
         << "<div>Target Expand Streak</div><div>"
         << (status.value->target_expand_streak.has_value() ? std::to_string(*status.value->target_expand_streak)
                                                            : std::string("n/a"))
         << "</div>"
         << "<div>Target Contract Streak</div><div>"
         << (status.value->target_contract_streak.has_value() ? std::to_string(*status.value->target_contract_streak)
                                                              : std::string("n/a"))
         << "</div>"
         << "<div>Fallback Rate</div><div>";
    if (status.value->adaptive_fallback_rate_bps.has_value()) {
      body << html_escape(format_bonus_percent(static_cast<std::uint32_t>(*status.value->adaptive_fallback_rate_bps)));
      if (status.value->adaptive_fallback_window_epochs.has_value()) {
        body << " <span class=\"muted\">(" << *status.value->adaptive_fallback_window_epochs << " epoch window)</span>";
      }
    } else {
      body << "n/a";
    }
    body << "</div><div>Sticky Fallback Rate</div><div>";
    if (status.value->adaptive_sticky_fallback_rate_bps.has_value()) {
      body << html_escape(
          format_bonus_percent(static_cast<std::uint32_t>(*status.value->adaptive_sticky_fallback_rate_bps)));
    } else {
      body << "n/a";
    }
    body << "</div><div>Telemetry Sample Count</div><div>"
         << (status.value->adaptive_telemetry_sample_count.has_value()
                 ? std::to_string(*status.value->adaptive_telemetry_sample_count)
                 : std::string("n/a"))
         << "</div>"
         << "<div>Telemetry Fallback Epochs</div><div>"
         << (status.value->adaptive_telemetry_fallback_epochs.has_value()
                 ? std::to_string(*status.value->adaptive_telemetry_fallback_epochs)
                 : std::string("n/a"))
         << "</div>"
         << "<div>Telemetry Sticky Fallback Epochs</div><div>"
         << (status.value->adaptive_telemetry_sticky_fallback_epochs.has_value()
                 ? std::to_string(*status.value->adaptive_telemetry_sticky_fallback_epochs)
                 : std::string("n/a"))
         << "</div>";
    body << "<div>Adaptive Alert Flags</div><div>";
    std::vector<std::string> adaptive_alerts;
    if (status.value->adaptive_near_threshold_operation.value_or(false)) adaptive_alerts.push_back("near-threshold");
    if (status.value->adaptive_prolonged_expand_buildup.value_or(false)) adaptive_alerts.push_back("expand-build");
    if (status.value->adaptive_prolonged_contract_buildup.value_or(false)) adaptive_alerts.push_back("contract-build");
    if (status.value->adaptive_repeated_sticky_fallback.value_or(false)) adaptive_alerts.push_back("sticky-repeat");
    if (status.value->adaptive_depth_collapse_after_bond_increase.value_or(false)) {
      adaptive_alerts.push_back("depth-drop-after-bond-rise");
    }
    if (adaptive_alerts.empty()) {
      body << "<span class=\"muted\">none</span>";
    } else {
      for (std::size_t i = 0; i < adaptive_alerts.size(); ++i) {
        if (i) body << ", ";
        body << html_escape(adaptive_alerts[i]);
      }
    }
    body << "</div><div>Local Operator</div><div>";
    if (status.value->availability_local_operator_known.value_or(false)) {
      body << html_escape(status.value->availability_local_operator_status.value_or("unknown"));
      if (status.value->availability_local_operator_seat_budget.has_value()) {
        body << " (seat budget " << *status.value->availability_local_operator_seat_budget << ")";
      }
      if (status.value->availability_local_operator_pubkey.has_value()) {
        body << " <code>" << html_escape(short_hex(*status.value->availability_local_operator_pubkey)) << "</code>";
      }
    } else {
      body << "n/a";
    }
    body << "</div></div></div>";
  }
  const auto recent = fetch_recent_tx_results(cfg, 8);
  body << "<div class=\"card\"><h2>Finalized Transactions</h2>";
  if (!recent.empty()) {
    body << "<div class=\"recent-list\">";
    for (const auto& item : recent) {
      const std::string tx_path = "/tx/" + item.txid;
      const std::string api_path = "/api/tx/" + item.txid;
      body << "<div class=\"recent-item\"><div class=\"recent-item-head\"><div>" << link_tx(item.txid)
           << "</div><div class=\"copy-button-row\">" << copy_action("Copy Txid", item.txid)
           << copy_action("Copy Page Path", tx_path) << copy_action("Copy API Path", api_path) << "</div></div>"
           << "<div class=\"recent-meta\">";
      if (item.height.has_value()) body << "<div>Height</div><div>" << link_transition_height(*item.height) << "</div>";
      if (item.timestamp.has_value()) body << "<div>Timestamp</div><div>" << html_escape(format_timestamp(*item.timestamp)) << "</div>";
      if (item.total_out.has_value()) body << "<div>Total Out</div><div>" << html_escape(format_amount(*item.total_out)) << "</div>";
      if (item.status_label.has_value()) body << "<div>Status</div><div>" << html_escape(*item.status_label) << "</div>";
      if (item.credit_safe.has_value()) body << "<div>Credit Safe</div><div>" << credit_safe_text(*item.credit_safe) << "</div>";
      body << "</div></div>";
    }
    body << "</div>";
  } else {
    body << "<div class=\"note\">No recent finalized transactions available from the current backend view.</div>";
  }
  body << "</div>";
  body << "<div class=\"card\"><h2>Routes</h2><ul>"
       << "<li><code>/tx/&lt;txid&gt;</code></li>"
       << "<li><code>/transition/&lt;height&gt;</code> or <code>/transition/&lt;hash&gt;</code></li>"
       << "<li><code>/address/&lt;address&gt;</code></li>"
       << "<li><code>/committee</code></li>"
       << "</ul></div>";
  return page_layout("Finalis Explorer", body.str());
}

std::string render_committee(const Config& cfg) {
  std::ostringstream body;
  body << "<h1>Committee</h1>";
  auto status = fetch_status_result(cfg);
  if (!status.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Status unavailable: "
         << html_escape(status.error ? status.error->message : "unknown error") << "</div></div>";
    return page_layout("Committee", body.str());
  }
  auto committee = fetch_committee_result(cfg, status.value->finalized_height);
  if (!committee.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Committee unavailable: "
         << html_escape(committee.error ? committee.error->message : "unknown error") << "</div></div>";
    return page_layout("Committee", body.str());
  }
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
  return page_layout("Committee", body.str());
}

std::optional<finalis::Block> fetch_transition_by_height(const Config& cfg, std::uint64_t height,
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
  auto transition = finalis::Block::parse(*bytes);
  if (!transition.has_value()) {
    if (err) *err = "transition parse failed";
    return std::nullopt;
  }
  if (transition_hash_hex) *transition_hash_hex = hash;
  return transition;
}

std::optional<finalis::Block> fetch_transition_by_hash(const Config& cfg, const std::string& hash_hex, std::string* err) {
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
  auto transition = finalis::Block::parse(*bytes);
  if (!transition.has_value()) {
    if (err) *err = "transition parse failed";
    return std::nullopt;
  }
  return transition;
}

LookupResult<StatusResult> fetch_status_result(const Config& cfg) {
  LookupResult<StatusResult> out;
  auto status = rpc_call(cfg.rpc_url, "get_status", "{}");
  if (!status.result.has_value() || !status.result->is_object()) {
    out.error = upstream_error(status.error.empty() ? "status unavailable" : status.error);
    return out;
  }
  StatusResult result;
  result.network = object_string(&*status.result, "network_name").value_or("unknown");
  result.network_id = object_string(&*status.result, "network_id").value_or("");
  result.genesis_hash = object_string(&*status.result, "genesis_hash").value_or("");
  result.finalized_height = object_u64(&*status.result, "finalized_height").value_or(0);
  result.finalized_transition_hash = object_string(&*status.result, "finalized_transition_hash")
                                         .value_or(object_string(&*status.result, "transition_hash").value_or(""));
  result.backend_version = object_string(&*status.result, "version").value_or("unknown");
  result.wallet_api_version = object_string(&*status.result, "wallet_api_version").value_or("");
  result.healthy_peer_count = object_u64(&*status.result, "healthy_peer_count").value_or(0);
  result.established_peer_count = object_u64(&*status.result, "established_peer_count").value_or(0);
  result.latest_finality_committee_size =
      static_cast<std::size_t>(object_u64(&*status.result, "latest_finality_committee_size").value_or(0));
  result.latest_finality_quorum_threshold =
      static_cast<std::size_t>(object_u64(&*status.result, "latest_finality_quorum_threshold").value_or(0));
  if (const auto* sync = status.result->get("sync"); sync && sync->is_object()) {
    result.observed_network_height_known = object_bool(sync, "observed_network_height_known").value_or(false);
    result.bootstrap_sync_incomplete = object_bool(sync, "bootstrap_sync_incomplete").value_or(false);
    result.peer_height_disagreement = object_bool(sync, "peer_height_disagreement").value_or(false);
    result.finalized_lag = object_u64(sync, "finalized_lag");
    if (result.observed_network_height_known) {
      result.observed_network_finalized_height = object_u64(sync, "observed_network_finalized_height");
    }
  }
  if (const auto* availability = status.result->get("availability"); availability && availability->is_object()) {
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
  if (const auto* adaptive_summary = status.result->get("adaptive_telemetry_summary");
      adaptive_summary && adaptive_summary->is_object()) {
    result.adaptive_telemetry_window_epochs = object_u64(adaptive_summary, "window_epochs");
    result.adaptive_telemetry_sample_count = object_u64(adaptive_summary, "sample_count");
    result.adaptive_telemetry_fallback_epochs = object_u64(adaptive_summary, "fallback_epochs");
    result.adaptive_telemetry_sticky_fallback_epochs = object_u64(adaptive_summary, "sticky_fallback_epochs");
  }
  if (const auto* ticket_pow = status.result->get("ticket_pow"); ticket_pow && ticket_pow->is_object()) {
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

LookupResult<CommitteeResult> fetch_committee_result(const Config& cfg, std::uint64_t height) {
  LookupResult<CommitteeResult> out;
  auto rpc = rpc_call(cfg.rpc_url, "get_committee",
                      std::string("{\"height\":") + std::to_string(height) + ",\"verbose\":true}");
  if (!rpc.result.has_value() || !rpc.result->is_object()) {
    out.error = rpc_not_found(rpc) ? not_found_error("committee unavailable in finalized state")
                                   : upstream_error(rpc.error.empty() ? "committee unavailable" : rpc.error);
    return out;
  }
  CommitteeResult result;
  result.height = object_u64(&*rpc.result, "height").value_or(height);
  result.epoch_start_height = object_u64(&*rpc.result, "epoch_start_height").value_or(0);
  result.checkpoint_derivation_mode = object_string(&*rpc.result, "checkpoint_derivation_mode");
  result.checkpoint_fallback_reason = object_string(&*rpc.result, "checkpoint_fallback_reason");
  result.fallback_sticky = object_bool(&*rpc.result, "fallback_sticky");
  result.availability_eligible_operator_count = object_u64(&*rpc.result, "availability_eligible_operator_count");
  result.availability_min_eligible_operators = object_u64(&*rpc.result, "availability_min_eligible_operators");
  result.adaptive_target_committee_size = object_u64(&*rpc.result, "adaptive_target_committee_size");
  result.adaptive_min_eligible = object_u64(&*rpc.result, "adaptive_min_eligible");
  result.adaptive_min_bond = object_u64(&*rpc.result, "adaptive_min_bond");
  result.qualified_depth = object_u64(&*rpc.result, "qualified_depth");
  result.adaptive_slack = object_i64(&*rpc.result, "slack");
  result.target_expand_streak = object_u64(&*rpc.result, "target_expand_streak");
  result.target_contract_streak = object_u64(&*rpc.result, "target_contract_streak");
  const auto* members = rpc.result->get("members");
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

LookupResult<TransitionResult> fetch_transition_result(const Config& cfg, const std::string& ident) {
  LookupResult<TransitionResult> out;
  if (is_digits(ident)) {
    try {
      const auto height = static_cast<std::uint64_t>(std::stoull(ident));
      std::string err;
      std::string transition_hash_hex;
      auto blk = fetch_transition_by_height(cfg, height, &transition_hash_hex, &err);
      if (!blk.has_value()) {
        out.error = err == "not_found" ? not_found_error() : upstream_error(err);
        return out;
      }
      TransitionResult result;
      result.found = true;
      result.height = blk->header.height;
      result.hash = transition_hash_hex;
      result.prev_finalized_hash = finalis::hex_encode32(blk->header.prev_finalized_hash);
      result.timestamp = blk->header.timestamp;
      result.round = blk->header.round;
      result.tx_count = blk->txs.size();
      result.txids.reserve(blk->txs.size());
      for (const auto& tx : blk->txs) result.txids.push_back(finalis::hex_encode32(tx.txid()));
      out.value = std::move(result);
      return out;
    } catch (...) {
      out.error = make_error(400, "invalid_transition_id", "malformed transition id");
      return out;
    }
  } else if (is_hex64(ident)) {
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
    result.height = blk->header.height;
    result.hash = finalis::hex_encode32(blk->header.block_id());
    result.prev_finalized_hash = finalis::hex_encode32(blk->header.prev_finalized_hash);
    result.timestamp = blk->header.timestamp;
    result.round = blk->header.round;
    result.tx_count = blk->txs.size();
    result.txids.reserve(blk->txs.size());
    for (const auto& tx : blk->txs) result.txids.push_back(finalis::hex_encode32(tx.txid()));
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
  auto tx = tx_bytes ? finalis::Tx::parse(*tx_bytes) : std::nullopt;
  if (!tx.has_value()) {
    out.error = upstream_error("tx parse failed");
    return out;
  }

  std::string network_name = "mainnet";
  if (auto st = fetch_status_result(cfg); st.value.has_value()) network_name = st.value->network;
  const std::string hrp = hrp_for_network_name(network_name);

  if (result.finalized_height.has_value()) {
    std::string transition_hash;
    std::string block_err;
    auto blk = fetch_transition_by_height(cfg, *result.finalized_height, &transition_hash, &block_err);
    if (blk.has_value()) result.timestamp = blk->header.timestamp;
  }

  std::uint64_t total_in = 0;
  bool fee_known = true;
  for (const auto& in : tx->inputs) {
    result.inputs.push_back(TxInputResult{finalis::hex_encode32(in.prev_txid), in.prev_index});
    auto prev_call = rpc_call(cfg.rpc_url, "get_tx", std::string("{\"txid\":\"") + finalis::hex_encode32(in.prev_txid) + "\"}");
    if (!prev_call.result.has_value() || !prev_call.result->is_object()) {
      fee_known = false;
      continue;
    }
    auto prev_hex = object_string(&*prev_call.result, "tx_hex");
    if (!prev_hex) {
      fee_known = false;
      continue;
    }
    auto prev_bytes = finalis::hex_decode(*prev_hex);
    auto prev_tx = prev_bytes ? finalis::Tx::parse(*prev_bytes) : std::nullopt;
    if (!prev_tx.has_value() || in.prev_index >= prev_tx->outputs.size()) {
      fee_known = false;
      continue;
    }
    total_in += prev_tx->outputs[in.prev_index].value;
  }

  for (const auto& tx_out : tx->outputs) {
    result.total_out += tx_out.value;
    result.outputs.push_back(TxOutputResult{
        tx_out.value,
        script_to_address(tx_out.script_pubkey, hrp),
        finalis::hex_encode(tx_out.script_pubkey),
    });
  }
  if (fee_known && total_in >= result.total_out) result.fee = total_in - result.total_out;
  out.value = std::move(result);
  return out;
}

LookupResult<AddressResult> fetch_address_result(const Config& cfg, const std::string& addr) {
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

  std::optional<std::uint64_t> cursor_height;
  std::optional<std::string> cursor_txid;
  for (int page = 0; page < 5; ++page) {
    std::ostringstream params;
    params << "{\"scripthash_hex\":\"" << finalis::hex_encode32(scripthash) << "\",\"limit\":100";
    if (cursor_height.has_value() && cursor_txid.has_value()) {
      params << ",\"start_after\":{\"height\":" << *cursor_height << ",\"txid\":\"" << *cursor_txid << "\"}";
    }
    params << "}";
    auto res = rpc_call(cfg.rpc_url, "get_history_page", params.str());
    if (!res.result.has_value() || !res.result->is_object()) {
      out.error = upstream_error(res.error.empty() ? "history lookup failed" : res.error);
      return out;
    }
    const auto* items = res.result->get("items");
    if (!items || !items->is_array()) break;
    for (const auto& item : items->array_value) {
      auto txid = object_string(&item, "txid");
      auto height = object_u64(&item, "height");
      if (!txid || !height) continue;
      result.history.items.push_back(AddressHistoryItemResult{*txid, *height});
    }
    result.history.has_more = object_bool(&*res.result, "has_more").value_or(false);
    result.history.next_cursor.reset();
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
  std::vector<RecentTxResult> out;
  if (max_items == 0) return out;
  auto status = fetch_status_result(cfg);
  if (!status.value.has_value()) return out;
  const auto tip = status.value->finalized_height;
  const std::uint64_t start_height = tip > 4 ? tip - 4 : 0;
  for (std::uint64_t h = tip + 1; h-- > start_height && out.size() < max_items;) {
    std::string err;
    std::string transition_hash_hex;
    auto blk = fetch_transition_by_height(cfg, h, &transition_hash_hex, &err);
    if (!blk.has_value()) continue;
    for (const auto& tx : blk->txs) {
      if (out.size() >= max_items) break;
      RecentTxResult item;
      item.txid = finalis::hex_encode32(tx.txid());
      item.height = h;
      item.timestamp = blk->header.timestamp;
      std::uint64_t total_out = 0;
      for (const auto& tx_out : tx.outputs) total_out += tx_out.value;
      item.total_out = total_out;
      auto tx_lookup = fetch_tx_result(cfg, item.txid);
      if (tx_lookup.value.has_value()) {
        item.status_label = tx_lookup.value->status_label;
        item.credit_safe = tx_lookup.value->credit_safe;
      }
      out.push_back(std::move(item));
    }
    if (h == 0) break;
  }
  return out;
}

std::string render_status_json(const StatusResult& result) {
  std::ostringstream oss;
  oss << "{\"network\":\"" << json_escape(result.network) << "\","
      << "\"network_id\":\"" << json_escape(result.network_id) << "\","
      << "\"genesis_hash\":\"" << json_escape(result.genesis_hash) << "\","
      << "\"finalized_height\":" << result.finalized_height << ","
      << "\"finalized_transition_hash\":\"" << json_escape(result.finalized_transition_hash) << "\","
      << "\"backend_version\":\"" << json_escape(result.backend_version) << "\","
      << "\"wallet_api_version\":\"" << json_escape(result.wallet_api_version) << "\","
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
  for (const auto& output : result.outputs) {
    if (output.address.has_value()) ++decoded_output_count;
  }
  oss << "],\"total_out\":" << result.total_out << ",\"fee\":"
      << (result.fee.has_value() ? std::to_string(*result.fee) : "null") << ","
      << "\"input_count\":" << result.inputs.size() << ",\"output_count\":" << result.outputs.size()
      << ",\"decoded_output_count\":" << decoded_output_count << ","
      << "\"finalized_only\":true}";
  return oss.str();
}

std::string render_transition_json(const TransitionResult& result) {
  std::ostringstream oss;
  oss << "{\"found\":" << json_bool(result.found) << ",\"finalized\":true,"
      << "\"height\":" << result.height << ",\"hash\":\"" << json_escape(result.hash) << "\","
      << "\"prev_finalized_hash\":\"" << json_escape(result.prev_finalized_hash) << "\","
      << "\"timestamp\":" << result.timestamp << ",\"round\":" << result.round
      << ",\"tx_count\":" << result.tx_count << ",\"txids\":[";
  for (std::size_t i = 0; i < result.txids.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << json_escape(result.txids[i]) << "\"";
  }
  oss << "],\"finalized_only\":true,\"snapshot_kind\":\"finalized_transition\"}";
  return oss.str();
}

std::string render_address_json(const AddressResult& result) {
  std::ostringstream oss;
  std::uint64_t finalized_balance = 0;
  for (const auto& utxo : result.utxos) finalized_balance += utxo.amount;
  oss << "{\"address\":\"" << json_escape(result.address) << "\","
      << "\"found\":" << json_bool(result.found) << ",\"finalized_balance\":" << finalized_balance
      << ",\"history_slice_complete\":" << json_bool(!result.history.has_more) << ",\"utxos\":[";
  for (std::size_t i = 0; i < result.utxos.size(); ++i) {
    if (i) oss << ",";
    oss << "{\"txid\":\"" << json_escape(result.utxos[i].txid) << "\",\"vout\":" << result.utxos[i].vout
        << ",\"amount\":" << result.utxos[i].amount << ",\"height\":" << result.utxos[i].height << "}";
  }
  oss << "],\"history\":{\"items\":[";
  for (std::size_t i = 0; i < result.history.items.size(); ++i) {
    if (i) oss << ",";
    oss << "{\"txid\":\"" << json_escape(result.history.items[i].txid) << "\",\"height\":"
        << result.history.items[i].height << "}";
  }
  oss << "],\"has_more\":" << json_bool(result.history.has_more) << ",\"next_cursor\":"
      << json_string_or_null(result.history.next_cursor) << "},\"finalized_only\":true}";
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

std::string render_committee_json(const CommitteeResult& result) {
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

std::string render_recent_tx_json(const std::vector<RecentTxResult>& items) {
  std::ostringstream oss;
  oss << "{\"items\":[";
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i) oss << ",";
    const auto& item = items[i];
    oss << "{\"txid\":\"" << json_escape(item.txid) << "\""
        << ",\"height\":" << json_u64_or_null(item.height)
        << ",\"timestamp\":" << json_u64_or_null(item.timestamp)
        << ",\"total_out\":" << json_u64_or_null(item.total_out)
        << ",\"status_label\":" << json_string_or_null(item.status_label)
        << ",\"credit_safe\":";
    if (item.credit_safe.has_value()) oss << json_bool(*item.credit_safe);
    else oss << "null";
    oss << "}";
  }
  oss << "],\"finalized_only\":true,\"snapshot_kind\":\"recent_finalized_transactions\"}";
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
    return page_layout("Transaction", body.str());
  }
  const auto& tx = *lookup.value;
  const std::string tx_path = "/tx/" + tx.txid;
  const std::string tx_api_path = "/api/tx/" + tx.txid;

  body << "<div class=\"card\"><div class=\"status-hero\">"
       << "<div>" << mono_value(tx.txid) << "</div><div>" << finalized_badge(tx.finalized) << " "
       << credit_safe_badge(tx.credit_safe) << "</div></div>"
       << "<div class=\"decision-line\">" << html_escape(credit_decision_text(tx.finalized, tx.credit_safe)) << "</div>"
       << "<div class=\"note\">Transaction view is finalized-state only. Relay acceptance, mempool state, and pre-finality observations are intentionally not shown here.</div>"
       << "<div class=\"grid\" style=\"margin-top:14px;\">"
       << "<div>Txid</div><div class=\"value-cell\">" << mono_value(tx.txid) << "</div>"
       << "<div>Status</div><div>" << html_escape(tx.status_label) << "</div>"
       << "<div>Finalized</div><div>" << finalized_text(tx.finalized) << "</div>"
       << "<div>Credit Safe</div><div>" << credit_safe_text(tx.credit_safe) << "</div>"
       << "<div>Finalized Only</div><div>yes</div>";
  if (tx.finalized_height.has_value()) body << "<div>Finalized Height</div><div>" << link_transition_height(*tx.finalized_height) << "</div>";
  if (!tx.transition_hash.empty()) body << "<div>Transition Hash</div><div class=\"value-cell\">" << mono_value(tx.transition_hash) << "</div>";
  if (tx.timestamp.has_value()) body << "<div>Timestamp</div><div>" << html_escape(format_timestamp(*tx.timestamp)) << "</div>";
  body << "<div>Finalized Depth</div><div>" << tx.finalized_depth << "</div>";
  body << "<div>Input Count</div><div>" << tx.inputs.size() << "</div>";
  body << "<div>Output Count</div><div>" << tx.outputs.size() << "</div>";
  if (tx.fee.has_value()) body << "<div>Fee</div><div>" << html_escape(format_amount(*tx.fee)) << "</div>";
  body << "<div>Total Out</div><div>" << html_escape(format_amount(tx.total_out)) << "</div>"
       << "</div><div class=\"summary-actions\">"
       << copy_action("Copy Txid", tx.txid)
       << copy_action("Copy Page Path", tx_path)
       << copy_action("Copy API Path", tx_api_path);
  if (!tx.transition_hash.empty()) body << copy_action("Copy Transition Hash", tx.transition_hash);
  body << "</div></div>";

  body << "<div class=\"card\"><h2>Inputs</h2><div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Prev Tx</th><th>Vout</th></tr></thead><tbody>";
  for (std::size_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& in = tx.inputs[i];
    body << "<tr><td>" << i << "</td><td>" << link_tx(in.prev_txid) << "</td><td>" << in.vout
         << "</td></tr>";
  }
  if (tx.inputs.empty()) body << "<tr><td colspan=\"3\" class=\"muted\">No inputs</td></tr>";
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

  return page_layout("Transaction " + txid_hex, body.str());
}

std::string render_transition(const Config& cfg, const std::string& ident) {
  std::ostringstream body;
  body << "<h1>Transition</h1>";
  auto lookup = fetch_transition_result(cfg, ident);
  if (!lookup.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Lookup failed: "
         << html_escape(lookup.error ? lookup.error->message : "unknown error") << "</div></div>";
    return page_layout("Transition", body.str());
  }
  const auto& transition = *lookup.value;
  const std::string transition_path = "/transition/" + transition.hash;
  const std::string transition_api_path = "/api/transition/" + transition.hash;

  body << "<div class=\"card\"><div class=\"status-hero\">"
       << "<div>" << mono_value(transition.hash) << "</div><div>" << finalized_badge(true) << "</div></div>"
       << "<div class=\"note\">Transition view is finalized-only. It shows the finalized checkpoint contents for one height, not proposal-stage or unfinalized round activity.</div>"
       << "<div class=\"grid\" style=\"margin-top:14px;\">"
       << "<div>Height</div><div>" << transition.height << "</div>"
       << "<div>Transition Hash</div><div class=\"value-cell\">" << mono_value(transition.hash) << "</div>"
       << "<div>Prev Finalized Hash</div><div class=\"value-cell\">" << mono_value(transition.prev_finalized_hash)
       << "</div>"
       << "<div>Timestamp</div><div>" << html_escape(format_timestamp(transition.timestamp)) << "</div>"
       << "<div>Round</div><div>" << transition.round << "</div>"
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
  if (transition.txids.empty()) body << "<tr><td colspan=\"3\" class=\"muted\">No transactions</td></tr>";
  body << "</tbody></table></div></div>";
  return page_layout("Transition " + transition.hash, body.str());
}

std::string render_address(const Config& cfg, const std::string& addr) {
  std::ostringstream body;
  body << "<h1>Address</h1>";
  auto lookup = fetch_address_result(cfg, addr);
  if (!lookup.value.has_value()) {
    body << "<div class=\"card\"><div class=\"note\">Lookup failed: "
         << html_escape(lookup.error ? lookup.error->message : "unknown error") << "</div></div>";
    return page_layout("Address", body.str());
  }
  const auto& address = *lookup.value;
  const std::string address_path = "/address/" + addr;
  const std::string address_api_path = "/api/address/" + addr;
  std::uint64_t finalized_balance = 0;
  for (const auto& u : address.utxos) finalized_balance += u.amount;
  body << "<div class=\"card\"><div class=\"status-hero\">"
       << "<div>" << mono_value(addr) << "</div><div>" << finalized_badge(true) << "</div></div>"
       << "<div class=\"note\">Address view is finalized-state only. It shows current finalized UTXOs plus a paginated finalized-history slice, not live mempool activity.</div>"
       << "<div class=\"grid\" style=\"margin-top:14px;\">"
       << "<div>Address</div><div class=\"value-cell\">" << mono_value(addr) << "</div>"
       << "<div>Finalized Activity</div><div>" << (address.found ? "yes" : "no") << "</div>"
       << "<div>Finalized UTXOs</div><div>" << address.utxos.size() << "</div>"
       << "<div>Finalized Balance</div><div>" << html_escape(format_amount(finalized_balance)) << "</div>"
       << "<div>History Items (Page)</div><div>" << address.history.items.size() << "</div>"
       << "<div>History Slice Complete</div><div>" << (address.history.has_more ? "no" : "yes") << "</div>";
  if (address.history.has_more && address.history.next_cursor.has_value()) {
    body << "<div>Next Cursor</div><div class=\"value-cell\"><code>" << html_escape(*address.history.next_cursor) << "</code></div>";
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

  body << "<div class=\"card\"><h2>Finalized History</h2><div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Txid</th><th>Height</th></tr></thead><tbody>";
  if (!address.history.items.empty()) {
    for (std::size_t i = 0; i < address.history.items.size(); ++i) {
      const auto& item = address.history.items[i];
      body << "<tr><td>" << i << "</td><td>" << link_tx(item.txid) << "</td><td>" << link_transition_height(item.height) << "</td></tr>";
    }
  } else {
    body << "<tr><td colspan=\"3\" class=\"muted\">No finalized history found.</td></tr>";
  }
  body << "</tbody></table></div></div>";
  if (address.history.has_more) {
    body << "<div class=\"card\"><div class=\"note\">Additional finalized history exists.";
    if (address.history.next_cursor.has_value()) body << " Next cursor: <code>" << html_escape(*address.history.next_cursor) << "</code>";
    body << "</div></div>";
  }

  return page_layout("Address " + addr, body.str());
}

bool write_all(int fd, const std::string& data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
    if (n <= 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

std::optional<std::string> read_http_request(int fd) {
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
    return result.value.has_value() ? json_response(200, render_status_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path == "/api/committee") {
    auto status = fetch_status_result(cfg);
    if (!status.value.has_value()) return json_error_response(*status.error);
    auto result = fetch_committee_result(cfg, status.value->finalized_height);
    return result.value.has_value() ? json_response(200, render_committee_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path == "/api/recent-tx") {
    return json_response(200, render_recent_tx_json(fetch_recent_tx_results(cfg, 8)));
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
    return result.value.has_value() ? json_response(200, render_transition_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path.rfind(api_address_prefix, 0) == 0) {
    auto result = fetch_address_result(cfg, path.substr(api_address_prefix.size()));
    return result.value.has_value() ? json_response(200, render_address_json(*result.value))
                                    : json_error_response(*result.error);
  }
  if (path.rfind(transition_prefix, 0) == 0) {
    return html_response(200, render_transition(cfg, path.substr(transition_prefix.size())));
  }
  if (path.rfind(tx_prefix, 0) == 0) return html_response(200, render_tx(cfg, path.substr(tx_prefix.size())));
  if (path.rfind(address_prefix, 0) == 0) return html_response(200, render_address(cfg, path.substr(address_prefix.size())));
  return html_response(404, render_not_found());
}

}  // namespace

int main(int argc, char** argv) {
  auto cfg = parse_args(argc, argv);
  if (!cfg.has_value()) {
    std::cerr << "usage: finalis-explorer [--bind 127.0.0.1] [--port 18080] [--rpc-url http://127.0.0.1:19444/rpc]\n";
    return 1;
  }

  int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    std::cerr << "socket failed\n";
    return 1;
  }
  int one = 1;
  (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg->port);
  if (::inet_pton(AF_INET, cfg->bind_ip.c_str(), &addr.sin_addr) != 1) {
    std::cerr << "invalid bind address\n";
    ::close(listen_fd);
    return 1;
  }
  if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::cerr << "bind failed\n";
    ::close(listen_fd);
    return 1;
  }
  if (::listen(listen_fd, 32) != 0) {
    std::cerr << "listen failed\n";
    ::close(listen_fd);
    return 1;
  }

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::cout << "finalis-explorer listening on http://" << cfg->bind_ip << ":" << cfg->port
            << " using lightserver " << cfg->rpc_url << "\n";

  while (!g_stop) {
    sockaddr_in client{};
    socklen_t len = sizeof(client);
    const int fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&client), &len);
    if (fd < 0) {
      if (g_stop) break;
      continue;
    }
    auto req = read_http_request(fd);
    const Response resp_obj =
        req.has_value() ? handle_request(*cfg, *req)
                        : html_response(400, page_layout("Bad Request", "<h1>Bad Request</h1>"));
    const std::string resp = http_response(resp_obj);
    (void)write_all(fd, resp);
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
  }

  ::close(listen_fd);
  return 0;
}
