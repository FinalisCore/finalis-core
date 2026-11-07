// SPDX-License-Identifier: MIT
// finalis-nodetest: the parts of the testnet traffic tool that need no network (options, network
// guard, pacing, peers file, wallet file, sweep, summary). main.cpp drives them against a lightserver.

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "crypto/confidential.hpp"
#include "lightserver/client.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/tx.hpp"

namespace finalis::nodetest {

// Per-participant limits. Defaults keep 13 validators running at once (1.3 tx/s in total) near the
// 2026-11-03 two-host load test (~1.3 tx/s, all final), well under the per-block record and
// confidential-verify caps.
inline constexpr double kDefaultRate = 0.1;  // tx per second
inline constexpr double kMaxRate = 1.0;
inline constexpr std::uint64_t kDefaultDurationSeconds = 30 * 60;
inline constexpr std::uint64_t kMaxDurationSeconds = 4 * 60 * 60;
inline constexpr std::uint64_t kDefaultDrainSeconds = 10 * 60;
inline constexpr std::size_t kWalletKeys = 8;
inline constexpr std::size_t kMaxPeers = 1000;
// Backoff after a retryable reject (relay_unavailable, mempool full, fee too low): doubles from the
// first value up to the cap; an accepted transaction resets it.
inline constexpr double kBackoffFirstSeconds = 5.0;
inline constexpr double kBackoffMaxSeconds = 300.0;
// This many non-retryable rejects in a row stop the run (something is wrong with the tool or node).
inline constexpr std::uint64_t kMaxConsecutiveRejects = 25;

enum class TxType : std::uint8_t { Std, HLock, Inherit, Shield, C2C, Unshield, Timed, TimedLong, Seal, SealLong };
inline constexpr std::array<TxType, 10> kAllTypes{TxType::Std,      TxType::HLock,    TxType::Inherit, TxType::Shield,
                                                  TxType::C2C,      TxType::Unshield, TxType::Timed,   TxType::TimedLong,
                                                  TxType::Seal,     TxType::SealLong};
std::string type_name(TxType t);
std::optional<TxType> parse_type(const std::string& name);
// Relative frequency of each type in a run (time locks hold 0.1 FLS each, so they are rarer).
std::uint32_t type_weight(TxType t);
bool is_timed_type(TxType t);

struct Options {
  std::string command{"run"};  // run | sweep | status | address | help
  std::string dir;             // wallet + logs: absolute path after parse_options (default ~/.finalis-nodetest)
  std::string rpc;             // default: the local testnet lightserver
  double rate{kDefaultRate};
  std::uint64_t duration_seconds{kDefaultDurationSeconds};
  std::uint64_t drain_seconds{kDefaultDrainSeconds};
  std::string peers_file;
  std::vector<TxType> types{kAllTypes.begin(), kAllTypes.end()};
  std::uint64_t min_peers{2};
  std::optional<std::int64_t> start_at_unix;  // --start-at: shared start time (UTC), unix seconds
  bool allow_late{false};                      // --allow-late: start even after the late cut-off
};

// Shared test window: every participant passes the same --start-at, so all nodes start together
// whatever their local time zone. Exactly "YYYY-MM-DDTHH:MM:SSZ" (UTC); nullopt otherwise.
std::optional<std::int64_t> parse_utc_time(const std::string& s);
std::string format_utc_time(std::int64_t unix_seconds);
// Started this long after --start-at, the tool refuses (the shared window is under way without it).
inline constexpr std::int64_t kLateStartSeconds = 10 * 60;
// A start time further ahead than this is refused as a likely typo.
inline constexpr std::int64_t kMaxStartAheadSeconds = 14 * 24 * 60 * 60;
// Each node starts up to this many seconds after --start-at, at random, so not all send in one second.
inline constexpr std::int64_t kStartJitterSeconds = 30;
enum class StartDecision : std::uint8_t { Wait, Start, TooLate, TooFar };
StartDecision start_decision(std::int64_t now_unix, std::int64_t start_unix, bool allow_late);
// argv without the program name. Refuses values above the hard limits instead of clamping them.
std::optional<Options> parse_options(const std::vector<std::string>& args, std::string* err);
std::string usage_text();
std::string default_state_dir();  // "~/.finalis-nodetest", unexpanded (help text shows no personal path)
// Expands a leading ~/ (HOME, Windows profile, else the password database) and makes the path
// absolute. Nullopt + *err when no home directory can be found or the path is ~user.
std::optional<std::string> resolve_state_dir(const std::string& raw, std::string* err);
std::string default_rpc_url();

// Nullopt when the server is on testnet-3 (testnet network id and the embedded testnet genesis);
// otherwise why the tool refuses to run there. Mainnet and every other chain are refused.
std::optional<std::string> refuse_network(const lightserver::RpcStatusView& status);
// Nullopt when the node looks synced and connected enough to load; otherwise the problem.
std::optional<std::string> preflight_problem(const lightserver::RpcStatusView& status, std::uint64_t min_peers);

// Peers file: one tsc1 address per line; '#' starts a comment. Own addresses and duplicates are
// skipped; anything else that is not a testnet P2PKH address is an error naming the line.
struct Peer {
  std::string address;
  Bytes script_pubkey;
};
std::optional<std::vector<Peer>> parse_peers(const std::string& text, const std::set<std::string>& own_addresses,
                                             std::string* err);

// Send pacing: one transaction every 1/rate seconds (no catch-up after a pause), pushed back by the
// backoff after retryable rejects.
class Pacer {
 public:
  Pacer(double rate, double start_seconds);
  bool due(double now) const { return now >= next_; }
  double next_at() const { return next_; }
  double backoff_seconds() const { return backoff_; }
  void sent(double now);
  void retryable_reject(double now);
  void accepted() { backoff_ = 0; }

 private:
  double interval_;
  double next_;
  double backoff_{0};
};

// The tool's own wallet. Keys derive from one random seed; it never reads validator keys.
struct Key {
  Bytes priv;
  std::array<std::uint8_t, 20> pkh{};
  Bytes script;
  Hash32 scripthash{};
  std::string address;
  Hash32 view_secret{};
  Hash32 spend_secret{};
};
Key derive_key(const Hash32& seed, std::uint32_t index);

struct ConfCoin {
  OutPoint op{};
  std::uint64_t amount{0};
  Hash32 spend_secret{};
  Hash32 blind{};
  crypto::Commitment33 commitment{};
  PubKey33 one_time{};
  std::uint32_t key{0};
  bool origin_final{false};  // the transaction creating it is final: spendable
  bool spent{false};         // its spend is final (kept so a crash cannot lose track of it)
  Hash32 spend_txid{};       // a spend sent but not yet final (zero: none)
};

struct Wallet {
  Hash32 seed{};
  std::vector<Key> keys;
  std::map<std::uint32_t, std::uint32_t> next_request;  // per key: next confidential request index
  std::vector<ConfCoin> conf;

  static Wallet create(const Hash32& seed);
  std::string serialize() const;
  static std::optional<Wallet> parse(const std::string& text, std::string* err);
  std::set<std::string> addresses() const;
};
bool save_wallet(const std::string& dir, const Wallet& w, std::string* err);
std::optional<Wallet> load_wallet(const std::string& dir, std::string* err);  // nullopt + empty err: none yet

// Fee with headroom for a base fee that rises before inclusion.
std::uint64_t fee_for(std::uint64_t base_fee_per_kib, std::size_t size_bytes);

// End of run: every coin given goes to `target_script` minus fees. Transparent coins are grouped by
// the key that may spend them (one transaction per key and up to 200 inputs); each confidential coin
// is unshielded on its own. Coins too small to pay their fee are left out and counted in *dust_units.
using Coin = std::pair<OutPoint, TxOut>;
struct SweepTx {
  AnyTx tx;
  Hash32 txid{};
  std::uint64_t input_units{0};
  std::uint64_t output_units{0};
  std::uint64_t fee{0};
  std::vector<OutPoint> conf_inputs;
};
std::vector<SweepTx> build_sweep(const Hash32& chain_domain, const Wallet& w,
                                 const std::map<std::uint32_t, std::vector<Coin>>& coins_by_key,
                                 const std::vector<ConfCoin>& conf, const Bytes& target_script,
                                 std::uint64_t base_fee_per_kib, std::uint64_t* dust_units, std::string* err);

struct Summary {
  std::map<std::string, std::uint64_t> sent;      // accepted for relay, by type
  std::map<std::string, std::uint64_t> finals;    // final, by type
  std::map<std::string, std::uint64_t> rejected;  // by reason
  std::map<std::string, std::uint64_t> expired;   // never final, by type
  std::uint64_t starved{0};                       // slots with no coin to spend
  std::vector<double> finality_seconds;
  std::string render() const;
};
// Nearest-rank percentile (p in 0..100) of `v`; 0 for an empty vector.
double percentile(std::vector<double> v, double p);

}  // namespace finalis::nodetest
