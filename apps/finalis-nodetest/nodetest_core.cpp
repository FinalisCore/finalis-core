// SPDX-License-Identifier: MIT

#include "apps/finalis-nodetest/nodetest_core.hpp"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "common/address.hpp"
#include "common/network.hpp"
#include "common/paths.hpp"
#include "consensus/monetary.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "crypto/secure_memory.hpp"
#include "genesis/embedded_testnet.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"
#include "wallet/confidential_builder.hpp"

namespace finalis::nodetest {

namespace {

constexpr const char* kTestnetHrp = "tsc";
constexpr std::size_t kSweepMaxInputs = 200;

Hash32 derive_hash(const std::string& tag, const Hash32& seed, std::uint32_t index) {
  Bytes b(tag.begin(), tag.end());
  b.insert(b.end(), seed.begin(), seed.end());
  for (int s = 0; s < 32; s += 8) b.push_back(static_cast<std::uint8_t>(index >> s));
  return crypto::sha256(b);
}

std::optional<Hash32> parse_h32(const std::string& s) {
  const auto b = hex_decode(s);
  if (!b || b->size() != 32) return std::nullopt;
  Hash32 h{};
  std::copy(b->begin(), b->end(), h.begin());
  return h;
}

template <std::size_t N>
std::optional<std::array<std::uint8_t, N>> parse_arr(const std::string& s) {
  const auto b = hex_decode(s);
  if (!b || b->size() != N) return std::nullopt;
  std::array<std::uint8_t, N> a{};
  std::copy(b->begin(), b->end(), a.begin());
  return a;
}

std::string hex_op(const OutPoint& op) { return hex_encode32(op.txid) + ":" + std::to_string(op.index); }

std::optional<OutPoint> parse_op(const std::string& s) {
  const auto c = s.find(':');
  if (c == std::string::npos) return std::nullopt;
  const auto txid = parse_h32(s.substr(0, c));
  if (!txid) return std::nullopt;
  try {
    const auto idx = std::stoul(s.substr(c + 1));
    return OutPoint{*txid, static_cast<std::uint32_t>(idx)};
  } catch (...) {
    return std::nullopt;
  }
}

std::string trim(const std::string& s) {
  const auto b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  const auto e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

bool parse_u64(const std::string& s, std::uint64_t* out) {
  if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos || s.size() > 19) return false;
  *out = std::stoull(s);
  return true;
}

wallet::ConfidentialOwnedCoin owned_coin(const ConfCoin& c) {
  return wallet::ConfidentialOwnedCoin{.outpoint = c.op,
                                       .amount = c.amount,
                                       .spend_secret = crypto::Blind32{c.spend_secret},
                                       .value_blind = crypto::Blind32{c.blind},
                                       .value_commitment = c.commitment,
                                       .one_time_pubkey = c.one_time};
}

Hash32 fresh_random() {
  Hash32 h{};
  if (!crypto::secure_random_bytes(h.data(), h.size())) throw std::runtime_error("no secure randomness");
  return h;
}

}  // namespace

std::string type_name(TxType t) {
  switch (t) {
    case TxType::Std: return "std";
    case TxType::HLock: return "hlock";
    case TxType::Inherit: return "inherit";
    case TxType::Shield: return "shield";
    case TxType::C2C: return "c2c";
    case TxType::Unshield: return "unshield";
    case TxType::Timed: return "timed";
    case TxType::TimedLong: return "timed-long";
    case TxType::Seal: return "seal";
    case TxType::SealLong: return "seal-long";
  }
  return "?";
}

std::optional<TxType> parse_type(const std::string& name) {
  for (const auto t : kAllTypes)
    if (type_name(t) == name) return t;
  return std::nullopt;
}

std::uint32_t type_weight(TxType t) {
  switch (t) {
    case TxType::Std: return 30;
    case TxType::HLock: return 8;
    case TxType::Inherit: return 8;
    case TxType::Shield: return 12;
    case TxType::C2C: return 10;
    case TxType::Unshield: return 10;
    case TxType::Timed: return 8;
    case TxType::TimedLong: return 2;
    case TxType::Seal: return 8;
    case TxType::SealLong: return 2;
  }
  return 0;
}

bool is_timed_type(TxType t) {
  return t == TxType::Timed || t == TxType::TimedLong || t == TxType::Seal || t == TxType::SealLong;
}

std::string default_state_dir() { return expand_user_home("~/.finalis-nodetest"); }

std::string default_rpc_url() {
  return "http://127.0.0.1:" + std::to_string(testnet_network().lightserver_default_port) + "/rpc";
}

std::string usage_text() {
  std::ostringstream o;
  o << "finalis-nodetest: random test transactions on the Finalis TESTNET from a throwaway wallet.\n"
       "\n"
       "Usage: finalis-nodetest [run|sweep|status|address] [options]\n"
       "  run      (default) send random transactions, then return the coins to address #0\n"
       "  sweep    only return every spendable coin to address #0\n"
       "  status   show the wallet's coins\n"
       "  address  print the wallet's addresses (give #0 to others for their --peers file)\n"
       "\n"
       "Options:\n"
       "  --rpc URL          lightserver RPC (default " << default_rpc_url() << ")\n"
       "  --dir DIR          wallet and logs (default " << default_state_dir() << ")\n"
       "  --rate R           transactions per second, at most " << kMaxRate << " (default " << kDefaultRate << ")\n"
       "  --duration S       seconds of sending, at most " << kMaxDurationSeconds << " (default " << kDefaultDurationSeconds << ")\n"
       "  --drain S          seconds to wait for open transactions before the sweep (default " << kDefaultDrainSeconds << ")\n"
       "  --types a,b,...    subset of: std hlock inherit shield c2c unshield timed timed-long seal seal-long\n"
       "  --peers FILE       other participants' tsc1 addresses, one per line: they receive some\n"
       "                     transparent payments. YOUR COINS THEN END UP PARTLY WITH THEM (and theirs\n"
       "                     with you); the final sweep only returns what this wallet still holds.\n"
       "  --min-peers N      refuse to start with fewer established node peers (default 2)\n"
       "\n"
       "Safety: testnet only (refuses mainnet and any other chain); uses only its own wallet, never\n"
       "validator keys; stops on Ctrl-C or when a file named STOP appears in --dir; backs off when the\n"
       "node is busy; uploads nothing. Fund it by sending testnet coins (5 FLS is plenty) to address #0.\n";
  return o.str();
}

std::optional<Options> parse_options(const std::vector<std::string>& args, std::string* err) {
  Options o;
  o.dir = default_state_dir();
  o.rpc = default_rpc_url();
  std::size_t i = 0;
  if (!args.empty() && args[0].rfind("--", 0) != 0) {
    o.command = args[0];
    i = 1;
    if (o.command != "run" && o.command != "sweep" && o.command != "status" && o.command != "address" &&
        o.command != "help") {
      *err = "unknown command: " + o.command;
      return std::nullopt;
    }
  }
  for (; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (a == "--help" || a == "-h") {
      o.command = "help";
      continue;
    }
    if (i + 1 >= args.size()) {
      *err = a + " needs a value";
      return std::nullopt;
    }
    const std::string v = args[++i];
    std::uint64_t n = 0;
    if (a == "--rpc") {
      o.rpc = v;
    } else if (a == "--dir") {
      o.dir = expand_user_home(v);
    } else if (a == "--peers") {
      o.peers_file = v;
    } else if (a == "--rate") {
      char* end = nullptr;
      const double r = std::strtod(v.c_str(), &end);
      if (end == v.c_str() || *end != '\0' || !std::isfinite(r) || r <= 0) {
        *err = "--rate must be a positive number";
        return std::nullopt;
      }
      if (r > kMaxRate) {
        std::ostringstream m;
        m << "--rate " << v << " is above the limit of " << kMaxRate << " tx/s";
        *err = m.str();
        return std::nullopt;
      }
      o.rate = r;
    } else if (a == "--duration") {
      if (!parse_u64(v, &n) || n == 0) {
        *err = "--duration must be a positive number of seconds";
        return std::nullopt;
      }
      if (n > kMaxDurationSeconds) {
        *err = "--duration " + v + " is above the limit of " + std::to_string(kMaxDurationSeconds) + " s";
        return std::nullopt;
      }
      o.duration_seconds = n;
    } else if (a == "--drain") {
      if (!parse_u64(v, &n) || n > kMaxDurationSeconds) {
        *err = "--drain must be 0.." + std::to_string(kMaxDurationSeconds) + " seconds";
        return std::nullopt;
      }
      o.drain_seconds = n;
    } else if (a == "--min-peers") {
      if (!parse_u64(v, &n) || n > 1000) {
        *err = "--min-peers must be 0..1000";
        return std::nullopt;
      }
      o.min_peers = n;
    } else if (a == "--types") {
      o.types.clear();
      std::stringstream ss(v);
      for (std::string t; std::getline(ss, t, ',');) {
        const auto parsed = parse_type(trim(t));
        if (!parsed) {
          *err = "unknown type in --types: " + t;
          return std::nullopt;
        }
        if (std::find(o.types.begin(), o.types.end(), *parsed) == o.types.end()) o.types.push_back(*parsed);
      }
      if (o.types.empty()) {
        *err = "--types is empty";
        return std::nullopt;
      }
    } else {
      *err = "unknown option: " + a;
      return std::nullopt;
    }
  }
  return o;
}

std::optional<std::string> refuse_network(const lightserver::RpcStatusView& s) {
  const auto& net = testnet_network();
  const std::string want_id = hex_encode(Bytes(net.network_id.begin(), net.network_id.end()));
  const std::string want_genesis = hex_encode32(genesis::TESTNET_GENESIS_HASH);
  if (s.chain.network_id_hex != want_id) {
    const auto& main = mainnet_network();
    const std::string main_id = hex_encode(Bytes(main.network_id.begin(), main.network_id.end()));
    if (s.chain.network_id_hex == main_id) return std::string("the node is on MAINNET; finalis-nodetest only runs on testnet");
    return "the node is not on the Finalis testnet (network id " + s.chain.network_id_hex + ")";
  }
  if (s.chain.genesis_hash_hex != want_genesis) {
    return "the node's testnet genesis " + s.chain.genesis_hash_hex + " is not this build's testnet (" + want_genesis +
           "); use the release for the current testnet";
  }
  if (!s.chain_id_ok || !s.chain.chain_id_ok) return std::string("the node reports a chain identity mismatch");
  return std::nullopt;
}

std::optional<std::string> preflight_problem(const lightserver::RpcStatusView& s, std::uint64_t min_peers) {
  if (s.bootstrap_sync_incomplete) return std::string("the node is still syncing (bootstrap sync incomplete)");
  if (s.finalized_lag && *s.finalized_lag > 2) {
    return "the node is " + std::to_string(*s.finalized_lag) + " blocks behind the network; wait until it catches up";
  }
  if (s.peer_height_disagreement) return std::string("the node's peers disagree about the chain height");
  if (min_peers > 0) {
    if (!s.established_peer_count) {
      return std::string("the node does not report its peer count; pass --min-peers 0 to skip this check");
    }
    if (*s.established_peer_count < min_peers) {
      return "the node has " + std::to_string(*s.established_peer_count) + " established peers, fewer than " +
             std::to_string(min_peers) + " (--min-peers)";
    }
  }
  return std::nullopt;
}

std::optional<std::vector<Peer>> parse_peers(const std::string& text, const std::set<std::string>& own,
                                             std::string* err) {
  std::vector<Peer> out;
  std::set<std::string> seen;
  std::stringstream ss(text);
  std::size_t line_no = 0;
  for (std::string line; std::getline(ss, line);) {
    ++line_no;
    const auto hash = line.find('#');
    if (hash != std::string::npos) line.resize(hash);
    const std::string a = trim(line);
    if (a.empty()) continue;
    const auto d = address::decode(a);
    if (!d) {
      *err = "peers line " + std::to_string(line_no) + ": not an address: " + a;
      return std::nullopt;
    }
    if (d->hrp != kTestnetHrp) {
      *err = "peers line " + std::to_string(line_no) + ": " + a + " is not a testnet (tsc1) address";
      return std::nullopt;
    }
    const auto normalized = address::encode_p2pkh(kTestnetHrp, d->pubkey_hash);
    if (!normalized) {
      *err = "peers line " + std::to_string(line_no) + ": cannot encode " + a;
      return std::nullopt;
    }
    if (own.count(*normalized) || !seen.insert(*normalized).second) continue;
    if (out.size() >= kMaxPeers) {
      *err = "more than " + std::to_string(kMaxPeers) + " peers";
      return std::nullopt;
    }
    out.push_back(Peer{*normalized, address::p2pkh_script_pubkey(d->pubkey_hash)});
  }
  return out;
}

Pacer::Pacer(double rate, double start_seconds) : interval_(1.0 / rate), next_(start_seconds) {}

void Pacer::sent(double now) { next_ = now + interval_; }

void Pacer::retryable_reject(double now) {
  backoff_ = backoff_ == 0 ? kBackoffFirstSeconds : std::min(backoff_ * 2, kBackoffMaxSeconds);
  next_ = now + std::max(interval_, backoff_);
}

Key derive_key(const Hash32& seed, std::uint32_t index) {
  Key k;
  const auto ed_seed = derive_hash("finalis-nodetest-ed25519", seed, index);
  auto kp = crypto::keypair_from_seed32(ed_seed);
  if (!kp) throw std::runtime_error("key derivation failed");
  k.priv = kp->private_key;
  k.pkh = crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()));
  k.script = address::p2pkh_script_pubkey(k.pkh);
  k.scripthash = crypto::sha256(k.script);
  k.address = *address::encode_p2pkh(kTestnetHrp, k.pkh);
  k.view_secret = derive_hash("finalis-nodetest-view", seed, index);
  k.spend_secret = derive_hash("finalis-nodetest-spend", seed, index);
  return k;
}

Wallet Wallet::create(const Hash32& seed) {
  Wallet w;
  w.seed = seed;
  for (std::uint32_t i = 0; i < kWalletKeys; ++i) w.keys.push_back(derive_key(seed, i));
  return w;
}

std::set<std::string> Wallet::addresses() const {
  std::set<std::string> out;
  for (const auto& k : keys) out.insert(k.address);
  return out;
}

std::string Wallet::serialize() const {
  std::ostringstream f;
  f << "finalis-nodetest-wallet 1\n";
  f << "seed " << hex_encode32(seed) << "\n";
  for (const auto& [k, v] : next_request) f << "req " << k << " " << v << "\n";
  for (const auto& c : conf) {
    f << "conf " << hex_op(c.op) << " " << c.amount << " " << hex_encode32(c.spend_secret) << " " << hex_encode32(c.blind)
      << " " << hex_encode(Bytes(c.commitment.bytes.begin(), c.commitment.bytes.end())) << " "
      << hex_encode(Bytes(c.one_time.begin(), c.one_time.end())) << " " << c.key << " " << (c.origin_final ? 1 : 0)
      << " " << (c.spent ? 1 : 0) << " " << hex_encode32(c.spend_txid) << "\n";
  }
  return f.str();
}

std::optional<Wallet> Wallet::parse(const std::string& text, std::string* err) {
  std::stringstream f(text);
  std::string magic, version;
  f >> magic >> version;
  if (magic != "finalis-nodetest-wallet" || version != "1") {
    *err = "not a finalis-nodetest wallet file";
    return std::nullopt;
  }
  std::optional<Hash32> seed;
  std::map<std::uint32_t, std::uint32_t> req;
  std::vector<ConfCoin> conf;
  std::string kind;
  while (f >> kind) {
    if (kind == "seed") {
      std::string s;
      f >> s;
      seed = parse_h32(s);
    } else if (kind == "req") {
      std::uint32_t k = 0, v = 0;
      if (!(f >> k >> v) || k >= kWalletKeys) {
        *err = "bad req line";
        return std::nullopt;
      }
      req[k] = v;
    } else if (kind == "conf") {
      std::string op, ss, bl, cm, ot, sp;
      ConfCoin c;
      int of = 0, spent = 0;
      if (!(f >> op >> c.amount >> ss >> bl >> cm >> ot >> c.key >> of >> spent >> sp)) {
        *err = "bad conf line";
        return std::nullopt;
      }
      const auto pop = parse_op(op);
      const auto pss = parse_h32(ss);
      const auto pbl = parse_h32(bl);
      const auto pcm = parse_arr<33>(cm);
      const auto pot = parse_arr<33>(ot);
      const auto psp = parse_h32(sp);
      if (!pop || !pss || !pbl || !pcm || !pot || !psp || c.key >= kWalletKeys) {
        *err = "bad conf line";
        return std::nullopt;
      }
      c.op = *pop;
      c.spend_secret = *pss;
      c.blind = *pbl;
      c.commitment.bytes = *pcm;
      c.one_time = *pot;
      c.origin_final = of != 0;
      c.spent = spent != 0;
      c.spend_txid = *psp;
      conf.push_back(c);
    } else {
      *err = "unknown wallet line: " + kind;
      return std::nullopt;
    }
  }
  if (!seed) {
    *err = "wallet has no seed";
    return std::nullopt;
  }
  Wallet w = Wallet::create(*seed);
  w.next_request = std::move(req);
  w.conf = std::move(conf);
  return w;
}

bool save_wallet(const std::string& dir, const Wallet& w, std::string* err) {
  if (!ensure_private_dir(dir)) {
    *err = "cannot create " + dir;
    return false;
  }
  const std::filesystem::path path = std::filesystem::path(dir) / "wallet.txt";
  const std::filesystem::path tmp = std::filesystem::path(dir) / "wallet.txt.tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) {
      *err = "cannot write " + tmp.string();
      return false;
    }
    std::error_code ec;
    std::filesystem::permissions(tmp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    f << w.serialize();
    f.flush();
    if (!f) {
      *err = "cannot write " + tmp.string();
      return false;
    }
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    *err = "cannot replace " + path.string() + ": " + ec.message();
    return false;
  }
  return true;
}

std::optional<Wallet> load_wallet(const std::string& dir, std::string* err) {
  err->clear();
  const std::filesystem::path path = std::filesystem::path(dir) / "wallet.txt";
  std::ifstream f(path, std::ios::binary);
  if (!f) return std::nullopt;
  std::stringstream ss;
  ss << f.rdbuf();
  auto w = Wallet::parse(ss.str(), err);
  if (!w && err->empty()) *err = "cannot read " + path.string();
  return w;
}

std::uint64_t fee_for(std::uint64_t base_fee_per_kib, std::size_t size_bytes) {
  return std::max<std::uint64_t>(2'000, consensus::required_base_fee_units(base_fee_per_kib * 3 + 2, size_bytes + 256));
}

std::vector<SweepTx> build_sweep(const Hash32& domain, const Wallet& w,
                                 const std::map<std::uint32_t, std::vector<Coin>>& coins_by_key,
                                 const std::vector<ConfCoin>& conf, const Bytes& target_script,
                                 std::uint64_t base_fee_per_kib, std::uint64_t* dust_units, std::string* err) {
  std::vector<SweepTx> out;
  *dust_units = 0;
  for (const auto& [key_index, coins] : coins_by_key) {
    if (key_index >= w.keys.size()) continue;
    const Key& key = w.keys[key_index];
    for (std::size_t start = 0; start < coins.size(); start += kSweepMaxInputs) {
      const std::vector<Coin> group(coins.begin() + start, coins.begin() + std::min(coins.size(), start + kSweepMaxInputs));
      std::uint64_t total = 0;
      for (const auto& c : group) total += c.second.value;
      // Already one plain coin at the target: nothing to do.
      if (group.size() == 1 && group[0].second.script_pubkey == target_script) continue;
      // Size from a first build at a placeholder fee, then the real fee.
      const std::uint64_t guess = fee_for(base_fee_per_kib, group.size() * 110 + 80);
      if (total <= guess + DEFAULT_WALLET_DUST_THRESHOLD_UNITS) {
        *dust_units += total;
        continue;
      }
      auto draft = build_signed_p2pkh_tx_multi_input(domain, group, key.priv, {TxOut{total - guess, target_script}}, err);
      if (!draft) return {};
      const std::uint64_t fee = std::max(guess, fee_for(base_fee_per_kib, draft->serialize().size()));
      if (total <= fee + DEFAULT_WALLET_DUST_THRESHOLD_UNITS) {
        *dust_units += total;
        continue;
      }
      auto tx = build_signed_p2pkh_tx_multi_input(domain, group, key.priv, {TxOut{total - fee, target_script}}, err);
      if (!tx) return {};
      SweepTx s{.tx = AnyTx{*tx}, .txid = tx->txid(), .input_units = total, .output_units = total - fee, .fee = fee, .conf_inputs = {}};
      out.push_back(std::move(s));
    }
  }
  for (const auto& c : conf) {
    const std::uint64_t fee = fee_for(base_fee_per_kib, 1600);
    if (c.amount <= fee + DEFAULT_WALLET_DUST_THRESHOLD_UNITS) {
      *dust_units += c.amount;
      continue;
    }
    auto tx = wallet::build_txv2_confidential_to_transparent(domain, owned_coin(c), TransparentTxOutV2{c.amount - fee, target_script},
                                                             fee, fresh_random(), fresh_random(), err);
    if (!tx) return {};
    SweepTx s{.tx = AnyTx{*tx}, .txid = tx->txid(), .input_units = c.amount, .output_units = c.amount - fee, .fee = fee,
              .conf_inputs = {c.op}};
    out.push_back(std::move(s));
  }
  return out;
}

double percentile(std::vector<double> v, double p) {
  if (v.empty()) return 0;
  std::sort(v.begin(), v.end());
  const double rank = std::ceil(p / 100.0 * static_cast<double>(v.size()));
  const std::size_t idx = rank < 1 ? 0 : std::min(v.size() - 1, static_cast<std::size_t>(rank) - 1);
  return v[idx];
}

std::string Summary::render() const {
  std::ostringstream o;
  std::uint64_t sent_total = 0, final_total = 0, rej_total = 0, exp_total = 0;
  for (const auto& [_, n] : sent) sent_total += n;
  for (const auto& [_, n] : finals) final_total += n;
  for (const auto& [_, n] : rejected) rej_total += n;
  for (const auto& [_, n] : expired) exp_total += n;
  o << "== finalis-nodetest summary ==\n";
  o << "accepted " << sent_total << "  final " << final_total << "  rejected " << rej_total << "  never-final "
    << exp_total << "  no-coin slots " << starved << "\n";
  o << "type          accepted   final\n";
  std::set<std::string> types;
  for (const auto& [t, _] : sent) types.insert(t);
  for (const auto& [t, _] : finals) types.insert(t);
  for (const auto& t : types) {
    const auto s = sent.count(t) ? sent.at(t) : 0;
    const auto f = finals.count(t) ? finals.at(t) : 0;
    o << std::left << std::setw(12) << t << std::right << std::setw(10) << s << std::setw(8) << f << "\n";
  }
  for (const auto& [reason, n] : rejected) o << "rejected " << n << "  " << reason << "\n";
  for (const auto& [t, n] : expired) o << "never final " << n << "  " << t << "\n";
  if (!finality_seconds.empty()) {
    o << std::fixed << std::setprecision(0) << "time to final (s): p50 " << percentile(finality_seconds, 50) << "  p95 "
      << percentile(finality_seconds, 95) << "  max " << percentile(finality_seconds, 100) << "\n";
  }
  return o.str();
}

}  // namespace finalis::nodetest
