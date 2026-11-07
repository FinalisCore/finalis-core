// SPDX-License-Identifier: MIT
// finalis-nodetest: sends random transactions of every type on the testnet from its own throwaway
// wallet, logs each one, and at the end returns the coins to the wallet's first address. See README.md.

#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>
#include <variant>

#include "apps/finalis-nodetest/nodetest_core.hpp"
#include "apps/finalis-wallet/confidential_memo.hpp"
#include "common/network.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/monetary.hpp"
#include "consensus/randomness.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/confidential.hpp"
#include "crypto/secure_memory.hpp"
#include "lightserver/client.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"
#include "wallet/confidential_builder.hpp"
#include "wallet/confidential_keys.hpp"

using namespace finalis;
using namespace finalis::nodetest;
namespace ls = finalis::lightserver;

namespace {

std::atomic<int> g_stop{0};
extern "C" void on_signal(int) { g_stop.fetch_add(1); }

// Coin sizes. Work coins can fund any type, a time lock included (0.1 FLS bond + prepaid fee).
constexpr std::uint64_t kWorkCoinUnits = 24'000'000;
constexpr std::size_t kTargetWorkCoins = 40;
constexpr std::uint64_t kMinSpendUnits = 200'000;
constexpr std::uint64_t kTimedAmountUnits = 1'000'000;
constexpr std::size_t kMaxTimedInFlight = 10;
constexpr std::size_t kMaxInFlight = 400;
// A transaction not final this many blocks after sending is given up (its coins are reused).
constexpr std::uint64_t kExpireBlocks = 20;
constexpr std::uint64_t kMinFundingUnits = consensus::BASE_UNITS_PER_COIN;  // 1 FLS

bool same_op(const OutPoint& a, const OutPoint& b) { return a.txid == b.txid && a.index == b.index; }

std::int64_t unix_now() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

double now_s() {
  return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string utc_now() {
  const std::time_t t = std::time(nullptr);
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

std::string fls(std::uint64_t units) {
  std::ostringstream o;
  o << units / consensus::BASE_UNITS_PER_COIN << "." << std::setw(8) << std::setfill('0')
    << units % consensus::BASE_UNITS_PER_COIN;
  return o.str();
}

Hash32 rnd() {
  Hash32 h{};
  if (!crypto::secure_random_bytes(h.data(), h.size())) throw std::runtime_error("no secure randomness");
  return h;
}

struct InFlight {
  Hash32 txid{};
  std::string type;
  double sent_at{0};
  std::uint64_t sent_tip{0};
  std::uint64_t expire_after_height{0};
  std::vector<OutPoint> inputs;
  std::vector<OutPoint> conf_spent;
  std::vector<OutPoint> conf_created;
  bool timed{false};
};

struct BodyHold {
  std::vector<OutPoint> inputs;
  std::uint64_t release_height{0};
};

class Runner {
 public:
  explicit Runner(Options o) : opt_(std::move(o)), rng_(std::random_device{}()) {}

  int main_command() {
    std::string err;
    std::cerr << "Wallet: " << opt_.dir << "\n";  // stderr: stdout stays the address list / tx log
    auto w = load_wallet(opt_.dir, &err);
    if (!w && !err.empty()) return fail(err);
    if (!w) {
      w = Wallet::create(rnd());
      if (!save_wallet(opt_.dir, *w, &err)) return fail(err);
      std::cout << "Created a new test wallet in " << opt_.dir << "\n";
    }
    w_ = std::move(*w);
    if (opt_.command == "address") {
      for (std::size_t i = 0; i < w_.keys.size(); ++i) std::cout << "#" << i << "  " << w_.keys[i].address << "\n";
      return 0;
    }
    if (!connect()) return 1;
    if (opt_.command == "status") return status_command();
    if (opt_.command == "sweep") return finish(false);
    return run_command();
  }

 private:
  Options opt_;
  Wallet w_;
  std::mt19937_64 rng_;
  Hash32 domain_{};
  std::uint64_t tip_{0};
  std::uint64_t base_fee_{0};
  std::vector<Peer> peers_;
  std::map<Hash32, InFlight> inflight_;
  std::vector<BodyHold> holds_;
  std::set<OutPoint> reserved_;
  std::map<std::uint32_t, std::vector<Coin>> coins_;  // spendable now, not reserved
  Summary sum_;
  std::ofstream log_;
  std::uint64_t consecutive_rejects_{0};
  bool split_in_flight_{false};

  int fail(const std::string& m) {
    std::cerr << "finalis-nodetest: " << m << "\n";
    return 1;
  }

  void log(const std::string& line) {
    const std::string l = utc_now() + "\t" + line;
    std::cout << l << "\n" << std::flush;
    if (log_) log_ << l << "\n" << std::flush;
  }

  bool stop_requested() const {
    return g_stop.load() > 0 || std::filesystem::exists(std::filesystem::path(opt_.dir) / "STOP");
  }

  void save() {
    std::string err;
    if (!save_wallet(opt_.dir, w_, &err)) throw std::runtime_error("saving wallet: " + err);
  }

  bool connect() {
    std::string err;
    auto s = ls::rpc_get_status(opt_.rpc, &err);
    if (!s) {
      std::cerr << "finalis-nodetest: cannot reach the lightserver at " << opt_.rpc << ": " << err
                << "\n  (run it with the node, or pass --rpc URL)\n";
      return false;
    }
    if (auto refuse = refuse_network(*s)) {
      std::cerr << "finalis-nodetest: refusing to run: " << *refuse << "\n";
      return false;
    }
    auto d = chain_domain_from_hex(s->chain.network_id_hex, s->chain.genesis_hash_hex);
    if (!d) {
      std::cerr << "finalis-nodetest: bad chain identity from the server\n";
      return false;
    }
    domain_ = *d;
    tip_ = s->tip_height;
    base_fee_ = s->base_fee_per_kib;
    return true;
  }

  bool refresh_status() {
    std::string err;
    auto s = ls::rpc_get_status(opt_.rpc, &err);
    if (!s) return false;
    if (refuse_network(*s)) throw std::runtime_error("the server changed chains");
    tip_ = s->tip_height;
    base_fee_ = s->base_fee_per_kib;
    return true;
  }

  // Coins each key may spend in the next block, minus those our open transactions use.
  void refresh_coins() {
    std::uint64_t h = tip_ + 1;
    for (auto it = holds_.begin(); it != holds_.end();) {
      if (tip_ >= it->release_height) {
        for (const auto& op : it->inputs) reserved_.erase(op);
        it = holds_.erase(it);
      } else {
        ++it;
      }
    }
    std::map<std::uint32_t, std::vector<Coin>> fresh;
    std::set<OutPoint> seen;
    for (std::uint32_t k = 0; k < w_.keys.size(); ++k) {
      std::string err;
      auto u = ls::rpc_get_utxos(opt_.rpc, w_.keys[k].scripthash, &err);
      if (!u) {
        coins_ = {};
        return;
      }
      for (const auto& v : *u) {
        const OutPoint op{v.txid, v.vout};
        if (v.value == 0 || reserved_.count(op) || !seen.insert(op).second) continue;
        if (!script_spendable_by(v.script_pubkey, w_.keys[k].pkh, h)) continue;
        fresh[k].push_back({op, TxOut{v.value, v.script_pubkey}});
      }
    }
    coins_ = std::move(fresh);
  }

  std::uint64_t transparent_units() const {
    std::uint64_t t = 0;
    for (const auto& [_, cs] : coins_)
      for (const auto& c : cs) t += c.second.value;
    return t;
  }

  std::vector<std::size_t> usable_conf() const {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < w_.conf.size(); ++i) {
      const auto& c = w_.conf[i];
      if (c.origin_final && !c.spent && c.spend_txid == Hash32{} && !reserved_.count(c.op)) out.push_back(i);
    }
    return out;
  }

  std::uint64_t conf_units() const {
    std::uint64_t t = 0;
    for (const auto i : usable_conf()) t += w_.conf[i].amount;
    return t;
  }

  // Confidential records whose creating or spending transaction was open when the tool last stopped.
  void recheck_conf() {
    bool changed = false;
    for (auto& c : w_.conf) {
      std::string err;
      if (!c.origin_final) {
        auto s = ls::rpc_get_tx_status(opt_.rpc, c.op.txid, &err);
        if (s && s->finalized) {
          c.origin_final = true;
          changed = true;
        }
      }
      if (c.spend_txid != Hash32{}) {
        auto s = ls::rpc_get_tx_status(opt_.rpc, c.spend_txid, &err);
        if (s && s->finalized) {
          c.spent = true;
          c.spend_txid = Hash32{};
          changed = true;
        } else if (inflight_.count(c.spend_txid) == 0) {
          // Sent by an earlier process and maybe still in a mempool: track it like our own, so the coin
          // is not spent twice; it comes free if the spend is not final within kExpireBlocks.
          InFlight f;
          f.txid = c.spend_txid;
          f.type = "resumed";
          f.sent_at = now_s();
          f.sent_tip = tip_;
          f.expire_after_height = tip_ + kExpireBlocks;
          f.conf_spent = {c.op};
          inflight_[c.spend_txid] = std::move(f);
        }
      }
    }
    // Coins the file still calls unspent but the chain no longer has: spent by a transaction this
    // wallet lost track of (e.g. a sweep finalized after its process ended).
    std::vector<OutPoint> ask;
    for (const auto& c : w_.conf)
      if (c.origin_final && !c.spent && c.spend_txid == Hash32{}) ask.push_back(c.op);
    for (std::size_t i = 0; i < ask.size(); i += 32) {
      const std::vector<OutPoint> chunk(ask.begin() + i, ask.begin() + std::min(ask.size(), i + 32));
      std::string err;
      auto proofs = ls::rpc_get_utxo_proofs(opt_.rpc, chunk, &err);
      if (!proofs) break;
      for (const auto& p : proofs->proofs) {
        if (p.value) continue;
        for (auto& c : w_.conf)
          if (same_op(c.op, p.outpoint) && !c.spent) {
            c.spent = true;
            changed = true;
          }
      }
    }
    if (changed) save();
  }

  // --- recipients and coin picking ---

  // A random recipient: one of our keys or (with --peers) another participant.
  Bytes recipient_script() {
    const std::size_t n = w_.keys.size() + peers_.size();
    const std::size_t i = std::uniform_int_distribution<std::size_t>(0, n - 1)(rng_);
    return i < w_.keys.size() ? w_.keys[i].script : peers_[i - w_.keys.size()].script_pubkey;
  }
  std::uint32_t random_key() {
    return static_cast<std::uint32_t>(std::uniform_int_distribution<std::size_t>(0, w_.keys.size() - 1)(rng_));
  }

  // Takes a coin (of any spendable script, or plain P2PKH only) of at least `min` units.
  std::optional<std::pair<std::uint32_t, Coin>> take_coin(std::uint64_t min, bool plain_only) {
    std::vector<std::pair<std::uint32_t, std::size_t>> cands;
    for (const auto& [k, cs] : coins_)
      for (std::size_t i = 0; i < cs.size(); ++i)
        if (cs[i].second.value >= min && (!plain_only || is_p2pkh_script_pubkey(cs[i].second.script_pubkey, nullptr)))
          cands.push_back({k, i});
    if (cands.empty()) return std::nullopt;
    const auto [k, i] = cands[std::uniform_int_distribution<std::size_t>(0, cands.size() - 1)(rng_)];
    Coin c = coins_[k][i];
    coins_[k].erase(coins_[k].begin() + static_cast<std::ptrdiff_t>(i));
    return std::make_pair(k, c);
  }

  void put_back(std::uint32_t k, const std::vector<Coin>& cs) {
    for (const auto& c : cs) coins_[k].push_back(c);
  }

  // A confidential output to key k's next request; fills the coin record (outpoint set by the caller).
  std::optional<wallet::ConfidentialPayment> conf_payment(std::uint32_t k, std::uint64_t value, ConfCoin* rec) {
    const std::uint32_t idx = w_.next_request[k]++;
    auto keys = wallet::derive_confidential_request_keys(w_.keys[k].view_secret, w_.keys[k].spend_secret, idx);
    if (!keys) return std::nullopt;
    const Hash32 blind_seed = rnd();
    auto blind = wallet::derive_output_value_blind(blind_seed, keys->pub.one_time_pubkey);
    if (!blind) return std::nullopt;
    wallet::ConfidentialRecipient to{.one_time_pubkey = keys->pub.one_time_pubkey,
                                     .ephemeral_pubkey = keys->pub.ephemeral_pubkey,
                                     .scan_tag = keys->pub.scan_tag,
                                     .memo = {}};
    auto memo = wallet::encrypt_confidential_recovery_memo(value, blind_seed, keys->pub.memo_key, to.one_time_pubkey,
                                                           to.ephemeral_pubkey);
    if (!memo) return std::nullopt;
    to.memo = *memo;
    crypto::ConfidentialOutputSecrets secrets{.amount = value, .value_blind = *blind};
    std::string err;
    auto out = wallet::build_confidential_output(to, secrets, rnd(), &err);
    if (!out) return std::nullopt;
    rec->amount = value;
    rec->spend_secret = keys->one_time_secret;
    rec->blind = blind->bytes;
    rec->commitment = out->value_commitment;
    rec->one_time = keys->pub.one_time_pubkey;
    rec->key = k;
    rec->origin_final = false;
    rec->spent = false;
    return wallet::ConfidentialPayment{.output = *out, .value = value, .value_blind = *blind};
  }

  // --- building ---

  struct Built {
    Bytes bytes;
    Hash32 txid{};
    std::string type;
    std::uint32_t key{0};
    std::vector<Coin> inputs;          // put back if rejected
    std::vector<OutPoint> body_inputs;  // timed body: held until its unlock height
    std::uint64_t body_release{0};
    std::uint64_t expire_after{0};
    std::vector<OutPoint> conf_spent;
    std::vector<ConfCoin> conf_created;
    bool timed{false};
  };

  std::optional<Built> build(TxType type, std::string* why) {
    std::string e;
    const std::uint64_t next = tip_ + 1;
    Built b;
    b.type = type_name(type);
    b.expire_after = tip_ + kExpireBlocks;
    switch (type) {
      case TxType::Std:
      case TxType::HLock:
      case TxType::Inherit: {
        auto taken = take_coin(kMinSpendUnits, false);
        if (!taken) return std::nullopt;
        auto& [k, coin] = *taken;
        const std::uint64_t fee = fee_for(base_fee_, 300);
        const std::uint64_t v = coin.second.value - fee;
        const Key& key = w_.keys[k];
        std::vector<TxOut> outs;
        if (type == TxType::Std) {
          if (v >= 2 * kWorkCoinUnits) {
            const std::uint64_t pay = std::uniform_int_distribution<std::uint64_t>(v / 4, v * 3 / 4)(rng_);
            outs = {TxOut{pay, recipient_script()}, TxOut{v - pay, w_.keys[random_key()].script}};
          } else {
            outs = {TxOut{v, recipient_script()}};
          }
        } else if (type == TxType::HLock) {
          outs = {TxOut{v, height_lock_script_pubkey(next + 4, w_.keys[random_key()].pkh)}};
        } else {
          std::uint32_t heir = random_key();
          if (heir == k) heir = (heir + 1) % w_.keys.size();
          outs = {TxOut{v, inheritance_lock_script_pubkey(next + 6, key.pkh, w_.keys[heir].pkh)}};
        }
        auto tx = build_signed_p2pkh_tx_single_input(domain_, coin.first, coin.second, key.priv, outs, &e);
        b.key = k;
        b.inputs = {coin};
        if (!tx) {
          put_back(k, b.inputs);
          *why = e;
          return std::nullopt;
        }
        b.bytes = tx->serialize();
        b.txid = tx->txid();
        return b;
      }
      case TxType::Shield: {
        auto taken = take_coin(kMinSpendUnits, true);
        if (!taken) return std::nullopt;
        auto& [k, coin] = *taken;
        const std::uint64_t fee = fee_for(base_fee_, 1600);
        ConfCoin rec;
        auto pay = conf_payment(random_key(), coin.second.value - fee, &rec);
        b.key = k;
        b.inputs = {coin};
        std::optional<TxV2> tx;
        if (pay) {
          tx = wallet::build_txv2_transparent_to_confidential(domain_, coin.first, coin.second, w_.keys[k].priv,
                                                              coin.second.value, std::nullopt, pay->output,
                                                              pay->value_blind, pay->value, fee, &e);
        }
        if (!tx) {
          put_back(k, b.inputs);
          *why = pay ? e : "confidential output";
          return std::nullopt;
        }
        b.bytes = tx->serialize();
        b.txid = tx->txid();
        rec.op = OutPoint{b.txid, 0};
        b.conf_created = {rec};
        return b;
      }
      case TxType::C2C:
      case TxType::Unshield: {
        const std::uint64_t fee = fee_for(base_fee_, type == TxType::C2C ? 3200 : 1600);
        std::vector<std::size_t> cands;
        for (const auto i : usable_conf())
          if (w_.conf[i].amount > fee + 2 * DEFAULT_WALLET_DUST_THRESHOLD_UNITS) cands.push_back(i);
        if (cands.empty()) return std::nullopt;
        const ConfCoin cc = w_.conf[cands[std::uniform_int_distribution<std::size_t>(0, cands.size() - 1)(rng_)]];
        std::optional<TxV2> tx;
        if (type == TxType::C2C) {
          const std::uint64_t total = cc.amount - fee;
          const std::uint64_t a = total >= 2 * kWorkCoinUnits ? total / 2 : total;
          ConfCoin r1, r2;
          std::vector<wallet::ConfidentialPayment> pays;
          auto p1 = conf_payment(random_key(), a, &r1);
          if (!p1) return std::nullopt;
          pays.push_back(*p1);
          if (a < total) {
            auto p2 = conf_payment(random_key(), total - a, &r2);
            if (!p2) return std::nullopt;
            pays.push_back(*p2);
          }
          tx = wallet::build_txv2_confidential_to_confidential(domain_, {wallet::ConfidentialOwnedCoin{
                                                                             .outpoint = cc.op,
                                                                             .amount = cc.amount,
                                                                             .spend_secret = crypto::Blind32{cc.spend_secret},
                                                                             .value_blind = crypto::Blind32{cc.blind},
                                                                             .value_commitment = cc.commitment,
                                                                             .one_time_pubkey = cc.one_time}},
                                                               pays, fee, rnd(), &e);
          if (tx) {
            b.txid = tx->txid();
            r1.op = OutPoint{b.txid, 0};
            b.conf_created.push_back(r1);
            if (pays.size() == 2) {
              r2.op = OutPoint{b.txid, 1};
              b.conf_created.push_back(r2);
            }
          }
        } else {
          tx = wallet::build_txv2_confidential_to_transparent(
              domain_,
              wallet::ConfidentialOwnedCoin{.outpoint = cc.op,
                                            .amount = cc.amount,
                                            .spend_secret = crypto::Blind32{cc.spend_secret},
                                            .value_blind = crypto::Blind32{cc.blind},
                                            .value_commitment = cc.commitment,
                                            .one_time_pubkey = cc.one_time},
              TransparentTxOutV2{cc.amount - fee, recipient_script()}, fee, rnd(), rnd(), &e);
        }
        if (!tx) {
          *why = e;
          return std::nullopt;
        }
        b.bytes = tx->serialize();
        b.txid = tx->txid();
        b.key = cc.key;
        b.conf_spent = {cc.op};
        return b;
      }
      case TxType::Timed:
      case TxType::TimedLong:
      case TxType::Seal:
      case TxType::SealLong:
        return build_timed(type, why);
    }
    return std::nullopt;
  }

  std::optional<Built> build_timed(TxType type, std::string* why) {
    std::size_t timed_open = 0;
    for (const auto& [_, f] : inflight_) timed_open += f.timed ? 1 : 0;
    if (timed_open >= kMaxTimedInFlight) return std::nullopt;
    const bool reveal = type == TxType::Seal || type == TxType::SealLong;
    const bool lng = type == TxType::TimedLong || type == TxType::SealLong;
    const std::uint64_t next = tip_ + 1;
    const std::uint64_t epoch_blocks = std::max<std::uint64_t>(1, testnet_network().committee_epoch_blocks);
    const std::uint64_t horizon = consensus::committee_epoch_start(next, epoch_blocks) + epoch_blocks - 1;
    const std::uint64_t unlock = lng ? horizon + 4 : std::min(horizon, next + 6);
    const std::uint64_t bond = consensus::kTxTimedMinForfeitBond;
    std::string e;
    // Plain coins of one key: the fee coin plus (for a transfer) coins for the sealed body.
    std::vector<std::uint32_t> keys;
    for (const auto& [k, cs] : coins_) {
      std::size_t big = 0, plain = 0;
      for (const auto& c : cs) {
        if (!is_p2pkh_script_pubkey(c.second.script_pubkey, nullptr)) continue;
        ++plain;
        if (c.second.value >= bond + 2'000'000) ++big;
      }
      if (big >= 1 && (reveal || plain >= 2)) keys.push_back(k);
    }
    if (keys.empty()) return std::nullopt;
    const std::uint32_t k = keys[std::uniform_int_distribution<std::size_t>(0, keys.size() - 1)(rng_)];
    const Key& key = w_.keys[k];
    std::vector<Coin> avail;
    for (const auto& c : coins_[k])
      if (is_p2pkh_script_pubkey(c.second.script_pubkey, nullptr)) avail.push_back(c);
    std::shuffle(avail.begin(), avail.end(), rng_);
    if (avail.size() > 4) avail.resize(4);
    std::string err;
    auto committee = ls::rpc_get_committee_bls_keys(opt_.rpc, next, &err);
    if (!committee || committee->keys.empty()) {
      *why = "committee keys: " + err;
      return std::nullopt;
    }
    Bytes data;
    if (reveal) {
      const std::string text = "finalis-nodetest " + utc_now() + " " + hex_encode32(rnd()).substr(0, 16);
      data.assign(text.begin(), text.end());
    }
    const auto prepaid_for = [&](std::size_t body_bytes) -> std::optional<std::uint64_t> {
      auto t = consensus::timed_lock_terms(next, unlock, epoch_blocks,
                                           timed_envelope_bytes_bound(committee->keys.size(), body_bytes));
      if (!t) return std::nullopt;
      return std::max<std::uint64_t>(fee_for(base_fee_, 4000), t->prepaid_fee);
    };
    const std::size_t reveal_bytes = reveal ? kTimedRevealTagBytes + data.size() : 0;
    auto terms = consensus::timed_lock_terms(next, unlock, epoch_blocks,
                                             timed_envelope_bytes_bound(committee->keys.size(), reveal_bytes), &e);
    if (!terms) {
      *why = "lock terms: " + e;  // e.g. too close to the epoch end for a long lock
      return std::nullopt;
    }
    std::uint64_t prepaid = 0;
    std::optional<TimedSendPlan> plan;
    if (reveal) {
      auto p = prepaid_for(reveal_bytes);
      if (!p) return std::nullopt;
      prepaid = *p;
      auto coin = select_timed_fee_coin(avail, prepaid, bond, &e);
      if (coin) plan = TimedSendPlan{*coin, {}, coin->second.value - prepaid - bond};
    } else {
      plan = plan_timed_p2pkh_send_priced(avail, recipient_script(), key.script, kTimedAmountUnits, fee_for(base_fee_, 300),
                                          bond, prepaid_for, &prepaid, &e);
    }
    if (!plan) {
      *why = "plan: " + e;
      return std::nullopt;
    }
    std::optional<Tx> body;
    if (!reveal) {
      body = build_signed_p2pkh_tx_multi_input(timed_body_chain_domain(domain_), plan->body.selected_prevs, key.priv,
                                               plan->body.outputs, &e);
      if (!body) {
        *why = "body: " + e;
        return std::nullopt;
      }
    }
    TimedTxParams p;
    p.fee_outpoint = plan->fee_coin.first;
    p.fee_prev_out = plan->fee_coin.second;
    p.prepaid_fee = prepaid;
    p.forfeit_bond = bond;
    p.bond_refund_script = key.script;
    if (plan->fee_change_units > 0) p.fee_change = TxOut{plan->fee_change_units, key.script};
    p.unlock_height = unlock;
    p.committee_epoch = terms->committee_epoch;
    p.committee_root = committee->root;
    p.committee_keys = committee->keys;
    p.threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(committee->keys.size()));
    const TimedBody sealed = reveal ? TimedBody{TimedReveal{data}} : TimedBody{AnyTx{*body}};
    auto tt = build_signed_timed_tx(domain_, p, sealed, key.priv, rnd(), &e);
    if (!tt) {
      *why = "timed: " + e;
      return std::nullopt;
    }
    Built b;
    b.type = type_name(type);
    b.timed = true;
    b.key = k;
    b.bytes = tt->serialize();
    b.txid = tt->txid();
    // Past its last inclusion height it can never be included: give it up then.
    b.expire_after = std::min(terms->last_inclusion_height, tip_ + kExpireBlocks);
    b.inputs = {plan->fee_coin};
    for (const auto& c : plan->body.selected_prevs) b.body_inputs.push_back(c.first);
    b.body_release = unlock + 2;
    // Take the used coins out of the cache.
    std::set<OutPoint> used(b.body_inputs.begin(), b.body_inputs.end());
    used.insert(plan->fee_coin.first);
    auto& cs = coins_[k];
    cs.erase(std::remove_if(cs.begin(), cs.end(), [&](const Coin& c) { return used.count(c.first) > 0; }), cs.end());
    return b;
  }

  // Splits a big coin into work coins when few are left, so sends do not stall on coins in flight.
  void maybe_split() {
    if (split_in_flight_) return;
    std::size_t work = 0;
    for (const auto& [_, cs] : coins_)
      for (const auto& c : cs)
        if (c.second.value >= kWorkCoinUnits) ++work;
    if (work >= kTargetWorkCoins) return;
    auto taken = take_coin(3 * kWorkCoinUnits, true);
    if (!taken) return;
    auto& [k, coin] = *taken;
    const std::size_t n = std::min<std::size_t>({kTargetWorkCoins - work, coin.second.value / kWorkCoinUnits - 1, 50});
    std::vector<TxOut> outs;
    for (std::size_t i = 0; i < n; ++i) outs.push_back(TxOut{kWorkCoinUnits, w_.keys[random_key()].script});
    const std::uint64_t fee = fee_for(base_fee_, 200 + 40 * n);
    outs.push_back(TxOut{coin.second.value - n * kWorkCoinUnits - fee, w_.keys[k].script});
    std::string e;
    auto tx = build_signed_p2pkh_tx_single_input(domain_, coin.first, coin.second, w_.keys[k].priv, outs, &e);
    if (!tx) {
      put_back(k, {coin});
      return;
    }
    Built b;
    b.type = "split";
    b.key = k;
    b.bytes = tx->serialize();
    b.txid = tx->txid();
    b.inputs = {coin};
    b.expire_after = tip_ + kExpireBlocks;
    if (send(b, false)) split_in_flight_ = true;
  }

  // Broadcasts; returns whether the server accepted it. `paced`: counts towards the summary/backoff.
  bool send(Built& b, bool paced, Pacer* pacer = nullptr, double now = 0) {
    // Confidential secrets reach disk before the transaction leaves.
    if (!b.conf_created.empty() || !b.conf_spent.empty()) {
      for (const auto& c : b.conf_created) w_.conf.push_back(c);
      for (auto& c : w_.conf)
        for (const auto& op : b.conf_spent)
          if (same_op(c.op, op)) c.spend_txid = b.txid;
      save();
    }
    std::string err;
    const auto r = ls::rpc_broadcast_tx(opt_.rpc, b.bytes, &err);
    const std::string id = hex_encode32(b.txid);
    if (r.outcome == ls::BroadcastOutcome::Rejected) {
      const std::string code = r.error_code.empty() ? r.error : r.error_code;
      const std::string reason = code + (r.error_message.empty() ? "" : ": " + r.error_message.substr(0, 100));
      log("send\t" + b.type + "\t" + id + "\t" + opt_.rpc + "\trejected\t" + reason);
      undo(b, code == "tx_missing_or_unconfirmed_input");
      if (paced) {
        sum_.rejected[b.type + " " + code]++;
        if (r.retryable || r.mempool_full) {
          consecutive_rejects_ = 0;
          if (pacer) pacer->retryable_reject(now);
        } else {
          ++consecutive_rejects_;
        }
      }
      return false;
    }
    // Sent, or ambiguous (it may have reached the node): track it either way.
    const bool ok = r.outcome == ls::BroadcastOutcome::Sent;
    log("send\t" + b.type + "\t" + id + "\t" + opt_.rpc + "\t" + (ok ? "accepted" : "ambiguous\t" + err));
    InFlight f;
    f.txid = b.txid;
    f.type = b.type;
    f.sent_at = now_s();
    f.sent_tip = tip_;
    f.expire_after_height = b.expire_after;
    f.timed = b.timed;
    for (const auto& c : b.inputs) {
      f.inputs.push_back(c.first);
      reserved_.insert(c.first);
    }
    for (const auto& op : b.body_inputs) reserved_.insert(op);
    if (!b.body_inputs.empty()) holds_.push_back(BodyHold{b.body_inputs, b.body_release});
    f.conf_spent = b.conf_spent;
    for (const auto& c : b.conf_created) f.conf_created.push_back(c.op);
    inflight_[b.txid] = std::move(f);
    if (paced) {
      consecutive_rejects_ = 0;
      if (ok) {
        sum_.sent[b.type]++;
        if (pacer) pacer->accepted();
      } else {
        sum_.rejected[b.type + " ambiguous"]++;
        if (pacer) pacer->retryable_reject(now);
      }
    }
    return ok;
  }

  // The server refused it: the coins are free again and the outputs never existed.
  void undo(const Built& b, bool inputs_gone) {
    if (!inputs_gone) put_back(b.key, b.inputs);
    if (!b.conf_created.empty() || !b.conf_spent.empty()) {
      std::set<OutPoint> created;
      for (const auto& c : b.conf_created) created.insert(c.op);
      w_.conf.erase(std::remove_if(w_.conf.begin(), w_.conf.end(), [&](const ConfCoin& c) { return created.count(c.op) > 0; }),
                    w_.conf.end());
      for (auto& c : w_.conf)
        for (const auto& op : b.conf_spent)
          if (same_op(c.op, op)) {
            c.spend_txid = Hash32{};
            if (inputs_gone) c.spent = true;  // the chain no longer has it
          }
      save();
    }
  }

  // Polls open transactions; records finality, gives up on old ones.
  void poll_inflight() {
    std::vector<Hash32> done;
    std::size_t polled = 0;
    bool changed = false;
    for (auto& [txid, f] : inflight_) {
      if (++polled > 100) break;
      std::string err;
      auto s = ls::rpc_get_tx_status(opt_.rpc, txid, &err);
      if (!s) continue;
      if (s->finalized) {
        const double secs = now_s() - f.sent_at;
        log("final\t" + f.type + "\t" + hex_encode32(txid) + "\theight=" + std::to_string(s->height) +
            "\tseconds=" + std::to_string(static_cast<long long>(secs)));
        if (f.type != "split" && f.type != "sweep" && f.type != "resumed") {
          sum_.finals[f.type]++;
          sum_.finality_seconds.push_back(secs);
        }
        for (auto& c : w_.conf) {
          for (const auto& op : f.conf_created)
            if (same_op(c.op, op)) c.origin_final = true;
          for (const auto& op : f.conf_spent)
            if (same_op(c.op, op)) {
              c.spent = true;
              c.spend_txid = Hash32{};
            }
        }
        changed = changed || !f.conf_created.empty() || !f.conf_spent.empty();
        for (const auto& op : f.inputs) reserved_.erase(op);  // spent now: refresh_coins no longer lists them
        if (f.type == "split") split_in_flight_ = false;
        done.push_back(txid);
      } else if (tip_ > f.expire_after_height) {
        log("expired\t" + f.type + "\t" + hex_encode32(txid) + "\tnot final by height " + std::to_string(f.expire_after_height));
        if (f.type != "split" && f.type != "sweep" && f.type != "resumed") sum_.expired[f.type]++;
        for (const auto& op : f.inputs) reserved_.erase(op);
        for (auto& c : w_.conf)
          for (const auto& op : f.conf_spent)
            if (same_op(c.op, op)) c.spend_txid = Hash32{};
        changed = changed || !f.conf_spent.empty();
        if (f.type == "split") split_in_flight_ = false;
        done.push_back(txid);
      }
    }
    for (const auto& t : done) inflight_.erase(t);
    if (changed) save();
  }

  TxType pick_type(const std::vector<TxType>& allowed) {
    std::vector<double> w;
    for (const auto t : allowed) w.push_back(type_weight(t));
    std::discrete_distribution<std::size_t> d(w.begin(), w.end());
    return allowed[d(rng_)];
  }

  // --- commands ---

  int status_command() {
    refresh_coins();
    recheck_conf();
    std::size_t locked = 0;
    std::uint64_t locked_units = 0;
    for (std::uint32_t k = 0; k < w_.keys.size(); ++k) {
      std::string err;
      auto u = ls::rpc_get_utxos(opt_.rpc, w_.keys[k].scripthash, &err);
      if (!u) continue;
      for (const auto& v : *u)
        if (!script_spendable_by(v.script_pubkey, w_.keys[k].pkh, tip_ + 1) && parse_height_lock_script(v.script_pubkey)) {
          ++locked;
          locked_units += v.value;
        }
    }
    std::cout << "tip " << tip_ << "  address #0 " << w_.keys[0].address << "\n"
              << "transparent spendable " << fls(transparent_units()) << " FLS\n"
              << "confidential spendable " << fls(conf_units()) << " FLS\n"
              << "height-locked (not yet spendable) " << fls(locked_units) << " FLS in " << locked << " coins\n";
    return 0;
  }

  int run_command() {
    std::string err;
    if (!opt_.peers_file.empty()) {
      std::ifstream pf(opt_.peers_file);
      if (!pf) return fail("cannot read " + opt_.peers_file);
      std::stringstream ss;
      ss << pf.rdbuf();
      auto p = parse_peers(ss.str(), w_.addresses(), &err);
      if (!p) return fail(err);
      peers_ = std::move(*p);
    }
    {
      auto s = ls::rpc_get_status(opt_.rpc, &err);
      if (!s) return fail("status: " + err);
      if (auto problem = preflight_problem(*s, opt_.min_peers)) return fail("not starting: " + *problem);
    }
    if (!crypto::confidential_crypto_init()) return fail("confidential crypto init failed");
    std::filesystem::remove(std::filesystem::path(opt_.dir) / "STOP");
    log_.open(std::filesystem::path(opt_.dir) / "txlog.tsv", std::ios::app);
    recheck_conf();
    refresh_coins();
    const std::uint64_t funds = transparent_units() + conf_units();
    if (funds < kMinFundingUnits) {
      std::cout << "This wallet holds " << fls(funds) << " FLS. Send at least 1 FLS (5 FLS is plenty) of testnet\n"
                << "coins to\n\n    " << w_.keys[0].address << "\n\nwait until the payment is final, then run again.\n";
      return 3;
    }
    if (opt_.start_at_unix) {
      switch (start_decision(unix_now(), *opt_.start_at_unix, opt_.allow_late)) {
        case StartDecision::TooFar:
          return fail("--start-at " + format_utc_time(*opt_.start_at_unix) + " is more than 14 days ahead; check the date");
        case StartDecision::TooLate:
          std::cerr << "finalis-nodetest: the shared test window started at " << format_utc_time(*opt_.start_at_unix)
                    << ", more than 10 minutes ago. Not starting alone (--allow-late to start anyway).\n";
          return 4;
        case StartDecision::Wait:
        case StartDecision::Start:
          break;
      }
    }
    std::cout << "finalis-nodetest on " << opt_.rpc << ": " << opt_.rate << " tx/s for " << opt_.duration_seconds
              << " s, " << opt_.types.size() << " types, " << peers_.size() << " peers, funds " << fls(funds)
              << " FLS. Ctrl-C or touch " << (std::filesystem::path(opt_.dir) / "STOP").string() << " to stop.\n";
    // A fresh wallet holds one or two coins: split them and wait until the work coins are final, so the
    // run does not start with empty slots.
    maybe_split();
    const double setup_end = now_s() + 900;
    if (split_in_flight_) std::cout << "waiting for the setup split to be final (one or two blocks)...\n";
    while (split_in_flight_ && !stop_requested() && now_s() < setup_end) {
      for (int i = 0; i < 50 && !stop_requested(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(200));
      if (refresh_status()) poll_inflight();
    }
    if (opt_.start_at_unix && !wait_for_start_time()) {
      std::cout << "Stopped before the start; no test transactions were sent.\n";
      return 0;
    }
    refresh_coins();
    log("start\trate=" + std::to_string(opt_.rate) + "\tduration=" + std::to_string(opt_.duration_seconds) +
        "\tpeers=" + std::to_string(peers_.size()) + "\ttip=" + std::to_string(tip_));
    const double start = now_s();
    const double end = start + static_cast<double>(opt_.duration_seconds);
    Pacer pacer(opt_.rate, start);
    double next_refresh = start + 15;
    while (!stop_requested() && now_s() < end) {
      const double now = now_s();
      if (now >= next_refresh) {
        if (refresh_status()) {
          poll_inflight();
          refresh_coins();
          maybe_split();
        }
        next_refresh = now + 15;
      }
      if (pacer.due(now) && inflight_.size() < kMaxInFlight) {
        std::vector<TxType> allowed = opt_.types;
        bool sent = false;
        std::string why;
        while (!allowed.empty() && !sent) {
          const TxType t = pick_type(allowed);
          auto b = build(t, &why);
          if (b) {
            send(*b, true, &pacer, now);
            sent = true;
          } else {
            if (!why.empty()) {
              log("build\t" + type_name(t) + "\tskipped\t" + why.substr(0, 160));
              why.clear();
            }
            allowed.erase(std::find(allowed.begin(), allowed.end(), t));
          }
        }
        if (!sent) ++sum_.starved;
        if (pacer.due(now)) pacer.sent(now);
        if (consecutive_rejects_ >= kMaxConsecutiveRejects) {
          log("stop\t" + std::to_string(consecutive_rejects_) + " rejects in a row");
          break;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    log(std::string("stop\t") + (stop_requested() ? "requested" : "duration reached or rejects"));
    return finish(true);
  }

  // --start-at: counts down to the shared start (plus a few random seconds), then waits until the node
  // passes the preflight again. False if stopped first, or if the node is not ready within the late
  // cut-off after the start.
  bool wait_for_start_time() {
    const std::int64_t start = *opt_.start_at_unix;
    const std::int64_t go = start + std::uniform_int_distribution<std::int64_t>(0, kStartJitterSeconds)(rng_);
    std::cout << "Shared start at " << format_utc_time(start) << " (this node starts at " << format_utc_time(go)
              << "). Leave this running; Ctrl-C or STOP cancels.\n";
    std::int64_t last_note = 0;
    while (unix_now() < go) {
      if (stop_requested()) return false;
      const std::int64_t left = go - unix_now();
      const std::int64_t every = left > 3600 ? 1800 : left > 600 ? 300 : 60;
      if (unix_now() - last_note >= every) {
        std::cout << "starting in " << left / 3600 << "h " << left % 3600 / 60 << "m " << left % 60 << "s\n" << std::flush;
        last_note = unix_now();
      }
      // Keep the open setup transactions moving while waiting.
      if (unix_now() % 15 == 0 && refresh_status()) poll_inflight();
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    while (true) {
      if (stop_requested()) return false;
      std::string err;
      auto s = ls::rpc_get_status(opt_.rpc, &err);
      std::string problem = s ? preflight_problem(*s, opt_.min_peers).value_or("") : "status: " + err;
      if (s && refuse_network(*s)) throw std::runtime_error("the server changed chains");
      if (problem.empty()) return true;
      if (unix_now() - start > kLateStartSeconds && !opt_.allow_late) {
        log("stop\tnode not ready by " + format_utc_time(start + kLateStartSeconds) + "\t" + problem);
        return false;
      }
      log("wait\tnode not ready\t" + problem);
      for (int i = 0; i < 75 && !stop_requested(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
  }

  // Waits for open transactions, returns every spendable coin to address #0, prints the summary.
  int finish(bool after_run) {
    if (!after_run) {
      if (!crypto::confidential_crypto_init()) return fail("confidential crypto init failed");
      log_.open(std::filesystem::path(opt_.dir) / "txlog.tsv", std::ios::app);
      recheck_conf();
    }
    const int stops_at_start = g_stop.load();
    const double drain_end = now_s() + static_cast<double>(opt_.drain_seconds);
    double last_note = 0;
    while (!inflight_.empty() && now_s() < drain_end && g_stop.load() == stops_at_start) {
      if (refresh_status()) poll_inflight();
      if (inflight_.empty()) break;
      if (now_s() - last_note > 60) {
        std::cout << "waiting for " << inflight_.size() << " open transactions (Ctrl-C to skip)...\n";
        last_note = now_s();
      }
      for (int i = 0; i < 50 && g_stop.load() == stops_at_start; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    // Sweep rounds: coins of transactions that expire meanwhile come free and go in the next round.
    const Bytes target = w_.keys[0].script;
    std::uint64_t moved = 0, fees = 0, dust = 0;
    std::size_t sweep_txs = 0;
    const double sweep_end = now_s() + std::min<double>(static_cast<double>(opt_.drain_seconds), 900);
    for (int round = 0; round < 3; ++round) {
      refresh_status();
      refresh_coins();
      if (round > 0) {  // the previous rounds' outputs are already home: only newly freed coins move
        auto& home = coins_[0];
        home.erase(std::remove_if(home.begin(), home.end(), [&](const Coin& c) { return c.second.script_pubkey == target; }),
                   home.end());
      }
      std::vector<ConfCoin> conf;
      for (const auto i : usable_conf()) conf.push_back(w_.conf[i]);
      std::string err;
      auto sweep = build_sweep(domain_, w_, coins_, conf, target, base_fee_, &dust, &err);
      if (!err.empty() && sweep.empty()) log("sweep\tbuild failed\t" + err);
      if (sweep.empty()) break;
      for (auto& s : sweep) {
        Built b;
        b.type = "sweep";
        b.txid = s.txid;
        b.bytes = std::visit([](const auto& t) { return t.serialize(); }, s.tx);
        b.conf_spent = s.conf_inputs;
        b.expire_after = tip_ + kExpireBlocks;
        if (send(b, false)) {
          ++sweep_txs;
          moved += s.output_units;
          fees += s.fee;
        }
      }
      // Wait (bounded) for the sweep itself so the final balance is real.
      while (!inflight_.empty() && now_s() < sweep_end && g_stop.load() <= stops_at_start + 1) {
        for (int i = 0; i < 50; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (refresh_status()) poll_inflight();
      }
      if (!inflight_.empty() || now_s() >= sweep_end) break;
    }
    save();
    std::cout << "\n" << sum_.render();
    std::cout << "sweep: " << sweep_txs << " txs, " << fls(moved) << " FLS to " << w_.keys[0].address << " (fees "
              << fls(fees) << ", left as dust " << fls(dust) << ")\n";
    if (!holds_.empty() || !inflight_.empty()) {
      std::cout << "Some coins are still time-locked or unconfirmed; run `finalis-nodetest sweep` again later.\n";
    }
    std::cout << "Log: " << (std::filesystem::path(opt_.dir) / "txlog.tsv").string()
              << " (nothing was uploaded; paste the summary above if you want to share it)\n";
    return 0;
  }
};

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> args(argv + 1, argv + argc);
  std::string err;
  auto opt = parse_options(args, &err);
  if (!opt) {
    std::cerr << "finalis-nodetest: " << err << "\n\n" << usage_text();
    return 2;
  }
  if (opt->command == "help") {
    std::cout << usage_text();
    return 0;
  }
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  try {
    Runner r(*opt);
    return r.main_command();
  } catch (const std::exception& e) {
    std::cerr << "finalis-nodetest: " << e.what() << "\n";
    return 1;
  }
}
