// SPDX-License-Identifier: MIT

// Time-locked transaction execution fuzzer (McFly layer, utxo/confidential_tx.hpp TxTimed). Runs a
// chain of blocks through execute_frontier_slice with a TimedExecutionContext, carrying the UTXO set,
// escrows and long-lock key sets from block to block as the canonical derivation does
// (apply_timed_escrows). Committees alternate per epoch (two 4-key sets out of 5 BLS keys, epoch 8
// blocks), so long locks settle under a committee that is no longer current.
//
// Each input is a script: blocks carrying new envelopes (short or long locks; transfer, reveal,
// non-plain, undecryptable or fee-coin-spending bodies; prepaid fee too low), plain transfers that
// race a sealed body for its inputs, replays of earlier envelopes and garbage records; per block the
// parent time signature is valid, missing or on the wrong height, and long locks get valid openings,
// none, or a forged one; jumps run empty blocks up to past the long-lock grace period. Oracles:
//   - conservation: transparent UTXO value + escrowed bonds + fees collected == genesis value;
//   - settlement: every escrow settles exactly once, short locks at unlock + 1, long locks within
//     unlock + 1 .. unlock + grace or expire at unlock + grace + 1; an envelope is included once;
//   - refund: the bond refund output exists iff the body applied or the lock expired, with the bond's
//     value, and never overwrites an output;
//   - no early opening: a body applies only in a block that carries a valid time signature on its
//     unlock height (short: the parent signature; long: a long_time_signatures entry);
//   - liveness: a plain transfer body whose inputs are unspent applies when the signature is valid;
//   - a sealed transfer executes only through its settlement: replayed as a plain record (anyone can
//     once the time signature is out) it is rejected, so nobody can spend its inputs first and make
//     the settlement forfeit the bond;
//   - a forged long opening makes the block invalid; valid openings never do;
//   - determinism: executing the same block twice gives the same result.
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary (fixed-seed scripts, or replay of the files given as arguments).

#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/address.hpp"
#include "common/network.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/frontier_execution.hpp"
#include "consensus/randomness.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

constexpr std::uint64_t kEpoch = 8;
constexpr std::size_t kOwners = 3;
constexpr std::size_t kCoinsPerOwner = 12;
constexpr std::uint64_t kCoinValue = 100'000'000;
constexpr std::uint64_t kPrepaid = 1'000'000;
constexpr std::size_t kMaxBlocks = 1200;

struct Stats {
  std::uint64_t inputs{0};
  std::uint64_t blocks{0};
  std::uint64_t included{0};
  std::uint64_t applied{0};
  std::uint64_t forfeited{0};
  std::uint64_t expired{0};
  std::uint64_t long_applied{0};
} g_stats;

[[noreturn]] void fail(const std::string& what, std::uint64_t height) {
  std::cerr << "fuzz_timed_execution: " << what << " height=" << height << "\n";
  std::abort();
}

struct Cursor {
  const Bytes& in;
  std::size_t pos{0};
  bool done() const { return pos >= in.size(); }
  std::uint8_t u8() { return pos < in.size() ? in[pos++] : 0; }
};

enum class BodyKind : std::uint8_t { Transfer, Reveal, NonPlain, Undecryptable, SpendsFeeCoin, Count };

// What the harness knows about an envelope it built (oracles only).
struct Built {
  TxTimed tx;
  BodyKind kind{BodyKind::Transfer};
  std::vector<OutPoint> body_inputs;
  Bytes body_raw;  // the sealed transfer's own encoding (empty for a reveal)
};

struct Fixture {
  Hash32 domain{};
  NetworkConfig network;
  ChainId chain_id;
  std::vector<crypto::BlsSecretKey> bls_sks;
  std::vector<crypto::BlsPublicKey> bls_pks;
  std::vector<crypto::KeyPair> owners;
  std::vector<Bytes> owner_scripts;
  UtxoSetV2 genesis;
  std::uint64_t genesis_value{0};
  // Signatures by height, shared by every input (deterministic keys).
  std::map<std::uint64_t, std::map<std::uint32_t, crypto::BlsSignature>> sig_cache;
};

// Committee of the epoch starting at `epoch_start`: keys 0..3 in even epochs, 1..4 in odd ones.
std::vector<std::uint32_t> committee_indices(std::uint64_t epoch_start) {
  return (epoch_start / kEpoch) % 2 == 0 ? std::vector<std::uint32_t>{0, 1, 2, 3}
                                          : std::vector<std::uint32_t>{1, 2, 3, 4};
}

Fixture make_fixture() {
  Fixture fx;
  fx.network = mainnet_network();
  fx.network.committee_epoch_blocks = kEpoch;
  fx.chain_id.network_name = fx.network.name;
  fx.chain_id.magic = fx.network.magic;
  fx.chain_id.network_id_hex = hex_encode(Bytes(fx.network.network_id.begin(), fx.network.network_id.end()));
  fx.chain_id.protocol_version = PROTOCOL_VERSION;
  fx.chain_id.genesis_hash_hex = "fuzz-timed";
  fx.chain_id.genesis_source = "fuzz";
  fx.domain = consensus_chain_domain(fx.network, fx.chain_id);
  for (std::uint8_t i = 0; i < 5; ++i) {
    Bytes ikm(32, 0xb1);
    ikm[0] = i;
    auto sk = crypto::bls_keygen(ikm);
    if (!sk) throw std::runtime_error("bls keygen");
    fx.bls_pks.push_back(*crypto::bls_public_key(*sk));
    fx.bls_sks.push_back(*sk);
  }
  for (std::uint8_t o = 0; o < kOwners; ++o) {
    std::array<std::uint8_t, 32> seed{};
    seed.fill(static_cast<std::uint8_t>(0x40 + o));
    auto kp = crypto::keypair_from_seed32(seed);
    if (!kp) throw std::runtime_error("ed25519 keygen");
    fx.owner_scripts.push_back(address::p2pkh_script_pubkey(crypto::h160(Bytes(kp->public_key.begin(), kp->public_key.end()))));
    fx.owners.push_back(std::move(*kp));
    for (std::uint32_t c = 0; c < kCoinsPerOwner; ++c) {
      Hash32 txid{};
      txid.fill(static_cast<std::uint8_t>(0x10 + o));
      fx.genesis[OutPoint{txid, c}] = UtxoEntryV2{TxOut{kCoinValue, fx.owner_scripts[o]}};
      fx.genesis_value += kCoinValue;
    }
  }
  return fx;
}

Fixture& fixture() {
  static Fixture fx = make_fixture();
  return fx;
}

std::vector<crypto::BlsPublicKey> committee_keys(const Fixture& fx, std::uint64_t epoch_start) {
  std::vector<crypto::BlsPublicKey> out;
  for (const auto i : committee_indices(epoch_start)) out.push_back(fx.bls_pks[i]);
  return out;
}

// The aggregate of the lowest-index threshold members of the committee whose keys are `keys` on
// time_signature_message(height).
TimeSignatureAggregate time_signature(Fixture& fx, const std::vector<crypto::BlsPublicKey>& keys, std::uint64_t height) {
  auto& by_key = fx.sig_cache[height];
  const auto msg = time_signature_message(fx.domain, height);
  std::map<std::uint32_t, crypto::BlsSignature> sigs;
  for (std::uint32_t i = 0; i < keys.size(); ++i) {
    for (std::uint32_t k = 0; k < fx.bls_pks.size(); ++k) {
      if (fx.bls_pks[k] != keys[i]) continue;
      if (!by_key.contains(k)) by_key[k] = *crypto::bls_sign(fx.bls_sks[k], msg, crypto::kBlsTimeSignatureDst);
      sigs[i] = by_key[k];
    }
  }
  auto agg = consensus::aggregate_time_signatures(keys, sigs, consensus::quorum_threshold(keys.size()));
  if (!agg) fail("aggregate", height);
  return *agg;
}

Bytes p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes out;
  out.push_back(0x40);
  out.insert(out.end(), sig.begin(), sig.end());
  out.push_back(0x20);
  out.insert(out.end(), pub.begin(), pub.end());
  return out;
}

struct Chain {
  Fixture& fx;
  std::uint64_t height{0};  // last executed block
  UtxoSetV2 utxos;
  consensus::TimedEscrowState escrows;
  consensus::TimedKeySets key_sets;
  std::uint64_t fees{0};
  std::map<Hash32, Built> built;          // by timed txid
  std::vector<Hash32> built_order;
  std::set<Hash32> included;              // timed txids ever included
  std::set<Hash32> settled;               // timed txids ever settled
  std::uint32_t seed_counter{0};
};

// A coin of `owner` (index `pick`), as an outpoint/output pair, whether or not it is still unspent.
std::pair<OutPoint, TxOut> owner_coin(const Fixture& fx, std::size_t owner, std::size_t pick) {
  Hash32 txid{};
  txid.fill(static_cast<std::uint8_t>(0x10 + owner));
  return {OutPoint{txid, static_cast<std::uint32_t>(pick % kCoinsPerOwner)}, TxOut{kCoinValue, fx.owner_scripts[owner]}};
}

// A transfer of `coin`, signed under `domain` (the chain's, or timed_body_chain_domain for a body).
std::optional<Tx> transfer(const Fixture& fx, const Hash32& domain, std::size_t owner, const std::pair<OutPoint, TxOut>& coin,
                           const Bytes& to, std::uint64_t fee) {
  return build_signed_p2pkh_tx_single_input(domain, coin.first, coin.second, fx.owners[owner].private_key,
                                            {TxOut{coin.second.value - fee, to}});
}

// A new envelope from `owner`: fee coin and body chosen by the script. Nullopt if the builder refuses.
std::optional<Built> build_envelope(Chain& chain, Cursor& cur, std::uint64_t next_height, bool any_unlock) {
  auto& fx = chain.fx;
  const std::size_t owner = cur.u8() % kOwners;
  const auto fee_coin = owner_coin(fx, owner, cur.u8());
  const auto epoch_start = consensus::committee_epoch_start(next_height, kEpoch);
  const auto epoch_end = epoch_start + kEpoch - 1;
  std::uint64_t unlock = any_unlock ? next_height + cur.u8() % 28 : next_height + cur.u8() % (epoch_end - next_height + 1);
  if (cur.u8() % 16 == 0 && unlock > 0) unlock -= 1;  // possibly already passed
  const auto flags = cur.u8();
  Built b;
  b.kind = static_cast<BodyKind>(flags % static_cast<std::uint8_t>(BodyKind::Count));
  const bool low_fee = (flags & 0x80) != 0 && (flags & 0x40) != 0;
  const std::uint64_t prepaid = low_fee ? 1'000 : kPrepaid;
  const std::uint64_t bond = consensus::kTxTimedMinForfeitBond - ((flags & 0x20) && (flags & 0x10) ? 1 : 0);

  TimedTxParams p;
  p.fee_outpoint = fee_coin.first;
  p.fee_prev_out = fee_coin.second;
  p.prepaid_fee = prepaid;
  p.forfeit_bond = bond;
  p.bond_refund_script = fx.owner_scripts[(owner + 1) % kOwners];
  p.fee_change = TxOut{kCoinValue - prepaid - bond, fx.owner_scripts[owner]};
  p.unlock_height = unlock;
  p.committee_epoch = epoch_start;
  p.committee_keys = committee_keys(fx, epoch_start);
  p.committee_root = consensus::committee_bls_key_root(p.committee_keys);
  p.threshold = static_cast<std::uint32_t>(consensus::quorum_threshold(p.committee_keys.size()));

  TimedBody body;
  const auto body_domain = timed_body_chain_domain(fx.domain);
  const auto body_coin = owner_coin(fx, owner, cur.u8());
  const auto to = fx.owner_scripts[cur.u8() % kOwners];
  switch (b.kind) {
    case BodyKind::Reveal:
      body = TimedReveal{Bytes{'d', 'a', 't', 'a', static_cast<std::uint8_t>(chain.seed_counter)}};
      break;
    case BodyKind::NonPlain: {
      auto tx = build_signed_p2pkh_tx_single_input(body_domain, body_coin.first, body_coin.second,
                                                   fx.owners[owner].private_key, {TxOut{kCoinValue - 1000, Bytes{0x6a}}});
      if (!tx) return std::nullopt;
      b.body_inputs = {body_coin.first};
      body = AnyTx{*tx};
      break;
    }
    case BodyKind::SpendsFeeCoin: {
      auto tx = transfer(fx, body_domain, owner, fee_coin, to, 1000);
      if (!tx) return std::nullopt;
      b.body_inputs = {fee_coin.first};
      body = AnyTx{*tx};
      break;
    }
    default: {
      auto tx = transfer(fx, body_domain, owner, body_coin, to, 1000);
      if (!tx) return std::nullopt;
      b.body_inputs = {body_coin.first};
      body = AnyTx{*tx};
      break;
    }
  }
  Hash32 seed{};
  seed[0] = 0x5e;
  const auto counter = ++chain.seed_counter;
  for (int i = 0; i < 4; ++i) seed[1 + i] = static_cast<std::uint8_t>(counter >> (8 * i));
  auto tx = build_signed_timed_tx(fx.domain, p, body, fx.owners[owner].private_key, seed);
  if (!tx) return std::nullopt;
  if (const auto* transfer_body = std::get_if<AnyTx>(&body)) b.body_raw = serialize_any_tx(*transfer_body);
  if (b.kind == BodyKind::Undecryptable) {
    tx->body_ciphertext[tx->body_ciphertext.size() / 2] ^= 0x01;
    const auto sig = crypto::ed25519_sign(signing_message_for_timed_fee_input(fx.domain, *tx), fx.owners[owner].private_key);
    tx->fee_input.script_sig = p2pkh_script_sig(*sig, fx.owners[owner].public_key);
  }
  b.tx = std::move(*tx);
  return b;
}

std::uint64_t transparent_value(const UtxoSetV2& utxos) {
  std::uint64_t sum = 0;
  for (const auto& [_, entry] : utxos) {
    const auto out = transparent_txout_from_utxo_entry(entry);
    if (out) sum += out->value;
  }
  return sum;
}

void check_conservation(const Chain& chain) {
  std::uint64_t bonds = 0;
  for (const auto& [_, tx] : chain.escrows) bonds += tx.forfeit_bond;
  const auto total = transparent_value(chain.utxos) + bonds + chain.fees;
  if (total != chain.fx.genesis_value) {
    fail("conservation: utxos+bonds+fees=" + std::to_string(total) + " genesis=" + std::to_string(chain.fx.genesis_value),
         chain.height);
  }
}

enum class SigMode : std::uint8_t { Valid, Missing, WrongHeight };
enum class LongMode : std::uint8_t { Valid, None, Forged };

// Executes block chain.height + 1 with `records`, checks the oracles and advances the chain.
void run_block(Chain& chain, const std::vector<Bytes>& records, SigMode sig_mode, LongMode long_mode) {
  auto& fx = chain.fx;
  const auto h = chain.height + 1;
  if (h > kMaxBlocks) return;
  ++g_stats.blocks;

  consensus::TimedExecutionContext timed;
  timed.height = h;
  timed.chain_domain = fx.domain;
  timed.committee_epoch_blocks = kEpoch;
  timed.escrows = &chain.escrows;
  timed.key_sets = &chain.key_sets;
  timed.committee_keys = [&fx, h](std::uint64_t epoch_start) -> std::optional<std::vector<crypto::BlsPublicKey>> {
    if (epoch_start > consensus::committee_epoch_start(h, kEpoch)) return std::nullopt;  // not yet known
    return committee_keys(fx, epoch_start);
  };
  // Signatures are produced only when an escrow can use them (BLS signing is the slow part).
  bool short_due = false;
  for (auto it = chain.escrows.lower_bound(consensus::TimedEscrowKey{h - 1, 0, 0});
       h >= 2 && it != chain.escrows.end() && it->first.unlock_height == h - 1; ++it) {
    short_due = true;
  }
  TimeSignatureAggregate parent_sig;
  if (h >= 2) {
    timed.parent_committee_keys = committee_keys(fx, consensus::committee_epoch_start(h - 1, kEpoch));
    if (short_due && sig_mode != SigMode::Missing) {
      parent_sig = time_signature(fx, timed.parent_committee_keys, sig_mode == SigMode::Valid ? h - 1 : h + 7);
    }
    if (sig_mode != SigMode::Missing) timed.parent_time_signature = &parent_sig;
  }

  // Long openings for every (unlock, key set) with a waiting long escrow in its grace window.
  std::vector<LongTimeSignature> long_sigs;
  bool forged = false;
  if (long_mode != LongMode::None) {
    std::set<std::pair<std::uint64_t, Hash32>> due;
    for (const auto& [key, tx] : chain.escrows) {
      if (!consensus::timed_is_long_lock(tx, kEpoch)) continue;
      if (key.unlock_height < h && h - key.unlock_height <= consensus::kTimedLongGraceBlocks) {
        due.insert({key.unlock_height, tx.committee_root});
      }
    }
    for (const auto& [unlock, root] : due) {
      if (long_sigs.size() >= kMaxLongTimeSignaturesPerBlock) break;
      const auto& keys = chain.key_sets.at(root);
      LongTimeSignature entry{unlock, root, time_signature(fx, keys, unlock)};
      if (long_mode == LongMode::Forged && !forged) {
        entry.signature = time_signature(fx, keys, unlock + 1);
        forged = true;
      }
      long_sigs.push_back(std::move(entry));
    }
  }
  timed.long_time_signatures = &long_sigs;

  SpecialValidationContext vctx;
  vctx.network = &fx.network;
  vctx.chain_id = &fx.chain_id;
  vctx.current_height = h;
  consensus::FrontierExecutionResult result;
  std::string err;
  const bool ok = consensus::execute_frontier_slice(chain.utxos, 0, 0, records, &vctx, &result, &err, true, nullptr, &timed);
  if (forged) {
    if (ok) fail("forged long opening accepted", h);
    return;  // an invalid block: the chain does not advance
  }
  if (!ok) fail("valid block rejected: " + err, h);

  consensus::FrontierExecutionResult again;
  if (!consensus::execute_frontier_slice(chain.utxos, 0, 0, records, &vctx, &again, &err, true, nullptr, &timed) ||
      again.result_id() != result.result_id() || again.transition.next_state_root != result.transition.next_state_root ||
      again.settlements.size() != result.settlements.size() || again.accepted_fee_units != result.accepted_fee_units) {
    fail("nondeterministic execution", h);
  }

  // Settlements: due, once, refund iff applied/expired, no early opening, liveness.
  std::set<Hash32> long_opened;
  for (const auto& entry : long_sigs) long_opened.insert(entry.committee_root);
  std::set<OutPoint> spent_by_bodies;
  for (const auto& s : result.settlements) {
    const auto it = chain.escrows.find(s.key);
    if (it == chain.escrows.end()) fail("settled an escrow that does not exist", h);
    const auto& tx = it->second;
    if (s.timed_txid != tx.txid()) fail("settlement txid mismatch", h);
    if (!chain.settled.insert(s.timed_txid).second) fail("escrow settled twice", h);
    const bool long_lock = consensus::timed_is_long_lock(tx, kEpoch);
    if (!long_lock && s.key.unlock_height + 1 != h) fail("short lock settled off its height", h);
    if (long_lock) {
      if (s.key.unlock_height >= h) fail("long lock settled before unlock", h);
      if (s.expired && h != s.key.unlock_height + consensus::kTimedLongGraceBlocks + 1) fail("expiry off its height", h);
      if (!s.expired && h - s.key.unlock_height > consensus::kTimedLongGraceBlocks) fail("long lock opened after grace", h);
    }
    if (s.expired && s.body_applied) fail("expired lock applied its body", h);
    if (s.body_applied) {
      const bool signed_ok = long_lock ? long_opened.contains(tx.committee_root) : sig_mode == SigMode::Valid;
      if (!signed_ok) fail("body applied without a valid time signature", h);
    }
    const auto refund = result.next_utxos.find(consensus::timed_refund_outpoint(s.timed_txid));
    const bool refunded = refund != result.next_utxos.end();
    if (refunded != (s.body_applied || s.expired)) fail("refund presence != applied/expired", h);
    if (refunded) {
      const auto out = transparent_txout_from_utxo_entry(refund->second);
      if (!out || out->value != tx.forfeit_bond || out->script_pubkey != tx.bond_refund_script) fail("refund value", h);
      if (chain.utxos.contains(consensus::timed_refund_outpoint(s.timed_txid))) fail("refund overwrote an output", h);
    }
    const auto b = chain.built.find(s.timed_txid);
    if (b == chain.built.end()) fail("settled an unknown envelope", h);
    const bool sig_valid = long_lock ? long_opened.contains(tx.committee_root) : sig_mode == SigMode::Valid;
    if (sig_valid && !s.expired && b->second.kind == BodyKind::Transfer) {
      bool inputs_free = true;
      for (const auto& in : b->second.body_inputs) {
        if (!chain.utxos.contains(in) || spent_by_bodies.contains(in)) inputs_free = false;
      }
      if (inputs_free && !s.body_applied) fail("valid transfer body with free inputs did not apply", h);
    }
    if (sig_valid && (b->second.kind == BodyKind::Reveal) && !s.body_applied) fail("reveal did not apply", h);
    if (s.body_applied && (b->second.kind == BodyKind::NonPlain || b->second.kind == BodyKind::Undecryptable ||
                           b->second.kind == BodyKind::SpendsFeeCoin)) {
      fail("invalid body applied", h);
    }
    if (s.body_applied) {
      for (const auto& in : b->second.body_inputs) spent_by_bodies.insert(in);
      ++(long_lock ? g_stats.long_applied : g_stats.applied);
    } else if (s.expired) {
      ++g_stats.expired;
    } else {
      ++g_stats.forfeited;
    }
  }
  for (const auto& decision : result.decisions) {
    if (!decision.accepted) continue;
    for (const auto& [_, b] : chain.built) {
      if (!b.body_raw.empty() && txid_any(*parse_any_tx(b.body_raw)) == decision.record_id) {
        fail("a sealed transfer was accepted as a standalone record", h);
      }
    }
  }
  for (const auto& [key, tx] : result.opened_escrows) {
    if (key.inclusion_height != h || tx.unlock_height < h) fail("escrow opened with a passed unlock height", h);
    if (tx.committee_epoch != consensus::committee_epoch_start(h, kEpoch)) fail("escrow names another epoch", h);
    if (tx.forfeit_bond < consensus::kTxTimedMinForfeitBond) fail("escrow bond below minimum", h);
    if (!chain.included.insert(tx.txid()).second) fail("envelope included twice", h);
    ++g_stats.included;
  }

  chain.utxos = std::move(result.next_utxos);
  consensus::apply_timed_escrows(result, &chain.escrows, &chain.key_sets);
  chain.fees += result.accepted_fee_units;
  chain.height = h;
  check_conservation(chain);
  for (const auto& [key, tx] : chain.escrows) {
    const bool long_lock = consensus::timed_is_long_lock(tx, kEpoch);
    if (!long_lock && key.unlock_height < h) fail("short escrow left past its settlement height", h);
    if (long_lock && key.unlock_height + consensus::kTimedLongGraceBlocks < h) fail("long escrow left past expiry", h);
    if (long_lock && !chain.key_sets.contains(tx.committee_root)) fail("long escrow lost its key set", h);
  }
}

void run_one(const Bytes& in) {
  ++g_stats.inputs;
  Chain chain{fixture()};
  chain.utxos = chain.fx.genesis;
  Cursor cur{in};
  while (!cur.done() && chain.height < kMaxBlocks) {
    const auto op = cur.u8();
    const auto mode = cur.u8();
    const auto sig_mode = static_cast<SigMode>(mode % 4 == 3 ? 2 : (mode % 4 == 2 ? 1 : 0));
    const auto long_mode = static_cast<LongMode>((mode >> 2) % 8 == 7 ? 2 : ((mode >> 2) % 8 == 6 ? 1 : 0));
    switch (op % 8) {
      case 0: case 1: case 2: case 3: {
        std::vector<Bytes> records;
        const auto n = 1 + cur.u8() % 4;
        for (std::size_t i = 0; i < n; ++i) {
          const auto kind = cur.u8() % 6;
          if (kind <= 1) {
            auto b = build_envelope(chain, cur, chain.height + 1, kind == 1);
            if (!b) continue;
            records.push_back(b->tx.serialize());
            const auto txid = b->tx.txid();
            chain.built.emplace(txid, std::move(*b));
            chain.built_order.push_back(txid);
          } else if (kind == 2) {
            const std::size_t owner = cur.u8() % kOwners;
            if (auto tx = transfer(chain.fx, chain.fx.domain, owner, owner_coin(chain.fx, owner, cur.u8()),
                                   chain.fx.owner_scripts[cur.u8() % kOwners], 2000)) {
              records.push_back(tx->serialize());
            }
          } else if (kind == 3 && (cur.u8() & 1) != 0 && !chain.built_order.empty()) {
            // A sealed transfer replayed as a plain record (as anyone who decrypted it could).
            const auto& body_raw = chain.built.at(chain.built_order[cur.u8() % chain.built_order.size()]).body_raw;
            if (!body_raw.empty()) records.push_back(body_raw);
          } else if (kind == 3 && !chain.built_order.empty()) {
            records.push_back(chain.built.at(chain.built_order[cur.u8() % chain.built_order.size()]).tx.serialize());
          } else if (kind == 4 && !chain.built_order.empty()) {
            auto raw = chain.built.at(chain.built_order[cur.u8() % chain.built_order.size()]).tx.serialize();
            raw[cur.u8() % raw.size()] ^= static_cast<std::uint8_t>(1 + cur.u8() % 255);
            records.push_back(std::move(raw));
          } else {
            records.push_back(Bytes{cur.u8(), cur.u8(), cur.u8()});
          }
        }
        run_block(chain, records, sig_mode, long_mode);
        break;
      }
      case 4: {
        const auto k = 1 + cur.u8() % 32;
        for (std::size_t i = 0; i < k; ++i) run_block(chain, {}, sig_mode, long_mode);
        break;
      }
      case 5: {  // past the long-lock grace period, openings withheld
        for (std::size_t i = 0; i <= consensus::kTimedLongGraceBlocks && chain.height < kMaxBlocks; ++i) {
          run_block(chain, {}, SigMode::Valid, LongMode::None);
        }
        break;
      }
      default:
        run_block(chain, {}, sig_mode, long_mode);
        break;
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  run_one(Bytes(data, data + size));
  return 0;
}

#ifndef FINALIS_LIBFUZZER
int main(int argc, char** argv) {
  if (argc > 1) {
    for (int i = 1; i < argc; ++i) {
      std::ifstream in(argv[i], std::ios::binary);
      if (!in.good()) continue;
      Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      run_one(b);
    }
    return 0;
  }
  const char* iters_env = std::getenv("FINALIS_FUZZ_ITERS");
  const char* seed_env = std::getenv("FINALIS_FUZZ_SEED");
  const int iters = iters_env ? std::atoi(iters_env) : 40;
  std::mt19937_64 rng(seed_env ? std::strtoull(seed_env, nullptr, 10) : 0x54494D45ULL);
  std::uniform_int_distribution<int> len_dist(8, 160);
  for (int i = 0; i < iters; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (auto& byte : b) byte = static_cast<std::uint8_t>(rng() & 0xFFu);
    // Bias toward the useful paths: blocks with records, valid signatures and openings.
    for (std::size_t j = 0; j + 1 < b.size(); j += 8) {
      if (rng() % 3 != 0) b[j] = static_cast<std::uint8_t>(rng() % 4);
      if (rng() % 2 != 0) b[j + 1] = 0;
    }
    run_one(b);
  }
  std::cout << "fuzz_timed_execution done inputs=" << g_stats.inputs << " blocks=" << g_stats.blocks
            << " included=" << g_stats.included << " applied=" << g_stats.applied
            << " long_applied=" << g_stats.long_applied << " forfeited=" << g_stats.forfeited
            << " expired=" << g_stats.expired << "\n";
  if (g_stats.included == 0 || g_stats.applied == 0) {
    std::cerr << "fuzz_timed_execution: smoke run reached no inclusion or no applied body\n";
    return 1;
  }
  return 0;
}
#endif
