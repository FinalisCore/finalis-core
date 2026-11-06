// SPDX-License-Identifier: MIT
// finalis-nodetest (apps/finalis-nodetest): network guard, limits, pacing, peers file, wallet file, sweep.

#include "support/test_chain_domain.hpp"
#include "test_framework.hpp"

#include "apps/finalis-nodetest/nodetest_core.hpp"
#include "common/address.hpp"
#include "common/network.hpp"
#include "crypto/confidential.hpp"
#include "genesis/embedded_testnet.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;
using namespace finalis::nodetest;

namespace {

std::string id_hex(const NetworkConfig& n) { return hex_encode(Bytes(n.network_id.begin(), n.network_id.end())); }

lightserver::RpcStatusView testnet_status() {
  lightserver::RpcStatusView s;
  s.chain.network_id_hex = id_hex(testnet_network());
  s.chain.genesis_hash_hex = hex_encode32(genesis::TESTNET_GENESIS_HASH);
  s.established_peer_count = 5;
  s.finalized_lag = 0;
  return s;
}

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

OutPoint op_of(std::uint8_t b, std::uint32_t i = 0) { return OutPoint{filled(b), i}; }

}  // namespace

// Mainnet, a foreign network and a testnet with another genesis are all refused; testnet-3 is not.
TEST(test_nodetest_refuses_mainnet_and_other_chains) {
  ASSERT_TRUE(!refuse_network(testnet_status()).has_value());

  auto main = testnet_status();
  main.chain.network_id_hex = id_hex(mainnet_network());
  const auto r1 = refuse_network(main);
  ASSERT_TRUE(r1.has_value() && r1->find("MAINNET") != std::string::npos);
  // Mainnet with the testnet genesis hash is still mainnet.
  main.chain.genesis_hash_hex = hex_encode32(genesis::TESTNET_GENESIS_HASH);
  ASSERT_TRUE(refuse_network(main).has_value());

  auto other = testnet_status();
  other.chain.network_id_hex = std::string(32, '0');
  ASSERT_TRUE(refuse_network(other).has_value());

  auto old_testnet = testnet_status();
  old_testnet.chain.genesis_hash_hex = std::string(64, 'a');
  ASSERT_TRUE(refuse_network(old_testnet).has_value());

  auto mismatch = testnet_status();
  mismatch.chain_id_ok = false;
  ASSERT_TRUE(refuse_network(mismatch).has_value());
}

TEST(test_nodetest_preflight_needs_synced_connected_node) {
  ASSERT_TRUE(!preflight_problem(testnet_status(), 2).has_value());
  auto syncing = testnet_status();
  syncing.bootstrap_sync_incomplete = true;
  ASSERT_TRUE(preflight_problem(syncing, 2).has_value());
  auto behind = testnet_status();
  behind.finalized_lag = 5;
  ASSERT_TRUE(preflight_problem(behind, 2).has_value());
  auto lonely = testnet_status();
  lonely.established_peer_count = 1;
  ASSERT_TRUE(preflight_problem(lonely, 2).has_value());
  ASSERT_TRUE(!preflight_problem(lonely, 1).has_value());
  auto unknown = testnet_status();
  unknown.established_peer_count.reset();
  ASSERT_TRUE(preflight_problem(unknown, 2).has_value());
  ASSERT_TRUE(!preflight_problem(unknown, 0).has_value());
}

// Rate and duration above the hard limits are refused, not clamped.
TEST(test_nodetest_options_enforce_hard_limits) {
  std::string err;
  auto d = parse_options({}, &err);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(d->command, std::string("run"));
  ASSERT_TRUE(d->rate == kDefaultRate && d->duration_seconds == kDefaultDurationSeconds);
  ASSERT_EQ(d->types.size(), kAllTypes.size());
  ASSERT_TRUE(d->rate * 13 <= 1.5);  // 13 validators at the default stay near the 2026-11-03 test level

  ASSERT_TRUE(parse_options({"--rate", "1"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--rate", "1.01"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--rate", "0"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--rate", "nan"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--rate", "2x"}, &err).has_value());
  ASSERT_TRUE(parse_options({"--duration", std::to_string(kMaxDurationSeconds)}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--duration", std::to_string(kMaxDurationSeconds + 1)}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--duration", "-5"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--rate"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"--bogus", "1"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"launch"}, &err).has_value());

  auto t = parse_options({"sweep", "--types", "std,c2c,std", "--min-peers", "0"}, &err);
  ASSERT_TRUE(t.has_value());
  ASSERT_EQ(t->command, std::string("sweep"));
  ASSERT_EQ(t->types.size(), 2u);
  ASSERT_TRUE(t->types[0] == TxType::Std && t->types[1] == TxType::C2C);
  ASSERT_EQ(t->min_peers, 0u);
  ASSERT_TRUE(!parse_options({"--types", "std,teleport"}, &err).has_value());
  for (const auto ty : kAllTypes) ASSERT_TRUE(parse_type(type_name(ty)) == ty && type_weight(ty) > 0);
}

// One send per interval, no burst after a pause; retryable rejects back off 5, 10, ... 300 s.
TEST(test_nodetest_pacer_rate_and_backoff) {
  Pacer p(0.5, 100.0);
  ASSERT_TRUE(p.due(100.0));
  p.sent(100.0);
  ASSERT_TRUE(!p.due(101.9));
  ASSERT_TRUE(p.due(102.0));
  p.sent(500.0);  // after a long pause: next is one interval later, not a catch-up burst
  ASSERT_EQ(p.next_at(), 502.0);

  p.retryable_reject(502.0);
  ASSERT_EQ(p.backoff_seconds(), kBackoffFirstSeconds);
  ASSERT_EQ(p.next_at(), 507.0);
  p.retryable_reject(507.0);
  ASSERT_EQ(p.backoff_seconds(), 10.0);
  ASSERT_EQ(p.next_at(), 517.0);
  for (int i = 0; i < 10; ++i) p.retryable_reject(1000.0);
  ASSERT_EQ(p.backoff_seconds(), kBackoffMaxSeconds);
  ASSERT_EQ(p.next_at(), 1000.0 + kBackoffMaxSeconds);
  p.accepted();
  ASSERT_EQ(p.backoff_seconds(), 0.0);
  p.retryable_reject(2000.0);
  ASSERT_EQ(p.backoff_seconds(), kBackoffFirstSeconds);

  // A slow rate's interval is longer than the first backoff step: the interval wins.
  Pacer slow(0.1, 0.0);
  slow.retryable_reject(0.0);
  ASSERT_EQ(slow.next_at(), 10.0);
}

TEST(test_nodetest_peers_file) {
  const Wallet mine = Wallet::create(filled(0x01));
  const Wallet other = Wallet::create(filled(0x02));
  const std::string a = other.keys[0].address;
  const std::string b = other.keys[1].address;
  std::string err;
  const std::string text = "# participants\n\n  " + a + "  # alice\n" + b + "\n" + a + "\n" + mine.keys[3].address + "\n";
  auto p = parse_peers(text, mine.addresses(), &err);
  ASSERT_TRUE(p.has_value());
  ASSERT_EQ(p->size(), 2u);  // duplicate and own address skipped
  ASSERT_EQ((*p)[0].address, a);
  ASSERT_TRUE((*p)[0].script_pubkey == other.keys[0].script);

  const auto mainnet_addr = *address::encode_p2pkh("sc", other.keys[0].pkh);
  ASSERT_TRUE(!parse_peers(a + "\n" + mainnet_addr + "\n", mine.addresses(), &err).has_value());
  ASSERT_TRUE(err.find("line 2") != std::string::npos);
  ASSERT_TRUE(!parse_peers("hello\n", mine.addresses(), &err).has_value());
  ASSERT_TRUE(parse_peers("", mine.addresses(), &err)->empty());
}

// Keys derive from the seed alone; the file round-trips confidential coin secrets and spend markers.
TEST(test_nodetest_wallet_file_roundtrip) {
  Wallet w = Wallet::create(filled(0x07));
  ASSERT_EQ(w.keys.size(), kWalletKeys);
  ASSERT_EQ(w.addresses().size(), kWalletKeys);
  for (const auto& k : w.keys) ASSERT_TRUE(k.address.rfind("tsc1", 0) == 0);
  ASSERT_TRUE(Wallet::create(filled(0x07)).keys[5].address == w.keys[5].address);
  ASSERT_TRUE(Wallet::create(filled(0x08)).keys[0].address != w.keys[0].address);

  w.next_request[3] = 17;
  ConfCoin c;
  c.op = op_of(0x42, 1);
  c.amount = 12345;
  c.spend_secret = filled(0x10);
  c.blind = filled(0x11);
  c.commitment.bytes.fill(0x12);
  c.one_time.fill(0x13);
  c.key = 3;
  c.origin_final = true;
  c.spend_txid = filled(0x14);
  w.conf.push_back(c);

  std::string err;
  auto back = Wallet::parse(w.serialize(), &err);
  ASSERT_TRUE(back.has_value());
  ASSERT_EQ(back->serialize(), w.serialize());
  ASSERT_EQ(back->next_request.at(3), 17u);
  ASSERT_TRUE(back->conf.size() == 1 && back->conf[0].spend_txid == filled(0x14) && back->conf[0].origin_final &&
              !back->conf[0].spent && back->conf[0].amount == 12345);

  ASSERT_TRUE(!Wallet::parse("garbage", &err).has_value());
  ASSERT_TRUE(!Wallet::parse("finalis-nodetest-wallet 1\nreq 1 2\n", &err).has_value());  // no seed
  ASSERT_TRUE(!Wallet::parse(w.serialize() + "conf zz\n", &err).has_value());
}

// The sweep moves every coin it is given to the target, minus only fees, in valid transactions:
// plain coins on several keys, an unlocked height lock, an inheritance lock and a confidential coin.
TEST(test_nodetest_sweep_returns_everything_minus_fees) {
  ASSERT_TRUE(crypto::confidential_crypto_init());
  const Wallet w = Wallet::create(filled(0x21));
  const Hash32 domain = test::test_chain_domain();
  const Bytes target = w.keys[0].script;
  const std::uint64_t height = 500;

  std::map<std::uint32_t, std::vector<Coin>> coins;
  coins[0] = {{op_of(0x30), TxOut{24'000'000, w.keys[0].script}},  // two coins on the target key: still merged
              {op_of(0x31), TxOut{1'000'000, height_lock_script_pubkey(400, w.keys[0].pkh)}}};
  coins[1] = {{op_of(0x32), TxOut{5'000'000, w.keys[1].script}},
              {op_of(0x33), TxOut{7'000'000, inheritance_lock_script_pubkey(900, w.keys[1].pkh, w.keys[2].pkh)}}};
  coins[2] = {{op_of(0x34), TxOut{300, w.keys[2].script}}};  // dust: cannot pay its own fee
  UtxoSet view;
  std::uint64_t transparent_in = 0;
  for (const auto& [_, cs] : coins)
    for (const auto& [op, out] : cs) {
      view[op] = UtxoEntry{out};
      transparent_in += out.value;
    }

  // A confidential coin the wallet owns.
  ConfCoin cc;
  cc.op = op_of(0x40);
  cc.amount = 9'000'000;
  cc.spend_secret = filled(0x41);
  cc.blind = filled(0x42);
  const auto commitment = crypto::confidential_amount_commitment(cc.amount, crypto::Blind32{cc.blind});
  const auto one_time = crypto::secp256k1_pubkey_from_scalar(cc.spend_secret);
  const auto ephemeral = crypto::secp256k1_pubkey_from_scalar(filled(0x43));
  ASSERT_TRUE(commitment && one_time && ephemeral);
  cc.commitment = *commitment;
  cc.one_time = *one_time;
  cc.origin_final = true;
  UtxoSetV2 view2;
  for (const auto& [op, e] : view) view2[op] = UtxoEntryV2(e);
  UtxoEntryV2 conf_entry;
  conf_entry.kind = UtxoOutputKind::Confidential;
  conf_entry.body = UtxoConfidentialData{.value_commitment = *commitment,
                                         .one_time_pubkey = *one_time,
                                         .ephemeral_pubkey = *ephemeral,
                                         .scan_tag = crypto::ScanTag{0x44},
                                         .memo = {}};
  view2[cc.op] = conf_entry;

  std::uint64_t dust = 0;
  std::string err;
  const auto sweep = build_sweep(domain, w, coins, {cc}, target, 1, &dust, &err);
  ASSERT_TRUE(err.empty());
  ASSERT_EQ(sweep.size(), 3u);  // key 0, key 1, the confidential coin
  ASSERT_EQ(dust, 300u);

  std::uint64_t in = 0, out = 0, fees = 0;
  ConfidentialPolicy policy;
  auto ctx = test::with_test_chain_identity(SpecialValidationContext{.current_height = height});
  ctx.confidential_policy = &policy;
  for (const auto& s : sweep) {
    ASSERT_EQ(s.input_units, s.output_units + s.fee);
    ASSERT_TRUE(s.fee >= 2'000 && s.fee < 100'000);
    in += s.input_units;
    out += s.output_units;
    fees += s.fee;
    if (const auto* tx = std::get_if<Tx>(&s.tx)) {
      ASSERT_EQ(tx->outputs.size(), 1u);
      ASSERT_TRUE(tx->outputs[0].script_pubkey == target);
      const auto r = validate_tx(*tx, 1, view, &ctx);
      ASSERT_TRUE(r.ok);
      ASSERT_EQ(r.fee, s.fee);
    } else {
      const auto& tx2 = std::get<TxV2>(s.tx);
      ASSERT_EQ(s.conf_inputs.size(), 1u);
      const auto r = validate_tx_v2(tx2, 1, view2, &ctx);
      ASSERT_TRUE(r.ok);
      ASSERT_EQ(r.cost.fee, s.fee);
    }
  }
  ASSERT_EQ(in, transparent_in - 300 + cc.amount);
  ASSERT_EQ(out, in - fees);

  // A single plain coin already at the target is left alone.
  std::map<std::uint32_t, std::vector<Coin>> one;
  one[0] = {{op_of(0x50), TxOut{24'000'000, target}}};
  ASSERT_TRUE(build_sweep(domain, w, one, {}, target, 1, &dust, &err).empty());
}

TEST(test_nodetest_summary_percentiles) {
  ASSERT_EQ(percentile({}, 50), 0.0);
  ASSERT_EQ(percentile({5, 1, 3, 2, 4}, 50), 3.0);
  ASSERT_EQ(percentile({5, 1, 3, 2, 4}, 100), 5.0);
  ASSERT_EQ(percentile({5, 1, 3, 2, 4}, 0), 1.0);
  Summary s;
  s.sent["std"] = 3;
  s.finals["std"] = 2;
  s.rejected["std relay_unavailable"] = 1;
  s.finality_seconds = {200, 400};
  const auto text = s.render();
  ASSERT_TRUE(text.find("accepted 3  final 2  rejected 1") != std::string::npos);
  ASSERT_TRUE(text.find("p50 200") != std::string::npos);
}
