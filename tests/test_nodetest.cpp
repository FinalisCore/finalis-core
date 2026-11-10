// SPDX-License-Identifier: MIT
// finalis-nodetest (apps/finalis-nodetest): network guard, limits, pacing, peers file, wallet file, sweep.

#include "support/test_chain_domain.hpp"
#include "test_framework.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

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
  ASSERT_TRUE(text.find("funding limit") == std::string::npos);  // no starved slots, no funding note
}

// Feedback 2026-11-10: no-coin slots looked like a network problem; the summary says where the coins were.
TEST(test_nodetest_summary_explains_no_coin_slots) {
  Summary s;
  s.starved = 2;
  s.starved_coins = {CoinPicture{10'000'000, 300'000'000, 100'000'000, 200'000'000},
                     CoinPicture{30'000'000, 100'000'000, 100'000'000, 200'000'000}};
  const auto text = s.render();
  ASSERT_TRUE(text.find("never-final 0  no-coin slots 2\n") != std::string::npos);  // headline count kept
  ASSERT_TRUE(text.find("a funding limit, not a network problem") != std::string::npos);
  ASSERT_TRUE(text.find("spendable 0.20  in flight 2.00  held by timed sends 1.00  height-locked 2.00") !=
              std::string::npos);
  ASSERT_TRUE(text.find("leave the locking types out of --types") != std::string::npos);
  ASSERT_TRUE(text.find("hlock, inherit: height-locked") != std::string::npos);
}

// --start-at takes exactly one UTC form, so every participant reads the same instant.
TEST(test_nodetest_start_at_parses_utc_only) {
  ASSERT_TRUE(parse_utc_time("2026-11-14T08:00:00Z") == std::optional<std::int64_t>(1794643200));
  ASSERT_TRUE(parse_utc_time("2028-02-29T23:59:59Z") == std::optional<std::int64_t>(1835481599));  // leap day
  ASSERT_EQ(format_utc_time(1794643200), std::string("2026-11-14T08:00:00Z"));
  ASSERT_EQ(format_utc_time(1835481599), std::string("2028-02-29T23:59:59Z"));
  for (const char* bad : {"2026-11-14T08:00:00", "2026-11-14T08:00:00+02:00", "2026-11-14 08:00:00Z",
                          "2026-11-14T08:00Z", "2026-02-29T08:00:00Z", "2026-13-01T08:00:00Z", "2026-11-31T08:00:00Z",
                          "2026-11-14T24:00:00Z", "2026-11-14T08:60:00Z", "2026-11-14T08:00:00.5Z", "tomorrow", ""}) {
    ASSERT_TRUE(!parse_utc_time(bad).has_value());
  }
  std::string err;
  auto o = parse_options({"--start-at", "2026-11-14T08:00:00Z", "--allow-late"}, &err);
  ASSERT_TRUE(o.has_value() && o->start_at_unix == std::optional<std::int64_t>(1794643200) && o->allow_late);
  ASSERT_TRUE(!parse_options({"--start-at", "2026-11-14T08:00:00"}, &err).has_value());
  ASSERT_TRUE(err.find("UTC") != std::string::npos);
  ASSERT_TRUE(!parse_options({}, &err)->start_at_unix.has_value());
}

// Wait before the start, start within the late cut-off, refuse after it (unless --allow-late) and
// refuse a start more than 14 days ahead.
TEST(test_nodetest_start_at_decision) {
  const std::int64_t t = 1794643200;
  ASSERT_TRUE(start_decision(t - 3600, t, false) == StartDecision::Wait);
  ASSERT_TRUE(start_decision(t - 1, t, false) == StartDecision::Wait);
  ASSERT_TRUE(start_decision(t, t, false) == StartDecision::Start);
  ASSERT_TRUE(start_decision(t + kLateStartSeconds, t, false) == StartDecision::Start);
  ASSERT_TRUE(start_decision(t + kLateStartSeconds + 1, t, false) == StartDecision::TooLate);
  ASSERT_TRUE(start_decision(t + kLateStartSeconds + 1, t, true) == StartDecision::Start);
  ASSERT_TRUE(start_decision(t - kMaxStartAheadSeconds, t, false) == StartDecision::Wait);
  ASSERT_TRUE(start_decision(t - kMaxStartAheadSeconds - 1, t, false) == StartDecision::TooFar);
}

// The wallet directory must not depend on the machine's shell setup or the directory the tool is
// started from: with HOME unset it used to land in "./~/.finalis-nodetest" (a new, empty wallet per
// working directory). The help text shows "~/...", not the local user's home path.
TEST(test_nodetest_state_dir_is_absolute_and_home_independent) {
  namespace fs = std::filesystem;
  std::string err;
  const char* old_home_c = std::getenv("HOME");
  const std::string old_home = old_home_c ? old_home_c : "";
  const auto restore = [&]() {
#ifdef _WIN32
    _putenv_s("HOME", old_home.c_str());
#else
    if (old_home_c) ::setenv("HOME", old_home.c_str(), 1); else ::unsetenv("HOME");
#endif
  };

  const fs::path fake_home = fs::temp_directory_path() / "finalis_nodetest_home";
#ifdef _WIN32
  _putenv_s("HOME", fake_home.string().c_str());
#else
  ::setenv("HOME", fake_home.string().c_str(), 1);
#endif
  auto d = resolve_state_dir("~/.finalis-nodetest", &err);
  ASSERT_TRUE(d.has_value());
  ASSERT_TRUE(fs::path(*d) == (fake_home / ".finalis-nodetest").lexically_normal());
  auto parsed = parse_options({"address"}, &err);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_TRUE(fs::path(parsed->dir) == (fake_home / ".finalis-nodetest").lexically_normal());
  ASSERT_TRUE(usage_text().find("(default ~/.finalis-nodetest)") != std::string::npos);
  ASSERT_TRUE(usage_text().find(fake_home.string()) == std::string::npos);

#ifndef _WIN32
  ::unsetenv("HOME");
  auto nohome = resolve_state_dir("~/.finalis-nodetest", &err);
  if (nohome) {  // the password database knows this account's home
    ASSERT_TRUE(fs::path(*nohome).is_absolute());
    ASSERT_TRUE(nohome->find('~') == std::string::npos);
  } else {
    ASSERT_TRUE(err.find("--dir") != std::string::npos);  // refused with a hint, never relative
  }
#endif
  restore();

  auto rel = resolve_state_dir("nodetest-rel/w", &err);
  ASSERT_TRUE(rel.has_value());
  ASSERT_TRUE(fs::path(*rel).is_absolute());
  ASSERT_TRUE(fs::path(*rel) == (fs::current_path() / "nodetest-rel" / "w").lexically_normal());
  ASSERT_TRUE(!resolve_state_dir("~bob/w", &err).has_value());
  ASSERT_TRUE(!resolve_state_dir("", &err).has_value());
  ASSERT_TRUE(!parse_options({"--dir", ""}, &err).has_value());
  ASSERT_TRUE(parse_options({"--help"}, &err).has_value());  // help needs no directory
}

namespace {
std::string schedule_json(const std::string& windows, const std::string& genesis = "") {
  return std::string("{\"version\":1,\"network\":\"testnet\",\"genesis_hash\":\"") +
         (genesis.empty() ? hex_encode32(genesis::TESTNET_GENESIS_HASH) : genesis) + "\",\"windows\":[" + windows + "]}";
}
}  // namespace

// `auto` reads its test windows from a published file; anything off about it refuses the whole file.
TEST(test_nodetest_schedule_parse_and_refusals) {
  std::string err;
  auto ok = parse_schedule(schedule_json(R"({"start":"2026-11-09T08:00:00Z"},)"
                                         R"({"start":"2026-11-08T08:00:00Z","duration_seconds":600,"rate":0.25})"),
                           &err);
  ASSERT_TRUE(ok.has_value());
  ASSERT_EQ(ok->size(), 2u);
  ASSERT_EQ((*ok)[0].start_unix, *parse_utc_time("2026-11-08T08:00:00Z"));  // sorted
  ASSERT_EQ((*ok)[0].duration_seconds, 600u);
  ASSERT_TRUE((*ok)[0].rate == 0.25);
  ASSERT_TRUE((*ok)[1].rate == kDefaultRate && (*ok)[1].duration_seconds == kDefaultDurationSeconds);
  ASSERT_TRUE(parse_schedule(schedule_json(""), &err).has_value());  // no windows yet is fine

  const auto refused = [&](const std::string& json) { return !parse_schedule(json, &err).has_value(); };
  ASSERT_TRUE(refused("not json"));
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z"})", std::string(64, 'a'))));  // other chain
  ASSERT_TRUE(err.find("genesis_hash") != std::string::npos);
  ASSERT_TRUE(refused(R"({"version":2,"network":"testnet","windows":[]})"));
  ASSERT_TRUE(refused(std::string(R"({"version":1,"network":"mainnet","genesis_hash":")") +
                      hex_encode32(genesis::TESTNET_GENESIS_HASH) + R"(","windows":[]})"));
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08 08:00"})")));
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z","rate":1.5})")));      // above the hard limit
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z","rate":0})")));
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z","rate":"0.1"})")));
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z","duration_seconds":14401})")));
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z","duration_seconds":30})")));
  // Overlap: the next window starts before the previous one's run + drain + sweep is over.
  ASSERT_TRUE(refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z"},{"start":"2026-11-08T08:40:00Z"})")));
  ASSERT_TRUE(err.find("overlap") != std::string::npos);
  ASSERT_TRUE(!refused(schedule_json(R"({"start":"2026-11-08T08:00:00Z"},{"start":"2026-11-08T09:00:00Z"})")));
  std::string many;
  for (int i = 0; i <= static_cast<int>(kMaxScheduleWindows); ++i)
    many += std::string(i ? "," : "") + "{\"start\":\"" + format_utc_time(1'800'000'000 + i * 86400) + "\"}";
  ASSERT_TRUE(refused(schedule_json(many)));

  // The file the release ships with must parse in this build.
  std::ifstream f(std::string(FINALIS_SOURCE_DIR) + "/testnet/NODETEST_SCHEDULE.json", std::ios::binary);
  ASSERT_TRUE(static_cast<bool>(f));
  std::stringstream ss;
  ss << f.rdbuf();
  auto repo = parse_schedule(ss.str(), &err);
  if (!repo) throw std::runtime_error(err);
  ASSERT_TRUE(!repo->empty());
}

TEST(test_nodetest_next_window_and_ceilings) {
  const std::int64_t t0 = *parse_utc_time("2026-11-08T08:00:00Z");
  const std::vector<ScheduleWindow> ws{{t0, 1800, 0.1}, {t0 + 86400, 1800, 0.5}};
  ASSERT_EQ(next_window(ws, t0 - 3600, 0)->start_unix, t0);
  ASSERT_EQ(next_window(ws, t0 + kLateStartSeconds, 0)->start_unix, t0);           // still joinable
  ASSERT_EQ(next_window(ws, t0 + kLateStartSeconds + 1, 0)->start_unix, t0 + 86400);  // too late: the next one
  ASSERT_EQ(next_window(ws, t0 - 3600, t0)->start_unix, t0 + 86400);                // already run
  ASSERT_TRUE(!next_window(ws, t0 + 86400 + kLateStartSeconds + 1, 0).has_value());
  ASSERT_TRUE(!next_window(ws, t0 - kMaxStartAheadSeconds - 1, 0).has_value());     // too far ahead

  std::string err;
  auto o = parse_options({"auto", "--rate", "0.2", "--duration", "600"}, &err);
  ASSERT_TRUE(o.has_value() && o->rate_set && o->duration_set);
  const auto w = apply_ceilings(ws[1], *o);
  ASSERT_TRUE(w.rate == 0.2 && w.duration_seconds == 600u);
  auto plain = parse_options({"auto"}, &err);
  ASSERT_TRUE(plain.has_value() && plain->schedule_url == std::string(kDefaultScheduleUrl));
  const auto same = apply_ceilings(ws[1], *plain);
  ASSERT_TRUE(same.rate == 0.5 && same.duration_seconds == 1800u);
  ASSERT_TRUE(!parse_options({"auto", "--start-at", "2026-11-08T08:00:00Z"}, &err).has_value());
  ASSERT_TRUE(!parse_options({"auto", "--schedule-url", "ftp://x/y"}, &err).has_value());
  auto file = parse_options({"auto", "--schedule", "/tmp/s.json"}, &err);
  ASSERT_TRUE(file.has_value() && file->schedule_file == "/tmp/s.json");
}

// Run 1 (2026-11-07): every lock sent late in the epoch unlocked at its last block, 16 settled there
// (kMaxTimedEscrowsPerUnlockHeight) and 20 expired. Unlocks now spread, and none is chosen too close
// to the epoch end.
TEST(test_nodetest_lock_unlock_heights_spread) {
  const std::uint64_t epoch_end = 4160;
  std::set<std::uint64_t> seen;
  for (std::uint64_t r = 0; r < 1000; ++r) {
    const std::uint64_t next = 4140 + r % 15;
    auto u = short_lock_unlock(next, epoch_end, r * 2654435761u);
    ASSERT_TRUE(u.has_value());
    ASSERT_TRUE(*u >= next + kShortLockMinLead && *u <= std::min(epoch_end, next + kShortLockMaxLead));
    seen.insert(*u);
  }
  ASSERT_TRUE(seen.size() >= 15);
  // Close to the end: still spread over what is left, then no short lock at all.
  std::set<std::uint64_t> late;
  for (std::uint64_t r = 0; r < 100; ++r) late.insert(*short_lock_unlock(4152, epoch_end, r));
  ASSERT_EQ(late.size(), 6u);  // 4155..4160
  ASSERT_TRUE(short_lock_unlock(epoch_end - kShortLockMinLead, epoch_end, 7).has_value());
  ASSERT_TRUE(!short_lock_unlock(epoch_end - kShortLockMinLead + 1, epoch_end, 7).has_value());
  // Long locks: in the first half of the next epoch, not all at one height.
  std::set<std::uint64_t> longs;
  for (std::uint64_t r = 0; r < 200; ++r) {
    const auto u = long_lock_unlock(epoch_end, 32, r);
    ASSERT_TRUE(u >= epoch_end + kLongLockMinLead && u < epoch_end + kLongLockMinLead + 16);
    longs.insert(u);
  }
  ASSERT_EQ(longs.size(), 16u);
}

// The schedule download: only a 200 with the file itself counts.
TEST(test_http_get_body_status_and_chunked) {
  std::string err;
  auto plain = lightserver::http_get_body("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", 1024, &err);
  ASSERT_TRUE(plain.has_value() && *plain == "{}");
  auto chunked = lightserver::http_get_body(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n", 1024, &err);
  ASSERT_TRUE(chunked.has_value() && *chunked == "{\"a\":1}");
  ASSERT_TRUE(!lightserver::http_get_body("HTTP/1.1 404 Not Found\r\n\r\nnope", 1024, &err).has_value());
  ASSERT_TRUE(err.find("404") != std::string::npos);
  ASSERT_TRUE(!lightserver::http_get_body("HTTP/1.1 301 Moved\r\nLocation: http://x/\r\n\r\n", 1024, &err).has_value());
  ASSERT_TRUE(!lightserver::http_get_body("HTTP/1.1 200 OK\r\n\r\n" + std::string(2000, 'x'), 1024, &err).has_value());
  ASSERT_TRUE(!lightserver::http_get_body(
                   "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort", 1024, &err)
                   .has_value());
  ASSERT_TRUE(!lightserver::http_get_body("garbage", 1024, &err).has_value());
}
