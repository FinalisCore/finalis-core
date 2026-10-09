// SPDX-License-Identifier: MIT
//
// Measures the CPU cost of the work charged by txv2_confidential_verify_weight, to calibrate
// the kConfidential*VerifyWeight constants (validate.hpp) against proof bytes.
//
//   finalis-bench-confidential [iterations] [load_threads]
//
// load_threads > 0 runs that many busy-spinning threads alongside the benchmark (contention /
// thermal / frequency effects). Build with CMAKE_BUILD_TYPE=Release; unoptimized numbers are
// meaningless.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "common/address.hpp"
#include "crypto/confidential.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

crypto::Blind32 blind_from(std::uint32_t seed) {
  crypto::Blind32 out;
  const Bytes pre{'b', static_cast<std::uint8_t>(seed), static_cast<std::uint8_t>(seed >> 8)};
  out.bytes = crypto::sha256(pre);
  return out;
}

Hash32 nonce_from(std::uint32_t seed) {
  const Bytes pre{'n', static_cast<std::uint8_t>(seed), static_cast<std::uint8_t>(seed >> 8)};
  return crypto::sha256(pre);
}

PubKey33 pubkey_from(std::uint32_t seed) {
  auto pk = crypto::secp256k1_pubkey_from_scalar(blind_from(seed + 0x1000).bytes);
  if (!pk) throw std::runtime_error("pubkey");
  return *pk;
}

crypto::KeyPair ed_key(std::uint8_t seed) {
  std::array<std::uint8_t, 32> s{};
  s.fill(seed);
  auto kp = crypto::keypair_from_seed32(s);
  if (!kp) throw std::runtime_error("ed25519 key");
  return *kp;
}

Bytes p2pkh_script_sig(const Sig64& sig, const PubKey32& pub) {
  Bytes ss;
  ss.push_back(0x40);
  ss.insert(ss.end(), sig.begin(), sig.end());
  ss.push_back(0x20);
  ss.insert(ss.end(), pub.begin(), pub.end());
  return ss;
}

void sign_balance(TxV2& tx, const crypto::Blind32& excess_blind) {
  auto pub = crypto::excess_xonly_pubkey_from_scalar(excess_blind);
  if (!pub) throw std::runtime_error("excess pubkey");
  tx.balance_proof.excess_pubkey = *pub;
  tx.balance_proof.excess_sig.fill(0);
  auto msg = balance_proof_message_v2(tx);
  auto sig = crypto::sign_excess_authorization(*msg, excess_blind, nonce_from(0xEE));
  if (!sig) throw std::runtime_error("excess sig");
  tx.balance_proof.excess_sig = *sig;
}

struct Fixture {
  TxV2 tx;
  UtxoSetV2 view;
};

// One transparent input funding n confidential outputs (wallet T->C shape, n=1).
Fixture make_t_to_c(std::size_t n_outputs) {
  const auto from = ed_key(0x27);
  const auto from_pkh = crypto::h160(Bytes(from.public_key.begin(), from.public_key.end()));
  const std::uint64_t per_output = 1'000;
  const std::uint64_t fee = 500;
  const std::uint64_t value_in = per_output * n_outputs + fee;
  Fixture f;
  OutPoint op{};
  op.txid.fill(0x47);
  f.view[op] = UtxoEntryV2(TxOut{value_in, address::p2pkh_script_pubkey(from_pkh)});
  f.tx.inputs.push_back(TxInV2{.prev_txid = op.txid, .prev_index = 0, .sequence = 0xFFFFFFFF,
                               .kind = TxInputKind::Transparent, .witness = TransparentInputWitnessV2{}});
  std::vector<crypto::Blind32> blinds;
  for (std::size_t i = 0; i < n_outputs; ++i) {
    const auto blind = blind_from(static_cast<std::uint32_t>(i + 1));
    blinds.push_back(blind);
    auto commitment = crypto::confidential_amount_commitment(per_output, blind);
    auto proof = crypto::sign_output_range_proof(*commitment, per_output, blind, nonce_from(static_cast<std::uint32_t>(i)));
    if (!commitment || !proof) throw std::runtime_error("output proof");
    f.tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Confidential,
                                   .body = ConfidentialTxOutV2{.value_commitment = *commitment,
                                                               .one_time_pubkey = pubkey_from(static_cast<std::uint32_t>(2 * i)),
                                                               .ephemeral_pubkey = pubkey_from(static_cast<std::uint32_t>(2 * i + 1)),
                                                               .scan_tag = crypto::ScanTag{0x01},
                                                               .range_proof = *proof,
                                                               .memo = Bytes(72, 0xAB)}});
  }
  f.tx.fee = fee;
  auto excess_blind = crypto::combine_blinds(blinds, 0);
  auto excess = crypto::confidential_amount_commitment(0, *excess_blind);
  f.tx.balance_proof.excess_commitment = *excess;
  sign_balance(f.tx, *excess_blind);
  auto msg = signing_message_for_input_v2(f.tx, 0);
  auto sig = crypto::ed25519_sign(*msg, from.private_key);
  std::get<TransparentInputWitnessV2>(f.tx.inputs[0].witness).script_sig = p2pkh_script_sig(*sig, from.public_key);
  return f;
}

// n confidential inputs spent to one transparent output (wallet C->T shape, n=1).
Fixture make_c_to_t(std::size_t n_inputs) {
  const auto to = ed_key(0x34);
  const std::uint64_t per_input = 10'000;
  const std::uint64_t fee = 500;
  Fixture f;
  std::vector<crypto::Blind32> spend_secrets;
  std::vector<crypto::Blind32> value_blinds;
  for (std::size_t i = 0; i < n_inputs; ++i) {
    const auto spend = blind_from(static_cast<std::uint32_t>(0x100 + i));
    const auto vblind = blind_from(static_cast<std::uint32_t>(0x200 + i));
    spend_secrets.push_back(spend);
    value_blinds.push_back(vblind);
    OutPoint op{};
    op.txid.fill(0x5B);
    op.index = static_cast<std::uint32_t>(i);
    UtxoEntryV2 entry;
    entry.kind = UtxoOutputKind::Confidential;
    entry.body = UtxoConfidentialData{.value_commitment = *crypto::confidential_amount_commitment(per_input, vblind),
                                      .one_time_pubkey = *crypto::secp256k1_pubkey_from_scalar(spend.bytes),
                                      .ephemeral_pubkey = pubkey_from(static_cast<std::uint32_t>(0x300 + i)),
                                      .scan_tag = crypto::ScanTag{0x02},
                                      .memo = Bytes{0x01}};
    f.view[op] = entry;
    f.tx.inputs.push_back(TxInV2{.prev_txid = op.txid, .prev_index = op.index, .sequence = 0xFFFFFFFF,
                                 .kind = TxInputKind::Confidential,
                                 .witness = ConfidentialInputWitnessV2{*crypto::secp256k1_pubkey_from_scalar(spend.bytes), Sig64{}}});
  }
  const auto to_pkh = crypto::h160(Bytes(to.public_key.begin(), to.public_key.end()));
  f.tx.outputs.push_back(TxOutV2{.kind = TxOutputKind::Transparent,
                                 .body = TransparentTxOutV2{per_input * n_inputs - fee, address::p2pkh_script_pubkey(to_pkh)}});
  f.tx.fee = fee;
  auto excess_blind = crypto::combine_blinds(value_blinds, value_blinds.size());
  f.tx.balance_proof.excess_commitment = *crypto::confidential_amount_commitment(0, *excess_blind);
  sign_balance(f.tx, *excess_blind);
  for (std::size_t i = 0; i < n_inputs; ++i) {
    auto msg = signing_message_for_input_v2(f.tx, static_cast<std::uint32_t>(i));
    Hash32 msg32{};
    std::copy(msg->begin(), msg->end(), msg32.begin());
    auto sig = crypto::sign_schnorr_authorization(msg32, spend_secrets[i], nonce_from(0x400 + static_cast<std::uint32_t>(i)));
    std::get<ConfidentialInputWitnessV2>(f.tx.inputs[i].witness).spend_sig = *sig;
  }
  return f;
}

// Median of `rounds` timings, each the mean over `iters` calls. Returns ns/op.
double bench(const std::function<void()>& fn, int iters, int rounds = 7) {
  for (int i = 0; i < std::max(1, iters / 10); ++i) fn();  // warm-up
  std::vector<double> samples;
  for (int r = 0; r < rounds; ++r) {
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < iters; ++i) fn();
    const auto t1 = std::chrono::steady_clock::now();
    samples.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / iters);
  }
  std::sort(samples.begin(), samples.end());
  return samples[samples.size() / 2];
}

void require(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(std::string("bench precondition failed: ") + what);
}

}  // namespace

int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 200;
  const int load_threads = argc > 2 ? std::atoi(argv[2]) : 0;
  if (!crypto::confidential_backend_status().confidential_outputs_supported) {
    std::fprintf(stderr, "zkp backend unavailable\n");
    return 1;
  }
  std::atomic<bool> stop{false};
  std::vector<std::thread> load;
  for (int i = 0; i < load_threads; ++i) {
    load.emplace_back([&] {
      volatile std::uint64_t x = 0;
      while (!stop.load(std::memory_order_relaxed)) x = x * 6364136223846793005ULL + 1;
    });
  }

  ConfidentialPolicy policy;
  SpecialValidationContext ctx;
  ctx.current_height = 100;
  ctx.confidential_policy = &policy;

  // Primitive fixtures.
  const auto blind = blind_from(7);
  const auto commitment = *crypto::confidential_amount_commitment(123'456, blind);
  const auto proof = *crypto::sign_output_range_proof(commitment, 123'456, blind, nonce_from(7));
  require(crypto::verify_output_range_proof(commitment, proof), "range proof");
  const auto secret = blind_from(9);
  const auto pub33 = *crypto::secp256k1_pubkey_from_scalar(secret.bytes);
  Hash32 msg{};
  msg.fill(0x42);
  const auto schnorr = *crypto::sign_schnorr_authorization(msg, secret, nonce_from(9));
  require(crypto::verify_schnorr_authorization(msg, pub33, schnorr), "schnorr");
  const auto excess = *crypto::confidential_amount_commitment(0, secret);
  const auto excess_x = *crypto::excess_xonly_pubkey_from_scalar(secret);
  const auto excess_sig = *crypto::sign_excess_authorization(msg, secret, nonce_from(10));
  require(crypto::verify_excess_authorization(msg, excess, excess_x, excess_sig), "excess");
  // Tally shaped like a 1-in / 1-out T->C: [transparent_in] == [conf_out, fee, excess].
  const auto b_out = blind_from(11);
  const auto c_out = *crypto::confidential_amount_commitment(9'500, b_out);
  const auto neg_b = *crypto::combine_blinds(std::span<const crypto::Blind32>(&b_out, 1), 0);
  const std::vector<crypto::Commitment33> pos{crypto::transparent_amount_commitment(10'000)};
  const std::vector<crypto::Commitment33> neg{c_out, crypto::transparent_amount_commitment(500),
                                              *crypto::confidential_amount_commitment(0, neg_b)};
  require(crypto::verify_commitment_tally(pos, neg), "tally");
  const auto ed = ed_key(0x11);
  const Bytes ed_msg(32, 0x42);
  const auto ed_sig = *crypto::ed25519_sign(ed_msg, ed.private_key);

  std::printf("# iters=%d load_threads=%d hw_threads=%u\n", iters, load_threads, std::thread::hardware_concurrency());
  std::printf("# canonical range proof bytes = %zu\n", proof.bytes.size());
  std::printf("%-46s %12s %10s %12s\n", "operation", "us/op", "weight", "ns/weight");
  auto row = [](const char* name, double ns, std::uint64_t weight) {
    std::printf("%-46s %12.2f %10llu %12s\n", name, ns / 1000.0, static_cast<unsigned long long>(weight),
                weight ? std::to_string(ns / static_cast<double>(weight)).substr(0, 6).c_str() : "-");
  };

  row("rangeproof verify (canonical 64-bit)",
      bench([&] { (void)crypto::verify_output_range_proof(commitment, proof); }, iters), proof.bytes.size());
  row("schnorr verify (confidential input)",
      bench([&] { (void)crypto::verify_schnorr_authorization(msg, pub33, schnorr); }, iters * 20),
      kConfidentialSignatureVerifyWeight);
  row("schnorr verify (excess, incl. canonical checks)",
      bench([&] { (void)crypto::verify_excess_authorization(msg, excess, excess_x, excess_sig); }, iters * 20),
      kConfidentialSignatureVerifyWeight);
  row("commitment tally (1 pos / 3 neg)",
      bench([&] { (void)crypto::verify_commitment_tally(pos, neg); }, iters * 20), 0);
  row("transparent_amount_commitment (fee)",
      bench([&] { (void)crypto::transparent_amount_commitment(500); }, iters * 20), 0);
  row("ed25519 verify (transparent input, unweighted)",
      bench([&] { (void)crypto::ed25519_verify(ed_msg, ed_sig, ed.public_key); }, iters * 20), 0);

  struct Shape {
    const char* name;
    Fixture f;
  };
  std::vector<Shape> shapes;
  shapes.push_back({"full T->C 1 in / 1 conf out", make_t_to_c(1)});
  shapes.push_back({"full T->C 1 in / 4 conf out", make_t_to_c(4)});
  shapes.push_back({"full T->C 1 in / 12 conf out (max by proof bytes)", make_t_to_c(12)});
  shapes.push_back({"full C->T 1 conf in / 1 out", make_c_to_t(1)});
  shapes.push_back({"full C->T 16 conf in / 1 out (max)", make_c_to_t(16)});
  for (auto& s : shapes) {
    const Bytes raw = s.f.tx.serialize();
    auto check = validate_tx_v2(s.f.tx, 1, s.f.view, &ctx);
    if (!check.ok) throw std::runtime_error(std::string(s.name) + ": " + check.error);
    const auto weight = txv2_confidential_verify_weight(s.f.tx);
    const int n = std::max(5, iters / static_cast<int>(1 + weight / 2000));
    row(s.name,
        bench(
            [&] {
              auto any = parse_any_tx(raw);
              (void)validate_tx_v2(std::get<TxV2>(*any), 1, s.f.view, &ctx);
            },
            n),
        weight);
  }
  row("parse only (T->C 1/1)", bench([&] { (void)parse_any_tx(shapes[0].f.tx.serialize()); }, iters * 20), 0);

  stop = true;
  for (auto& t : load) t.join();
  return 0;
}
