// SPDX-License-Identifier: MIT
//
// Measures the McFly SWE work of time-locked transactions (crypto/swe.hpp, swe_proofs.hpp) per
// committee size, and the worst-case time-lock work of one block: kMaxTimedTxPerBlock inclusions
// (well-formedness proof checks) plus the settlements a block can carry (one short-lock unlock
// height's kMaxTimedEscrowsPerUnlockHeight escrows and kMaxLongSettlementsPerBlock long ones, each
// one decryption).
//
//   finalis-bench-swe [iterations]
//
// Build with CMAKE_BUILD_TYPE=Release; unoptimized numbers are meaningless.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>

#include "consensus/canonical_derivation.hpp"
#include "consensus/frontier_execution.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/swe.hpp"
#include "crypto/swe_proofs.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

struct Committee {
  std::vector<crypto::BlsSecretKey> sks;
  std::vector<crypto::BlsPublicKey> pks;
};

Committee make_committee(std::size_t n) {
  Committee c;
  for (std::size_t i = 0; i < n; ++i) {
    Bytes seed(32, 0);
    seed[0] = static_cast<std::uint8_t>(i);
    seed[1] = static_cast<std::uint8_t>(i >> 8);
    seed[2] = 0x5e;
    const auto sk = crypto::bls_key_from_validator_seed(seed);
    if (!sk) throw std::runtime_error("bls key derivation failed");
    c.sks.push_back(*sk);
    c.pks.push_back(*crypto::bls_public_key(*sk));
  }
  return c;
}

// Median of `iterations` runs of fn, in milliseconds.
template <class Fn>
double median_ms(int iterations, Fn&& fn) {
  std::vector<double> runs;
  for (int i = 0; i < iterations; ++i) {
    const auto start = Clock::now();
    fn();
    runs.push_back(ms_since(start));
  }
  std::sort(runs.begin(), runs.end());
  return runs[runs.size() / 2];
}

}  // namespace

int main(int argc, char** argv) {
  const int iterations = argc > 1 ? std::max(1, std::atoi(argv[1])) : 5;
  const Bytes msg = time_signature_message(Hash32{}, 1'000);
  Hash32 key{};
  key.fill(0x4b);
  Hash32 seed{};
  seed.fill(0x53);
  (void)crypto::swe_gt_dlog(crypto::swe_gt_pow(1));  // builds the baby-step table once

  std::printf("%5s %5s %10s %10s %10s %10s %12s %16s\n", "n", "t", "enc_ms", "prove_ms", "verify_ms", "decrypt_ms",
              "envelope_B", "worst_block_ms");
  for (const std::size_t n : {4, 16, 32, 64, 128}) {
    if (n > MAX_COMMITTEE) continue;
    const auto c = make_committee(n);
    const auto t = static_cast<std::uint32_t>(consensus::time_signature_threshold(n));
    std::optional<crypto::SweCiphertext> ct;
    const double enc = median_ms(iterations, [&] {
      ct = crypto::swe_encrypt(c.pks, t, msg, crypto::kBlsTimeSignatureDst, crypto::swe_key_to_chunks(key), seed);
    });
    if (!ct) throw std::runtime_error("swe_encrypt failed");
    std::optional<crypto::SweWellFormednessProof> proof;
    const double prove = median_ms(iterations, [&] {
      proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, crypto::kBlsTimeSignatureDst, seed);
    });
    if (!proof) throw std::runtime_error("swe_prove_well_formed failed");
    bool ok = true;
    const double verify = median_ms(iterations, [&] {
      ok = ok && crypto::swe_verify_well_formed(*ct, c.pks, msg, crypto::kBlsTimeSignatureDst, *proof);
    });
    std::vector<crypto::BlsPublicKey> signers(c.pks.begin(), c.pks.begin() + t);
    std::vector<crypto::BlsSignature> sigs;
    for (std::uint32_t i = 0; i < t; ++i) sigs.push_back(*crypto::bls_sign(c.sks[i], msg, crypto::kBlsTimeSignatureDst));
    const auto aggregate = crypto::mcfly_aggregate(signers, sigs);
    if (!aggregate) throw std::runtime_error("mcfly_aggregate failed");
    const double decrypt = median_ms(iterations, [&] {
      const auto chunks = crypto::swe_decrypt(*ct, c.pks, signers, *aggregate, msg, crypto::kBlsTimeSignatureDst);
      ok = ok && chunks && crypto::swe_key_from_chunks(*chunks) == key;
    });
    if (!ok) throw std::runtime_error("verify or decrypt failed");
    const std::size_t settlements = consensus::kMaxTimedEscrowsPerUnlockHeight + consensus::kMaxLongSettlementsPerBlock;
    const double worst_block = consensus::kMaxTimedTxPerBlock * verify + settlements * decrypt;
    std::printf("%5zu %5u %10.1f %10.1f %10.1f %10.1f %12zu %16.0f\n", n, t, enc, prove, verify, decrypt,
                timed_envelope_bytes_bound(n, 256), worst_block);
  }
  std::printf("worst_block_ms = %zu x verify + (%zu short + %zu long) x decrypt; envelope_B for a 256-byte body\n",
              consensus::kMaxTimedTxPerBlock, consensus::kMaxTimedEscrowsPerUnlockHeight,
              consensus::kMaxLongSettlementsPerBlock);
  return 0;
}
