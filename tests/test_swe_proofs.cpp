// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <chrono>
#include <iostream>

#include "consensus/validator_registry.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/hash.hpp"
#include "crypto/swe.hpp"
#include "crypto/swe_proofs.hpp"

using namespace finalis;

namespace {

struct Committee {
  std::vector<crypto::BlsSecretKey> sks;
  std::vector<crypto::BlsPublicKey> pks;
};

Committee make_committee(std::size_t n, std::uint8_t tag) {
  Committee c;
  for (std::size_t i = 0; i < n; ++i) {
    Bytes ikm(32, tag);
    ikm[0] = static_cast<std::uint8_t>(i);
    ikm[1] = static_cast<std::uint8_t>(i >> 8);
    auto sk = crypto::bls_keygen(ikm);
    ASSERT_TRUE(sk.has_value());
    c.pks.push_back(*crypto::bls_public_key(*sk));
    c.sks.push_back(*sk);
  }
  return c;
}

Bytes time_message(std::uint64_t height) {
  Bytes m{'F', 'I', 'N', 'A', 'L', 'I', 'S', '/', 't', 'i', 'm', 'e', '/', 'v', '1'};
  for (int s = 56; s >= 0; s -= 8) m.push_back(static_cast<std::uint8_t>(height >> s));
  return m;
}

Hash32 seed_of(std::uint8_t b) {
  Hash32 s{};
  s.fill(b);
  return s;
}

std::optional<std::vector<std::uint32_t>> decrypt_with(const crypto::SweCiphertext& ct, const Committee& c,
                                                       const std::vector<std::size_t>& who, const Bytes& msg) {
  std::vector<crypto::BlsPublicKey> pks;
  std::vector<crypto::BlsSignature> sigs;
  for (const auto i : who) {
    pks.push_back(c.pks[i]);
    sigs.push_back(*crypto::bls_sign(c.sks[i], msg, crypto::kBlsTimeSignatureDst));
  }
  const auto agg = crypto::mcfly_aggregate(pks, sigs);
  ASSERT_TRUE(agg.has_value());
  return crypto::swe_decrypt(ct, c.pks, pks, *agg, msg, crypto::kBlsTimeSignatureDst);
}

constexpr auto kDst = crypto::kBlsTimeSignatureDst;

}  // namespace

TEST(test_swe_well_formedness_proof_accepts_honest_ciphertexts) {
  const auto msg = time_message(77);
  for (const auto& [n, t] : std::vector<std::pair<std::size_t, std::uint32_t>>{{1, 1}, {4, 3}, {7, 5}, {7, 7}, {10, 7}}) {
    const auto c = make_committee(n, static_cast<std::uint8_t>(0x10 + n));
    const auto ct = crypto::swe_encrypt(c.pks, t, msg, kDst, {1, 2, 3, 4}, seed_of(static_cast<std::uint8_t>(n)));
    ASSERT_TRUE(ct.has_value());
    const auto proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(static_cast<std::uint8_t>(n)));
    ASSERT_TRUE(proof.has_value());
    ASSERT_TRUE(crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, *proof));
    const auto wire = proof->serialize();
    ASSERT_EQ(wire.size(), crypto::kSweWellFormednessProofBytes);
    const auto back = crypto::SweWellFormednessProof::parse(wire);
    ASSERT_TRUE(back.has_value() && *back == *proof);
  }
}

// What the proof is for: a ciphertext with one bad key share decrypts differently depending on
// who signs. The proof the encryptor can still produce for it does not verify.
TEST(test_swe_well_formedness_proof_rejects_inconsistent_key_share) {
  const auto c = make_committee(7, 0x21);
  const auto msg = time_message(5);
  const std::vector<std::uint32_t> chunks = {11, 22, 33};
  auto ct = crypto::swe_encrypt(c.pks, 5, msg, kDst, chunks, seed_of(1));
  ASSERT_TRUE(ct.has_value());
  const auto other = crypto::swe_encrypt(c.pks, 5, msg, kDst, chunks, seed_of(2));
  ct->key_shares[6] = other->key_shares[6];  // a valid G1 point, not a share of this polynomial

  const auto without_6 = decrypt_with(*ct, c, {0, 1, 2, 3, 4}, msg);
  const auto with_6 = decrypt_with(*ct, c, {2, 3, 4, 5, 6}, msg);
  ASSERT_TRUE(without_6.has_value() && *without_6 == chunks);
  ASSERT_TRUE(!with_6.has_value() || *with_6 != chunks);  // signer-dependent outcome

  const auto proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(1));
  ASSERT_TRUE(proof.has_value());  // the prover does not check; the verifier must
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, *proof));
}

TEST(test_swe_well_formedness_proof_rejects_inconsistent_chunk_base) {
  const auto c = make_committee(5, 0x31);
  const auto msg = time_message(9);
  auto ct = crypto::swe_encrypt(c.pks, 4, msg, kDst, {5, 6}, seed_of(3));
  const auto other = crypto::swe_encrypt(c.pks, 4, msg, kDst, {5, 6}, seed_of(4));
  ASSERT_TRUE(ct && other);
  const auto honest = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(3));
  ASSERT_TRUE(crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, *honest));
  ct->chunks[1].t = other->chunks[1].t;  // H(T)^alpha' with alpha' != log_c(a_1)
  const auto proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(3));
  ASSERT_TRUE(proof.has_value());
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, *proof));
}

// The proof binds the statement: another committee, message, DST or claimed threshold fails, as
// does a proof moved to another ciphertext or altered in any field.
TEST(test_swe_well_formedness_proof_binds_statement) {
  const auto c = make_committee(7, 0x41);
  const auto msg = time_message(11);
  const auto ct = crypto::swe_encrypt(c.pks, 5, msg, kDst, {1, 2, 3}, seed_of(5));
  const auto proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(5));
  ASSERT_TRUE(ct && proof);
  ASSERT_TRUE(crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, *proof));
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, make_committee(7, 0x42).pks, msg, kDst, *proof));
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, time_message(12), kDst, *proof));
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, msg, crypto::kBlsPopDst, *proof));
  // A lower claimed threshold is not consistent with a degree-4 sharing (5 signers needed).
  auto lower = *ct;
  lower.threshold = 4;
  ASSERT_TRUE(!crypto::swe_verify_well_formed(lower, c.pks, msg, kDst,
                                              *crypto::swe_prove_well_formed(lower, c.pks, msg, kDst, seed_of(5))));
  const auto ct2 = crypto::swe_encrypt(c.pks, 5, msg, kDst, {1, 2, 3}, seed_of(6));
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct2, c.pks, msg, kDst, *proof));
  auto bad_z = *proof;
  bad_z.z.back() ^= 1;
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, bad_z));
  auto bad_f = *proof;
  bad_f.f = ct->c;
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, bad_f));
  auto bad_fs = *proof;
  bad_fs.f_star = ct->c0;
  ASSERT_TRUE(!crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, bad_fs));
  // Encoding: wrong length, version, a point off the curve, z >= r.
  auto wire = proof->serialize();
  ASSERT_TRUE(!crypto::SweWellFormednessProof::parse(Bytes(wire.begin(), wire.end() - 1)).has_value());
  auto v2 = wire;
  v2[0] = 2;
  ASSERT_TRUE(!crypto::SweWellFormednessProof::parse(v2).has_value());
  auto off = wire;
  off[5] ^= 0x01;
  ASSERT_TRUE(!crypto::SweWellFormednessProof::parse(off).has_value());
  auto big_z = wire;
  std::fill(big_z.end() - 32, big_z.end(), 0xff);
  ASSERT_TRUE(!crypto::SweWellFormednessProof::parse(big_z).has_value());
}

TEST(test_swe_well_formedness_prover_needs_the_encryption_seed) {
  const auto c = make_committee(4, 0x51);
  const auto msg = time_message(3);
  const auto ct = crypto::swe_encrypt(c.pks, 3, msg, kDst, {9}, seed_of(7));
  ASSERT_TRUE(ct.has_value());
  ASSERT_TRUE(!crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(8)).has_value());
  // Deterministic for one statement; the nonce differs across statements from one seed.
  const auto p1 = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(7));
  const auto p2 = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(7));
  ASSERT_TRUE(p1 && p2 && *p1 == *p2);
  auto other_msg = crypto::swe_encrypt(c.pks, 3, time_message(4), kDst, {9}, seed_of(7));
  const auto p3 = crypto::swe_prove_well_formed(*other_msg, c.pks, time_message(4), kDst, seed_of(7));
  ASSERT_TRUE(p3.has_value() && p3->f != p1->f);
}

TEST(test_swe_well_formedness_full_committee_timing) {
  const auto c = make_committee(MAX_COMMITTEE, 0x61);
  const auto t = static_cast<std::uint32_t>(consensus::quorum_threshold(c.pks.size()));
  const auto msg = time_message(4242);
  const auto chunks = crypto::swe_key_to_chunks(crypto::sha256(Bytes{4, 5, 6}));
  const auto ct = crypto::swe_encrypt(c.pks, t, msg, kDst, chunks, seed_of(9));
  ASSERT_TRUE(ct.has_value());
  const auto t0 = std::chrono::steady_clock::now();
  const auto proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, kDst, seed_of(9));
  const auto t1 = std::chrono::steady_clock::now();
  ASSERT_TRUE(proof.has_value());
  const bool ok = crypto::swe_verify_well_formed(*ct, c.pks, msg, kDst, *proof);
  const auto t2 = std::chrono::steady_clock::now();
  ASSERT_TRUE(ok);
  const auto ms = [](auto a, auto b) { return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count(); };
  std::cerr << "[swe-proof] n=" << MAX_COMMITTEE << " t=" << t << " proof_bytes=" << proof->serialize().size()
            << " prove_ms=" << ms(t0, t1) << " verify_ms=" << ms(t1, t2) << "\n";
}
