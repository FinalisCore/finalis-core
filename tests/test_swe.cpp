// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <chrono>
#include <iostream>

#include "consensus/validator_registry.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/hash.hpp"
#include "crypto/swe.hpp"

using namespace finalis;

namespace {

// A simulated committee: n validators with BLS keys from distinct key material.
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
    auto pk = crypto::bls_public_key(*sk);
    ASSERT_TRUE(pk.has_value());
    c.sks.push_back(*sk);
    c.pks.push_back(*pk);
  }
  return c;
}

// The time-signature message of a height (the consensus layer will own the real encoding).
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

// The aggregate a decryptor builds from the signers' published time signatures.
crypto::BlsSignature aggregate_of(const Committee& c, const std::vector<std::size_t>& who, const Bytes& msg) {
  std::vector<crypto::BlsPublicKey> pks;
  std::vector<crypto::BlsSignature> sigs;
  for (const auto i : who) {
    pks.push_back(c.pks[i]);
    auto s = crypto::bls_sign(c.sks[i], msg, crypto::kBlsTimeSignatureDst);
    ASSERT_TRUE(s.has_value());
    sigs.push_back(*s);
  }
  auto agg = crypto::mcfly_aggregate(pks, sigs);
  ASSERT_TRUE(agg.has_value());
  return *agg;
}

std::vector<crypto::BlsPublicKey> keys_of(const Committee& c, const std::vector<std::size_t>& who) {
  std::vector<crypto::BlsPublicKey> out;
  for (const auto i : who) out.push_back(c.pks[i]);
  return out;
}

std::optional<Hash32> decrypt_key(const crypto::SweCiphertext& ct, const Committee& c, const std::vector<std::size_t>& who,
                                  const Bytes& msg) {
  const auto chunks = crypto::swe_decrypt(ct, c.pks, keys_of(c, who), aggregate_of(c, who, msg), msg,
                                          crypto::kBlsTimeSignatureDst);
  if (!chunks) return std::nullopt;
  return crypto::swe_key_from_chunks(*chunks);
}

}  // namespace

TEST(test_swe_gt_dlog_recovers_every_chunk_range_edge) {
  for (const std::uint32_t m : {0u, 1u, 2u, 4095u, 4096u, 4097u, 0x123456u, crypto::kSweChunkLimit - 1}) {
    const auto got = crypto::swe_gt_dlog(crypto::swe_gt_pow(m));
    ASSERT_TRUE(got.has_value());
    ASSERT_EQ(*got, m);
  }
  // Outside [0, 2^24): not found.
  ASSERT_TRUE(!crypto::swe_gt_dlog(crypto::swe_gt_pow(crypto::kSweChunkLimit)).has_value());
  // Not a canonical GT element.
  crypto::GtBytes junk{};
  junk.fill(0xff);
  ASSERT_TRUE(!crypto::swe_gt_dlog(junk).has_value());
}

TEST(test_swe_key_chunking_roundtrips) {
  Hash32 key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(0xa5 ^ (i * 37));
  const auto chunks = crypto::swe_key_to_chunks(key);
  ASSERT_EQ(chunks.size(), crypto::kSweKeyChunks);
  for (std::size_t i = 0; i + 1 < chunks.size(); ++i) ASSERT_TRUE(chunks[i] < crypto::kSweChunkLimit);
  ASSERT_TRUE(chunks.back() < (1u << 16));
  ASSERT_TRUE(*crypto::swe_key_from_chunks(chunks) == key);
  auto bad = chunks;
  bad.back() = 1u << 16;  // the last chunk is 16 bits wide
  ASSERT_TRUE(!crypto::swe_key_from_chunks(bad).has_value());
  ASSERT_TRUE(!crypto::swe_key_from_chunks({1, 2, 3}).has_value());
}

// End to end against a simulated committee: the quorum threshold of 7 (5), every signer subset of
// size >= t decrypts to the same key; fewer, the wrong height, a non-member or a repeat do not.
TEST(test_swe_threshold_decryption_with_committee_aggregate) {
  const auto c = make_committee(7, 0x41);
  const std::uint32_t t = static_cast<std::uint32_t>(consensus::quorum_threshold(c.pks.size()));
  ASSERT_EQ(t, 5u);
  const auto msg = time_message(1234);
  Hash32 key{};
  for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 7 + 3);
  const auto ct = crypto::swe_encrypt(c.pks, t, msg, crypto::kBlsTimeSignatureDst, crypto::swe_key_to_chunks(key), seed_of(9));
  ASSERT_TRUE(ct.has_value());
  ASSERT_EQ(ct->key_shares.size(), 7u);
  ASSERT_EQ(ct->chunks.size(), crypto::kSweKeyChunks);

  for (const auto& who : std::vector<std::vector<std::size_t>>{
           {0, 1, 2, 3, 4}, {2, 3, 4, 5, 6}, {6, 0, 3, 1, 5}, {0, 1, 2, 3, 4, 5}, {0, 1, 2, 3, 4, 5, 6}}) {
    const auto got = decrypt_key(*ct, c, who, msg);
    ASSERT_TRUE(got.has_value());
    ASSERT_TRUE(*got == key);
  }
  // Below the threshold: refused.
  ASSERT_TRUE(!decrypt_key(*ct, c, {0, 1, 2, 3}, msg).has_value());
  // Signatures on another height do not open it.
  const auto other = time_message(1235);
  ASSERT_TRUE(!crypto::swe_decrypt(*ct, c.pks, keys_of(c, {0, 1, 2, 3, 4}), aggregate_of(c, {0, 1, 2, 3, 4}, other), msg,
                                   crypto::kBlsTimeSignatureDst)
                   .has_value());
  ASSERT_TRUE(!decrypt_key(*ct, c, {0, 1, 2, 3, 4}, other).has_value());
  // A signer outside the committee, or a repeated one.
  const auto outsider = make_committee(1, 0x77);
  auto with_outsider = keys_of(c, {0, 1, 2, 3});
  with_outsider.push_back(outsider.pks[0]);
  ASSERT_TRUE(!crypto::swe_decrypt(*ct, c.pks, with_outsider, aggregate_of(c, {0, 1, 2, 3, 4}, msg), msg,
                                   crypto::kBlsTimeSignatureDst)
                   .has_value());
  ASSERT_TRUE(!crypto::swe_decrypt(*ct, c.pks, keys_of(c, {0, 1, 2, 3, 3}), aggregate_of(c, {0, 1, 2, 3, 4}, msg), msg,
                                   crypto::kBlsTimeSignatureDst)
                   .has_value());
  // The ciphertext is bound to its committee: a different key set, same size, does not open it.
  const auto other_committee = make_committee(7, 0x42);
  ASSERT_TRUE(!decrypt_key(*ct, other_committee, {0, 1, 2, 3, 4}, msg).has_value());
}

// The enhanced construction: identical chunk values under the one message T stay unlinkable
// (fresh alpha per chunk), and the chunk bases satisfy e(a_i, H(T)) = e(c, t_i) (checked later by
// the well-formedness proof). Seeds make encryption deterministic; distinct seeds differ.
TEST(test_swe_encryption_is_seeded_and_rerandomizes_chunks) {
  const auto c = make_committee(4, 0x51);
  const auto msg = time_message(7);
  const std::vector<std::uint32_t> same = {42, 42, 42};
  const auto a = crypto::swe_encrypt(c.pks, 3, msg, crypto::kBlsTimeSignatureDst, same, seed_of(1));
  const auto b = crypto::swe_encrypt(c.pks, 3, msg, crypto::kBlsTimeSignatureDst, same, seed_of(1));
  const auto d = crypto::swe_encrypt(c.pks, 3, msg, crypto::kBlsTimeSignatureDst, same, seed_of(2));
  ASSERT_TRUE(a && b && d);
  ASSERT_TRUE(*a == *b);
  ASSERT_TRUE(!(*a == *d));
  ASSERT_TRUE(a->chunks[0].c_prime != a->chunks[1].c_prime && a->chunks[1].c_prime != a->chunks[2].c_prime);
  ASSERT_TRUE(a->chunks[0].t != a->chunks[1].t);
  const auto got = crypto::swe_decrypt(*a, c.pks, keys_of(c, {0, 1, 3}), aggregate_of(c, {0, 1, 3}, msg), msg,
                                       crypto::kBlsTimeSignatureDst);
  ASSERT_TRUE(got.has_value() && *got == same);
}

TEST(test_swe_ciphertext_encoding_roundtrips_and_rejects_bad_points) {
  const auto c = make_committee(5, 0x61);
  const auto msg = time_message(99);
  const auto ct = crypto::swe_encrypt(c.pks, 4, msg, crypto::kBlsTimeSignatureDst, {1, 2, 3}, seed_of(3));
  ASSERT_TRUE(ct.has_value());
  const auto wire = ct->serialize();
  ASSERT_EQ(wire.size(), 7 + (2 + 5) * crypto::kBlsPublicKeyBytes +
                             3 * (crypto::kBlsPublicKeyBytes + crypto::kBlsSignatureBytes + crypto::kGtBytes));
  const auto back = crypto::SweCiphertext::parse(wire);
  ASSERT_TRUE(back.has_value() && *back == *ct);
  // Truncated, trailing bytes, wrong version, threshold above n, too many keys for the caller's cap.
  ASSERT_TRUE(!crypto::SweCiphertext::parse(Bytes(wire.begin(), wire.end() - 1)).has_value());
  auto longer = wire;
  longer.push_back(0);
  ASSERT_TRUE(!crypto::SweCiphertext::parse(longer).has_value());
  auto bad_version = wire;
  bad_version[0] = 2;
  ASSERT_TRUE(!crypto::SweCiphertext::parse(bad_version).has_value());
  auto bad_threshold = wire;
  bad_threshold[2] = 6;
  ASSERT_TRUE(!crypto::SweCiphertext::parse(bad_threshold).has_value());
  ASSERT_TRUE(!crypto::SweCiphertext::parse(wire, 4).has_value());
  // A corrupted G1 key share, G2 chunk base and GT component are each rejected.
  for (const std::size_t at : {7 + 2 * crypto::kBlsPublicKeyBytes + 5,                                       // c_0
                               7 + 7 * crypto::kBlsPublicKeyBytes + crypto::kBlsPublicKeyBytes + 9,         // t_0
                               7 + 7 * crypto::kBlsPublicKeyBytes + crypto::kBlsPublicKeyBytes +
                                   crypto::kBlsSignatureBytes + 100}) {                                      // c'_0
    auto bad = wire;
    bad[at] ^= 0x01;
    ASSERT_TRUE(!crypto::SweCiphertext::parse(bad).has_value());
  }
}

// A tampered (but well-encoded) GT component decrypts to no valid chunk rather than a wrong key.
TEST(test_swe_tampered_component_does_not_decrypt) {
  const auto c = make_committee(4, 0x71);
  const auto msg = time_message(5);
  auto ct = crypto::swe_encrypt(c.pks, 3, msg, crypto::kBlsTimeSignatureDst, {7, 8}, seed_of(4));
  ASSERT_TRUE(ct.has_value());
  ct->chunks[1].c_prime = ct->chunks[0].c_prime;  // a valid GT element from the wrong slot
  const auto got = crypto::swe_decrypt(*ct, c.pks, keys_of(c, {0, 1, 2}), aggregate_of(c, {0, 1, 2}, msg), msg,
                                       crypto::kBlsTimeSignatureDst);
  ASSERT_TRUE(!got.has_value() || (*got)[1] != 8u);
}

TEST(test_swe_rejects_bad_parameters) {
  const auto c = make_committee(3, 0x81);
  const auto msg = time_message(1);
  const auto dst = crypto::kBlsTimeSignatureDst;
  ASSERT_TRUE(!crypto::swe_encrypt({}, 1, msg, dst, {1}, seed_of(1)).has_value());
  ASSERT_TRUE(!crypto::swe_encrypt(c.pks, 0, msg, dst, {1}, seed_of(1)).has_value());
  ASSERT_TRUE(!crypto::swe_encrypt(c.pks, 4, msg, dst, {1}, seed_of(1)).has_value());
  ASSERT_TRUE(!crypto::swe_encrypt(c.pks, 2, msg, dst, {}, seed_of(1)).has_value());
  ASSERT_TRUE(!crypto::swe_encrypt(c.pks, 2, msg, dst, {crypto::kSweChunkLimit}, seed_of(1)).has_value());
  ASSERT_TRUE(!crypto::swe_encrypt({c.pks[0], c.pks[0], c.pks[1]}, 2, msg, dst, {1}, seed_of(1)).has_value());
}

// Footprint and cost at the largest committee (MAX_COMMITTEE = 128, quorum 86), 256-bit key.
TEST(test_swe_full_committee_footprint_and_timing) {
  const auto c = make_committee(MAX_COMMITTEE, 0x91);
  const auto t = static_cast<std::uint32_t>(consensus::quorum_threshold(c.pks.size()));
  const auto msg = time_message(4242);
  Hash32 key = crypto::sha256(Bytes{1, 2, 3});
  const auto t0 = std::chrono::steady_clock::now();
  const auto ct = crypto::swe_encrypt(c.pks, t, msg, crypto::kBlsTimeSignatureDst, crypto::swe_key_to_chunks(key), seed_of(5));
  const auto t1 = std::chrono::steady_clock::now();
  ASSERT_TRUE(ct.has_value());
  std::vector<std::size_t> who;
  for (std::size_t i = 0; i < t; ++i) who.push_back((i * 3) % MAX_COMMITTEE);  // 86 distinct members
  const auto agg = aggregate_of(c, who, msg);
  const auto t2 = std::chrono::steady_clock::now();
  const auto chunks = crypto::swe_decrypt(*ct, c.pks, keys_of(c, who), agg, msg, crypto::kBlsTimeSignatureDst);
  const auto t3 = std::chrono::steady_clock::now();
  ASSERT_TRUE(chunks.has_value());
  ASSERT_TRUE(*crypto::swe_key_from_chunks(*chunks) == key);
  const auto ms = [](auto a, auto b) { return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count(); };
  std::cerr << "[swe] n=" << MAX_COMMITTEE << " t=" << t << " ciphertext_bytes=" << ct->serialize().size()
            << " encrypt_ms=" << ms(t0, t1) << " decrypt_ms=" << ms(t2, t3) << "\n";
}
