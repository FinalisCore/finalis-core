// SPDX-License-Identifier: MIT

#include "test_framework.hpp"

#include <random>

#include <sodium.h>

#include "consensus/frontier_execution.hpp"
#include "consensus/validator_registry.hpp"
#include "crypto/bls12_381.hpp"
#include "crypto/hash.hpp"
#include "crypto/swe.hpp"
#include "crypto/swe_proofs.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/validate.hpp"

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
    auto sk = crypto::bls_keygen(ikm);
    ASSERT_TRUE(sk.has_value());
    c.pks.push_back(*crypto::bls_public_key(*sk));
    c.sks.push_back(*sk);
  }
  return c;
}

Hash32 filled(std::uint8_t b) {
  Hash32 h{};
  h.fill(b);
  return h;
}

// A body: any well-encoded transaction (validity against the UTXO set is execution's business).
Tx sample_body() {
  Tx tx;
  TxIn in;
  in.prev_txid = filled(0x33);
  in.prev_index = 1;
  in.script_sig = Bytes(64, 0x44);
  tx.inputs.push_back(in);
  tx.outputs.push_back(TxOut{12345, Bytes{0x76, 0xa9, 0x14}});
  return tx;
}

TxTimed sample_envelope(bool with_change) {
  TxTimed tx;
  tx.fee_input.prev_txid = filled(0x11);
  tx.fee_input.prev_index = 3;
  tx.fee_input.script_sig = Bytes(96, 0x22);
  tx.prepaid_fee = 1000;
  tx.forfeit_bond = 5000;
  tx.bond_refund_script = Bytes{0x76, 0xa9, 0x14, 0x02};
  if (with_change) tx.fee_change = TxOut{9000, Bytes{0x76, 0xa9, 0x14, 0x01}};
  tx.unlock_height = 1200;
  tx.committee_epoch = 1184;
  tx.committee_root = filled(0x55);
  tx.swe_ciphertext = Bytes(500, 0x66);
  tx.swe_proof = Bytes(kTxTimedSweProofBytes, 0x77);
  tx.body_nonce.fill(0x88);
  tx.body_ciphertext = Bytes(200, 0x99);
  return tx;
}

}  // namespace

TEST(test_timed_tx_envelope_roundtrips_and_enforces_limits) {
  for (const bool change : {false, true}) {
    const auto tx = sample_envelope(change);
    const auto wire = tx.serialize();
    const auto back = TxTimed::parse(wire);
    ASSERT_TRUE(back.has_value());
    ASSERT_TRUE(back->serialize() == wire);
    ASSERT_TRUE(back->txid() == tx.txid());
    ASSERT_EQ(back->fee_change.has_value(), change);
  }
  const auto base = sample_envelope(true);
  const auto base_wire = base.serialize();
  ASSERT_TRUE(!TxTimed::parse(Bytes(base_wire.begin(), base_wire.end() - 1)).has_value());
  auto trailing = base.serialize();
  trailing.push_back(0);
  ASSERT_TRUE(!TxTimed::parse(trailing).has_value());
  auto v = base.serialize();
  v[0] = 2;  // a TxV2 version tag is not a TxTimed
  ASSERT_TRUE(!TxTimed::parse(v).has_value());
  auto big_ct = base;
  big_ct.swe_ciphertext = Bytes(kTxTimedMaxSweCiphertextBytes + 1, 1);
  ASSERT_TRUE(!TxTimed::parse(big_ct.serialize()).has_value());
  auto max_ct = base;
  max_ct.swe_ciphertext = Bytes(kTxTimedMaxSweCiphertextBytes, 1);
  ASSERT_TRUE(TxTimed::parse(max_ct.serialize()).has_value());
  auto short_proof = base;
  short_proof.swe_proof.pop_back();
  ASSERT_TRUE(!TxTimed::parse(short_proof.serialize()).has_value());
  auto no_tag = base;
  no_tag.body_ciphertext = Bytes(kTxTimedBodyTagBytes - 1, 0);
  ASSERT_TRUE(!TxTimed::parse(no_tag.serialize()).has_value());
  auto big_body = base;
  big_body.body_ciphertext = Bytes(kTxTimedMaxBodyCiphertextBytes + 1, 0);
  ASSERT_TRUE(!TxTimed::parse(big_body.serialize()).has_value());
  // The SWE footprint at a full committee is exactly the cap.
  ASSERT_EQ(kTxTimedMaxSweCiphertextBytes, 14167u);
}

// The fee signature covers everything but the script_sig; the time-signature message depends on
// the height and the chain domain only.
TEST(test_timed_tx_signing_and_time_messages) {
  const Hash32 domain = filled(0xd0);
  const auto tx = sample_envelope(true);
  const auto m = signing_message_for_timed_fee_input(domain, tx);
  auto other_sig = tx;
  other_sig.fee_input.script_sig = Bytes(10, 1);
  ASSERT_TRUE(signing_message_for_timed_fee_input(domain, other_sig) == m);
  auto other_body = tx;
  other_body.body_ciphertext.back() ^= 1;
  ASSERT_TRUE(signing_message_for_timed_fee_input(domain, other_body) != m);
  auto other_unlock = tx;
  other_unlock.unlock_height += 1;
  ASSERT_TRUE(signing_message_for_timed_fee_input(domain, other_unlock) != m);
  auto other_bond = tx;
  other_bond.forfeit_bond += 1;
  ASSERT_TRUE(signing_message_for_timed_fee_input(domain, other_bond) != m);
  auto other_refund = tx;
  other_refund.bond_refund_script.back() ^= 1;
  ASSERT_TRUE(signing_message_for_timed_fee_input(domain, other_refund) != m);
  ASSERT_TRUE(signing_message_for_timed_fee_input(filled(0xd1), tx) != m);

  ASSERT_EQ(time_signature_message(domain, 7).size(), 32u);
  ASSERT_TRUE(time_signature_message(domain, 7) == time_signature_message(domain, 7));
  ASSERT_TRUE(time_signature_message(domain, 7) != time_signature_message(domain, 8));
  ASSERT_TRUE(time_signature_message(domain, 7) != time_signature_message(filled(0xd1), 7));
  ASSERT_TRUE(time_signature_message(domain, 7) != timeout_vote_signing_message(domain, 7, 0));
}

// Client to chain and back: the sender seals a body under a fresh key, SWE-encrypts the key to the
// unlock height's committee with a well-formedness proof; once the committee has signed that height,
// anyone holding the aggregate recovers the key and opens exactly that body.
TEST(test_timed_tx_end_to_end_with_committee_time_signature) {
  const Hash32 domain = filled(0xd2);
  const auto c = make_committee(7, 0xa1);
  const auto t = static_cast<std::uint32_t>(consensus::quorum_threshold(c.pks.size()));
  const std::uint64_t unlock = 4321;
  const auto msg = time_signature_message(domain, unlock);
  const Hash32 key = crypto::sha256(Bytes{'k', 'e', 'y'});
  const Hash32 seed = crypto::sha256(Bytes{'s', 'e', 'e', 'd'});

  TxTimed tx = sample_envelope(true);
  tx.unlock_height = unlock;
  const auto ct = crypto::swe_encrypt(c.pks, t, msg, crypto::kBlsTimeSignatureDst, crypto::swe_key_to_chunks(key), seed);
  const auto proof = crypto::swe_prove_well_formed(*ct, c.pks, msg, crypto::kBlsTimeSignatureDst, seed);
  ASSERT_TRUE(ct && proof);
  tx.swe_ciphertext = ct->serialize();
  tx.swe_proof = proof->serialize();
  ASSERT_TRUE(tx.swe_ciphertext.size() <= kTxTimedMaxSweCiphertextBytes);
  ASSERT_TRUE(seal_timed_body(tx, key, AnyTx{sample_body()}));
  const auto wire = tx.serialize();

  // Admission side: parse, the ciphertext for this committee, the proof.
  const auto got = TxTimed::parse(wire);
  ASSERT_TRUE(got.has_value());
  const auto got_ct = crypto::SweCiphertext::parse(got->swe_ciphertext, c.pks.size());
  const auto got_proof = crypto::SweWellFormednessProof::parse(got->swe_proof);
  ASSERT_TRUE(got_ct && got_proof);
  ASSERT_TRUE(crypto::swe_verify_well_formed(*got_ct, c.pks, time_signature_message(domain, got->unlock_height),
                                             crypto::kBlsTimeSignatureDst, *got_proof));

  // Settlement side: the committee's time signatures for the unlock height.
  std::vector<crypto::BlsPublicKey> signers;
  std::vector<crypto::BlsSignature> sigs;
  for (std::size_t i = 1; i <= t; ++i) {
    signers.push_back(c.pks[i]);
    sigs.push_back(*crypto::bls_sign(c.sks[i], msg, crypto::kBlsTimeSignatureDst));
  }
  const auto agg = crypto::mcfly_aggregate(signers, sigs);
  const auto chunks = crypto::swe_decrypt(*got_ct, c.pks, signers, *agg, msg, crypto::kBlsTimeSignatureDst);
  ASSERT_TRUE(chunks.has_value());
  const auto recovered = crypto::swe_key_from_chunks(*chunks);
  ASSERT_TRUE(recovered.has_value() && *recovered == key);
  const auto body = open_timed_body(*got, *recovered);
  ASSERT_TRUE(body.has_value());
  ASSERT_TRUE(serialize_any_tx(*body) == sample_body().serialize());

  // The body opens only in its own envelope and under its own key.
  auto moved = *got;
  moved.unlock_height += 1;
  ASSERT_TRUE(!open_timed_body(moved, key).has_value());
  auto other_fee = *got;
  other_fee.prepaid_fee += 1;
  ASSERT_TRUE(!open_timed_body(other_fee, key).has_value());
  auto other_refund = *got;
  other_refund.bond_refund_script.push_back(0);  // the refund destination is bound to the body
  ASSERT_TRUE(!open_timed_body(other_refund, key).has_value());
  auto flipped = *got;
  flipped.body_ciphertext[3] ^= 1;
  ASSERT_TRUE(!open_timed_body(flipped, key).has_value());
  ASSERT_TRUE(!open_timed_body(*got, crypto::sha256(Bytes{'x'})).has_value());
  // The fee script_sig is outside the associated data: signing after sealing is possible.
  auto resigned = *got;
  resigned.fee_input.script_sig = Bytes(64, 0x5a);
  ASSERT_TRUE(open_timed_body(resigned, key).has_value());
}

// A body that is not exactly one Tx / TxV2 encoding is an invalid body, even with a valid tag.
TEST(test_timed_tx_garbage_body_does_not_open) {
  ASSERT_TRUE(sodium_init() >= 0);
  const Hash32 key = filled(0x0b);
  auto seal_raw = [&](TxTimed& tx, const Bytes& plain) {
    const Hash32 aad = tx.body_aad();
    tx.body_ciphertext.assign(plain.size() + crypto_aead_chacha20poly1305_ietf_ABYTES, 0);
    unsigned long long len = 0;
    ASSERT_TRUE(crypto_aead_chacha20poly1305_ietf_encrypt(tx.body_ciphertext.data(), &len, plain.data(), plain.size(),
                                                          aad.data(), aad.size(), nullptr, tx.body_nonce.data(),
                                                          key.data()) == 0);
  };
  auto trailing = sample_body().serialize();
  trailing.push_back(0);
  for (const auto& plain : {Bytes{1, 2, 3}, trailing, Bytes{}, sample_envelope(false).serialize()}) {
    TxTimed tx = sample_envelope(false);
    seal_raw(tx, plain);
    ASSERT_TRUE(!open_timed_body(tx, key).has_value());
  }
  TxTimed ok = sample_envelope(false);
  seal_raw(ok, sample_body().serialize());
  ASSERT_TRUE(open_timed_body(ok, key).has_value());
}

// Value conservation of the bond rule: the penalty is the declared bond, never more.
TEST(test_timed_escrow_conserves_value) {
  const OutPoint op{filled(0x01), 0};
  const Bytes refund{0x76, 0xa9};
  // Exactly prepaid + bond + change, and the bond meets the minimum.
  ASSERT_TRUE(consensus::open_timed_escrow(op, 1000, 400, 600, refund, std::nullopt, 600).has_value());
  ASSERT_TRUE(!consensus::open_timed_escrow(op, 1000, 400, 600, refund, std::nullopt, 601).has_value());
  ASSERT_TRUE(!consensus::open_timed_escrow(op, 1000, 400, 500, refund, std::nullopt, 0).has_value());
  ASSERT_TRUE(!consensus::open_timed_escrow(op, 1000, 400, 500, refund, TxOut{99, {}}, 0).has_value());
  ASSERT_TRUE(consensus::open_timed_escrow(op, 1000, 400, 500, refund, TxOut{100, {}}, 0).has_value());
  ASSERT_TRUE(!consensus::open_timed_escrow(op, 1000, 1001, 0, refund, std::nullopt, 0).has_value());
  ASSERT_TRUE(!consensus::open_timed_escrow(op, 100, 50, ~std::uint64_t{0}, refund, TxOut{51, {}}, 0).has_value());

  std::mt19937_64 rng(42);
  for (int i = 0; i < 10000; ++i) {
    const std::uint64_t value = rng() >> (rng() % 63);
    const std::uint64_t prepaid = rng() % (value + 1);
    const std::uint64_t bond = rng() % (value - prepaid + 1);
    const std::uint64_t change_value = value - prepaid - bond;
    std::optional<TxOut> change;
    if (change_value > 0) change = TxOut{change_value, Bytes{1}};
    const auto inc = consensus::open_timed_escrow(op, value, prepaid, bond, refund, change, 0);
    ASSERT_TRUE(inc.has_value());
    const std::uint64_t at_inclusion = inc->fee + (inc->change ? inc->change->value : 0);
    ASSERT_EQ(at_inclusion + inc->escrow.forfeit_bond, value);
    for (const bool applied : {true, false}) {
      const auto s = consensus::settle_timed_escrow(inc->escrow, applied);
      const std::uint64_t refunded = s.refund ? s.refund->value : 0;
      ASSERT_EQ(at_inclusion + refunded + s.forfeited_fee, value);
      ASSERT_TRUE(refunded == 0 || s.forfeited_fee == 0);
      ASSERT_EQ(applied ? refunded : s.forfeited_fee, bond);  // the penalty is the bond, never more
      if (s.refund) ASSERT_TRUE(s.refund->script_pubkey == refund);
    }
  }
}
