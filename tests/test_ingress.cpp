#include "test_framework.hpp"

#include <atomic>
#include <array>
#include <filesystem>
#include <stdexcept>

#include "address/address.hpp"
#include "consensus/ingress.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "p2p/messages.hpp"
#include "storage/db.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/signing.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

std::string unique_test_base(const std::string& prefix) {
  static std::atomic<std::uint64_t> seq{0};
  return prefix + "_" + std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

IngressCertificate sample_ingress_certificate(std::uint32_t lane = 3, std::uint64_t seq = 1) {
  IngressCertificate cert;
  cert.epoch = 7;
  cert.lane = lane;
  cert.seq = seq;
  cert.txid.fill(0x11);
  cert.tx_hash.fill(0x22);
  cert.prev_lane_root.fill(0x33);
  FinalitySig sig;
  sig.validator_pubkey.fill(0x44);
  sig.signature.fill(0x55);
  cert.sigs.push_back(sig);
  return cert;
}

LaneState sample_lane_state(std::uint32_t lane = 3, std::uint64_t max_seq = 9) {
  LaneState state;
  state.epoch = 8;
  state.lane = lane;
  state.max_seq = max_seq;
  state.lane_root.fill(0x66);
  return state;
}

crypto::KeyPair key_from_byte(std::uint8_t base) {
  std::array<std::uint8_t, 32> seed{};
  seed.fill(base);
  auto kp = crypto::keypair_from_seed32(seed);
  if (!kp.has_value()) throw std::runtime_error("key derivation failed");
  return *kp;
}

TxOut p2pkh_out_for_pub(const PubKey32& pub, std::uint64_t value) {
  const auto pkh = crypto::h160(Bytes(pub.begin(), pub.end()));
  return TxOut{value, address::p2pkh_script_pubkey(pkh)};
}

Bytes signed_spend_tx_bytes(const OutPoint& op, const TxOut& prev, const crypto::KeyPair& from, const PubKey32& to_pub,
                            std::uint64_t value_out) {
  const auto to_pkh = crypto::h160(Bytes(to_pub.begin(), to_pub.end()));
  auto tx = build_signed_p2pkh_tx_single_input(
      op, prev, from.private_key, std::vector<TxOut>{TxOut{value_out, address::p2pkh_script_pubkey(to_pkh)}});
  if (!tx.has_value()) throw std::runtime_error("failed to build tx");
  return tx->serialize();
}

IngressCertificate signed_ingress_certificate(const Bytes& tx_bytes, std::uint64_t epoch, std::uint64_t seq,
                                              const Hash32& prev_lane_root, const std::vector<crypto::KeyPair>& signers) {
  auto tx = parse_any_tx(tx_bytes);
  if (!tx.has_value()) throw std::runtime_error("invalid tx bytes");
  IngressCertificate cert;
  cert.epoch = epoch;
  cert.lane = consensus::assign_ingress_lane(*tx);
  cert.seq = seq;
  cert.txid = txid_any(*tx);
  cert.tx_hash = crypto::sha256d(tx_bytes);
  cert.prev_lane_root = prev_lane_root;
  const auto signing_hash = cert.signing_hash();
  const Bytes msg(signing_hash.begin(), signing_hash.end());
  for (const auto& kp : signers) {
    auto sig = crypto::ed25519_sign(msg, kp.private_key);
    if (!sig.has_value()) throw std::runtime_error("failed to sign ingress certificate");
    cert.sigs.push_back(FinalitySig{kp.public_key, *sig});
  }
  return cert;
}

}  // namespace

TEST(test_ingress_certificate_roundtrip) {
  const auto cert = sample_ingress_certificate();
  const auto bytes = cert.serialize();
  const auto parsed = IngressCertificate::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(*parsed, cert);
}

TEST(test_ingress_certificate_signing_hash_is_stable_and_field_sensitive) {
  const auto cert = sample_ingress_certificate();
  const auto h = cert.signing_hash();
  ASSERT_EQ(h, cert.signing_hash());

  auto changed_epoch = cert;
  changed_epoch.epoch += 1;
  ASSERT_TRUE(changed_epoch.signing_hash() != h);

  auto changed_lane = cert;
  changed_lane.lane += 1;
  ASSERT_TRUE(changed_lane.signing_hash() != h);

  auto changed_seq = cert;
  changed_seq.seq += 1;
  ASSERT_TRUE(changed_seq.signing_hash() != h);

  auto changed_txid = cert;
  changed_txid.txid[0] ^= 0x01;
  ASSERT_TRUE(changed_txid.signing_hash() != h);

  auto changed_tx_hash = cert;
  changed_tx_hash.tx_hash[0] ^= 0x01;
  ASSERT_TRUE(changed_tx_hash.signing_hash() != h);

  auto changed_prev_lane_root = cert;
  changed_prev_lane_root.prev_lane_root[0] ^= 0x01;
  ASSERT_TRUE(changed_prev_lane_root.signing_hash() != h);
}

TEST(test_lane_state_roundtrip) {
  const auto state = sample_lane_state();
  const auto bytes = state.serialize();
  const auto parsed = LaneState::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(*parsed, state);
}

TEST(test_lane_state_storage_roundtrip) {
  const std::string path = unique_test_base("/tmp/finalis_test_lane_state_roundtrip");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const auto state = sample_lane_state(12, 14);
  ASSERT_TRUE(db.put_lane_state(state.lane, state));
  const auto loaded = db.get_lane_state(state.lane);
  ASSERT_TRUE(loaded.has_value());
  ASSERT_EQ(*loaded, state);
}

TEST(test_ingress_certificate_storage_rejects_conflicting_rewrite) {
  const std::string path = unique_test_base("/tmp/finalis_test_ingress_rewrite");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  Bytes tx_bytes{0x01, 0x02, 0x03};
  const auto txid = crypto::sha256d(tx_bytes);
  ASSERT_TRUE(db.put_ingress_bytes(txid, tx_bytes));

  auto cert = sample_ingress_certificate(5, 1);
  cert.txid = txid;
  cert.tx_hash = crypto::sha256d(tx_bytes);
  ASSERT_TRUE(db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize()));
  ASSERT_TRUE(db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize()));

  auto conflicting = cert;
  conflicting.tx_hash[0] ^= 0x01;
  ASSERT_TRUE(!db.put_ingress_certificate(conflicting.lane, conflicting.seq, conflicting.serialize()));
}

TEST(test_lane_state_rejects_rewind) {
  const std::string path = unique_test_base("/tmp/finalis_test_lane_rewind");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const auto advanced = sample_lane_state(4, 5);
  ASSERT_TRUE(db.put_lane_state(advanced.lane, advanced));

  auto rewound = advanced;
  rewound.max_seq = 4;
  ASSERT_TRUE(!db.put_lane_state(rewound.lane, rewound));
}

TEST(test_ingress_certificate_store_rejects_seq_rewind_against_lane_state) {
  const std::string path = unique_test_base("/tmp/finalis_test_ingress_seq_rewind");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  auto state = sample_lane_state(6, 5);
  ASSERT_TRUE(db.put_lane_state(state.lane, state));

  Bytes tx_bytes{0xAA};
  const auto txid = crypto::sha256d(tx_bytes);
  ASSERT_TRUE(db.put_ingress_bytes(txid, tx_bytes));

  auto cert = sample_ingress_certificate(6, 4);
  cert.txid = txid;
  cert.tx_hash = crypto::sha256d(tx_bytes);
  cert.prev_lane_root = state.lane_root;
  ASSERT_TRUE(!db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize()));
}

TEST(test_ingress_certificate_store_enforces_lane_root_continuity) {
  const std::string path = unique_test_base("/tmp/finalis_test_ingress_lane_root");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  LaneState state;
  state.epoch = 12;
  state.lane = 7;
  state.max_seq = 0;
  state.lane_root.fill(0x77);
  ASSERT_TRUE(db.put_lane_state(state.lane, state));

  Bytes tx_bytes{0xAB, 0xCD};
  const auto txid = crypto::sha256d(tx_bytes);
  ASSERT_TRUE(db.put_ingress_bytes(txid, tx_bytes));

  auto bad = sample_ingress_certificate(state.lane, 1);
  bad.txid = txid;
  bad.tx_hash = crypto::sha256d(tx_bytes);
  bad.prev_lane_root.fill(0x99);
  ASSERT_TRUE(!db.put_ingress_certificate(bad.lane, bad.seq, bad.serialize()));

  auto good = sample_ingress_certificate(state.lane, 1);
  good.txid = txid;
  good.tx_hash = crypto::sha256d(tx_bytes);
  good.prev_lane_root = state.lane_root;
  ASSERT_TRUE(db.put_ingress_certificate(good.lane, good.seq, good.serialize()));
}

TEST(test_ingress_certificate_store_requires_associated_bytes) {
  const std::string path = unique_test_base("/tmp/finalis_test_ingress_bytes");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  auto cert = sample_ingress_certificate(8, 1);
  ASSERT_TRUE(!db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize()));

  Bytes tx_bytes{0x10, 0x20, 0x30};
  cert.txid = crypto::sha256d(tx_bytes);
  cert.tx_hash = crypto::sha256d(tx_bytes);
  ASSERT_TRUE(db.put_ingress_bytes(cert.txid, tx_bytes));
  ASSERT_TRUE(db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize()));
  const auto stored = db.get_ingress_certificate(cert.lane, cert.seq);
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(*stored, cert.serialize());
  const auto lane_range = db.load_ingress_lane_range(cert.lane, cert.seq, cert.seq);
  ASSERT_EQ(lane_range.size(), static_cast<std::size_t>(1));
  ASSERT_EQ(lane_range.front(), cert.serialize());
}

TEST(test_append_validated_ingress_record_succeeds_with_valid_cert_bytes_and_lane_state) {
  const std::string path = unique_test_base("/tmp/finalis_test_ingress_append_ok");
  std::filesystem::remove_all(path);

  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const auto from = key_from_byte(1);
  const auto to = key_from_byte(2);
  OutPoint op{};
  op.txid.fill(0x31);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto tx_bytes = signed_spend_tx_bytes(op, prev, from, to.public_key, 9'800);
  const auto cert = signed_ingress_certificate(tx_bytes, 9, 1, zero_hash(), {key_from_byte(21), key_from_byte(22)});
  const std::vector<PubKey32> committee{cert.sigs[0].validator_pubkey, cert.sigs[1].validator_pubkey};

  std::string err;
  ASSERT_TRUE(consensus::append_validated_ingress_record(db, cert, tx_bytes, committee, &err));
  ASSERT_TRUE(db.get_ingress_bytes(cert.txid).has_value());
  ASSERT_TRUE(db.get_ingress_certificate(cert.lane, cert.seq).has_value());
  const auto state = db.get_lane_state(cert.lane);
  ASSERT_TRUE(state.has_value());
  ASSERT_EQ(state->max_seq, cert.seq);
  ASSERT_EQ(state->lane_root, consensus::compute_lane_root_append(zero_hash(), cert.tx_hash));
}

TEST(test_append_validated_ingress_record_rejects_tx_parse_mismatch) {
  storage::DB db;
  ASSERT_TRUE(db.open(unique_test_base("/tmp/finalis_test_ingress_parse_fail")));
  const auto signer = key_from_byte(23);
  auto cert = sample_ingress_certificate(0, 1);
  const auto signing_hash = cert.signing_hash();
  auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), signer.private_key);
  ASSERT_TRUE(sig.has_value());
  cert.sigs = {FinalitySig{signer.public_key, *sig}};
  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, Bytes{0x00, 0xFF}, {signer.public_key}, &err));
  ASSERT_EQ(err, "ingress-tx-parse-failed");
}

TEST(test_append_validated_ingress_record_rejects_txid_mismatch) {
  storage::DB db;
  ASSERT_TRUE(db.open(unique_test_base("/tmp/finalis_test_ingress_txid_mismatch")));
  const auto from = key_from_byte(3);
  const auto to = key_from_byte(4);
  OutPoint op{};
  op.txid.fill(0x41);
  op.index = 0;
  const auto tx_bytes = signed_spend_tx_bytes(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  auto cert = signed_ingress_certificate(tx_bytes, 1, 1, zero_hash(), {key_from_byte(24)});
  cert.txid[0] ^= 0x01;
  cert.sigs.clear();
  const auto signing_hash = cert.signing_hash();
  auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), key_from_byte(24).private_key);
  ASSERT_TRUE(sig.has_value());
  cert.sigs.push_back(FinalitySig{key_from_byte(24).public_key, *sig});
  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, tx_bytes, {cert.sigs[0].validator_pubkey}, &err));
  ASSERT_EQ(err, "ingress-txid-mismatch");
}

TEST(test_append_validated_ingress_record_rejects_tx_hash_mismatch) {
  storage::DB db;
  ASSERT_TRUE(db.open(unique_test_base("/tmp/finalis_test_ingress_hash_mismatch")));
  const auto from = key_from_byte(5);
  const auto to = key_from_byte(6);
  OutPoint op{};
  op.txid.fill(0x51);
  op.index = 0;
  const auto tx_bytes = signed_spend_tx_bytes(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  auto cert = signed_ingress_certificate(tx_bytes, 1, 1, zero_hash(), {key_from_byte(25)});
  cert.tx_hash[0] ^= 0x01;
  cert.sigs.clear();
  const auto signing_hash = cert.signing_hash();
  auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), key_from_byte(25).private_key);
  ASSERT_TRUE(sig.has_value());
  cert.sigs.push_back(FinalitySig{key_from_byte(25).public_key, *sig});
  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, tx_bytes, {cert.sigs[0].validator_pubkey}, &err));
  ASSERT_EQ(err, "ingress-tx-hash-mismatch");
}

TEST(test_append_validated_ingress_record_rejects_wrong_lane_assignment) {
  storage::DB db;
  ASSERT_TRUE(db.open(unique_test_base("/tmp/finalis_test_ingress_lane_mismatch")));
  const auto from = key_from_byte(7);
  const auto to = key_from_byte(8);
  OutPoint op{};
  op.txid.fill(0x61);
  op.index = 0;
  const auto tx_bytes = signed_spend_tx_bytes(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  auto cert = signed_ingress_certificate(tx_bytes, 1, 1, zero_hash(), {key_from_byte(26)});
  cert.lane = (cert.lane + 1) % consensus::INGRESS_LANE_COUNT;
  cert.sigs.clear();
  const auto signing_hash = cert.signing_hash();
  auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), key_from_byte(26).private_key);
  ASSERT_TRUE(sig.has_value());
  cert.sigs.push_back(FinalitySig{key_from_byte(26).public_key, *sig});
  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, tx_bytes, {cert.sigs[0].validator_pubkey}, &err));
  ASSERT_EQ(err, "ingress-lane-mismatch");
}

TEST(test_append_validated_ingress_record_rejects_bad_prev_lane_root) {
  storage::DB db;
  ASSERT_TRUE(db.open(unique_test_base("/tmp/finalis_test_ingress_prev_root")));

  const auto from = key_from_byte(9);
  const auto to = key_from_byte(10);
  OutPoint op{};
  op.txid.fill(0x71);
  op.index = 0;
  auto tx_bytes = signed_spend_tx_bytes(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  auto cert = signed_ingress_certificate(tx_bytes, 2, 1, zero_hash(), {key_from_byte(27)});
  LaneState state;
  state.epoch = 2;
  state.lane = cert.lane;
  state.max_seq = 0;
  state.lane_root.fill(0xAA);
  ASSERT_TRUE(db.put_lane_state(state.lane, state));
  cert.prev_lane_root.fill(0xBB);
  cert.sigs.clear();
  const auto signing_hash = cert.signing_hash();
  auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), key_from_byte(27).private_key);
  ASSERT_TRUE(sig.has_value());
  cert.sigs.push_back(FinalitySig{key_from_byte(27).public_key, *sig});
  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, tx_bytes, {cert.sigs[0].validator_pubkey}, &err));
  ASSERT_EQ(err, "ingress-prev-lane-root-mismatch");
}

TEST(test_append_validated_ingress_record_rejects_epoch_mismatch_when_expected_epoch_provided) {
  storage::DB db;
  ASSERT_TRUE(db.open(unique_test_base("/tmp/finalis_test_ingress_epoch_mismatch")));

  const auto from = key_from_byte(30);
  const auto to = key_from_byte(31);
  OutPoint op{};
  op.txid.fill(0x72);
  op.index = 0;
  const auto tx_bytes = signed_spend_tx_bytes(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  const auto signer = key_from_byte(32);
  auto cert = signed_ingress_certificate(tx_bytes, 1, 1, zero_hash(), {signer});

  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert, tx_bytes, {signer.public_key}, 5, &err));
  ASSERT_EQ(err, "ingress-epoch-mismatch");
}

TEST(test_append_validated_ingress_record_rejects_equivocation_without_partial_persist) {
  const std::string path = unique_test_base("/tmp/finalis_test_ingress_equivocation");
  std::filesystem::remove_all(path);
  storage::DB db;
  ASSERT_TRUE(db.open(path));

  const auto signer = key_from_byte(28);
  const std::vector<PubKey32> committee{signer.public_key};

  const auto from = key_from_byte(11);
  const auto to_a = key_from_byte(12);
  const auto to_b = key_from_byte(13);
  OutPoint op{};
  op.txid.fill(0x81);
  op.index = 0;
  const auto prev = p2pkh_out_for_pub(from.public_key, 10'000);
  const auto tx_bytes_a = signed_spend_tx_bytes(op, prev, from, to_a.public_key, 9'800);
  auto tx_bytes_b = signed_spend_tx_bytes(op, prev, from, to_b.public_key, 9'700);

  auto cert_a = signed_ingress_certificate(tx_bytes_a, 3, 1, zero_hash(), {signer});
  ASSERT_TRUE(consensus::append_validated_ingress_record(db, cert_a, tx_bytes_a, committee));

  auto parsed_b_template = Tx::parse(tx_bytes_b);
  ASSERT_TRUE(parsed_b_template.has_value());
  for (int i = 0; i < 256; ++i) {
    Tx candidate;
    candidate.version = 1;
    candidate.inputs = parsed_b_template->inputs;
    candidate.outputs.push_back(TxOut{9'700, Bytes{static_cast<std::uint8_t>(i)}});
    tx_bytes_b = candidate.serialize();
    auto parsed = Tx::parse(tx_bytes_b);
    ASSERT_TRUE(parsed.has_value());
    if (consensus::assign_ingress_lane(*parsed) == cert_a.lane) break;
  }

  auto cert_b = signed_ingress_certificate(tx_bytes_b, 3, cert_a.seq, zero_hash(), {signer});
  ASSERT_EQ(cert_b.lane, cert_a.lane);
  cert_b.sigs.clear();
  const auto signing_hash = cert_b.signing_hash();
  auto sig = crypto::ed25519_sign(Bytes(signing_hash.begin(), signing_hash.end()), signer.private_key);
  ASSERT_TRUE(sig.has_value());
  cert_b.sigs.push_back(FinalitySig{signer.public_key, *sig});

  std::string err;
  ASSERT_TRUE(!consensus::append_validated_ingress_record(db, cert_b, tx_bytes_b, committee, &err));
  ASSERT_EQ(err, "ingress-equivocation-detected");
  const auto stored_cert = db.get_ingress_certificate(cert_a.lane, cert_a.seq);
  ASSERT_TRUE(stored_cert.has_value());
  ASSERT_EQ(*stored_cert, cert_a.serialize());
  ASSERT_TRUE(!db.get_ingress_bytes(cert_b.txid).has_value());
  const auto evidence = db.get_ingress_equivocation_evidence(cert_a.epoch, cert_a.lane, cert_a.seq);
  ASSERT_TRUE(evidence.has_value());
  ASSERT_EQ(evidence->epoch, cert_a.epoch);
  ASSERT_EQ(evidence->lane, cert_a.lane);
  ASSERT_EQ(evidence->seq, cert_a.seq);
  ASSERT_TRUE(evidence->first_txid == cert_a.txid || evidence->second_txid == cert_a.txid);
  ASSERT_TRUE(evidence->first_txid == cert_b.txid || evidence->second_txid == cert_b.txid);
}

TEST(test_lane_root_append_helper_is_stable) {
  Hash32 prev{};
  prev.fill(0x11);
  Hash32 tx_hash{};
  tx_hash.fill(0x22);
  const auto a = consensus::compute_lane_root_append(prev, tx_hash);
  const auto b = consensus::compute_lane_root_append(prev, tx_hash);
  ASSERT_EQ(a, b);
  tx_hash[0] ^= 0x01;
  ASSERT_TRUE(consensus::compute_lane_root_append(prev, tx_hash) != a);
}

TEST(test_ingress_p2p_message_roundtrip) {
  const auto signer = key_from_byte(29);
  const auto from = key_from_byte(14);
  const auto to = key_from_byte(15);
  OutPoint op{};
  op.txid.fill(0x91);
  op.index = 0;
  const auto tx_bytes = signed_spend_tx_bytes(op, p2pkh_out_for_pub(from.public_key, 10'000), from, to.public_key, 9'800);
  const auto cert = signed_ingress_certificate(tx_bytes, 5, 1, zero_hash(), {signer});

  p2p::IngressRecordMsg rec{cert, tx_bytes};
  auto rec_roundtrip = p2p::de_ingress_record(p2p::ser_ingress_record(rec));
  ASSERT_TRUE(rec_roundtrip.has_value());
  ASSERT_EQ(rec_roundtrip->certificate, cert);
  ASSERT_EQ(rec_roundtrip->tx_bytes, tx_bytes);

  p2p::GetIngressRangeMsg get{cert.lane, 1, 3};
  auto get_roundtrip = p2p::de_get_ingress_range(p2p::ser_get_ingress_range(get));
  ASSERT_TRUE(get_roundtrip.has_value());
  ASSERT_EQ(get_roundtrip->lane, get.lane);
  ASSERT_EQ(get_roundtrip->from_seq, get.from_seq);
  ASSERT_EQ(get_roundtrip->to_seq, get.to_seq);

  p2p::IngressRangeMsg range;
  range.lane = cert.lane;
  range.from_seq = 1;
  range.to_seq = 1;
  range.records.push_back(rec);
  auto range_roundtrip = p2p::de_ingress_range(p2p::ser_ingress_range(range));
  ASSERT_TRUE(range_roundtrip.has_value());
  ASSERT_EQ(range_roundtrip->lane, range.lane);
  ASSERT_EQ(range_roundtrip->from_seq, range.from_seq);
  ASSERT_EQ(range_roundtrip->to_seq, range.to_seq);
  ASSERT_EQ(range_roundtrip->records.size(), static_cast<std::size_t>(1));
  ASSERT_EQ(range_roundtrip->records[0].certificate, cert);

  p2p::IngressTipsMsg tips;
  tips.lane_tips[cert.lane] = 7;
  auto tips_roundtrip = p2p::de_ingress_tips(p2p::ser_ingress_tips(tips));
  ASSERT_TRUE(tips_roundtrip.has_value());
  ASSERT_EQ(tips_roundtrip->lane_tips[cert.lane], 7u);
}
