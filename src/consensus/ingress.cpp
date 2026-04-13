#include "consensus/ingress.hpp"

#include <set>

#include "codec/bytes.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {
namespace {

Hash32 outpoint_anchor_hash(const TxIn& in) {
  codec::ByteWriter w;
  w.bytes_fixed(in.prev_txid);
  w.u32le(in.prev_index);
  return crypto::sha256d(w.take());
}

bool validate_ingress_payload(const IngressCertificate& cert, const Bytes& tx_bytes, std::string* error) {
  const auto tx = parse_any_tx(tx_bytes);
  if (!tx.has_value()) {
    if (error) *error = "ingress-tx-parse-failed";
    return false;
  }

  const auto expected_txid = txid_any(*tx);
  if (expected_txid != cert.txid) {
    if (error) *error = "ingress-txid-mismatch";
    return false;
  }

  const auto expected_tx_hash = crypto::sha256d(tx_bytes);
  if (expected_tx_hash != cert.tx_hash) {
    if (error) *error = "ingress-tx-hash-mismatch";
    return false;
  }

  if (assign_ingress_lane(*tx) != cert.lane) {
    if (error) *error = "ingress-lane-mismatch";
    return false;
  }
  return true;
}

}  // namespace

Hash32 ingress_lane_anchor(const Tx& tx) {
  if (tx.inputs.empty()) return tx.txid();

  Hash32 best = outpoint_anchor_hash(tx.inputs.front());
  for (std::size_t i = 1; i < tx.inputs.size(); ++i) {
    const auto candidate = outpoint_anchor_hash(tx.inputs[i]);
    if (candidate < best) best = candidate;
  }
  return best;
}

Hash32 ingress_lane_anchor(const TxV2& tx) {
  if (tx.inputs.empty()) return tx.txid();

  Hash32 best = outpoint_anchor_hash(TxIn{tx.inputs.front().prev_txid, tx.inputs.front().prev_index});
  for (std::size_t i = 1; i < tx.inputs.size(); ++i) {
    const auto candidate = outpoint_anchor_hash(TxIn{tx.inputs[i].prev_txid, tx.inputs[i].prev_index});
    if (candidate < best) best = candidate;
  }
  return best;
}

Hash32 ingress_lane_anchor(const AnyTx& tx) {
  return std::visit([](const auto& value) { return ingress_lane_anchor(value); }, tx);
}

std::uint32_t assign_ingress_lane(const Tx& tx) {
  const auto anchor = ingress_lane_anchor(tx);
  Bytes anchor_bytes(anchor.begin(), anchor.end());
  codec::ByteReader r(anchor_bytes);
  auto first8 = r.u64le();
  if (!first8.has_value()) return 0;
  return static_cast<std::uint32_t>(*first8 % INGRESS_LANE_COUNT);
}

std::uint32_t assign_ingress_lane(const TxV2& tx) {
  const auto anchor = ingress_lane_anchor(tx);
  Bytes anchor_bytes(anchor.begin(), anchor.end());
  codec::ByteReader r(anchor_bytes);
  auto first8 = r.u64le();
  if (!first8.has_value()) return 0;
  return static_cast<std::uint32_t>(*first8 % INGRESS_LANE_COUNT);
}

std::uint32_t assign_ingress_lane(const AnyTx& tx) { return std::visit([](const auto& value) { return assign_ingress_lane(value); }, tx); }

Hash32 compute_lane_root_append(const Hash32& prev_root, const Hash32& tx_hash) {
  codec::ByteWriter w;
  static constexpr std::uint8_t kDomain[] = {'i', 'n', 'g', 'r', 'e', 's', 's', '-', 'l', 'a', 'n', 'e', '-', 'a', 'p', 'p', 'e', 'n', 'd', '/', 'v', '1'};
  w.bytes(Bytes(kDomain, kDomain + sizeof(kDomain)));
  w.bytes_fixed(prev_root);
  w.bytes_fixed(tx_hash);
  return crypto::sha256d(w.take());
}

bool verify_ingress_certificate(const IngressCertificate& cert, const std::vector<PubKey32>& committee, std::string* error) {
  if (cert.sigs.empty()) {
    if (error) *error = "ingress-cert-missing-signatures";
    return false;
  }

  const auto signing_hash = cert.signing_hash();
  const auto msg = Bytes(signing_hash.begin(), signing_hash.end());
  std::set<PubKey32> committee_set(committee.begin(), committee.end());
  std::set<PubKey32> seen;
  for (const auto& sig : cert.sigs) {
    if (!committee_set.empty() && committee_set.find(sig.validator_pubkey) == committee_set.end()) {
      if (error) *error = "ingress-cert-signer-not-in-committee";
      return false;
    }
    if (!seen.insert(sig.validator_pubkey).second) {
      if (error) *error = "ingress-cert-duplicate-signer";
      return false;
    }
    if (!crypto::ed25519_verify(msg, sig.signature, sig.validator_pubkey)) {
      if (error) *error = "ingress-cert-invalid-signature";
      return false;
    }
  }
  return true;
}

bool validate_ingress_append(const std::optional<LaneState>& lane_state, const IngressCertificate& cert, const Bytes& tx_bytes,
                             std::string* error) {
  if (!validate_ingress_payload(cert, tx_bytes, error)) return false;

  if (lane_state.has_value()) {
    if (cert.seq != lane_state->max_seq + 1) {
      if (error) *error = "ingress-seq-discontinuity";
      return false;
    }
    if (cert.prev_lane_root != lane_state->lane_root) {
      if (error) *error = "ingress-prev-lane-root-mismatch";
      return false;
    }
  } else if (cert.seq != 1) {
    if (error) *error = "ingress-first-seq-must-be-one";
    return false;
  }

  return true;
}

bool detect_ingress_equivocation(const std::optional<IngressCertificate>& existing, const IngressCertificate& incoming,
                                 std::string* error) {
  if (!existing.has_value()) return false;
  if (existing->epoch != incoming.epoch || existing->lane != incoming.lane || existing->seq != incoming.seq) return false;
  if (existing->serialize() == incoming.serialize()) return false;
  if (error) *error = "ingress-equivocation-detected";
  return true;
}

storage::IngressEquivocationEvidence make_ingress_equivocation_evidence(const IngressCertificate& existing,
                                                                        const IngressCertificate& incoming) {
  const Hash32 existing_cert_hash = crypto::sha256d(existing.serialize());
  const Hash32 incoming_cert_hash = crypto::sha256d(incoming.serialize());
  storage::IngressEquivocationEvidence rec;
  rec.epoch = existing.epoch;
  rec.lane = existing.lane;
  rec.seq = existing.seq;
  if (incoming_cert_hash < existing_cert_hash) {
    rec.first_cert_hash = incoming_cert_hash;
    rec.second_cert_hash = existing_cert_hash;
    rec.first_txid = incoming.txid;
    rec.second_txid = existing.txid;
    rec.first_tx_hash = incoming.tx_hash;
    rec.second_tx_hash = existing.tx_hash;
  } else {
    rec.first_cert_hash = existing_cert_hash;
    rec.second_cert_hash = incoming_cert_hash;
    rec.first_txid = existing.txid;
    rec.second_txid = incoming.txid;
    rec.first_tx_hash = existing.tx_hash;
    rec.second_tx_hash = incoming.tx_hash;
  }
  codec::ByteWriter w;
  static constexpr std::uint8_t kDomain[] = {'i', 'n', 'g', 'r', 'e', 's', 's', '-', 'e', 'q', 'u',
                                             'i', 'v', 'o', 'c', 'a', 't', 'i', 'o', 'n', '/', 'v', '1'};
  w.bytes(Bytes(kDomain, kDomain + sizeof(kDomain)));
  w.u64le(rec.epoch);
  w.u32le(rec.lane);
  w.u64le(rec.seq);
  w.bytes_fixed(rec.first_cert_hash);
  w.bytes_fixed(rec.second_cert_hash);
  rec.evidence_id = crypto::sha256d(w.take());
  return rec;
}

bool persist_ingress_equivocation_evidence(storage::DB& db, const IngressCertificate& existing,
                                           const IngressCertificate& incoming, std::string* error) {
  const auto rec = make_ingress_equivocation_evidence(existing, incoming);
  if (!db.put_ingress_equivocation_evidence(rec)) {
    if (error) *error = "ingress-equivocation-evidence-store-failed";
    return false;
  }
  return true;
}

bool append_validated_ingress_record(storage::DB& db, const IngressCertificate& cert, const Bytes& tx_bytes,
                                     const std::vector<PubKey32>& committee, std::string* error) {
  const auto lane_state = db.get_lane_state(cert.lane);
  if (!validate_ingress_payload(cert, tx_bytes, error)) return false;
  if (!verify_ingress_certificate(cert, committee, error)) return false;

  const auto existing_bytes = db.get_ingress_bytes(cert.txid);
  if (existing_bytes.has_value() && *existing_bytes != tx_bytes) {
    if (error) *error = "ingress-bytes-conflict";
    return false;
  }

  const auto existing_cert_bytes = db.get_ingress_certificate(cert.lane, cert.seq);
  if (existing_cert_bytes.has_value()) {
    const auto existing_cert = IngressCertificate::parse(*existing_cert_bytes);
    if (!existing_cert.has_value()) {
      if (error) *error = "stored-ingress-certificate-invalid";
      return false;
    }
    if (detect_ingress_equivocation(existing_cert, cert, error)) {
      std::string persist_error;
      if (!persist_ingress_equivocation_evidence(db, *existing_cert, cert, &persist_error)) {
        if (error) *error = persist_error;
      }
      return false;
    }
    if (*existing_cert == cert) return true;
  }

  if (lane_state.has_value()) {
    if (cert.seq != lane_state->max_seq + 1) {
      if (error) *error = "ingress-seq-discontinuity";
      return false;
    }
    if (cert.prev_lane_root != lane_state->lane_root) {
      if (error) *error = "ingress-prev-lane-root-mismatch";
      return false;
    }
  } else if (cert.seq != 1) {
    if (error) *error = "ingress-first-seq-must-be-one";
    return false;
  }

  if (!db.put_ingress_bytes(cert.txid, tx_bytes)) {
    if (error) *error = "ingress-bytes-store-failed";
    return false;
  }
  if (!db.put_ingress_certificate(cert.lane, cert.seq, cert.serialize())) {
    if (error && error->empty()) *error = "ingress-certificate-store-failed";
    return false;
  }

  LaneState next_state;
  next_state.epoch = cert.epoch;
  next_state.lane = cert.lane;
  next_state.max_seq = cert.seq;
  next_state.lane_root = compute_lane_root_append(lane_state.has_value() ? lane_state->lane_root : zero_hash(), cert.tx_hash);
  if (!db.put_lane_state(cert.lane, next_state)) {
    if (error) *error = "lane-state-store-failed";
    return false;
  }
  return true;
}

}  // namespace finalis::consensus
