// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "storage/db.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

constexpr std::uint32_t INGRESS_LANE_COUNT = static_cast<std::uint32_t>(finalis::INGRESS_LANE_COUNT);

Hash32 ingress_lane_anchor(const Tx& tx);
Hash32 ingress_lane_anchor(const TxV2& tx);
Hash32 ingress_lane_anchor(const AnyTx& tx);
std::uint32_t assign_ingress_lane(const Tx& tx);
// First height of the certifier term holding `height`. Terms of `term_blocks` tile each committee epoch
// (epochs start at 1, epoch_blocks + 1, ...); if term_blocks is 0 or does not divide epoch_blocks, a
// term is the whole epoch. An IngressCertificate's epoch field is this value: a certificate is valid
// only in its own term, and a new term starts each lane from its finalized tip (C1).
std::uint64_t ingress_certifier_term_start(std::uint64_t height, std::uint64_t epoch_blocks, std::uint64_t term_blocks);
// The committee member that certifies `lane` during the term starting at `term_start`: a per-term hash
// over the committee members in `live` (those seen signing recently), or over the whole committee if
// none of them is live. A censoring or offline certifier holds a lane for one term at most.
// Routing only: certificate validity does not depend on it, but two nodes that disagree would both
// certify the lane, so `live` must come from finalized data only.
PubKey32 designated_ingress_certifier(const std::vector<PubKey32>& committee, const std::set<PubKey32>& live,
                                      std::uint32_t lane, std::uint64_t term_start);
std::uint32_t assign_ingress_lane(const TxV2& tx);
std::uint32_t assign_ingress_lane(const AnyTx& tx);
Hash32 compute_lane_root_append(const Hash32& prev_root, const Hash32& tx_hash);

// An ordered (ingress) record is a Tx, a TxV2 or a TxTimed. A TxTimed is anchored on its fee input,
// like a Tx spending the same outpoint, so the two land in one lane and conflict there.
struct IngressRecordIdentity {
  Hash32 txid{};
  std::uint32_t lane{0};
  bool timed{false};
};
std::optional<IngressRecordIdentity> ingress_record_identity(const Bytes& tx_bytes);

// tx_bytes parse, and their txid, hash and lane match the certificate.
bool validate_ingress_payload(const IngressCertificate& cert, const Bytes& tx_bytes, std::string* error = nullptr);

bool validate_ingress_certificate_epoch(const IngressCertificate& cert, std::uint64_t expected_epoch,
                                       std::string* error = nullptr);

bool verify_ingress_certificate(const IngressCertificate& cert, const std::vector<PubKey32>& committee,
                                std::string* error = nullptr);

bool validate_ingress_append(const std::optional<LaneState>& lane_state, const IngressCertificate& cert, const Bytes& tx_bytes,
                             std::uint64_t expected_epoch = 0, std::string* error = nullptr);
bool validate_ingress_append(const std::optional<LaneState>& lane_state, const IngressCertificate& cert, const Bytes& tx_bytes,
                             std::string* error);

bool detect_ingress_equivocation(const std::optional<IngressCertificate>& existing, const IngressCertificate& incoming,
                                 std::string* error = nullptr);
storage::IngressEquivocationEvidence make_ingress_equivocation_evidence(const IngressCertificate& existing,
                                                                        const IngressCertificate& incoming);
bool persist_ingress_equivocation_evidence(storage::DB& db, const IngressCertificate& existing,
                                           const IngressCertificate& incoming, std::string* error = nullptr);

bool append_validated_ingress_record(storage::DB& db, const IngressCertificate& cert, const Bytes& tx_bytes,
                                     const std::vector<PubKey32>& committee, std::uint64_t expected_epoch = 0,
                                     std::string* error = nullptr);
bool append_validated_ingress_record(storage::DB& db, const IngressCertificate& cert, const Bytes& tx_bytes,
                                     const std::vector<PubKey32>& committee, std::string* error);

}  // namespace finalis::consensus
