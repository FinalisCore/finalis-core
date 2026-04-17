#pragma once

#include <optional>
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
std::uint32_t assign_ingress_lane(const TxV2& tx);
std::uint32_t assign_ingress_lane(const AnyTx& tx);
Hash32 compute_lane_root_append(const Hash32& prev_root, const Hash32& tx_hash);

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
