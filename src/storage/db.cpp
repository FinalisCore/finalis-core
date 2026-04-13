#include "storage/db.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>

#include "codec/bytes.hpp"
#include "common/paths.hpp"
#include "crypto/hash.hpp"

#ifdef SC_HAS_ROCKSDB
#include <rocksdb/db.h>
#endif

namespace finalis::storage {

namespace {

#ifdef SC_HAS_ROCKSDB
rocksdb::Status open_rocksdb_rw(const rocksdb::Options& options, const std::string& path,
                                std::unique_ptr<rocksdb::DB>* out) {
#ifdef _WIN32
  return rocksdb::DB::Open(options, path, out);
#else
  rocksdb::DB* raw = nullptr;
  auto status = rocksdb::DB::Open(options, path, &raw);
  if (status.ok()) out->reset(raw);
  return status;
#endif
}

rocksdb::Status open_rocksdb_ro(const rocksdb::Options& options, const std::string& path,
                                std::unique_ptr<rocksdb::DB>* out) {
#ifdef _WIN32
  return rocksdb::DB::OpenForReadOnly(options, path, out);
#else
  rocksdb::DB* raw = nullptr;
  auto status = rocksdb::DB::OpenForReadOnly(options, path, &raw);
  if (status.ok()) out->reset(raw);
  return status;
#endif
}
#endif

Bytes serialize_tip(const TipState& tip) {
  codec::ByteWriter w;
  w.u64le(tip.height);
  w.bytes_fixed(tip.hash);
  return w.take();
}

std::optional<TipState> parse_tip(const Bytes& b) {
  TipState t;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!h || !hash) return false;
        t.height = *h;
        t.hash = *hash;
        return true;
      })) {
    return std::nullopt;
  }
  return t;
}

Bytes serialize_outpoint(const OutPoint& op) {
  codec::ByteWriter w;
  w.bytes_fixed(op.txid);
  w.u32le(op.index);
  return w.take();
}

std::optional<OutPoint> parse_outpoint(const Bytes& b) {
  OutPoint op;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto tx = r.bytes_fixed<32>();
        auto idx = r.u32le();
        if (!tx || !idx) return false;
        op.txid = *tx;
        op.index = *idx;
        return true;
      })) {
    return std::nullopt;
  }
  return op;
}

Bytes serialize_txout(const TxOut& out) {
  codec::ByteWriter w;
  w.u64le(out.value);
  w.varbytes(out.script_pubkey);
  return w.take();
}

std::optional<TxOut> parse_txout(const Bytes& b) {
  TxOut out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto v = r.u64le();
        auto s = r.varbytes();
        if (!v || !s) return false;
        out.value = *v;
        out.script_pubkey = *s;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_validator(const consensus::ValidatorInfo& info) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(info.status));
  w.u64le(info.joined_height);
  w.bytes_fixed(info.operator_id);
  w.u8(info.has_bond ? 1 : 0);
  w.bytes_fixed(info.bond_outpoint.txid);
  w.u32le(info.bond_outpoint.index);
  w.u64le(info.unbond_height);
  w.u64le(info.eligible_count_window);
  w.u64le(info.participated_count_window);
  w.u64le(info.liveness_window_start);
  w.u64le(info.suspended_until_height);
  w.u64le(info.last_join_height);
  w.u64le(info.last_exit_height);
  w.u32le(info.penalty_strikes);
  w.u64le(info.bonded_amount);
  return w.take();
}

std::optional<consensus::ValidatorInfo> parse_validator(const Bytes& b) {
  consensus::ValidatorInfo info;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto st = r.u8();
        auto h = r.u64le();
        if (!st || !h) return false;
        info.status = static_cast<consensus::ValidatorStatus>(*st);
        info.joined_height = *h;
        if (r.eof()) {
          // Older validator records omitted bond metadata; keep the default bonded state.
          info.bonded_amount = BOND_AMOUNT;
          info.has_bond = true;
          info.unbond_height = 0;
          return true;
        }
        if (r.remaining() == 137) {
          auto operator_id = r.bytes_fixed<32>();
          if (!operator_id) return false;
          info.operator_id = *operator_id;
        }
        auto has_bond = r.u8();
        auto txid = r.bytes_fixed<32>();
        auto idx = r.u32le();
        auto unbond = r.u64le();
        if (!has_bond || !txid || !idx || !unbond) return false;
        info.has_bond = (*has_bond != 0);
        info.bond_outpoint = OutPoint{*txid, *idx};
        info.unbond_height = *unbond;
        if (r.eof()) return true;
        auto eligible = r.u64le();
        auto participated = r.u64le();
        auto lstart = r.u64le();
        auto suspended = r.u64le();
        auto last_join = r.u64le();
        auto last_exit = r.u64le();
        auto strikes = r.u32le();
        if (!eligible || !participated || !lstart || !suspended || !last_join || !last_exit || !strikes) return false;
        info.eligible_count_window = *eligible;
        info.participated_count_window = *participated;
        info.liveness_window_start = *lstart;
        info.suspended_until_height = *suspended;
        info.last_join_height = *last_join;
        info.last_exit_height = *last_exit;
        info.penalty_strikes = *strikes;
        if (!r.eof()) {
          auto bonded = r.u64le();
          if (!bonded || !r.eof()) return false;
          info.bonded_amount = *bonded;
        } else {
          info.bonded_amount = BOND_AMOUNT;
        }
        return true;
      })) {
    return std::nullopt;
  }
  return info;
}

Bytes serialize_validator_join_request(const ValidatorJoinRequest& req) {
  codec::ByteWriter w;
  w.bytes_fixed(req.request_txid);
  w.bytes_fixed(req.validator_pubkey);
  w.bytes_fixed(req.payout_pubkey);
  w.bytes_fixed(req.bond_outpoint.txid);
  w.u32le(req.bond_outpoint.index);
  w.u64le(req.bond_amount);
  w.u64le(req.requested_height);
  w.u64le(req.approved_height);
  w.u8(static_cast<std::uint8_t>(req.status));
  return w.take();
}

std::optional<ValidatorJoinRequest> parse_validator_join_request(const Bytes& b) {
  ValidatorJoinRequest req;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto request_txid = r.bytes_fixed<32>();
        auto validator_pub = r.bytes_fixed<32>();
        auto payout_pub = r.bytes_fixed<32>();
        auto bond_txid = r.bytes_fixed<32>();
        auto bond_index = r.u32le();
        auto bond_amount = r.u64le();
        auto requested_height = r.u64le();
        auto approved_height = r.u64le();
        auto status = r.u8();
        if (!request_txid || !validator_pub || !payout_pub || !bond_txid || !bond_index || !bond_amount ||
            !requested_height || !approved_height || !status) {
          return false;
        }
        req.request_txid = *request_txid;
        req.validator_pubkey = *validator_pub;
        req.payout_pubkey = *payout_pub;
        req.bond_outpoint = OutPoint{*bond_txid, *bond_index};
        req.bond_amount = *bond_amount;
        req.requested_height = *requested_height;
        req.approved_height = *approved_height;
        req.status = static_cast<ValidatorJoinRequestStatus>(*status);
        return true;
      })) {
    return std::nullopt;
  }
  return req;
}

Bytes serialize_slashing_record(const SlashingRecord& rec) {
  codec::ByteWriter w;
  w.bytes_fixed(rec.record_id);
  w.u8(static_cast<std::uint8_t>(rec.kind));
  w.bytes_fixed(rec.validator_pubkey);
  w.u64le(rec.height);
  w.u32le(rec.round);
  w.u64le(rec.observed_height);
  w.bytes_fixed(rec.object_a);
  w.bytes_fixed(rec.object_b);
  w.bytes_fixed(rec.txid);
  return w.take();
}

std::optional<SlashingRecord> parse_slashing_record(const Bytes& b) {
  SlashingRecord rec;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto rid = r.bytes_fixed<32>();
        auto kind = r.u8();
        auto pub = r.bytes_fixed<32>();
        auto height = r.u64le();
        auto round = r.u32le();
        auto observed = r.u64le();
        auto a = r.bytes_fixed<32>();
        auto c = r.bytes_fixed<32>();
        auto txid = r.bytes_fixed<32>();
        if (!rid || !kind || !pub || !height || !round || !observed || !a || !c || !txid) return false;
        rec.record_id = *rid;
        rec.kind = static_cast<SlashingRecordKind>(*kind);
        rec.validator_pubkey = *pub;
        rec.height = *height;
        rec.round = *round;
        rec.observed_height = *observed;
        rec.object_a = *a;
        rec.object_b = *c;
        rec.txid = *txid;
        return true;
      })) {
    return std::nullopt;
  }
  return rec;
}

Bytes serialize_ingress_equivocation_evidence(const IngressEquivocationEvidence& rec) {
  codec::ByteWriter w;
  w.bytes_fixed(rec.evidence_id);
  w.u64le(rec.epoch);
  w.u32le(rec.lane);
  w.u64le(rec.seq);
  w.bytes_fixed(rec.first_cert_hash);
  w.bytes_fixed(rec.second_cert_hash);
  w.bytes_fixed(rec.first_txid);
  w.bytes_fixed(rec.second_txid);
  w.bytes_fixed(rec.first_tx_hash);
  w.bytes_fixed(rec.second_tx_hash);
  return w.take();
}

std::optional<IngressEquivocationEvidence> parse_ingress_equivocation_evidence(const Bytes& b) {
  IngressEquivocationEvidence rec;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto evidence_id = r.bytes_fixed<32>();
        auto epoch = r.u64le();
        auto lane = r.u32le();
        auto seq = r.u64le();
        auto first_cert_hash = r.bytes_fixed<32>();
        auto second_cert_hash = r.bytes_fixed<32>();
        auto first_txid = r.bytes_fixed<32>();
        auto second_txid = r.bytes_fixed<32>();
        auto first_tx_hash = r.bytes_fixed<32>();
        auto second_tx_hash = r.bytes_fixed<32>();
        if (!evidence_id || !epoch || !lane || !seq || !first_cert_hash || !second_cert_hash || !first_txid ||
            !second_txid || !first_tx_hash || !second_tx_hash) {
          return false;
        }
        rec.evidence_id = *evidence_id;
        rec.epoch = *epoch;
        rec.lane = *lane;
        rec.seq = *seq;
        rec.first_cert_hash = *first_cert_hash;
        rec.second_cert_hash = *second_cert_hash;
        rec.first_txid = *first_txid;
        rec.second_txid = *second_txid;
        rec.first_tx_hash = *first_tx_hash;
        rec.second_tx_hash = *second_tx_hash;
        return true;
      })) {
    return std::nullopt;
  }
  return rec;
}

Bytes serialize_finalized_committee_checkpoint(const FinalizedCommitteeCheckpoint& checkpoint) {
  codec::ByteWriter w;
  w.u64le(checkpoint.epoch_start_height);
  w.bytes_fixed(checkpoint.epoch_seed);
  w.u8(checkpoint.ticket_difficulty_bits);
  w.varint(checkpoint.ordered_members.size());
  for (const auto& member : checkpoint.ordered_members) w.bytes_fixed(member);
  w.varint(checkpoint.ordered_ticket_hashes.size());
  for (const auto& hash : checkpoint.ordered_ticket_hashes) w.bytes_fixed(hash);
  w.varint(checkpoint.ordered_ticket_nonces.size());
  for (const auto nonce : checkpoint.ordered_ticket_nonces) w.u64le(nonce);
  w.varint(checkpoint.ordered_operator_ids.size());
  for (const auto& operator_id : checkpoint.ordered_operator_ids) w.bytes_fixed(operator_id);
  w.varint(checkpoint.ordered_base_weights.size());
  for (const auto base_weight : checkpoint.ordered_base_weights) w.u64le(base_weight);
  w.varint(checkpoint.ordered_ticket_bonus_bps.size());
  for (const auto ticket_bonus_bps : checkpoint.ordered_ticket_bonus_bps) w.u32le(ticket_bonus_bps);
  w.varint(checkpoint.ordered_final_weights.size());
  for (const auto final_weight : checkpoint.ordered_final_weights) w.u64le(final_weight);
  w.u8(static_cast<std::uint8_t>(checkpoint.derivation_mode));
  w.u8(static_cast<std::uint8_t>(checkpoint.fallback_reason));
  w.u64le(checkpoint.availability_eligible_operator_count);
  w.u64le(checkpoint.availability_min_eligible_operators);
  w.u64le(checkpoint.adaptive_target_committee_size);
  w.u64le(checkpoint.adaptive_min_eligible);
  w.u64le(checkpoint.adaptive_min_bond);
  w.u64le(checkpoint.qualified_depth);
  w.u32le(checkpoint.target_expand_streak);
  w.u32le(checkpoint.target_contract_streak);
  return w.take();
}

std::optional<FinalizedCommitteeCheckpoint> parse_finalized_committee_checkpoint(const Bytes& b) {
  FinalizedCommitteeCheckpoint checkpoint;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch_start = r.u64le();
        auto seed = r.bytes_fixed<32>();
        auto difficulty_bits = r.u8();
        auto count = r.varint();
        if (!epoch_start || !seed || !difficulty_bits || !count) return false;
        checkpoint.epoch_start_height = *epoch_start;
        checkpoint.epoch_seed = *seed;
        checkpoint.ticket_difficulty_bits = *difficulty_bits;
        checkpoint.ordered_members.clear();
        checkpoint.ordered_members.reserve(*count);
        for (std::uint64_t i = 0; i < *count; ++i) {
          auto member = r.bytes_fixed<32>();
          if (!member) return false;
          checkpoint.ordered_members.push_back(*member);
        }
        checkpoint.ordered_operator_ids.clear();
        checkpoint.ordered_base_weights.clear();
        checkpoint.ordered_ticket_bonus_bps.clear();
        checkpoint.ordered_final_weights.clear();
        checkpoint.ordered_ticket_hashes.clear();
        checkpoint.ordered_ticket_nonces.clear();
        if (!r.remaining()) return true;
        auto hash_count = r.varint();
        if (!hash_count) return false;
        checkpoint.ordered_ticket_hashes.reserve(*hash_count);
        for (std::uint64_t i = 0; i < *hash_count; ++i) {
          auto hash = r.bytes_fixed<32>();
          if (!hash) return false;
          checkpoint.ordered_ticket_hashes.push_back(*hash);
        }
        if (!r.remaining()) return true;
        auto nonce_count = r.varint();
        if (!nonce_count) return false;
        checkpoint.ordered_ticket_nonces.reserve(*nonce_count);
        for (std::uint64_t i = 0; i < *nonce_count; ++i) {
          auto nonce = r.u64le();
          if (!nonce) return false;
          checkpoint.ordered_ticket_nonces.push_back(*nonce);
        }
        if (!r.remaining()) return true;
        auto operator_count = r.varint();
        if (!operator_count) return false;
        checkpoint.ordered_operator_ids.reserve(*operator_count);
        for (std::uint64_t i = 0; i < *operator_count; ++i) {
          auto operator_id = r.bytes_fixed<32>();
          if (!operator_id) return false;
          checkpoint.ordered_operator_ids.push_back(*operator_id);
        }
        if (!r.remaining()) return true;
        auto base_weight_count = r.varint();
        if (!base_weight_count) return false;
        checkpoint.ordered_base_weights.reserve(*base_weight_count);
        for (std::uint64_t i = 0; i < *base_weight_count; ++i) {
          auto base_weight = r.u64le();
          if (!base_weight) return false;
          checkpoint.ordered_base_weights.push_back(*base_weight);
        }
        if (!r.remaining()) return true;
        auto ticket_bonus_count = r.varint();
        if (!ticket_bonus_count) return false;
        checkpoint.ordered_ticket_bonus_bps.reserve(*ticket_bonus_count);
        for (std::uint64_t i = 0; i < *ticket_bonus_count; ++i) {
          auto ticket_bonus = r.u32le();
          if (!ticket_bonus) return false;
          checkpoint.ordered_ticket_bonus_bps.push_back(*ticket_bonus);
        }
        if (!r.remaining()) return true;
        auto final_weight_count = r.varint();
        if (!final_weight_count) return false;
        checkpoint.ordered_final_weights.reserve(*final_weight_count);
        for (std::uint64_t i = 0; i < *final_weight_count; ++i) {
          auto final_weight = r.u64le();
          if (!final_weight) return false;
          checkpoint.ordered_final_weights.push_back(*final_weight);
        }
        if (!r.remaining()) return true;
        auto derivation_mode = r.u8();
        if (!derivation_mode) return false;
        if (*derivation_mode > static_cast<std::uint8_t>(FinalizedCommitteeDerivationMode::FALLBACK)) return false;
        checkpoint.derivation_mode = static_cast<FinalizedCommitteeDerivationMode>(*derivation_mode);
        if (!r.remaining()) return true;
        if (r.remaining() == 16) {
          auto eligible_count = r.u64le();
          auto min_eligible = r.u64le();
          if (!eligible_count || !min_eligible || !r.eof()) return false;
          checkpoint.availability_eligible_operator_count = *eligible_count;
          checkpoint.availability_min_eligible_operators = *min_eligible;
          if (checkpoint.derivation_mode == FinalizedCommitteeDerivationMode::FALLBACK &&
              checkpoint.availability_eligible_operator_count < checkpoint.availability_min_eligible_operators) {
            checkpoint.fallback_reason = FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
          }
          return true;
        }
        auto fallback_reason = r.u8();
        auto eligible_count = r.u64le();
        auto min_eligible = r.u64le();
        if (!fallback_reason || !eligible_count || !min_eligible) return false;
        if (*fallback_reason > static_cast<std::uint8_t>(FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING)) {
          return false;
        }
        checkpoint.fallback_reason = static_cast<FinalizedCommitteeFallbackReason>(*fallback_reason);
        checkpoint.availability_eligible_operator_count = *eligible_count;
        checkpoint.availability_min_eligible_operators = *min_eligible;
        if (!r.remaining()) return true;
        auto adaptive_target = r.u64le();
        auto adaptive_min_eligible = r.u64le();
        auto adaptive_min_bond = r.u64le();
        auto qualified_depth = r.u64le();
        auto expand_streak = r.u32le();
        auto contract_streak = r.u32le();
        if (!adaptive_target || !adaptive_min_eligible || !adaptive_min_bond || !qualified_depth || !expand_streak ||
            !contract_streak || !r.eof()) {
          return false;
        }
        checkpoint.adaptive_target_committee_size = *adaptive_target;
        checkpoint.adaptive_min_eligible = *adaptive_min_eligible;
        checkpoint.adaptive_min_bond = *adaptive_min_bond;
        checkpoint.qualified_depth = *qualified_depth;
        checkpoint.target_expand_streak = *expand_streak;
        checkpoint.target_contract_streak = *contract_streak;
        return true;
      })) {
    return std::nullopt;
  }
  return checkpoint;
}

Bytes serialize_epoch_reward_settlement(const EpochRewardSettlementState& state) {
  codec::ByteWriter w;
  w.u64le(state.epoch_start_height);
  w.u64le(state.total_reward_units);
  w.u8(state.settled ? 1 : 0);
  w.varint(state.reward_score_units.size());
  for (const auto& [pub, score] : state.reward_score_units) {
    w.bytes_fixed(pub);
    w.u64le(score);
  }
  w.varint(state.expected_participation_units.size());
  for (const auto& [pub, units] : state.expected_participation_units) {
    w.bytes_fixed(pub);
    w.u64le(units);
  }
  w.varint(state.observed_participation_units.size());
  for (const auto& [pub, units] : state.observed_participation_units) {
    w.bytes_fixed(pub);
    w.u64le(units);
  }
  w.u64le(state.fee_pool_units);
  w.u64le(state.reserve_accrual_units);
  w.u64le(state.reserve_subsidy_units);
  return w.take();
}

std::optional<EpochRewardSettlementState> parse_epoch_reward_settlement(const Bytes& b) {
  EpochRewardSettlementState state;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch_start = r.u64le();
        auto total_reward = r.u64le();
        auto settled = r.u8();
        auto count = r.varint();
        if (!epoch_start || !total_reward || !settled || !count) return false;
        state.epoch_start_height = *epoch_start;
        state.total_reward_units = *total_reward;
        state.fee_pool_units = 0;
        state.settled = (*settled != 0);
        state.reserve_subsidy_units = 0;
        state.reserve_accrual_units = 0;
        state.reward_score_units.clear();
        for (std::uint64_t i = 0; i < *count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto score = r.u64le();
          if (!pub || !score) return false;
          state.reward_score_units[*pub] = *score;
        }
        state.expected_participation_units.clear();
        state.observed_participation_units.clear();
        if (!r.remaining()) return true;
        auto expected_count = r.varint();
        if (!expected_count) return false;
        for (std::uint64_t i = 0; i < *expected_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto units = r.u64le();
          if (!pub || !units) return false;
          state.expected_participation_units[*pub] = *units;
        }
        if (!r.remaining()) return true;
        auto observed_count = r.varint();
        if (!observed_count) return false;
        for (std::uint64_t i = 0; i < *observed_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto units = r.u64le();
          if (!pub || !units) return false;
          state.observed_participation_units[*pub] = *units;
        }
        if (!r.remaining()) return true;
        auto fee_pool = r.u64le();
        if (!fee_pool) return false;
        state.fee_pool_units = *fee_pool;
        if (!r.remaining()) return true;
        auto reserve_accrual = r.u64le();
        if (!reserve_accrual) return false;
        state.reserve_accrual_units = *reserve_accrual;
        if (!r.remaining()) return true;
        auto reserve_subsidy = r.u64le();
        if (!reserve_subsidy || !r.eof()) return false;
        state.reserve_subsidy_units = *reserve_subsidy;
        return true;
      })) {
    return std::nullopt;
  }
  return state;
}

Bytes serialize_epoch_ticket(const consensus::EpochTicket& ticket) {
  codec::ByteWriter w;
  w.u64le(ticket.epoch);
  w.bytes_fixed(ticket.participant_pubkey);
  w.bytes_fixed(ticket.challenge_anchor);
  w.u64le(ticket.nonce);
  w.bytes_fixed(ticket.work_hash);
  w.u64le(ticket.source_height);
  w.u8(static_cast<std::uint8_t>(ticket.origin));
  return w.take();
}

std::optional<consensus::EpochTicket> parse_epoch_ticket(const Bytes& b) {
  consensus::EpochTicket ticket;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto pub = r.bytes_fixed<32>();
        auto anchor = r.bytes_fixed<32>();
        auto nonce = r.u64le();
        auto work = r.bytes_fixed<32>();
        auto source_height = r.u64le();
        if (!epoch || !pub || !anchor || !nonce || !work || !source_height) return false;
        ticket.epoch = *epoch;
        ticket.participant_pubkey = *pub;
        ticket.challenge_anchor = *anchor;
        ticket.nonce = *nonce;
        ticket.work_hash = *work;
        ticket.source_height = *source_height;
        if (!r.eof()) {
          auto origin = r.u8();
          if (!origin || !r.eof()) return false;
          ticket.origin = static_cast<consensus::EpochTicketOrigin>(*origin);
        } else {
          ticket.origin = consensus::EpochTicketOrigin::NETWORK;
        }
        return true;
      })) {
    return std::nullopt;
  }
  return ticket;
}

Bytes serialize_epoch_committee_snapshot(const consensus::EpochCommitteeSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u64le(snapshot.epoch);
  w.bytes_fixed(snapshot.challenge_anchor);
  w.varint(snapshot.selected_winners.size());
  for (const auto& winner : snapshot.selected_winners) {
    w.bytes_fixed(winner.participant_pubkey);
    w.bytes_fixed(winner.work_hash);
    w.u64le(winner.nonce);
    w.u64le(winner.source_height);
  }
  w.varint(snapshot.ordered_members.size());
  for (const auto& member : snapshot.ordered_members) w.bytes_fixed(member);
  return w.take();
}

std::optional<consensus::EpochCommitteeSnapshot> parse_epoch_committee_snapshot(const Bytes& b) {
  consensus::EpochCommitteeSnapshot snapshot;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto anchor = r.bytes_fixed<32>();
        auto winner_count = r.varint();
        if (!epoch || !anchor || !winner_count) return false;
        snapshot.epoch = *epoch;
        snapshot.challenge_anchor = *anchor;
        snapshot.selected_winners.clear();
        snapshot.selected_winners.reserve(*winner_count);
        for (std::uint64_t i = 0; i < *winner_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto work = r.bytes_fixed<32>();
          auto nonce = r.u64le();
          auto source_height = r.u64le();
          if (!pub || !work || !nonce || !source_height) return false;
          snapshot.selected_winners.push_back(consensus::EpochCommitteeMember{*pub, *work, *nonce, *source_height});
        }
        auto member_count = r.varint();
        if (!member_count) return false;
        snapshot.ordered_members.clear();
        snapshot.ordered_members.reserve(*member_count);
        for (std::uint64_t i = 0; i < *member_count; ++i) {
          auto member = r.bytes_fixed<32>();
          if (!member) return false;
          snapshot.ordered_members.push_back(*member);
        }
        return true;
      })) {
    return std::nullopt;
  }
  return snapshot;
}

Bytes serialize_epoch_committee_freeze_marker(const EpochCommitteeFreezeMarker& marker) {
  codec::ByteWriter w;
  w.u64le(marker.epoch);
  w.bytes_fixed(marker.challenge_anchor);
  w.u64le(marker.member_count);
  return w.take();
}

std::optional<EpochCommitteeFreezeMarker> parse_epoch_committee_freeze_marker(const Bytes& b) {
  EpochCommitteeFreezeMarker marker;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto anchor = r.bytes_fixed<32>();
        auto members = r.u64le();
        if (!epoch || !anchor || !members) return false;
        marker.epoch = *epoch;
        marker.challenge_anchor = *anchor;
        marker.member_count = *members;
        return true;
      })) {
    return std::nullopt;
  }
  return marker;
}

Bytes serialize_consensus_state_commitment_cache(const ConsensusStateCommitmentCache& cache) {
  codec::ByteWriter w;
  w.u64le(cache.height);
  w.bytes_fixed(cache.hash);
  w.bytes_fixed(cache.commitment);
  return w.take();
}

std::optional<ConsensusStateCommitmentCache> parse_consensus_state_commitment_cache(const Bytes& b) {
  ConsensusStateCommitmentCache cache;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto height = r.u64le();
        auto hash = r.bytes_fixed<32>();
        auto commitment = r.bytes_fixed<32>();
        if (!height || !hash || !commitment) return false;
        cache.height = *height;
        cache.hash = *hash;
        cache.commitment = *commitment;
        return true;
      })) {
    return std::nullopt;
  }
  return cache;
}

Bytes serialize_adaptive_epoch_telemetry(const AdaptiveEpochTelemetry& telemetry) {
  codec::ByteWriter w;
  w.u64le(telemetry.epoch_start_height);
  w.u64le(telemetry.derivation_height);
  w.u64le(telemetry.qualified_depth);
  w.u64le(telemetry.adaptive_target_committee_size);
  w.u64le(telemetry.adaptive_min_eligible);
  w.u64le(telemetry.adaptive_min_bond);
  w.u64le(static_cast<std::uint64_t>(telemetry.slack) ^ 0x8000000000000000ULL);
  w.u32le(telemetry.target_expand_streak);
  w.u32le(telemetry.target_contract_streak);
  w.u8(static_cast<std::uint8_t>(telemetry.derivation_mode));
  w.u8(static_cast<std::uint8_t>(telemetry.fallback_reason));
  w.u8(telemetry.fallback_sticky ? 1 : 0);
  w.u64le(telemetry.committee_size_selected);
  w.u64le(telemetry.eligible_operator_count);
  return w.take();
}

std::optional<AdaptiveEpochTelemetry> parse_adaptive_epoch_telemetry(const Bytes& b) {
  AdaptiveEpochTelemetry telemetry;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch_start = r.u64le();
        auto derivation_height = r.u64le();
        auto qualified_depth = r.u64le();
        auto adaptive_target = r.u64le();
        auto adaptive_min_eligible = r.u64le();
        auto adaptive_min_bond = r.u64le();
        auto slack = r.u64le();
        auto expand_streak = r.u32le();
        auto contract_streak = r.u32le();
        auto derivation_mode = r.u8();
        auto fallback_reason = r.u8();
        auto fallback_sticky = r.u8();
        auto committee_size_selected = r.u64le();
        auto eligible_operator_count = r.u64le();
        if (!epoch_start || !derivation_height || !qualified_depth || !adaptive_target || !adaptive_min_eligible ||
            !adaptive_min_bond || !slack || !expand_streak || !contract_streak || !derivation_mode ||
            !fallback_reason || !fallback_sticky || !committee_size_selected || !eligible_operator_count) {
          return false;
        }
        telemetry.epoch_start_height = *epoch_start;
        telemetry.derivation_height = *derivation_height;
        telemetry.qualified_depth = *qualified_depth;
        telemetry.adaptive_target_committee_size = *adaptive_target;
        telemetry.adaptive_min_eligible = *adaptive_min_eligible;
        telemetry.adaptive_min_bond = *adaptive_min_bond;
        telemetry.slack = static_cast<std::int64_t>(*slack ^ 0x8000000000000000ULL);
        telemetry.target_expand_streak = *expand_streak;
        telemetry.target_contract_streak = *contract_streak;
        telemetry.derivation_mode = static_cast<FinalizedCommitteeDerivationMode>(*derivation_mode);
        telemetry.fallback_reason = static_cast<FinalizedCommitteeFallbackReason>(*fallback_reason);
        telemetry.fallback_sticky = (*fallback_sticky != 0);
        telemetry.committee_size_selected = *committee_size_selected;
        telemetry.eligible_operator_count = *eligible_operator_count;
        return true;
      })) {
    return std::nullopt;
  }
  return telemetry;
}

Bytes serialize_node_runtime_status_snapshot(const NodeRuntimeStatusSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u8(snapshot.chain_id_ok ? 1 : 0);
  w.u8(snapshot.db_open ? 1 : 0);
  w.u64le(snapshot.local_finalized_height);
  w.u8(snapshot.observed_network_height_known ? 1 : 0);
  w.u64le(snapshot.observed_network_finalized_height);
  w.u64le(static_cast<std::uint64_t>(snapshot.healthy_peer_count));
  w.u64le(static_cast<std::uint64_t>(snapshot.established_peer_count));
  w.u64le(snapshot.finalized_lag);
  w.u8(snapshot.peer_height_disagreement ? 1 : 0);
  w.u8(snapshot.next_height_committee_available ? 1 : 0);
  w.u8(snapshot.next_height_proposer_available ? 1 : 0);
  w.u8(snapshot.bootstrap_sync_incomplete ? 1 : 0);
  w.u8(snapshot.registration_ready_preflight ? 1 : 0);
  w.u8(snapshot.registration_ready ? 1 : 0);
  w.u32le(snapshot.readiness_stable_samples);
  w.varbytes(Bytes(snapshot.readiness_blockers_csv.begin(), snapshot.readiness_blockers_csv.end()));
  w.u64le(snapshot.captured_at_unix_ms);
  w.u64le(snapshot.mempool_tx_count);
  w.u64le(snapshot.mempool_bytes);
  w.u8(snapshot.mempool_full ? 1 : 0);
  w.u8(snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte.has_value() ? 1 : 0);
  if (snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte.has_value()) {
    w.u64le(*snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte);
  }
  w.u64le(snapshot.rejected_full_not_good_enough);
  w.u64le(snapshot.evicted_for_better_incoming);
  w.u64le(snapshot.min_relay_fee);
  w.u64le(snapshot.availability_epoch);
  w.u64le(snapshot.availability_retained_prefix_count);
  w.u64le(snapshot.availability_tracked_operator_count);
  w.u64le(snapshot.availability_eligible_operator_count);
  w.u8(snapshot.availability_below_min_eligible ? 1 : 0);
  w.u8(snapshot.availability_local_operator_known ? 1 : 0);
  w.bytes_fixed(snapshot.availability_local_operator_pubkey);
  w.u8(snapshot.availability_local_operator_status);
  w.u64le(static_cast<std::uint64_t>(snapshot.availability_local_service_score) ^ 0x8000000000000000ULL);
  w.u64le(snapshot.availability_local_warmup_epochs);
  w.u64le(snapshot.availability_local_successful_audits);
  w.u64le(snapshot.availability_local_late_audits);
  w.u64le(snapshot.availability_local_missed_audits);
  w.u64le(snapshot.availability_local_invalid_audits);
  w.u64le(snapshot.availability_local_retained_prefix_count);
  w.u64le(static_cast<std::uint64_t>(snapshot.availability_local_eligibility_score) ^ 0x8000000000000000ULL);
  w.u32le(snapshot.availability_local_seat_budget);
  w.u8(snapshot.availability_checkpoint_derivation_mode);
  w.u8(snapshot.availability_checkpoint_fallback_reason);
  w.u8(snapshot.availability_fallback_sticky ? 1 : 0);
  w.u8(snapshot.availability_state_rebuild_triggered ? 1 : 0);
  w.varbytes(Bytes(snapshot.availability_state_rebuild_reason.begin(), snapshot.availability_state_rebuild_reason.end()));
  w.u64le(snapshot.adaptive_target_committee_size);
  w.u64le(snapshot.adaptive_min_eligible);
  w.u64le(snapshot.adaptive_min_bond);
  w.u64le(snapshot.qualified_depth);
  w.u64le(static_cast<std::uint64_t>(snapshot.adaptive_slack) ^ 0x8000000000000000ULL);
  w.u32le(snapshot.target_expand_streak);
  w.u32le(snapshot.target_contract_streak);
  w.u32le(snapshot.adaptive_fallback_rate_bps);
  w.u32le(snapshot.adaptive_sticky_fallback_rate_bps);
  w.u32le(snapshot.adaptive_fallback_window_epochs);
  w.u8(snapshot.adaptive_near_threshold_operation ? 1 : 0);
  w.u8(snapshot.adaptive_prolonged_expand_buildup ? 1 : 0);
  w.u8(snapshot.adaptive_prolonged_contract_buildup ? 1 : 0);
  w.u8(snapshot.adaptive_repeated_sticky_fallback ? 1 : 0);
  w.u8(snapshot.adaptive_depth_collapse_after_bond_increase ? 1 : 0);
  return w.take();
}

std::optional<NodeRuntimeStatusSnapshot> parse_node_runtime_status_snapshot(const Bytes& b) {
  NodeRuntimeStatusSnapshot snapshot;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto chain_ok = r.u8();
        auto db_open = r.u8();
        auto local_height = r.u64le();
        auto observed_known = r.u8();
        auto observed_height = r.u64le();
        auto healthy_peers = r.u64le();
        auto established_peers = r.u64le();
        auto lag = r.u64le();
        auto disagreement = r.u8();
        auto committee_available = r.u8();
        auto proposer_available = r.u8();
        auto bootstrap_incomplete = r.u8();
        auto ready_preflight = r.u8();
        auto ready = r.u8();
        auto stable_samples = r.u32le();
        auto blockers = r.varbytes();
        auto captured_at = r.u64le();
        if (!chain_ok || !db_open || !local_height || !observed_known || !observed_height || !healthy_peers ||
            !established_peers || !lag || !disagreement || !committee_available || !proposer_available ||
            !bootstrap_incomplete || !ready_preflight || !ready || !stable_samples || !blockers || !captured_at) {
          return false;
        }
        snapshot.chain_id_ok = (*chain_ok != 0);
        snapshot.db_open = (*db_open != 0);
        snapshot.local_finalized_height = *local_height;
        snapshot.observed_network_height_known = (*observed_known != 0);
        snapshot.observed_network_finalized_height = *observed_height;
        snapshot.healthy_peer_count = static_cast<std::size_t>(*healthy_peers);
        snapshot.established_peer_count = static_cast<std::size_t>(*established_peers);
        snapshot.finalized_lag = *lag;
        snapshot.peer_height_disagreement = (*disagreement != 0);
        snapshot.next_height_committee_available = (*committee_available != 0);
        snapshot.next_height_proposer_available = (*proposer_available != 0);
        snapshot.bootstrap_sync_incomplete = (*bootstrap_incomplete != 0);
        snapshot.registration_ready_preflight = (*ready_preflight != 0);
        snapshot.registration_ready = (*ready != 0);
        snapshot.readiness_stable_samples = *stable_samples;
        snapshot.readiness_blockers_csv = std::string(blockers->begin(), blockers->end());
        snapshot.captured_at_unix_ms = *captured_at;
        if (r.eof()) return true;
        auto mempool_tx_count = r.u64le();
        auto mempool_bytes = r.u64le();
        auto mempool_full = r.u8();
        auto has_min_fee_rate = r.u8();
        if (!mempool_tx_count || !mempool_bytes || !mempool_full || !has_min_fee_rate) return false;
        snapshot.mempool_tx_count = *mempool_tx_count;
        snapshot.mempool_bytes = *mempool_bytes;
        snapshot.mempool_full = (*mempool_full != 0);
        if (*has_min_fee_rate != 0) {
          auto min_fee_rate = r.u64le();
          if (!min_fee_rate) return false;
          snapshot.min_fee_rate_to_enter_when_full_milliunits_per_byte = *min_fee_rate;
        }
        auto rejected_full = r.u64le();
        auto evicted = r.u64le();
        auto min_relay_fee = r.u64le();
        if (!rejected_full || !evicted || !min_relay_fee) return false;
        snapshot.rejected_full_not_good_enough = *rejected_full;
        snapshot.evicted_for_better_incoming = *evicted;
        snapshot.min_relay_fee = *min_relay_fee;
        if (r.eof()) return true;
        auto availability_epoch = r.u64le();
        auto retained_prefixes = r.u64le();
        auto tracked_operators = r.u64le();
        auto eligible_operators = r.u64le();
        auto below_min = r.u8();
        auto local_known = r.u8();
        auto local_pub = r.bytes_fixed<32>();
        auto local_status = r.u8();
        auto local_score = r.u64le();
        auto local_warmup = r.u64le();
        auto local_successful = r.u64le();
        auto local_late = r.u64le();
        auto local_missed = r.u64le();
        auto local_invalid = r.u64le();
        auto local_retained = r.u64le();
        auto local_eligibility = r.u64le();
        auto local_seat_budget = r.u32le();
        if (!availability_epoch || !retained_prefixes || !tracked_operators || !eligible_operators || !below_min ||
            !local_known || !local_pub || !local_status || !local_score || !local_warmup || !local_successful ||
            !local_late || !local_missed || !local_invalid || !local_retained || !local_eligibility ||
            !local_seat_budget) {
          return false;
        }
        snapshot.availability_epoch = *availability_epoch;
        snapshot.availability_retained_prefix_count = *retained_prefixes;
        snapshot.availability_tracked_operator_count = *tracked_operators;
        snapshot.availability_eligible_operator_count = *eligible_operators;
        snapshot.availability_below_min_eligible = (*below_min != 0);
        if (r.eof()) return true;
        auto checkpoint_mode = r.u8();
        auto checkpoint_reason = r.u8();
        auto fallback_sticky = r.u8();
        if (!checkpoint_mode || !checkpoint_reason || !fallback_sticky) return false;
        snapshot.availability_checkpoint_derivation_mode = *checkpoint_mode;
        snapshot.availability_checkpoint_fallback_reason = *checkpoint_reason;
        snapshot.availability_fallback_sticky = (*fallback_sticky != 0);
        if (r.eof()) return true;
        auto rebuild_triggered = r.u8();
        auto rebuild_reason = r.varbytes();
        if (!rebuild_triggered || !rebuild_reason) return false;
        snapshot.availability_state_rebuild_triggered = (*rebuild_triggered != 0);
        snapshot.availability_state_rebuild_reason = std::string(rebuild_reason->begin(), rebuild_reason->end());
        if (r.eof()) return true;
        auto adaptive_target = r.u64le();
        auto adaptive_min_eligible = r.u64le();
        auto adaptive_min_bond = r.u64le();
        auto qualified_depth = r.u64le();
        auto adaptive_slack = r.u64le();
        auto expand_streak = r.u32le();
        auto contract_streak = r.u32le();
        auto fallback_rate_bps = r.u32le();
        auto sticky_fallback_rate_bps = r.u32le();
        auto fallback_window_epochs = r.u32le();
        auto near_threshold = r.u8();
        auto expand_buildup = r.u8();
        auto contract_buildup = r.u8();
        auto repeated_sticky = r.u8();
        auto depth_collapse = r.u8();
        if (!adaptive_target || !adaptive_min_eligible || !adaptive_min_bond || !qualified_depth || !adaptive_slack ||
            !expand_streak || !contract_streak || !fallback_rate_bps || !sticky_fallback_rate_bps ||
            !fallback_window_epochs || !near_threshold || !expand_buildup || !contract_buildup || !repeated_sticky ||
            !depth_collapse) {
          return false;
        }
        snapshot.adaptive_target_committee_size = *adaptive_target;
        snapshot.adaptive_min_eligible = *adaptive_min_eligible;
        snapshot.adaptive_min_bond = *adaptive_min_bond;
        snapshot.qualified_depth = *qualified_depth;
        snapshot.adaptive_slack = static_cast<std::int64_t>(*adaptive_slack ^ 0x8000000000000000ULL);
        snapshot.target_expand_streak = *expand_streak;
        snapshot.target_contract_streak = *contract_streak;
        snapshot.adaptive_fallback_rate_bps = *fallback_rate_bps;
        snapshot.adaptive_sticky_fallback_rate_bps = *sticky_fallback_rate_bps;
        snapshot.adaptive_fallback_window_epochs = *fallback_window_epochs;
        snapshot.adaptive_near_threshold_operation = (*near_threshold != 0);
        snapshot.adaptive_prolonged_expand_buildup = (*expand_buildup != 0);
        snapshot.adaptive_prolonged_contract_buildup = (*contract_buildup != 0);
        snapshot.adaptive_repeated_sticky_fallback = (*repeated_sticky != 0);
        snapshot.adaptive_depth_collapse_after_bond_increase = (*depth_collapse != 0);
        snapshot.availability_local_operator_known = (*local_known != 0);
        snapshot.availability_local_operator_pubkey = *local_pub;
        snapshot.availability_local_operator_status = *local_status;
        snapshot.availability_local_service_score =
            static_cast<std::int64_t>(*local_score ^ 0x8000000000000000ULL);
        snapshot.availability_local_warmup_epochs = *local_warmup;
        snapshot.availability_local_successful_audits = *local_successful;
        snapshot.availability_local_late_audits = *local_late;
        snapshot.availability_local_missed_audits = *local_missed;
        snapshot.availability_local_invalid_audits = *local_invalid;
        snapshot.availability_local_retained_prefix_count = *local_retained;
        snapshot.availability_local_eligibility_score =
            static_cast<std::int64_t>(*local_eligibility ^ 0x8000000000000000ULL);
        snapshot.availability_local_seat_budget = *local_seat_budget;
        return true;
      })) {
    return std::nullopt;
  }
  return snapshot;
}

Bytes u64be_bytes(std::uint64_t v) {
  Bytes out(8);
  for (int i = 7; i >= 0; --i) {
    out[7 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
  }
  return out;
}

}  // namespace

std::string key_finality_certificate_height(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "FC:H:" + hex_encode(w.data());
}
std::string key_tip() { return "T:"; }
std::string key_genesis_hash() { return "G:"; }
std::string key_genesis_artifact() { return "GB:"; }
std::string key_genesis_json() { return "G:J"; }
std::string key_root_index(const std::string& kind, std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "ROOT:" + kind + ":" + hex_encode(w.data());
}
std::string key_root_index_prefix() { return "ROOT:"; }
std::string key_finality_certificate_height_prefix() { return "FC:H:"; }
std::string key_height(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "H:" + hex_encode(w.data());
}
std::string key_height_prefix() { return "H:"; }
std::string key_utxo_prefix() { return "U:"; }
std::string key_utxo(const OutPoint& op) { return "U:" + hex_encode(serialize_outpoint(op)); }
std::string key_validator_prefix() { return "V:"; }
std::string key_validator(const PubKey32& pub) { return "V:" + hex_encode(Bytes(pub.begin(), pub.end())); }
std::string key_validator_join_request(const Hash32& request_txid) {
  return "VJR:" + hex_encode(Bytes(request_txid.begin(), request_txid.end()));
}
std::string key_slashing_record(const Hash32& record_id) {
  return "SL:" + hex_encode(Bytes(record_id.begin(), record_id.end()));
}
std::string key_finalized_committee_checkpoint(std::uint64_t epoch_start_height) {
  codec::ByteWriter w;
  w.u64le(epoch_start_height);
  return "CE:" + hex_encode(w.data());
}

std::string key_epoch_reward_settlement(std::uint64_t epoch_start_height) {
  codec::ByteWriter w;
  w.u64le(epoch_start_height);
  return "ER:" + hex_encode(w.data());
}
std::string key_adaptive_epoch_telemetry(std::uint64_t epoch_start_height) {
  codec::ByteWriter w;
  w.u64le(epoch_start_height);
  return "AT:" + hex_encode(w.data());
}
std::string key_adaptive_epoch_telemetry_prefix() { return "AT:"; }
std::string key_epoch_prefix(std::uint64_t epoch) { return hex_encode(u64be_bytes(epoch)); }
std::string key_epoch_ticket_prefix(std::uint64_t epoch) { return "ET:" + key_epoch_prefix(epoch) + ":"; }
std::string key_epoch_ticket(const consensus::EpochTicket& ticket) {
  codec::ByteWriter w;
  w.u64le(ticket.nonce);
  return key_epoch_ticket_prefix(ticket.epoch) + hex_encode(Bytes(ticket.participant_pubkey.begin(), ticket.participant_pubkey.end())) +
         ":" + hex_encode(Bytes(ticket.work_hash.begin(), ticket.work_hash.end())) + ":" + hex_encode(w.data());
}
std::string key_best_epoch_ticket(std::uint64_t epoch, const PubKey32& pub) {
  return "EB:" + key_epoch_prefix(epoch) + ":" + hex_encode(Bytes(pub.begin(), pub.end()));
}
std::string key_epoch_committee_snapshot(std::uint64_t epoch) { return "EC:" + key_epoch_prefix(epoch); }
std::string key_epoch_committee_freeze_marker(std::uint64_t epoch) { return "ECF:" + key_epoch_prefix(epoch); }
std::string key_node_runtime_status_snapshot() { return "NRS"; }
std::string key_availability_persistent_state() { return "APS"; }
std::string key_consensus_state_commitment_cache() { return "CSC:TIP"; }
std::string key_protocol_reserve_balance() { return "PRB"; }
std::string key_validator_onboarding(const PubKey32& pub) { return "VO:" + hex_encode(Bytes(pub.begin(), pub.end())); }
std::string key_txidx_prefix() { return "X:"; }
std::string key_txidx(const Hash32& txid) { return "X:" + hex_encode(Bytes(txid.begin(), txid.end())); }
std::string key_ingress_record_prefix() { return "IR:"; }
std::string key_ingress_record(std::uint64_t seq) { return "IR:" + hex_encode(u64be_bytes(seq)); }
std::string key_finalized_ingress_tip() { return "IFTIP"; }
std::string key_ingress_certificate_prefix() { return "IC:"; }
std::string key_ingress_certificate(std::uint32_t lane, std::uint64_t seq) {
  codec::ByteWriter w;
  w.u32le(lane);
  return "IC:" + hex_encode(w.data()) + ":" + hex_encode(u64be_bytes(seq));
}
std::string key_ingress_bytes_prefix() { return "IB:"; }
std::string key_ingress_bytes(const Hash32& txid) { return "IB:" + hex_encode(Bytes(txid.begin(), txid.end())); }
std::string key_lane_state_prefix() { return "ILS:"; }
std::string key_lane_state(std::uint32_t lane) {
  codec::ByteWriter w;
  w.u32le(lane);
  return "ILS:" + hex_encode(w.data());
}
std::string key_ingress_equivocation_prefix() { return "IE:"; }
std::string key_ingress_equivocation(std::uint64_t epoch, std::uint32_t lane, std::uint64_t seq) {
  codec::ByteWriter w;
  w.u64le(epoch);
  w.u32le(lane);
  w.u64le(seq);
  return "IE:" + hex_encode(w.data());
}
std::string key_frontier_transition_prefix() { return "FT:"; }
std::string key_frontier_transition(const Hash32& id) { return "FT:" + hex_encode(Bytes(id.begin(), id.end())); }
std::string key_finalized_frontier_height() { return "FFH"; }
std::string key_frontier_height_prefix() { return "FH:"; }
std::string key_frontier_height(std::uint64_t height) { return "FH:" + hex_encode(u64be_bytes(height)); }
std::string key_smt_leaf_prefix(const std::string& tree_id) { return "SMTL:" + tree_id + ":"; }
std::string key_smt_leaf(const std::string& tree_id, const Hash32& key) {
  return key_smt_leaf_prefix(tree_id) + hex_encode(Bytes(key.begin(), key.end()));
}
std::string key_smt_root_prefix(const std::string& tree_id) { return "SMTR:" + tree_id + ":"; }
std::string key_smt_root(const std::string& tree_id, std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return key_smt_root_prefix(tree_id) + hex_encode(w.data());
}
std::string key_script_utxo_prefix(const Hash32& scripthash) {
  return "SU:" + hex_encode(Bytes(scripthash.begin(), scripthash.end())) + ":";
}
std::string key_script_utxo(const Hash32& scripthash, const OutPoint& op) {
  return key_script_utxo_prefix(scripthash) + hex_encode(serialize_outpoint(op));
}
std::string key_script_history_prefix(const Hash32& scripthash) {
  return "SH:" + hex_encode(Bytes(scripthash.begin(), scripthash.end())) + ":";
}
std::string key_script_history(const Hash32& scripthash, std::uint64_t height, const Hash32& txid) {
  return key_script_history_prefix(scripthash) + hex_encode(u64be_bytes(height)) + ":" +
         hex_encode(Bytes(txid.begin(), txid.end()));
}

#ifdef SC_HAS_ROCKSDB
class DB::RocksImpl {
 public:
  std::unique_ptr<rocksdb::DB> db;
};
#endif

DB::DB() = default;
DB::~DB() = default;

bool DB::open(const std::string& path) {
  path_ = expand_user_home(path);
  (void)ensure_private_dir(path_);
  readonly_ = false;
#ifdef SC_HAS_ROCKSDB
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  rocks_ = std::make_unique<RocksImpl>();
  rocksdb::Options options;
  options.create_if_missing = true;
  std::unique_ptr<rocksdb::DB> raw;
  auto s = open_rocksdb_rw(options, path_, &raw);
  if (!s.ok()) return false;
  rocks_->db = std::move(raw);
  return true;
#else
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  return load_file();
#endif
}

bool DB::open_readonly(const std::string& path) {
  path_ = expand_user_home(path);
  (void)ensure_private_dir(path_);
  readonly_ = true;
#ifdef SC_HAS_ROCKSDB
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  rocks_ = std::make_unique<RocksImpl>();
  rocksdb::Options options;
  options.create_if_missing = false;
  std::unique_ptr<rocksdb::DB> raw;
  auto s = open_rocksdb_ro(options, path_, &raw);
  if (!s.ok()) return false;
  rocks_->db = std::move(raw);
  return true;
#else
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  return load_file();
#endif
}

bool DB::put(const std::string& key, const Bytes& value) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Put(rocksdb::WriteOptions(), key, rocksdb::Slice(reinterpret_cast<const char*>(value.data()), value.size()));
  return s.ok();
#else
  mem_[key] = value;
  return flush_file();
#endif
}

std::optional<Bytes> DB::get(const std::string& key) const {
#ifdef SC_HAS_ROCKSDB
  std::string v;
  auto s = rocks_->db->Get(rocksdb::ReadOptions(), key, &v);
  if (!s.ok()) return std::nullopt;
  return Bytes(v.begin(), v.end());
#else
  auto it = mem_.find(key);
  if (it == mem_.end()) return std::nullopt;
  return it->second;
#endif
}

bool DB::erase(const std::string& key) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Delete(rocksdb::WriteOptions(), key);
  return s.ok();
#else
  mem_.erase(key);
  return flush_file();
#endif
}

std::map<std::string, Bytes> DB::scan_prefix(const std::string& prefix) const {
  std::map<std::string, Bytes> out;
#ifdef SC_HAS_ROCKSDB
  std::unique_ptr<rocksdb::Iterator> it(rocks_->db->NewIterator(rocksdb::ReadOptions()));
  for (it->Seek(prefix); it->Valid(); it->Next()) {
    std::string k = it->key().ToString();
    if (k.rfind(prefix, 0) != 0) break;
    out[k] = Bytes(it->value().data(), it->value().data() + it->value().size());
  }
#else
  for (const auto& [k, v] : mem_) {
    if (k.rfind(prefix, 0) == 0) out[k] = v;
  }
#endif
  return out;
}

bool DB::set_tip(const TipState& tip) { return put(key_tip(), serialize_tip(tip)); }

std::optional<TipState> DB::get_tip() const {
  auto b = get(key_tip());
  if (!b.has_value()) return std::nullopt;
  return parse_tip(*b);
}

bool DB::put_finality_certificate(const FinalityCertificate& cert) {
  if (auto existing = get_finality_certificate_by_height(cert.height); existing.has_value()) {
    if (existing->frontier_transition_id != cert.frontier_transition_id || existing->serialize() != cert.serialize()) {
      std::cerr << "finalized-state-invariant-violation source=db-write-finality-certificate height=" << cert.height
                << " existing_hash=" << hex_encode(Bytes(existing->frontier_transition_id.begin(), existing->frontier_transition_id.end()))
                << " conflicting_hash=" << hex_encode(Bytes(cert.frontier_transition_id.begin(), cert.frontier_transition_id.end())) << "\n";
      return false;
    }
  }
  const Bytes bytes = cert.serialize();
  return put(key_finality_certificate_height(cert.height), bytes);
}

std::optional<FinalityCertificate> DB::get_finality_certificate_by_height(std::uint64_t height) const {
  auto b = get(key_finality_certificate_height(height));
  if (!b.has_value()) return std::nullopt;
  return FinalityCertificate::parse(*b);
}

bool DB::set_height_hash(std::uint64_t height, const Hash32& hash) {
  if (auto existing = get_height_hash(height); existing.has_value() && *existing != hash) {
    std::cerr << "finalized-state-invariant-violation source=db-write-height-index height=" << height
              << " existing_hash=" << hex_encode(Bytes(existing->begin(), existing->end()))
              << " conflicting_hash=" << hex_encode(Bytes(hash.begin(), hash.end())) << "\n";
    return false;
  }
  return put(key_height(height), Bytes(hash.begin(), hash.end()));
}

std::optional<Hash32> DB::get_height_hash(std::uint64_t height) const {
  auto b = get(key_height(height));
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 h{};
  std::copy(b->begin(), b->end(), h.begin());
  return h;
}

bool DB::put_utxo(const OutPoint& op, const TxOut& out) { return put(key_utxo(op), serialize_txout(out)); }
bool DB::put_utxo_v2(const OutPoint& op, const UtxoEntryV2& entry) { return put(key_utxo(op), serialize_utxo_entry_v2(entry)); }
bool DB::erase_utxo(const OutPoint& op) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Delete(rocksdb::WriteOptions(), key_utxo(op));
  return s.ok();
#else
  mem_.erase(key_utxo(op));
  return flush_file();
#endif
}

std::optional<TxOut> DB::get_utxo(const OutPoint& op) const {
  auto raw = get(key_utxo(op));
  if (!raw.has_value()) return std::nullopt;
  return parse_txout(*raw);
}

std::optional<UtxoEntryV2> DB::get_utxo_v2(const OutPoint& op) const {
  auto raw = get(key_utxo(op));
  if (!raw.has_value()) return std::nullopt;
  if (auto parsed = parse_utxo_entry_v2(*raw); parsed.has_value()) return parsed;
  auto legacy = parse_txout(*raw);
  if (!legacy.has_value()) return std::nullopt;
  return UtxoEntryV2{*legacy};
}

std::map<OutPoint, UtxoEntry> DB::load_utxos() const {
  std::map<OutPoint, UtxoEntry> out;
  for (const auto& [k, v] : scan_prefix(key_utxo_prefix())) {
    auto op_hex = k.substr(2);
    auto op_b = hex_decode(op_hex);
    if (!op_b.has_value()) continue;
    auto op = parse_outpoint(*op_b);
    if (!op.has_value()) continue;
    if (auto entry_v2 = parse_utxo_entry_v2(v); entry_v2.has_value()) {
      const auto transparent = transparent_txout_from_utxo_entry(*entry_v2);
      if (!transparent.has_value()) continue;
      out[*op] = UtxoEntry{*transparent};
      continue;
    }
    auto txout = parse_txout(v);
    if (!txout.has_value()) continue;
    out[*op] = UtxoEntry{*txout};
  }
  return out;
}

std::map<OutPoint, UtxoEntryV2> DB::load_utxos_v2() const {
  std::map<OutPoint, UtxoEntryV2> out;
  for (const auto& [k, v] : scan_prefix(key_utxo_prefix())) {
    auto op_hex = k.substr(2);
    auto op_b = hex_decode(op_hex);
    if (!op_b.has_value()) continue;
    auto op = parse_outpoint(*op_b);
    if (!op.has_value()) continue;
    auto entry = parse_utxo_entry_v2(v);
    if (entry.has_value()) {
      out[*op] = *entry;
      continue;
    }
    auto txout = parse_txout(v);
    if (!txout.has_value()) continue;
    out[*op] = UtxoEntryV2{*txout};
  }
  return out;
}

bool DB::put_validator(const PubKey32& pub, const consensus::ValidatorInfo& info) {
  return put(key_validator(pub), serialize_validator(info));
}

std::map<PubKey32, consensus::ValidatorInfo> DB::load_validators() const {
  std::map<PubKey32, consensus::ValidatorInfo> out;
  for (const auto& [k, v] : scan_prefix(key_validator_prefix())) {
    auto hex = k.substr(2);
    auto b = hex_decode(hex);
    auto info = parse_validator(v);
    if (!b.has_value() || b->size() != 32 || !info.has_value()) continue;
    PubKey32 pub{};
    std::copy(b->begin(), b->end(), pub.begin());
    if (info->operator_id == PubKey32{}) info->operator_id = pub;
    out[pub] = *info;
  }
  return out;
}

bool DB::put_validator_join_request(const Hash32& request_txid, const ValidatorJoinRequest& req) {
  return put(key_validator_join_request(request_txid), serialize_validator_join_request(req));
}

std::map<Hash32, ValidatorJoinRequest> DB::load_validator_join_requests() const {
  std::map<Hash32, ValidatorJoinRequest> out;
  for (const auto& [k, v] : scan_prefix("VJR:")) {
    auto hex = k.substr(4);
    auto b = hex_decode(hex);
    auto req = parse_validator_join_request(v);
    if (!b.has_value() || b->size() != 32 || !req.has_value()) continue;
    Hash32 request_txid{};
    std::copy(b->begin(), b->end(), request_txid.begin());
    out[request_txid] = *req;
  }
  return out;
}

bool DB::put_slashing_record(const SlashingRecord& rec) {
  return put(key_slashing_record(rec.record_id), serialize_slashing_record(rec));
}

std::map<Hash32, SlashingRecord> DB::load_slashing_records() const {
  std::map<Hash32, SlashingRecord> out;
  for (const auto& [k, v] : scan_prefix("SL:")) {
    auto rec = parse_slashing_record(v);
    if (!rec.has_value()) continue;
    out[rec->record_id] = *rec;
  }
  return out;
}

bool DB::put_ingress_equivocation_evidence(const IngressEquivocationEvidence& rec) {
  const auto key = key_ingress_equivocation(rec.epoch, rec.lane, rec.seq);
  const Bytes bytes = serialize_ingress_equivocation_evidence(rec);
  if (auto existing = get(key); existing.has_value()) {
    if (*existing != bytes) {
      std::cerr << "finalized-state-invariant-violation source=db-write-ingress-equivocation epoch=" << rec.epoch
                << " lane=" << rec.lane << " seq=" << rec.seq << " detail=conflicting-rewrite\n";
      return false;
    }
    return true;
  }
  return put(key, bytes);
}

std::optional<IngressEquivocationEvidence> DB::get_ingress_equivocation_evidence(std::uint64_t epoch, std::uint32_t lane,
                                                                                  std::uint64_t seq) const {
  auto b = get(key_ingress_equivocation(epoch, lane, seq));
  if (!b.has_value()) return std::nullopt;
  return parse_ingress_equivocation_evidence(*b);
}

std::map<Hash32, IngressEquivocationEvidence> DB::load_ingress_equivocation_evidence() const {
  std::map<Hash32, IngressEquivocationEvidence> out;
  for (const auto& [_, v] : scan_prefix(key_ingress_equivocation_prefix())) {
    auto rec = parse_ingress_equivocation_evidence(v);
    if (!rec.has_value()) continue;
    out[rec->evidence_id] = *rec;
  }
  return out;
}

bool DB::put_finalized_committee_checkpoint(const FinalizedCommitteeCheckpoint& checkpoint) {
  return put(key_finalized_committee_checkpoint(checkpoint.epoch_start_height),
             serialize_finalized_committee_checkpoint(checkpoint));
}

std::optional<FinalizedCommitteeCheckpoint> DB::get_finalized_committee_checkpoint(std::uint64_t epoch_start_height) const {
  auto b = get(key_finalized_committee_checkpoint(epoch_start_height));
  if (!b.has_value()) return std::nullopt;
  return parse_finalized_committee_checkpoint(*b);
}

std::map<std::uint64_t, FinalizedCommitteeCheckpoint> DB::load_finalized_committee_checkpoints() const {
  std::map<std::uint64_t, FinalizedCommitteeCheckpoint> out;
  for (const auto& [_, v] : scan_prefix("CE:")) {
    auto checkpoint = parse_finalized_committee_checkpoint(v);
    if (!checkpoint.has_value()) continue;
    out[checkpoint->epoch_start_height] = *checkpoint;
  }
  return out;
}

bool DB::put_epoch_reward_settlement(const EpochRewardSettlementState& state) {
  return put(key_epoch_reward_settlement(state.epoch_start_height), serialize_epoch_reward_settlement(state));
}

std::optional<EpochRewardSettlementState> DB::get_epoch_reward_settlement(std::uint64_t epoch_start_height) const {
  auto b = get(key_epoch_reward_settlement(epoch_start_height));
  if (!b.has_value()) return std::nullopt;
  return parse_epoch_reward_settlement(*b);
}

std::map<std::uint64_t, EpochRewardSettlementState> DB::load_epoch_reward_settlements() const {
  std::map<std::uint64_t, EpochRewardSettlementState> out;
  for (const auto& [_, v] : scan_prefix("ER:")) {
    auto state = parse_epoch_reward_settlement(v);
    if (!state.has_value()) continue;
    out[state->epoch_start_height] = *state;
  }
  return out;
}

bool DB::put_protocol_reserve_balance(std::uint64_t balance_units) {
  codec::ByteWriter w;
  w.u64le(balance_units);
  return put(key_protocol_reserve_balance(), w.take());
}

std::optional<std::uint64_t> DB::get_protocol_reserve_balance() const {
  auto b = get(key_protocol_reserve_balance());
  if (!b.has_value()) return std::nullopt;
  std::optional<std::uint64_t> out;
  if (!codec::parse_exact(*b, [&](codec::ByteReader& r) {
        auto value = r.u64le();
        if (!value || !r.eof()) return false;
        out = *value;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

bool DB::put_epoch_ticket(const consensus::EpochTicket& ticket) { return put(key_epoch_ticket(ticket), serialize_epoch_ticket(ticket)); }

std::vector<consensus::EpochTicket> DB::load_epoch_tickets(std::uint64_t epoch) const {
  std::vector<consensus::EpochTicket> out;
  for (const auto& [_, v] : scan_prefix(key_epoch_ticket_prefix(epoch))) {
    auto ticket = parse_epoch_ticket(v);
    if (!ticket.has_value()) continue;
    out.push_back(*ticket);
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.work_hash != b.work_hash) return a.work_hash < b.work_hash;
    if (a.participant_pubkey != b.participant_pubkey) return a.participant_pubkey < b.participant_pubkey;
    if (a.nonce != b.nonce) return a.nonce < b.nonce;
    return a.source_height < b.source_height;
  });
  return out;
}

std::vector<std::uint64_t> DB::load_epoch_ticket_epochs() const {
  std::vector<std::uint64_t> out;
  std::optional<std::uint64_t> last;
  for (const auto& [k, _] : scan_prefix("ET:")) {
    if (k.size() < 19) continue;
    const std::string epoch_hex = k.substr(3, 16);
    auto b = hex_decode(epoch_hex);
    if (!b.has_value() || b->size() != 8) continue;
    std::uint64_t epoch = 0;
    for (std::size_t i = 0; i < 8; ++i) epoch = (epoch << 8) | (*b)[i];
    if (last.has_value() && *last == epoch) continue;
    out.push_back(epoch);
    last = epoch;
  }
  return out;
}

bool DB::put_best_epoch_ticket(const consensus::EpochBestTicket& ticket) {
  return put(key_best_epoch_ticket(ticket.epoch, ticket.participant_pubkey), serialize_epoch_ticket(ticket));
}

std::map<PubKey32, consensus::EpochBestTicket> DB::load_best_epoch_tickets(std::uint64_t epoch) const {
  std::map<PubKey32, consensus::EpochBestTicket> out;
  const std::string prefix = "EB:" + key_epoch_prefix(epoch) + ":";
  for (const auto& [_, v] : scan_prefix(prefix)) {
    auto ticket = parse_epoch_ticket(v);
    if (!ticket.has_value()) continue;
    out[ticket->participant_pubkey] = *ticket;
  }
  return out;
}

bool DB::clear_best_epoch_tickets(std::uint64_t epoch) {
  if (readonly_) return false;
  const std::string prefix = "EB:" + key_epoch_prefix(epoch) + ":";
#ifdef SC_HAS_ROCKSDB
  std::vector<std::string> keys;
  for (const auto& [k, _] : scan_prefix(prefix)) keys.push_back(k);
  for (const auto& k : keys) {
    auto s = rocks_->db->Delete(rocksdb::WriteOptions(), k);
    if (!s.ok()) return false;
  }
  return true;
#else
  for (const auto& [k, _] : scan_prefix(prefix)) mem_.erase(k);
  return flush_file();
#endif
}

bool DB::put_epoch_committee_snapshot(const consensus::EpochCommitteeSnapshot& snapshot) {
  return put(key_epoch_committee_snapshot(snapshot.epoch), serialize_epoch_committee_snapshot(snapshot));
}

std::optional<consensus::EpochCommitteeSnapshot> DB::get_epoch_committee_snapshot(std::uint64_t epoch) const {
  auto b = get(key_epoch_committee_snapshot(epoch));
  if (!b.has_value()) return std::nullopt;
  return parse_epoch_committee_snapshot(*b);
}

std::map<std::uint64_t, consensus::EpochCommitteeSnapshot> DB::load_epoch_committee_snapshots() const {
  std::map<std::uint64_t, consensus::EpochCommitteeSnapshot> out;
  for (const auto& [_, v] : scan_prefix("EC:")) {
    auto snapshot = parse_epoch_committee_snapshot(v);
    if (!snapshot.has_value()) continue;
    out[snapshot->epoch] = *snapshot;
  }
  return out;
}

bool DB::put_epoch_committee_freeze_marker(const EpochCommitteeFreezeMarker& marker) {
  return put(key_epoch_committee_freeze_marker(marker.epoch), serialize_epoch_committee_freeze_marker(marker));
}

std::optional<EpochCommitteeFreezeMarker> DB::get_epoch_committee_freeze_marker(std::uint64_t epoch) const {
  auto b = get(key_epoch_committee_freeze_marker(epoch));
  if (!b.has_value()) return std::nullopt;
  return parse_epoch_committee_freeze_marker(*b);
}

std::map<std::uint64_t, EpochCommitteeFreezeMarker> DB::load_epoch_committee_freeze_markers() const {
  std::map<std::uint64_t, EpochCommitteeFreezeMarker> out;
  for (const auto& [_, v] : scan_prefix("ECF:")) {
    auto marker = parse_epoch_committee_freeze_marker(v);
    if (!marker.has_value()) continue;
    out[marker->epoch] = *marker;
  }
  return out;
}

bool DB::put_node_runtime_status_snapshot(const NodeRuntimeStatusSnapshot& snapshot) {
  return put(key_node_runtime_status_snapshot(), serialize_node_runtime_status_snapshot(snapshot));
}

std::optional<NodeRuntimeStatusSnapshot> DB::get_node_runtime_status_snapshot() const {
  auto b = get(key_node_runtime_status_snapshot());
  if (!b.has_value()) return std::nullopt;
  return parse_node_runtime_status_snapshot(*b);
}

bool DB::put_adaptive_epoch_telemetry(const AdaptiveEpochTelemetry& telemetry) {
  return put(key_adaptive_epoch_telemetry(telemetry.epoch_start_height), serialize_adaptive_epoch_telemetry(telemetry));
}

std::optional<AdaptiveEpochTelemetry> DB::get_adaptive_epoch_telemetry(std::uint64_t epoch_start_height) const {
  auto b = get(key_adaptive_epoch_telemetry(epoch_start_height));
  if (!b.has_value()) return std::nullopt;
  return parse_adaptive_epoch_telemetry(*b);
}

std::map<std::uint64_t, AdaptiveEpochTelemetry> DB::load_adaptive_epoch_telemetry() const {
  std::map<std::uint64_t, AdaptiveEpochTelemetry> out;
  for (const auto& [_, v] : scan_prefix("AT:")) {
    auto telemetry = parse_adaptive_epoch_telemetry(v);
    if (!telemetry.has_value()) continue;
    out[telemetry->epoch_start_height] = *telemetry;
  }
  return out;
}

bool DB::put_availability_persistent_state(const availability::AvailabilityPersistentState& state) {
  return put(key_availability_persistent_state(), state.serialize());
}

std::optional<availability::AvailabilityPersistentState> DB::get_availability_persistent_state() const {
  auto b = get(key_availability_persistent_state());
  if (!b.has_value()) return std::nullopt;
  return availability::AvailabilityPersistentState::parse(*b);
}

bool DB::put_consensus_state_commitment_cache(const ConsensusStateCommitmentCache& cache) {
  return put(key_consensus_state_commitment_cache(), serialize_consensus_state_commitment_cache(cache));
}

std::optional<ConsensusStateCommitmentCache> DB::get_consensus_state_commitment_cache() const {
  auto b = get(key_consensus_state_commitment_cache());
  if (!b.has_value()) return std::nullopt;
  return parse_consensus_state_commitment_cache(*b);
}

bool DB::put_validator_onboarding_record(const PubKey32& pub, const Bytes& value) {
  return put(key_validator_onboarding(pub), value);
}

std::optional<Bytes> DB::get_validator_onboarding_record(const PubKey32& pub) const {
  return get(key_validator_onboarding(pub));
}

std::map<PubKey32, Bytes> DB::load_validator_onboarding_records() const {
  std::map<PubKey32, Bytes> out;
  for (const auto& [k, v] : scan_prefix("VO:")) {
    auto hex = k.substr(3);
    auto pub = hex_decode(hex);
    if (!pub.has_value() || pub->size() != 32) continue;
    PubKey32 key{};
    std::copy(pub->begin(), pub->end(), key.begin());
    out.emplace(key, v);
  }
  return out;
}

bool DB::erase_validator_onboarding_record(const PubKey32& pub) {
  return erase(key_validator_onboarding(pub));
}

bool DB::put_tx_index(const Hash32& txid, std::uint64_t height, std::uint32_t tx_index, const Bytes& tx_bytes) {
  codec::ByteWriter w;
  w.u64le(height);
  w.u32le(tx_index);
  w.varbytes(tx_bytes);
  return put(key_txidx(txid), w.take());
}

std::optional<DB::TxLocation> DB::get_tx_index(const Hash32& txid) const {
  auto b = get(key_txidx(txid));
  if (!b.has_value()) return std::nullopt;
  TxLocation out;
  if (!codec::parse_exact(*b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto i = r.u32le();
        auto tx = r.varbytes();
        if (!h || !i || !tx) return false;
        out.height = *h;
        out.tx_index = *i;
        out.tx_bytes = *tx;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

bool DB::put_ingress_record(std::uint64_t seq, const Bytes& record_bytes) {
  const auto key = key_ingress_record(seq);
  if (auto existing = get(key); existing.has_value() && *existing != record_bytes) {
    std::cerr << "finalized-state-invariant-violation source=db-write-ingress-record seq=" << seq << "\n";
    return false;
  }
  return put(key, record_bytes);
}

std::optional<Bytes> DB::get_ingress_record(std::uint64_t seq) const { return get(key_ingress_record(seq)); }

std::vector<Bytes> DB::load_ingress_slice(std::uint64_t from_exclusive, std::uint64_t to_inclusive) const {
  std::vector<Bytes> out;
  if (to_inclusive <= from_exclusive) return out;
  for (std::uint64_t seq = from_exclusive + 1; seq <= to_inclusive; ++seq) {
    auto record = get_ingress_record(seq);
    if (!record.has_value()) break;
    out.push_back(*record);
  }
  return out;
}

bool DB::ingress_slice_matches(std::uint64_t from_exclusive, const std::vector<Bytes>& ordered_records) const {
  std::uint64_t seq = from_exclusive;
  for (const auto& record_bytes : ordered_records) {
    ++seq;
    auto stored = get_ingress_record(seq);
    if (!stored.has_value() || *stored != record_bytes) return false;
  }
  return true;
}

bool DB::set_finalized_ingress_tip(std::uint64_t seq) {
  if (auto existing = get_finalized_ingress_tip(); existing.has_value() && *existing > seq) {
    std::cerr << "finalized-state-invariant-violation source=db-set-finalized-ingress-tip seq=" << seq
              << " existing=" << *existing << "\n";
    return false;
  }
  codec::ByteWriter w;
  w.u64le(seq);
  return put(key_finalized_ingress_tip(), w.take());
}

std::optional<std::uint64_t> DB::get_finalized_ingress_tip() const {
  auto b = get(key_finalized_ingress_tip());
  if (!b.has_value()) return std::nullopt;
  std::uint64_t out = 0;
  if (!codec::parse_exact(*b, [&](codec::ByteReader& r) {
        auto seq = r.u64le();
        if (!seq) return false;
        out = *seq;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

bool DB::put_ingress_certificate(std::uint32_t lane, std::uint64_t seq, const Bytes& cert_bytes) {
  auto cert = IngressCertificate::parse(cert_bytes);
  if (!cert.has_value() || cert->lane != lane || cert->seq != seq) {
    std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
              << " seq=" << seq << " detail=invalid-certificate\n";
    return false;
  }
  if (!get_ingress_bytes(cert->txid).has_value()) {
    std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
              << " seq=" << seq << " detail=missing-ingress-bytes\n";
    return false;
  }
  const auto key = key_ingress_certificate(lane, seq);
  if (auto existing = get(key); existing.has_value()) {
    if (*existing != cert_bytes) {
      std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
                << " seq=" << seq << " detail=conflicting-rewrite\n";
      return false;
    }
    return true;
  }

  auto state = get_lane_state(lane);
  if (state.has_value()) {
    if (seq <= state->max_seq) {
      std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
                << " seq=" << seq << " existing=" << state->max_seq << " detail=rewind\n";
      return false;
    }
    if (seq != state->max_seq + 1) {
      std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
                << " seq=" << seq << " existing=" << state->max_seq << " detail=gap\n";
      return false;
    }
    if (cert->prev_lane_root != state->lane_root) {
      std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
                << " seq=" << seq << " detail=prev-lane-root-mismatch\n";
      return false;
    }
  } else if (seq != 1) {
    std::cerr << "finalized-state-invariant-violation source=db-write-ingress-certificate lane=" << lane
              << " seq=" << seq << " detail=missing-lane-state\n";
    return false;
  }

  return put(key, cert_bytes);
}

std::optional<Bytes> DB::get_ingress_certificate(std::uint32_t lane, std::uint64_t seq) const {
  return get(key_ingress_certificate(lane, seq));
}

bool DB::put_ingress_bytes(const Hash32& txid, const Bytes& tx_bytes) {
  const auto key = key_ingress_bytes(txid);
  if (auto existing = get(key); existing.has_value() && *existing != tx_bytes) {
    std::cerr << "finalized-state-invariant-violation source=db-write-ingress-bytes txid="
              << hex_encode(Bytes(txid.begin(), txid.end())) << "\n";
    return false;
  }
  return put(key, tx_bytes);
}

std::optional<Bytes> DB::get_ingress_bytes(const Hash32& txid) const { return get(key_ingress_bytes(txid)); }

bool DB::put_lane_state(std::uint32_t lane, const LaneState& state) {
  if (state.lane != lane) {
    std::cerr << "finalized-state-invariant-violation source=db-write-lane-state lane=" << lane
              << " detail=lane-mismatch\n";
    return false;
  }
  const auto key = key_lane_state(lane);
  if (auto existing = get_lane_state(lane); existing.has_value()) {
    if (existing->max_seq > state.max_seq) {
      std::cerr << "finalized-state-invariant-violation source=db-write-lane-state lane=" << lane
                << " seq=" << state.max_seq << " existing=" << existing->max_seq << " detail=rewind\n";
      return false;
    }
    if (existing->max_seq == state.max_seq && *existing != state) {
      std::cerr << "finalized-state-invariant-violation source=db-write-lane-state lane=" << lane
                << " seq=" << state.max_seq << " detail=conflicting-rewrite\n";
      return false;
    }
  }
  return put(key, state.serialize());
}

std::optional<LaneState> DB::get_lane_state(std::uint32_t lane) const {
  auto b = get(key_lane_state(lane));
  if (!b.has_value()) return std::nullopt;
  return LaneState::parse(*b);
}

std::vector<Bytes> DB::load_ingress_lane_range(std::uint32_t lane, std::uint64_t from_seq, std::uint64_t to_seq) const {
  std::vector<Bytes> out;
  if (to_seq < from_seq) return out;
  for (std::uint64_t seq = from_seq; seq <= to_seq; ++seq) {
    auto cert = get_ingress_certificate(lane, seq);
    if (!cert.has_value()) break;
    out.push_back(*cert);
  }
  return out;
}

bool DB::put_frontier_transition(const Hash32& id, const Bytes& transition_bytes) {
  const auto key = key_frontier_transition(id);
  if (auto existing = get(key); existing.has_value() && *existing != transition_bytes) {
    std::cerr << "finalized-state-invariant-violation source=db-write-frontier-transition id="
              << hex_encode(Bytes(id.begin(), id.end())) << "\n";
    return false;
  }
  return put(key, transition_bytes);
}

std::optional<Bytes> DB::get_frontier_transition(const Hash32& id) const { return get(key_frontier_transition(id)); }

bool DB::set_finalized_frontier_height(std::uint64_t height) {
  if (auto existing = get_finalized_frontier_height(); existing.has_value() && *existing > height) {
    std::cerr << "finalized-state-invariant-violation source=db-set-finalized-frontier-height height=" << height
              << " existing=" << *existing << "\n";
    return false;
  }
  codec::ByteWriter w;
  w.u64le(height);
  return put(key_finalized_frontier_height(), w.take());
}

std::optional<std::uint64_t> DB::get_finalized_frontier_height() const {
  auto b = get(key_finalized_frontier_height());
  if (!b.has_value()) return std::nullopt;
  std::uint64_t out = 0;
  if (!codec::parse_exact(*b, [&](codec::ByteReader& r) {
        auto height = r.u64le();
        if (!height) return false;
        out = *height;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

bool DB::map_height_to_frontier_transition(std::uint64_t height, const Hash32& id) {
  const auto key = key_frontier_height(height);
  const Bytes value(id.begin(), id.end());
  if (auto existing = get(key); existing.has_value() && *existing != value) {
    std::cerr << "finalized-state-invariant-violation source=db-map-frontier-height height=" << height << "\n";
    return false;
  }
  return put(key, value);
}

std::optional<Hash32> DB::get_frontier_transition_by_height(std::uint64_t height) const {
  auto b = get(key_frontier_height(height));
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

bool DB::put_script_utxo(const Hash32& scripthash, const OutPoint& op, const TxOut& out, std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  w.u64le(out.value);
  w.varbytes(out.script_pubkey);
  return put(key_script_utxo(scripthash, op), w.take());
}

bool DB::erase_script_utxo(const Hash32& scripthash, const OutPoint& op) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Delete(rocksdb::WriteOptions(), key_script_utxo(scripthash, op));
  return s.ok();
#else
  mem_.erase(key_script_utxo(scripthash, op));
  return flush_file();
#endif
}

std::vector<DB::ScriptUtxoEntry> DB::get_script_utxos(const Hash32& scripthash) const {
  std::vector<ScriptUtxoEntry> out;
  const std::string prefix = key_script_utxo_prefix(scripthash);
  for (const auto& [k, v] : scan_prefix(prefix)) {
    const std::string op_hex = k.substr(prefix.size());
    auto op_b = hex_decode(op_hex);
    if (!op_b.has_value()) continue;
    auto op = parse_outpoint(*op_b);
    if (!op.has_value()) continue;

    ScriptUtxoEntry e;
    e.outpoint = *op;
    if (!codec::parse_exact(v, [&](codec::ByteReader& r) {
          auto h = r.u64le();
          auto val = r.u64le();
          auto spk = r.varbytes();
          if (!h || !val || !spk) return false;
          e.height = *h;
          e.value = *val;
          e.script_pubkey = *spk;
          return true;
        })) {
      continue;
    }
    out.push_back(std::move(e));
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.height != b.height) return a.height < b.height;
    return std::tie(a.outpoint.txid, a.outpoint.index) < std::tie(b.outpoint.txid, b.outpoint.index);
  });
  return out;
}

bool DB::add_script_history(const Hash32& scripthash, std::uint64_t height, const Hash32& txid) {
  return put(key_script_history(scripthash, height, txid), {});
}

bool DB::flush() {
#ifdef SC_HAS_ROCKSDB
  if (!rocks_ || !rocks_->db) return false;
  rocksdb::FlushOptions opts;
  opts.wait = true;
  auto s = rocks_->db->Flush(opts);
  return s.ok();
#else
  return flush_file();
#endif
}

void DB::close() {
#ifdef SC_HAS_ROCKSDB
  rocks_.reset();
#else
  mem_.clear();
#endif
}

std::vector<DB::ScriptHistoryEntry> DB::get_script_history(const Hash32& scripthash) const {
  std::vector<ScriptHistoryEntry> out;
  const std::string prefix = key_script_history_prefix(scripthash);
  for (const auto& [k, _] : scan_prefix(prefix)) {
    const std::string rest = k.substr(prefix.size());
    const auto pos = rest.find(':');
    if (pos == std::string::npos) continue;
    const std::string h_hex = rest.substr(0, pos);
    const std::string txid_hex = rest.substr(pos + 1);
    auto hb = hex_decode(h_hex);
    auto tb = hex_decode(txid_hex);
    if (!hb.has_value() || hb->size() != 8 || !tb.has_value() || tb->size() != 32) continue;

    std::uint64_t height = 0;
    for (size_t i = 0; i < 8; ++i) {
      height = (height << 8) | (*hb)[i];
    }
    Hash32 txid{};
    std::copy(tb->begin(), tb->end(), txid.begin());
    out.push_back(ScriptHistoryEntry{txid, height});
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.height != b.height) return a.height < b.height;
    return a.txid < b.txid;
  });
  return out;
}

AdaptiveTelemetrySummary summarize_adaptive_epoch_telemetry(
    const std::map<std::uint64_t, AdaptiveEpochTelemetry>& telemetry_by_epoch, std::size_t window_epochs) {
  AdaptiveTelemetrySummary summary;
  summary.window_epochs = static_cast<std::uint32_t>(window_epochs);
  if (telemetry_by_epoch.empty() || window_epochs == 0) return summary;

  std::vector<const AdaptiveEpochTelemetry*> ordered;
  ordered.reserve(telemetry_by_epoch.size());
  for (const auto& [_, telemetry] : telemetry_by_epoch) ordered.push_back(&telemetry);
  const std::size_t begin = ordered.size() > window_epochs ? (ordered.size() - window_epochs) : 0;
  const std::size_t samples = ordered.size() - begin;
  summary.sample_count = static_cast<std::uint32_t>(samples);
  if (samples == 0) return summary;

  for (std::size_t i = begin; i < ordered.size(); ++i) {
    const auto& current = *ordered[i];
    if (current.derivation_mode == FinalizedCommitteeDerivationMode::FALLBACK) ++summary.fallback_epochs;
    if (current.fallback_sticky) ++summary.sticky_fallback_epochs;
  }
  summary.fallback_rate_bps =
      static_cast<std::uint32_t>((static_cast<std::uint64_t>(summary.fallback_epochs) * 10000ULL) / samples);
  summary.sticky_fallback_rate_bps =
      static_cast<std::uint32_t>((static_cast<std::uint64_t>(summary.sticky_fallback_epochs) * 10000ULL) / samples);

  const auto& latest = *ordered.back();
  summary.near_threshold_operation = latest.slack <= 1;
  summary.prolonged_expand_buildup =
      latest.adaptive_target_committee_size == 16 && latest.target_expand_streak >= 3;
  summary.prolonged_contract_buildup =
      latest.adaptive_target_committee_size == 24 && latest.target_contract_streak >= 5;
  summary.repeated_sticky_fallback = summary.sticky_fallback_epochs >= 2;

  for (std::size_t i = begin + 1; i < ordered.size(); ++i) {
    const auto& prev = *ordered[i - 1];
    const auto& current = *ordered[i];
    if (current.adaptive_min_bond > prev.adaptive_min_bond && current.qualified_depth + 2 <= prev.qualified_depth) {
      summary.depth_collapse_after_bond_increase = true;
      break;
    }
  }
  return summary;
}

#ifndef SC_HAS_ROCKSDB
bool DB::flush_file() const {
  codec::ByteWriter w;
  w.varint(mem_.size());
  for (const auto& [k, v] : mem_) {
    w.varbytes(Bytes(k.begin(), k.end()));
    w.varbytes(v);
  }
  std::ofstream f(path_ + "/kv.bin", std::ios::binary | std::ios::trunc);
  if (!f.good()) return false;
  const auto& d = w.data();
  f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size()));
  return f.good();
}

bool DB::load_file() {
  mem_.clear();
  std::ifstream f(path_ + "/kv.bin", std::ios::binary);
  if (!f.good()) return true;
  std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  Bytes b(raw.begin(), raw.end());
  codec::ByteReader r(b);
  auto n = r.varint();
  if (!n.has_value()) return false;
  for (std::uint64_t i = 0; i < *n; ++i) {
    auto k = r.varbytes();
    auto v = r.varbytes();
    if (!k || !v) return false;
    mem_[std::string(k->begin(), k->end())] = *v;
  }
  return r.eof();
}
#endif

}  // namespace finalis::storage
