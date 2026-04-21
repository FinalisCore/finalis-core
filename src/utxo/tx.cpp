// SPDX-License-Identifier: MIT

#include "utxo/tx.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis {
namespace {
constexpr std::uint64_t kMaxTxInputs = 10'000;
constexpr std::uint64_t kMaxTxOutputs = 10'000;
constexpr std::size_t kMaxScriptBytes = 256 * 1024;
constexpr std::size_t kMaxMemoBytes = 64 * 1024;
}  // namespace

Bytes serialize_utxo_entry_v2(const UtxoEntryV2& entry) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(entry.kind));
  if (entry.kind == UtxoOutputKind::Transparent) {
    const auto& transparent = std::get<UtxoTransparentData>(entry.body);
    w.u64le(transparent.out.value);
    w.varbytes(transparent.out.script_pubkey);
    return w.take();
  }
  const auto& confidential = std::get<UtxoConfidentialData>(entry.body);
  w.bytes_fixed(confidential.value_commitment.bytes);
  w.bytes_fixed(confidential.one_time_pubkey);
  w.bytes_fixed(confidential.ephemeral_pubkey);
  w.u8(confidential.scan_tag.value);
  w.varbytes(confidential.memo);
  return w.take();
}

std::optional<UtxoEntryV2> parse_utxo_entry_v2(const Bytes& b) {
  UtxoEntryV2 entry;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto kind = r.u8();
        if (!kind) return false;
        if (*kind > static_cast<std::uint8_t>(UtxoOutputKind::Confidential)) return false;
        entry.kind = static_cast<UtxoOutputKind>(*kind);
        if (entry.kind == UtxoOutputKind::Transparent) {
          auto value = r.u64le();
          auto script = r.varbytes();
          if (!value || !script || script->size() > kMaxScriptBytes) return false;
          entry.body = UtxoTransparentData{TxOut{*value, *script}};
          return true;
        }
        auto value_commitment = r.bytes_fixed<33>();
        auto one_time_pubkey = r.bytes_fixed<33>();
        auto ephemeral_pubkey = r.bytes_fixed<33>();
        auto scan_tag = r.u8();
        auto memo = r.varbytes();
        if (!value_commitment || !one_time_pubkey || !ephemeral_pubkey || !scan_tag || !memo) return false;
        if (memo->size() > kMaxMemoBytes) return false;
        entry.body = UtxoConfidentialData{
            .value_commitment = crypto::Commitment33{*value_commitment},
            .one_time_pubkey = *one_time_pubkey,
            .ephemeral_pubkey = *ephemeral_pubkey,
            .scan_tag = crypto::ScanTag{*scan_tag},
            .memo = *memo,
        };
        return true;
      })) {
    return std::nullopt;
  }
  return entry;
}

std::optional<TxOut> transparent_txout_from_utxo_entry(const UtxoEntryV2& entry) {
  if (entry.kind != UtxoOutputKind::Transparent) return std::nullopt;
  return std::get<UtxoTransparentData>(entry.body).out;
}

UtxoSet downgrade_utxo_set_v1(const UtxoSetV2& utxos) {
  UtxoSet out;
  for (const auto& [op, entry] : utxos) {
    const auto transparent = transparent_txout_from_utxo_entry(entry);
    if (!transparent.has_value()) continue;
    out.emplace(op, UtxoEntry{*transparent});
  }
  return out;
}

Bytes Tx::serialize_without_hashcash() const {
  codec::ByteWriter w;
  w.u32le(version);
  w.varint(inputs.size());
  for (const auto& in : inputs) {
    w.bytes_fixed(in.prev_txid);
    w.u32le(in.prev_index);
    w.varbytes(in.script_sig);
    w.u32le(in.sequence);
  }
  w.varint(outputs.size());
  for (const auto& out : outputs) {
    w.u64le(out.value);
    w.varbytes(out.script_pubkey);
  }
  w.u32le(lock_time);
  return w.take();
}

Bytes Tx::serialize() const {
  codec::ByteWriter w;
  w.bytes(serialize_without_hashcash());
  if (!hashcash.has_value()) {
    w.u8(0);
    return w.take();
  }
  w.u8(1);
  w.u32le(hashcash->version);
  w.u64le(hashcash->epoch_bucket);
  w.u32le(hashcash->bits);
  w.u64le(hashcash->nonce);
  return w.take();
}

std::optional<Tx> Tx::parse(const Bytes& b) {
  Tx tx;
  try {
    if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
          auto version = r.u32le();
          auto in_count = r.varint();
          if (!version || !in_count) return false;
          if (*version != 1) return false;
          if (*in_count > kMaxTxInputs) return false;
          tx.version = *version;

          tx.inputs.clear();
          tx.inputs.reserve(*in_count);
          for (std::uint64_t i = 0; i < *in_count; ++i) {
            TxIn in;
            auto prev = r.bytes_fixed<32>();
            auto idx = r.u32le();
            auto script = r.varbytes();
            auto seq = r.u32le();
            if (!prev || !idx || !script || !seq) return false;
            if (script->size() > kMaxScriptBytes) return false;
            in.prev_txid = *prev;
            in.prev_index = *idx;
            in.script_sig = *script;
            in.sequence = *seq;
            tx.inputs.push_back(std::move(in));
          }

          auto out_count = r.varint();
          if (!out_count) return false;
          if (*out_count > kMaxTxOutputs) return false;
          tx.outputs.clear();
          tx.outputs.reserve(*out_count);
          for (std::uint64_t i = 0; i < *out_count; ++i) {
            TxOut out;
            auto value = r.u64le();
            auto script = r.varbytes();
            if (!value || !script) return false;
            if (script->size() > kMaxScriptBytes) return false;
            out.value = *value;
            out.script_pubkey = *script;
            tx.outputs.push_back(std::move(out));
          }

          auto lock = r.u32le();
          if (!lock) return false;
          tx.lock_time = *lock;
          if (r.eof()) return true;
          auto has_hashcash = r.u8();
          if (!has_hashcash) return false;
          if (*has_hashcash == 0) return r.eof();
          if (*has_hashcash != 1) return false;
          auto stamp_version = r.u32le();
          auto epoch_bucket = r.u64le();
          auto bits = r.u32le();
          auto nonce = r.u64le();
          if (!stamp_version || !epoch_bucket || !bits || !nonce) return false;
          tx.hashcash = TxHashcashStamp{
              .version = *stamp_version,
              .epoch_bucket = *epoch_bucket,
              .bits = *bits,
              .nonce = *nonce,
          };
          return true;
        })) {
      return std::nullopt;
    }
    return tx;
  } catch (...) {
    return std::nullopt;
  }
}

Hash32 Tx::txid() const { return crypto::sha256d(serialize_without_hashcash()); }

Bytes BlockHeader::serialize_without_signature() const {
  codec::ByteWriter w;
  w.bytes_fixed(prev_finalized_hash);
  w.bytes_fixed(prev_finality_cert_hash);
  w.u64le(height);
  w.u64le(timestamp);
  w.bytes_fixed(merkle_root);
  w.bytes_fixed(leader_pubkey);
  w.u32le(round);
  return w.take();
}

Bytes BlockHeader::serialize() const {
  codec::ByteWriter w;
  w.bytes_fixed(prev_finalized_hash);
  w.bytes_fixed(prev_finality_cert_hash);
  w.u64le(height);
  w.u64le(timestamp);
  w.bytes_fixed(merkle_root);
  w.bytes_fixed(leader_pubkey);
  w.u32le(round);
  w.bytes_fixed(leader_signature);
  return w.take();
}

std::optional<BlockHeader> BlockHeader::parse(const Bytes& b) {
  BlockHeader h;
  try {
    codec::ByteReader r(b);
    auto prev = r.bytes_fixed<32>();
    if (!prev) return std::nullopt;
    h.prev_finalized_hash = *prev;

    const std::size_t legacy_suffix = 8 + 8 + 32 + 32 + 4 + 64;
    const std::size_t extended_suffix = 32 + legacy_suffix;
    if (r.remaining() == extended_suffix) {
      auto prev_cert = r.bytes_fixed<32>();
      if (!prev_cert) return std::nullopt;
      h.prev_finality_cert_hash = *prev_cert;
    } else if (r.remaining() != legacy_suffix) {
      return std::nullopt;
    }

    auto height = r.u64le();
    auto ts = r.u64le();
    auto merkle = r.bytes_fixed<32>();
    auto leader = r.bytes_fixed<32>();
    auto round = r.u32le();
    auto leader_sig = r.bytes_fixed<64>();
    if (!height || !ts || !merkle || !leader || !round || !leader_sig || !r.eof()) return std::nullopt;
    h.height = *height;
    h.timestamp = *ts;
    h.merkle_root = *merkle;
    h.leader_pubkey = *leader;
    h.round = *round;
    h.leader_signature = *leader_sig;
  } catch (...) {
    return std::nullopt;
  }
  return h;
}

Hash32 BlockHeader::block_id() const {
  Bytes pre{'S', 'C', '-', 'B', 'L', 'O', 'C', 'K', '-', 'V', '0'};
  const Bytes hbytes = serialize_without_signature();
  pre.insert(pre.end(), hbytes.begin(), hbytes.end());
  return crypto::sha256d(pre);
}

Bytes FinalityProof::serialize() const {
  codec::ByteWriter w;
  w.varint(sigs.size());
  for (const auto& s : sigs) {
    w.bytes_fixed(s.validator_pubkey);
    w.bytes_fixed(s.signature);
  }
  return w.take();
}

std::optional<FinalityProof> FinalityProof::parse(const Bytes& b) {
  FinalityProof p;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto n = r.varint();
        if (!n) return false;
        p.sigs.clear();
        p.sigs.reserve(*n);
        for (std::uint64_t i = 0; i < *n; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          p.sigs.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return p;
}

Bytes FinalityCertificate::serialize() const {
  codec::ByteWriter w;
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(frontier_transition_id);
  w.u32le(quorum_threshold);
  w.varint(committee_members.size());
  for (const auto& member : committee_members) w.bytes_fixed(member);
  w.varint(signatures.size());
  for (const auto& s : signatures) {
    w.bytes_fixed(s.validator_pubkey);
    w.bytes_fixed(s.signature);
  }
  return w.take();
}

std::optional<FinalityCertificate> FinalityCertificate::parse(const Bytes& b) {
  FinalityCertificate cert;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto block = r.bytes_fixed<32>();
        auto quorum = r.u32le();
        auto committee_count = r.varint();
        if (!h || !round || !block || !quorum || !committee_count) return false;
        cert.height = *h;
        cert.round = *round;
        cert.frontier_transition_id = *block;
        cert.quorum_threshold = *quorum;
        cert.committee_members.clear();
        cert.committee_members.reserve(*committee_count);
        for (std::uint64_t i = 0; i < *committee_count; ++i) {
          auto member = r.bytes_fixed<32>();
          if (!member) return false;
          cert.committee_members.push_back(*member);
        }
        auto sig_count = r.varint();
        if (!sig_count) return false;
        cert.signatures.clear();
        cert.signatures.reserve(*sig_count);
        for (std::uint64_t i = 0; i < *sig_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          cert.signatures.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return cert;
}

Bytes Block::serialize() const {
  codec::ByteWriter w;
  w.varbytes(header.serialize());
  w.varint(txs.size());
  for (const auto& tx : txs) {
    w.bytes(tx.serialize_without_hashcash());
  }
  w.bytes(finality_proof.serialize());
  return w.take();
}

std::optional<Block> Block::parse(const Bytes& b) {
  Block blk;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto header_bytes = r.varbytes();
        if (!header_bytes) return false;
        auto header = BlockHeader::parse(*header_bytes);
        if (!header.has_value()) return false;
        blk.header = *header;

        auto n = r.varint();
        if (!n || *n < 1) return false;
        blk.txs.clear();
        blk.txs.reserve(*n);
        for (std::uint64_t i = 0; i < *n; ++i) {
          auto version = r.u32le();
          auto in_count = r.varint();
          if (!version || !in_count) return false;
          Tx tx;
          tx.version = *version;
          for (std::uint64_t j = 0; j < *in_count; ++j) {
            auto prev_t = r.bytes_fixed<32>();
            auto prev_i = r.u32le();
            auto sig = r.varbytes();
            auto seq = r.u32le();
            if (!prev_t || !prev_i || !sig || !seq) return false;
            tx.inputs.push_back(TxIn{*prev_t, *prev_i, *sig, *seq});
          }
          auto out_count = r.varint();
          if (!out_count) return false;
          for (std::uint64_t j = 0; j < *out_count; ++j) {
            auto v = r.u64le();
            auto spk = r.varbytes();
            if (!v || !spk) return false;
            tx.outputs.push_back(TxOut{*v, *spk});
          }
          auto lock = r.u32le();
          if (!lock) return false;
          tx.lock_time = *lock;
          blk.txs.push_back(std::move(tx));
        }

        auto sig_count = r.varint();
        if (!sig_count) return false;
        blk.finality_proof.sigs.clear();
        blk.finality_proof.sigs.reserve(*sig_count);
        for (std::uint64_t i = 0; i < *sig_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          blk.finality_proof.sigs.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return blk;
}

Bytes FrontierDecision::serialize() const {
  codec::ByteWriter w;
  w.bytes_fixed(record_id);
  w.u8(accepted ? 1 : 0);
  w.u8(static_cast<std::uint8_t>(reject_reason));
  return w.take();
}

std::optional<FrontierDecision> FrontierDecision::parse(const Bytes& b) {
  FrontierDecision out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto record = r.bytes_fixed<32>();
        auto accepted = r.u8();
        auto reject = r.u8();
        if (!record || !accepted || !reject) return false;
        out.record_id = *record;
        out.accepted = (*accepted != 0);
        out.reject_reason = static_cast<FrontierRejectReason>(*reject);
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes FrontierSettlement::serialize() const {
  codec::ByteWriter w;
  w.u64le(settlement_epoch_start);
  w.varint(outputs.size());
  for (const auto& [pub, units] : outputs) {
    w.bytes_fixed(pub);
    w.u64le(units);
  }
  w.u64le(total);
  w.u64le(current_fees);
  w.u64le(settled_epoch_fees);
  w.u64le(settled_epoch_rewards);
  w.u64le(reserve_subsidy_units);
  return w.take();
}

std::optional<FrontierSettlement> FrontierSettlement::parse(const Bytes& b) {
  FrontierSettlement out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto output_count = r.varint();
        if (!epoch || !output_count) return false;
        out.settlement_epoch_start = *epoch;
        out.outputs.clear();
        out.outputs.reserve(static_cast<std::size_t>(*output_count));
        for (std::uint64_t i = 0; i < *output_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto units = r.u64le();
          if (!pub || !units) return false;
          out.outputs.push_back({*pub, *units});
        }
        auto total = r.u64le();
        auto current_fees = r.u64le();
        if (!total || !current_fees) return false;
        out.total = *total;
        out.current_fees = *current_fees;
        if (r.remaining() == 8) {
          auto settled_epoch_rewards = r.u64le();
          if (!settled_epoch_rewards || !r.eof()) return false;
          out.settled_epoch_rewards = *settled_epoch_rewards;
          return true;
        }
        auto settled_epoch_fees = r.u64le();
        auto settled_epoch_rewards = r.u64le();
        if (!settled_epoch_fees || !settled_epoch_rewards) return false;
        out.settled_epoch_fees = *settled_epoch_fees;
        out.settled_epoch_rewards = *settled_epoch_rewards;
        if (r.remaining()) {
          auto reserve_subsidy_units = r.u64le();
          if (!reserve_subsidy_units || !r.eof()) return false;
          out.reserve_subsidy_units = *reserve_subsidy_units;
          return true;
        }
        return r.eof();
      })) {
    return std::nullopt;
  }
  return out;
}

Hash32 FrontierSettlement::commitment() const {
  Bytes pre{'S', 'C', '-', 'F', 'R', '-', 'S', 'E', 'T', 'T', 'L', 'E', '-', 'V', '1'};
  const Bytes payload = serialize();
  pre.insert(pre.end(), payload.begin(), payload.end());
  return crypto::sha256d(pre);
}

Bytes FrontierVector::serialize() const {
  codec::ByteWriter w;
  for (const auto seq : lane_max_seq) w.u64le(seq);
  return w.take();
}

std::optional<FrontierVector> FrontierVector::parse(const Bytes& b) {
  FrontierVector out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        for (auto& seq : out.lane_max_seq) {
          auto value = r.u64le();
          if (!value) return false;
          seq = *value;
        }
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

std::uint64_t FrontierVector::total_count() const {
  std::uint64_t total = 0;
  for (const auto seq : lane_max_seq) total += seq;
  return total;
}

Bytes FrontierTransition::serialize() const {
  codec::ByteWriter w;
  w.bytes_fixed(prev_finalized_hash);
  w.bytes_fixed(prev_finality_link_hash);
  w.u64le(height);
  w.u32le(round);
  w.bytes_fixed(leader_pubkey);
  w.varbytes(prev_vector.serialize());
  w.varbytes(next_vector.serialize());
  w.bytes_fixed(ingress_commitment);
  w.u64le(prev_frontier);
  w.u64le(next_frontier);
  w.bytes_fixed(prev_state_root);
  w.bytes_fixed(next_state_root);
  w.bytes_fixed(ordered_slice_commitment);
  w.bytes_fixed(decisions_commitment);
  w.u32le(quorum_threshold);
  w.varint(observed_signers.size());
  for (const auto& pub : observed_signers) w.bytes_fixed(pub);
  w.varbytes(settlement.serialize());
  w.bytes_fixed(settlement_commitment);
  return w.take();
}

std::optional<FrontierTransition> FrontierTransition::parse(const Bytes& b) {
  FrontierTransition out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto prev_finalized = r.bytes_fixed<32>();
        auto prev_finality_link = r.bytes_fixed<32>();
        auto height = r.u64le();
        auto round = r.u32le();
        auto leader = r.bytes_fixed<32>();
        auto prev_vector_bytes = r.varbytes();
        auto next_vector_bytes = r.varbytes();
        auto ingress_commitment = r.bytes_fixed<32>();
        auto prev = r.u64le();
        auto next = r.u64le();
        auto prev_root = r.bytes_fixed<32>();
        auto next_root = r.bytes_fixed<32>();
        auto ordered = r.bytes_fixed<32>();
        auto decisions = r.bytes_fixed<32>();
        auto quorum = r.u32le();
        auto signer_count = r.varint();
        if (!prev_finalized || !prev_finality_link || !height || !round || !leader || !prev_vector_bytes ||
            !next_vector_bytes || !ingress_commitment || !prev || !next || !prev_root || !next_root || !ordered ||
            !decisions || !quorum || !signer_count) {
          return false;
        }
        auto prev_vector = FrontierVector::parse(*prev_vector_bytes);
        auto next_vector = FrontierVector::parse(*next_vector_bytes);
        if (!prev_vector.has_value() || !next_vector.has_value()) return false;
        out.prev_finalized_hash = *prev_finalized;
        out.prev_finality_link_hash = *prev_finality_link;
        out.height = *height;
        out.round = *round;
        out.leader_pubkey = *leader;
        out.prev_vector = *prev_vector;
        out.next_vector = *next_vector;
        out.ingress_commitment = *ingress_commitment;
        out.prev_frontier = *prev;
        out.next_frontier = *next;
        out.prev_state_root = *prev_root;
        out.next_state_root = *next_root;
        out.ordered_slice_commitment = *ordered;
        out.decisions_commitment = *decisions;
        out.quorum_threshold = *quorum;
        out.observed_signers.clear();
        out.observed_signers.reserve(static_cast<std::size_t>(*signer_count));
        for (std::uint64_t i = 0; i < *signer_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          if (!pub) return false;
          out.observed_signers.push_back(*pub);
        }
        auto settlement_bytes = r.varbytes();
        auto settlement_commitment = r.bytes_fixed<32>();
        if (!settlement_bytes || !settlement_commitment) return false;
        auto settlement = FrontierSettlement::parse(*settlement_bytes);
        if (!settlement.has_value()) return false;
        out.settlement = *settlement;
        out.settlement_commitment = *settlement_commitment;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Hash32 FrontierTransition::transition_id() const {
  Bytes pre{'S', 'C', '-', 'F', 'R', 'O', 'N', 'T', 'I', 'E', 'R', '-', 'V', '1'};
  const Bytes payload = serialize();
  pre.insert(pre.end(), payload.begin(), payload.end());
  return crypto::sha256d(pre);
}

Bytes FrontierProposal::serialize() const {
  codec::ByteWriter w;
  w.varbytes(transition.serialize());
  w.varint(ordered_records.size());
  for (const auto& record : ordered_records) w.varbytes(record);
  return w.take();
}

std::optional<FrontierProposal> FrontierProposal::parse(const Bytes& b) {
  FrontierProposal out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto transition_bytes = r.varbytes();
        auto count = r.varint();
        if (!transition_bytes || !count) return false;
        auto transition = FrontierTransition::parse(*transition_bytes);
        if (!transition.has_value()) return false;
        out.transition = *transition;
        out.ordered_records.clear();
        out.ordered_records.reserve(static_cast<std::size_t>(*count));
        for (std::uint64_t i = 0; i < *count; ++i) {
          auto record = r.varbytes();
          if (!record) return false;
          out.ordered_records.push_back(*record);
        }
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes IngressCertificate::serialize() const {
  codec::ByteWriter w;
  w.u64le(epoch);
  w.u32le(lane);
  w.u64le(seq);
  w.bytes_fixed(txid);
  w.bytes_fixed(tx_hash);
  w.bytes_fixed(prev_lane_root);
  w.varint(sigs.size());
  for (const auto& sig : sigs) {
    w.bytes_fixed(sig.validator_pubkey);
    w.bytes_fixed(sig.signature);
  }
  return w.take();
}

std::optional<IngressCertificate> IngressCertificate::parse(const Bytes& b) {
  IngressCertificate out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto lane = r.u32le();
        auto seq = r.u64le();
        auto txid = r.bytes_fixed<32>();
        auto tx_hash = r.bytes_fixed<32>();
        auto prev_lane_root = r.bytes_fixed<32>();
        auto sig_count = r.varint();
        if (!epoch || !lane || !seq || !txid || !tx_hash || !prev_lane_root || !sig_count) return false;
        out.epoch = *epoch;
        out.lane = *lane;
        out.seq = *seq;
        out.txid = *txid;
        out.tx_hash = *tx_hash;
        out.prev_lane_root = *prev_lane_root;
        out.sigs.clear();
        out.sigs.reserve(static_cast<std::size_t>(*sig_count));
        for (std::uint64_t i = 0; i < *sig_count; ++i) {
          auto pub = r.bytes_fixed<32>();
          auto sig = r.bytes_fixed<64>();
          if (!pub || !sig) return false;
          out.sigs.push_back(FinalitySig{*pub, *sig});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Hash32 IngressCertificate::signing_hash() const {
  codec::ByteWriter w;
  static constexpr std::uint8_t kDomain[] = {'i', 'n', 'g', 'r', 'e', 's', 's', '-', 'c', 'e', 'r', 't', '/', 'v', '1'};
  w.bytes(Bytes(kDomain, kDomain + sizeof(kDomain)));
  w.u64le(epoch);
  w.u32le(lane);
  w.u64le(seq);
  w.bytes_fixed(txid);
  w.bytes_fixed(tx_hash);
  w.bytes_fixed(prev_lane_root);
  return crypto::sha256d(w.take());
}

Bytes LaneState::serialize() const {
  codec::ByteWriter w;
  w.u64le(epoch);
  w.u32le(lane);
  w.u64le(max_seq);
  w.bytes_fixed(lane_root);
  return w.take();
}

std::optional<LaneState> LaneState::parse(const Bytes& b) {
  LaneState out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto lane = r.u32le();
        auto max_seq = r.u64le();
        auto lane_root = r.bytes_fixed<32>();
        if (!epoch || !lane || !max_seq || !lane_root) return false;
        out.epoch = *epoch;
        out.lane = *lane;
        out.max_seq = *max_seq;
        out.lane_root = *lane_root;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

bool is_validator_register_script(const Bytes& script, PubKey32* out_pubkey) {
  static const std::array<std::uint8_t, 8> prefix = {'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
  if (script.size() != 40) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out_pubkey) {
    std::copy(script.begin() + 8, script.end(), out_pubkey->begin());
  }
  return true;
}

bool is_validator_unbond_script(const Bytes& script, PubKey32* out_pubkey) {
  static const std::array<std::uint8_t, 8> prefix = {'S', 'C', 'V', 'A', 'L', 'U', 'N', 'B'};
  if (script.size() != 40) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out_pubkey) {
    std::copy(script.begin() + 8, script.end(), out_pubkey->begin());
  }
  return true;
}

bool parse_onboarding_registration_script(const Bytes& script, OnboardingRegistrationScriptData* out) {
  static const std::array<std::uint8_t, 8> prefix = {'S', 'C', 'O', 'N', 'B', 'R', 'E', 'G'};
  if (script.size() != 136 && script.size() != 152) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out) {
    std::copy(script.begin() + 8, script.begin() + 40, out->validator_pubkey.begin());
    std::copy(script.begin() + 40, script.begin() + 72, out->payout_pubkey.begin());
    std::copy(script.begin() + 72, script.begin() + 136, out->pop.begin());
    out->has_admission_pow = (script.size() == 152);
    out->admission_pow_epoch = 0;
    out->admission_pow_nonce = 0;
    if (out->has_admission_pow) {
      Bytes suffix(script.begin() + 136, script.end());
      codec::ByteReader r(suffix);
      auto epoch = r.u64le();
      auto nonce = r.u64le();
      if (!epoch || !nonce || !r.eof()) return false;
      out->admission_pow_epoch = *epoch;
      out->admission_pow_nonce = *nonce;
    }
  }
  return true;
}

bool is_onboarding_registration_script(const Bytes& script, PubKey32* out_validator_pubkey,
                                       PubKey32* out_payout_pubkey, Sig64* out_pop,
                                       std::uint64_t* out_admission_pow_epoch,
                                       std::uint64_t* out_admission_pow_nonce) {
  OnboardingRegistrationScriptData parsed;
  if (!parse_onboarding_registration_script(script, &parsed)) return false;
  if (out_validator_pubkey) *out_validator_pubkey = parsed.validator_pubkey;
  if (out_payout_pubkey) *out_payout_pubkey = parsed.payout_pubkey;
  if (out_pop) *out_pop = parsed.pop;
  if (out_admission_pow_epoch) *out_admission_pow_epoch = parsed.has_admission_pow ? parsed.admission_pow_epoch : 0;
  if (out_admission_pow_nonce) *out_admission_pow_nonce = parsed.has_admission_pow ? parsed.admission_pow_nonce : 0;
  return true;
}

bool parse_validator_join_request_script(const Bytes& script, ValidatorJoinRequestScriptData* out) {
  static const std::array<std::uint8_t, 8> prefix = {'S', 'C', 'V', 'A', 'L', 'J', 'R', 'Q'};
  if (script.size() != 136 && script.size() != 152) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out) {
    std::copy(script.begin() + 8, script.begin() + 40, out->validator_pubkey.begin());
    std::copy(script.begin() + 40, script.begin() + 72, out->payout_pubkey.begin());
    std::copy(script.begin() + 72, script.begin() + 136, out->pop.begin());
    out->has_admission_pow = (script.size() == 152);
    out->admission_pow_epoch = 0;
    out->admission_pow_nonce = 0;
    if (out->has_admission_pow) {
      Bytes suffix(script.begin() + 136, script.end());
      codec::ByteReader r(suffix);
      auto epoch = r.u64le();
      auto nonce = r.u64le();
      if (!epoch || !nonce || !r.eof()) return false;
      out->admission_pow_epoch = *epoch;
      out->admission_pow_nonce = *nonce;
    }
  }
  return true;
}

bool is_validator_join_request_script(const Bytes& script, PubKey32* out_validator_pubkey,
                                      PubKey32* out_payout_pubkey, Sig64* out_pop,
                                      std::uint64_t* out_admission_pow_epoch,
                                      std::uint64_t* out_admission_pow_nonce) {
  ValidatorJoinRequestScriptData parsed;
  if (!parse_validator_join_request_script(script, &parsed)) return false;
  if (out_validator_pubkey) *out_validator_pubkey = parsed.validator_pubkey;
  if (out_payout_pubkey) *out_payout_pubkey = parsed.payout_pubkey;
  if (out_pop) *out_pop = parsed.pop;
  if (out_admission_pow_epoch) *out_admission_pow_epoch = parsed.has_admission_pow ? parsed.admission_pow_epoch : 0;
  if (out_admission_pow_nonce) *out_admission_pow_nonce = parsed.has_admission_pow ? parsed.admission_pow_nonce : 0;
  return true;
}

bool is_burn_script(const Bytes& script, Hash32* out_evidence_hash) {
  static const std::array<std::uint8_t, 6> prefix = {'S', 'C', 'B', 'U', 'R', 'N'};
  if (script.size() != 38) return false;
  if (!std::equal(prefix.begin(), prefix.end(), script.begin())) return false;
  if (out_evidence_hash) {
    std::copy(script.begin() + 6, script.end(), out_evidence_hash->begin());
  }
  return true;
}

}  // namespace finalis
