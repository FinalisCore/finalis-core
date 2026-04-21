// SPDX-License-Identifier: MIT

#include "p2p/messages.hpp"

#include "codec/bytes.hpp"

namespace finalis::p2p {
namespace {

// The VERSION fingerprint currently carries chain-id plus bootstrap/runtime
// metadata, so the cap must comfortably exceed the minimal local fingerprint.
constexpr std::size_t kMaxSoftwareVersionBytes = 512;
constexpr std::size_t kMaxProposalBytes = 2 * 1024 * 1024;
constexpr std::size_t kMaxBlockMessageBytes = 2 * 1024 * 1024;
constexpr std::size_t kMaxTxMessageBytes = 256 * 1024;
constexpr std::size_t kMaxIngressRecordBytes = 256 * 1024;
constexpr std::uint64_t kMaxIngressRangeEntries = 4096;
constexpr std::uint64_t kMaxAddrEntries = 256;
constexpr std::uint32_t kMaxEpochTicketResponseEntries = 2048;

}  // namespace

bool is_known_message_type(std::uint16_t msg_type) {
  switch (msg_type) {
    case MsgType::VERSION:
    case MsgType::VERACK:
    case MsgType::GET_FINALIZED_TIP:
    case MsgType::FINALIZED_TIP:
    case MsgType::PROPOSE:
    case MsgType::VOTE:
    case MsgType::TIMEOUT_VOTE:
    case MsgType::GET_TRANSITION:
    case MsgType::TRANSITION:
    case MsgType::TX:
    case MsgType::GETADDR:
    case MsgType::ADDR:
    case MsgType::PING:
    case MsgType::PONG:
    case MsgType::GET_TRANSITION_BY_HEIGHT:
    case MsgType::EPOCH_TICKET:
    case MsgType::GET_EPOCH_TICKETS:
    case MsgType::EPOCH_TICKETS:
    case MsgType::INGRESS_RECORD:
    case MsgType::GET_INGRESS_RANGE:
    case MsgType::INGRESS_RANGE:
    case MsgType::GET_INGRESS_TIPS:
    case MsgType::INGRESS_TIPS:
      return true;
    default:
      return false;
  }
}

Bytes ser_version(const VersionMsg& m) {
  codec::ByteWriter w;
  w.u32le(m.proto_version);
  w.bytes_fixed(m.network_id);
  w.u64le(m.feature_flags);
  w.u64le(m.services);
  w.u64le(m.timestamp);
  w.u32le(m.nonce);
  w.varbytes(Bytes(m.node_software_version.begin(), m.node_software_version.end()));
  w.u64le(m.start_height);
  w.bytes_fixed(m.start_hash);
  return w.take();
}

std::optional<VersionMsg> de_version(const Bytes& b) {
  VersionMsg m;
  // v0.7 format
  if (codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto pv = r.u32le();
        auto nid = r.bytes_fixed<16>();
        auto ff = r.u64le();
        auto s = r.u64le();
        auto ts = r.u64le();
        auto n = r.u32le();
        auto sw = r.varbytes();
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!pv || !nid || !ff || !s || !ts || !n || !sw || !h || !hash) return false;
        if (sw->size() > kMaxSoftwareVersionBytes) return false;
        m.proto_version = *pv;
        m.network_id = *nid;
        m.feature_flags = *ff;
        m.services = *s;
        m.timestamp = *ts;
        m.nonce = *n;
        m.node_software_version = std::string(sw->begin(), sw->end());
        m.start_height = *h;
        m.start_hash = *hash;
        return true;
      })) return m;

  // Backward-aware parse for pre-v0.7 payloads in this repo line.
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto pv16 = r.u16le();
        auto s = r.u64le();
        auto ts = r.u64le();
        auto n = r.u32le();
        auto ua = r.varbytes();
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!pv16 || !s || !ts || !n || !ua || !h || !hash) return false;
        if (ua->size() > kMaxSoftwareVersionBytes) return false;
        m.proto_version = *pv16;
        m.network_id.fill(0);
        m.feature_flags = 0;
        m.services = *s;
        m.timestamp = *ts;
        m.nonce = *n;
        m.node_software_version = std::string(ua->begin(), ua->end());
        m.start_height = *h;
        m.start_hash = *hash;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_finalized_tip(const FinalizedTipMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.height);
  w.bytes_fixed(m.hash);
  return w.take();
}

std::optional<FinalizedTipMsg> de_finalized_tip(const Bytes& b) {
  FinalizedTipMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!h || !hash) return false;
        m.height = *h;
        m.hash = *hash;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_propose(const ProposeMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.height);
  w.u32le(m.round);
  w.bytes_fixed(m.prev_finalized_hash);
  w.varbytes(m.frontier_proposal_bytes);
  w.u8(m.justify_qc.has_value() ? 1 : 0);
  if (m.justify_qc.has_value()) {
    w.u64le(m.justify_qc->height);
    w.u32le(m.justify_qc->round);
    w.bytes_fixed(m.justify_qc->frontier_transition_id);
    w.varint(m.justify_qc->signatures.size());
    for (const auto& sig : m.justify_qc->signatures) {
      w.bytes_fixed(sig.validator_pubkey);
      w.bytes_fixed(sig.signature);
    }
  }
  w.u8(m.justify_tc.has_value() ? 1 : 0);
  if (m.justify_tc.has_value()) {
    w.u64le(m.justify_tc->height);
    w.u32le(m.justify_tc->round);
    w.varint(m.justify_tc->signatures.size());
    for (const auto& sig : m.justify_tc->signatures) {
      w.bytes_fixed(sig.validator_pubkey);
      w.bytes_fixed(sig.signature);
    }
  }
  return w.take();
}

std::optional<ProposeMsg> de_propose(const Bytes& b) {
  ProposeMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto prev = r.bytes_fixed<32>();
        auto blk = r.varbytes();
        auto has_qc = r.u8();
        if (!h || !round || !prev || !blk || !has_qc) return false;
        if (blk->size() > kMaxProposalBytes) return false;
        m.height = *h;
        m.round = *round;
        m.prev_finalized_hash = *prev;
        m.frontier_proposal_bytes = *blk;
        if (*has_qc != 0) {
          QuorumCertificate qc;
          auto qc_height = r.u64le();
          auto qc_round = r.u32le();
          auto qc_block = r.bytes_fixed<32>();
          auto qc_count = r.varint();
          if (!qc_height || !qc_round || !qc_block || !qc_count) return false;
          qc.height = *qc_height;
          qc.round = *qc_round;
          qc.frontier_transition_id = *qc_block;
          qc.signatures.reserve(*qc_count);
          for (std::uint64_t i = 0; i < *qc_count; ++i) {
            auto pub = r.bytes_fixed<32>();
            auto sig = r.bytes_fixed<64>();
            if (!pub || !sig) return false;
            qc.signatures.push_back(FinalitySig{*pub, *sig});
          }
          m.justify_qc = qc;
        } else {
          m.justify_qc.reset();
        }
        auto has_tc = r.u8();
        if (!has_tc) return false;
        if (*has_tc != 0) {
          TimeoutCertificate tc;
          auto tc_height = r.u64le();
          auto tc_round = r.u32le();
          auto tc_count = r.varint();
          if (!tc_height || !tc_round || !tc_count) return false;
          tc.height = *tc_height;
          tc.round = *tc_round;
          tc.signatures.reserve(*tc_count);
          for (std::uint64_t i = 0; i < *tc_count; ++i) {
            auto pub = r.bytes_fixed<32>();
            auto sig = r.bytes_fixed<64>();
            if (!pub || !sig) return false;
            tc.signatures.push_back(FinalitySig{*pub, *sig});
          }
          m.justify_tc = tc;
        } else {
          m.justify_tc.reset();
        }
        return true;
      }))
    return std::nullopt;
  return m;
}

Bytes ser_vote(const VoteMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.vote.height);
  w.u32le(m.vote.round);
  w.bytes_fixed(m.vote.frontier_transition_id);
  w.bytes_fixed(m.vote.validator_pubkey);
  w.bytes_fixed(m.vote.signature);
  return w.take();
}

std::optional<VoteMsg> de_vote(const Bytes& b) {
  VoteMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto block = r.bytes_fixed<32>();
        auto pub = r.bytes_fixed<32>();
        auto sig = r.bytes_fixed<64>();
        if (!h || !round || !block || !pub || !sig) return false;
        m.vote.height = *h;
        m.vote.round = *round;
        m.vote.frontier_transition_id = *block;
        m.vote.validator_pubkey = *pub;
        m.vote.signature = *sig;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_timeout_vote(const TimeoutVoteMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.vote.height);
  w.u32le(m.vote.round);
  w.bytes_fixed(m.vote.validator_pubkey);
  w.bytes_fixed(m.vote.signature);
  return w.take();
}

std::optional<TimeoutVoteMsg> de_timeout_vote(const Bytes& b) {
  TimeoutVoteMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto round = r.u32le();
        auto pub = r.bytes_fixed<32>();
        auto sig = r.bytes_fixed<64>();
        if (!h || !round || !pub || !sig) return false;
        m.vote.height = *h;
        m.vote.round = *round;
        m.vote.validator_pubkey = *pub;
        m.vote.signature = *sig;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_get_transition(const GetTransitionMsg& m) {
  codec::ByteWriter w;
  w.bytes_fixed(m.hash);
  return w.take();
}

std::optional<GetTransitionMsg> de_get_transition(const Bytes& b) {
  if (b.size() != 32) return std::nullopt;
  GetTransitionMsg m;
  std::copy(b.begin(), b.end(), m.hash.begin());
  return m;
}

Bytes ser_get_transition_by_height(const GetTransitionByHeightMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.height);
  return w.take();
}

std::optional<GetTransitionByHeightMsg> de_get_transition_by_height(const Bytes& b) {
  GetTransitionByHeightMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        if (!h) return false;
        m.height = *h;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_transition(const TransitionMsg& m) {
  codec::ByteWriter w;
  w.varbytes(m.frontier_proposal_bytes);
  w.u8(m.certificate.has_value() ? 1 : 0);
  if (m.certificate.has_value()) {
    w.varbytes(m.certificate->serialize());
  }
  return w.take();
}

std::optional<TransitionMsg> de_transition(const Bytes& b) {
  TransitionMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto blk = r.varbytes();
        auto has_cert = r.u8();
        if (!blk || !has_cert) return false;
        if (blk->size() > kMaxBlockMessageBytes) return false;
        m.frontier_proposal_bytes = *blk;
        if (*has_cert != 0) {
          auto cert_bytes = r.varbytes();
          if (!cert_bytes) return false;
          auto cert = FinalityCertificate::parse(*cert_bytes);
          if (!cert.has_value()) return false;
          m.certificate = *cert;
        } else {
          m.certificate.reset();
        }
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_epoch_ticket(const EpochTicketMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.ticket.epoch);
  w.bytes_fixed(m.ticket.participant_pubkey);
  w.bytes_fixed(m.ticket.challenge_anchor);
  w.u64le(m.ticket.nonce);
  w.bytes_fixed(m.ticket.work_hash);
  w.u64le(m.ticket.source_height);
  w.u8(static_cast<std::uint8_t>(m.ticket.origin));
  return w.take();
}

std::optional<EpochTicketMsg> de_epoch_ticket(const Bytes& b) {
  EpochTicketMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto pub = r.bytes_fixed<32>();
        auto anchor = r.bytes_fixed<32>();
        auto nonce = r.u64le();
        auto work = r.bytes_fixed<32>();
        auto source_height = r.u64le();
        auto origin = r.u8();
        if (!epoch || !pub || !anchor || !nonce || !work || !source_height || !origin) return false;
        m.ticket.epoch = *epoch;
        m.ticket.participant_pubkey = *pub;
        m.ticket.challenge_anchor = *anchor;
        m.ticket.nonce = *nonce;
        m.ticket.work_hash = *work;
        m.ticket.source_height = *source_height;
        m.ticket.origin = static_cast<consensus::EpochTicketOrigin>(*origin);
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_get_epoch_tickets(const GetEpochTicketsMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.epoch);
  w.u32le(m.max_tickets);
  return w.take();
}

std::optional<GetEpochTicketsMsg> de_get_epoch_tickets(const Bytes& b) {
  GetEpochTicketsMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto max = r.u32le();
        if (!epoch || !max) return false;
        m.epoch = *epoch;
        m.max_tickets = *max;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_epoch_tickets(const EpochTicketsMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.epoch);
  w.u8(m.epoch_closed ? 1 : 0);
  w.varint(m.tickets.size());
  for (const auto& ticket : m.tickets) {
    w.u64le(ticket.epoch);
    w.bytes_fixed(ticket.participant_pubkey);
    w.bytes_fixed(ticket.challenge_anchor);
    w.u64le(ticket.nonce);
    w.bytes_fixed(ticket.work_hash);
    w.u64le(ticket.source_height);
    w.u8(static_cast<std::uint8_t>(ticket.origin));
  }
  return w.take();
}

std::optional<EpochTicketsMsg> de_epoch_tickets(const Bytes& b) {
  EpochTicketsMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch = r.u64le();
        auto closed = r.u8();
        auto count = r.varint();
        if (!epoch || !closed || !count || *count > kMaxEpochTicketResponseEntries) return false;
        m.epoch = *epoch;
        m.epoch_closed = (*closed != 0);
        m.tickets.clear();
        m.tickets.reserve(*count);
        for (std::uint64_t i = 0; i < *count; ++i) {
          consensus::EpochTicket ticket;
          auto tepoch = r.u64le();
          auto pub = r.bytes_fixed<32>();
          auto anchor = r.bytes_fixed<32>();
          auto nonce = r.u64le();
          auto work = r.bytes_fixed<32>();
          auto source_height = r.u64le();
          auto origin = r.u8();
          if (!tepoch || !pub || !anchor || !nonce || !work || !source_height || !origin) return false;
          ticket.epoch = *tepoch;
          ticket.participant_pubkey = *pub;
          ticket.challenge_anchor = *anchor;
          ticket.nonce = *nonce;
          ticket.work_hash = *work;
          ticket.source_height = *source_height;
          ticket.origin = static_cast<consensus::EpochTicketOrigin>(*origin);
          m.tickets.push_back(ticket);
        }
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_tx(const TxMsg& m) {
  codec::ByteWriter w;
  w.varbytes(m.tx_bytes);
  return w.take();
}

std::optional<TxMsg> de_tx(const Bytes& b) {
  TxMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto tx = r.varbytes();
        if (!tx) return false;
        if (tx->size() > kMaxTxMessageBytes) return false;
        m.tx_bytes = *tx;
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_ingress_record(const IngressRecordMsg& m) {
  codec::ByteWriter w;
  w.varbytes(m.certificate.serialize());
  w.varbytes(m.tx_bytes);
  return w.take();
}

std::optional<IngressRecordMsg> de_ingress_record(const Bytes& b) {
  IngressRecordMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto cert_bytes = r.varbytes();
        auto tx_bytes = r.varbytes();
        if (!cert_bytes || !tx_bytes) return false;
        if (tx_bytes->size() > kMaxIngressRecordBytes) return false;
        auto cert = IngressCertificate::parse(*cert_bytes);
        if (!cert.has_value()) return false;
        m.certificate = *cert;
        m.tx_bytes = *tx_bytes;
        return true;
      })) {
    return std::nullopt;
  }
  return m;
}

Bytes ser_get_ingress_range(const GetIngressRangeMsg& m) {
  codec::ByteWriter w;
  w.u32le(m.lane);
  w.u64le(m.from_seq);
  w.u64le(m.to_seq);
  return w.take();
}

std::optional<GetIngressRangeMsg> de_get_ingress_range(const Bytes& b) {
  GetIngressRangeMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto lane = r.u32le();
        auto from = r.u64le();
        auto to = r.u64le();
        if (!lane || !from || !to) return false;
        m.lane = *lane;
        m.from_seq = *from;
        m.to_seq = *to;
        return true;
      })) {
    return std::nullopt;
  }
  return m;
}

Bytes ser_ingress_range(const IngressRangeMsg& m) {
  codec::ByteWriter w;
  w.u32le(m.lane);
  w.u64le(m.from_seq);
  w.u64le(m.to_seq);
  w.varint(m.records.size());
  for (const auto& record : m.records) w.varbytes(ser_ingress_record(record));
  return w.take();
}

std::optional<IngressRangeMsg> de_ingress_range(const Bytes& b) {
  IngressRangeMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto lane = r.u32le();
        auto from = r.u64le();
        auto to = r.u64le();
        auto count = r.varint();
        if (!lane || !from || !to || !count) return false;
        if (*count > kMaxIngressRangeEntries) return false;
        m.lane = *lane;
        m.from_seq = *from;
        m.to_seq = *to;
        m.records.clear();
        m.records.reserve(static_cast<std::size_t>(*count));
        for (std::uint64_t i = 0; i < *count; ++i) {
          auto record_bytes = r.varbytes();
          if (!record_bytes) return false;
          auto record = de_ingress_record(*record_bytes);
          if (!record.has_value()) return false;
          m.records.push_back(*record);
        }
        return true;
      })) {
    return std::nullopt;
  }
  return m;
}

Bytes ser_get_ingress_tips(const GetIngressTipsMsg&) { return {}; }

std::optional<GetIngressTipsMsg> de_get_ingress_tips(const Bytes& b) {
  if (!b.empty()) return std::nullopt;
  return GetIngressTipsMsg{};
}

Bytes ser_ingress_tips(const IngressTipsMsg& m) {
  codec::ByteWriter w;
  for (const auto tip : m.lane_tips) w.u64le(tip);
  return w.take();
}

std::optional<IngressTipsMsg> de_ingress_tips(const Bytes& b) {
  IngressTipsMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        for (auto& tip : m.lane_tips) {
          auto value = r.u64le();
          if (!value) return false;
          tip = *value;
        }
        return true;
      })) {
    return std::nullopt;
  }
  return m;
}

Bytes ser_getaddr(const GetAddrMsg&) { return {}; }

std::optional<GetAddrMsg> de_getaddr(const Bytes& b) {
  if (!b.empty()) return std::nullopt;
  return GetAddrMsg{};
}

Bytes ser_addr(const AddrMsg& m) {
  codec::ByteWriter w;
  w.varint(m.entries.size());
  for (const auto& e : m.entries) {
    w.u8(e.ip_version);
    if (e.ip_version == 4) {
      Bytes ip4{e.ip[0], e.ip[1], e.ip[2], e.ip[3]};
      w.bytes(ip4);
    } else {
      w.bytes_fixed(e.ip);
    }
    w.u16le(e.port);
    w.u64le(e.last_seen_unix);
  }
  return w.take();
}

std::optional<AddrMsg> de_addr(const Bytes& b) {
  AddrMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto n = r.varint();
        if (!n || *n > kMaxAddrEntries) return false;
        m.entries.clear();
        m.entries.reserve(*n);
        for (std::uint64_t i = 0; i < *n; ++i) {
          AddrEntryMsg e;
          auto ver = r.u8();
          if (!ver || (*ver != 4 && *ver != 6)) return false;
          e.ip_version = *ver;
          if (*ver == 4) {
            auto ip4 = r.bytes(4);
            if (!ip4) return false;
            e.ip.fill(0);
            e.ip[0] = (*ip4)[0];
            e.ip[1] = (*ip4)[1];
            e.ip[2] = (*ip4)[2];
            e.ip[3] = (*ip4)[3];
          } else {
            auto ip6 = r.bytes_fixed<16>();
            if (!ip6) return false;
            e.ip = *ip6;
          }
          auto p = r.u16le();
          auto seen = r.u64le();
          if (!p || !seen) return false;
          e.port = *p;
          e.last_seen_unix = *seen;
          m.entries.push_back(e);
        }
        return true;
      })) return std::nullopt;
  return m;
}

Bytes ser_ping(const PingMsg& m) {
  codec::ByteWriter w;
  w.u64le(m.nonce);
  return w.take();
}

std::optional<PingMsg> de_ping(const Bytes& b) {
  PingMsg m;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto nonce = r.u64le();
        if (!nonce) return false;
        m.nonce = *nonce;
        return true;
      })) return std::nullopt;
  return m;
}

}  // namespace finalis::p2p
