// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <optional>
#include <string>

#include "consensus/epoch_tickets.hpp"
#include "utxo/tx.hpp"

namespace finalis::p2p {

enum MsgType : std::uint16_t {
  VERSION = 1,
  VERACK = 2,
  GET_FINALIZED_TIP = 3,
  FINALIZED_TIP = 4,
  PROPOSE = 5,
  VOTE = 6,
  TIMEOUT_VOTE = 23,
  GET_TRANSITION = 7,
  TRANSITION = 8,
  TX = 9,
  GETADDR = 10,
  ADDR = 11,
  PING = 12,
  PONG = 13,
  GET_TRANSITION_BY_HEIGHT = 14,
  EPOCH_TICKET = 15,
  GET_EPOCH_TICKETS = 16,
  EPOCH_TICKETS = 17,
  INGRESS_RECORD = 18,
  GET_INGRESS_RANGE = 19,
  INGRESS_RANGE = 20,
  GET_INGRESS_TIPS = 21,
  INGRESS_TIPS = 22,
};

struct VersionMsg {
  std::uint32_t proto_version{PROTOCOL_VERSION};
  std::array<std::uint8_t, 16> network_id{};
  std::uint64_t feature_flags{0};
  std::uint64_t services{0};
  std::uint64_t timestamp{0};
  std::uint32_t nonce{0};
  std::string node_software_version{"finalis-core/0.7"};
  std::uint64_t start_height{0};
  Hash32 start_hash{};
};

struct FinalizedTipMsg {
  std::uint64_t height{0};
  Hash32 hash{};
};

struct ProposeMsg {
  std::uint64_t height{0};
  std::uint32_t round{0};
  Hash32 prev_finalized_hash{};
  Bytes frontier_proposal_bytes;
  std::optional<QuorumCertificate> justify_qc;
  std::optional<TimeoutCertificate> justify_tc;
};

struct VoteMsg {
  Vote vote;
};

struct TimeoutVoteMsg {
  TimeoutVote vote;
};

struct GetTransitionMsg {
  Hash32 hash{};
};

struct GetTransitionByHeightMsg {
  std::uint64_t height{0};
};

struct TransitionMsg {
  Bytes frontier_proposal_bytes;
  std::optional<FinalityCertificate> certificate;
};

struct EpochTicketMsg {
  consensus::EpochTicket ticket;
};

struct GetEpochTicketsMsg {
  std::uint64_t epoch{0};
  std::uint32_t max_tickets{0};
};

struct EpochTicketsMsg {
  std::uint64_t epoch{0};
  bool epoch_closed{false};
  std::vector<consensus::EpochTicket> tickets;
};

struct TxMsg {
  Bytes tx_bytes;
};

struct IngressRecordMsg {
  IngressCertificate certificate;
  Bytes tx_bytes;
};

struct GetIngressRangeMsg {
  std::uint32_t lane{0};
  std::uint64_t from_seq{0};
  std::uint64_t to_seq{0};
};

struct IngressRangeMsg {
  std::uint32_t lane{0};
  std::uint64_t from_seq{0};
  std::uint64_t to_seq{0};
  std::vector<IngressRecordMsg> records;
};

struct GetIngressTipsMsg {};

struct IngressTipsMsg {
  std::array<std::uint64_t, INGRESS_LANE_COUNT> lane_tips{};
};

struct GetAddrMsg {};

struct AddrEntryMsg {
  std::uint8_t ip_version{4};  // 4 or 6
  std::array<std::uint8_t, 16> ip{};
  std::uint16_t port{0};
  std::uint64_t last_seen_unix{0};
};

struct AddrMsg {
  std::vector<AddrEntryMsg> entries;
};

struct PingMsg {
  std::uint64_t nonce{0};
};

bool is_known_message_type(std::uint16_t msg_type);

Bytes ser_version(const VersionMsg& m);
std::optional<VersionMsg> de_version(const Bytes& b);
Bytes ser_finalized_tip(const FinalizedTipMsg& m);
std::optional<FinalizedTipMsg> de_finalized_tip(const Bytes& b);
Bytes ser_propose(const ProposeMsg& m);
std::optional<ProposeMsg> de_propose(const Bytes& b);
Bytes ser_vote(const VoteMsg& m);
std::optional<VoteMsg> de_vote(const Bytes& b);
Bytes ser_timeout_vote(const TimeoutVoteMsg& m);
std::optional<TimeoutVoteMsg> de_timeout_vote(const Bytes& b);
Bytes ser_get_transition(const GetTransitionMsg& m);
std::optional<GetTransitionMsg> de_get_transition(const Bytes& b);
Bytes ser_get_transition_by_height(const GetTransitionByHeightMsg& m);
std::optional<GetTransitionByHeightMsg> de_get_transition_by_height(const Bytes& b);
Bytes ser_transition(const TransitionMsg& m);
std::optional<TransitionMsg> de_transition(const Bytes& b);
Bytes ser_epoch_ticket(const EpochTicketMsg& m);
std::optional<EpochTicketMsg> de_epoch_ticket(const Bytes& b);
Bytes ser_get_epoch_tickets(const GetEpochTicketsMsg& m);
std::optional<GetEpochTicketsMsg> de_get_epoch_tickets(const Bytes& b);
Bytes ser_epoch_tickets(const EpochTicketsMsg& m);
std::optional<EpochTicketsMsg> de_epoch_tickets(const Bytes& b);
Bytes ser_tx(const TxMsg& m);
std::optional<TxMsg> de_tx(const Bytes& b);
Bytes ser_ingress_record(const IngressRecordMsg& m);
std::optional<IngressRecordMsg> de_ingress_record(const Bytes& b);
Bytes ser_get_ingress_range(const GetIngressRangeMsg& m);
std::optional<GetIngressRangeMsg> de_get_ingress_range(const Bytes& b);
Bytes ser_ingress_range(const IngressRangeMsg& m);
std::optional<IngressRangeMsg> de_ingress_range(const Bytes& b);
Bytes ser_get_ingress_tips(const GetIngressTipsMsg& m);
std::optional<GetIngressTipsMsg> de_get_ingress_tips(const Bytes& b);
Bytes ser_ingress_tips(const IngressTipsMsg& m);
std::optional<IngressTipsMsg> de_ingress_tips(const Bytes& b);
Bytes ser_getaddr(const GetAddrMsg& m);
std::optional<GetAddrMsg> de_getaddr(const Bytes& b);
Bytes ser_addr(const AddrMsg& m);
std::optional<AddrMsg> de_addr(const Bytes& b);
Bytes ser_ping(const PingMsg& m);
std::optional<PingMsg> de_ping(const Bytes& b);

}  // namespace finalis::p2p
