// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "common/types.hpp"

namespace finalis::consensus {

enum class EpochTicketOrigin : std::uint8_t {
  LOCAL = 1,
  NETWORK = 2,
};

struct EpochTicket {
  std::uint64_t epoch{0};
  PubKey32 participant_pubkey{};
  Hash32 challenge_anchor{};
  std::uint64_t nonce{0};
  Hash32 work_hash{};
  std::uint64_t source_height{0};
  EpochTicketOrigin origin{EpochTicketOrigin::NETWORK};
};

using EpochBestTicket = EpochTicket;

constexpr std::uint64_t EPOCH_TICKET_MAX_NONCE = 4095;
constexpr std::uint8_t DEFAULT_TICKET_DIFFICULTY_BITS = 8;
constexpr std::uint8_t MIN_BOUNDED_TICKET_DIFFICULTY_BITS = 8;
constexpr std::uint8_t MAX_BOUNDED_TICKET_DIFFICULTY_BITS = 12;

Hash32 make_epoch_ticket_work_hash(std::uint64_t epoch, const Hash32& challenge_anchor, const PubKey32& operator_id,
                                   std::uint64_t nonce);

bool validate_epoch_ticket(const EpochTicket& ticket);
std::uint8_t leading_zero_bits(const Hash32& hash);
bool epoch_ticket_meets_difficulty(const EpochTicket& ticket, std::uint8_t difficulty_bits);
std::uint32_t ticket_pow_bonus_bps(const EpochTicket& ticket, std::uint8_t difficulty_bits);
std::uint32_t ticket_pow_bonus_bps(const EpochTicket& ticket, std::uint8_t difficulty_bits, std::uint32_t cap_bps);
std::uint32_t quorum_relative_participation_bps(std::size_t signature_count, std::size_t quorum_size);
bool ticket_difficulty_epoch_is_healthy(std::size_t active_validator_count, std::size_t committee_capacity,
                                        std::uint32_t average_round_x1000, std::uint32_t average_participation_bps);
bool ticket_difficulty_epoch_is_unhealthy(std::uint32_t average_round_x1000, std::uint32_t average_participation_bps);
std::uint8_t adjust_bounded_ticket_difficulty_bits(std::uint8_t previous_bits, std::size_t active_validator_count,
                                                   std::size_t committee_capacity,
                                                   std::size_t consecutive_healthy_epochs,
                                                   std::size_t consecutive_unhealthy_epochs,
                                                   std::uint8_t min_bits = MIN_BOUNDED_TICKET_DIFFICULTY_BITS,
                                                   std::uint8_t max_bits = MAX_BOUNDED_TICKET_DIFFICULTY_BITS);

bool epoch_ticket_better(const EpochTicket& candidate, const EpochTicket& current_best);

std::optional<EpochBestTicket> best_epoch_ticket_for_operator_id(std::uint64_t epoch, const Hash32& challenge_anchor,
                                                                 const PubKey32& operator_id,
                                                                 std::uint64_t source_height,
                                                                 std::uint64_t max_nonce = EPOCH_TICKET_MAX_NONCE);

std::map<PubKey32, EpochBestTicket> best_epoch_tickets_by_pubkey(const std::vector<EpochTicket>& tickets);

}  // namespace finalis::consensus
