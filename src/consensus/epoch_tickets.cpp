#include "consensus/epoch_tickets.hpp"

#include <algorithm>

#include "codec/bytes.hpp"
#include "consensus/monetary.hpp"
#include "crypto/hash.hpp"

namespace finalis::consensus {

Hash32 make_epoch_ticket_work_hash(std::uint64_t epoch, const Hash32& challenge_anchor, const PubKey32& operator_id,
                                   std::uint64_t nonce) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'E', 'P', 'O', 'C', 'H', '-', 'T', 'I', 'C', 'K', 'E', 'T', '-', 'V', '2'});
  w.u64le(epoch);
  w.bytes_fixed(challenge_anchor);
  w.bytes_fixed(operator_id);
  w.u64le(nonce);
  return crypto::sha256d(w.data());
}

bool validate_epoch_ticket(const EpochTicket& ticket) {
  return ticket.work_hash ==
         make_epoch_ticket_work_hash(ticket.epoch, ticket.challenge_anchor, ticket.participant_pubkey, ticket.nonce);
}

std::uint8_t leading_zero_bits(const Hash32& hash) {
  std::uint16_t zeros = 0;
  for (auto byte : hash) {
    if (byte == 0) {
      zeros += 8;
      if (zeros >= 255) return 255;
      continue;
    }
    for (int bit = 7; bit >= 0; --bit) {
      if (((byte >> bit) & 0x1U) == 0U) {
        ++zeros;
        if (zeros >= 255) return 255;
      } else {
        return static_cast<std::uint8_t>(zeros);
      }
    }
  }
  return static_cast<std::uint8_t>(std::min<std::uint16_t>(zeros, 255));
}

bool epoch_ticket_meets_difficulty(const EpochTicket& ticket, std::uint8_t difficulty_bits) {
  return leading_zero_bits(ticket.work_hash) >= difficulty_bits;
}

std::uint32_t ticket_pow_bonus_bps(const EpochTicket& ticket, std::uint8_t difficulty_bits) {
  return ticket_pow_bonus_bps(ticket, difficulty_bits, 2'500U);
}

std::uint32_t ticket_pow_bonus_bps(const EpochTicket& ticket, std::uint8_t difficulty_bits, std::uint32_t cap_bps) {
  const auto zeros = leading_zero_bits(ticket.work_hash);
  if (zeros < difficulty_bits) return 0;
  const auto surplus = static_cast<std::uint32_t>(zeros - difficulty_bits);
  const auto smooth = static_cast<std::uint32_t>(integer_sqrt(static_cast<std::uint64_t>(surplus + 1U)));
  return std::min<std::uint32_t>(cap_bps, 500U + smooth * 400U);
}

std::uint32_t quorum_relative_participation_bps(std::size_t signature_count, std::size_t quorum_size) {
  const auto denom = std::max<std::size_t>(1, quorum_size);
  const auto num = std::min<std::size_t>(signature_count, denom);
  return static_cast<std::uint32_t>((num * 10'000ULL) / denom);
}

bool ticket_difficulty_epoch_is_healthy(std::size_t active_validator_count, std::size_t committee_capacity,
                                        std::uint32_t average_round_x1000, std::uint32_t average_participation_bps) {
  return active_validator_count > committee_capacity && average_round_x1000 <= 1'250 && average_participation_bps >= 9'500;
}

bool ticket_difficulty_epoch_is_unhealthy(std::uint32_t average_round_x1000, std::uint32_t average_participation_bps) {
  return average_round_x1000 >= 2'500 && average_participation_bps < 8'500;
}

std::uint8_t adjust_bounded_ticket_difficulty_bits(std::uint8_t previous_bits, std::size_t active_validator_count,
                                                   std::size_t committee_capacity,
                                                   std::size_t consecutive_healthy_epochs,
                                                   std::size_t consecutive_unhealthy_epochs, std::uint8_t min_bits,
                                                   std::uint8_t max_bits) {
  std::uint8_t out = std::min<std::uint8_t>(max_bits, std::max<std::uint8_t>(min_bits, previous_bits));
  if (active_validator_count > committee_capacity && consecutive_healthy_epochs >= 2 && out < max_bits) {
    ++out;
    return out;
  }
  if (consecutive_unhealthy_epochs >= 3 && out > min_bits) {
    --out;
    return out;
  }
  return out;
}

bool epoch_ticket_better(const EpochTicket& candidate, const EpochTicket& current_best) {
  if (candidate.work_hash != current_best.work_hash) return candidate.work_hash < current_best.work_hash;
  if (candidate.nonce != current_best.nonce) return candidate.nonce < current_best.nonce;
  return candidate.participant_pubkey < current_best.participant_pubkey;
}

std::optional<EpochBestTicket> best_epoch_ticket_for_operator_id(std::uint64_t epoch, const Hash32& challenge_anchor,
                                                                 const PubKey32& operator_id, std::uint64_t source_height,
                                                                 std::uint64_t max_nonce) {
  if (epoch == 0) return std::nullopt;
  EpochBestTicket best;
  bool found = false;
  for (std::uint64_t nonce = 0; nonce <= max_nonce; ++nonce) {
    EpochTicket candidate;
    candidate.epoch = epoch;
    candidate.participant_pubkey = operator_id;
    candidate.challenge_anchor = challenge_anchor;
    candidate.nonce = nonce;
    candidate.work_hash =
        make_epoch_ticket_work_hash(candidate.epoch, candidate.challenge_anchor, candidate.participant_pubkey, nonce);
    candidate.source_height = source_height;
    candidate.origin = EpochTicketOrigin::LOCAL;
    if (!found || epoch_ticket_better(candidate, best)) {
      best = candidate;
      found = true;
    }
  }
  if (!found) return std::nullopt;
  return best;
}

std::map<PubKey32, EpochBestTicket> best_epoch_tickets_by_pubkey(const std::vector<EpochTicket>& tickets) {
  std::map<PubKey32, EpochBestTicket> out;
  for (const auto& ticket : tickets) {
    if (!validate_epoch_ticket(ticket)) continue;
    auto it = out.find(ticket.participant_pubkey);
    if (it == out.end() || epoch_ticket_better(ticket, it->second)) out[ticket.participant_pubkey] = ticket;
  }
  return out;
}

}  // namespace finalis::consensus
