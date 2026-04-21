// SPDX-License-Identifier: MIT

#include "consensus/epoch_committee.hpp"

#include <algorithm>

namespace finalis::consensus {

namespace {

bool epoch_committee_bond_ok(const PubKey32& pub, const std::map<PubKey32, ValidatorInfo>* validators,
                             bool require_bonded_validator) {
  if (!require_bonded_validator) return true;
  if (!validators) return true;
  auto it = validators->find(pub);
  if (it == validators->end()) return false;
  return it->second.has_bond && it->second.status != ValidatorStatus::BANNED;
}

}  // namespace

EpochCommitteeSnapshot derive_epoch_committee_snapshot(
    std::uint64_t epoch, const Hash32& challenge_anchor, const std::map<PubKey32, EpochBestTicket>& best_tickets,
    std::size_t committee_size_limit, const std::map<PubKey32, ValidatorInfo>* validators,
    bool require_bonded_validator) {
  EpochCommitteeSnapshot snapshot;
  snapshot.epoch = epoch;
  snapshot.challenge_anchor = challenge_anchor;

  std::vector<EpochCommitteeMember> eligible;
  eligible.reserve(best_tickets.size());
  for (const auto& [pub, best] : best_tickets) {
    if (!validate_epoch_ticket(best)) continue;
    if (best.epoch != epoch || best.challenge_anchor != challenge_anchor) continue;
    if (!epoch_committee_bond_ok(pub, validators, require_bonded_validator)) continue;
    eligible.push_back(EpochCommitteeMember{pub, best.work_hash, best.nonce, best.source_height});
  }

  std::sort(eligible.begin(), eligible.end(), [](const auto& a, const auto& b) {
    if (a.work_hash != b.work_hash) return a.work_hash < b.work_hash;
    if (a.nonce != b.nonce) return a.nonce < b.nonce;
    return a.participant_pubkey < b.participant_pubkey;
  });

  const auto take = std::min<std::size_t>(committee_size_limit, eligible.size());
  snapshot.selected_winners.assign(eligible.begin(), eligible.begin() + take);
  snapshot.ordered_members.reserve(snapshot.selected_winners.size());
  for (const auto& winner : snapshot.selected_winners) snapshot.ordered_members.push_back(winner.participant_pubkey);
  return snapshot;
}

}  // namespace finalis::consensus
