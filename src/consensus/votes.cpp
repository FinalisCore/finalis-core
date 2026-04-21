// SPDX-License-Identifier: MIT

#include "consensus/votes.hpp"

namespace finalis::consensus {

VoteTallyResult VoteTracker::add_vote(const Vote& vote) {
  VoteTallyResult out;
  auto& seen = last_vote_by_validator_[vote.height];
  std::size_t total_votes = 0;
  for (const auto& [_, by_validator] : by_block_) total_votes += by_validator.size();
  if (total_votes >= limits_.max_votes_global) return out;

  const auto it = seen.find(vote.validator_pubkey);
  if (it != seen.end()) {
    const auto& prior = it->second;
    if (prior.round == vote.round) {
      if (prior.frontier_transition_id == vote.frontier_transition_id) {
        out.accepted = false;
        out.duplicate = true;
        return out;
      }
      out.accepted = false;
      out.equivocation = true;
      out.evidence = EquivocationEvidence{prior, vote};
      return out;
    }
    if (vote.round < prior.round) {
      out.accepted = false;
      out.duplicate = true;
      return out;
    }
  }

  const Key key{vote.height, vote.round, vote.frontier_transition_id};
  std::size_t block_keys_for_hr = 0;
  for (const auto& [k, _] : by_block_) {
    if (k.height == vote.height && k.round == vote.round) ++block_keys_for_hr;
  }
  if (by_block_.find(key) == by_block_.end() && block_keys_for_hr >= limits_.max_blocks_per_height_round) return out;
  by_block_[key][vote.validator_pubkey] = vote.signature;
  seen[vote.validator_pubkey] = vote;
  out.accepted = true;
  out.votes_for_block = by_block_[key].size();
  return out;
}

std::vector<FinalitySig> VoteTracker::signatures_for(std::uint64_t height, std::uint32_t round,
                                                      const Hash32& transition_id) const {
  const Key key{height, round, transition_id};
  auto it = by_block_.find(key);
  if (it == by_block_.end()) return {};
  std::vector<FinalitySig> out;
  out.reserve(it->second.size());
  for (const auto& [pub, sig] : it->second) {
    out.push_back(FinalitySig{pub, sig});
  }
  return out;
}

std::set<PubKey32> VoteTracker::participants_for(std::uint64_t height, std::uint32_t round) const {
  std::set<PubKey32> out;
  for (const auto& [k, sigs] : by_block_) {
    if (k.height != height || k.round != round) continue;
    for (const auto& [pub, _] : sigs) out.insert(pub);
  }
  return out;
}

void VoteTracker::clear_height(std::uint64_t height) {
  for (auto it = by_block_.begin(); it != by_block_.end();) {
    if (it->first.height == height) {
      it = by_block_.erase(it);
    } else {
      ++it;
    }
  }
  for (auto it = last_vote_by_validator_.begin(); it != last_vote_by_validator_.end();) {
    if (it->first == height) {
      it = last_vote_by_validator_.erase(it);
    } else {
      ++it;
    }
  }
}

TimeoutVoteTallyResult TimeoutVoteTracker::add_vote(const TimeoutVote& vote) {
  TimeoutVoteTallyResult out;
  auto& seen = last_vote_by_validator_[vote.height];
  std::size_t total_votes = 0;
  for (const auto& [_, by_validator] : by_round_) total_votes += by_validator.size();
  if (total_votes >= limits_.max_votes_global) return out;

  const auto it = seen.find(vote.validator_pubkey);
  if (it != seen.end()) {
    const auto& prior = it->second;
    if (prior.round == vote.round) {
      out.duplicate = true;
      return out;
    }
    if (vote.round < prior.round) {
      out.duplicate = true;
      return out;
    }
  }

  const Key key{vote.height, vote.round};
  std::size_t round_keys_for_height = 0;
  for (const auto& [k, _] : by_round_) {
    if (k.height == vote.height) ++round_keys_for_height;
  }
  if (by_round_.find(key) == by_round_.end() && round_keys_for_height >= limits_.max_rounds_per_height) return out;
  by_round_[key][vote.validator_pubkey] = vote.signature;
  seen[vote.validator_pubkey] = vote;
  out.accepted = true;
  out.votes_for_round = by_round_[key].size();
  return out;
}

std::vector<FinalitySig> TimeoutVoteTracker::signatures_for(std::uint64_t height, std::uint32_t round) const {
  const Key key{height, round};
  auto it = by_round_.find(key);
  if (it == by_round_.end()) return {};
  std::vector<FinalitySig> out;
  out.reserve(it->second.size());
  for (const auto& [pub, sig] : it->second) out.push_back(FinalitySig{pub, sig});
  return out;
}

void TimeoutVoteTracker::clear_height(std::uint64_t height) {
  for (auto it = by_round_.begin(); it != by_round_.end();) {
    if (it->first.height == height) it = by_round_.erase(it);
    else ++it;
  }
  for (auto it = last_vote_by_validator_.begin(); it != last_vote_by_validator_.end();) {
    if (it->first == height) it = last_vote_by_validator_.erase(it);
    else ++it;
  }
}

}  // namespace finalis::consensus
