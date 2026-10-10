// SPDX-License-Identifier: MIT

#pragma once

#include <map>
#include <optional>
#include <set>
#include <vector>

#include "consensus/validator_registry.hpp"
#include "utxo/tx.hpp"

namespace finalis::consensus {

struct VoteTallyResult {
  bool accepted{false};
  bool duplicate{false};
  bool equivocation{false};
  std::optional<EquivocationEvidence> evidence;
  std::size_t votes_for_block{0};
};

struct TimeoutVoteTallyResult {
  bool accepted{false};
  bool duplicate{false};
  // Vote's round is older than every round retained for its height while the
  // window is full. Benign under propagation lag: callers soft-reject it.
  bool stale{false};
  // Set when accepting this vote evicted the oldest retained round.
  std::optional<std::uint32_t> evicted_round;
  std::size_t votes_for_round{0};
};

// The precommit signatures for one (round, transition) at a height.
struct VoteSet {
  std::uint32_t round{0};
  Hash32 transition_id{};
  std::vector<FinalitySig> signatures;
};

class VoteTracker {
 public:
  struct Limits {
    std::size_t max_blocks_per_height_round{256};
    std::size_t max_votes_global{50'000};
  };

  VoteTracker() = default;
  explicit VoteTracker(Limits limits) : limits_(limits) {}
  VoteTallyResult add_vote(const Vote& vote);
  std::vector<FinalitySig> signatures_for(std::uint64_t height, std::uint32_t round, const Hash32& transition_id) const;
  std::set<PubKey32> participants_for(std::uint64_t height, std::uint32_t round) const;
  // Every (round, transition) with at least one vote at `height`, in (round, transition) order.
  std::vector<VoteSet> vote_sets_for_height(std::uint64_t height) const;
  void clear_height(std::uint64_t height);

 private:
  struct Key {
    std::uint64_t height;
    std::uint32_t round;
    Hash32 transition_id;

    bool operator<(const Key& o) const {
      return std::tie(height, round, transition_id) < std::tie(o.height, o.round, o.transition_id);
    }
  };

  std::map<Key, std::map<PubKey32, Sig64>> by_block_;
  std::map<std::uint64_t, std::map<PubKey32, Vote>> last_vote_by_validator_;
  Limits limits_{};
};

class TimeoutVoteTracker {
 public:
  struct Limits {
    // Sliding window: at most this many distinct rounds are retained per
    // height. A vote for a new round beyond it evicts the oldest round
    // instead of being rejected, so a long stall cannot exhaust the tracker.
    std::size_t max_rounds_per_height{256};
    std::size_t max_votes_global{50'000};
  };

  TimeoutVoteTracker() = default;
  explicit TimeoutVoteTracker(Limits limits) : limits_(limits) {}
  TimeoutVoteTallyResult add_vote(const TimeoutVote& vote);
  std::vector<FinalitySig> signatures_for(std::uint64_t height, std::uint32_t round) const;
  void clear_height(std::uint64_t height);

 private:
  struct Key {
    std::uint64_t height;
    std::uint32_t round;

    bool operator<(const Key& o) const { return std::tie(height, round) < std::tie(o.height, o.round); }
  };

  std::map<Key, std::map<PubKey32, Sig64>> by_round_;
  std::map<std::uint64_t, std::map<PubKey32, TimeoutVote>> last_vote_by_validator_;
  Limits limits_{};
};

}  // namespace finalis::consensus
