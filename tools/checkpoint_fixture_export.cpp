// SPDX-License-Identifier: MIT

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "consensus/availability_retention.hpp"
#include "common/network.hpp"
#include "consensus/canonical_derivation.hpp"
#include "consensus/committee_schedule.hpp"
#include "consensus/epoch_tickets.hpp"
#include "consensus/finalized_committee.hpp"
#include "consensus/monetary.hpp"
#include "consensus/randomness.hpp"
#include "crypto/hash.hpp"

using namespace finalis;

namespace {

struct FixtureValidatorSpec {
  std::string label;
  PubKey32 pubkey{};
  PubKey32 operator_id{};
  std::uint64_t bonded_amount{0};
  bool has_bond{true};
  std::uint64_t joined_height{0};
  consensus::ValidatorStatus status{consensus::ValidatorStatus::ACTIVE};
};

struct FixtureAvailabilitySpec {
  std::string label;
  PubKey32 operator_id{};
  availability::AvailabilityOperatorStatus status{availability::AvailabilityOperatorStatus::ACTIVE};
  std::uint64_t bond{0};
  std::int64_t service_score{0};
  std::uint64_t retained_prefix_count{0};
};

struct CheckpointFixtureCase {
  std::string name;
  std::size_t committee_size{0};
  std::uint64_t min_eligible{0};
  std::vector<FixtureValidatorSpec> validators;
  std::vector<FixtureAvailabilitySpec> availability;
  storage::FinalizedCommitteeDerivationMode previous_mode{storage::FinalizedCommitteeDerivationMode::NORMAL};
  storage::FinalizedCommitteeFallbackReason previous_reason{storage::FinalizedCommitteeFallbackReason::NONE};
};

struct ComparatorFixtureCase {
  std::string name;
  std::size_t committee_size{0};
  Hash32 seed{};
  std::vector<consensus::FinalizedCommitteeCandidate> candidates;
};

struct DerivedCheckpointFixtureExpected {
  std::uint64_t eligible_operator_count{0};
  storage::FinalizedCommitteeDerivationMode mode{storage::FinalizedCommitteeDerivationMode::NORMAL};
  storage::FinalizedCommitteeFallbackReason reason{storage::FinalizedCommitteeFallbackReason::NONE};
  std::vector<PubKey32> committee;
  std::vector<PubKey32> proposer_schedule;
};

PubKey32 pub_fill(std::uint8_t b) {
  PubKey32 out{};
  out.fill(b);
  return out;
}

Hash32 hash_fill(std::uint8_t b) {
  Hash32 out{};
  out.fill(b);
  return out;
}

std::string hex_of_bytes(const std::uint8_t* data, std::size_t size) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < size; ++i) oss << std::setw(2) << static_cast<unsigned>(data[i]);
  return oss.str();
}

template <typename Array>
std::string hex_of(const Array& arr) {
  return hex_of_bytes(arr.data(), arr.size());
}

std::string mode_name(storage::FinalizedCommitteeDerivationMode mode) {
  return mode == storage::FinalizedCommitteeDerivationMode::NORMAL ? "NORMAL" : "FALLBACK";
}

std::string reason_name(storage::FinalizedCommitteeFallbackReason reason) {
  switch (reason) {
    case storage::FinalizedCommitteeFallbackReason::NONE:
      return "NONE";
    case storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS:
      return "INSUFFICIENT_ELIGIBLE_OPERATORS";
    case storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING:
      return "HYSTERESIS_RECOVERY_PENDING";
  }
  return "UNKNOWN";
}

std::string availability_status_name(availability::AvailabilityOperatorStatus status) {
  switch (status) {
    case availability::AvailabilityOperatorStatus::WARMUP:
      return "WARMUP";
    case availability::AvailabilityOperatorStatus::ACTIVE:
      return "ACTIVE";
    case availability::AvailabilityOperatorStatus::PROBATION:
      return "PROBATION";
    case availability::AvailabilityOperatorStatus::EJECTED:
      return "EJECTED";
  }
  return "UNKNOWN";
}

std::string validator_join_source(const consensus::ValidatorInfo& info) {
  return info.joined_height == 0 ? "GENESIS" : "POST_GENESIS";
}

bool availability_fixture_operator_eligible(const availability::AvailabilityOperatorState& state,
                                            const availability::AvailabilityConfig& cfg) {
  return availability::operator_is_eligible(state, cfg);
}

DerivedCheckpointFixtureExpected derive_checkpoint_fixture_expected(const consensus::CanonicalDerivationConfig& cfg,
                                                                   const CheckpointFixtureCase& fixture,
                                                                   const consensus::CanonicalDerivedState& state,
                                                                   std::uint64_t epoch_start_height) {
  DerivedCheckpointFixtureExpected out;
  const auto effective_min_bond =
      std::max<std::uint64_t>(cfg.validator_bond_min_amount,
                              consensus::validator_min_bond_units(cfg.network, epoch_start_height,
                                                                  state.validators.active_sorted(epoch_start_height).size()));
  const auto econ = active_economics_policy(cfg.network, epoch_start_height);
  const auto availability_cfg = cfg.availability;
  std::map<PubKey32, const availability::AvailabilityOperatorState*> availability_by_operator;
  for (const auto& operator_state : state.availability_state.operators) {
    availability_by_operator[operator_state.operator_pubkey] = &operator_state;
    if (availability_fixture_operator_eligible(operator_state, availability_cfg)) ++out.eligible_operator_count;
  }

  out.mode = storage::FinalizedCommitteeDerivationMode::NORMAL;
  out.reason = storage::FinalizedCommitteeFallbackReason::NONE;
  if (out.eligible_operator_count < fixture.min_eligible) {
    out.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    out.reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS;
  } else if (fixture.previous_mode == storage::FinalizedCommitteeDerivationMode::FALLBACK &&
             out.eligible_operator_count < fixture.min_eligible + 1ULL) {
    out.mode = storage::FinalizedCommitteeDerivationMode::FALLBACK;
    out.reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING;
  }

  const bool enforce_availability = out.mode == storage::FinalizedCommitteeDerivationMode::NORMAL;
  std::vector<consensus::OperatorCommitteeInput> operator_inputs;
  std::map<PubKey32, std::pair<PubKey32, std::uint64_t>> by_operator;
  for (const auto& [pub, info] : state.validators.all()) {
    const bool base_eligible = info.has_bond && state.validators.is_active_for_height(pub, epoch_start_height) &&
                               (info.joined_height == 0 || info.bonded_amount >= effective_min_bond);
    if (!base_eligible) continue;
    const auto operator_id = consensus::canonical_operator_id(pub, info);
    const auto availability_it = availability_by_operator.find(operator_id);
    if (enforce_availability &&
        (availability_it == availability_by_operator.end() ||
         !availability_fixture_operator_eligible(*availability_it->second, availability_cfg))) {
      continue;
    }
    auto& seed = by_operator[operator_id];
    seed.second += info.bonded_amount;
    if (seed.first == PubKey32{} || pub < seed.first) seed.first = pub;
  }

  const auto epoch_randomness = state.committee_epoch_randomness_cache.at(epoch_start_height);
  const auto epoch_seed = consensus::committee_epoch_seed(epoch_randomness, epoch_start_height);
  operator_inputs.reserve(by_operator.size());
  for (const auto& [operator_id, seed] : by_operator) {
    if (seed.first == PubKey32{}) continue;
    consensus::OperatorCommitteeInput input;
    input.pubkey = seed.first;
    input.operator_id = operator_id;
    input.bonded_amount = seed.second;
    auto ticket = consensus::best_epoch_ticket_for_operator_id(epoch_start_height, epoch_seed, operator_id, epoch_start_height,
                                                               consensus::EPOCH_TICKET_MAX_NONCE);
    if (ticket.has_value()) {
      input.ticket_work_hash = ticket->work_hash;
      input.ticket_nonce = ticket->nonce;
      input.ticket_bonus_bps =
          consensus::ticket_pow_bonus_bps(*ticket, consensus::DEFAULT_TICKET_DIFFICULTY_BITS, econ.ticket_bonus_cap_bps);
    }
    operator_inputs.push_back(input);
  }

  const auto candidates = consensus::aggregate_operator_committee_candidates(operator_inputs, econ, epoch_start_height, 0);
  out.committee = consensus::select_finalized_committee(candidates, epoch_seed, fixture.committee_size);

  std::vector<consensus::ValidatorBestTicket> committee_tickets;
  for (const auto& member : out.committee) {
    auto it = std::find_if(candidates.begin(), candidates.end(),
                           [&](const auto& candidate) { return candidate.pubkey == member; });
    if (it == candidates.end()) continue;
    committee_tickets.push_back(consensus::ValidatorBestTicket{.validator_pubkey = it->pubkey,
                                                               .best_ticket_hash = it->ticket_work_hash,
                                                               .nonce = it->ticket_nonce});
  }
  const auto proposer_seed =
      consensus::compute_proposer_seed(epoch_seed, epoch_start_height, consensus::compute_committee_root(committee_tickets));
  out.proposer_schedule = consensus::proposer_schedule_from_committee(committee_tickets, proposer_seed);
  return out;
}

void write_text_file(const std::filesystem::path& path, const std::string& text) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::trunc);
  out << text;
}

consensus::CanonicalDerivationConfig make_cfg(std::size_t committee_size, std::uint64_t min_eligible) {
  consensus::CanonicalDerivationConfig cfg;
  cfg.network = mainnet_network();
  cfg.max_committee = committee_size;
  cfg.availability_min_eligible_operators = min_eligible;
  cfg.chain_id.network_name = cfg.network.name;
  cfg.chain_id.magic = cfg.network.magic;
  cfg.chain_id.protocol_version = cfg.network.protocol_version;
  cfg.chain_id.network_id_hex = hex_of(cfg.network.network_id);
  cfg.chain_id.genesis_hash_hex = hex_of(hash_fill(0xAB));
  cfg.availability.min_bond = BOND_AMOUNT;
  cfg.availability.eligibility_min_score = 0;
  return cfg;
}

consensus::CanonicalDerivedState build_state(const consensus::CanonicalDerivationConfig& cfg, const CheckpointFixtureCase& fixture,
                                             std::uint64_t epoch_start_height) {
  consensus::CanonicalDerivedState state;
  state.finalized_height = epoch_start_height - 1;
  state.finalized_identity = consensus::FinalizedIdentity::transition(hash_fill(0xCD));
  state.finalized_randomness = hash_fill(0x11);
  state.committee_epoch_randomness_cache[epoch_start_height] = hash_fill(0x22);
  state.validators.set_rules(consensus::ValidatorRules{
      .min_bond = BOND_AMOUNT,
      .warmup_blocks = 0,
      .cooldown_blocks = 0,
  });
  for (const auto& item : fixture.validators) {
    consensus::ValidatorInfo info;
    info.status = item.status;
    info.joined_height = item.joined_height;
    info.bonded_amount = item.bonded_amount;
    info.operator_id = item.operator_id;
    info.has_bond = item.has_bond;
    info.bond_outpoint = OutPoint{hash_fill(static_cast<std::uint8_t>(item.pubkey[0] + 1)), 0};
    state.validators.upsert(item.pubkey, info);
  }
  state.availability_state.current_epoch = 1;
  for (const auto& item : fixture.availability) {
    availability::AvailabilityOperatorState state_item;
    state_item.operator_pubkey = item.operator_id;
    state_item.bond = item.bond;
    state_item.status = item.status;
    state_item.service_score = item.service_score;
    state_item.retained_prefix_count = item.retained_prefix_count;
    state_item.warmup_epochs = 1;
    state.availability_state.operators.push_back(state_item);
  }
  availability::normalize_availability_consensus_state(&state.availability_state);

  const auto epoch_blocks = std::max<std::uint64_t>(1, cfg.network.committee_epoch_blocks);
  const auto previous_epoch_start = epoch_start_height > epoch_blocks ? epoch_start_height - epoch_blocks : 1;
  storage::FinalizedCommitteeCheckpoint previous;
  previous.epoch_start_height = previous_epoch_start;
  previous.epoch_seed = hash_fill(0x33);
  previous.ticket_difficulty_bits = consensus::DEFAULT_TICKET_DIFFICULTY_BITS;
  previous.derivation_mode = fixture.previous_mode;
  previous.fallback_reason = fixture.previous_reason;
  previous.availability_min_eligible_operators = fixture.min_eligible;
  state.finalized_committee_checkpoints[previous_epoch_start] = previous;
  return state;
}

std::vector<PubKey32> proposer_schedule_for_checkpoint(const consensus::CanonicalDerivationConfig& cfg,
                                                       consensus::CanonicalDerivedState state,
                                                       const storage::FinalizedCommitteeCheckpoint& checkpoint) {
  state.finalized_committee_checkpoints[checkpoint.epoch_start_height] = checkpoint;
  std::vector<PubKey32> schedule;
  for (std::size_t round = 0; round < checkpoint.ordered_members.size(); ++round) {
    auto leader = consensus::canonical_leader_for_height_round(cfg, state, checkpoint.epoch_start_height,
                                                               static_cast<std::uint32_t>(round));
    if (!leader.has_value()) break;
    schedule.push_back(*leader);
  }
  return schedule;
}

std::string checkpoint_fixture_json(const CheckpointFixtureCase& fixture) {
  const std::uint64_t epoch_start_height = 33;
  const auto cfg = make_cfg(fixture.committee_size, fixture.min_eligible);
  auto state = build_state(cfg, fixture, epoch_start_height);
  const auto effective_min_bond = std::max<std::uint64_t>(
      cfg.validator_bond_min_amount, consensus::validator_min_bond_units(cfg.network, epoch_start_height,
                                                                         state.validators.active_sorted(epoch_start_height).size()));
  const auto derived = derive_checkpoint_fixture_expected(cfg, fixture, state, epoch_start_height);
  const auto epoch_seed = consensus::committee_epoch_seed(state.committee_epoch_randomness_cache.at(epoch_start_height),
                                                          epoch_start_height);

  std::ostringstream oss;
  oss << "{\n";
  oss << "  \"fixture_version\": 1,\n";
  oss << "  \"name\": \"" << fixture.name << "\",\n";
  oss << "  \"protocol_params\": {\n";
  oss << "    \"epoch_start_height\": " << epoch_start_height << ",\n";
  oss << "    \"committee_size\": " << fixture.committee_size << ",\n";
  oss << "    \"min_eligible\": " << fixture.min_eligible << ",\n";
  oss << "    \"effective_min_bond\": " << effective_min_bond << ",\n";
  oss << "    \"ticket_difficulty_bits\": " << static_cast<unsigned>(consensus::DEFAULT_TICKET_DIFFICULTY_BITS) << ",\n";
  oss << "    \"ticket_bonus_cap_bps\": " << active_economics_policy(cfg.network, epoch_start_height).ticket_bonus_cap_bps << ",\n";
  oss << "    \"max_effective_bond_multiple\": " << active_economics_policy(cfg.network, epoch_start_height).max_effective_bond_multiple
      << ",\n";
  oss << "    \"availability_min_bond\": " << cfg.availability.min_bond << ",\n";
  oss << "    \"availability_eligibility_min_score\": " << cfg.availability.eligibility_min_score << ",\n";
  oss << "    \"epoch_seed\": \"" << hex_of(epoch_seed) << "\"\n";
  oss << "  },\n";
  const auto previous_epoch_start = epoch_start_height - cfg.network.committee_epoch_blocks;
  const auto& previous = state.finalized_committee_checkpoints.at(previous_epoch_start);
  oss << "  \"previous_checkpoint\": {\n";
  oss << "    \"derivation_mode\": \"" << mode_name(previous.derivation_mode) << "\",\n";
  oss << "    \"fallback_reason\": \"" << reason_name(previous.fallback_reason) << "\",\n";
  oss << "    \"ticket_difficulty_bits\": " << static_cast<unsigned>(previous.ticket_difficulty_bits) << "\n";
  oss << "  },\n";
  oss << "  \"validators\": [\n";
  for (std::size_t i = 0; i < fixture.validators.size(); ++i) {
    const auto& item = fixture.validators[i];
    const auto info = state.validators.get(item.pubkey).value();
    oss << "    {\"validator_pubkey\":\"" << hex_of(item.pubkey) << "\","
        << "\"operator_id\":\"" << hex_of(consensus::canonical_operator_id(item.pubkey, info)) << "\","
        << "\"join_source\":\"" << validator_join_source(info) << "\","
        << "\"bonded_amount\":" << info.bonded_amount << ","
        << "\"has_bond\":" << (info.has_bond ? "true" : "false") << ","
        << "\"lifecycle_active\":"
        << (state.validators.is_active_for_height(item.pubkey, epoch_start_height) ? "true" : "false") << "}";
    if (i + 1 != fixture.validators.size()) oss << ",";
    oss << "\n";
  }
  oss << "  ],\n";
  oss << "  \"availability\": [\n";
  for (std::size_t i = 0; i < state.availability_state.operators.size(); ++i) {
    const auto& item = state.availability_state.operators[i];
    oss << "    {\"operator_id\":\"" << hex_of(item.operator_pubkey) << "\","
        << "\"state\":\"" << availability_status_name(item.status) << "\","
        << "\"bond\":" << item.bond << ","
        << "\"service_score\":" << item.service_score << ","
        << "\"retained_prefix_count\":" << item.retained_prefix_count << "}";
    if (i + 1 != state.availability_state.operators.size()) oss << ",";
    oss << "\n";
  }
  oss << "  ],\n";
  oss << "  \"expected\": {\n";
  oss << "    \"eligible_operator_count\": " << derived.eligible_operator_count << ",\n";
  oss << "    \"derivation_mode\": \"" << mode_name(derived.mode) << "\",\n";
  oss << "    \"fallback_reason\": \"" << reason_name(derived.reason) << "\",\n";
  oss << "    \"committee\": [";
  for (std::size_t i = 0; i < derived.committee.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << hex_of(derived.committee[i]) << "\"";
  }
  oss << "],\n";
  oss << "    \"proposer_schedule\": [";
  for (std::size_t i = 0; i < derived.proposer_schedule.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << hex_of(derived.proposer_schedule[i]) << "\"";
  }
  oss << "]\n";
  oss << "  }\n";
  oss << "}\n";
  return oss.str();
}

std::string comparator_fixture_json(const ComparatorFixtureCase& fixture) {
  const auto ranked = consensus::rank_finalized_committee_candidates(fixture.candidates, fixture.seed);
  const auto selected = consensus::select_finalized_committee(fixture.candidates, fixture.seed, fixture.committee_size);
  std::ostringstream oss;
  oss << "{\n";
  oss << "  \"fixture_version\": 1,\n";
  oss << "  \"name\": \"" << fixture.name << "\",\n";
  oss << "  \"committee_size\": " << fixture.committee_size << ",\n";
  oss << "  \"seed\": \"" << hex_of(fixture.seed) << "\",\n";
  oss << "  \"candidates\": [\n";
  for (std::size_t i = 0; i < fixture.candidates.size(); ++i) {
    const auto& c = fixture.candidates[i];
    oss << "    {\"pubkey\":\"" << hex_of(c.pubkey) << "\","
        << "\"selection_id\":\"" << hex_of(c.selection_id) << "\","
        << "\"bonded_amount\":" << c.bonded_amount << ","
        << "\"capped_bonded_amount\":" << c.capped_bonded_amount << ","
        << "\"effective_weight\":" << c.effective_weight << ","
        << "\"ticket_work_hash\":\"" << hex_of(c.ticket_work_hash) << "\","
        << "\"ticket_nonce\":" << c.ticket_nonce << ","
        << "\"ticket_bonus_bps\":" << c.ticket_bonus_bps << ","
        << "\"ticket_bonus_cap_bps\":" << c.ticket_bonus_cap_bps << "}";
    if (i + 1 != fixture.candidates.size()) oss << ",";
    oss << "\n";
  }
  oss << "  ],\n";
  oss << "  \"expected_sorted_order\": [";
  for (std::size_t i = 0; i < ranked.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << hex_of(ranked[i].pubkey) << "\"";
  }
  oss << "],\n";
  oss << "  \"expected_selected_top_k\": [";
  for (std::size_t i = 0; i < selected.size(); ++i) {
    if (i) oss << ",";
    oss << "\"" << hex_of(selected[i]) << "\"";
  }
  oss << "]\n";
  oss << "}\n";
  return oss.str();
}

std::vector<CheckpointFixtureCase> checkpoint_cases() {
  const auto min_bond = 250ULL * consensus::BASE_UNITS_PER_COIN;
  const auto low_bond = 150ULL * consensus::BASE_UNITS_PER_COIN;
  return {
      CheckpointFixtureCase{
          .name = "normal_large_candidates",
          .committee_size = 3,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x11), pub_fill(0xA1), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x12), pub_fill(0xA2), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x13), pub_fill(0xA3), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v4", pub_fill(0x14), pub_fill(0xA4), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v5", pub_fill(0x15), pub_fill(0xA5), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xA1), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xA2), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xA3), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o4", pub_fill(0xA4), availability::AvailabilityOperatorStatus::WARMUP, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o5", pub_fill(0xA5), availability::AvailabilityOperatorStatus::PROBATION, min_bond, -1, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::NORMAL,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::NONE,
      },
      CheckpointFixtureCase{
          .name = "enter_fallback_below_min",
          .committee_size = 3,
          .min_eligible = 3,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x21), pub_fill(0xB1), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x22), pub_fill(0xB2), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x23), pub_fill(0xB3), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xB1), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xB2), availability::AvailabilityOperatorStatus::WARMUP, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xB3), availability::AvailabilityOperatorStatus::PROBATION, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::NORMAL,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::NONE,
      },
      CheckpointFixtureCase{
          .name = "sticky_fallback_equal_min",
          .committee_size = 3,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x31), pub_fill(0xC1), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x32), pub_fill(0xC2), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x33), pub_fill(0xC3), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xC1), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xC2), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xC3), availability::AvailabilityOperatorStatus::WARMUP, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::INSUFFICIENT_ELIGIBLE_OPERATORS,
      },
      CheckpointFixtureCase{
          .name = "recover_normal_min_plus_one",
          .committee_size = 3,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x41), pub_fill(0xD1), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x42), pub_fill(0xD2), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x43), pub_fill(0xD3), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xD1), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xD2), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xD3), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::FALLBACK,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::HYSTERESIS_RECOVERY_PENDING,
      },
      CheckpointFixtureCase{
          .name = "grandfathered_genesis_below_min_bond",
          .committee_size = 3,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x51), pub_fill(0xE1), low_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x52), pub_fill(0xE2), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x53), pub_fill(0xE3), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xE1), availability::AvailabilityOperatorStatus::ACTIVE, low_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xE2), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xE3), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::NORMAL,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::NONE,
      },
      CheckpointFixtureCase{
          .name = "post_genesis_below_min_bond_rejected",
          .committee_size = 3,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x61), pub_fill(0xF1), low_bond, true, 10, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x62), pub_fill(0xF2), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x63), pub_fill(0xF3), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xF1), availability::AvailabilityOperatorStatus::ACTIVE, low_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xF2), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xF3), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::NORMAL,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::NONE,
      },
      CheckpointFixtureCase{
          .name = "availability_ejected_excluded",
          .committee_size = 3,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v1", pub_fill(0x69), pub_fill(0xE9), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x6A), pub_fill(0xEA), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v3", pub_fill(0x6B), pub_fill(0xEB), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v4", pub_fill(0x6C), pub_fill(0xEC), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o1", pub_fill(0xE9), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0xEA), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o3", pub_fill(0xEB), availability::AvailabilityOperatorStatus::EJECTED, min_bond, -20, 1},
                  FixtureAvailabilitySpec{"o4", pub_fill(0xEC), availability::AvailabilityOperatorStatus::WARMUP, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::NORMAL,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::NONE,
      },
      CheckpointFixtureCase{
          .name = "shuffled_small_candidate_set",
          .committee_size = 4,
          .min_eligible = 2,
          .validators =
              {
                  FixtureValidatorSpec{"v3", pub_fill(0x73), pub_fill(0x73), min_bond, true, 40, consensus::ValidatorStatus::PENDING},
                  FixtureValidatorSpec{"v1", pub_fill(0x71), pub_fill(0x71), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v4", pub_fill(0x74), pub_fill(0x74), min_bond, false, 0, consensus::ValidatorStatus::ACTIVE},
                  FixtureValidatorSpec{"v2", pub_fill(0x72), pub_fill(0x72), min_bond, true, 0, consensus::ValidatorStatus::ACTIVE},
              },
          .availability =
              {
                  FixtureAvailabilitySpec{"o3", pub_fill(0x73), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o1", pub_fill(0x71), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o4", pub_fill(0x74), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
                  FixtureAvailabilitySpec{"o2", pub_fill(0x72), availability::AvailabilityOperatorStatus::ACTIVE, min_bond, 0, 1},
              },
          .previous_mode = storage::FinalizedCommitteeDerivationMode::NORMAL,
          .previous_reason = storage::FinalizedCommitteeFallbackReason::NONE,
      },
  };
}

std::vector<ComparatorFixtureCase> comparator_cases() {
  const auto seed = hash_fill(0x55);
  const auto units = consensus::BASE_UNITS_PER_COIN;
  return {
      ComparatorFixtureCase{
          .name = "primary_rank_tie_selection_id",
          .committee_size = 2,
          .seed = seed,
          .candidates =
              {
                  {.pubkey = pub_fill(0x21),
                   .selection_id = pub_fill(0x91),
                   .bonded_amount = 10 * units,
                   .capped_bonded_amount = 10 * units,
                   .effective_weight = consensus::effective_weight(10 * units),
                   .ticket_work_hash = hash_fill(0x11),
                   .ticket_nonce = 1,
                   .ticket_bonus_bps = 100,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x22),
                   .selection_id = pub_fill(0x92),
                   .bonded_amount = 10 * units,
                   .capped_bonded_amount = 10 * units,
                   .effective_weight = consensus::effective_weight(10 * units),
                   .ticket_work_hash = hash_fill(0x11),
                   .ticket_nonce = 1,
                   .ticket_bonus_bps = 100,
                   .ticket_bonus_cap_bps = 1000},
              },
      },
      ComparatorFixtureCase{
          .name = "selection_id_tie_pubkey",
          .committee_size = 2,
          .seed = hash_fill(0x56),
          .candidates =
              {
                  {.pubkey = pub_fill(0x31),
                   .selection_id = pub_fill(0xA0),
                   .bonded_amount = 10 * units,
                   .capped_bonded_amount = 10 * units,
                   .effective_weight = consensus::effective_weight(10 * units),
                   .ticket_work_hash = hash_fill(0x21),
                   .ticket_nonce = 2,
                   .ticket_bonus_bps = 100,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x32),
                   .selection_id = pub_fill(0xA0),
                   .bonded_amount = 10 * units,
                   .capped_bonded_amount = 10 * units,
                   .effective_weight = consensus::effective_weight(10 * units),
                   .ticket_work_hash = hash_fill(0x21),
                   .ticket_nonce = 2,
                   .ticket_bonus_bps = 100,
                   .ticket_bonus_cap_bps = 1000},
              },
      },
      ComparatorFixtureCase{
          .name = "deep_tiebreak_ticket_hash_nonce_cap",
          .committee_size = 3,
          .seed = hash_fill(0x57),
          .candidates =
              {
                  {.pubkey = pub_fill(0x41),
                   .selection_id = pub_fill(0xB1),
                   .bonded_amount = 12 * units,
                   .capped_bonded_amount = 12 * units,
                   .effective_weight = consensus::effective_weight(12 * units),
                   .ticket_work_hash = hash_fill(0x30),
                   .ticket_nonce = 4,
                   .ticket_bonus_bps = 400,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x42),
                   .selection_id = pub_fill(0xB2),
                   .bonded_amount = 12 * units,
                   .capped_bonded_amount = 12 * units,
                   .effective_weight = consensus::effective_weight(12 * units),
                   .ticket_work_hash = hash_fill(0x31),
                   .ticket_nonce = 3,
                   .ticket_bonus_bps = 400,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x43),
                   .selection_id = pub_fill(0xB3),
                   .bonded_amount = 12 * units,
                   .capped_bonded_amount = 12 * units,
                   .effective_weight = consensus::effective_weight(12 * units),
                   .ticket_work_hash = hash_fill(0x31),
                   .ticket_nonce = 5,
                   .ticket_bonus_bps = 400,
                   .ticket_bonus_cap_bps = 500},
              },
      },
      ComparatorFixtureCase{
          .name = "mixed_weights_and_bonus",
          .committee_size = 2,
          .seed = hash_fill(0x58),
          .candidates =
              {
                  {.pubkey = pub_fill(0x51),
                   .selection_id = pub_fill(0xC1),
                   .bonded_amount = 30 * units,
                   .capped_bonded_amount = 20 * units,
                   .effective_weight = consensus::effective_weight(20 * units),
                   .ticket_work_hash = hash_fill(0x40),
                   .ticket_nonce = 1,
                   .ticket_bonus_bps = 50,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x52),
                   .selection_id = pub_fill(0xC2),
                   .bonded_amount = 12 * units,
                   .capped_bonded_amount = 12 * units,
                   .effective_weight = consensus::effective_weight(12 * units),
                   .ticket_work_hash = hash_fill(0x10),
                   .ticket_nonce = 2,
                   .ticket_bonus_bps = 700,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x53),
                   .selection_id = pub_fill(0xC3),
                   .bonded_amount = 18 * units,
                   .capped_bonded_amount = 18 * units,
                   .effective_weight = consensus::effective_weight(18 * units),
                   .ticket_work_hash = hash_fill(0x20),
                   .ticket_nonce = 3,
                   .ticket_bonus_bps = 300,
                   .ticket_bonus_cap_bps = 1000},
              },
      },
      ComparatorFixtureCase{
          .name = "shuffled_input_order",
          .committee_size = 3,
          .seed = hash_fill(0x59),
          .candidates =
              {
                  {.pubkey = pub_fill(0x63),
                   .selection_id = pub_fill(0xD3),
                   .bonded_amount = 9 * units,
                   .capped_bonded_amount = 9 * units,
                   .effective_weight = consensus::effective_weight(9 * units),
                   .ticket_work_hash = hash_fill(0x13),
                   .ticket_nonce = 3,
                   .ticket_bonus_bps = 700,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x61),
                   .selection_id = pub_fill(0xD1),
                   .bonded_amount = 9 * units,
                   .capped_bonded_amount = 9 * units,
                   .effective_weight = consensus::effective_weight(9 * units),
                   .ticket_work_hash = hash_fill(0x11),
                   .ticket_nonce = 1,
                   .ticket_bonus_bps = 700,
                   .ticket_bonus_cap_bps = 1000},
                  {.pubkey = pub_fill(0x62),
                   .selection_id = pub_fill(0xD2),
                   .bonded_amount = 9 * units,
                   .capped_bonded_amount = 9 * units,
                   .effective_weight = consensus::effective_weight(9 * units),
                   .ticket_work_hash = hash_fill(0x12),
                   .ticket_nonce = 2,
                   .ticket_bonus_bps = 700,
                   .ticket_bonus_cap_bps = 1000},
              },
      },
  };
}

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path root =
      argc >= 2 ? std::filesystem::path(argv[1]) : (std::filesystem::current_path() / "tests" / "fixtures");
  const auto checkpoint_dir = root / "checkpoint";
  const auto comparator_dir = root / "comparator";
  std::filesystem::create_directories(checkpoint_dir);
  std::filesystem::create_directories(comparator_dir);

  for (const auto& fixture : checkpoint_cases()) {
    write_text_file(checkpoint_dir / (fixture.name + ".json"), checkpoint_fixture_json(fixture));
  }
  for (const auto& fixture : comparator_cases()) {
    write_text_file(comparator_dir / (fixture.name + ".json"), comparator_fixture_json(fixture));
  }
  return 0;
}
