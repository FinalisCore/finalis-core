// SPDX-License-Identifier: MIT

// Stateful consensus + storage-fault fuzzer. One validator node (4-validator genesis, no P2P, timers
// parked, proposals paused) runs a script of operations: proposals and re-proposals with POL and TC,
// duplicate and reordered PREVOTE / PRECOMMIT / TIMEOUT_VOTE messages from the other committee
// members, round changes, storage faults (tests/support/storage_fault_injection: WAL write EIO or
// ENOSPC, WAL sync EIO, sync-then-EIO) and process restarts over the same database.
//
// Oracles, checked after every operation across the whole execution (restarts included):
//   double-precommit   two own precommits at one (height, round)
//   double-prevote     two own prevote records at one (height, round)
//   lock-rule          an own prevote for X at round r while the latest own precommit at a round
//                      r1 <= r is for Y != X, without a POL for X from a round >= r1 on the proposal
//   precommit-durable  after a restart, a precommit already sent at an open height has no lock at or
//                      after its round (the node can contradict it)
//   prevote-durable    after a restart, a prevote record of an open height is gone. The stall
//                      rebroadcast sends in-memory prevote records, so every record counts as sent;
//                      with timers parked the harness never runs that rebroadcast itself.
//   finality           a finalized (height, transition) changes or a reported height rolls back
//   restart            the node cannot start again over its own database
//   signed-after-fail-stop  a validator-key signature made after a failed safety write put the node
//                      in fail-stop (Node::signatures_after_fail_stop_for_test), before the restart
// Fault model: of the three other committee members, keys[3] is Byzantine (signs anything) and
// keys[1], keys[2] keep the honest-signer constraints the oracles rely on (one vote per
// (height, round, kind); no vote for a transition below its own round). FINALIS_FUZZ_BYZANTINE_MAJORITY=1
// drops them (beyond f: three arbitrary signers can certify anything).
// "Sent" precommits: recorded in the vote tracker (broadcast and recorded together), or present in
// the stall rebroadcast set (rebroadcast-probe op).
//
// Reproduction: every byte the script reader hands out (including zero padding past the end) is
// logged, so the history since the fixture was created is one exact input. On a violation it is
// written to $FINALIS_FUZZ_ARTIFACT_DIR (default: current directory) as
// crash-<oracle>-<hash>.bin; replay with `fuzz_consensus_persistence <file>...`, each against a fresh
// node. Storage faults need a Linux RocksDB build; elsewhere fault ops are no-ops.
//
// Standalone smoke: FINALIS_FUZZ_ITERS (default 40 scripts), FINALIS_FUZZ_SEED, FINALIS_FUZZ_FAULTS
// (default 1; 0 disables fault ops, the configuration that must stay clean), FINALIS_FUZZ_BYZANTINE_MAJORITY.
// Exit 1 on a violation.
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/).

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

#include "common/keystore.hpp"
#include "crypto/hash.hpp"
#include "genesis/genesis.hpp"
#include "support/test_genesis.hpp"
#include "node/node.hpp"
#include "crypto/bls12_381.hpp"
#include "p2p/messages.hpp"
#include "support/storage_fault_injection.hpp"
#include "utxo/validate.hpp"

using namespace finalis;
namespace faults = finalis::test::storage_faults;

namespace {

constexpr std::size_t kValidators = 4;
constexpr std::uint32_t kRounds = 6;
constexpr std::size_t kMaxProposals = 12;

// Script reader that logs every byte it returns, so the consumed stream replays exactly.
struct Cursor {
  const Bytes& in;
  Bytes* log;
  std::size_t pos{0};
  bool done() const { return pos >= in.size(); }
  std::uint8_t u8() {
    const std::uint8_t b = pos < in.size() ? in[pos] : 0;
    ++pos;
    if (log) log->push_back(b);
    return b;
  }
};

bool write_genesis(const std::string& path, const std::vector<crypto::KeyPair>& keys) {
  genesis::Document d;
  d.version = genesis::kGenesisVersion;
  d.network_name = "mainnet";
  d.protocol_version = mainnet_network().protocol_version;
  d.network_id = mainnet_network().network_id;
  d.magic = mainnet_network().magic;
  d.genesis_time_unix = 1735689600ULL;
  d.initial_height = 0;
  d.initial_active_set_size = static_cast<std::uint32_t>(kValidators);
  d.initial_committee_params.min_committee = static_cast<std::uint32_t>(kValidators);
  d.initial_committee_params.max_committee = static_cast<std::uint32_t>(mainnet_network().max_committee);
  d.initial_committee_params.sizing_rule = "min(MAX_COMMITTEE,ACTIVE_SIZE)";
  d.initial_committee_params.c = 2;
  d.monetary_params_ref = "README.md#monetary-policy-7m-hard-cap";
  d.note = "fuzz-consensus-persistence";
  for (std::size_t i = 0; i < kValidators; ++i) d.initial_validators.push_back(keys[i].public_key);
  test::fill_test_genesis_bls(d, keys);
  std::ofstream out(path, std::ios::trunc);
  out << genesis::to_json(d);
  return out.good();
}

struct Fixture {
  std::string base;
  node::NodeConfig cfg;
  std::unique_ptr<node::Node> node;
  std::vector<crypto::KeyPair> keys;
  Hash32 domain{};

  ~Fixture() {
    faults::disarm();
    if (node) node->stop();
    node.reset();
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
  }

  bool start_node() {
    node = std::make_unique<node::Node>(cfg);
    if (!node->init()) return false;
    node->start();
    (void)node->pause_proposals_for_test(true);
    domain = node->consensus_domain_for_test();
    return true;
  }

  // Crash + restart: a new process over the same database; the disk is healthy again.
  bool restart() {
    faults::disarm();
    node->stop();
    node.reset();
    return start_node();
  }
};

std::unique_ptr<Fixture> make_fixture() {
  static std::uint64_t instance = 0;
  auto fx = std::make_unique<Fixture>();
  fx->keys = node::Node::deterministic_test_keypairs();
  fx->base = (std::filesystem::temp_directory_path() /
              ("finalis_fuzz_consensus_persistence_" + std::to_string(::getpid()) + "_" + std::to_string(instance++)))
                 .string();
  std::error_code ec;
  std::filesystem::remove_all(fx->base, ec);
  std::filesystem::create_directories(fx->base);
  auto& cfg = fx->cfg;
  cfg.allow_unencrypted_keystore = true;
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();
  cfg.network.round_timeout_ms = 3'600'000;  // timers parked: only the script moves rounds
  cfg.network.max_round_timeout_ms = 3'600'000;
  cfg.network.min_block_interval_ms = 100;
  cfg.db_path = fx->base + "/node0";
  cfg.genesis_path = fx->base + "/genesis.json";
  cfg.allow_unsafe_genesis_override = true;
  cfg.validator_key_file = cfg.db_path + "/keystore/validator.json";
  cfg.validator_passphrase = "fuzz";
  if (!write_genesis(cfg.genesis_path, fx->keys)) return nullptr;
  std::array<std::uint8_t, 32> seed{};  // node 0 = deterministic_test_keypairs()[0]
  for (std::size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(19 + j);
  keystore::ValidatorKey key;
  std::string err;
  if (!keystore::create_validator_keystore(cfg.validator_key_file, cfg.validator_passphrase, "mainnet", "sc", seed, &key,
                                           &err)) {
    return nullptr;
  }
  if (!fx->start_node()) return nullptr;
  return fx;
}

struct Violation {
  std::string oracle;
  std::string detail;
};

bool skip_d7_rollback_from_env();

class Runner {
 public:
  struct Stats {
    std::uint64_t ops{0};
    std::uint64_t proposals_accepted{0};
    std::uint64_t faults_armed{0};
    std::uint64_t faults_injected{0};
    std::uint64_t restarts{0};
    std::uint64_t own_prevotes{0};
    std::uint64_t own_precommits{0};
    std::uint64_t finalized{0};
    std::uint64_t skipped_rollbacks{0};
  } stats;

  Runner(Fixture& fx, bool faults_enabled, bool byzantine_majority)
      : fx_(fx), faults_enabled_(faults_enabled), byzantine_majority_(byzantine_majority) {}

  const Bytes& history() const { return history_; }
  const std::vector<std::string>& trace() const { return trace_; }

  // Runs one script; returns the first violation (the runner state is then unspecified).
  std::optional<Violation> run(const Bytes& in) {
    Cursor c{in, &history_};
    while (!c.done()) {
      deliver_time_signatures();
      const std::uint8_t op = c.u8() % 12;
      ++stats.ops;
      switch (op) {
        case 0: propose(c); break;
        case 1: repropose(c); break;
        case 2: prevote(c, false); break;
        case 3: prevote(c, true); break;  // a polka from the other members
        case 4: precommit(c, false); break;
        case 5: precommit(c, true); break;  // a quorum of the other members
        case 6: timeout_quorum(c); break;
        case 7: advance_round(c); break;
        case 8: redeliver(); break;
        case 9: arm_fault(c); break;
        case 10: restart(); break;
        default: rebroadcast_probe(); break;
      }
      if (auto v = observe(); v.has_value()) return v;
      if (restart_failed_) return Violation{"restart", "init() failed over the node's own database"};
    }
    settle();
    return observe();
  }

 private:
  struct Proposal {
    std::uint64_t height;
    std::uint32_t round;  // the transition's round
    Hash32 id;
    Bytes bytes;
    PubKey32 leader;
  };

  std::uint64_t time_signatures_delivered_{0};  // tip whose peer time signatures the node holds

  std::uint64_t next_height() const { return fx_.node->status().height + 1; }
  std::uint32_t current_round() const { return fx_.node->status().round; }

  void note(const std::string& s) {
    trace_.push_back(s);
    if (trace_.size() > 64) trace_.erase(trace_.begin());
  }

  const crypto::KeyPair* key_for(const PubKey32& pub) const {
    for (const auto& k : fx_.keys) {
      if (k.public_key == pub) return &k;
    }
    return nullptr;
  }

  // The other committee members (never the node's own key: its votes come only from the node).
  std::vector<const crypto::KeyPair*> others(std::size_t first, std::size_t count) const {
    std::vector<const crypto::KeyPair*> out;
    for (std::size_t i = 0; i < count && i < kValidators - 1; ++i) out.push_back(&fx_.keys[1 + (first + i) % (kValidators - 1)]);
    return out;
  }

  std::uint32_t pick_round(Cursor& c) const {
    const std::uint8_t b = c.u8();
    const std::uint32_t cur = current_round();
    if (b % 3 != 0) return cur;
    const int offset = static_cast<int>((b >> 2) % 5) - 2;  // -2 .. +2
    return offset < 0 && cur < static_cast<std::uint32_t>(-offset) ? 0 : static_cast<std::uint32_t>(static_cast<int>(cur) + offset);
  }

  const Proposal* pick_proposal(Cursor& c) const {
    const std::uint8_t b = c.u8();
    if (proposals_.empty()) return nullptr;
    const std::uint64_t h = next_height();
    std::vector<const Proposal*> open;
    for (const auto& p : proposals_) {
      if (p.height == h) open.push_back(&p);
    }
    if (open.empty()) return nullptr;
    return open[b % open.size()];
  }

  Hash32 pick_id(Cursor& c) const {
    if (const auto* p = pick_proposal(c)) return p->id;
    Hash32 h{};
    h[0] = c.u8();
    return h;
  }

  TimeoutCertificate tc_for(std::uint64_t h, std::uint32_t round, std::size_t first) const {
    TimeoutCertificate tc;
    tc.height = h;
    tc.round = round;
    const Bytes msg = timeout_vote_signing_message(fx_.domain, h, round);
    for (const auto* kp : others(first, 3)) {
      tc.signatures.push_back(FinalitySig{kp->public_key, crypto::ed25519_sign(msg, kp->private_key).value_or(Sig64{})});
    }
    return tc;
  }

  QuorumCertificate polka_for(std::uint64_t h, std::uint32_t round, const Hash32& id, std::size_t first) const {
    QuorumCertificate qc;
    qc.height = h;
    qc.round = round;
    qc.frontier_transition_id = id;
    const Bytes msg = prevote_signing_message(fx_.domain, h, round, id);
    for (const auto* kp : others(first, 3)) {
      qc.signatures.push_back(FinalitySig{kp->public_key, crypto::ed25519_sign(msg, kp->private_key).value_or(Sig64{})});
    }
    return qc;
  }

  // Highest POL round an accepted proposal for (h, r, id) carried; -1 for none (not 0: a missing
  // entry must not read as a round-0 POL).
  void record_pol(const p2p::ProposeMsg& m, const Hash32& id) {
    auto [it, inserted] = pol_by_slot_.emplace(std::make_tuple(m.height, m.round, id), -1);
    it->second = std::max(it->second, m.pol ? static_cast<int>(m.pol->round) : -1);
  }

  void send_propose(const p2p::ProposeMsg& msg, const crypto::KeyPair& signer, const Hash32& id) {
    p2p::ProposeMsg m = msg;
    const std::optional<std::uint32_t> pol_round = m.pol ? std::optional<std::uint32_t>(m.pol->round) : std::nullopt;
    m.proposer_signature =
        crypto::ed25519_sign(propose_signing_message(fx_.domain, m.height, m.round, id, pol_round), signer.private_key)
            .value_or(Sig64{});
    const auto res = fx_.node->inject_network_propose_result_for_test(m);
    if (res == "accepted") {
      ++stats.proposals_accepted;
      record_pol(m, id);
    }
    last_propose_ = m;
    last_propose_signer_ = &signer;
    last_propose_id_ = id;
    last_kind_ = Last::Propose;
  }

  // A fresh proposal in a round this node leads (its own build carries a valid leader VRF), possibly
  // equivocated by the leader (timestamp shifted, re-signed): two transitions in one round.
  void propose(Cursor& c) {
    const std::uint64_t h = next_height();
    std::uint32_t round = current_round() + c.u8() % 3;
    const auto me = fx_.node->local_validator_pubkey_for_test();
    bool found = false;
    for (std::uint32_t r = round; r < round + kRounds; ++r) {
      if (fx_.node->proposer_for_height_round_for_test(h, r) == me) {
        round = r;
        found = true;
        break;
      }
    }
    if (!found) return;
    (void)fx_.node->advance_round_for_test(h, round);
    auto proposal = fx_.node->build_frontier_proposal_for_test(h, round);
    if (!proposal.has_value()) return;
    if (c.u8() % 3 == 0) proposal->transition.timestamp += 1 + c.u8() % 29;
    const Hash32 id = proposal->transition.transition_id();
    const auto* leader = key_for(proposal->transition.leader_pubkey);
    if (!leader) return;
    if (proposals_.size() == kMaxProposals) proposals_.erase(proposals_.begin());
    proposals_.push_back(Proposal{h, round, id, proposal->serialize(), proposal->transition.leader_pubkey});
    p2p::ProposeMsg msg;
    msg.height = h;
    msg.round = round;
    msg.prev_finalized_hash = proposal->transition.prev_finalized_hash;
    msg.frontier_proposal_bytes = proposal->serialize();
    if (round > 0) msg.justify_tc = tc_for(h, round - 1, c.u8());
    note("propose h=" + std::to_string(h) + " r=" + std::to_string(round) + " id=" + short_id(id));
    send_propose(msg, *leader, id);
  }

  // A known transition re-proposed in the current round by that round's leader, with a POL from an
  // earlier round (valid value / lock change), as test_stalled_height_regossips_old_round_precommits does.
  void repropose(Cursor& c) {
    const auto* p = pick_proposal(c);
    if (!p) return;
    const std::uint64_t h = next_height();
    const std::uint32_t round = current_round();
    if (round == 0 || p->round >= round) return;
    const std::uint32_t pol_round = std::min<std::uint32_t>(round - 1, p->round + c.u8() % (round - p->round + 1));
    const auto leader_pub = fx_.node->proposer_for_height_round_for_test(h, round);
    const auto* leader = leader_pub ? key_for(*leader_pub) : nullptr;
    if (!leader) return;
    p2p::ProposeMsg msg;
    msg.height = h;
    msg.round = round;
    auto parsed = FrontierProposal::parse(p->bytes);
    if (!parsed) return;
    msg.prev_finalized_hash = parsed->transition.prev_finalized_hash;
    msg.frontier_proposal_bytes = p->bytes;
    if (c.u8() % 4 != 0) msg.pol = polka_for(h, pol_round, p->id, c.u8());
    msg.justify_tc = tc_for(h, round - 1, c.u8());
    note("repropose h=" + std::to_string(h) + " r=" + std::to_string(round) + " id=" + short_id(p->id) +
         " pol=" + (msg.pol ? std::to_string(pol_round) : std::string("none")));
    send_propose(msg, *leader, p->id);
  }

  // Honest-signer constraints for keys[1] and keys[2] (keys[3] is the Byzantine member).
  bool honest_may_sign(const Vote& v, bool is_precommit) {
    if (byzantine_majority_ || v.validator_pubkey == fx_.keys[3].public_key) return true;
    for (const auto& p : proposals_) {
      if (p.id == v.frontier_transition_id && p.round > v.round) return false;
    }
    auto [it, inserted] = honest_votes_.emplace(std::make_tuple(v.validator_pubkey, v.height, v.round, is_precommit),
                                                v.frontier_transition_id);
    return inserted || it->second == v.frontier_transition_id;
  }

  void send_vote(const Vote& v, bool is_precommit) {
    if (!honest_may_sign(v, is_precommit)) return;
    (void)(is_precommit ? fx_.node->inject_network_vote_result_for_test(v) : fx_.node->inject_network_prevote_result_for_test(v));
    last_vote_ = v;
    last_vote_precommit_ = is_precommit;
    last_kind_ = Last::Vote;
  }

  Vote make_vote(std::uint64_t h, std::uint32_t r, const Hash32& id, const crypto::KeyPair& kp, bool is_precommit) const {
    Vote v;
    v.height = h;
    v.round = r;
    v.frontier_transition_id = id;
    v.validator_pubkey = kp.public_key;
    const Bytes msg = is_precommit ? vote_signing_message(fx_.domain, h, r, id) : prevote_signing_message(fx_.domain, h, r, id);
    v.signature = crypto::ed25519_sign(msg, kp.private_key).value_or(Sig64{});
    return v;
  }

  void prevote(Cursor& c, bool quorum) {
    const std::uint64_t h = next_height();
    const std::uint32_t r = pick_round(c);
    const Hash32 id = pick_id(c);
    const std::size_t first = c.u8();
    const std::size_t n = quorum ? 2 + c.u8() % 2 : 1;
    note(std::string(quorum ? "polka" : "prevote") + " r=" + std::to_string(r) + " id=" + short_id(id) + " n=" + std::to_string(n));
    for (const auto* kp : others(first, n)) send_vote(make_vote(h, r, id, *kp, false), false);
  }

  void precommit(Cursor& c, bool quorum) {
    const std::uint64_t h = next_height();
    const std::uint32_t r = pick_round(c);
    const Hash32 id = pick_id(c);
    const std::size_t first = c.u8();
    const std::size_t n = quorum ? 3 : 1;
    note(std::string(quorum ? "commit-quorum" : "precommit") + " r=" + std::to_string(r) + " id=" + short_id(id));
    for (const auto* kp : others(first, n)) send_vote(make_vote(h, r, id, *kp, true), true);
  }

  void timeout_quorum(Cursor& c) {
    const std::uint64_t h = next_height();
    const std::uint32_t r = pick_round(c);
    note("tc r=" + std::to_string(r));
    for (const auto* kp : others(c.u8(), 3)) {
      TimeoutVote v;
      v.height = h;
      v.round = r;
      v.validator_pubkey = kp->public_key;
      v.signature = crypto::ed25519_sign(timeout_vote_signing_message(fx_.domain, h, r), kp->private_key).value_or(Sig64{});
      (void)fx_.node->inject_timeout_vote_for_test(v);
    }
  }

  void advance_round(Cursor& c) {
    const std::uint32_t r = pick_round(c);
    note("advance r=" + std::to_string(r));
    (void)fx_.node->advance_round_for_test(next_height(), r);
  }

  // Duplicate delivery of the last message (proposal re-delivery re-enters on_candidate_body_locked).
  void redeliver() {
    note("redeliver");
    if (last_kind_ == Last::Propose && last_propose_ && last_propose_signer_) {
      // Recorded like a first delivery: the first one may have been rejected (e.g. a halted node
      // after a fault) and this one accepted, and lock-rule needs the POL it carries.
      if (fx_.node->inject_network_propose_result_for_test(*last_propose_) == "accepted") {
        record_pol(*last_propose_, last_propose_id_);
      }
    } else if (last_kind_ == Last::Vote && last_vote_) {
      (void)(last_vote_precommit_ ? fx_.node->inject_network_vote_result_for_test(*last_vote_)
                                  : fx_.node->inject_network_prevote_result_for_test(*last_vote_));
    }
  }

  void arm_fault(Cursor& c) {
    const std::uint8_t b = c.u8();
    if (!faults_enabled_) return;
#ifdef FINALIS_STORAGE_FAULTS
    static constexpr faults::Mode kModes[] = {faults::Mode::FailWalWrite, faults::Mode::FailWalWriteNoSpace,
                                              faults::Mode::FailWalSync, faults::Mode::SyncThenFailWal};
    const auto mode = kModes[b % 4];
    note("fault mode=" + std::to_string(b % 4));
    // Stays armed until the restart: RocksDB refuses every write after the first failure anyway.
    faults::arm(fx_.cfg.db_path, mode, -1);
    ++stats.faults_armed;
#else
    (void)b;
#endif
  }

  void settle() { std::this_thread::sleep_for(std::chrono::milliseconds(50)); }

  // The other members' time signatures on the finalized tip, as honest peers send them once it is
  // final: the node's own proposal for the next height waits for a threshold of them. Consumes no
  // script bytes.
  void deliver_time_signatures() {
    const auto tip = fx_.node->status().height;
    if (tip == 0 || tip == time_signatures_delivered_) return;
    const auto msg = time_signature_message(fx_.domain, tip);
    for (const auto* kp : others(0, kValidators - 1)) {
      const auto sk = crypto::bls_key_from_validator_seed(kp->private_key);
      const auto sig = sk ? crypto::bls_sign(*sk, msg, crypto::kBlsTimeSignatureDst) : std::nullopt;
      if (sig) (void)fx_.node->inject_time_signature_for_test(p2p::TimeSignatureMsg{tip, kp->public_key, *sig});
    }
    time_signatures_delivered_ = tip;
  }

  void restart() {
    note("restart");
    settle();
    if (auto v = observe(); v.has_value()) {
      pending_ = v;
      return;
    }
    stats.faults_injected += static_cast<std::uint64_t>(faults::injected());
    if (!fx_.restart()) {
      restart_failed_ = true;
      return;
    }
    ++stats.restarts;
    after_restart_ = true;
    time_signatures_delivered_ = 0;
  }

  void rebroadcast_probe() {
    note("rebroadcast-probe");
    const auto me = fx_.node->local_validator_pubkey_for_test();
    for (const auto& v : fx_.node->precommits_for_rebroadcast_for_test(next_height())) {
      if (v.validator_pubkey == me) mark_precommit(v.height, v.round, v.frontier_transition_id);
    }
  }

  static std::string short_id(const Hash32& id) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 4; ++i) {
      s += hex[id[i] >> 4];
      s += hex[id[i] & 15];
    }
    return s;
  }

  std::optional<Violation> mark_precommit(std::uint64_t h, std::uint32_t r, const Hash32& id) {
    auto [it, inserted] = sent_pc_.emplace(std::make_pair(h, r), id);
    if (inserted) {
      ++stats.own_precommits;
      note("OWN precommit h=" + std::to_string(h) + " r=" + std::to_string(r) + " id=" + short_id(id));
      return std::nullopt;
    }
    if (it->second != id) {
      return Violation{"double-precommit", "h=" + std::to_string(h) + " r=" + std::to_string(r) + " " + short_id(it->second) +
                                               " vs " + short_id(id)};
    }
    return std::nullopt;
  }

  std::vector<Hash32> known_ids(std::uint64_t h) const {
    std::vector<Hash32> ids;
    for (const auto& p : proposals_) {
      if (p.height == h) ids.push_back(p.id);
    }
    return ids;
  }

  std::optional<Violation> observe() {
    if (pending_) {
      auto v = pending_;
      pending_.reset();
      return v;
    }
    auto& n = *fx_.node;
    if (const auto late = n.signatures_after_fail_stop_for_test(); late > 0) {
      return Violation{"signed-after-fail-stop", std::to_string(late) + " signature(s) after: " + n.safety_storage_failure_for_test()};
    }
    const auto st = n.status();
    const std::uint64_t h = st.height + 1;

    // finality: a finalized height never changes its transition or rolls back.
    if (st.height < max_height_) {
      if (!skip_d7_rollback_from_env()) {
        return Violation{"finality", "reported height rolled back from " + std::to_string(max_height_) + " to " +
                                         std::to_string(st.height)};
      }
      ++stats.skipped_rollbacks;
      // Known D7 rollback: the heights above the durable tip were never durably finalized, so the
      // node may finalize them again with another transition; keep checking the other oracles.
      finalized_.erase(finalized_.upper_bound(st.height), finalized_.end());
      max_height_ = st.height;
    }
    if (st.height > 0) {
      auto [it, inserted] = finalized_.emplace(st.height, st.transition_hash);
      if (inserted) ++stats.finalized;
      if (!inserted && it->second != st.transition_hash) {
        return Violation{"finality", "height " + std::to_string(st.height) + " changed transition"};
      }
    }
    max_height_ = std::max(max_height_, st.height);

    const auto ids = known_ids(h);
    const std::uint32_t hi = std::max(current_round(), max_round_seen_) + kRounds;
    if (after_restart_) {
      after_restart_ = false;
      // precommit-durable / prevote-durable at the open height.
      const auto lock = n.local_vote_lock_for_test(h);
      for (const auto& [slot, id] : sent_pc_) {
        if (slot.first != h) continue;
        const bool covered = lock.has_value() && (lock->second > slot.second || (lock->second == slot.second && lock->first == id));
        if (!covered) {
          return Violation{"precommit-durable", "h=" + std::to_string(h) + " r=" + std::to_string(slot.second) + " id=" + short_id(id) +
                                                    " lock=" + (lock ? short_id(lock->first) + "@" + std::to_string(lock->second) : "none")};
        }
      }
      for (const auto& [slot, id] : seen_pv_) {
        if (slot.first != h) continue;
        if (!n.local_prevote_recorded_for_test(h, slot.second, id)) {
          return Violation{"prevote-durable", "h=" + std::to_string(h) + " r=" + std::to_string(slot.second) + " id=" + short_id(id)};
        }
      }
    }
    for (std::uint32_t r = 0; r <= hi; ++r) {
      for (const auto& id : ids) {
        if (n.local_vote_recorded_for_test(h, r, id)) {
          if (auto v = mark_precommit(h, r, id)) return v;
        }
        if (!n.local_prevote_recorded_for_test(h, r, id)) continue;
        max_round_seen_ = std::max(max_round_seen_, r);
        auto [it, inserted] = seen_pv_.emplace(std::make_pair(h, r), id);
        if (!inserted) {
          if (it->second != id) {
            return Violation{"double-prevote", "h=" + std::to_string(h) + " r=" + std::to_string(r) + " " + short_id(it->second) +
                                                   " vs " + short_id(id)};
          }
          continue;
        }
        ++stats.own_prevotes;
        note("OWN prevote h=" + std::to_string(h) + " r=" + std::to_string(r) + " id=" + short_id(id));
        // lock-rule: the lock is the latest own precommit at a round <= r (a precommit on a polka can
        // precede the node's own prevote in that round); a prevote for another value needs a POL
        // from a round at or after it (can_prevote_locked).
        const std::pair<std::uint32_t, Hash32>* latest = nullptr;
        std::pair<std::uint32_t, Hash32> latest_value;
        for (const auto& [slot, pid] : sent_pc_) {
          if (slot.first != h || slot.second > r) continue;
          if (!latest || slot.second > latest_value.first) {
            latest_value = {slot.second, pid};
            latest = &latest_value;
          }
        }
        if (latest && latest->second != id) {
          int pol = -1;
          if (auto p = pol_by_slot_.find({h, r, id}); p != pol_by_slot_.end()) pol = p->second;
          if (pol < static_cast<int>(latest->first)) {
            return Violation{"lock-rule", "prevote " + short_id(id) + "@" + std::to_string(r) + " after precommit " +
                                              short_id(latest->second) + "@" + std::to_string(latest->first) +
                                              " with pol=" + std::to_string(pol)};
          }
        }
      }
    }
    return std::nullopt;
  }

  enum class Last { None, Propose, Vote };

  Fixture& fx_;
  bool faults_enabled_;
  bool byzantine_majority_;
  std::map<std::tuple<PubKey32, std::uint64_t, std::uint32_t, bool>, Hash32> honest_votes_;
  std::vector<Proposal> proposals_;
  std::map<std::tuple<std::uint64_t, std::uint32_t, Hash32>, int> pol_by_slot_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, Hash32> sent_pc_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, Hash32> seen_pv_;
  std::map<std::uint64_t, Hash32> finalized_;
  std::uint64_t max_height_{0};
  std::uint32_t max_round_seen_{0};
  bool after_restart_{false};
  bool restart_failed_{false};
  std::optional<Violation> pending_;
  Last last_kind_{Last::None};
  std::optional<p2p::ProposeMsg> last_propose_;
  const crypto::KeyPair* last_propose_signer_{nullptr};
  Hash32 last_propose_id_{};
  std::optional<Vote> last_vote_;
  bool last_vote_precommit_{false};
  Bytes history_;
  std::vector<std::string> trace_;
};

std::string artifact_path(const std::string& oracle, const Bytes& history) {
  const char* dir = std::getenv("FINALIS_FUZZ_ARTIFACT_DIR");
  const auto digest = crypto::sha256(history);
  std::string hex;
  static const char* h = "0123456789abcdef";
  for (int i = 0; i < 8; ++i) {
    hex += h[digest[i] >> 4];
    hex += h[digest[i] & 15];
  }
  return (std::filesystem::path(dir ? dir : ".") / ("crash-" + oracle + "-" + hex + ".bin")).string();
}

void report(const Violation& v, const Runner& runner, const char* where) {
  std::cerr << "fuzz_consensus_persistence: VIOLATION oracle=" << v.oracle << " " << v.detail << " (" << where << ")\n";
  std::cerr << "  last operations:\n";
  for (const auto& line : runner.trace()) std::cerr << "    " << line << "\n";
  const auto path = artifact_path(v.oracle, runner.history());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(runner.history().data()), static_cast<std::streamsize>(runner.history().size()));
  std::cerr << "  reproducer (" << runner.history().size() << " bytes): " << path << "\n";
}

// FINALIS_FUZZ_SKIP_D7=1: a reported-height rollback (the open defect D7) is counted, not reported,
// so a campaign can exercise the other oracles past it. A finalized height that changes its
// transition is still a violation.
bool skip_d7_rollback_from_env() {
  const char* env = std::getenv("FINALIS_FUZZ_SKIP_D7");
  return env != nullptr && std::string(env) == "1";
}

bool faults_enabled_from_env() {
  const char* env = std::getenv("FINALIS_FUZZ_FAULTS");
  return env == nullptr || std::string(env) != "0";
}

bool byzantine_majority_from_env() {
  const char* env = std::getenv("FINALIS_FUZZ_BYZANTINE_MAJORITY");
  return env != nullptr && std::string(env) == "1";
}

Bytes random_script(std::mt19937_64& rng) {
  Bytes b(48 + rng() % 208);
  for (auto& x : b) x = static_cast<std::uint8_t>(rng());
  return b;
}

// libFuzzer: a fresh node per input, so every crash input reproduces on its own.
struct Env {
  Env() { faults::disarm(); }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static Env env;
  if (size == 0 || size > 512) return 0;
  auto fx = make_fixture();
  if (!fx) {
    std::cerr << "fuzz_consensus_persistence: fixture setup failed\n";
    std::abort();
  }
  Runner runner(*fx, faults_enabled_from_env(), byzantine_majority_from_env());
  if (auto v = runner.run(Bytes(data, data + size)); v.has_value()) {
    report(*v, runner, "libfuzzer");
    std::abort();
  }
  return 0;
}

#ifndef FINALIS_LIBFUZZER
int main(int argc, char** argv) {
  const bool with_faults = faults_enabled_from_env();
  if (argc > 1) {  // replay: each file against a fresh node
    int violations = 0;
    for (int i = 1; i < argc; ++i) {
      std::ifstream in(argv[i], std::ios::binary);
      if (!in.good()) continue;
      Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      auto fx = make_fixture();
      if (!fx) return 2;
      Runner runner(*fx, with_faults, byzantine_majority_from_env());
      if (auto v = runner.run(b); v.has_value()) {
        report(*v, runner, argv[i]);
        ++violations;
      }
    }
    return violations == 0 ? 0 : 1;
  }
  const char* iters_env = std::getenv("FINALIS_FUZZ_ITERS");
  const char* seed_env = std::getenv("FINALIS_FUZZ_SEED");
  const int iters = iters_env ? std::atoi(iters_env) : 40;
  const std::uint64_t seed = seed_env ? std::strtoull(seed_env, nullptr, 0) : 0x50455253ULL;
  std::mt19937_64 rng(seed);
  // Scripts carry state on one node; the history since the fixture started is the reproducer. A
  // fresh fixture every 8 scripts keeps reproducers short.
  std::unique_ptr<Fixture> fx;
  std::unique_ptr<Runner> runner;
  Runner::Stats total;
  const auto add = [&](const Runner::Stats& s) {
    total.ops += s.ops;
    total.proposals_accepted += s.proposals_accepted;
    total.faults_armed += s.faults_armed;
    total.faults_injected += s.faults_injected;
    total.skipped_rollbacks += s.skipped_rollbacks;
    total.restarts += s.restarts;
    total.own_prevotes += s.own_prevotes;
    total.own_precommits += s.own_precommits;
    total.finalized += s.finalized;
  };
  for (int i = 0; i < iters; ++i) {
    if (i % 8 == 0) {
      if (runner) add(runner->stats);
      runner.reset();
      fx = make_fixture();
      if (!fx) return 2;
      runner = std::make_unique<Runner>(*fx, with_faults, byzantine_majority_from_env());
    }
    if (auto v = runner->run(random_script(rng)); v.has_value()) {
      std::ostringstream where;
      where << "seed=" << seed << " script=" << i;
      report(*v, *runner, where.str().c_str());
      return 1;
    }
  }
  if (runner) add(runner->stats);
  std::cout << "fuzz_consensus_persistence done scripts=" << iters << " seed=" << seed << " faults=" << with_faults
            << " ops=" << total.ops << " proposals_accepted=" << total.proposals_accepted
            << " faults_armed=" << total.faults_armed << " faults_injected=" << total.faults_injected
            << " skipped_d7_rollbacks=" << total.skipped_rollbacks
            << " restarts=" << total.restarts << " own_prevotes=" << total.own_prevotes
            << " own_precommits=" << total.own_precommits << " finalized_heights=" << total.finalized << "\n";
  return 0;
}
#endif
