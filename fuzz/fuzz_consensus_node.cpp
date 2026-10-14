// SPDX-License-Identifier: MIT

// Stateful consensus fuzzer: one validator node (4-validator genesis, no P2P, timers parked) is
// fed a script of PROPOSE / PREVOTE / PRECOMMIT / TIMEOUT_VOTE messages. Messages are signed with
// the committee's real keys, so they get past signature checks into proposal validation, POL and
// timeout-certificate handling, locking and finalization. Fields, signers, certificates and
// proposal bytes come from the input.
//
// Oracle: besides sanitizer findings, the node must never prevote or precommit two different
// transitions at the same (height, round).

#include <array>
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
#include <string>
#include <vector>

#include <unistd.h>

#include "common/keystore.hpp"
#include "genesis/genesis.hpp"
#include "node/node.hpp"
#include "p2p/messages.hpp"
#include "utxo/validate.hpp"

using namespace finalis;

namespace {

constexpr std::size_t kValidators = 4;
constexpr std::uint32_t kRounds = 8;
constexpr std::size_t kMaxIds = 16;

// Reads the script; an exhausted input yields zeros.
struct Cursor {
  const Bytes& in;
  std::size_t pos{0};
  bool done() const { return pos >= in.size(); }
  std::uint8_t u8() { return pos < in.size() ? in[pos++] : 0; }
  Hash32 h32() {
    Hash32 h{};
    for (auto& b : h) b = u8();
    return h;
  }
};

struct Fixture {
  std::string base;
  std::unique_ptr<node::Node> node;
  std::vector<crypto::KeyPair> keys;  // [0, kValidators): committee; the rest are outsiders
  Hash32 domain{};
};

bool write_genesis(const std::string& path, const std::vector<crypto::KeyPair>& keys) {
  genesis::Document d;
  d.version = 1;
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
  d.note = "fuzz-consensus-node";
  for (std::size_t i = 0; i < kValidators; ++i) d.initial_validators.push_back(keys[i].public_key);
  std::ofstream out(path, std::ios::trunc);
  out << genesis::to_json(d);
  return out.good();
}

std::unique_ptr<Fixture> make_fixture() {
  auto fx = std::make_unique<Fixture>();
  fx->keys = node::Node::deterministic_test_keypairs();
  fx->base = (std::filesystem::temp_directory_path() / ("finalis_fuzz_consensus_node_" + std::to_string(::getpid()))).string();
  std::error_code ec;
  std::filesystem::remove_all(fx->base, ec);
  std::filesystem::create_directories(fx->base);

  node::NodeConfig cfg;
  cfg.allow_unencrypted_keystore = true;
  cfg.disable_p2p = true;
  cfg.node_id = 0;
  cfg.dns_seeds = false;
  cfg.network.default_seeds.clear();
  // Timers parked: only the script moves rounds.
  cfg.network.round_timeout_ms = 3'600'000;
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
  fx->node = std::make_unique<node::Node>(cfg);
  if (!fx->node->init()) return nullptr;
  fx->node->start();
  (void)fx->node->pause_proposals_for_test(true);
  fx->domain = fx->node->consensus_domain_for_test();
  return fx;
}

class Runner {
 public:
  struct Stats {
    std::uint64_t proposals_accepted{0};
    std::uint64_t prevotes_accepted{0};
    std::uint64_t precommits_accepted{0};
    std::uint64_t local_prevote_slots{0};  // (height, round) slots the double-vote oracle watched
  } stats;

  explicit Runner(Fixture& fx) : fx_(fx) {}

  void run(const Bytes& in) {
    Cursor c{in};
    for (int ops = 0; ops < 64 && !c.done(); ++ops) {
      switch (c.u8() % 10) {
        case 0: propose(c); break;
        case 1: vote(c, /*precommit=*/false); break;
        case 2: vote(c, /*precommit=*/true); break;
        case 3: timeout_vote(c); break;
        case 4: advance_round(c); break;
        case 5: raw_propose(c); break;
        case 6: quorum(c, /*precommit=*/false); break;  // a polka
        case 7: quorum(c, /*precommit=*/true); break;   // finality, when the id is a real proposal
        case 8: timeout_quorum(c); break;               // a TC: the node moves to a fresh round
        default: remember_id(c.h32()); break;
      }
      check_no_double_vote();
    }
  }

 private:
  std::uint64_t next_height() const { return fx_.node->status().height + 1; }

  std::uint32_t current_round() const { return fx_.node->status().round; }

  // Mostly the node's current round (messages for it get past the round checks), else nearby.
  std::uint32_t pick_round(Cursor& c) const {
    const std::uint8_t b = c.u8();
    const std::uint32_t cur = current_round();
    if (b % 4 != 0) return cur;
    const int offset = static_cast<int>((b >> 2) % kRounds) - 2;  // -2 .. +5
    return offset < 0 && cur < static_cast<std::uint32_t>(-offset) ? 0 : static_cast<std::uint32_t>(static_cast<int>(cur) + offset);
  }

  // `count` distinct committee members, starting at `first`.
  std::vector<const crypto::KeyPair*> committee_signers(std::size_t first, std::size_t count) const {
    std::vector<const crypto::KeyPair*> out;
    for (std::size_t i = 0; i < count && i < kValidators; ++i) out.push_back(&fx_.keys[(first + i) % kValidators]);
    return out;
  }

  // Mostly the next height; sometimes one past it, or the finalized one.
  std::uint64_t pick_height(Cursor& c) const {
    const std::uint64_t h = next_height();
    switch (c.u8() % 8) {
      case 0: return h + 1;
      case 1: return h - 1;
      default: return h;
    }
  }

  const crypto::KeyPair& signer(Cursor& c) const {
    const std::uint8_t b = c.u8();
    return fx_.keys[b % 8 == 7 ? kValidators + (b >> 3) % 4 : b % kValidators];  // 1/8: an outsider
  }

  Hash32 pick_id(Cursor& c) {
    if (ids_.empty() || c.u8() % 8 == 0) {
      const Hash32 id = c.h32();
      remember_id(id);
      return id;
    }
    return ids_[c.u8() % ids_.size()];
  }

  void remember_id(const Hash32& id) {
    for (const auto& known : ids_) {
      if (known == id) return;
    }
    if (ids_.size() == kMaxIds) ids_.erase(ids_.begin());
    ids_.push_back(id);
  }

  static Sig64 sign(const Bytes& msg, const crypto::KeyPair& kp, Cursor& c) {
    auto sig = crypto::ed25519_sign(msg, kp.private_key);
    Sig64 out = sig.value_or(Sig64{});
    if (c.u8() % 16 == 0) out[c.u8() % out.size()] ^= 0x01;  // occasionally a bad signature
    return out;
  }

  std::vector<FinalitySig> signatures(Cursor& c, const Bytes& msg) {
    std::vector<FinalitySig> out;
    const std::size_t n = c.u8() % (kValidators + 2);  // up to a duplicate signer
    for (std::size_t i = 0; i < n; ++i) {
      const auto& kp = signer(c);
      out.push_back(FinalitySig{kp.public_key, sign(msg, kp, c)});
    }
    return out;
  }

  void propose(Cursor& c) {
    const std::uint64_t h = next_height();
    std::uint32_t round = pick_round(c);
    if (c.u8() % 2 == 0) {  // a round this node leads: its own build (leader VRF) is then valid
      for (std::uint32_t r = round; r < round + kRounds; ++r) {
        if (fx_.node->proposer_for_height_round_for_test(h, r) == fx_.node->local_validator_pubkey_for_test()) {
          round = r;
          break;
        }
      }
      (void)fx_.node->advance_round_for_test(h, round);
    }
    auto proposal = fx_.node->build_frontier_proposal_for_test(h, round);
    if (!proposal.has_value()) return;
    Bytes bytes = proposal->serialize();
    Hash32 id = proposal->transition.transition_id();
    if (c.u8() % 4 == 0 && !bytes.empty()) {  // mutate the proposal, then sign what is sent
      for (int k = 1 + c.u8() % 3; k > 0; --k) bytes[(c.u8() << 8 | c.u8()) % bytes.size()] ^= c.u8() | 1;
      if (auto reparsed = FrontierProposal::parse(bytes); reparsed.has_value()) id = reparsed->transition.transition_id();
    }
    remember_id(id);

    p2p::ProposeMsg msg;
    msg.height = h;
    msg.round = c.u8() % 4 == 0 ? pick_round(c) : round;
    msg.prev_finalized_hash = c.u8() % 16 == 0 ? c.h32() : proposal->transition.prev_finalized_hash;
    msg.frontier_proposal_bytes = std::move(bytes);
    if (c.u8() % 3 == 0) {  // proof of lock
      QuorumCertificate pol;
      pol.height = h;
      pol.round = c.u8() % 2 ? (round > 0 ? round - 1 : 0) : pick_round(c);
      pol.frontier_transition_id = c.u8() % 2 ? id : pick_id(c);
      pol.signatures = signatures(c, prevote_signing_message(fx_.domain, pol.height, pol.round, pol.frontier_transition_id));
      msg.pol = pol;
    }
    if (msg.round > 0 && c.u8() % 4 != 0) {  // the quorum TC a round > 0 proposal needs
      TimeoutCertificate tc;
      tc.height = h;
      tc.round = msg.round - 1;
      const Bytes tmsg = timeout_vote_signing_message(fx_.domain, tc.height, tc.round);
      for (const auto* kp : committee_signers(c.u8(), 3)) tc.signatures.push_back(FinalitySig{kp->public_key, sign(tmsg, *kp, c)});
      msg.justify_tc = tc;
    } else if (c.u8() % 3 == 0) {  // an arbitrary one
      TimeoutCertificate tc;
      tc.height = h;
      tc.round = pick_round(c);
      tc.signatures = signatures(c, timeout_vote_signing_message(fx_.domain, tc.height, tc.round));
      msg.justify_tc = tc;
    }
    const std::optional<std::uint32_t> pol_round = msg.pol ? std::optional<std::uint32_t>(msg.pol->round) : std::nullopt;
    // Usually the transition's leader signs; otherwise an arbitrary key.
    const crypto::KeyPair* kp = &signer(c);
    if (c.u8() % 4 != 0) {
      for (std::size_t i = 0; i < kValidators; ++i) {
        if (fx_.keys[i].public_key == proposal->transition.leader_pubkey) kp = &fx_.keys[i];
      }
    }
    msg.proposer_signature = sign(propose_signing_message(fx_.domain, msg.height, msg.round, id, pol_round), *kp, c);
    if (fx_.node->inject_network_propose_result_for_test(msg) == "accepted") {
      accepted_ = {msg.height, msg.round, id};
      ++stats.proposals_accepted;
    }
  }

  void vote(Cursor& c, bool precommit) {
    Vote v;
    v.height = pick_height(c);
    v.round = pick_round(c);
    v.frontier_transition_id = pick_id(c);
    const auto& kp = signer(c);
    v.validator_pubkey = kp.public_key;
    v.signature = sign(precommit ? vote_signing_message(fx_.domain, v.height, v.round, v.frontier_transition_id)
                                 : prevote_signing_message(fx_.domain, v.height, v.round, v.frontier_transition_id),
                       kp, c);
    (void)(precommit ? fx_.node->inject_network_vote_result_for_test(v) : fx_.node->inject_network_prevote_result_for_test(v));
  }

  void quorum(Cursor& c, bool precommit) {
    std::uint64_t h = next_height();
    std::uint32_t r = pick_round(c);
    Hash32 id = pick_id(c);
    if (accepted_.has_value() && c.u8() % 2 == 0) {  // back the last accepted proposal
      h = accepted_->height;
      r = accepted_->round;
      id = accepted_->id;
    }
    const std::size_t first = c.u8();
    for (const auto* kp : committee_signers(first, 2 + c.u8() % 3)) {
      Vote v;
      v.height = h;
      v.round = r;
      v.frontier_transition_id = id;
      v.validator_pubkey = kp->public_key;
      v.signature = sign(precommit ? vote_signing_message(fx_.domain, h, r, id) : prevote_signing_message(fx_.domain, h, r, id),
                         *kp, c);
      const auto res =
          precommit ? fx_.node->inject_network_vote_result_for_test(v) : fx_.node->inject_network_prevote_result_for_test(v);
      if (res == "accepted") ++(precommit ? stats.precommits_accepted : stats.prevotes_accepted);
    }
  }

  void timeout_vote(Cursor& c) {
    TimeoutVote v;
    v.height = pick_height(c);
    v.round = c.u8() % 4 == 0 ? current_round() + c.u8() : pick_round(c);  // also beyond the catch-up window
    const auto& kp = signer(c);
    v.validator_pubkey = kp.public_key;
    v.signature = sign(timeout_vote_signing_message(fx_.domain, v.height, v.round), kp, c);
    (void)fx_.node->inject_timeout_vote_for_test(v);
  }

  void advance_round(Cursor& c) { (void)fx_.node->advance_round_for_test(next_height(), pick_round(c)); }

  void timeout_quorum(Cursor& c) {
    const std::uint64_t h = next_height();
    const std::uint32_t r = pick_round(c);
    for (const auto* kp : committee_signers(c.u8(), 2 + c.u8() % 3)) {
      TimeoutVote v;
      v.height = h;
      v.round = r;
      v.validator_pubkey = kp->public_key;
      v.signature = sign(timeout_vote_signing_message(fx_.domain, h, r), *kp, c);
      (void)fx_.node->inject_timeout_vote_for_test(v);
    }
  }

  // Unsigned, arbitrary PROPOSE payload: the rest of the script, length-prefixed.
  void raw_propose(Cursor& c) {
    const std::size_t n = c.u8() << 4;
    Bytes payload;
    for (std::size_t i = 0; i < n && !c.done(); ++i) payload.push_back(c.u8());
    if (auto msg = p2p::de_propose(payload); msg.has_value()) (void)fx_.node->inject_network_propose_result_for_test(*msg);
  }

  // The honest node signs at most one prevote and one precommit per (height, round).
  void check_no_double_vote() {
    const std::uint64_t h = next_height();
    const std::uint32_t cur = current_round();
    for (std::uint32_t r = cur > kRounds ? cur - kRounds : 0; r <= cur + kRounds; ++r) {
      int precommits = 0;
      for (const auto& id : ids_) {
        if (fx_.node->local_vote_recorded_for_test(h, r, id)) ++precommits;
        if (!fx_.node->local_prevote_recorded_for_test(h, r, id)) continue;
        auto [it, inserted] = prevoted_.emplace(std::make_pair(h, r), id);
        if (inserted) ++stats.local_prevote_slots;
        if (!inserted && it->second != id) {
          std::cerr << "fuzz_consensus_node: two local prevotes at height=" << h << " round=" << r << "\n";
          std::abort();
        }
      }
      if (precommits > 1) {
        std::cerr << "fuzz_consensus_node: two local precommits at height=" << h << " round=" << r << "\n";
        std::abort();
      }
    }
  }

  struct Accepted {
    std::uint64_t height;
    std::uint32_t round;
    Hash32 id;
  };

  Fixture& fx_;
  std::optional<Accepted> accepted_;
  std::vector<Hash32> ids_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, Hash32> prevoted_;
};

Bytes random_script(std::mt19937_64& rng) {
  Bytes b(64 + rng() % 448);
  for (auto& x : b) x = static_cast<std::uint8_t>(rng());
  return b;
}

}  // namespace

int main(int argc, char** argv) {
  auto fx = make_fixture();
  if (!fx) {
    std::cerr << "fuzz_consensus_node: fixture setup failed\n";
    return 1;
  }
  Runner runner(*fx);
  if (argc > 1) {  // replay inputs (crash reproduction) against one fresh node
    for (int i = 1; i < argc; ++i) {
      std::ifstream in(argv[i], std::ios::binary);
      if (!in.good()) continue;
      Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      runner.run(b);
    }
  } else {
    const char* iters_env = std::getenv("FINALIS_FUZZ_ITERS");
    const int iters = iters_env ? std::atoi(iters_env) : 2000;
    std::mt19937_64 rng(0x434F4E53ULL);
    for (int i = 0; i < iters; ++i) runner.run(random_script(rng));
    std::cout << "fuzz_consensus_node done scripts=" << iters << " height=" << fx->node->status().height
              << " proposals_accepted=" << runner.stats.proposals_accepted
              << " quorum_prevotes_accepted=" << runner.stats.prevotes_accepted
              << " quorum_precommits_accepted=" << runner.stats.precommits_accepted
              << " local_prevote_slots=" << runner.stats.local_prevote_slots << "\n";
  }
  fx->node->stop();
  std::error_code ec;
  std::filesystem::remove_all(fx->base, ec);
  return 0;
}
