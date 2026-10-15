// SPDX-License-Identifier: MIT

// PROPOSE / PREVOTE / PRECOMMIT / TIMEOUT_VOTE payload decoders. Every accepted input must
// re-encode to exactly the input bytes (one encoding per message), and the PROPOSE frontier
// payload must survive FrontierProposal::parse the same way the node calls it.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>

#include "p2p/messages.hpp"

using namespace finalis;

namespace {

std::uint64_t g_accepted = 0;

template <class De, class Ser>
void check_roundtrip(const Bytes& in, De de, Ser ser, const char* what) {
  auto m = de(in);
  if (!m.has_value()) return;
  ++g_accepted;
  const Bytes enc = ser(*m);
  auto again = de(enc);
  if (!again.has_value() || ser(*again) != enc || enc != in) {
    std::cerr << "fuzz_consensus_msgs: non-canonical " << what << " size=" << in.size() << "\n";
    std::abort();
  }
}

void run_one(const Bytes& in) {
  check_roundtrip(in, p2p::de_vote, p2p::ser_vote, "precommit");
  check_roundtrip(in, p2p::de_prevote, p2p::ser_prevote, "prevote");
  check_roundtrip(in, p2p::de_timeout_vote, p2p::ser_timeout_vote, "timeout_vote");
  check_roundtrip(in, p2p::de_propose, p2p::ser_propose, "propose");
  check_roundtrip(in, p2p::de_tx_result, p2p::ser_tx_result, "tx_result");
  if (auto p = p2p::de_propose(in); p.has_value()) {
    if (auto fp = FrontierProposal::parse(p->frontier_proposal_bytes); fp.has_value()) {
      (void)FrontierProposal::parse(fp->serialize());
    }
  }
}

void fill(std::mt19937_64& rng, std::uint8_t* p, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) p[i] = static_cast<std::uint8_t>(rng());
}

std::vector<Bytes> seeds(std::mt19937_64& rng) {
  Vote v;
  v.height = 42;
  v.round = 3;
  fill(rng, v.block_id.data(), v.block_id.size());
  fill(rng, v.validator_pubkey.data(), v.validator_pubkey.size());
  fill(rng, v.signature.data(), v.signature.size());
  TimeoutVote tv;
  tv.height = 42;
  tv.round = 3;
  tv.validator_pubkey = v.validator_pubkey;
  tv.signature = v.signature;

  auto sigs = [&](std::size_t n) {
    std::vector<FinalitySig> out(n);
    for (auto& s : out) {
      fill(rng, s.validator_pubkey.data(), s.validator_pubkey.size());
      fill(rng, s.signature.data(), s.signature.size());
    }
    return out;
  };
  p2p::ProposeMsg plain;
  plain.height = 42;
  plain.round = 3;
  fill(rng, plain.prev_finalized_hash.data(), plain.prev_finalized_hash.size());
  plain.frontier_proposal_bytes = FrontierProposal{}.serialize();
  fill(rng, plain.proposer_signature.data(), plain.proposer_signature.size());
  p2p::ProposeMsg full = plain;
  QuorumCertificate pol;
  pol.height = 42;
  pol.round = 1;
  pol.block_id = v.block_id;
  pol.signatures = sigs(3);
  full.pol = pol;
  full.justify_tc = TimeoutCertificate{42, 2, sigs(3)};

  return {p2p::ser_vote({v}), p2p::ser_prevote({v}), p2p::ser_timeout_vote({tv}), p2p::ser_propose(plain),
          p2p::ser_propose(full)};
}

Bytes mutate(std::mt19937_64& rng, Bytes b) {
  const int ops = 1 + static_cast<int>(rng() % 4);
  for (int k = 0; k < ops; ++k) {
    switch (rng() % 5) {
      case 0:  // flip a byte
        if (!b.empty()) b[rng() % b.size()] ^= static_cast<std::uint8_t>(1u + rng() % 255u);
        break;
      case 1:  // truncate
        if (!b.empty()) b.resize(rng() % b.size());
        break;
      case 2:  // append junk
        for (int i = 1 + static_cast<int>(rng() % 8); i > 0; --i) b.push_back(static_cast<std::uint8_t>(rng()));
        break;
      case 3:  // insert a byte
        b.insert(b.begin() + static_cast<std::ptrdiff_t>(rng() % (b.size() + 1)), static_cast<std::uint8_t>(rng()));
        break;
      default:  // erase a byte
        if (!b.empty()) b.erase(b.begin() + static_cast<std::ptrdiff_t>(rng() % b.size()));
        break;
    }
  }
  return b;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  run_one(Bytes(data, data + size));
  return 0;
}

#ifndef FINALIS_LIBFUZZER
int main(int argc, char** argv) {
  if (argc > 1) {
    for (int i = 1; i < argc; ++i) {
      std::ifstream in(argv[i], std::ios::binary);
      if (!in.good()) continue;
      Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      run_one(b);
    }
    return 0;
  }

  std::mt19937_64 rng(0x50524F50ULL);
  const auto base = seeds(rng);
  for (const auto& s : base) run_one(s);
  for (int i = 0; i < 200000; ++i) run_one(mutate(rng, base[rng() % base.size()]));
  std::uniform_int_distribution<int> len_dist(0, 1024);
  for (int i = 0; i < 20000; ++i) {
    Bytes b(static_cast<std::size_t>(len_dist(rng)));
    fill(rng, b.data(), b.size());
    run_one(b);
  }
  std::cout << "fuzz_consensus_msgs done accepted=" << g_accepted << "\n";
  return 0;
}
#endif
