// SPDX-License-Identifier: MIT

// Round trips for every block, certificate, frontier, sync and snapshot codec not covered by
// fuzz_consensus_msgs / fuzz_tx_parse. The first input byte picks the codec, the rest is its input.
// An accepted input must re-encode to bytes that parse again to the same encoding. Strict codecs
// must also re-encode to exactly the input (one encoding per value: these objects are hashed, signed
// or compared by their bytes); local state that is normalized on parse is not strict.
//
// Built as a libFuzzer target with -DFINALIS_LIBFUZZER (see .clusterfuzzlite/); otherwise a
// standalone smoke binary.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>

#include "consensus/availability_retention.hpp"
#include "p2p/messages.hpp"
#include "storage/snapshot.hpp"
#include "utxo/tx.hpp"

using namespace finalis;

namespace {

struct Codec {
  const char* name;
  std::function<void(const Bytes&)> run;
};

template <class De, class Ser>
Codec codec(const char* name, De de, Ser ser, bool strict = true) {
  return {name, [name, de, ser, strict](const Bytes& in) {
            auto m = de(in);
            if (!m.has_value()) return;
            const Bytes enc = ser(*m);
            auto again = de(enc);
            if (!again.has_value() || ser(*again) != enc || (strict && enc != in)) {
              std::cerr << "fuzz_wire_codecs: non-canonical " << name << " size=" << in.size() << "\n";
              std::abort();
            }
          }};
}

template <class T>
Codec type_codec(const char* name, bool strict = true) {
  return codec(
      name, [](const Bytes& b) { return T::parse(b); }, [](const T& v) { return v.serialize(); }, strict);
}

const std::vector<Codec>& codecs() {
  static const std::vector<Codec> all = {
      type_codec<BlockHeader>("BlockHeader"),
      type_codec<Block>("Block"),
      type_codec<FinalityProof>("FinalityProof"),
      type_codec<FinalityCertificate>("FinalityCertificate"),
      type_codec<FrontierDecision>("FrontierDecision"),
      type_codec<FrontierSettlement>("FrontierSettlement"),
      type_codec<FrontierVector>("FrontierVector"),
      type_codec<FrontierTransition>("FrontierTransition"),
      type_codec<FrontierProposal>("FrontierProposal"),
      type_codec<IngressCertificate>("IngressCertificate"),
      type_codec<LaneState>("LaneState"),
      type_codec<storage::SnapshotManifest>("SnapshotManifest"),
      type_codec<storage::SnapshotBundle>("SnapshotBundle"),
      type_codec<availability::AvailabilityPersistentState>("AvailabilityPersistentState", false),
      codec("version", p2p::de_version, p2p::ser_version),
      codec("finalized_tip", p2p::de_finalized_tip, p2p::ser_finalized_tip),
      codec("get_transition", p2p::de_get_transition, p2p::ser_get_transition),
      codec("get_transition_by_height", p2p::de_get_transition_by_height, p2p::ser_get_transition_by_height),
      codec("transition", p2p::de_transition, p2p::ser_transition),
      codec("epoch_ticket", p2p::de_epoch_ticket, p2p::ser_epoch_ticket),
      codec("get_epoch_tickets", p2p::de_get_epoch_tickets, p2p::ser_get_epoch_tickets),
      codec("epoch_tickets", p2p::de_epoch_tickets, p2p::ser_epoch_tickets),
      codec("tx", p2p::de_tx, p2p::ser_tx),
      codec("ingress_record", p2p::de_ingress_record, p2p::ser_ingress_record),
      codec("get_ingress_range", p2p::de_get_ingress_range, p2p::ser_get_ingress_range),
      codec("ingress_range", p2p::de_ingress_range, p2p::ser_ingress_range),
      codec("get_ingress_tips", p2p::de_get_ingress_tips, p2p::ser_get_ingress_tips),
      codec("ingress_tips", p2p::de_ingress_tips, p2p::ser_ingress_tips),
      codec("getaddr", p2p::de_getaddr, p2p::ser_getaddr),
      codec("addr", p2p::de_addr, p2p::ser_addr),
      codec("ping", p2p::de_ping, p2p::ser_ping),
  };
  return all;
}

void run_one(const Bytes& in) {
  if (in.empty()) return;
  const auto& all = codecs();
  all[in[0] % all.size()].run(Bytes(in.begin() + 1, in.end()));
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

  std::mt19937_64 rng(0x57495245ULL);
  std::uniform_int_distribution<int> len_dist(1, 4096);
  for (int i = 0; i < 20000; ++i) {
    const int n = len_dist(rng);
    Bytes b(static_cast<std::size_t>(n));
    for (int j = 0; j < n; ++j) b[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(rng() & 0xFFu);
    run_one(b);
  }
  std::cout << "fuzz_wire_codecs done\n";
  return 0;
}
#endif
